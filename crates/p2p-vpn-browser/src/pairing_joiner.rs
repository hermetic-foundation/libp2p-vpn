//! Pairing-only client over one authenticated direct or relay route. The caller keeps the identity and owns
//! persistence, membership installation, and subsequent VPN connections.

use std::{error::Error, io, time::Duration};

use futures::{FutureExt, StreamExt, pin_mut, select_biased};
use gloo_timers::future::TimeoutFuture;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, Transport,
    core::transport::TransportError,
    multiaddr::Protocol,
    request_response::{self, Event, Message, ProtocolSupport},
    swarm::{ConnectionId, DialError, NetworkBehaviour, SwarmEvent, dial_opts::DialOpts},
};
use p2p_vpn::{
    config::RouteConfig,
    identity::NodeIdentity,
    pairing::{
        PairingAcceptanceMode, PairingError, PairingOffer, PairingRequest, PairingRequestOptions,
        PairingResponse, build_named_pairing_request_at,
    },
    pairing_code::{
        PairingCode, PairingCodeError, PairingCodeSession, authenticate_pairing_request,
        open_pairing_code_challenge_at, open_pairing_code_challenge_v2_at,
        pairing_request_transcript_sha256, start_pairing_code_hello_at,
        start_pairing_code_hello_v2_at,
    },
    runtime::pairing::{PAIRING_PROTOCOL, PairingCodec},
    runtime::pairing_code::{
        PAIRING_CODE_PROTOCOL, PAIRING_CODE_V2_PROTOCOL, PairingCodeCodec,
        PairingCodeRejectionReason, PairingCodeRequest, PairingCodeResponse, PairingCodeV2Codec,
        PairingCodeV2Request, PairingCodeV2Response,
    },
};
use web_time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(feature = "relay-client")]
use crate::relay::{RelayRoute, build_transport};

const MAX_WAIT: Duration = Duration::from_secs(60 * 60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL_MS: u32 = 1_000;

pub struct JoinOptions {
    pub timeout: Duration,
    pub requested_hostname: Option<String>,
    pub requested_vpn_ip: Option<String>,
    pub requested_routes: Vec<RouteConfig>,
}

pub struct Enrollment {
    pub offer: PairingOffer,
    pub response: PairingResponse,
    pub transcript_sha256: String,
}

#[derive(Debug)]
pub enum JoinError {
    InvalidAddress,
    InvalidIdentity,
    InvalidTimeout,
    InvalidClock,
    CandidateMiss(CandidateMiss),
    Dial(DialError),
    Disconnected,
    WrongPeer,
    Expired,
    UnexpectedResponse,
    InvalidTicket,
    Rejected(PairingCodeRejectionReason),
    Transport(request_response::OutboundFailure),
    Code(PairingCodeError),
    Pairing(PairingError),
}

#[derive(Debug)]
pub enum CandidateMiss {
    Transport,
    Unavailable,
}

/// Submit the existing signed file-bearer request once; no discovery or protocol fallback.
pub async fn exchange_file_bearer(
    identity: &NodeIdentity,
    offer: &PairingOffer,
    mut request: PairingRequest,
    dial_address: Multiaddr,
    timeout: Duration,
) -> Result<PairingResponse, JoinError> {
    if offer.payload.acceptance_mode != PairingAcceptanceMode::FileBearer
        || request.code_authentication.is_some()
    {
        return Err(JoinError::UnexpectedResponse);
    }
    let inviter = offer
        .payload
        .inviter_peer
        .parse()
        .map_err(|_| JoinError::WrongPeer)?;
    // Supply the exact signed offer, including any addresses exported separately
    // from the daemon's running config. The request signature already binds it.
    request.offer = Some(offer.clone());
    request
        .verify_for_offer_at(offer, unix_time()?.as_secs())
        .map_err(JoinError::Pairing)?;
    let mut channel = Channel::<PairingCodec>::connect(
        identity,
        inviter,
        dial_address,
        timeout,
        Some(offer.payload.expires_at_unix_seconds),
    )
    .await?;
    let response = channel.request(request).await?;
    response
        .verify_for_offer_at(offer, identity, unix_time()?.as_secs())
        .map_err(JoinError::Pairing)?;
    Ok(response)
}

/// Enroll with an explicitly addressed inviter using the caller's browser identity.
/// `on_pending` runs once after the inviter returns a valid pending ticket.
/// Dropping the future stops the local attempt; it does not cancel native approval.
pub async fn join_v2(
    identity: &NodeIdentity,
    code: &PairingCode,
    expected_peer: PeerId,
    dial_address: Multiaddr,
    options: JoinOptions,
    on_pending: impl FnOnce(),
) -> Result<Enrollment, JoinError> {
    let mut channel = Channel::<PairingCodeV2Codec>::connect(
        identity,
        expected_peer,
        dial_address,
        options.timeout,
        None,
    )
    .await?;
    let (hello, pending) =
        start_pairing_code_hello_v2_at(code, identity, expected_peer, unix_time()?.as_secs())
            .map_err(JoinError::Code)?;
    let challenge = match channel
        .request(PairingCodeV2Request::Hello {
            hello: Box::new(hello),
        })
        .await?
    {
        PairingCodeV2Response::Challenge { challenge } => challenge,
        PairingCodeV2Response::Rejected { reason } => return Err(hello_rejection(reason)),
        _ => return Err(JoinError::UnexpectedResponse),
    };
    let (offer, session) = open_pairing_code_challenge_v2_at(
        pending,
        &challenge,
        expected_peer,
        unix_time()?.as_secs(),
    )
    .map_err(JoinError::Code)?;
    finish_approval(channel, identity, offer, session, options, on_pending).await
}

/// Explicit, network-scoped v1. Never attempted as a retry of v2.
pub async fn join_v1(
    identity: &NodeIdentity,
    code: &PairingCode,
    network_name: &str,
    expected_peer: PeerId,
    dial_address: Multiaddr,
    options: JoinOptions,
    on_pending: impl FnOnce(),
) -> Result<Enrollment, JoinError> {
    if network_name.is_empty() {
        return Err(JoinError::Code(PairingCodeError::EmptyNetworkName));
    }
    let mut channel = Channel::<PairingCodeCodec>::connect(
        identity,
        expected_peer,
        dial_address,
        options.timeout,
        None,
    )
    .await?;
    let (hello, pending) = start_pairing_code_hello_at(
        code,
        network_name,
        identity,
        expected_peer,
        unix_time()?.as_secs(),
    )
    .map_err(JoinError::Code)?;
    let challenge = match channel
        .request(PairingCodeRequest::Hello {
            hello: Box::new(hello),
        })
        .await?
    {
        PairingCodeResponse::Challenge { challenge } => challenge,
        PairingCodeResponse::Rejected { reason } => return Err(hello_rejection(reason)),
        _ => return Err(JoinError::UnexpectedResponse),
    };
    let (offer, session) =
        open_pairing_code_challenge_at(pending, &challenge, expected_peer, unix_time()?.as_secs())
            .map_err(JoinError::Code)?;
    finish_approval(channel, identity, offer, session, options, on_pending).await
}

fn hello_rejection(reason: PairingCodeRejectionReason) -> JoinError {
    if reason == PairingCodeRejectionReason::Unavailable {
        JoinError::CandidateMiss(CandidateMiss::Unavailable)
    } else {
        JoinError::Rejected(reason)
    }
}

async fn finish_approval<C: CodeWire>(
    mut channel: Channel<C>,
    identity: &NodeIdentity,
    offer: PairingOffer,
    session: PairingCodeSession,
    options: JoinOptions,
    on_pending: impl FnOnce(),
) -> Result<Enrollment, JoinError> {
    if offer.payload.acceptance_mode != PairingAcceptanceMode::CodeApproval {
        return Err(JoinError::UnexpectedResponse);
    }
    channel.cap_expiry(offer.payload.expires_at_unix_seconds)?;
    let mut request = build_named_pairing_request_at(
        &offer,
        PairingRequestOptions {
            identity: identity.clone(),
            requested_vpn_ip: options.requested_vpn_ip,
            requested_routes: options.requested_routes,
        },
        options.requested_hostname.as_deref(),
        unix_time()?.as_secs(),
    )
    .map_err(JoinError::Pairing)?;
    authenticate_pairing_request(&mut request, &session).map_err(JoinError::Code)?;
    let transcript_sha256 = pairing_request_transcript_sha256(&request).map_err(JoinError::Code)?;

    let mut outgoing = C::submit(request);
    let mut on_pending = Some(on_pending);
    let mut pending_ticket = None;
    loop {
        match C::approval(channel.request(outgoing).await?)? {
            Approval::Accepted(response) => {
                response
                    .verify_for_offer_at(&offer, identity, unix_time()?.as_secs())
                    .map_err(JoinError::Pairing)?;
                channel.remaining()?;
                return Ok(Enrollment {
                    offer,
                    response: *response,
                    transcript_sha256,
                });
            }
            Approval::Pending {
                ticket,
                expires_at_unix_seconds,
            } => {
                if ticket.is_empty()
                    || pending_ticket
                        .as_ref()
                        .is_some_and(|first| first != &ticket)
                {
                    return Err(JoinError::InvalidTicket);
                }
                channel.cap_expiry(expires_at_unix_seconds)?;
                if let Some(notify) = on_pending.take() {
                    pending_ticket = Some(ticket.clone());
                    notify();
                }
                channel.wait_for_poll().await?;
                outgoing = C::poll(ticket);
            }
        }
    }
}

fn validate_direct_address(address: &Multiaddr, expected_peer: PeerId) -> Result<(), JoinError> {
    let mut parts = address.iter();
    if !matches!(parts.next(), Some(Protocol::Ip4(_) | Protocol::Ip6(_)))
        || !matches!(parts.next(), Some(Protocol::Udp(1..)))
        || !matches!(parts.next(), Some(Protocol::WebRTCDirect))
        || !matches!(parts.next(), Some(Protocol::Certhash(hash)) if hash.code() == 0x12 && hash.size() == 32)
        || !matches!(parts.next(), Some(Protocol::P2p(peer)) if peer == expected_peer)
        || parts.next().is_some()
    {
        return Err(JoinError::InvalidAddress);
    }
    Ok(())
}

enum Approval {
    Accepted(Box<PairingResponse>),
    Pending {
        ticket: String,
        expires_at_unix_seconds: u64,
    },
}

trait PairingWire:
    request_response::Codec<Protocol = StreamProtocol> + Clone + Default + Send + 'static
{
    const PROTOCOL: &'static str;
}

impl PairingWire for PairingCodec {
    const PROTOCOL: &'static str = PAIRING_PROTOCOL;
}

trait CodeWire: PairingWire {
    fn submit(request: PairingRequest) -> Self::Request;
    fn poll(ticket: String) -> Self::Request;
    fn approval(response: Self::Response) -> Result<Approval, JoinError>;
}

macro_rules! code_wire {
    ($codec:ident, $protocol:ident, $request:ident, $response:ident) => {
        impl PairingWire for $codec {
            const PROTOCOL: &'static str = $protocol;
        }

        impl CodeWire for $codec {
            fn submit(request: PairingRequest) -> Self::Request {
                $request::Submit {
                    request: Box::new(request),
                }
            }

            fn poll(ticket: String) -> Self::Request {
                $request::Poll { ticket }
            }

            fn approval(response: Self::Response) -> Result<Approval, JoinError> {
                match response {
                    $response::Accepted { response } => Ok(Approval::Accepted(response)),
                    $response::Pending {
                        ticket,
                        expires_at_unix_seconds,
                    } => Ok(Approval::Pending {
                        ticket,
                        expires_at_unix_seconds,
                    }),
                    $response::Rejected { reason } => Err(JoinError::Rejected(reason)),
                    $response::Challenge { .. } => Err(JoinError::UnexpectedResponse),
                }
            }
        }
    };
}

code_wire!(
    PairingCodeCodec,
    PAIRING_CODE_PROTOCOL,
    PairingCodeRequest,
    PairingCodeResponse
);
code_wire!(
    PairingCodeV2Codec,
    PAIRING_CODE_V2_PROTOCOL,
    PairingCodeV2Request,
    PairingCodeV2Response
);

#[derive(NetworkBehaviour)]
struct Behaviour<C: PairingWire> {
    pairing: request_response::Behaviour<C>,
    #[cfg(feature = "relay-client")]
    relay: libp2p::swarm::behaviour::toggle::Toggle<libp2p::relay::client::Behaviour>,
}

struct Channel<C: PairingWire> {
    swarm: Swarm<Behaviour<C>>,
    peer: PeerId,
    connection: ConnectionId,
    deadline: Instant,
    wall_limit: Duration,
}

impl<C: PairingWire> Channel<C> {
    async fn connect(
        identity: &NodeIdentity,
        peer: PeerId,
        address: Multiaddr,
        timeout: Duration,
        expires_at: Option<u64>,
    ) -> Result<Self, JoinError> {
        if timeout.is_zero() || timeout > MAX_WAIT {
            return Err(JoinError::InvalidTimeout);
        }
        let deadline = Instant::now() + timeout;
        let keys = identity.keypair().map_err(|_| JoinError::InvalidIdentity)?;
        let local_peer = keys.public().to_peer_id();
        if local_peer.to_string() != identity.peer_id {
            return Err(JoinError::InvalidIdentity);
        }
        let relayed = address.iter().any(|part| part == Protocol::P2pCircuit);
        let direct = || {
            validate_direct_address(&address, peer)?;
            Ok(libp2p::core::transport::timeout::TransportTimeout::new(
                libp2p::webrtc_websys::Transport::new(libp2p::webrtc_websys::Config::new(&keys))
                    .boxed(),
                REQUEST_TIMEOUT,
            )
            .boxed())
        };
        #[cfg(feature = "relay-client")]
        let (transport, relay) = if relayed {
            let route =
                RelayRoute::from_dial_addr(&address).map_err(|_| JoinError::InvalidAddress)?;
            if route.destination() != peer {
                return Err(JoinError::InvalidAddress);
            }
            let (transport, relay) =
                build_transport(&keys, &route).map_err(|_| JoinError::InvalidAddress)?;
            (transport, Some(relay))
        } else {
            (direct()?, None)
        };
        #[cfg(not(feature = "relay-client"))]
        let transport = direct()?;
        let swarm = Swarm::new(
            transport,
            Behaviour {
                pairing: request_response::Behaviour::<C>::new(
                    [(StreamProtocol::new(C::PROTOCOL), ProtocolSupport::Outbound)],
                    request_response::Config::default()
                        .with_request_timeout(REQUEST_TIMEOUT)
                        .with_max_concurrent_streams(1),
                ),
                #[cfg(feature = "relay-client")]
                relay: relay.into(),
            },
            local_peer,
            libp2p::swarm::Config::with_wasm_executor().with_idle_connection_timeout(MAX_WAIT),
        );
        let dial = DialOpts::peer_id(peer).addresses(vec![address]).build();
        let connection = dial.connection_id();
        let mut channel = Self {
            swarm,
            peer,
            connection,
            deadline,
            wall_limit: Duration::MAX,
        };
        if let Some(expiry) = expires_at {
            channel.cap_expiry(expiry)?;
        }
        channel
            .swarm
            .dial(dial)
            .map_err(|error| initial_failure(JoinError::Dial(error)))?;
        loop {
            if let SwarmEvent::ConnectionEstablished {
                connection_id,
                peer_id,
                endpoint,
                ..
            } = channel.next_event().await.map_err(initial_failure)?
                && connection_id == connection
            {
                return if peer_id == peer && endpoint.is_relayed() == relayed {
                    Ok(channel)
                } else {
                    Err(JoinError::WrongPeer)
                };
            }
        }
    }

    fn cap_expiry(&mut self, expires_at: u64) -> Result<(), JoinError> {
        self.wall_limit = self.wall_limit.min(Duration::from_secs(expires_at));
        let now = Instant::now();
        self.deadline = self.deadline.min(now + self.remaining()?);
        Ok(())
    }

    fn remaining(&self) -> Result<Duration, JoinError> {
        let remaining = self
            .deadline
            .saturating_duration_since(Instant::now())
            .min(self.wall_limit.saturating_sub(unix_time()?));
        if remaining.is_zero() {
            Err(JoinError::Expired)
        } else {
            Ok(remaining)
        }
    }

    async fn next_event(&mut self) -> Result<SwarmEvent<BehaviourEvent<C>>, JoinError> {
        let millis = u32::try_from(self.remaining()?.as_millis() + 1)
            .map_err(|_| JoinError::InvalidTimeout)?;
        let timer = TimeoutFuture::new(millis).fuse();
        let next = self.swarm.select_next_some().fuse();
        pin_mut!(timer, next);
        let event = select_biased! {
            () = timer => return Err(JoinError::Expired),
            event = next => event,
        };
        match event {
            SwarmEvent::OutgoingConnectionError {
                connection_id,
                error,
                ..
            } if connection_id == self.connection => Err(JoinError::Dial(error)),
            SwarmEvent::ConnectionClosed { connection_id, .. }
                if connection_id == self.connection =>
            {
                Err(JoinError::Disconnected)
            }
            event => Ok(event),
        }
    }

    async fn wait_for_poll(&mut self) -> Result<(), JoinError> {
        let tick = TimeoutFuture::new(POLL_INTERVAL_MS).fuse();
        pin_mut!(tick);
        loop {
            let event = self.next_event().fuse();
            pin_mut!(event);
            select_biased! {
                () = tick => break,
                result = event => { result?; }
            }
        }
        self.remaining()?;
        Ok(())
    }

    async fn request(&mut self, message: C::Request) -> Result<C::Response, JoinError> {
        self.remaining()?;
        let expected = self
            .swarm
            .behaviour_mut()
            .pairing
            .send_request(&self.peer, message);
        loop {
            match self.next_event().await? {
                SwarmEvent::Behaviour(BehaviourEvent::Pairing(Event::Message {
                    peer,
                    connection_id,
                    message:
                        Message::Response {
                            request_id,
                            response,
                        },
                })) if request_id == expected => {
                    self.remaining()?;
                    if peer != self.peer || connection_id != self.connection {
                        return Err(JoinError::WrongPeer);
                    }
                    return Ok(response);
                }
                SwarmEvent::Behaviour(BehaviourEvent::Pairing(Event::OutboundFailure {
                    request_id,
                    error,
                    ..
                })) if request_id == expected => return Err(JoinError::Transport(error)),
                _ => {}
            }
        }
    }
}

// Only Channel::connect uses this conversion. Once Hello can have been sent,
// an I/O failure is ambiguous, so it cannot trigger candidate fallback.
fn initial_failure(error: JoinError) -> JoinError {
    let missed = match &error {
        JoinError::Expired => true,
        JoinError::Dial(DialError::Transport(failures)) => {
            !failures.is_empty()
                && failures.iter().all(|(_, failure)| {
                    matches!(failure, TransportError::Other(error) if !identity_denied(error))
                })
        }
        _ => false,
    };
    if missed {
        JoinError::CandidateMiss(CandidateMiss::Transport)
    } else {
        error
    }
}

fn identity_denied(error: &io::Error) -> bool {
    let mut cause = Some(error as &(dyn Error + 'static));
    while let Some(error) = cause {
        if matches!(
            error.downcast_ref::<libp2p::webrtc_websys::Error>(),
            Some(
                libp2p::webrtc_websys::Error::Authentication(_)
                    | libp2p::webrtc_websys::Error::UnknownRemotePeerId
            )
        ) {
            return true;
        }
        if let Some(io_error) = error.downcast_ref::<io::Error>() {
            if io_error.kind() == io::ErrorKind::PermissionDenied {
                return true;
            }
            cause = io_error.get_ref().map(|inner| inner as &dyn Error);
        } else {
            cause = error.source();
        }
    }
    false
}

fn unix_time() -> Result<Duration, JoinError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| JoinError::InvalidClock)
}
