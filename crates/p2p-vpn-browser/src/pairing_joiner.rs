//! Pairing-only WebRTC Direct client. The caller keeps the identity and owns
//! persistence, membership installation, and subsequent VPN connections.

use std::time::Duration;

use futures::{FutureExt, StreamExt, pin_mut, select_biased};
use gloo_timers::future::TimeoutFuture;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder,
    multiaddr::Protocol,
    request_response::{self, Event, Message, ProtocolSupport},
    swarm::{ConnectionId, DialError, SwarmEvent, dial_opts::DialOpts},
};
use p2p_vpn::{
    config::RouteConfig,
    identity::NodeIdentity,
    pairing::{
        PairingAcceptanceMode, PairingError, PairingOffer, PairingRequestOptions, PairingResponse,
        build_named_pairing_request_at,
    },
    pairing_code::{
        PairingCode, PairingCodeError, authenticate_pairing_request,
        open_pairing_code_challenge_v2_at, pairing_request_transcript_sha256,
        start_pairing_code_hello_v2_at,
    },
    runtime::pairing_code::{
        PAIRING_CODE_V2_PROTOCOL, PairingCodeRejectionReason, PairingCodeV2Codec,
        PairingCodeV2Request, PairingCodeV2Response,
    },
};
use web_time::{Instant, SystemTime, UNIX_EPOCH};

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
    validate_address(&dial_address, expected_peer)?;
    if options.timeout.is_zero() || options.timeout > MAX_WAIT {
        return Err(JoinError::InvalidTimeout);
    }
    let deadline = Instant::now() + options.timeout;
    let keys = identity.keypair().map_err(|_| JoinError::InvalidIdentity)?;
    if keys.public().to_peer_id().to_string() != identity.peer_id {
        return Err(JoinError::InvalidIdentity);
    }
    let mut channel = Channel::connect(keys, expected_peer, dial_address, deadline).await?;
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
        PairingCodeV2Response::Rejected { reason } => return Err(JoinError::Rejected(reason)),
        _ => return Err(JoinError::UnexpectedResponse),
    };
    let (offer, session) = open_pairing_code_challenge_v2_at(
        pending,
        &challenge,
        expected_peer,
        unix_time()?.as_secs(),
    )
    .map_err(JoinError::Code)?;
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

    let mut outgoing = PairingCodeV2Request::Submit {
        request: Box::new(request),
    };
    let mut on_pending = Some(on_pending);
    let mut pending_ticket = None;
    loop {
        match channel.request(outgoing).await? {
            PairingCodeV2Response::Accepted { response } => {
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
            PairingCodeV2Response::Pending {
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
                outgoing = PairingCodeV2Request::Poll { ticket };
            }
            PairingCodeV2Response::Rejected { reason } => return Err(JoinError::Rejected(reason)),
            PairingCodeV2Response::Challenge { .. } => return Err(JoinError::UnexpectedResponse),
        }
    }
}

fn validate_address(address: &Multiaddr, expected_peer: PeerId) -> Result<(), JoinError> {
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

type Behaviour = request_response::Behaviour<PairingCodeV2Codec>;
type PairingEvent = Event<PairingCodeV2Request, PairingCodeV2Response>;

struct Channel {
    swarm: Swarm<Behaviour>,
    peer: PeerId,
    connection: ConnectionId,
    deadline: Instant,
    wall_limit: Duration,
}

impl Channel {
    async fn connect(
        keys: libp2p::identity::Keypair,
        peer: PeerId,
        address: Multiaddr,
        deadline: Instant,
    ) -> Result<Self, JoinError> {
        let mut swarm = SwarmBuilder::with_existing_identity(keys)
            .with_wasm_bindgen()
            .with_other_transport(|key| {
                libp2p::webrtc_websys::Transport::new(libp2p::webrtc_websys::Config::new(key))
            })
            .expect("adding the WebRTC transport is infallible")
            .with_behaviour(|_| {
                Behaviour::with_codec(
                    PairingCodeV2Codec,
                    [(
                        StreamProtocol::new(PAIRING_CODE_V2_PROTOCOL),
                        ProtocolSupport::Outbound,
                    )],
                    request_response::Config::default()
                        .with_request_timeout(REQUEST_TIMEOUT)
                        .with_max_concurrent_streams(1),
                )
            })
            .expect("adding the pairing behaviour is infallible")
            .with_swarm_config(|config| config.with_idle_connection_timeout(MAX_WAIT))
            .build();
        let dial = DialOpts::peer_id(peer).addresses(vec![address]).build();
        let connection = dial.connection_id();
        swarm.dial(dial).map_err(JoinError::Dial)?;
        let mut channel = Self {
            swarm,
            peer,
            connection,
            deadline,
            wall_limit: Duration::MAX,
        };
        loop {
            if let SwarmEvent::ConnectionEstablished {
                connection_id,
                peer_id,
                ..
            } = channel.next_event().await?
                && connection_id == connection
            {
                return if peer_id == peer {
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

    async fn next_event(&mut self) -> Result<SwarmEvent<PairingEvent>, JoinError> {
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

    async fn request(
        &mut self,
        message: PairingCodeV2Request,
    ) -> Result<PairingCodeV2Response, JoinError> {
        self.remaining()?;
        let expected = self.swarm.behaviour_mut().send_request(&self.peer, message);
        loop {
            match self.next_event().await? {
                SwarmEvent::Behaviour(Event::Message {
                    peer,
                    connection_id,
                    message:
                        Message::Response {
                            request_id,
                            response,
                        },
                }) if request_id == expected => {
                    self.remaining()?;
                    if peer != self.peer || connection_id != self.connection {
                        return Err(JoinError::WrongPeer);
                    }
                    return Ok(response);
                }
                SwarmEvent::Behaviour(Event::OutboundFailure {
                    request_id, error, ..
                }) if request_id == expected => return Err(JoinError::Transport(error)),
                _ => {}
            }
        }
    }
}

fn unix_time() -> Result<Duration, JoinError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| JoinError::InvalidClock)
}
