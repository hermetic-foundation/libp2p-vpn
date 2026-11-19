//! One explicitly addressed, relay-only v2 code invitation.

use std::{borrow::Cow, net::IpAddr, time::Duration};

use libp2p::{
    Multiaddr, PeerId, multiaddr::Protocol, request_response::InboundRequestId, swarm::ConnectionId,
};
use p2p_vpn::{
    config::{Config, DiscoveryConfig, InitConfigTemplate, PeerConfig, RouteConfig},
    identity::NodeIdentity,
    membership::{
        MembershipRecordIssueOptions, MembershipRecordSubject, MembershipRole,
        issue_named_membership_record_for_subject_at,
    },
    pairing::{
        MAX_PAIRING_MESSAGE_LEN, PairingOffer, PairingOfferOptions, PairingRequest,
        PairingResponse, PairingResponseOptions, build_pairing_response_at,
        export_code_pairing_offer_at,
    },
    pairing_code::{
        PairingCode, PairingCodeSession, answer_pairing_code_hello_v2_at,
        verify_pairing_request_code_authentication,
    },
    route::builtin_ipv4,
    runtime::{
        forward::Forwarder,
        pairing_code::{
            PairingCodeRejectionReason as Rejection, PairingCodeV2Request as Request,
            PairingCodeV2Response as Response,
        },
    },
};
use wasm_bindgen::prelude::*;
use web_time::{Instant, SystemTime, UNIX_EPOCH};

use crate::{
    BrowserVpn,
    browser::code_invitation::{Event, InvitationTransport},
    file_inviter_core::{
        open_legacy_config, prepare_legacy_approval, validate_legacy_request, validate_new_joiner,
    },
    membership_store::MembershipStore,
    relay::RelayRoute,
};

const INVITATION_SECONDS: u64 = 300;
// Leave room for browser setup before the companion's 120-second lease ends.
const SCOPED_INVITATION_SECONDS: u64 = 110;
const RESERVATION_SECONDS: u64 = 15;
const MAX_HELLOS: u8 = 8;

struct Approval {
    peer: PeerId,
    request: Box<PairingRequest>,
    offer: PairingOffer,
    ticket: String,
    response: Option<Box<PairingResponse>>,
    sending: Option<InboundRequestId>,
    delivered: bool,
}

struct PakeAttempt {
    session: PairingCodeSession,
    issued_at: u64,
    connection: ConnectionId,
    peer: PeerId,
}

enum Profile {
    New {
        inviter_ip: IpAddr,
        joiner_ip: IpAddr,
        store: Option<MembershipStore>,
    },
    Existing {
        store: MembershipStore,
        advertised_circuit: String,
    },
}

impl Profile {
    fn assigned_ip(&self, peer: PeerId) -> IpAddr {
        match self {
            Self::New { joiner_ip, .. } => *joiner_ip,
            Self::Existing { .. } => builtin_ipv4(p2p_vpn::PeerId::from_libp2p(peer)).into(),
        }
    }

    fn offer_config<'a>(&self, config: &'a Config) -> Cow<'a, Config> {
        let Self::Existing {
            advertised_circuit, ..
        } = self
        else {
            return Cow::Borrowed(config);
        };
        // Advertise only this invitation's circuit. Keep the inviter's local
        // endpoints and configured peers unchanged for activation.
        let mut config = config.clone();
        config.network.external_addresses = vec![advertised_circuit.clone()];
        config.network.listen_addresses.clear();
        config.network.relay.reservations.clear();
        Cow::Owned(config)
    }
}

/// Owns a browser-local legacy identity and a single invitation.
/// Only pairing is served until the approved VPN authority has been installed.
#[wasm_bindgen]
pub struct BrowserCodeInviter {
    config: Config,
    transport: InvitationTransport,
    profile: Profile,
    unpinned: bool,
    code: PairingCode,
    expires: u64,
    hellos: u8,
    session: Option<PakeAttempt>,
    approval: Option<Approval>,
    cancelled: bool,
}

#[wasm_bindgen]
impl BrowserCodeInviter {
    /// Generate an inviter identity without reading or exporting any private key.
    #[wasm_bindgen(constructor)]
    pub fn new(
        network_name: &str,
        inviter_vpn_ip: &str,
        joiner_vpn_ip: &str,
        joiner_peer: &str,
        relay_entrance: &str,
    ) -> Result<BrowserCodeInviter, JsError> {
        if network_name.is_empty() || network_name.len() > 256 {
            return Err(JsError::new("Invalid invitation network name"));
        }
        let inviter_ip: IpAddr = inviter_vpn_ip.parse().map_err(js)?;
        let joiner_ip: IpAddr = joiner_vpn_ip.parse().map_err(js)?;
        if inviter_ip == joiner_ip || inviter_ip.is_ipv4() != joiner_ip.is_ipv4() {
            return Err(JsError::new(
                "Invitation requires distinct same-family VPN addresses",
            ));
        }
        let peer: PeerId = joiner_peer.parse().map_err(js)?;
        let route = invitation_route(relay_entrance, peer)?;
        let config = new_network_config(network_name, inviter_ip, &route)?;
        Self::start(
            config,
            route,
            Profile::New {
                inviter_ip,
                joiner_ip,
                store: None,
            },
        )
    }

    /// Controlled incoming enrollment. The caller must isolate the explicit
    /// relay transport at the OS boundary; there is no public lookup here.
    #[cfg(feature = "test-hooks")]
    pub async fn open_unpinned_controlled(
        network_name: &str,
        inviter_vpn_ip: &str,
        joiner_vpn_ip: &str,
        relay_entrance: &str,
    ) -> Result<BrowserCodeInviter, JsError> {
        if relay_entrance.len() > 512 {
            return Err(JsError::new("Invalid relay entrance"));
        }
        let route = RelayRoute::for_invitation(relay_entrance.parse().map_err(js)?).map_err(js)?;
        Self::open_incoming(network_name, inviter_vpn_ip, joiner_vpn_ip, route).await
    }

    /// Open an incoming invitation from the same-origin companion's prepared
    /// relay. The first address is transport-only; the second is the signed
    /// route and must still be confirmed by the exact relay listener.
    pub async fn open_unpinned_scoped(
        network_name: &str,
        inviter_vpn_ip: &str,
        joiner_vpn_ip: &str,
        relay_peer: &str,
        relay_entrance: &str,
        native_alias: &str,
    ) -> Result<BrowserCodeInviter, JsError> {
        let route = scoped_invitation_route(relay_peer, relay_entrance, native_alias)?;
        let mut inviter =
            Self::open_incoming(network_name, inviter_vpn_ip, joiner_vpn_ip, route).await?;
        inviter.expires = unix_seconds()? + SCOPED_INVITATION_SECONDS;
        Ok(inviter)
    }

    /// Open an exclusive detached invitation on a trusted local legacy config.
    /// The config is neither rewritten nor sent to the companion.
    pub async fn open_existing(
        config_json: &str,
        joiner_peer: &str,
        relay_entrance: &str,
    ) -> Result<BrowserCodeInviter, JsError> {
        let route = invitation_route(relay_entrance, joiner_peer.parse().map_err(js)?)?;
        Self::open_existing_on_route(config_json, route).await
    }

    /// Invite an unknown applicant into a rooted legacy network over a
    /// companion-prepared relay. The legacy config stays in the browser.
    pub async fn open_existing_scoped(
        config_json: &str,
        relay_peer: &str,
        relay_entrance: &str,
        native_alias: &str,
    ) -> Result<BrowserCodeInviter, JsError> {
        let route = scoped_invitation_route(relay_peer, relay_entrance, native_alias)?;
        let mut inviter = Self::open_existing_on_route(config_json, route).await?;
        inviter.expires = unix_seconds()? + SCOPED_INVITATION_SECONDS;
        Ok(inviter)
    }

    pub fn peer_id(&self) -> String {
        self.config.network.local_peer.clone()
    }

    /// Test a poll without an issued ticket, through a separate Noise identity.
    #[cfg(feature = "test-hooks")]
    pub async fn controlled_unsolicited_poll(peer: &str, address: &str) -> Result<bool, JsError> {
        crate::pairing_joiner::controlled_unsolicited_poll(
            peer.parse().map_err(js)?,
            address.parse().map_err(js)?,
        )
        .await
        .map_err(js)
    }

    /// Create the reservation only on explicit request and return its confirmed address.
    pub async fn reserve(&mut self) -> Result<String, JsError> {
        self.require_live()?;
        self.transport.start_reservation()?;
        let deadline = Instant::now() + Duration::from_secs(RESERVATION_SECONDS);
        loop {
            if let Some(address) = self.transport.confirmed_address() {
                return Ok(address);
            }
            if Instant::now() >= deadline {
                self.transport.release_reservation();
                return Err(JsError::new("Invitation relay reservation timed out"));
            }
            self.step(100).await?;
        }
    }

    pub fn code(&self) -> Result<String, JsError> {
        self.require_live()?;
        self.transport
            .confirmed_address()
            .ok_or_else(|| JsError::new("No confirmed invitation reservation"))?;
        Ok(self.code.to_string())
    }

    /// Retire this invitation. An already saved grant remains in the ledger.
    pub fn cancel(&mut self) {
        self.cancelled = true;
        self.session = None;
        self.approval = None;
        self.transport.release_reservation();
    }

    /// Test-only one-shot public-protocol announcement. The caller must
    /// isolate the browser's existing relay transport at the OS boundary.
    #[cfg(feature = "test-hooks")]
    pub async fn publish_locator_controlled(&mut self, alias: &str) -> Result<(), JsError> {
        if alias.len() > p2p_vpn::peer_address_record::browser_advertisement::MAX_CIRCUIT_BYTES {
            return Err(JsError::new("Reservation alias exceeds its size limit"));
        }
        self.announce_locator(alias.parse().map_err(js)?).await
    }

    /// Announce one locator over the already confirmed scoped connection.
    /// This is a local substream write, not a remote DHT storage receipt.
    pub async fn publish_locator_scoped(&mut self) -> Result<(), JsError> {
        let address = self
            .transport
            .scoped_publication_address()
            .ok_or_else(|| JsError::new("Expected a companion-prepared invitation"))?;
        self.announce_locator(address).await
    }

    /// Drive the foreground swarm for one bounded wait.
    pub async fn drive(&mut self, timeout_ms: u32) -> Result<(), JsError> {
        if let Err(error) = self.require_live() {
            self.cancel();
            return Err(error);
        }
        if !(1..=1_000).contains(&timeout_ms) {
            return Err(JsError::new(
                "Invitation drive timeout must be between 1 and 1000 ms",
            ));
        }
        if !self.transport.has_reservation() {
            return Err(JsError::new("No invitation reservation"));
        }
        self.step(timeout_ms).await
    }

    /// Show the authenticated candidate before asking for local approval.
    pub fn pending_candidate(&self) -> Option<String> {
        let candidate = self
            .approval
            .as_ref()
            .filter(|approval| approval.response.is_none())?;
        if self.require_live().is_err() || self.transport.confirmed_address().is_none() {
            return None;
        }
        Some(
            serde_json::json!({
                "peer_id": candidate.request.payload.joiner_peer,
                "requested_hostname": candidate.request.payload.requested_hostname,
                "assigned_vpn_ip": self.profile.assigned_ip(candidate.peer).to_string(),
            })
            .to_string(),
        )
    }

    /// Approve exactly the candidate shown to the local operator. The signed
    /// response is sent only on that authenticated joiner's next poll.
    pub fn approve(&mut self, joiner_peer: &str) -> Result<(), JsError> {
        let now = self.require_live()?;
        if self.transport.confirmed_address().is_none() {
            return Err(JsError::new("No confirmed invitation reservation"));
        }
        let offer_config = self.profile.offer_config(&self.config);
        let approval = self
            .approval
            .as_mut()
            .filter(|approval| {
                approval.response.is_none() && approval.request.payload.joiner_peer == joiner_peer
            })
            .ok_or_else(|| JsError::new("No pending invitation for that peer"))?;

        if let Profile::Existing { store, .. } = &self.profile {
            let (response, ledger) = prepare_legacy_approval(
                &offer_config,
                &approval.offer,
                &approval.request,
                now,
                self.expires - now,
            )
            .map_err(JsError::new)?;
            let mut candidate = self.config.clone();
            candidate.network.member_records = ledger;
            validate_preserved_members(&self.config, &candidate, joiner_peer.parse().map_err(js)?)?;
            store.save(&candidate.network.member_records)?;
            self.config = candidate;
            approval.response = Some(Box::new(response));
            return Ok(());
        }
        let Profile::New {
            inviter_ip,
            joiner_ip,
            store,
        } = &self.profile
        else {
            unreachable!()
        };
        let identity = self.config.identity().map_err(js)?;
        let issue = |member, ip: IpAddr, hostname| {
            let prefix_len = if ip.is_ipv4() { 32 } else { 128 };
            issue_named_membership_record_for_subject_at(
                &identity,
                MembershipRecordIssueOptions {
                    network_name: self.config.network.name.clone(),
                    member,
                    membership_epoch: now,
                    sequence: 1,
                    revoked: false,
                    roles: vec![
                        MembershipRole::OverlayMember,
                        MembershipRole::RouteAuthority,
                    ],
                    route_grants: vec![RouteConfig {
                        prefix: format!("{ip}/{prefix_len}"),
                        metric: 0,
                    }],
                    expires_at_unix_seconds: None,
                },
                hostname,
                now,
            )
            .map_err(js)
        };
        let member_records = vec![
            issue(
                MembershipRecordSubject::from_identity(&identity).map_err(js)?,
                *inviter_ip,
                None,
            )?,
            issue(
                MembershipRecordSubject {
                    peer_id: joiner_peer.to_owned(),
                    public_key: approval.request.payload.joiner_public_key.clone(),
                },
                *joiner_ip,
                approval.request.payload.requested_hostname.as_deref(),
            )?,
        ];
        let response = build_pairing_response_at(
            &self.config,
            &approval.offer,
            PairingResponseOptions {
                joiner_peer: joiner_peer.to_owned(),
                assigned_vpn_ip: Some(joiner_ip.to_string()),
                membership_key: None,
                member_records,
                expires_in_seconds: self.expires - now,
            },
            now,
        )
        .map_err(js)?;
        let mut candidate = self.config.clone();
        candidate.network.member_records = response.payload.member_records.clone();
        candidate.peers.push(PeerConfig {
            id: joiner_peer.to_owned(),
            name: None,
            ip: None,
            vpn_ip: Some(joiner_ip.to_string()),
            addresses: Vec::new(),
            routes: Vec::new(),
        });
        if let Some(store) = store {
            validate_preserved_members(&self.config, &candidate, approval.peer)?;
            store.save(&candidate.network.member_records)?;
        }
        self.config = candidate;
        approval.response = Some(Box::new(response));
        Ok(())
    }

    pub fn delivered(&self) -> bool {
        self.approval
            .as_ref()
            .is_some_and(|approval| approval.delivered)
    }

    /// Install the approved authority on the same swarm without exporting the
    /// inviter's config or replacing the authenticated relay reservation.
    pub async fn into_vpn(self) -> Result<BrowserVpn, JsError> {
        let expiry = self.unpinned.then_some(self.expires);
        if expiry.is_some() {
            self.require_live()?;
        }
        let peer = self
            .approval
            .as_ref()
            .filter(|approval| approval.delivered)
            .map(|approval| approval.peer)
            .ok_or_else(|| JsError::new("Wait for the approved response to be sent"))?;
        let store = match self.profile {
            Profile::New { store, .. } => store,
            Profile::Existing { store, .. } => Some(store),
        };
        let vpn = self.transport.activate(self.config, store, peer).await?;
        if let Some(expires) = expiry
            && unix_seconds()? >= expires
        {
            return Err(JsError::new("Invitation expired"));
        }
        Ok(vpn)
    }
}

impl BrowserCodeInviter {
    async fn open_existing_on_route(config_json: &str, route: RelayRoute) -> Result<Self, JsError> {
        if config_json.len() > 32 * MAX_PAIRING_MESSAGE_LEN {
            return Err(JsError::new("Legacy config exceeds its size limit"));
        }
        let config: Config = serde_json::from_str(config_json)
            .map_err(|_| JsError::new("Invalid legacy inviter config"))?;
        let local = config
            .local_peer()
            .map_err(|_| JsError::new("Invalid inviter identity"))?;
        let store = MembershipStore::open(&config.network.name, &local).await?;
        let config =
            open_legacy_config(config, &store.load()?, unix_seconds()?).map_err(JsError::new)?;
        if config.network.member_records.is_empty() {
            return Err(JsError::new(
                "An existing invitation requires a rooted legacy ledger",
            ));
        }
        if let Some(joiner) = route.selected_peer() {
            validate_new_joiner(&config, joiner).map_err(JsError::new)?;
        }
        let advertised_circuit = route
            .advertised_reservation_addr(local.parse().map_err(js)?)
            .to_string();
        Self::start(
            config,
            route,
            Profile::Existing {
                store,
                advertised_circuit,
            },
        )
    }

    async fn open_incoming(
        network_name: &str,
        inviter_vpn_ip: &str,
        joiner_vpn_ip: &str,
        route: RelayRoute,
    ) -> Result<Self, JsError> {
        if network_name.is_empty() || network_name.len() > 256 {
            return Err(JsError::new("Invalid invitation network name"));
        }
        let inviter_ip: IpAddr = inviter_vpn_ip.parse().map_err(js)?;
        let joiner_ip: IpAddr = joiner_vpn_ip.parse().map_err(js)?;
        if inviter_ip == joiner_ip || inviter_ip.is_ipv4() != joiner_ip.is_ipv4() {
            return Err(JsError::new(
                "Invitation requires distinct same-family VPN addresses",
            ));
        }
        let config = new_network_config(network_name, inviter_ip, &route)?;
        let store = MembershipStore::open(network_name, &config.network.local_peer).await?;
        if !store.load()?.is_empty() {
            return Err(JsError::new(
                "A fresh invitation cannot replace an existing ledger",
            ));
        }
        Self::start(
            config,
            route,
            Profile::New {
                inviter_ip,
                joiner_ip,
                store: Some(store),
            },
        )
    }

    async fn announce_locator(&mut self, address: libp2p::Multiaddr) -> Result<(), JsError> {
        self.require_live()?;
        if self.approval.is_some() {
            return Err(JsError::new("Publish before starting approval"));
        }
        self.transport
            .start_locator_publication(&address, &self.code.global_locator())?;
        let result = self.wait_for_locator_publication(&address).await;
        self.transport.cancel_locator_publication();
        result
    }

    async fn wait_for_locator_publication(
        &mut self,
        address: &libp2p::Multiaddr,
    ) -> Result<(), JsError> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            self.require_live()?;
            match self.transport.locator_publication_result(address)? {
                Some(true) => return Ok(()),
                Some(false) => {
                    return Err(JsError::new("Relay did not accept the Kademlia substream"));
                }
                None if Instant::now() >= deadline => {
                    return Err(JsError::new("Locator announcement timed out"));
                }
                None => self.step(50).await?,
            }
        }
    }

    fn start(config: Config, route: RelayRoute, profile: Profile) -> Result<Self, JsError> {
        let unpinned = route.selected_peer().is_none();
        let transport = InvitationTransport::new(config.clone(), route)?;
        Ok(Self {
            config,
            transport,
            profile,
            unpinned,
            code: PairingCode::generate(),
            expires: unix_seconds()? + INVITATION_SECONDS,
            hellos: 0,
            session: None,
            approval: None,
            cancelled: false,
        })
    }

    fn require_live(&self) -> Result<u64, JsError> {
        if self.cancelled {
            return Err(JsError::new("Invitation cancelled"));
        }
        let now = unix_seconds()?;
        if now >= self.expires {
            return Err(JsError::new("Invitation expired"));
        }
        Ok(now)
    }

    async fn step(&mut self, timeout_ms: u32) -> Result<(), JsError> {
        match self.transport.next(timeout_ms).await? {
            Some(Event::Request {
                peer,
                connection,
                id,
                request,
                channel,
            }) => {
                let response = self.respond(peer, connection, request);
                let accepted = matches!(response, Response::Accepted { .. });
                if self.transport.respond(channel, response)
                    && accepted
                    && let Some(approval) = self.approval.as_mut()
                {
                    approval.sending = Some(id);
                }
            }
            Some(Event::ResponseSent(id)) => {
                if let Some(approval) = self.approval.as_mut()
                    && approval.sending == Some(id)
                {
                    approval.delivered = true;
                }
            }
            Some(Event::CircuitClosed(id)) => {
                if self
                    .session
                    .as_ref()
                    .is_some_and(|attempt| attempt.connection == id)
                {
                    self.session = None;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn respond(&mut self, peer: PeerId, connection: ConnectionId, request: Request) -> Response {
        let Ok(now) = self.require_live() else {
            return rejected(Rejection::Expired);
        };
        match request {
            Request::Hello { hello } if self.approval.is_none() => {
                if self.hellos == MAX_HELLOS {
                    return rejected(Rejection::RateLimited);
                }
                self.hellos += 1;
                if self.unpinned && self.session.is_some() {
                    return rejected(Rejection::Unavailable);
                }
                match answer_pairing_code_hello_v2_at(
                    &self.profile.offer_config(&self.config),
                    &self.code,
                    &hello,
                    peer,
                    PairingOfferOptions {
                        expires_in_seconds: self.expires - now,
                        rendezvous_token: None,
                    },
                    now,
                ) {
                    Ok((challenge, session)) => {
                        self.session = Some(PakeAttempt {
                            session,
                            issued_at: now,
                            peer,
                            connection,
                        });
                        Response::Challenge {
                            challenge: Box::new(challenge),
                        }
                    }
                    Err(_) => rejected(Rejection::Unavailable),
                }
            }
            Request::Submit { request } => {
                if let Some(approval) = &self.approval {
                    return if peer == approval.peer && request == approval.request {
                        self.approval_response(approval)
                    } else {
                        rejected(Rejection::Unavailable)
                    };
                }
                let Some(offer) = self.verified_offer(peer, connection, &request, now) else {
                    return rejected(Rejection::Unavailable);
                };
                let allowed = match self.profile {
                    Profile::Existing { .. } => {
                        validate_legacy_request(&self.config, &offer, &request, now).is_ok()
                    }
                    Profile::New { joiner_ip, .. } => {
                        request.payload.requested_routes.is_empty()
                            && request
                                .payload
                                .requested_vpn_ip
                                .as_deref()
                                .is_none_or(|ip| ip.parse::<IpAddr>().ok() == Some(joiner_ip))
                    }
                };
                if !allowed || !self.transport.select_candidate(peer, connection) {
                    return rejected(Rejection::Unavailable);
                }
                self.session = None;
                let approval = Approval {
                    peer,
                    request,
                    offer,
                    ticket: PairingCode::generate().to_string(),
                    response: None,
                    sending: None,
                    delivered: false,
                };
                let response = self.approval_response(&approval);
                self.approval = Some(approval);
                response
            }
            Request::Poll { ticket } => self
                .approval
                .as_ref()
                .filter(|approval| approval.peer == peer && approval.ticket == ticket)
                .map_or_else(
                    || rejected(Rejection::Unavailable),
                    |approval| self.approval_response(approval),
                ),
            _ => rejected(Rejection::Unavailable),
        }
    }

    fn verified_offer(
        &self,
        peer: PeerId,
        connection: ConnectionId,
        request: &PairingRequest,
        now: u64,
    ) -> Option<PairingOffer> {
        let attempt = self.session.as_ref()?;
        if attempt.peer != peer
            || attempt.connection != connection
            || request.payload.joiner_peer != peer.to_string()
        {
            return None;
        }
        verify_pairing_request_code_authentication(request, &attempt.session).ok()?;
        // Addressed offers are omitted from Submit. Recover the exact signed
        // offer from our own challenge state, never from requester timestamps.
        let offer = export_code_pairing_offer_at(
            &self.profile.offer_config(&self.config),
            PairingOfferOptions {
                expires_in_seconds: self.expires - attempt.issued_at,
                rendezvous_token: Some(attempt.session.rendezvous_token().to_owned()),
            },
            attempt.issued_at,
        )
        .ok()?;
        request.verify_for_offer_at(&offer, now).ok()?;
        Some(offer)
    }

    fn approval_response(&self, approval: &Approval) -> Response {
        approval.response.as_ref().map_or_else(
            || Response::Pending {
                ticket: approval.ticket.clone(),
                expires_at_unix_seconds: self.expires,
            },
            |response| Response::Accepted {
                response: response.clone(),
            },
        )
    }
}

fn new_network_config(
    network_name: &str,
    inviter_ip: IpAddr,
    route: &RelayRoute,
) -> Result<Config, JsError> {
    let identity = NodeIdentity::generate_ed25519().map_err(js)?;
    let local = identity.peer_id.parse().map_err(js)?;
    let address = route.advertised_reservation_addr(local);
    if route.public_reservation_addr(local).is_some()
        && p2p_vpn::peer_address_record::browser_advertisement::circuit_relay(&address, local)
            != Some(route.relay_peer())
    {
        return Err(JsError::new("Expected a public TCP or QUIC relay alias"));
    }
    let config = InitConfigTemplate {
        identity,
        network_name: network_name.to_owned(),
        membership_key: None,
        vpn_ip: Some(inviter_ip.to_string()),
        local_routes: Vec::new(),
        interface_name: "pvbrowser0".into(),
        mtu: 1280,
        listen_addresses: Vec::new(),
        external_addresses: vec![address.to_string()],
        packet_plane: Default::default(),
        bootstrap_peers: Vec::new(),
        peers: Vec::new(),
        discovery: DiscoveryConfig {
            mdns: false,
            kademlia: false,
            kademlia_provider_advertisement: false,
            dcutr: false,
            autonat: false,
            ..DiscoveryConfig::default()
        },
        relay: Default::default(),
    }
    .into_config();
    config.validate_runtime().map_err(js)?;
    Ok(config)
}

fn scoped_invitation_route(
    relay_peer: &str,
    relay_entrance: &str,
    native_alias: &str,
) -> Result<RelayRoute, JsError> {
    if relay_peer.len() > 128 || relay_entrance.len() > 512 || native_alias.len() > 256 {
        return Err(JsError::new("Invalid prepared relay addresses"));
    }
    let native_alias: Multiaddr = native_alias.parse().map_err(js)?;
    let relay = if relay_peer.is_empty() {
        match native_alias.iter().last() {
            Some(Protocol::P2p(peer)) => peer,
            _ => return Err(JsError::new("Prepared relay alias has no peer ID")),
        }
    } else {
        relay_peer.parse().map_err(js)?
    };
    RelayRoute::for_scoped_invitation(relay, relay_entrance.parse().map_err(js)?, native_alias)
        .map_err(js)
}

fn invitation_route(entrance: &str, peer: PeerId) -> Result<RelayRoute, JsError> {
    if entrance.len() > 512 {
        return Err(JsError::new("Invalid invitation relay entrance"));
    }
    let address = format!("{entrance}/p2p-circuit/p2p/{peer}")
        .parse()
        .map_err(js)?;
    RelayRoute::from_dial_addr(&address).map_err(js)
}

fn validate_preserved_members(
    original: &Config,
    next: &Config,
    joiner: PeerId,
) -> Result<(), JsError> {
    let old = Forwarder::from_config(original).map_err(js)?;
    let new = Forwarder::from_config(next).map_err(js)?;
    if !new.is_configured_transport_peer(joiner)
        || old
            .configured_transport_peers()
            .any(|peer| !new.is_configured_transport_peer(peer))
        || original
            .network
            .member_records
            .iter()
            .any(|record| !next.network.member_records.contains(record))
    {
        return Err(JsError::new(
            "Admission cannot replace legacy membership or remove an existing peer",
        ));
    }
    Ok(())
}

fn rejected(reason: Rejection) -> Response {
    Response::Rejected { reason }
}

fn unix_seconds() -> Result<u64, JsError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(js)
}

fn js(error: impl std::fmt::Debug) -> JsError {
    JsError::new(&format!("{error:?}"))
}
