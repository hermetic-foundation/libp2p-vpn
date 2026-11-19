//! Checkpoint synchronization for the browser's single pinned transport peer.
//! The host owns the foreground event loop, forwarding projection, and protected store.
//! Provision a verified retained seed and separate capability before selecting
//! checkpoint mode. Never export credentials with generic configuration.

use std::{collections::HashMap, time::Duration};

use libp2p::{PeerId, request_response as rr};
use p2p_vpn::{
    config::membership_tag,
    identity::NodeIdentity,
    membership::checkpoint::{
        BranchSelection, CooperativeMembershipState, MembershipSyncState, NetworkAnchor,
        NetworkCapability, RetainedCheckpointState, SnapshotChallenge, SnapshotRank,
    },
    runtime::control::{
        ControlCapabilities, ControlRejectionReason,
        checkpoint::{
            CheckpointCapabilities, CheckpointCodec, CheckpointPageRequest, CheckpointPageResponse,
            CheckpointProgress, CheckpointRejection, CheckpointSync, CheckpointSyncError,
            CheckpointSyncIndicator, CheckpointSyncLimits, MAX_TRANSFER_SESSIONS,
        },
        validate_capabilities,
    },
};
use web_time::Instant;

const RESYNC_WINDOW: Duration = Duration::from_secs(15);
const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

pub type CheckpointBehaviour = rr::Behaviour<CheckpointCodec>;
pub type CheckpointEvent = rr::Event<CheckpointPageRequest, CheckpointPageResponse>;

#[derive(Clone, PartialEq, Eq)]
struct PeerHint {
    descriptor: CheckpointCapabilities,
    hostname_inventory: Option<[u8; 32]>,
}

struct Round {
    candidate: CooperativeMembershipState,
    challenge: SnapshotChallenge,
    deadline: Instant,
}

struct OutstandingPage {
    id: rr::OutboundRequestId,
    request: CheckpointPageRequest,
}

/// Checkpoint mode is chosen by trusted bootstrap, never by a peer advertisement.
/// There is no legacy authority or isolated timeout activation in this driver.
pub struct CheckpointDriver {
    peer: PeerId,
    identity: NodeIdentity,
    network_name: String,
    membership_tag: String,
    secret: Box<[u8]>,
    state: CooperativeMembershipState,
    enrollment_floor: Option<SnapshotRank>,
    transfer: CheckpointSync,
    hint: Option<PeerHint>,
    attempted_hint: Option<PeerHint>,
    retry_at: Option<Instant>,
    round: Option<Round>,
    outbound: Option<OutstandingPage>,
    inbound: HashMap<rr::InboundRequestId, SnapshotChallenge>,
}

impl CheckpointDriver {
    /// `anchor`, `secret`, the retained JSON, and any enrollment floor must come
    /// from protected local state or explicitly approved provisioning. A pending
    /// enrollment must restore its floor across restarts until durable activation.
    pub fn restore(
        identity: NodeIdentity,
        peer: PeerId,
        network_name: String,
        anchor: NetworkAnchor,
        secret: Box<[u8]>,
        retained_json: &[u8],
        enrollment_floor: Option<SnapshotRank>,
    ) -> Result<Self, CheckpointSyncError> {
        let local_peer = identity
            .keypair()
            .map_err(|_| CheckpointSyncError::Invalid("local checkpoint identity"))?
            .public()
            .to_peer_id();
        if local_peer.to_string() != identity.peer_id || local_peer == peer {
            return Err(CheckpointSyncError::WrongPeer);
        }
        if let Some(floor) = enrollment_floor {
            floor.validate()?;
        }
        let capability = NetworkCapability::from_secret(anchor.clone(), Some(&secret))?;
        let retained = RetainedCheckpointState::decode(retained_json, &capability)?;
        let state =
            CooperativeMembershipState::restore(capability, identity.peer_id.clone(), retained)?;
        Ok(Self {
            peer,
            identity,
            membership_tag: membership_tag(&network_name, &secret),
            network_name,
            secret,
            state,
            enrollment_floor,
            transfer: CheckpointSync::new(local_peer, anchor, CheckpointSyncLimits::default())?,
            hint: None,
            attempted_hint: None,
            retry_at: None,
            round: None,
            outbound: None,
            inbound: HashMap::new(),
        })
    }

    pub fn state(&self) -> &CooperativeMembershipState {
        &self.state
    }

    pub fn anchor(&self) -> &NetworkAnchor {
        &self.state.snapshot().payload.anchor
    }

    pub fn membership_tag(&self) -> &str {
        &self.membership_tag
    }

    pub fn decorate_capabilities(
        &self,
        mut caps: ControlCapabilities,
        wall_now: u64,
    ) -> Result<ControlCapabilities, CheckpointSyncError> {
        caps.network_name.clone_from(&self.network_name);
        caps.membership_tag = Some(self.membership_tag.clone());
        caps.member_records.clear();
        caps.hostname_records.clear();
        caps.supports_membership_record_pages = false;
        caps.membership_records_snapshot = None;
        caps.membership_record_count = 0;
        let local_active = self.local_active_at(wall_now);
        if self.state.sync_state() != MembershipSyncState::Participating || !local_active {
            caps.advertised_routes.clear();
        }
        let mut caps = caps.with_checkpoint(&self.state)?;
        let descriptor = caps.checkpoint.as_mut().expect("descriptor just attached");
        if self.round.is_some() {
            descriptor.sync = CheckpointSyncIndicator::Resyncing;
        } else if descriptor.sync == CheckpointSyncIndicator::Participating && !local_active {
            descriptor.sync = CheckpointSyncIndicator::Excluded;
        }
        Ok(caps)
    }

    /// Consume only authenticated control messages matched to the pinned peer.
    /// Success permits checkpoint traffic, not packets or route advertisements.
    pub fn observe_capabilities(
        &mut self,
        peer: PeerId,
        caps: &ControlCapabilities,
    ) -> Result<(), ControlRejectionReason> {
        if peer != self.peer {
            return Err(ControlRejectionReason::UnauthorizedPeer);
        }
        if let Some(reason) =
            validate_capabilities(caps, &self.network_name, Some(&self.membership_tag), &[])
        {
            return Err(reason);
        }
        let descriptor = caps
            .checkpoint
            .as_ref()
            .ok_or(ControlRejectionReason::InvalidMembershipRecord)?;
        descriptor
            .validate_for(self.anchor())
            .map_err(|_| ControlRejectionReason::InvalidMembershipRecord)?;
        self.hint = Some(PeerHint {
            descriptor: descriptor.clone(),
            hostname_inventory: caps.checkpoint_hostname_inventory,
        });
        Ok(())
    }

    /// Tick while polling the swarm, even when it yields no event. Use the
    /// dedicated checkpoint behaviour; the driver never dials from a hint.
    pub fn drive_sync(
        &mut self,
        wire: &mut CheckpointBehaviour,
        now: Instant,
    ) -> Result<(), CheckpointSyncError> {
        self.transfer.cleanup(now);
        if self.round.is_some() || self.outbound.is_some() || !wire.is_connected(&self.peer) {
            return Ok(());
        }
        let Some(hint) = self.hint.as_ref() else {
            return Ok(());
        };
        if matches!(
            hint.descriptor.sync,
            CheckpointSyncIndicator::Excluded | CheckpointSyncIndicator::ResyncRequired
        ) || (self.attempted_hint.as_ref() == Some(hint)
            && self.retry_at.is_some_and(|retry_at| now < retry_at))
        {
            return Ok(());
        }

        let mut candidate = self.state.clone();
        let challenge = candidate.begin_resync(now, RESYNC_WINDOW)?;
        let deadline = now + RESYNC_WINDOW;
        let request = match self.transfer.start_request(
            self.peer,
            challenge.clone(),
            &self.secret,
            now,
            deadline,
        ) {
            Ok(request) => request,
            // The shared transfer layer retains spent nonce slots until expiry.
            Err(CheckpointSyncError::ResourceLimit) => return Ok(()),
            Err(error) => return Err(error),
        };
        self.attempted_hint = Some(hint.clone());
        self.retry_at = Some(deadline);
        self.round = Some(Round {
            candidate,
            challenge,
            deadline,
        });
        self.send_page(wire, request);
        Ok(())
    }

    /// Route all checkpoint behaviour events here, including terminal failures.
    pub fn handle_event(
        &mut self,
        wire: &mut CheckpointBehaviour,
        event: CheckpointEvent,
        now: Instant,
        wall_now: u64,
    ) -> Result<(), CheckpointSyncError> {
        match event {
            rr::Event::Message {
                peer,
                message:
                    rr::Message::Request {
                        request_id,
                        request,
                        channel,
                    },
                ..
            } => {
                let response = self.respond(peer, &request, now, wall_now);
                let published = matches!(response, CheckpointPageResponse::Page(_));
                let sent = wire.send_response(channel, response).is_ok();
                if published {
                    if sent {
                        self.inbound.insert(request_id, request.challenge);
                    } else {
                        self.transfer.cancel(peer, &request.challenge, now);
                    }
                }
            }
            rr::Event::Message {
                peer,
                message:
                    rr::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(request) = self.take_page(peer, request_id)
                    && self.owns_round(&request)
                    && let Err(error) = self.accept_page(wire, &request, response, now, wall_now)
                {
                    self.cancel_round(now);
                    return Err(error);
                }
            }
            rr::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                if let Some(request) = self.take_page(peer, request_id)
                    && self.owns_round(&request)
                {
                    self.cancel_round(now);
                    return Err(match error {
                        rr::OutboundFailure::Timeout => CheckpointSyncError::Expired,
                        rr::OutboundFailure::UnsupportedProtocols => {
                            CheckpointSyncError::Invalid("peer does not support checkpoint sync")
                        }
                        _ => CheckpointSyncError::Invalid("checkpoint page request failed"),
                    });
                }
            }
            rr::Event::InboundFailure {
                peer, request_id, ..
            } if peer == self.peer => {
                if let Some(challenge) = self.inbound.remove(&request_id) {
                    self.transfer.cancel(peer, &challenge, now);
                }
            }
            rr::Event::ResponseSent {
                peer, request_id, ..
            } if peer == self.peer => {
                self.inbound.remove(&request_id);
            }
            _ => {}
        }
        Ok(())
    }

    /// Call when the last connection to the pinned peer closes. Keep the old
    /// request ID until its terminal event, but discard its semantic ownership.
    pub fn disconnected(&mut self, now: Instant) {
        self.round = None;
        self.hint = None;
        self.attempted_hint = None;
        self.inbound.clear();
        self.transfer.cancel_peer(self.peer, now);
    }

    /// A due round must contain an authenticated remote offer, including on
    /// restart. Prepare the forwarding update and persist the candidate before
    /// committing this token. Dropping it leaves the installed state unchanged.
    /// If a store write may have succeeded, gate packets and reload the store
    /// rather than continuing with potentially superseded forwarding grants.
    pub fn finish_due(
        &mut self,
        now: Instant,
        wall_now: u64,
    ) -> Result<Option<CheckpointInstall<'_>>, CheckpointSyncError> {
        if self.round.as_ref().is_none_or(|round| now < round.deadline) {
            return Ok(None);
        }
        let Round {
            mut candidate,
            challenge,
            ..
        } = self.round.take().expect("due round");
        self.transfer.cancel(self.peer, &challenge, now);
        let selection = candidate.finish_resync(now, wall_now)?;
        if !selection.observed_remote_offer {
            return Ok(None);
        }
        if let Some(floor) = self.enrollment_floor
            && candidate.snapshot().payload.rank()? < floor
        {
            return Ok(None);
        }
        Ok(Some(CheckpointInstall {
            driver: self,
            candidate,
            selection,
            now,
        }))
    }

    fn send_page(&mut self, wire: &mut CheckpointBehaviour, request: CheckpointPageRequest) {
        // The vendored cancellable-send API uses std::time::Instant (not WASM).
        // This behaviour has its own stream timeout; the portable round owns a
        // fixed deadline and drops late events before they can affect authority.
        let id = wire.send_request(&self.peer, request.clone());
        self.outbound = Some(OutstandingPage { id, request });
    }

    fn take_page(
        &mut self,
        peer: PeerId,
        id: rr::OutboundRequestId,
    ) -> Option<CheckpointPageRequest> {
        (peer == self.peer && self.outbound.as_ref().is_some_and(|page| page.id == id))
            .then(|| self.outbound.take().expect("matching page").request)
    }

    fn owns_round(&self, request: &CheckpointPageRequest) -> bool {
        self.round
            .as_ref()
            .is_some_and(|round| round.challenge == request.challenge)
    }

    fn accept_page(
        &mut self,
        wire: &mut CheckpointBehaviour,
        request: &CheckpointPageRequest,
        response: CheckpointPageResponse,
        now: Instant,
        wall_now: u64,
    ) -> Result<(), CheckpointSyncError> {
        let round = self.round.as_mut().expect("matched round");
        if now >= round.deadline {
            return Err(CheckpointSyncError::Expired);
        }
        match self
            .transfer
            .accept_response(self.peer, request, response, &self.secret, now)?
        {
            CheckpointProgress::More(next) => {
                if !wire.is_connected(&self.peer) {
                    return Err(CheckpointSyncError::UnknownSession);
                }
                self.send_page(wire, next);
            }
            CheckpointProgress::Complete(offer) => {
                if !offer
                    .payload
                    .snapshot
                    .payload
                    .member(&offer.payload.publisher.peer_id)
                    .is_some_and(|member| member.active_at(wall_now))
                {
                    return Err(CheckpointSyncError::Unauthorized);
                }
                round.candidate.collect_offer(&offer, self.peer, now)?;
            }
        }
        Ok(())
    }

    fn cancel_round(&mut self, now: Instant) {
        if let Some(round) = self.round.take() {
            self.transfer.cancel(self.peer, &round.challenge, now);
        }
    }

    fn local_active_at(&self, wall_now: u64) -> bool {
        self.state
            .snapshot()
            .payload
            .member(&self.identity.peer_id)
            .is_some_and(|member| member.active_at(wall_now))
    }

    fn respond(
        &mut self,
        peer: PeerId,
        request: &CheckpointPageRequest,
        now: Instant,
        wall_now: u64,
    ) -> CheckpointPageResponse {
        let reason = if peer != self.peer {
            CheckpointRejection::Unauthorized
        } else if self.inbound.len() >= MAX_TRANSFER_SESSIONS {
            CheckpointRejection::Busy
        } else if self.state.sync_state() != MembershipSyncState::Participating
            || !self.local_active_at(wall_now)
        {
            CheckpointRejection::InvalidTransfer
        } else {
            match self.transfer.respond_at(
                peer,
                request,
                &self.state,
                &self.identity,
                &self.secret,
                now,
                wall_now,
            ) {
                Ok(response) => return response,
                Err(CheckpointSyncError::Unauthorized) => CheckpointRejection::Unauthorized,
                Err(CheckpointSyncError::ResourceLimit) => CheckpointRejection::Busy,
                Err(CheckpointSyncError::Expired) => CheckpointRejection::Expired,
                Err(_) => CheckpointRejection::InvalidTransfer,
            }
        };
        CheckpointPageResponse::rejected(request, reason)
    }
}

/// Selected authority that has not yet been installed. Persist `state().retained()`
/// and clear any stored enrollment floor in the same atomic transaction.
#[must_use]
pub struct CheckpointInstall<'a> {
    driver: &'a mut CheckpointDriver,
    candidate: CooperativeMembershipState,
    selection: BranchSelection,
    now: Instant,
}

impl CheckpointInstall<'_> {
    pub fn state(&self) -> &CooperativeMembershipState {
        &self.candidate
    }

    /// Call only after durable persistence and forwarding projection commit.
    pub fn commit(self) -> BranchSelection {
        let Self {
            driver,
            candidate,
            selection,
            now,
        } = self;
        driver.state = candidate;
        driver.enrollment_floor = None;
        driver.retry_at = Some(now + REFRESH_INTERVAL);
        if selection.sync_state == MembershipSyncState::Excluded {
            driver.transfer.cancel_peer(driver.peer, now);
        }
        selection
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::collections::HashSet;

    use futures::StreamExt;
    use libp2p::{Swarm, SwarmBuilder, noise, swarm::SwarmEvent, tcp, yamux};
    use p2p_vpn::{
        config::Config,
        membership::checkpoint::{CheckpointMember, MembershipChange, SnapshotPolicy},
        runtime::{control::checkpoint, forward::Forwarder},
    };

    use super::*;

    const WALL_NOW: u64 = 1_700_000_000;
    const SECRET: [u8; 32] = [41; 32];

    struct Fixture {
        client: CheckpointDriver,
        publisher: NodeIdentity,
        publisher_state: CooperativeMembershipState,
        config: Config,
    }

    fn fixture(wrong_mac_key: bool, remove_client: bool, pending_floor: bool) -> Fixture {
        let anchor = NetworkAnchor::new([67; 32]).unwrap();
        let mut used_addresses = HashSet::new();
        let mut new_identity = || loop {
            let identity = NodeIdentity::generate_ed25519().unwrap();
            let peer = identity.peer_id.parse().unwrap();
            if used_addresses.insert(p2p_vpn::route::builtin_ipv4(p2p_vpn::PeerId::from_libp2p(
                peer,
            ))) {
                break identity;
            }
        };
        let local = new_identity();
        let publisher = new_identity();
        let extra = new_identity();
        let peer = publisher.peer_id.parse().unwrap();
        let mut members = vec![
            CheckpointMember::new(&publisher).unwrap(),
            CheckpointMember::new(&local).unwrap(),
            CheckpointMember::new(&extra).unwrap(),
        ];
        members.extend((0..31).map(|_| CheckpointMember::new(&new_identity()).unwrap()));
        let cap = NetworkCapability::from_secret(anchor.clone(), Some(&SECRET)).unwrap();
        let seed = CooperativeMembershipState::bootstrap_at(
            cap,
            publisher.peer_id.clone(),
            members.clone(),
            SnapshotPolicy::default(),
            WALL_NOW,
        )
        .unwrap();
        let mut publisher_state = if wrong_mac_key {
            CooperativeMembershipState::bootstrap_at(
                NetworkCapability::from_secret(anchor.clone(), Some(&[82; 32])).unwrap(),
                publisher.peer_id.clone(),
                members,
                SnapshotPolicy::default(),
                WALL_NOW,
            )
            .unwrap()
        } else {
            seed.clone()
        };
        let removed = if remove_client {
            local.peer_id.clone()
        } else {
            extra.peer_id
        };
        let mutation = publisher_state
            .sign_mutation_at(
                &publisher,
                MembershipChange::RemoveMember(removed),
                WALL_NOW,
            )
            .unwrap();
        publisher_state
            .apply_mutation_at(&mutation, WALL_NOW)
            .unwrap();

        let config = serde_json::from_value(serde_json::json!({
            "network": { "name": "lab", "local_peer": local.peer_id, "private_key": local.private_key },
            "peers": [{ "id": publisher.peer_id, "addresses": [] }],
        })).unwrap();
        let client = CheckpointDriver::restore(
            local,
            peer,
            "lab".into(),
            anchor,
            Box::new(SECRET),
            &serde_json::to_vec(&seed.retained()).unwrap(),
            pending_floor.then(|| {
                let mut floor = publisher_state.snapshot().payload.rank().unwrap();
                floor.authority_revision += 1;
                floor
            }),
        )
        .unwrap();
        Fixture {
            client,
            publisher,
            publisher_state,
            config,
        }
    }

    fn swarm(identity: &NodeIdentity) -> Swarm<CheckpointBehaviour> {
        SwarmBuilder::with_existing_identity(identity.keypair().unwrap())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_behaviour(|_| checkpoint::behaviour(4))
            .unwrap()
            .build()
    }

    async fn transfer(
        fixture: &mut Fixture,
        first_page_only: bool,
    ) -> (usize, Instant, Result<(), CheckpointSyncError>) {
        tokio::time::timeout(Duration::from_secs(10), async {
            let Fixture { client, publisher, publisher_state, .. } = fixture;
            let mut server = swarm(publisher);
            let mut receiver = swarm(&client.identity);
            let mut publisher_wire = CheckpointSync::new(
                client.peer,
                client.anchor().clone(),
                CheckpointSyncLimits::default(),
            ).unwrap();
            server.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
            let address = loop {
                if let SwarmEvent::NewListenAddr { address, .. } = server.select_next_some().await {
                    break address.with(libp2p::multiaddr::Protocol::P2p(client.peer));
                }
            };
            receiver.dial(address).unwrap();
            let mut pages = 0;
            loop {
                tokio::select! {
                    event = server.select_next_some() => {
                        if let SwarmEvent::Behaviour(rr::Event::Message {
                            peer, message: rr::Message::Request { request, channel, .. }, ..
                        }) = event {
                            assert_eq!(&peer, receiver.local_peer_id());
                            let response = publisher_wire.respond_at(
                                peer, &request, publisher_state, publisher, &SECRET, Instant::now(), WALL_NOW,
                            ).unwrap();
                            server.behaviour_mut().send_response(channel, response).unwrap();
                            pages += 1;
                        }
                    }
                    event = receiver.select_next_some() => match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            let mut advertised = ControlCapabilities::local("lab", Some(client.membership_tag().into()), 1280)
                                .with_checkpoint(publisher_state).unwrap();
                            // Even a higher hinted rank must not replace the authenticated rank.
                            advertised.checkpoint.as_mut().unwrap().boundary.authority_revision += 100;
                            client.observe_capabilities(peer_id, &advertised).unwrap();
                            client.drive_sync(receiver.behaviour_mut(), Instant::now()).unwrap();
                            let caps = client.decorate_capabilities(ControlCapabilities::local("lab", None, 1280), WALL_NOW).unwrap();
                            assert_eq!(caps.checkpoint.unwrap().sync, CheckpointSyncIndicator::Resyncing);
                        }
                        SwarmEvent::Behaviour(event) => {
                            let deadline = client.round.as_ref().unwrap().deadline;
                            let result = client.handle_event(receiver.behaviour_mut(), event, Instant::now(), WALL_NOW);
                            if first_page_only && client.transfer.stats().buffered_bytes > 0 {
                                return (pages, deadline, result);
                            }
                            if result.is_err() || client.outbound.is_none() {
                                assert_eq!(client.transfer.stats().buffered_bytes, 0);
                                return (pages, deadline, result);
                            }
                        }
                        _ => (),
                    }
                }
            }
        }).await.expect("checkpoint transfer exceeded ten seconds")
    }

    #[tokio::test]
    async fn installs_only_a_complete_authenticated_native_transfer() {
        for remove_client in [false, true] {
            let mut fixture = fixture(false, remove_client, false);
            let client = &fixture.client;
            let mut forwarder = Forwarder::from_checkpoint_config(
                &fixture.config,
                client.state(),
                client.anchor(),
                WALL_NOW,
            )
            .unwrap();
            assert!(!forwarder.is_configured_transport_peer(client.peer));

            let (pages, deadline, result) = transfer(&mut fixture, false).await;
            result.unwrap();
            assert!(pages > 1);
            let client = &mut fixture.client;
            let peer = client.peer;
            let anchor = client.anchor().clone();
            assert!(
                client
                    .finish_due(deadline - Duration::from_millis(1), WALL_NOW)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(client.state().snapshot().payload.authority_revision, 0);
            let install = client.finish_due(deadline, WALL_NOW).unwrap().unwrap();
            assert_eq!(
                install.state().snapshot(),
                fixture.publisher_state.snapshot()
            );
            let update = forwarder
                .prepare_checkpoint_update(install.state(), &anchor, WALL_NOW)
                .unwrap();
            assert!(!forwarder.is_configured_transport_peer(peer));
            let persisted = serde_json::to_vec(&install.state().retained()).unwrap();
            forwarder.commit_checkpoint_update(update).unwrap();
            let selection = install.commit();
            assert!(selection.observed_remote_offer);
            assert_eq!(selection.selected.authority_revision, 1);
            assert_eq!(forwarder.is_configured_transport_peer(peer), !remove_client);
            let caps = client
                .decorate_capabilities(ControlCapabilities::local("lab", None, 1280), WALL_NOW)
                .unwrap();
            let descriptor = caps.checkpoint.unwrap();
            assert_eq!(descriptor.boundary, selection.selected);
            assert_eq!(descriptor.active_member_count, 33);
            assert_eq!(
                descriptor.sync,
                if remove_client {
                    CheckpointSyncIndicator::Excluded
                } else {
                    CheckpointSyncIndicator::Participating
                }
            );
            assert_eq!(
                caps.membership_tag.as_deref(),
                Some(client.membership_tag())
            );
            assert!(caps.checkpoint_hostname_inventory.is_some());

            let mut requester =
                CheckpointSync::new(peer, anchor.clone(), CheckpointSyncLimits::default()).unwrap();
            let request = requester
                .start_request(
                    client.identity.peer_id.parse().unwrap(),
                    SnapshotChallenge {
                        anchor: anchor.clone(),
                        nonce: [94; 32],
                    },
                    &SECRET,
                    deadline,
                    deadline + RESYNC_WINDOW,
                )
                .unwrap();
            let response = client.respond(peer, &request, deadline, WALL_NOW);
            assert_eq!(
                matches!(response, CheckpointPageResponse::Page(_)),
                !remove_client
            );
            assert_eq!(
                client.transfer.stats().publisher_sessions,
                usize::from(!remove_client)
            );
            client.disconnected(deadline);
            assert_eq!(client.transfer.stats().buffered_bytes, 0);

            let restarted = CheckpointDriver::restore(
                client.identity.clone(),
                peer,
                "lab".into(),
                anchor,
                Box::new(SECRET),
                &persisted,
                None,
            )
            .unwrap();
            assert_eq!(restarted.state().snapshot(), client.state().snapshot());
            assert_eq!(
                restarted.state().sync_state(),
                MembershipSyncState::ResyncRequired
            );
        }
    }

    #[tokio::test]
    async fn rejects_wrong_mac_and_offers_below_protected_enrollment_floor() {
        for wrong_mac_key in [false, true] {
            let mut fixture = fixture(wrong_mac_key, false, true);
            let (pages, deadline, result) = transfer(&mut fixture, false).await;
            assert!(pages > 1);
            if wrong_mac_key {
                assert!(matches!(result, Err(CheckpointSyncError::Core(_))));
            } else {
                result.unwrap();
            }
            let client = &mut fixture.client;
            assert!(client.finish_due(deadline, WALL_NOW).unwrap().is_none());
            assert_eq!(
                client.state().sync_state(),
                MembershipSyncState::ResyncRequired
            );
            assert!(client.enrollment_floor.is_some());
        }
    }

    #[tokio::test]
    async fn deadline_retires_partial_transfer_without_activating_the_seed() {
        let mut fixture = fixture(false, false, false);
        let (pages, deadline, result) = transfer(&mut fixture, true).await;
        result.unwrap();
        assert_eq!(pages, 1);
        let client = &mut fixture.client;
        assert!(client.transfer.stats().buffered_bytes > 0);
        assert!(client.finish_due(deadline, WALL_NOW).unwrap().is_none());
        assert_eq!(client.transfer.stats().buffered_bytes, 0);
        assert_eq!(
            client.state().sync_state(),
            MembershipSyncState::ResyncRequired
        );
    }

    #[test]
    fn missing_or_wrong_scope_descriptor_cannot_begin_legacy_authority() {
        let Fixture {
            mut client,
            publisher_state,
            ..
        } = fixture(false, false, false);
        let caps = ControlCapabilities::local("lab", Some(client.membership_tag().into()), 1280);
        assert!(client.observe_capabilities(client.peer, &caps).is_err());
        let mut caps = caps.with_checkpoint(&publisher_state).unwrap();
        caps.checkpoint.as_mut().unwrap().anchor = NetworkAnchor::new([29; 32]).unwrap();
        assert!(client.observe_capabilities(client.peer, &caps).is_err());
        assert!(client.hint.is_none());
        assert_eq!(
            client.state().sync_state(),
            MembershipSyncState::ResyncRequired
        );
    }
}
