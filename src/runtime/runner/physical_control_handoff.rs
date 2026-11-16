//! Bounded TCP replacement: preserve the old path until an exact candidate replies.

use super::*;
use crate::runtime::physical_network::linux::control::Snapshot;
use crate::runtime::physical_network::linux::egress::RouteEpoch;
use futures::future::AbortHandle;

mod recovery;
use recovery::Recovery;

const MAX_ROUNDS: usize = 64;
const MAX_ACTIVE: usize = 4;
const MAX_PENDING: usize = 8;
const MAX_ATTEMPTS: u8 = 3;
const CONNECT_WINDOW: Duration = Duration::from_secs(20);
const VALIDATION_WINDOW: Duration = Duration::from_secs(10);
const DRAIN_WINDOW: Duration = Duration::from_secs(20);
const DUPLICATE_GRACE: Duration = Duration::from_secs(40);

#[derive(Default)]
pub(crate) struct State {
    rounds: HashMap<Libp2pPeerId, Round>,
    pending: HashMap<request_response::OutboundRequestId, Pending>,
    grace: HashMap<(Libp2pPeerId, ConnectionId), Instant>,
}

struct Round {
    anchor: Snapshot,
    epoch: RouteEpoch,
    attempts: u8,
    phase: Phase,
    draining: HashSet<ConnectionId>,
    recovery: Recovery,
}

enum Phase {
    Waiting(Instant),
    Dialing(ConnectionId, Instant),
    Validating(ConnectionId, request_response::OutboundRequestId),
    Draining(ConnectionId, Instant),
    Exhausted,
}

struct Pending {
    peer: Libp2pPeerId,
    connection: ConnectionId,
    epoch: RouteEpoch,
    owner: u64,
    deadline: Instant,
    cancellation: AbortHandle,
}

impl Round {
    fn candidate(&self) -> Option<ConnectionId> {
        match self.phase {
            Phase::Dialing(id, _) | Phase::Validating(id, _) | Phase::Draining(id, _) => Some(id),
            _ => None,
        }
    }

    fn active(&self) -> bool {
        matches!(
            self.phase,
            Phase::Dialing(..) | Phase::Validating(..) | Phase::Draining(..)
        )
    }

    fn current(&self, routes: &[Snapshot]) -> bool {
        if let Phase::Draining(candidate, _) = self.phase {
            return routes.iter().any(|route| {
                route.peer == self.anchor.peer
                    && route.connection_id == Some(candidate)
                    && (validated_path_is_current(route, &self.epoch)
                        || validated_path_awaits_audit(route))
            });
        }
        if self.active() && !self.anchor.is_live() {
            // Losing the fallback must not cancel an already-owned replacement.
            return self.epoch.is_current();
        }
        routes.iter().any(|route| {
            route.id == self.anchor.id
                && route.peer == self.anchor.peer
                && route.refresh_required() == Some(true)
                && route.inspection_epoch().as_ref() == Some(&self.epoch)
        })
    }
}

impl State {
    pub(crate) fn owns_request(&self, id: request_response::OutboundRequestId) -> bool {
        self.pending.contains_key(&id)
    }

    pub(crate) fn protects(&self, peer: Libp2pPeerId, now: Instant) -> bool {
        self.grace
            .iter()
            .any(|((owner, _), deadline)| *owner == peer && now < *deadline)
            || self.rounds.get(&peer).is_some_and(Round::active)
    }

    pub(crate) fn is_candidate(&self, peer: Libp2pPeerId, id: ConnectionId) -> bool {
        self.rounds.get(&peer).is_some_and(|round| {
            matches!(round.phase, Phase::Dialing(candidate, _) | Phase::Validating(candidate, _) if candidate == id)
        })
    }
}

pub(super) fn observe_established(
    swarm: &mut Swarm<Behaviour>,
    forwarder: &Forwarder,
    connections: &HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
    peer: Libp2pPeerId,
    id: ConnectionId,
    now: Instant,
) {
    if swarm
        .behaviour()
        .connection_retention
        .physical_handoff
        .is_candidate(peer, id)
    {
        set_outbound(swarm.behaviour_mut(), peer, id, false);
    }
    if !forwarder.is_configured_transport_peer(peer)
        || !connections.iter().any(|((other, cid), endpoint)| {
            *other == peer
                && *cid != id
                && path_kind_for_endpoint(endpoint) == PathKind::DirectTcpStream
        })
        || swarm
            .behaviour()
            .connection_retention
            .physical_routes()
            .and_then(|routes| routes.bound_connection(peer, id))
            .is_none()
    {
        return;
    }
    let state = &mut swarm.behaviour_mut().connection_retention.physical_handoff;
    if state.grace.len() < MAX_ROUNDS {
        // Another incoming duplicate cannot extend an existing grace indefinitely.
        state
            .grace
            .entry((peer, id))
            .or_insert(now + DUPLICATE_GRACE);
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn drive(
    swarm: &mut Swarm<Behaviour>,
    epochs: &mut ConnectionEpochs,
    forwarder: &Forwarder,
    local: &ControlCapabilities,
    configured: &[(Libp2pPeerId, Multiaddr)],
    discovered: &DiscoveredPeerAddresses,
    connections: &HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
    paths: &mut PathSet,
    metrics: &RuntimeMetrics,
    now: Instant,
) {
    let Some(owners) = swarm
        .behaviour()
        .connection_retention
        .physical_routes()
        .cloned()
    else {
        return;
    };
    let routes = owners.snapshot();
    let mut state =
        std::mem::take(&mut swarm.behaviour_mut().connection_retention.physical_handoff);
    let expired_grace = state
        .grace
        .iter()
        .filter_map(|((peer, _), deadline)| (now >= *deadline).then_some(*peer))
        .collect::<HashSet<_>>();
    state
        .grace
        .retain(|owner, deadline| now < *deadline && connections.contains_key(owner));
    for pending in state.pending.values() {
        if now >= pending.deadline || !pending_is_current(pending, &routes, forwarder, epochs) {
            pending.cancellation.abort();
        }
    }
    // Completed validation survives unrelated kernel events only when a fresh
    // audit confirms that the exact validated path remains preferred.
    for (peer, round) in &mut state.rounds {
        if let Phase::Draining(candidate, _) = round.phase
            && let Some(route) = routes
                .iter()
                .find(|route| route.peer == *peer && route.connection_id == Some(candidate))
            && route.refresh_required() == Some(false)
            && let Some(epoch) = route.inspection_epoch()
        {
            round.epoch = epoch;
        }
    }
    let obsolete = state
        .rounds
        .iter()
        .filter_map(|(peer, round)| {
            (!round.current(&routes) || !eligible(forwarder, *peer)).then_some(*peer)
        })
        .collect::<Vec<_>>();
    for peer in obsolete {
        let round = state.rounds.remove(&peer).expect("selected round");
        if matches!(round.phase, Phase::Draining(..)) {
            rollback(
                swarm, epochs, forwarder, paths, metrics, &routes, peer, &round,
            );
        } else {
            abandon(swarm, epochs, &state, peer, &round);
        }
    }
    for route in &routes {
        if state.rounds.len() >= MAX_ROUNDS {
            break;
        }
        if route.refresh_required() == Some(true)
            && route.connection_id.is_some_and(|id| epochs.is_usable(id))
            && eligible(forwarder, route.peer)
        {
            state.rounds.entry(route.peer).or_insert_with(|| Round {
                anchor: route.clone(),
                epoch: route.inspection_epoch().expect("checked inspection"),
                attempts: 0,
                phase: Phase::Waiting(now),
                draining: HashSet::new(),
                recovery: Recovery::default(),
            });
        }
    }
    let peers = state.rounds.keys().copied().collect::<Vec<_>>();
    for peer in peers {
        let mut round = state.rounds.remove(&peer).expect("selected round");
        let mut rearm_addresses = None;
        if matches!(round.phase, Phase::Exhausted) && round.recovery.ready(now) {
            let addresses =
                candidate_addresses(peer, configured, discovered, connections, forwarder, now);
            if let Some(reason) =
                round
                    .recovery
                    .rearm(&addresses, recovery::demand(forwarder, peer), now)
            {
                round.attempts = 0;
                round.phase = Phase::Waiting(now);
                rearm_addresses = Some(addresses);
                log_runtime_event(
                    LogLevel::Info,
                    "control_tcp_replacement_rearmed",
                    &[
                        ("peer", &peer.to_string()),
                        ("generation", &round.epoch.generation().to_string()),
                        ("reason", reason),
                    ],
                );
            }
        }
        match round.phase {
            Phase::Waiting(retry_at)
                if now >= retry_at
                    && state.rounds.values().filter(|round| round.active()).count()
                        < MAX_ACTIVE
                    && state.pending.len() < MAX_PENDING =>
            {
                let addresses = rearm_addresses.unwrap_or_else(|| {
                    candidate_addresses(peer, configured, discovered, connections, forwarder, now)
                });
                let address = round
                    .recovery
                    .attempt(addresses, recovery::demand(forwarder, peer));
                round.attempts += 1;
                if let Some(address) = address {
                    let options = DialOpts::peer_id(peer)
                        .addresses(vec![address.clone()])
                        .condition(PeerCondition::Always)
                        .allocate_new_port()
                        .build();
                    let candidate = options.connection_id();
                    match epochs.dial(swarm, options) {
                        Ok(()) => {
                            round.phase = Phase::Dialing(candidate, now + CONNECT_WINDOW);
                            transition(
                                "control_tcp_replacement_dialing",
                                peer,
                                candidate,
                                round.epoch.generation(),
                            );
                        }
                        Err(_) => retry(&mut round, now),
                    }
                } else {
                    retry(&mut round, now);
                }
            }
            Phase::Dialing(candidate, deadline) => {
                let route = routes
                    .iter()
                    .find(|route| route.peer == peer && route.connection_id == Some(candidate))
                    .filter(|_| now < deadline);
                if let Some(route) = route.filter(|route| candidate_is_current(route, &round.epoch))
                {
                    let validation_deadline = now + VALIDATION_WINDOW;
                    let capabilities =
                        refreshed_local_capabilities_for_swarm(swarm, local, forwarder);
                    if let Ok((request, cancellation)) = swarm
                        .behaviour_mut()
                        .control
                        .send_request_on_connection_cancellable(
                            &peer,
                            candidate,
                            ControlRequest::Capabilities(capabilities),
                            validation_deadline,
                        )
                    {
                        state.pending.insert(
                            request,
                            Pending {
                                peer,
                                connection: candidate,
                                epoch: round.epoch.clone(),
                                owner: route.id,
                                deadline: validation_deadline,
                                cancellation,
                            },
                        );
                        round.phase = Phase::Validating(candidate, request);
                        metrics.record_control_request_sent();
                        transition(
                            "control_tcp_replacement_validating",
                            peer,
                            candidate,
                            round.epoch.generation(),
                        );
                    } else if now >= deadline {
                        abandon(swarm, epochs, &state, peer, &round);
                        retry(&mut round, now);
                    }
                } else if now >= deadline {
                    abandon(swarm, epochs, &state, peer, &round);
                    retry(&mut round, now);
                }
            }
            Phase::Validating(candidate, request) => {
                if state
                    .pending
                    .get(&request)
                    .is_none_or(|pending| now >= pending.deadline)
                {
                    abandon(swarm, epochs, &state, peer, &round);
                    retry(&mut round, now);
                    transition(
                        "control_tcp_replacement_retry",
                        peer,
                        candidate,
                        round.epoch.generation(),
                    );
                }
            }
            Phase::Draining(candidate, deadline) => {
                let candidate = routes
                    .iter()
                    .find(|route| route.peer == peer && route.connection_id == Some(candidate));
                if candidate.is_some_and(validated_path_awaits_audit) {
                    // Observer loss is not peer failure. Preserve validated service
                    // and stop fallback retirement until a fresh audit is available.
                    state.rounds.insert(peer, round);
                    continue;
                }
                if candidate.is_some_and(|route| validated_path_is_current(route, &round.epoch)) {
                    for fallback in routes.iter().filter(|route| {
                        route.peer == peer
                            && route.connection_id
                                != candidate.and_then(|route| route.connection_id)
                            && route.refresh_required() == Some(true)
                            && route.inspection_epoch().as_ref() == Some(&round.epoch)
                    }) {
                        if let Some(id) = fallback.connection_id {
                            set_outbound(swarm.behaviour_mut(), peer, id, false);
                            if required_relay_owner(swarm.behaviour(), forwarder, peer, id) {
                                continue;
                            }
                            if (now >= deadline || !connection_busy(swarm.behaviour(), peer, id))
                                && epochs.mark_retiring(id)
                            {
                                round.draining.remove(&id);
                                swarm.close_connection(id);
                                transition(
                                    "control_tcp_fallback_retired",
                                    peer,
                                    id,
                                    round.epoch.generation(),
                                );
                            }
                        }
                    }
                    if now >= deadline {
                        round.phase = Phase::Exhausted;
                    }
                } else {
                    rollback(
                        swarm, epochs, forwarder, paths, metrics, &routes, peer, &round,
                    );
                    retry(&mut round, now);
                }
            }
            _ => {}
        }
        state.rounds.insert(peer, round);
    }
    swarm.behaviour_mut().connection_retention.physical_handoff = state;
    for peer in expired_grace {
        close_redundant_direct_connections(
            swarm,
            forwarder,
            connections,
            epochs,
            peer,
            "physical_handoff_grace_expired",
        );
    }
}

fn eligible(forwarder: &Forwarder, peer: Libp2pPeerId) -> bool {
    forwarder.is_configured_transport_peer(peer)
        && !forwarder.config().network.relay.server
        && !forwarder.data_path_is_dormant(PeerId::from_libp2p(peer))
}

pub(super) fn required_relay_owner(
    behaviour: &Behaviour,
    forwarder: &Forwarder,
    peer: Libp2pPeerId,
    id: ConnectionId,
) -> bool {
    // Relay reservations/circuits have their own lifetimes. Overlay TCP
    // validation is not proof that their incoming service has migrated.
    forwarder.config().network.relay.server
        || behaviour
            .relay
            .confirmed_reservation_connections(peer)
            .any(|owner| owner == id)
        || forwarder
            .config()
            .network
            .relay
            .reservations
            .iter()
            .any(|address| {
                address
                    .parse::<Multiaddr>()
                    .ok()
                    .and_then(|address| relayed_address_relay_peer(&address))
                    == Some(peer)
            })
}

fn retry(round: &mut Round, now: Instant) {
    round.phase = if round.attempts >= MAX_ATTEMPTS {
        let delay = round.recovery.exhaust(now);
        log_runtime_event(
            LogLevel::Info,
            "control_tcp_replacement_exhausted",
            &[
                ("peer", &round.anchor.peer.to_string()),
                ("generation", &round.epoch.generation().to_string()),
                ("retry_after_seconds", &delay.as_secs().to_string()),
                ("action", "wait_for_new_demand_or_address"),
            ],
        );
        Phase::Exhausted
    } else {
        Phase::Waiting(now + Duration::from_secs(5 * (1_u64 << round.attempts)))
    };
}

fn abandon(
    swarm: &mut Swarm<Behaviour>,
    epochs: &mut ConnectionEpochs,
    state: &State,
    peer: Libp2pPeerId,
    round: &Round,
) {
    if let Phase::Validating(_, request) = round.phase
        && let Some(pending) = state.pending.get(&request)
    {
        pending.cancellation.abort();
    }
    if let Some(candidate) = round.candidate() {
        epochs.mark_retiring(candidate);
        swarm.close_connection(candidate);
        transition(
            "control_tcp_replacement_abandoned",
            peer,
            candidate,
            round.epoch.generation(),
        );
    }
}

fn validated_path_awaits_audit(route: &Snapshot) -> bool {
    route.is_live()
        && route.is_adopted()
        && !route.lease.is_current()
        && route.inspection_epoch().is_none()
}

fn candidate_is_current(route: &Snapshot, epoch: &RouteEpoch) -> bool {
    route.is_live()
        && route.is_adopted()
        && route.lease.preferred_dial
        && &route.lease.epoch() == epoch
        && route.lease.is_current()
}

fn validated_path_is_current(route: &Snapshot, epoch: &RouteEpoch) -> bool {
    candidate_is_current(route, epoch)
        || (route.refresh_required() == Some(false)
            && route.inspection_epoch().as_ref() == Some(epoch))
}

fn rollback(
    swarm: &mut Swarm<Behaviour>,
    epochs: &mut ConnectionEpochs,
    forwarder: &Forwarder,
    paths: &mut PathSet,
    metrics: &RuntimeMetrics,
    routes: &[Snapshot],
    peer: Libp2pPeerId,
    round: &Round,
) {
    if let Some(candidate) = round.candidate()
        && !required_relay_owner(swarm.behaviour(), forwarder, peer, candidate)
        && routes.iter().any(|route| {
            route.peer == peer
                && route.is_live()
                && route.connection_id.is_some_and(|id| {
                    id != candidate
                        && epochs.is_usable(id)
                        && paths.contains_healthy_connection(
                            PeerId::from_libp2p(peer),
                            PathKind::DirectTcpStream,
                            None,
                            id,
                        )
                })
        })
    {
        let lost = paths.record_failed_connection(
            PeerId::from_libp2p(peer),
            PathKind::DirectTcpStream,
            None,
            candidate,
        );
        record_path_selection_change(metrics, lost.selection_change);
        set_outbound(swarm.behaviour_mut(), peer, candidate, false);
        epochs.mark_retiring(candidate);
        swarm.close_connection(candidate);
        transition(
            "control_tcp_replacement_rolled_back",
            peer,
            candidate,
            round.epoch.generation(),
        );
    } else if let Some(candidate) = round.candidate() {
        // A promoted path can become the next fallback before its previous
        // drain deadline. Never discard the sole working authenticated path.
        transition(
            "control_tcp_promotion_superseded",
            peer,
            candidate,
            round.epoch.generation(),
        );
    }
    for route in routes
        .iter()
        .filter(|route| route.peer == peer && route.is_live())
    {
        if let Some(id) = route.connection_id.filter(|id| epochs.is_usable(*id)) {
            set_outbound(swarm.behaviour_mut(), peer, id, true);
        }
    }
}

fn pending_is_current(
    pending: &Pending,
    routes: &[Snapshot],
    forwarder: &Forwarder,
    epochs: &ConnectionEpochs,
) -> bool {
    eligible(forwarder, pending.peer)
        && epochs.is_usable(pending.connection)
        && routes.iter().any(|route| {
            route.peer == pending.peer
                && route.connection_id == Some(pending.connection)
                && route.id == pending.owner
                && candidate_is_current(route, &pending.epoch)
        })
}

fn candidate_addresses(
    peer: Libp2pPeerId,
    configured: &[(Libp2pPeerId, Multiaddr)],
    discovered: &DiscoveredPeerAddresses,
    connections: &HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
    forwarder: &Forwarder,
    now: Instant,
) -> Vec<Multiaddr> {
    let networks = local_interface_networks(&forwarder.config().interface.name);
    let mut addresses = configured
        .iter()
        .filter(|(other, _)| *other == peer)
        .map(|(_, address)| address.clone())
        .chain(
            discovered
                .addresses
                .iter()
                .filter(|entry| {
                    entry.peer == peer && entry.quarantined_until.is_none_or(|until| now >= until)
                })
                .map(|entry| entry.address.clone()),
        )
        .chain(connections.iter().filter_map(|((other, _), endpoint)| {
            if *other == peer
                && let ConnectedPoint::Dialer { address, .. } = endpoint
            {
                Some(address.clone())
            } else {
                None
            }
        }))
        .filter(|address| direct_tcp_address(address, peer))
        .map(|address| canonical_discovered_address(peer, address))
        .collect::<Vec<_>>();
    addresses.sort_by_key(|address| {
        (
            auto_relay_candidate_address_rank(address, &networks),
            address.to_vec(),
        )
    });
    addresses.dedup();
    addresses.truncate(recovery::MAX_ADDRESSES);
    addresses
}

fn direct_tcp_address(address: &Multiaddr, peer: Libp2pPeerId) -> bool {
    let mut parts = address.iter();
    if !matches!(
        parts.next(),
        Some(
            Protocol::Ip4(_)
                | Protocol::Ip6(_)
                | Protocol::Dns(_)
                | Protocol::Dns4(_)
                | Protocol::Dns6(_)
        )
    ) || !matches!(parts.next(), Some(Protocol::Tcp(_)))
    {
        return false;
    }
    match parts.next() {
        None => true,
        Some(Protocol::P2p(id)) => id == peer && parts.next().is_none(),
        _ => false,
    }
}

fn set_outbound(behaviour: &mut Behaviour, peer: Libp2pPeerId, id: ConnectionId, enabled: bool) {
    behaviour
        .control
        .set_connection_outbound_enabled(&peer, id, enabled);
    behaviour
        .lifecycle
        .set_connection_outbound_enabled(&peer, id, enabled);
    behaviour
        .checkpoint
        .set_connection_outbound_enabled(&peer, id, enabled);
    behaviour
        .checkpoint_mutation
        .set_connection_outbound_enabled(&peer, id, enabled);
    behaviour
        .packet
        .set_connection_outbound_enabled(&peer, id, enabled);
    behaviour
        .pairing
        .set_connection_outbound_enabled(&peer, id, enabled);
    behaviour
        .pairing_code
        .set_connection_outbound_enabled(&peer, id, enabled);
    behaviour
        .pairing_code_v2
        .set_connection_outbound_enabled(&peer, id, enabled);
    behaviour
        .service
        .set_connection_outbound_enabled(&peer, id, enabled);
}

fn connection_busy(behaviour: &Behaviour, peer: Libp2pPeerId, id: ConnectionId) -> bool {
    behaviour
        .control
        .has_pending_requests_on_connection(&peer, id)
        || behaviour
            .lifecycle
            .has_pending_requests_on_connection(&peer, id)
        || behaviour
            .checkpoint
            .has_pending_requests_on_connection(&peer, id)
        || behaviour
            .checkpoint_mutation
            .has_pending_requests_on_connection(&peer, id)
        || behaviour
            .packet
            .has_pending_requests_on_connection(&peer, id)
        || behaviour
            .pairing
            .has_pending_requests_on_connection(&peer, id)
        || behaviour
            .pairing_code
            .has_pending_requests_on_connection(&peer, id)
        || behaviour
            .pairing_code_v2
            .has_pending_requests_on_connection(&peer, id)
        || behaviour
            .service
            .has_pending_requests_on_connection(&peer, id)
        || behaviour.pinned_packet_stream.has_pending_work(peer)
}

pub(super) fn handle_validation_event(
    swarm: &mut Swarm<Behaviour>,
    context: &mut SwarmEventContext<'_>,
    event: &request_response::Event<ControlRequest, ControlResponse>,
) -> bool {
    let (peer, connection, request, response) = match event {
        request_response::Event::Message {
            peer,
            connection_id,
            message:
                Message::Response {
                    request_id,
                    response,
                },
        } => (*peer, *connection_id, *request_id, Some(response)),
        request_response::Event::OutboundFailure {
            peer,
            connection_id,
            request_id,
            ..
        } => (*peer, *connection_id, *request_id, None),
        _ => return false,
    };
    let state = &mut swarm.behaviour_mut().connection_retention.physical_handoff;
    let Some(pending) = state.pending.get(&request) else {
        return false;
    };
    if pending.peer != peer || pending.connection != connection {
        return true;
    }
    let pending = state.pending.remove(&request).expect("checked owner");
    let matches_round = state.rounds.get(&peer).is_some_and(|round| {
        round.epoch == pending.epoch
            && matches!(round.phase, Phase::Validating(candidate, id) if candidate == connection && id == request)
    });
    let routes = swarm
        .behaviour()
        .connection_retention
        .physical_routes()
        .map(|routes| routes.snapshot())
        .unwrap_or_default();
    let now = Instant::now();
    let accepted = matches_round
        && now < pending.deadline
        && pending_is_current(
            &pending,
            &routes,
            context.forwarder,
            context.connection_epochs,
        )
        && swarm
            .behaviour()
            .connection_retention
            .physical_handoff
            .rounds
            .get(&peer)
            .is_some_and(|round| round.current(&routes))
        && matches!(response, Some(ControlResponse::CapabilitiesAccepted(capabilities))
            if validate_capabilities(capabilities, &context.local_capabilities.network_name,
                context.local_capabilities.membership_tag.as_deref(), context.previous_membership_tags).is_none());
    if accepted {
        let draining = routes
            .iter()
            .filter(|route| {
                route.peer == peer
                    && route.refresh_required() == Some(true)
                    && route.inspection_epoch().as_ref() == Some(&pending.epoch)
            })
            .filter_map(|route| route.connection_id)
            .filter(|id| {
                *id != connection
                    && !required_relay_owner(swarm.behaviour(), context.forwarder, peer, *id)
            })
            .collect();
        let state = &mut swarm.behaviour_mut().connection_retention.physical_handoff;
        let round = state.rounds.get_mut(&peer).expect("checked round");
        round.phase = Phase::Draining(connection, now + DRAIN_WINDOW);
        round.draining = draining;
        set_outbound(swarm.behaviour_mut(), peer, connection, true);
        promote_authenticated_overlay_connection(
            swarm,
            context,
            peer,
            connection,
            "preferred_physical_route_validated",
        );
        for route in routes
            .iter()
            .filter(|route| route.peer == peer && route.refresh_required() == Some(true))
        {
            if let Some(id) = route.connection_id {
                set_outbound(swarm.behaviour_mut(), peer, id, false);
            }
        }
        context.metrics.record_control_response_received();
        transition(
            "control_tcp_replacement_promoted",
            peer,
            connection,
            pending.epoch.generation(),
        );
    } else if matches_round {
        let mut state =
            std::mem::take(&mut swarm.behaviour_mut().connection_retention.physical_handoff);
        if let Some(mut round) = state.rounds.remove(&peer) {
            abandon(swarm, context.connection_epochs, &state, peer, &round);
            retry(&mut round, now);
            state.rounds.insert(peer, round);
        }
        swarm.behaviour_mut().connection_retention.physical_handoff = state;
        context.metrics.record_control_failure();
    }
    true
}

fn transition(event: &str, peer: Libp2pPeerId, id: ConnectionId, generation: u64) {
    log_runtime_event(
        LogLevel::Info,
        event,
        &[
            ("peer", &peer.to_string()),
            ("connection_id", &id.to_string()),
            ("generation", &generation.to_string()),
        ],
    );
}

pub(super) fn observe_closed(state: &mut State, peer: Libp2pPeerId, id: ConnectionId) {
    state.grace.remove(&(peer, id));
    if let Some(round) = state.rounds.get_mut(&peer)
        && matches!(round.phase, Phase::Draining(..))
        && round.draining.remove(&id)
    {
        log_runtime_event(
            LogLevel::Info,
            "control_tcp_fallback_retired",
            &[
                ("peer", &peer.to_string()),
                ("connection_id", &id.to_string()),
                ("generation", &round.epoch.generation().to_string()),
                ("reason", "transport_closed"),
            ],
        );
    }
}

#[cfg(test)]
mod tests;
