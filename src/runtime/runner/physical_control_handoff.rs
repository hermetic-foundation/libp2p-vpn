//! Bounded native control replacement: preserve the old path until an exact candidate replies.

use super::*;
use crate::runtime::physical_network::linux::SocketProtocol;
use crate::runtime::physical_network::linux::control::Snapshot;
use crate::runtime::physical_network::linux::egress::RouteEpoch;
use futures::future::AbortHandle;

mod circuit;
pub(super) mod recovery;
use recovery::Recovery;

/// Call once at establishment, after native circuit and socket admission.
pub(super) fn log_established_binding(behaviour: &Behaviour, peer: Libp2pPeerId, id: ConnectionId) {
    let Some(fields) = circuit::established_binding_fields(behaviour, peer, id) else {
        return;
    };
    let fields = fields.each_ref().map(|(key, value)| (*key, value.as_str()));
    log_runtime_event(LogLevel::Info, "control_relay_circuit_owned", &fields);
}

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
    replacement_protocol: Option<SocketProtocol>,
    epoch: RouteEpoch,
    attempts: u8,
    phase: Phase,
    draining: HashSet<ConnectionId>,
    recovery: Recovery,
    circuit: Option<circuit::Replacement>,
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
    protocol: SocketProtocol,
    deadline: Instant,
    cancellation: AbortHandle,
    circuit: Option<circuit::Route>,
}

impl Round {
    fn event(&self, tcp: &'static str, quic: &'static str, circuit: &'static str) -> &'static str {
        if self.circuit.is_some() {
            circuit
        } else {
            match self
                .replacement_protocol
                .unwrap_or(self.anchor.lease.context.protocol)
            {
                SocketProtocol::Tcp => tcp,
                SocketProtocol::Udp => quic,
            }
        }
    }
    fn peer(&self) -> Libp2pPeerId {
        self.circuit
            .as_ref()
            .map_or(self.anchor.peer, |circuit| circuit.peer)
    }
    fn candidate_route<'a>(
        &self,
        behaviour: &Behaviour,
        routes: &'a [Snapshot],
        peer: Libp2pPeerId,
    ) -> Option<&'a Snapshot> {
        circuit::route_for(
            behaviour,
            routes,
            peer,
            self.candidate()?,
            self.circuit.as_ref().map(|circuit| circuit.route),
        )
        .filter(|route| self.matches_replacement(route))
    }

    fn matches_replacement(&self, route: &Snapshot) -> bool {
        self.replacement_protocol == Some(route.lease.context.protocol)
    }

    fn current_on(&self, behaviour: &Behaviour, routes: &[Snapshot], peer: Libp2pPeerId) -> bool {
        if let Some(circuit) = &self.circuit {
            if matches!(self.phase, Phase::Draining(..)) {
                return self
                    .candidate_route(behaviour, routes, peer)
                    .is_some_and(|route| {
                        validated_path_is_current(route, &self.epoch)
                            || validated_path_awaits_audit(route)
                    });
            }
            if !self.active()
                && behaviour
                    .relay
                    .circuit_connection_owner(peer, circuit.old)
                    .is_none()
            {
                return false;
            }
        }
        self.current(routes)
    }

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

    fn finish_drain(&mut self, now: Instant, deadline: Instant, audit_pending: bool) {
        if now >= deadline && !audit_pending && (self.circuit.is_none() || self.draining.is_empty())
        {
            self.phase = Phase::Exhausted;
        }
    }

    fn current(&self, routes: &[Snapshot]) -> bool {
        if let Phase::Draining(candidate, _) = self.phase {
            return routes.iter().any(|route| {
                route.peer == self.anchor.peer
                    && route.connection_id == Some(candidate)
                    && self.matches_replacement(route)
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
    pub(super) fn validated_candidates(
        &self,
    ) -> impl Iterator<Item = (Libp2pPeerId, ConnectionId, RouteEpoch)> + '_ {
        self.rounds
            .iter()
            .filter_map(|(peer, round)| match round.phase {
                Phase::Draining(id, _) if round.circuit.is_none() => {
                    Some((*peer, id, round.epoch.clone()))
                }
                _ => None,
            })
    }

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
    let Some(route) = swarm
        .behaviour()
        .connection_retention
        .physical_routes()
        .and_then(|routes| routes.bound_connection(peer, id))
    else {
        return;
    };
    let protocol = route.lease.context.protocol;
    if !forwarder.is_configured_transport_peer(peer)
        || !connections
            .get(&(peer, id))
            .is_some_and(|endpoint| direct_endpoint(endpoint, peer, protocol))
        || !connections.iter().any(|((other, cid), endpoint)| {
            *other == peer && *cid != id && direct_endpoint(endpoint, peer, protocol)
        })
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
        if now >= pending.deadline
            || !pending_is_current_on(pending, swarm.behaviour(), &routes, forwarder, epochs)
        {
            pending.cancellation.abort();
        }
    }
    // Completed validation survives unrelated kernel events only when a fresh
    // audit confirms that the exact validated path remains preferred.
    for (peer, round) in &mut state.rounds {
        if let Phase::Draining(_, _) = round.phase
            && let Some(route) = round.candidate_route(swarm.behaviour(), &routes, *peer)
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
            (!round.current_on(swarm.behaviour(), &routes, *peer) || !eligible(forwarder, *peer))
                .then_some(*peer)
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
                replacement_protocol: None,
                epoch: route.inspection_epoch().expect("checked inspection"),
                attempts: 0,
                phase: Phase::Waiting(now),
                draining: HashSet::new(),
                recovery: Recovery::default(),
                circuit: None,
            });
        }
    }
    circuit::admit_rounds(
        &mut state,
        swarm.behaviour(),
        &routes,
        forwarder,
        connections,
        epochs,
        now,
    );
    let peers = state.rounds.keys().copied().collect::<Vec<_>>();
    for peer in peers {
        let mut round = state.rounds.remove(&peer).expect("selected round");
        let mut rearm_addresses = None;
        if matches!(round.phase, Phase::Exhausted) && round.recovery.ready(now) {
            let addresses = circuit::addresses(&round, connections, peer).unwrap_or_else(|| {
                candidate_addresses_for(
                    &round.anchor,
                    peer,
                    configured,
                    discovered,
                    connections,
                    forwarder,
                    now,
                )
            });
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
                    round.event(
                        "control_tcp_replacement_rearmed",
                        "control_quic_replacement_rearmed",
                        "control_relay_replacement_rearmed",
                    ),
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
                    circuit::addresses(&round, connections, peer).unwrap_or_else(|| {
                        candidate_addresses_for(
                            &round.anchor,
                            peer,
                            configured,
                            discovered,
                            connections,
                            forwarder,
                            now,
                        )
                    })
                });
                let address = round
                    .recovery
                    .attempt(addresses, recovery::demand(forwarder, peer));
                round.attempts += 1;
                if let Some(address) = address {
                    round.replacement_protocol = if let Some(circuit) = &round.circuit {
                        routes
                            .iter()
                            .find(|route| {
                                route.peer == circuit.route.relay
                                    && route.connection_id == Some(circuit.route.outer)
                            })
                            .map(|route| route.lease.context.protocol)
                    } else {
                        address_protocol(&address, peer)
                    };
                    let options = DialOpts::peer_id(peer)
                        .addresses(vec![address.clone()])
                        .condition(PeerCondition::Always)
                        .allocate_new_port()
                        .build();
                    let candidate = options.connection_id();
                    match epochs.dial(swarm, options) {
                        Ok(()) => {
                            if let Some(circuit) = round.circuit.as_mut() {
                                let Some(pin) = swarm.behaviour_mut().relay.pin_circuit_dial(
                                    peer,
                                    candidate,
                                    circuit.route.relay,
                                    circuit.route.outer,
                                ) else {
                                    epochs.mark_retiring(candidate);
                                    swarm.close_connection(candidate);
                                    transition(
                                        "control_relay_replacement_pin_failed",
                                        peer,
                                        candidate,
                                        round.epoch.generation(),
                                    );
                                    retry(&mut round, now);
                                    state.rounds.insert(peer, round);
                                    continue;
                                };
                                circuit.pin = Some(pin);
                            }
                            round.phase = Phase::Dialing(candidate, now + CONNECT_WINDOW);
                            transition(
                                round.event(
                                    "control_tcp_replacement_dialing",
                                    "control_quic_replacement_dialing",
                                    "control_relay_replacement_dialing",
                                ),
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
                let route = round
                    .candidate_route(swarm.behaviour(), &routes, peer)
                    .filter(|_| now < deadline);
                if let Some(route) = route.filter(|route| {
                    if round.circuit.is_some() {
                        validated_path_is_current(route, &round.epoch)
                    } else {
                        candidate_is_current(route, &round.epoch)
                    }
                }) {
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
                                protocol: route.lease.context.protocol,
                                deadline: validation_deadline,
                                cancellation,
                                circuit: round.circuit.as_ref().map(|circuit| circuit.route),
                            },
                        );
                        round.phase = Phase::Validating(candidate, request);
                        metrics.record_control_request_sent();
                        transition(
                            round.event(
                                "control_tcp_replacement_validating",
                                "control_quic_replacement_validating",
                                "control_relay_replacement_validating",
                            ),
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
                        round.event(
                            "control_tcp_replacement_retry",
                            "control_quic_replacement_retry",
                            "control_relay_replacement_retry",
                        ),
                        peer,
                        candidate,
                        round.epoch.generation(),
                    );
                }
            }
            Phase::Draining(id, deadline) => {
                let candidate = round
                    .candidate_route(swarm.behaviour(), &routes, peer)
                    .filter(|_| epochs.is_usable(id));
                if candidate.is_some_and(validated_path_awaits_audit) {
                    // Observer loss is not peer failure. Preserve validated service
                    // and stop fallback retirement until a fresh audit is available.
                    state.rounds.insert(peer, round);
                    continue;
                }
                if candidate.is_some_and(|route| validated_path_is_current(route, &round.epoch))
                    && (round.circuit.is_some()
                        || replacement_covers_services(swarm.behaviour(), &routes, peer, id))
                {
                    if round.circuit.is_some() {
                        let tracked = round.draining.iter().copied().collect::<Vec<_>>();
                        for inner in tracked {
                            let owner = circuit::binding(swarm.behaviour(), peer, inner, true);
                            if let Some(owner) = circuit::release_recovered_fallback(
                                &mut round, &routes, epochs, inner, owner,
                            ) {
                                set_outbound(swarm.behaviour_mut(), peer, inner, true);
                                log_runtime_event(
                                    LogLevel::Info,
                                    "control_relay_fallback_released",
                                    &[
                                        ("peer", &peer.to_string()),
                                        ("connection_id", &inner.to_string()),
                                        ("relay", &owner.relay.to_string()),
                                        ("outer", &owner.outer.to_string()),
                                        ("generation", &round.epoch.generation().to_string()),
                                        ("reason", "route_recovered"),
                                    ],
                                );
                            }
                        }
                    }
                    let fallbacks = if round.circuit.is_some() {
                        circuit::fallbacks(
                            swarm.behaviour(),
                            &routes,
                            connections,
                            peer,
                            round.candidate().expect("draining"),
                            &round.epoch,
                        )
                    } else {
                        routes
                            .iter()
                            .filter(|route| {
                                route.peer == peer
                                    && route.connection_id
                                        != candidate.and_then(|route| route.connection_id)
                                    && route.refresh_required() == Some(true)
                                    && route.inspection_epoch().as_ref() == Some(&round.epoch)
                            })
                            .filter_map(|route| route.connection_id)
                            .collect()
                    };
                    for id in fallbacks {
                        set_outbound(swarm.behaviour_mut(), peer, id, false);
                        if round.circuit.is_none()
                            && required_relay_owner(swarm.behaviour(), forwarder, peer, id)
                        {
                            continue;
                        }
                        if (now >= deadline || !connection_busy(swarm.behaviour(), peer, id))
                            && epochs.mark_retiring(id)
                        {
                            if round.circuit.is_none() {
                                round.draining.remove(&id);
                            }
                            swarm.close_connection(id);
                            transition(
                                round.event(
                                    "control_tcp_fallback_retired",
                                    "control_quic_fallback_retired",
                                    "control_relay_fallback_close_requested",
                                ),
                                peer,
                                id,
                                round.epoch.generation(),
                            );
                        }
                    }
                    let audit_pending = round.draining.iter().any(|id| {
                        epochs.is_usable(*id)
                            && (round.circuit.is_some()
                                || !required_relay_owner(swarm.behaviour(), forwarder, peer, *id))
                            && circuit::route_for(
                                swarm.behaviour(),
                                &routes,
                                peer,
                                *id,
                                circuit::binding(
                                    swarm.behaviour(),
                                    peer,
                                    *id,
                                    round.circuit.is_some(),
                                ),
                            )
                            .is_some_and(|route| {
                                route.is_live()
                                    && route.is_adopted()
                                    && route.refresh_required().is_none()
                            })
                    });
                    round.finish_drain(now, deadline, audit_pending);
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
    let moved = behaviour
        .connection_retention
        .infrastructure_handoff
        .can_release_relay(behaviour, peer, id);
    // Relay reservations/circuits have their own lifetimes. Overlay control
    // validation is not proof that their incoming service has migrated.
    forwarder.config().network.relay.server
        || behaviour.relay.has_connection_dependencies(peer, id)
        || (!moved
            && forwarder
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
                }))
}

fn retry(round: &mut Round, now: Instant) {
    if let Some(circuit) = &mut round.circuit {
        circuit.pin = None;
    }
    round.phase = if round.attempts >= MAX_ATTEMPTS {
        let delay = round.recovery.exhaust(now);
        log_runtime_event(
            LogLevel::Info,
            round.event(
                "control_tcp_replacement_exhausted",
                "control_quic_replacement_exhausted",
                "control_relay_replacement_exhausted",
            ),
            &[
                ("peer", &round.peer().to_string()),
                ("generation", &round.epoch.generation().to_string()),
                ("retry_after_seconds", &delay.as_secs().to_string()),
                ("action", "wait_for_new_demand_or_address"),
            ],
        );
        Phase::Exhausted
    } else {
        Phase::Waiting(now + Duration::from_secs(5 * (1_u64 << round.attempts)))
    };
    round.replacement_protocol = None;
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
        if swarm
            .behaviour()
            .connection_retention
            .infrastructure_handoff
            .protects(peer, candidate)
        {
            return;
        }
        epochs.mark_retiring(candidate);
        swarm.close_connection(candidate);
        transition(
            round.event(
                "control_tcp_replacement_abandoned",
                "control_quic_replacement_abandoned",
                "control_relay_replacement_abandoned",
            ),
            peer,
            candidate,
            round.epoch.generation(),
        );
    }
}

pub(super) fn validated_path_awaits_audit(route: &Snapshot) -> bool {
    route.is_live()
        && route.is_adopted()
        && !route.lease.is_current()
        && route.inspection_epoch().is_none()
}

pub(super) fn candidate_is_current(route: &Snapshot, epoch: &RouteEpoch) -> bool {
    route.is_live()
        && route.is_adopted()
        && route.lease.preferred_dial
        && &route.lease.epoch() == epoch
        && route.lease.is_current()
}

pub(super) fn validated_path_is_current(route: &Snapshot, epoch: &RouteEpoch) -> bool {
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
    if round.circuit.is_some() {
        circuit::rollback(swarm, epochs, paths, metrics, routes, peer, round);
        return;
    }
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
                            transport_path_kind(route.lease.context.protocol),
                            None,
                            id,
                        )
                })
        })
    {
        let lost = paths.record_failed_connection(
            PeerId::from_libp2p(peer),
            transport_path_kind(
                round
                    .replacement_protocol
                    .unwrap_or(round.anchor.lease.context.protocol),
            ),
            None,
            candidate,
        );
        record_path_selection_change(metrics, lost.selection_change);
        set_outbound(swarm.behaviour_mut(), peer, candidate, false);
        epochs.mark_retiring(candidate);
        swarm.close_connection(candidate);
        transition(
            round.event(
                "control_tcp_replacement_rolled_back",
                "control_quic_replacement_rolled_back",
                "control_relay_replacement_rolled_back",
            ),
            peer,
            candidate,
            round.epoch.generation(),
        );
    } else if let Some(candidate) = round.candidate() {
        // A promoted path can become the next fallback before its previous
        // drain deadline. Never discard the sole working authenticated path.
        transition(
            round.event(
                "control_tcp_promotion_superseded",
                "control_quic_promotion_superseded",
                "control_relay_promotion_superseded",
            ),
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
                && route.lease.context.protocol == pending.protocol
                && candidate_is_current(route, &pending.epoch)
        })
}

fn pending_is_current_on(
    pending: &Pending,
    behaviour: &Behaviour,
    routes: &[Snapshot],
    forwarder: &Forwarder,
    epochs: &ConnectionEpochs,
) -> bool {
    if pending.circuit.is_none() {
        return pending_is_current(pending, routes, forwarder, epochs);
    }
    eligible(forwarder, pending.peer)
        && epochs.is_usable(pending.connection)
        && circuit::route_for(
            behaviour,
            routes,
            pending.peer,
            pending.connection,
            pending.circuit,
        )
        .is_some_and(|route| {
            route.id == pending.owner
                && route.lease.context.protocol == pending.protocol
                && validated_path_is_current(route, &pending.epoch)
        })
}

fn replacement_covers_services(
    behaviour: &Behaviour,
    routes: &[Snapshot],
    peer: Libp2pPeerId,
    candidate: ConnectionId,
) -> bool {
    use crate::runtime::connection_retention::IdentifiedServices;
    let mut required = IdentifiedServices::default();
    for services in routes
        .iter()
        .filter(|route| {
            route.peer == peer
                && route.connection_id != Some(candidate)
                && route.refresh_required() == Some(true)
        })
        .filter_map(|route| {
            route
                .connection_id
                .and_then(|id| behaviour.connection_retention.services(peer, id))
        })
    {
        required.include(services);
    }
    required == IdentifiedServices::default()
        || behaviour
            .connection_retention
            .services(peer, candidate)
            .is_some_and(|services| services.covers(required))
}

fn transport_path_kind(protocol: SocketProtocol) -> PathKind {
    // These snapshots belong to native libp2p control, not packet-plane Quinn.
    match protocol {
        SocketProtocol::Tcp => PathKind::DirectTcpStream,
        SocketProtocol::Udp => PathKind::DirectQuicStream,
    }
}

pub(super) fn candidate_addresses_for(
    anchor: &Snapshot,
    peer: Libp2pPeerId,
    configured: &[(Libp2pPeerId, Multiaddr)],
    discovered: &DiscoveredPeerAddresses,
    connections: &HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
    forwarder: &Forwarder,
    now: Instant,
) -> Vec<Multiaddr> {
    let networks = local_interface_networks(&forwarder.config().interface.name);
    let mut addresses =
        candidate_addresses(peer, configured, discovered, connections, forwarder, now);
    addresses.extend(collect_candidate_addresses(
        SocketProtocol::Udp,
        peer,
        configured,
        discovered,
        connections,
        forwarder,
        now,
    ));
    let preferred = anchor.lease.context.protocol;
    let alternate = match preferred {
        SocketProtocol::Tcp => SocketProtocol::Udp,
        SocketProtocol::Udp => SocketProtocol::Tcp,
    };
    let mut result = Vec::new();
    // Locality is stronger than transport preference. Alternate within each
    // locality so one blocked transport cannot consume all three attempts.
    for locality in 0..=3 {
        let networks = &networks;
        let of_kind = |protocol| {
            addresses.iter().filter(move |address| {
                auto_relay_candidate_address_rank(address, networks) == locality
                    && address_protocol(address, peer) == Some(protocol)
            })
        };
        let mut primary = of_kind(preferred);
        let mut fallback = of_kind(alternate);
        loop {
            let pair = [primary.next(), fallback.next()];
            if pair.iter().all(Option::is_none) {
                break;
            }
            for address in pair.into_iter().flatten() {
                result.push(address.clone());
                if result.len() == recovery::MAX_ADDRESSES {
                    return result;
                }
            }
        }
    }
    result
}

pub(super) fn candidate_addresses(
    peer: Libp2pPeerId,
    configured: &[(Libp2pPeerId, Multiaddr)],
    discovered: &DiscoveredPeerAddresses,
    connections: &HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
    forwarder: &Forwarder,
    now: Instant,
) -> Vec<Multiaddr> {
    collect_candidate_addresses(
        SocketProtocol::Tcp,
        peer,
        configured,
        discovered,
        connections,
        forwarder,
        now,
    )
}

fn collect_candidate_addresses(
    protocol: SocketProtocol,
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
        .filter(|address| direct_address(address, peer, protocol))
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

fn direct_endpoint(
    endpoint: &ConnectedPoint,
    peer: Libp2pPeerId,
    protocol: SocketProtocol,
) -> bool {
    if endpoint.is_relayed() {
        return false;
    }
    let address = match endpoint {
        ConnectedPoint::Dialer { address, .. } => address,
        ConnectedPoint::Listener { local_addr, .. } => local_addr,
    };
    direct_address(address, peer, protocol)
}

fn direct_address(address: &Multiaddr, peer: Libp2pPeerId, protocol: SocketProtocol) -> bool {
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
    ) {
        return false;
    }
    match (protocol, parts.next()) {
        (SocketProtocol::Tcp, Some(Protocol::Tcp(_))) => {}
        (SocketProtocol::Udp, Some(Protocol::Udp(_)))
            if matches!(parts.next(), Some(Protocol::QuicV1)) => {}
        _ => return false,
    }
    match parts.next() {
        None => true,
        Some(Protocol::P2p(id)) => id == peer && parts.next().is_none(),
        _ => false,
    }
}

pub(super) fn address_protocol(address: &Multiaddr, peer: Libp2pPeerId) -> Option<SocketProtocol> {
    [SocketProtocol::Tcp, SocketProtocol::Udp]
        .into_iter()
        .find(|protocol| direct_address(address, peer, *protocol))
}

fn set_outbound(behaviour: &mut Behaviour, peer: Libp2pPeerId, id: ConnectionId, enabled: bool) {
    behaviour
        .kad
        .set_connection_outbound_enabled(&peer, id, enabled);
    if let Some(kad) = behaviour.pairing_kad.as_mut() {
        kad.set_connection_outbound_enabled(&peer, id, enabled);
    }
    if let Some(autonat) = behaviour.autonat.as_mut() {
        autonat.set_connection_outbound_enabled(&peer, id, enabled);
    }
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

pub(super) fn connection_busy(behaviour: &Behaviour, peer: Libp2pPeerId, id: ConnectionId) -> bool {
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
        || behaviour.kad.has_pending_requests_on_connection(&peer, id)
        || behaviour
            .pairing_kad
            .as_ref()
            .is_some_and(|kad| kad.has_pending_requests_on_connection(&peer, id))
        || behaviour
            .autonat
            .as_ref()
            .is_some_and(|autonat| autonat.has_pending_requests_on_connection(&peer, id))
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
            && round.replacement_protocol == Some(pending.protocol)
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
        && pending_is_current_on(
            &pending,
            swarm.behaviour(),
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
            .is_some_and(|round| round.current_on(swarm.behaviour(), &routes, peer))
        && (pending.circuit.is_some()
            || replacement_covers_services(swarm.behaviour(), &routes, peer, connection))
        && matches!(response, Some(ControlResponse::CapabilitiesAccepted(capabilities))
            if validate_capabilities(capabilities, &context.local_capabilities.network_name,
                context.local_capabilities.membership_tag.as_deref(), context.previous_membership_tags).is_none());
    if accepted {
        let is_circuit = swarm
            .behaviour()
            .connection_retention
            .physical_handoff
            .rounds[&peer]
            .circuit
            .is_some();
        let draining: HashSet<ConnectionId> = if is_circuit {
            circuit::fallbacks(
                swarm.behaviour(),
                &routes,
                context.active_connections,
                peer,
                connection,
                &pending.epoch,
            )
            .into_iter()
            .collect()
        } else {
            routes
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
                .collect()
        };
        let old_connections = if is_circuit {
            draining.iter().copied().collect::<Vec<_>>()
        } else {
            routes
                .iter()
                .filter(|route| route.peer == peer && route.refresh_required() == Some(true))
                .filter_map(|route| route.connection_id)
                .collect()
        };
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
        for id in old_connections {
            set_outbound(swarm.behaviour_mut(), peer, id, false);
        }
        context.metrics.record_control_response_received();
        transition(
            if is_circuit {
                "control_relay_replacement_promoted"
            } else {
                match pending.protocol {
                    SocketProtocol::Tcp => "control_tcp_replacement_promoted",
                    SocketProtocol::Udp => "control_quic_replacement_promoted",
                }
            },
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
            round.event(
                "control_tcp_fallback_retired",
                "control_quic_fallback_retired",
                "control_relay_fallback_retired",
            ),
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
