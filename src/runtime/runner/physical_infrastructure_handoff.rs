//! Public services use Identify on the exact authenticated replacement, not overlay RPCs.

use super::*;
use crate::runtime::connection_retention::IdentifiedServices;
use crate::runtime::physical_network::linux::{
    SocketProtocol, control::Snapshot, egress::RouteEpoch,
};
use physical_control_handoff::recovery::Recovery;
use physical_control_handoff::{
    address_protocol, candidate_is_current, validated_path_awaits_audit, validated_path_is_current,
};

mod relay_handoff;

const MAX_ROUNDS: usize = 64;
const MAX_ACTIVE: usize = 4;
const MAX_ATTEMPTS: u8 = 3;
const CONNECT_WINDOW: Duration = Duration::from_secs(30);
const DRAIN_WINDOW: Duration = Duration::from_secs(20);
const SETTLE_WINDOW: Duration = Duration::from_secs(1);

#[derive(Default)]
pub(crate) struct State {
    rounds: HashMap<Libp2pPeerId, Round>,
    at_capacity: bool,
    relay_handoff: relay_handoff::State,
}

struct Round {
    anchor: Snapshot,
    replacement_protocol: Option<SocketProtocol>,
    epoch: RouteEpoch,
    required: IdentifiedServices,
    attempts: u8,
    recovery: Recovery,
    phase: Phase,
}

enum Phase {
    Waiting(Instant),
    Dialing(ConnectionId, Instant),
    Draining(ConnectionId, Instant),
    Complete(ConnectionId),
    Exhausted,
}

impl Round {
    fn event(&self, tcp: &'static str, quic: &'static str) -> &'static str {
        match self
            .replacement_protocol
            .unwrap_or(self.anchor.lease.context.protocol)
        {
            SocketProtocol::Tcp => tcp,
            SocketProtocol::Udp => quic,
        }
    }

    fn candidate_is_current(&self, route: &Snapshot) -> bool {
        self.matches_replacement(route) && candidate_is_current(route, &self.epoch)
    }

    fn matches_replacement(&self, route: &Snapshot) -> bool {
        self.replacement_protocol == Some(route.lease.context.protocol)
    }

    fn candidate(&self) -> Option<ConnectionId> {
        match self.phase {
            Phase::Dialing(id, _) | Phase::Draining(id, _) | Phase::Complete(id) => Some(id),
            _ => None,
        }
    }

    fn current(&self, routes: &[Snapshot]) -> bool {
        if matches!(self.phase, Phase::Draining(..) | Phase::Complete(..)) {
            return routes.iter().any(|route| {
                route.peer == self.anchor.peer
                    && route.connection_id == self.candidate()
                    && self.matches_replacement(route)
                    && (validated_path_is_current(route, &self.epoch)
                        || validated_path_awaits_audit(route))
            });
        }
        if matches!(self.phase, Phase::Dialing(..)) && !self.anchor.is_live() {
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
                Phase::Draining(id, _) | Phase::Complete(id) => {
                    Some((*peer, id, round.epoch.clone()))
                }
                _ => None,
            })
    }
    pub(crate) fn owns_relay_listener(&self, peer: Libp2pPeerId, listener: ListenerId) -> bool {
        self.relay_handoff.owns_listener(peer, listener)
    }

    pub(crate) fn owns_relay_peer(&self, peer: Libp2pPeerId) -> bool {
        self.relay_handoff.owns_peer(peer)
    }

    pub(crate) fn relay_listener_closed(&mut self, listener: ListenerId) {
        self.relay_handoff.listener_closed(listener);
    }

    pub(crate) fn can_release_relay(
        &self,
        behaviour: &Behaviour,
        peer: Libp2pPeerId,
        id: ConnectionId,
    ) -> bool {
        self.relay_handoff.can_release(behaviour, peer, id)
    }

    pub(crate) fn is_candidate(&self, peer: Libp2pPeerId, id: ConnectionId) -> bool {
        self.rounds
            .get(&peer)
            .is_some_and(|round| matches!(round.phase, Phase::Dialing(owner, _) if owner == id))
    }

    pub(crate) fn protects(&self, peer: Libp2pPeerId, id: ConnectionId) -> bool {
        self.relay_handoff.protects(peer, id)
            || self.rounds.get(&peer).is_some_and(|round| {
                matches!(
                    round.phase,
                    Phase::Waiting(..) | Phase::Dialing(..) | Phase::Draining(..)
                ) && (round.anchor.connection_id == Some(id) || round.candidate() == Some(id))
            })
    }
}

pub(super) struct Context<'a> {
    pub swarm: &'a mut Swarm<Behaviour>,
    pub epochs: &'a mut ConnectionEpochs,
    pub forwarder: &'a Forwarder,
    pub membership: &'a OverlayMembership,
    pub routing: &'a RoutingInfrastructurePeers,
    pub infrastructure: &'a InfrastructurePeers,
    pub auto_relay: &'a mut AutoRelayState,
    pub readiness: &'a mut RelayReadiness,
    pub configured_listeners: &'a mut HashSet<ListenerId>,
    pub retiring_listeners: &'a mut HashSet<ListenerId>,
    pub pairing: &'a CodePairingSessions,
    pub probes: &'a MembershipProbeConnections,
    pub relays: &'a [(Libp2pPeerId, Multiaddr)],
    pub bootstrap: &'a [(Libp2pPeerId, Multiaddr)],
    pub discovered: &'a DiscoveredPeerAddresses,
    pub connections: &'a HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
    pub now: Instant,
}

fn eligible(context: &Context<'_>, peer: Libp2pPeerId) -> bool {
    allowed(context, peer)
        && (context.routing.contains(peer)
            || context.infrastructure.contains(peer)
            || context.bootstrap.iter().any(|(owner, _)| *owner == peer)
            || context.relays.iter().any(|(owner, _)| *owner == peer)
            || context.connections.keys().any(|(owner, id)| {
                *owner == peer
                    && context
                        .swarm
                        .behaviour()
                        .relay
                        .has_connection_dependencies(peer, *id)
            }))
}

fn allowed(context: &Context<'_>, peer: Libp2pPeerId) -> bool {
    !context.forwarder.config().network.relay.server
        && context.swarm.behaviour().relay_server.as_ref().is_none()
        && !context.forwarder.is_configured_transport_peer(peer)
        && !context.membership.allows_membership_sync(peer)
        && !context.pairing.uses_pairing_relay(peer)
        && !context.pairing.allows_pairing_probe(peer)
        && !context
            .probes
            .by_peer
            .get(&peer)
            .is_some_and(|probe| context.now < probe.expires_at)
}

fn relay_required(
    context: &Context<'_>,
    moves: &relay_handoff::State,
    peer: Libp2pPeerId,
    id: ConnectionId,
) -> bool {
    let moved = moves.can_release(context.swarm.behaviour(), peer, id);
    context.forwarder.config().network.relay.server
        || context.swarm.behaviour().relay_server.as_ref().is_some()
        || (!moved
            && context.configured_listeners.iter().any(|listener| {
                context
                    .swarm
                    .behaviour()
                    .relay
                    .reservation_listener_connection(peer, *listener)
                    == Some(id)
            }))
        || context
            .auto_relay
            .pending_reservations
            .get(&peer)
            .is_some_and(|pending| pending.owned_dial == Some(id))
        || (!moved
            && context
                .auto_relay
                .reservation_listeners
                .get(&peer)
                .is_some_and(|listener| listener.connection == id))
        || moves.protects(peer, id)
        || context
            .swarm
            .behaviour()
            .relay
            .has_connection_dependencies(peer, id)
        || context.pairing.uses_pairing_relay(peer)
        || context.pairing.allows_pairing_probe(peer)
        || context
            .probes
            .by_peer
            .get(&peer)
            .is_some_and(|probe| context.now < probe.expires_at)
}

pub(super) fn observe_established(
    swarm: &mut Swarm<Behaviour>,
    peer: Libp2pPeerId,
    id: ConnectionId,
) {
    if swarm
        .behaviour()
        .connection_retention
        .infrastructure_handoff
        .is_candidate(peer, id)
    {
        set_outbound(swarm.behaviour_mut(), peer, id, false);
    }
}

pub(super) fn drive(context: &mut Context<'_>) {
    let Some(owners) = context
        .swarm
        .behaviour()
        .connection_retention
        .physical_routes()
        .cloned()
    else {
        return;
    };
    let routes = owners.snapshot();
    let mut state = std::mem::take(
        &mut context
            .swarm
            .behaviour_mut()
            .connection_retention
            .infrastructure_handoff,
    );
    for round in state.rounds.values_mut() {
        let mut required = None;
        for services in routes
            .iter()
            .filter(|route| {
                route.peer == round.anchor.peer && route.refresh_required() == Some(true)
            })
            .filter_map(|route| {
                route.connection_id.and_then(|id| {
                    context
                        .swarm
                        .behaviour()
                        .connection_retention
                        .services(route.peer, id)
                })
            })
        {
            required
                .get_or_insert(IdentifiedServices::default())
                .include(services);
        }
        if let Some(required) = required {
            round.required = required;
        }
        if matches!(round.phase, Phase::Draining(..) | Phase::Complete(..))
            && let Some(route) = routes.iter().find(|route| {
                route.peer == round.anchor.peer
                    && route.connection_id == round.candidate()
                    && round.matches_replacement(route)
            })
            && route.refresh_required() == Some(false)
            && let Some(epoch) = route.inspection_epoch()
        {
            round.epoch = epoch;
        }
    }
    let mut candidates = state
        .rounds
        .iter()
        .filter_map(|(peer, round)| {
            (matches!(round.phase, Phase::Draining(..) | Phase::Complete(..))
                && round.current(&routes))
            .then(|| {
                round.candidate().map(|id| relay_handoff::Candidate {
                    peer: *peer,
                    id,
                    epoch: round.epoch.clone(),
                })
            })
            .flatten()
        })
        .collect::<Vec<_>>();
    candidates.extend(
        context
            .swarm
            .behaviour()
            .connection_retention
            .physical_handoff
            .validated_candidates()
            .map(|(peer, id, epoch)| relay_handoff::Candidate { peer, id, epoch }),
    );
    relay_handoff::drive(&mut state.relay_handoff, context, &routes, &candidates);
    let obsolete = state
        .rounds
        .iter()
        .filter_map(|(peer, round)| {
            let no_fallbacks = matches!(round.phase, Phase::Complete(..))
                && !routes.iter().any(|route| {
                    route.peer == *peer
                        && route.connection_id != round.candidate()
                        && route.refresh_required() == Some(true)
                });
            let owned_recovery = matches!(round.phase, Phase::Dialing(..))
                && !round.anchor.is_live()
                && round.epoch.is_current()
                && allowed(context, *peer);
            (!(eligible(context, *peer) || owned_recovery)
                || !round.required.infrastructure()
                || !round.current(&routes)
                || no_fallbacks)
                .then_some(*peer)
        })
        .collect::<Vec<_>>();
    for peer in obsolete {
        let round = state.rounds.remove(&peer).expect("selected round");
        restore(context, &routes, peer);
        if let Phase::Dialing(candidate, _) = round.phase {
            abandon(context, &state.relay_handoff, peer, candidate);
        }
    }
    for route in &routes {
        if state.rounds.len() >= MAX_ROUNDS {
            break;
        }
        let Some(id) = route
            .connection_id
            .filter(|id| context.epochs.is_usable(*id))
        else {
            continue;
        };
        let Some(required) = context
            .swarm
            .behaviour()
            .connection_retention
            .services(route.peer, id)
            .filter(|services| services.infrastructure())
        else {
            continue;
        };
        if route.refresh_required() == Some(true) && eligible(context, route.peer) {
            state.rounds.entry(route.peer).or_insert_with(|| Round {
                anchor: route.clone(),
                replacement_protocol: None,
                epoch: route.inspection_epoch().expect("checked inspection"),
                required,
                attempts: 0,
                recovery: Recovery::default(),
                phase: Phase::Waiting(context.now + SETTLE_WINDOW),
            });
        }
    }
    let at_capacity = state.rounds.len() >= MAX_ROUNDS;
    if at_capacity && !state.at_capacity {
        log_runtime_event(
            LogLevel::Warn,
            "infrastructure_tcp_handoff_capacity",
            &[
                ("round_limit", &MAX_ROUNDS.to_string()),
                ("action", "preserve_existing_paths"),
            ],
        );
    }
    state.at_capacity = at_capacity;
    let peers = state.rounds.keys().copied().collect::<Vec<_>>();
    for peer in peers {
        let mut round = state.rounds.remove(&peer).expect("selected round");
        if let Phase::Complete(candidate) = round.phase
            && fallback_routes(&routes, peer, candidate, &round)
                .next()
                .is_some()
        {
            round.phase = Phase::Draining(candidate, context.now + DRAIN_WINDOW);
        }
        if matches!(round.phase, Phase::Exhausted) && round.recovery.ready(context.now) {
            let addresses = addresses(context, peer, &round.anchor);
            if round
                .recovery
                .rearm(&addresses, None, context.now)
                .is_some()
            {
                round.attempts = 0;
                round.phase = Phase::Waiting(context.now);
            }
        }
        match round.phase {
            Phase::Waiting(at)
                if context.now >= at
                    && state
                        .rounds
                        .values()
                        .filter(|round| matches!(round.phase, Phase::Dialing(..)))
                        .count()
                        < MAX_ACTIVE =>
            {
                if let Some(route) = routes
                    .iter()
                    .filter(|route| {
                        route.peer == peer && route.connection_id != round.anchor.connection_id
                    })
                    .filter_map(|route| route.connection_id.map(|id| (route, id)))
                    .find(|(route, id)| {
                        context.epochs.is_usable(*id)
                            && candidate_is_current(route, &round.epoch)
                            && context
                                .swarm
                                .behaviour()
                                .connection_retention
                                .services(peer, *id)
                                .is_some_and(|services| services.covers(round.required))
                    })
                    .map(|(route, _)| route)
                {
                    let candidate = route.connection_id.expect("filtered native owner");
                    round.replacement_protocol = Some(route.lease.context.protocol);
                    promote(context, &routes, peer, &mut round, candidate);
                    state.rounds.insert(peer, round);
                    continue;
                }
                round.attempts += 1;
                if let Some(address) = round
                    .recovery
                    .attempt(addresses(context, peer, &round.anchor), None)
                {
                    round.replacement_protocol = address_protocol(&address, peer);
                    let options = DialOpts::peer_id(peer)
                        .addresses(vec![address])
                        .condition(PeerCondition::Always)
                        .allocate_new_port()
                        .build();
                    let id = options.connection_id();
                    if context.epochs.dial(context.swarm, options).is_ok() {
                        round.phase = Phase::Dialing(id, context.now + CONNECT_WINDOW);
                        transition(
                            round.event(
                                "infrastructure_tcp_replacement_dialing",
                                "infrastructure_quic_replacement_dialing",
                            ),
                            peer,
                            id,
                            &round.epoch,
                        );
                    } else {
                        retry(&mut round, context.now);
                    }
                } else {
                    retry(&mut round, context.now);
                }
            }
            Phase::Dialing(candidate, deadline) => {
                let valid = context.now < deadline
                    && context.epochs.is_usable(candidate)
                    && context
                        .swarm
                        .behaviour()
                        .connection_retention
                        .services(peer, candidate)
                        .is_some_and(|services| services.covers(round.required))
                    && routes.iter().any(|route| {
                        route.peer == peer
                            && route.connection_id == Some(candidate)
                            && round.candidate_is_current(route)
                    });
                if valid {
                    promote(context, &routes, peer, &mut round, candidate);
                } else if context.now >= deadline || !context.epochs.is_usable(candidate) {
                    let reason = if !context.epochs.connections.contains_key(&candidate) {
                        "terminal_failure"
                    } else if !context.epochs.is_current(candidate) {
                        "obsolete_epoch"
                    } else if context.epochs.retiring.contains(&candidate) {
                        "retiring"
                    } else {
                        "connect_timeout"
                    };
                    log_runtime_event(
                        LogLevel::Info,
                        round.event(
                            "infrastructure_tcp_replacement_failed",
                            "infrastructure_quic_replacement_failed",
                        ),
                        &[
                            ("peer", &peer.to_string()),
                            ("connection_id", &candidate.to_string()),
                            ("generation", &round.epoch.generation().to_string()),
                            ("reason", reason),
                        ],
                    );
                    abandon(context, &state.relay_handoff, peer, candidate);
                    retry(&mut round, context.now);
                }
            }
            Phase::Draining(candidate, deadline) => {
                let path = routes.iter().find(|route| {
                    route.peer == peer
                        && route.connection_id == Some(candidate)
                        && round.matches_replacement(route)
                });
                if path.is_some_and(validated_path_awaits_audit) {
                    state.rounds.insert(peer, round);
                    continue;
                }
                let supported = context
                    .swarm
                    .behaviour()
                    .connection_retention
                    .services(peer, candidate)
                    .is_some_and(|services| services.covers(round.required));
                if !supported
                    || !context.epochs.is_usable(candidate)
                    || !path.is_some_and(|route| validated_path_is_current(route, &round.epoch))
                {
                    restore(context, &routes, peer);
                    let fallback = routes.iter().any(|route| {
                        route.peer == peer
                            && route.is_live()
                            && route.connection_id.is_some_and(|id| {
                                id != candidate
                                    && context.epochs.is_usable(id)
                                    && context
                                        .swarm
                                        .behaviour()
                                        .connection_retention
                                        .services(peer, id)
                                        .is_some_and(|services| services.covers(round.required))
                            })
                    });
                    if fallback {
                        set_outbound(context.swarm.behaviour_mut(), peer, candidate, false);
                        abandon(context, &state.relay_handoff, peer, candidate);
                    }
                    retry(&mut round, context.now);
                } else {
                    for fallback in fallback_routes(&routes, peer, candidate, &round) {
                        let id = fallback.connection_id.expect("filtered connection");
                        set_outbound(context.swarm.behaviour_mut(), peer, id, false);
                        if !relay_required(context, &state.relay_handoff, peer, id)
                            && (context.now >= deadline
                                || !physical_control_handoff::connection_busy(
                                    context.swarm.behaviour(),
                                    peer,
                                    id,
                                ))
                            && context.epochs.mark_retiring(id)
                        {
                            let closed = context.swarm.close_connection(id);
                            log_runtime_event(
                                LogLevel::Info,
                                round.event(
                                    "infrastructure_tcp_fallback_close_requested",
                                    "infrastructure_quic_fallback_close_requested",
                                ),
                                &[
                                    ("peer", &peer.to_string()),
                                    ("connection_id", &id.to_string()),
                                    ("generation", &round.epoch.generation().to_string()),
                                    ("close_requested", &closed.to_string()),
                                ],
                            );
                        }
                    }
                    let audit_pending = routes.iter().any(|route| {
                        route.peer == peer
                            && route.connection_id != Some(candidate)
                            && route.is_live()
                            && route.is_adopted()
                            && route.refresh_required().is_none()
                    });
                    let remaining = fallback_routes(&routes, peer, candidate, &round)
                        .any(|route| route.is_live());
                    if !remaining && !audit_pending {
                        round.phase = Phase::Complete(candidate);
                    }
                }
            }
            _ => {}
        }
        state.rounds.insert(peer, round);
    }
    context
        .swarm
        .behaviour_mut()
        .connection_retention
        .infrastructure_handoff = state;
}

fn promote(
    context: &mut Context<'_>,
    routes: &[Snapshot],
    peer: Libp2pPeerId,
    round: &mut Round,
    candidate: ConnectionId,
) {
    let services = context
        .swarm
        .behaviour()
        .connection_retention
        .services(peer, candidate)
        .expect("validated exact services");
    let behaviour = context.swarm.behaviour_mut();
    behaviour
        .kad
        .set_connection_outbound_enabled(&peer, candidate, services.primary_dht);
    if let Some(kad) = behaviour.pairing_kad.as_mut() {
        kad.set_connection_outbound_enabled(&peer, candidate, services.public_dht);
    }
    if let Some(autonat) = behaviour.autonat.as_mut() {
        autonat.set_connection_outbound_enabled(&peer, candidate, services.autonat);
    }
    if services.relay {
        behaviour.relay.prefer_relay_connection(peer, candidate);
    }
    for fallback in fallback_routes(routes, peer, candidate, round) {
        set_outbound(
            context.swarm.behaviour_mut(),
            peer,
            fallback.connection_id.expect("filtered connection"),
            false,
        );
    }
    round.phase = Phase::Draining(candidate, context.now + DRAIN_WINDOW);
    transition(
        round.event(
            "infrastructure_tcp_replacement_promoted",
            "infrastructure_quic_replacement_promoted",
        ),
        peer,
        candidate,
        &round.epoch,
    );
}

fn fallback_routes<'a>(
    routes: &'a [Snapshot],
    peer: Libp2pPeerId,
    candidate: ConnectionId,
    round: &'a Round,
) -> impl Iterator<Item = &'a Snapshot> {
    routes.iter().filter(move |route| {
        route.peer == peer
            && route.connection_id.is_some_and(|id| id != candidate)
            && route.refresh_required() == Some(true)
            && route.inspection_epoch().as_ref() == Some(&round.epoch)
    })
}

fn addresses(context: &Context<'_>, peer: Libp2pPeerId, anchor: &Snapshot) -> Vec<Multiaddr> {
    physical_control_handoff::candidate_addresses_for(
        anchor,
        peer,
        context.bootstrap,
        context.discovered,
        context.connections,
        context.forwarder,
        context.now,
    )
}

fn restore(context: &mut Context<'_>, routes: &[Snapshot], peer: Libp2pPeerId) {
    for id in routes
        .iter()
        .filter(|route| route.peer == peer && route.is_live())
        .filter_map(|route| route.connection_id)
        .filter(|id| context.epochs.is_usable(*id))
    {
        set_outbound(context.swarm.behaviour_mut(), peer, id, true);
    }
}

fn abandon(
    context: &mut Context<'_>,
    moves: &relay_handoff::State,
    peer: Libp2pPeerId,
    id: ConnectionId,
) {
    if context.epochs.connections.contains_key(&id)
        && !context.forwarder.is_configured_transport_peer(peer)
        && !relay_required(context, moves, peer, id)
    {
        context.epochs.mark_retiring(id);
        context.swarm.close_connection(id);
    }
}

fn retry(round: &mut Round, now: Instant) {
    round.phase = if round.attempts >= MAX_ATTEMPTS {
        round.recovery.exhaust(now);
        transition(
            round.event(
                "infrastructure_tcp_replacement_exhausted",
                "infrastructure_quic_replacement_exhausted",
            ),
            round.anchor.peer,
            round.anchor.connection_id.expect("adopted anchor"),
            &round.epoch,
        );
        Phase::Exhausted
    } else {
        Phase::Waiting(now + Duration::from_secs(5 * (1_u64 << round.attempts)))
    };
    round.replacement_protocol = None;
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
}

fn transition(event: &str, peer: Libp2pPeerId, id: ConnectionId, epoch: &RouteEpoch) {
    log_runtime_event(
        LogLevel::Info,
        event,
        &[
            ("peer", &peer.to_string()),
            ("connection_id", &id.to_string()),
            ("generation", &epoch.generation().to_string()),
        ],
    );
}

#[cfg(test)]
mod tests;
