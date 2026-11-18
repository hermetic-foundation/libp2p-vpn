//! Reservation attempts outlive semantic route rounds until native ownership settles.

use super::*;

const MAX_MOVES: usize = 8;
const MAX_PEERS: usize = 64;
const RESERVATION_WINDOW: Duration = Duration::from_secs(20);

#[derive(Clone)]
pub(super) struct Candidate {
    pub peer: Libp2pPeerId,
    pub id: ConnectionId,
    pub epoch: RouteEpoch,
}

#[derive(Clone)]
struct Anchor {
    peer: Libp2pPeerId,
    connection: ConnectionId,
    listener: ListenerId,
}

struct Move {
    candidate: Candidate,
    listener: ListenerId,
    old: Vec<Anchor>,
    required: IdentifiedServices,
    configured: bool,
    automatic: bool,
    deadline: Instant,
    failed: bool,
}

struct Retired {
    listeners: Vec<ListenerId>,
    required: IdentifiedServices,
    // Aborted setup may return to a working fallback, not necessarily the OS preference.
    fallback: Option<Anchor>,
}

struct Budget {
    epoch: RouteEpoch,
    attempts: u8,
    recovery: Recovery,
}

#[derive(Default)]
pub(super) struct State {
    moves: HashMap<Libp2pPeerId, Move>,
    retired: HashMap<(Libp2pPeerId, ConnectionId), Retired>,
    anchors: HashMap<Libp2pPeerId, Anchor>,
    budgets: HashMap<Libp2pPeerId, Budget>,
}

impl State {
    pub(super) fn owns_peer(&self, peer: Libp2pPeerId) -> bool {
        self.moves.contains_key(&peer)
    }

    pub(super) fn owns_listener(&self, peer: Libp2pPeerId, id: ListenerId) -> bool {
        self.moves
            .get(&peer)
            .is_some_and(|operation| operation.listener == id)
    }

    pub(super) fn listener_closed(&mut self, id: ListenerId) {
        for operation in self
            .moves
            .values_mut()
            .filter(|operation| operation.listener == id)
        {
            operation.failed = true;
        }
        self.anchors.retain(|_, anchor| anchor.listener != id);
    }

    pub(super) fn protects(&self, peer: Libp2pPeerId, id: ConnectionId) -> bool {
        self.moves.get(&peer).is_some_and(|operation| {
            operation.candidate.id == id || operation.old.iter().any(|old| old.connection == id)
        }) || self.retired.contains_key(&(peer, id))
    }

    pub(super) fn can_release(
        &self,
        behaviour: &Behaviour,
        peer: Libp2pPeerId,
        id: ConnectionId,
    ) -> bool {
        self.release_anchor(behaviour, peer, id).is_some()
    }

    fn release_anchor(
        &self,
        behaviour: &Behaviour,
        peer: Libp2pPeerId,
        id: ConnectionId,
    ) -> Option<&Anchor> {
        let Some(retired) = self.retired.get(&(peer, id)) else {
            return None;
        };
        if !behaviour.relay.is_reservation_draining(peer, id) {
            return None;
        }
        retired
            .fallback
            .as_ref()
            .filter(|anchor| {
                anchor.connection != id && anchor_valid(behaviour, anchor, retired.required, false)
            })
            .or_else(|| {
                self.anchors.get(&peer).filter(|anchor| {
                    anchor.connection != id
                        && anchor_valid(behaviour, anchor, retired.required, true)
                })
            })
    }

    fn admit(&mut self, candidate: &Candidate, addresses: &[Multiaddr], now: Instant) -> bool {
        if !self.budgets.contains_key(&candidate.peer) && self.budgets.len() >= MAX_PEERS {
            return false;
        }
        let budget = self
            .budgets
            .entry(candidate.peer)
            .or_insert_with(|| Budget {
                epoch: candidate.epoch.clone(),
                attempts: 0,
                recovery: Recovery::default(),
            });
        if budget.epoch != candidate.epoch {
            *budget = Budget {
                epoch: candidate.epoch.clone(),
                attempts: 0,
                recovery: Recovery::default(),
            };
        }
        if budget.attempts >= MAX_ATTEMPTS {
            if budget.recovery.rearm(addresses, None, now).is_none() {
                return false;
            }
            budget.attempts = 0;
        } else if budget.attempts > 0 && !budget.recovery.ready(now) {
            return false;
        }
        budget.recovery.attempt(addresses.to_vec(), None);
        budget.attempts += 1;
        true
    }

    fn failed(&mut self, peer: Libp2pPeerId, now: Instant) {
        if let Some(budget) = self.budgets.get_mut(&peer) {
            budget.recovery.exhaust(now);
        }
    }
}

fn anchor_valid(
    behaviour: &Behaviour,
    anchor: &Anchor,
    required: IdentifiedServices,
    preferred: bool,
) -> bool {
    behaviour
        .relay
        .reservation_listener_connection(anchor.peer, anchor.listener)
        == Some(anchor.connection)
        && behaviour
            .relay
            .confirmed_reservation_connections(anchor.peer)
            .any(|id| id == anchor.connection)
        && behaviour
            .connection_retention
            .services(anchor.peer, anchor.connection)
            .is_some_and(|services| services.covers(required))
        && behaviour
            .connection_retention
            .physical_routes()
            .and_then(|owners| owners.connection(anchor.peer, anchor.connection))
            .is_some_and(|route| {
                route.is_live()
                    && route.is_adopted()
                    && (!preferred
                        || route.refresh_required() == Some(false)
                        || (route.lease.preferred_dial && route.lease.is_current()))
            })
}

fn owned_anchors(context: &Context<'_>, peer: Libp2pPeerId) -> Vec<Anchor> {
    let mut seen = HashSet::new();
    context
        .readiness
        .relayed_listen_addresses
        .get(&peer)
        .into_iter()
        .flatten()
        .filter(|(listener, _)| {
            context.configured_listeners.contains(listener)
                || context.auto_relay.owns_listener(peer, *listener)
        })
        .filter_map(|(listener, _)| {
            let connection = context
                .swarm
                .behaviour()
                .relay
                .reservation_listener_connection(peer, *listener)?;
            seen.insert(*listener).then_some(Anchor {
                peer,
                connection,
                listener: *listener,
            })
        })
        .collect()
}

fn current_candidate(context: &Context<'_>, routes: &[Snapshot], candidate: &Candidate) -> bool {
    context.epochs.is_usable(candidate.id)
        && candidate.epoch.is_current()
        && routes.iter().any(|route| {
            route.peer == candidate.peer
                && route.connection_id == Some(candidate.id)
                && validated_path_is_current(route, &candidate.epoch)
        })
}

fn transfer_allowed(context: &Context<'_>, peer: Libp2pPeerId) -> bool {
    !context.forwarder.config().network.relay.server
        && context.swarm.behaviour().relay_server.as_ref().is_none()
        && !context.membership.allows_membership_sync(peer)
        && !context.pairing.uses_pairing_relay(peer)
        && !context.pairing.allows_pairing_probe(peer)
        && !context
            .probes
            .by_peer
            .get(&peer)
            .is_some_and(|probe| context.now < probe.expires_at)
}

pub(super) fn drive(
    state: &mut State,
    context: &mut Context<'_>,
    routes: &[Snapshot],
    candidates: &[Candidate],
) {
    // Discover normal acquisition/recovery anchors too, not only our own moves.
    for peer in context
        .readiness
        .accepted_reservations
        .iter()
        .copied()
        .collect::<Vec<_>>()
    {
        if let Some(anchor) = owned_anchors(context, peer).into_iter().find(|anchor| {
            anchor_valid(
                context.swarm.behaviour(),
                anchor,
                IdentifiedServices {
                    relay: true,
                    ..Default::default()
                },
                true,
            )
        }) {
            state.anchors.insert(peer, anchor);
        }
    }
    state
        .anchors
        .retain(|peer, _| context.connections.keys().any(|(owner, _)| owner == peer));
    let peers = state.moves.keys().copied().collect::<Vec<_>>();
    for peer in peers {
        let operation = state.moves.remove(&peer).expect("selected operation");
        let live_binding = context
            .swarm
            .behaviour()
            .relay
            .reservation_listener_connection(peer, operation.listener);
        let new = Anchor {
            peer,
            connection: operation.candidate.id,
            listener: operation.listener,
        };
        let ready = context
            .readiness
            .relayed_listen_addresses
            .get(&peer)
            .is_some_and(|addresses| addresses.iter().any(|(id, _)| *id == operation.listener))
            && anchor_valid(context.swarm.behaviour(), &new, operation.required, false);
        let current = current_candidate(context, routes, &operation.candidate)
            && transfer_allowed(context, peer);
        if ready && current {
            commit(state, context, operation, new, true);
            continue;
        }
        let fallback = operation
            .old
            .iter()
            .find(|old| anchor_valid(context.swarm.behaviour(), old, operation.required, false))
            .cloned();
        if ready && fallback.is_none() {
            // A stale success is not a preferred-path promotion. Retain the only
            // authenticated incoming anchor while fresh-route recovery proceeds.
            commit(state, context, operation, new, false);
            continue;
        }
        if operation.failed || !current || context.now >= operation.deadline {
            if live_binding.is_none() {
                context.swarm.remove_listener(operation.listener);
                context.readiness.forget_listener(peer, operation.listener);
                state.failed(peer, context.now);
                log_move(
                    "relay_reservation_move_failed",
                    peer,
                    operation.candidate.id,
                    operation.listener,
                );
                continue;
            }
            if let Some(fallback) = fallback
                && context.swarm.behaviour_mut().relay.begin_reservation_drain(
                    peer,
                    operation.candidate.id,
                    fallback.connection,
                )
            {
                context.retiring_listeners.insert(operation.listener);
                context.readiness.forget_listener(peer, operation.listener);
                state.retired.insert(
                    (peer, operation.candidate.id),
                    Retired {
                        listeners: vec![operation.listener],
                        required: operation.required,
                        fallback: Some(fallback),
                    },
                );
                state.failed(peer, context.now);
                log_move(
                    "relay_reservation_move_aborting",
                    peer,
                    operation.candidate.id,
                    operation.listener,
                );
                continue;
            }
            // Assigned native work can have committed remotely. Do not discard
            // its listener solely because our observation deadline elapsed.
        }
        state.moves.insert(peer, operation);
    }
    cleanup(state, context);
    for candidate in candidates {
        if state.moves.len() >= MAX_MOVES {
            break;
        }
        if state.moves.contains_key(&candidate.peer)
            || !current_candidate(context, routes, candidate)
            || !transfer_allowed(context, candidate.peer)
        {
            continue;
        }
        let peer = candidate.peer;
        let stale = routes
            .iter()
            .filter(|route| route.peer == peer && route.refresh_required() == Some(true))
            .filter_map(|route| route.connection_id)
            .collect::<HashSet<_>>();
        let old = owned_anchors(context, peer)
            .into_iter()
            .filter(|old| {
                stale.contains(&old.connection)
                    && !context
                        .swarm
                        .behaviour()
                        .relay
                        .is_reservation_draining(peer, old.connection)
            })
            .collect::<Vec<_>>();
        if old.is_empty() {
            continue;
        }
        let mut required = IdentifiedServices {
            relay: true,
            ..Default::default()
        };
        for services in old.iter().filter_map(|old| {
            context
                .swarm
                .behaviour()
                .connection_retention
                .services(peer, old.connection)
        }) {
            required.include(services);
        }
        if !context
            .swarm
            .behaviour()
            .connection_retention
            .services(peer, candidate.id)
            .is_some_and(|services| services.covers(required))
        {
            continue;
        }
        if context.auto_relay.pending_reservations.contains_key(&peer) {
            continue;
        }
        let configured = old
            .iter()
            .any(|old| context.configured_listeners.contains(&old.listener));
        let automatic = old
            .iter()
            .any(|old| context.auto_relay.owns_listener(peer, old.listener));
        if let Some(new) = owned_anchors(context, peer).into_iter().find(|anchor| {
            anchor.connection == candidate.id
                && anchor_valid(context.swarm.behaviour(), anchor, required, true)
        }) {
            let operation = Move {
                candidate: candidate.clone(),
                listener: new.listener,
                old,
                required,
                configured,
                automatic,
                deadline: context.now,
                failed: false,
            };
            commit(state, context, operation, new, true);
            continue;
        }
        let Some(address) = context
            .connections
            .get(&(peer, candidate.id))
            .and_then(|endpoint| auto_relay_candidate_address(peer, endpoint.get_remote_address()))
        else {
            continue;
        };
        if !state.admit(candidate, std::slice::from_ref(&address), context.now) {
            continue;
        }
        let Ok(listener) = context.swarm.listen_on(address.with(Protocol::P2pCircuit)) else {
            state.failed(peer, context.now);
            continue;
        };
        if !context
            .swarm
            .behaviour_mut()
            .relay
            .pin_reservation_listener(peer, listener, candidate.id)
        {
            context.swarm.remove_listener(listener);
            state.failed(peer, context.now);
            continue;
        }
        log_move(
            "relay_reservation_move_started",
            peer,
            candidate.id,
            listener,
        );
        state.moves.insert(
            peer,
            Move {
                candidate: candidate.clone(),
                listener,
                old,
                required,
                configured,
                automatic,
                deadline: context.now + RESERVATION_WINDOW,
                failed: false,
            },
        );
    }
    state.budgets.retain(|peer, budget| {
        budget.epoch.is_current()
            || state.moves.contains_key(peer)
            || state.retired.keys().any(|(owner, _)| owner == peer)
            || context.connections.keys().any(|(owner, _)| owner == peer)
    });
}

fn commit(
    state: &mut State,
    context: &mut Context<'_>,
    operation: Move,
    new: Anchor,
    preferred: bool,
) {
    let peer = new.peer;
    if preferred {
        context
            .swarm
            .behaviour_mut()
            .relay
            .prefer_relay_connection(peer, new.connection);
    }
    if operation.configured {
        context.configured_listeners.insert(new.listener);
    }
    if operation.automatic {
        context.auto_relay.reservation_listeners.insert(
            peer,
            AutoRelayListener {
                id: new.listener,
                connection: new.connection,
            },
        );
        context.auto_relay.record_reservation_accepted(peer);
    }
    context.readiness.record_reservation_accepted(peer);
    state.anchors.insert(peer, new.clone());
    if preferred {
        for old in operation.old {
            if old.connection == new.connection {
                continue;
            }
            if context.swarm.behaviour_mut().relay.begin_reservation_drain(
                peer,
                old.connection,
                new.connection,
            ) {
                context.configured_listeners.remove(&old.listener);
                context.retiring_listeners.insert(old.listener);
                context.readiness.forget_listener(peer, old.listener);
                let entry = state
                    .retired
                    .entry((peer, old.connection))
                    .or_insert_with(|| Retired {
                        listeners: Vec::new(),
                        required: operation.required,
                        fallback: None,
                    });
                if !entry.listeners.contains(&old.listener) {
                    entry.listeners.push(old.listener);
                }
            }
        }
    }
    log_move(
        if preferred {
            "relay_reservation_move_committed"
        } else {
            "relay_reservation_fallback_retained"
        },
        peer,
        new.connection,
        new.listener,
    );
}

fn cleanup(state: &mut State, context: &mut Context<'_>) {
    let keys = state.retired.keys().copied().collect::<Vec<_>>();
    for (peer, id) in keys {
        if !context.connections.contains_key(&(peer, id)) {
            let retired = state
                .retired
                .remove(&(peer, id))
                .expect("selected retirement");
            for listener in retired.listeners {
                context.swarm.remove_listener(listener);
                context.readiness.forget_listener(peer, listener);
            }
            continue;
        }
        if !transfer_allowed(context, peer) {
            continue;
        }
        let Some(replacement) = state
            .release_anchor(context.swarm.behaviour(), peer, id)
            .cloned()
        else {
            continue;
        };
        set_outbound(context.swarm.behaviour_mut(), peer, id, false);
        set_outbound(
            context.swarm.behaviour_mut(),
            peer,
            replacement.connection,
            true,
        );
        context
            .swarm
            .behaviour_mut()
            .relay
            .prefer_relay_connection(peer, replacement.connection);
        if context
            .swarm
            .behaviour()
            .relay
            .has_connection_dependencies(peer, id)
            || physical_control_handoff::connection_busy(context.swarm.behaviour(), peer, id)
        {
            continue;
        }
        if context.epochs.mark_retiring(id) {
            let requested = context.swarm.close_connection(id);
            log_runtime_event(
                LogLevel::Info,
                "relay_reservation_old_transport_close_requested",
                &[
                    ("peer", &peer.to_string()),
                    ("connection_id", &id.to_string()),
                    ("close_requested", &requested.to_string()),
                ],
            );
        }
    }
}

fn log_move(event: &str, peer: Libp2pPeerId, connection: ConnectionId, listener: ListenerId) {
    log_runtime_event(
        LogLevel::Info,
        event,
        &[
            ("peer", &peer.to_string()),
            ("connection_id", &connection.to_string()),
            ("listener", &listener.to_string()),
        ],
    );
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
