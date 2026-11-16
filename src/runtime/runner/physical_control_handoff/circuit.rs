//! Overlay circuit identity and physical relay identity are separate proofs.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Route {
    pub relay: Libp2pPeerId,
    pub outer: ConnectionId,
}

pub(super) struct Replacement {
    pub peer: Libp2pPeerId,
    pub old: ConnectionId,
    pub route: Route,
    pub pin: Option<relay::client::CircuitDialPin>,
}

pub(super) fn binding(
    behaviour: &Behaviour,
    peer: Libp2pPeerId,
    inner: ConnectionId,
    circuit: bool,
) -> Option<Route> {
    if !circuit {
        return None;
    }
    let (relay, outer) = behaviour.relay.circuit_connection_owner(peer, inner)?;
    Some(Route { relay, outer })
}

pub(super) fn established_binding_fields(
    behaviour: &Behaviour,
    peer: Libp2pPeerId,
    inner: ConnectionId,
) -> Option<[(&'static str, String); 8]> {
    let owner = binding(behaviour, peer, inner, true)?;
    let physical = behaviour
        .connection_retention
        .physical_routes()?
        .connection(owner.relay, owner.outer)?;
    if !physical.is_live() || !physical.is_adopted() {
        return None;
    }
    // A real binding without its exact socket owner is not a physical proof.
    // Lease metadata describes ownership, not a fresh preferred-route audit.
    Some([
        ("peer", peer.to_string()),
        ("connection_id", inner.to_string()),
        ("relay", owner.relay.to_string()),
        ("outer", owner.outer.to_string()),
        (
            "physical_transport",
            match physical.lease.context.protocol {
                SocketProtocol::Tcp => "tcp",
                SocketProtocol::Udp => "quic",
            }
            .to_owned(),
        ),
        ("source", physical.lease.local_addr.to_string()),
        (
            "interface",
            physical.lease.route.interface_index.to_string(),
        ),
        ("generation", physical.lease.route.generation.to_string()),
    ])
}

pub(super) fn route_for<'a>(
    behaviour: &Behaviour,
    routes: &'a [Snapshot],
    peer: Libp2pPeerId,
    connection: ConnectionId,
    circuit: Option<Route>,
) -> Option<&'a Snapshot> {
    let (owner, id) = if let Some(expected) = circuit {
        let actual = binding(behaviour, peer, connection, true)?;
        if actual != expected {
            return None;
        }
        (actual.relay, actual.outer)
    } else {
        // A circuit is never a physical socket, even if a caller supplied no binding.
        if behaviour
            .relay
            .circuit_connection_owner(peer, connection)
            .is_some()
        {
            return None;
        }
        (peer, connection)
    };
    routes
        .iter()
        .find(|route| route.peer == owner && route.connection_id == Some(id))
}

pub(super) fn admit_rounds(
    state: &mut State,
    behaviour: &Behaviour,
    routes: &[Snapshot],
    forwarder: &Forwarder,
    connections: &HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
    epochs: &ConnectionEpochs,
    now: Instant,
) {
    let candidates = behaviour
        .connection_retention
        .infrastructure_handoff
        .validated_candidates()
        .chain(state.validated_candidates())
        .collect::<Vec<_>>();
    for ((peer, inner), endpoint) in connections {
        if state.rounds.len() >= MAX_ROUNDS {
            break;
        }
        if !endpoint.is_relayed()
            || state.rounds.contains_key(peer)
            || !epochs.is_usable(*inner)
            || !eligible(forwarder, *peer)
        {
            continue;
        }
        let Some(old) = binding(behaviour, *peer, *inner, true) else {
            continue;
        };
        let Some(anchor) = routes.iter().find(|route| {
            route.peer == old.relay
                && route.connection_id == Some(old.outer)
                && route.refresh_required() == Some(true)
        }) else {
            continue;
        };
        let epoch = anchor
            .inspection_epoch()
            .expect("current stale-route audit");
        let replacement = candidates.iter().find(|(relay, outer, generation)| {
            *relay == old.relay
                && *outer != old.outer
                && generation == &epoch
                && epochs.is_usable(*outer)
                && behaviour
                    .connection_retention
                    .services(*relay, *outer)
                    .is_some_and(|services| services.relay)
                && routes.iter().any(|route| {
                    route.peer == *relay
                        && route.connection_id == Some(*outer)
                        && validated_path_is_current(route, &epoch)
                })
        });
        let Some((relay, outer, _)) = replacement else {
            continue;
        };
        let replacement_protocol = routes
            .iter()
            .find(|route| route.peer == *relay && route.connection_id == Some(*outer))
            .map(|route| route.lease.context.protocol);
        state.rounds.insert(
            *peer,
            Round {
                anchor: anchor.clone(),
                replacement_protocol,
                epoch,
                attempts: 0,
                phase: Phase::Waiting(now + Duration::from_secs(1)),
                draining: HashSet::new(),
                recovery: Recovery::default(),
                circuit: Some(Replacement {
                    peer: *peer,
                    old: *inner,
                    route: Route {
                        relay: *relay,
                        outer: *outer,
                    },
                    pin: None,
                }),
            },
        );
        log_runtime_event(
            LogLevel::Info,
            "control_relay_handoff_admitted",
            &[
                ("peer", &peer.to_string()),
                ("old_circuit", &inner.to_string()),
                ("relay", &relay.to_string()),
                ("old_outer", &old.outer.to_string()),
                ("replacement_outer", &outer.to_string()),
            ],
        );
    }
}

pub(super) fn addresses(
    round: &Round,
    connections: &HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
    peer: Libp2pPeerId,
) -> Option<Vec<Multiaddr>> {
    let circuit = round.circuit.as_ref()?;
    Some(
        connections
            .get(&(circuit.route.relay, circuit.route.outer))
            .filter(|endpoint| {
                address_protocol(endpoint.get_remote_address(), circuit.route.relay).is_some()
            })
            .and_then(|endpoint| {
                auto_relay_candidate_address(circuit.route.relay, endpoint.get_remote_address())
            })
            .map(|address| vec![address.with(Protocol::P2pCircuit).with(Protocol::P2p(peer))])
            .unwrap_or_default(),
    )
}

pub(super) fn fallbacks(
    behaviour: &Behaviour,
    routes: &[Snapshot],
    connections: &HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
    peer: Libp2pPeerId,
    candidate: ConnectionId,
    epoch: &RouteEpoch,
) -> Vec<ConnectionId> {
    connections
        .iter()
        .filter_map(|((owner, inner), endpoint)| {
            if *owner != peer || *inner == candidate || !endpoint.is_relayed() {
                return None;
            }
            let binding = binding(behaviour, peer, *inner, true)?;
            routes
                .iter()
                .any(|route| {
                    route.peer == binding.relay
                        && route.connection_id == Some(binding.outer)
                        && route.refresh_required() == Some(true)
                        && route.inspection_epoch().as_ref() == Some(epoch)
                })
                .then_some(*inner)
        })
        .collect()
}

// `owner` is the live native association observed by the caller, not a peer
// preference. An unknown audit or a close already in progress is not recovery.
pub(super) fn release_recovered_fallback(
    round: &mut Round,
    routes: &[Snapshot],
    epochs: &ConnectionEpochs,
    inner: ConnectionId,
    owner: Option<Route>,
) -> Option<Route> {
    if round.circuit.is_none() || !matches!(round.phase, Phase::Draining(..)) {
        return None;
    }
    let owner = owner?;
    if !epochs.is_usable(inner)
        || !epochs.is_usable(owner.outer)
        || !routes.iter().any(|route| {
            route.peer == owner.relay
                && route.connection_id == Some(owner.outer)
                && route.refresh_required() == Some(false)
                && route.inspection_epoch().as_ref() == Some(&round.epoch)
        })
    {
        return None;
    }
    round.draining.remove(&inner).then_some(owner)
}

pub(super) fn rollback(
    swarm: &mut Swarm<Behaviour>,
    epochs: &mut ConnectionEpochs,
    paths: &mut PathSet,
    metrics: &RuntimeMetrics,
    routes: &[Snapshot],
    peer: Libp2pPeerId,
    round: &Round,
) {
    let circuit = round.circuit.as_ref().expect("circuit rollback");
    let fallback = binding(swarm.behaviour(), peer, circuit.old, true)
        .filter(|_| epochs.is_usable(circuit.old))
        .filter(|binding| {
            paths.contains_healthy_connection(
                PeerId::from_libp2p(peer),
                PathKind::CircuitRelay,
                Some(PeerId::from_libp2p(binding.relay)),
                circuit.old,
            )
        });
    if let Some(candidate) = round.candidate() {
        if fallback.is_some() {
            let lost = paths.record_failed_connection(
                PeerId::from_libp2p(peer),
                PathKind::CircuitRelay,
                Some(PeerId::from_libp2p(circuit.route.relay)),
                candidate,
            );
            record_path_selection_change(metrics, lost.selection_change);
            set_outbound(swarm.behaviour_mut(), peer, candidate, false);
            epochs.mark_retiring(candidate);
            swarm.close_connection(candidate);
            transition(
                "control_relay_replacement_rolled_back",
                peer,
                candidate,
                round.epoch.generation(),
            );
        } else {
            transition(
                "control_relay_promotion_superseded",
                peer,
                candidate,
                round.epoch.generation(),
            );
        }
    }
    for route in routes.iter().filter(|route| route.is_live()) {
        // Only restore overlay circuits belonging to this peer, not the relay's
        // unrelated physical service requests.
        for id in &round.draining {
            if epochs.is_usable(*id)
                && binding(swarm.behaviour(), peer, *id, true).is_some_and(|binding| {
                    route.peer == binding.relay && route.connection_id == Some(binding.outer)
                })
            {
                set_outbound(swarm.behaviour_mut(), peer, *id, true);
            }
        }
    }
    if fallback.is_some() {
        set_outbound(swarm.behaviour_mut(), peer, circuit.old, true);
    }
}

#[cfg(test)]
mod tests;
