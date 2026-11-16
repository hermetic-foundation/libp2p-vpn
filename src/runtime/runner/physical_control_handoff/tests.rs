use super::*;
use crate::runtime::physical_network::linux::control::{ControlRoutes, Registration};
use std::sync::Arc;

async fn route(peer: Libp2pPeerId, id: usize) -> (Arc<ControlRoutes>, Registration, Snapshot) {
    let routes = Arc::new(ControlRoutes::new(8));
    let (_, lease) = routes
        .egress
        .prepare_tcp("127.0.0.1:4001".parse().unwrap(), false, &[])
        .await
        .unwrap();
    let registration = routes.register(peer, lease).unwrap();
    registration
        .bind_connection(ConnectionId::new_unchecked(id))
        .unwrap();
    registration.adopt().unwrap();
    let snapshot = routes
        .connection(peer, ConnectionId::new_unchecked(id))
        .unwrap();
    (routes, registration, snapshot)
}

fn forwarder(peer: Libp2pPeerId) -> Forwarder {
    let identity = NodeIdentity::generate_ed25519().unwrap();
    let config: Config = serde_json::from_value(serde_json::json!({
        "network": {"name": "control-handoff", "private_key": identity.private_key},
        "peers": [{"id": peer.to_string()}]
    }))
    .unwrap();
    Forwarder::from_config(&config).unwrap()
}

#[tokio::test]
async fn protection_is_peer_scoped_and_exhaustion_stops_retries() {
    let peer = Libp2pPeerId::random();
    let (_routes, _registration, anchor) = route(peer, 1).await;
    let now = Instant::now();
    let mut state = State::default();
    state.rounds.insert(
        peer,
        Round {
            generation: anchor.lease.route.generation,
            anchor,
            attempts: 1,
            phase: Phase::Dialing(ConnectionId::new_unchecked(2), now + CONNECT_WINDOW),
            draining: HashSet::new(),
        },
    );
    assert!(state.protects(peer, now));
    assert!(!state.protects(Libp2pPeerId::random(), now));
    assert!(state.is_candidate(peer, ConnectionId::new_unchecked(2)));
    assert!(!state.is_candidate(peer, ConnectionId::new_unchecked(1)));
    let round = state.rounds.get_mut(&peer).unwrap();
    retry(round, now);
    assert!(matches!(round.phase, Phase::Waiting(until) if until == now + Duration::from_secs(10)));
    round.attempts = MAX_ATTEMPTS;
    retry(round, now);
    assert!(matches!(round.phase, Phase::Exhausted));
    assert!(!state.protects(peer, now));
}

#[test]
fn duplicate_grace_expires_and_does_not_protect_other_peers() {
    let peer = Libp2pPeerId::random();
    let now = Instant::now();
    let mut state = State::default();
    state.grace.insert(
        (peer, ConnectionId::new_unchecked(1)),
        now + DUPLICATE_GRACE,
    );
    assert!(state.protects(peer, now));
    assert!(!state.protects(peer, now + DUPLICATE_GRACE));
    assert!(!state.protects(Libp2pPeerId::random(), now));
    let later = now + DUPLICATE_GRACE - Duration::from_secs(1);
    state.grace.insert(
        (peer, ConnectionId::new_unchecked(2)),
        later + DUPLICATE_GRACE,
    );
    assert!(state.protects(peer, now + DUPLICATE_GRACE));
    observe_closed(&mut state, peer, ConnectionId::new_unchecked(1));
    assert!(state.protects(peer, now + DUPLICATE_GRACE));
    observe_closed(&mut state, peer, ConnectionId::new_unchecked(2));
    assert!(!state.protects(peer, now + DUPLICATE_GRACE));
}

#[tokio::test]
async fn native_validation_owner_survives_semantic_round_removal_until_terminal_delivery() {
    let peer = Libp2pPeerId::random();
    let mut node =
        super::super::tests::membership_sync_test_node(NodeIdentity::generate_ed25519().unwrap());
    let request = node.swarm.behaviour_mut().control.send_request(
        &peer,
        ControlRequest::Capabilities(ControlCapabilities::local("lab", None, 1280)),
    );
    assert!(
        !node
            .swarm
            .behaviour()
            .connection_retention
            .owns_physical_validation(request)
    );
    let (cancellation, _) = AbortHandle::new_pair();
    node.swarm
        .behaviour_mut()
        .connection_retention
        .physical_handoff
        .pending
        .insert(
            request,
            Pending {
                peer,
                connection: ConnectionId::new_unchecked(1),
                generation: 1,
                owner: 1,
                deadline: Instant::now() + VALIDATION_WINDOW,
                cancellation,
            },
        );
    // Checkpoint response routing must leave native completion with this owner,
    // even after revocation/cancellation has removed its semantic round.
    assert!(
        node.swarm
            .behaviour()
            .connection_retention
            .physical_handoff
            .rounds
            .is_empty()
    );
    assert!(
        node.swarm
            .behaviour()
            .connection_retention
            .owns_physical_validation(request)
    );
    node.swarm
        .behaviour_mut()
        .connection_retention
        .physical_handoff
        .pending
        .remove(&request);
    assert!(
        !node
            .swarm
            .behaviour()
            .connection_retention
            .owns_physical_validation(request)
    );
}

#[tokio::test]
async fn bound_but_not_yet_adopted_tcp_duplicate_gets_grace() {
    let peer = Libp2pPeerId::random();
    let mut node =
        super::super::tests::membership_sync_test_node(NodeIdentity::generate_ed25519().unwrap());
    let owners = node
        .swarm
        .behaviour()
        .connection_retention
        .physical_routes()
        .unwrap()
        .clone();
    let (_, lease) = owners
        .egress
        .prepare_tcp("127.0.0.1:4001".parse().unwrap(), false, &[])
        .await
        .unwrap();
    let owner = owners.register(peer, lease).unwrap();
    let id = ConnectionId::new_unchecked(2);
    owner.bind_connection(id).unwrap();
    assert!(owners.connection(peer, id).is_none());
    assert!(owners.bound_connection(peer, id).is_some());
    let endpoint = ConnectedPoint::Listener {
        local_addr: "/ip4/127.0.0.1/tcp/4001".parse().unwrap(),
        send_back_addr: "/ip4/127.0.0.1/tcp/50000".parse().unwrap(),
    };
    let connections = HashMap::from([
        ((peer, ConnectionId::new_unchecked(1)), endpoint.clone()),
        ((peer, id), endpoint),
    ]);
    let forwarder = forwarder(peer);
    let now = Instant::now();
    observe_established(&mut node.swarm, &forwarder, &connections, peer, id, now);
    assert!(
        node.swarm
            .behaviour()
            .connection_retention
            .physical_handoff
            .protects(peer, now)
    );
    let deadline = node
        .swarm
        .behaviour()
        .connection_retention
        .physical_handoff
        .grace[&(peer, id)];
    observe_established(
        &mut node.swarm,
        &forwarder,
        &connections,
        peer,
        id,
        now + Duration::from_secs(1),
    );
    assert_eq!(
        node.swarm
            .behaviour()
            .connection_retention
            .physical_handoff
            .grace[&(peer, id)],
        deadline
    );
}

#[test]
fn direct_dns_tcp_candidates_preserve_peer_scope_and_reject_transport_suffixes() {
    let peer = Libp2pPeerId::random();
    for address in [
        "/dns/example.invalid/tcp/4001",
        "/dns4/example.invalid/tcp/4001",
        "/dns6/example.invalid/tcp/4001",
    ] {
        let address: Multiaddr = address.parse().unwrap();
        assert!(direct_tcp_address(&address, peer));
        assert!(direct_tcp_address(
            &address.clone().with(Protocol::P2p(peer)),
            peer
        ));
        assert!(!direct_tcp_address(
            &address.clone().with(Protocol::P2p(Libp2pPeerId::random())),
            peer
        ));
        assert!(!direct_tcp_address(
            &address.with(Protocol::P2pCircuit),
            peer
        ));
    }
}

#[tokio::test]
async fn relay_roles_are_not_retired_as_redundant_overlay_fallbacks() {
    let peer = Libp2pPeerId::random();
    let forwarder = forwarder(peer);
    let node =
        super::super::tests::membership_sync_test_node(NodeIdentity::generate_ed25519().unwrap());
    let id = ConnectionId::new_unchecked(1);
    assert!(!required_relay_owner(
        node.swarm.behaviour(),
        &forwarder,
        peer,
        id
    ));
    let mut config = forwarder.config().clone();
    config
        .network
        .relay
        .reservations
        .push(format!("/ip4/127.0.0.1/tcp/4001/p2p/{peer}/p2p-circuit"));
    let reserved = Forwarder::from_config(&config).unwrap();
    assert!(required_relay_owner(
        node.swarm.behaviour(),
        &reserved,
        peer,
        id
    ));
    assert!(!required_relay_owner(
        node.swarm.behaviour(),
        &reserved,
        Libp2pPeerId::random(),
        id
    ));
    config.network.relay.server = true;
    let server = Forwarder::from_config(&config).unwrap();
    assert!(!eligible(&server, peer));
    assert!(required_relay_owner(
        node.swarm.behaviour(),
        &server,
        peer,
        id
    ));
}

#[tokio::test]
async fn rollback_restores_fallback_packet_selection_and_duplicate_close_is_idempotent() {
    let peer = Libp2pPeerId::random();
    let (_old_routes, _old_owner, old) = route(peer, 1).await;
    let (_new_routes, _new_owner, new) = route(peer, 2).await;
    let old_id = old.connection_id.unwrap();
    let new_id = new.connection_id.unwrap();
    let forwarder = forwarder(peer);
    let mut node =
        super::super::tests::membership_sync_test_node(NodeIdentity::generate_ed25519().unwrap());
    let mut epochs = ConnectionEpochs::default();
    let mut paths = PathSet::new();
    let metrics = RuntimeMetrics::default();
    let endpoint = ConnectedPoint::Listener {
        local_addr: "/ip4/127.0.0.1/tcp/4001".parse().unwrap(),
        send_back_addr: "/ip4/127.0.0.1/tcp/50000".parse().unwrap(),
    };
    for id in [old_id, new_id] {
        epochs.record_started(id);
        assert!(epochs.record_established(id));
        record_path_established(&mut paths, &forwarder, &metrics, peer, id, &endpoint);
    }
    assert_eq!(
        paths
            .best_for(PeerId::from_libp2p(peer))
            .unwrap()
            .latest_connection_id,
        Some(new_id)
    );
    let round = Round {
        generation: new.lease.route.generation,
        anchor: old.clone(),
        attempts: 1,
        phase: Phase::Draining(new_id, Instant::now() + DRAIN_WINDOW),
        draining: HashSet::new(),
    };
    rollback(
        &mut node.swarm,
        &mut epochs,
        &forwarder,
        &mut paths,
        &metrics,
        &[old, new],
        peer,
        &round,
    );
    assert!(!epochs.is_usable(new_id));
    assert!(epochs.is_usable(old_id));
    let selected = paths.best_for(PeerId::from_libp2p(peer)).unwrap();
    assert_eq!(selected.latest_connection_id, Some(old_id));
    assert_eq!(selected.established_connections, 1);
    record_path_closed(&mut paths, &forwarder, &metrics, peer, new_id, &endpoint);
    assert_eq!(paths.best_for(PeerId::from_libp2p(peer)).unwrap(), selected);
}

#[tokio::test]
async fn next_route_change_preserves_sole_validated_path_after_fallbacks_are_drained() {
    let peer = Libp2pPeerId::random();
    let (_old_routes, old_owner, old) = route(peer, 1).await;
    let (_new_routes, _new_owner, new) = route(peer, 2).await;
    let id = new.connection_id.unwrap();
    let forwarder = forwarder(peer);
    let mut node =
        super::super::tests::membership_sync_test_node(NodeIdentity::generate_ed25519().unwrap());
    let mut epochs = ConnectionEpochs::default();
    let mut paths = PathSet::new();
    let metrics = RuntimeMetrics::default();
    let endpoint = ConnectedPoint::Listener {
        local_addr: "/ip4/127.0.0.1/tcp/4001".parse().unwrap(),
        send_back_addr: "/ip4/127.0.0.1/tcp/50000".parse().unwrap(),
    };
    for connection in [old.connection_id.unwrap(), id] {
        epochs.record_started(connection);
        assert!(epochs.record_established(connection));
    }
    record_path_established(&mut paths, &forwarder, &metrics, peer, id, &endpoint);
    let round = Round {
        generation: new.lease.route.generation,
        anchor: old.clone(),
        attempts: 1,
        phase: Phase::Draining(id, Instant::now() + DRAIN_WINDOW),
        draining: HashSet::new(),
    };
    // A bound but unpublished sibling is not a working packet fallback.
    rollback(
        &mut node.swarm,
        &mut epochs,
        &forwarder,
        &mut paths,
        &metrics,
        &[old.clone(), new.clone()],
        peer,
        &round,
    );
    assert!(epochs.is_usable(id));
    assert!(paths.contains_healthy_connection(
        PeerId::from_libp2p(peer),
        PathKind::DirectTcpStream,
        None,
        id
    ));
    assert!(!paths.contains_healthy_connection(
        PeerId::from_libp2p(peer),
        PathKind::DirectTcpStream,
        None,
        old.connection_id.unwrap()
    ));
    drop(old_owner);
    rollback(
        &mut node.swarm,
        &mut epochs,
        &forwarder,
        &mut paths,
        &metrics,
        &[new],
        peer,
        &round,
    );
    assert!(epochs.is_usable(id));
    let selected = paths.best_for(PeerId::from_libp2p(peer)).unwrap();
    assert_eq!(selected.latest_connection_id, Some(id));
    assert_eq!(selected.established_connections, 1);
}

#[tokio::test]
async fn candidate_and_request_evidence_require_exact_live_owner_and_generation() {
    let peer = Libp2pPeerId::random();
    let (_routes, registration, route) = route(peer, 2).await;
    let generation = route.lease.route.generation;
    assert!(candidate_is_current(&route, generation));
    assert!(!candidate_is_current(&route, generation + 1));
    let mut epochs = ConnectionEpochs::default();
    let id = ConnectionId::new_unchecked(2);
    epochs.record_started(id);
    epochs.record_established(id);
    let (cancellation, _) = AbortHandle::new_pair();
    let mut pending = Pending {
        peer,
        connection: id,
        generation,
        owner: route.id,
        deadline: Instant::now() + VALIDATION_WINDOW,
        cancellation,
    };
    let forwarder = forwarder(peer);
    assert!(pending_is_current(
        &pending,
        &[route.clone()],
        &forwarder,
        &epochs
    ));
    pending.owner += 1;
    assert!(!pending_is_current(
        &pending,
        &[route.clone()],
        &forwarder,
        &epochs
    ));
    pending.owner = route.id;
    pending.connection = ConnectionId::new_unchecked(3);
    assert!(!pending_is_current(
        &pending,
        &[route.clone()],
        &forwarder,
        &epochs
    ));
    pending.connection = id;
    pending.peer = Libp2pPeerId::random();
    assert!(!pending_is_current(
        &pending,
        &[route.clone()],
        &forwarder,
        &epochs
    ));
    pending.peer = peer;
    epochs.mark_retiring(id);
    assert!(!pending_is_current(
        &pending,
        &[route.clone()],
        &forwarder,
        &epochs
    ));
    drop(registration);
    assert!(!candidate_is_current(&route, generation));
}

#[tokio::test]
async fn losing_anchor_does_not_cancel_owned_recovery_but_stops_new_idle_retries() {
    let peer = Libp2pPeerId::random();
    let (_routes, owner, anchor) = route(peer, 1).await;
    let mut round = Round {
        generation: anchor.lease.route.generation,
        anchor,
        attempts: 1,
        phase: Phase::Dialing(
            ConnectionId::new_unchecked(2),
            Instant::now() + CONNECT_WINDOW,
        ),
        draining: HashSet::new(),
    };
    drop(owner);
    assert!(round.current(&[]));
    round.phase = Phase::Waiting(Instant::now());
    assert!(!round.current(&[]));
}

#[tokio::test]
async fn remote_fallback_retirement_is_exact_owned_and_recorded_only_once_after_promotion() {
    let peer = Libp2pPeerId::random();
    let (_routes, _owner, anchor) = route(peer, 1).await;
    let old = ConnectionId::new_unchecked(1);
    let new = ConnectionId::new_unchecked(2);
    let mut state = State::default();
    state.rounds.insert(
        peer,
        Round {
            generation: anchor.lease.route.generation,
            anchor,
            attempts: 1,
            phase: Phase::Draining(new, Instant::now() + DRAIN_WINDOW),
            draining: HashSet::from([old]),
        },
    );
    observe_closed(&mut state, Libp2pPeerId::random(), old);
    observe_closed(&mut state, peer, new);
    assert_eq!(state.rounds[&peer].draining, HashSet::from([old]));
    observe_closed(&mut state, peer, old);
    assert!(state.rounds[&peer].draining.is_empty());
    observe_closed(&mut state, peer, old);
    assert!(state.rounds[&peer].draining.is_empty());
}

#[test]
fn candidates_exclude_relays_quic_other_peers_quarantine_and_listener_ephemeral_ports() {
    let peer = Libp2pPeerId::random();
    let other = Libp2pPeerId::random();
    let mut discovered = DiscoveredPeerAddresses::default();
    for (who, address) in [
        (peer, "/ip4/127.0.0.1/tcp/4001"),
        (peer, "/ip4/127.0.0.1/udp/4001/quic-v1"),
        (peer, "/ip4/127.0.0.1/tcp/4001/p2p-circuit"),
        (other, "/ip4/127.0.0.1/tcp/4002"),
        (peer, "/ip4/127.0.0.1/tcp/4003"),
    ] {
        discovered.insert(who, address.parse().unwrap());
    }
    discovered.addresses.last_mut().unwrap().quarantined_until =
        Some(Instant::now() + Duration::from_secs(60));
    let connections = HashMap::from([(
        (peer, ConnectionId::new_unchecked(1)),
        ConnectedPoint::Listener {
            local_addr: "/ip4/127.0.0.1/tcp/4001".parse().unwrap(),
            send_back_addr: "/ip4/127.0.0.1/tcp/50000".parse().unwrap(),
        },
    )]);
    let configured = [(peer, "/ip4/127.0.0.1/tcp/4001".parse().unwrap())];
    assert_eq!(
        candidate_addresses(
            peer,
            &configured,
            &discovered,
            &connections,
            &forwarder(peer),
            Instant::now()
        ),
        vec!["/ip4/127.0.0.1/tcp/4001".parse::<Multiaddr>().unwrap()]
    );
}
