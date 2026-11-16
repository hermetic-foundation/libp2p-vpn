use super::*;
use crate::runtime::physical_network::linux::control::{ControlRoutes, Registration};
use std::sync::Arc;

#[tokio::test]
async fn overlay_drain_includes_dispatch_owned_by_the_native_dht() {
    use futures::future::poll_fn;
    use libp2p::swarm::{FromSwarm, NetworkBehaviour, NotifyHandler, ToSwarm};
    let peer = Libp2pPeerId::random();
    let id = ConnectionId::new_unchecked(901);
    let mut node =
        super::super::tests::membership_sync_test_node(NodeIdentity::generate_ed25519().unwrap());
    let local = node.local_peer_id;
    let mut config = kad::Config::new(libp2p::StreamProtocol::new(PUBLIC_IPFS_KADEMLIA_PROTOCOL));
    config.set_query_timeout(Duration::from_secs(5));
    node.swarm.behaviour_mut().kad =
        kad::Behaviour::with_config(local, kad::store::MemoryStore::new(local), config);
    let native = &mut node.swarm.behaviour_mut().kad;
    native.set_background_jobs_paused(true);
    let endpoint = ConnectedPoint::Dialer {
        address: "/ip4/127.0.0.1/tcp/4001".parse().unwrap(),
        role_override: libp2p::core::Endpoint::Dialer,
        port_use: libp2p::core::transport::PortUse::New,
    };
    let _handler = native
        .handle_established_outbound_connection(
            id,
            peer,
            endpoint.get_remote_address(),
            libp2p::core::Endpoint::Dialer,
            libp2p::core::transport::PortUse::New,
        )
        .unwrap();
    native.on_swarm_event(FromSwarm::ConnectionEstablished(
        libp2p::swarm::behaviour::ConnectionEstablished {
            peer_id: peer,
            connection_id: id,
            endpoint: &endpoint,
            failed_addresses: &[],
            other_established: 0,
        },
    ));
    native.add_address(&peer, endpoint.get_remote_address().clone());
    native.get_closest_peers(peer.to_bytes());
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let ToSwarm::NotifyHandler {
                handler: NotifyHandler::One(owner),
                ..
            } = poll_fn(|cx| native.poll(cx)).await
            {
                assert_eq!(owner, id);
                break;
            }
        }
    })
    .await
    .unwrap();
    assert!(connection_busy(node.swarm.behaviour(), peer, id));
    set_outbound(node.swarm.behaviour_mut(), peer, id, false);
    assert!(
        connection_busy(node.swarm.behaviour(), peer, id),
        "already dispatched native work stays with the fallback while excluded"
    );
    assert!(!connection_busy(
        node.swarm.behaviour(),
        peer,
        ConnectionId::new_unchecked(902)
    ));
}

pub(super) async fn route(
    peer: Libp2pPeerId,
    id: usize,
) -> (Arc<ControlRoutes>, Registration, Snapshot) {
    route_with_protocol(peer, id, SocketProtocol::Tcp).await
}

pub(super) async fn route_with_protocol(
    peer: Libp2pPeerId,
    id: usize,
    protocol: SocketProtocol,
) -> (Arc<ControlRoutes>, Registration, Snapshot) {
    let routes = Arc::new(ControlRoutes::new(8));
    let destination = "127.0.0.1:4001".parse().unwrap();
    let lease = match protocol {
        SocketProtocol::Tcp => {
            routes
                .egress
                .prepare_tcp(destination, false, &[])
                .await
                .unwrap()
                .1
        }
        SocketProtocol::Udp => routes.egress.prepare(destination).await.unwrap().1,
    };
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

pub(super) fn forwarder(peer: Libp2pPeerId) -> Forwarder {
    let identity = NodeIdentity::generate_ed25519().unwrap();
    let config: Config = serde_json::from_value(serde_json::json!({
        "network": {"name": "control-handoff", "private_key": identity.private_key},
        "peers": [{"id": peer.to_string()}]
    }))
    .unwrap();
    Forwarder::from_config(&config).unwrap()
}

fn listener_endpoint(protocol: SocketProtocol) -> ConnectedPoint {
    let (transport, suffix) = match protocol {
        SocketProtocol::Tcp => ("tcp", ""),
        SocketProtocol::Udp => ("udp", "/quic-v1"),
    };
    ConnectedPoint::Listener {
        local_addr: format!("/ip4/127.0.0.1/{transport}/4001{suffix}")
            .parse()
            .unwrap(),
        send_back_addr: format!("/ip4/127.0.0.1/{transport}/50000{suffix}")
            .parse()
            .unwrap(),
    }
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
            replacement_protocol: Some(anchor.lease.context.protocol),
            epoch: anchor.lease.epoch(),
            anchor,
            attempts: 1,
            phase: Phase::Dialing(ConnectionId::new_unchecked(2), now + CONNECT_WINDOW),
            draining: HashSet::new(),
            recovery: Recovery::default(),
            circuit: None,
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
    let (_routes, _owner, anchor) = route(peer, 1).await;
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
                epoch: anchor.lease.epoch(),
                owner: 1,
                protocol: SocketProtocol::Tcp,
                deadline: Instant::now() + VALIDATION_WINDOW,
                cancellation,
                circuit: None,
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
    bound_duplicate_gets_grace(SocketProtocol::Tcp).await;
}

#[tokio::test]
async fn bound_quic_duplicate_gets_grace_only_with_a_matching_direct_sibling() {
    bound_duplicate_gets_grace(SocketProtocol::Udp).await;
}

async fn bound_duplicate_gets_grace(protocol: SocketProtocol) {
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
    let destination = "127.0.0.1:4001".parse().unwrap();
    let lease = match protocol {
        SocketProtocol::Tcp => {
            owners
                .egress
                .prepare_tcp(destination, false, &[])
                .await
                .unwrap()
                .1
        }
        SocketProtocol::Udp => owners.egress.prepare(destination).await.unwrap().1,
    };
    let owner = owners.register(peer, lease).unwrap();
    let id = ConnectionId::new_unchecked(2);
    owner.bind_connection(id).unwrap();
    assert!(owners.connection(peer, id).is_none());
    assert!(owners.bound_connection(peer, id).is_some());
    let endpoint = listener_endpoint(protocol);
    let mut connections = HashMap::from([
        ((peer, ConnectionId::new_unchecked(1)), endpoint.clone()),
        ((peer, id), endpoint),
    ]);
    let forwarder = forwarder(peer);
    let now = Instant::now();
    let other_protocol = match protocol {
        SocketProtocol::Tcp => SocketProtocol::Udp,
        SocketProtocol::Udp => SocketProtocol::Tcp,
    };
    connections.insert(
        (peer, ConnectionId::new_unchecked(1)),
        listener_endpoint(other_protocol),
    );
    observe_established(&mut node.swarm, &forwarder, &connections, peer, id, now);
    assert!(
        !node
            .swarm
            .behaviour()
            .connection_retention
            .physical_handoff
            .protects(peer, now)
    );
    connections.insert(
        (peer, ConnectionId::new_unchecked(1)),
        listener_endpoint(protocol),
    );
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
        assert!(direct_address(&address, peer, SocketProtocol::Tcp));
        assert!(direct_address(
            &address.clone().with(Protocol::P2p(peer)),
            peer,
            SocketProtocol::Tcp
        ));
        assert!(!direct_address(
            &address.clone().with(Protocol::P2p(Libp2pPeerId::random())),
            peer,
            SocketProtocol::Tcp
        ));
        assert!(!direct_address(
            &address.with(Protocol::P2pCircuit),
            peer,
            SocketProtocol::Tcp
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
    rollback_restores_selection(SocketProtocol::Tcp).await;
}

#[tokio::test]
async fn quic_rollback_restores_fallback_packet_selection_and_duplicate_close_is_idempotent() {
    rollback_restores_selection(SocketProtocol::Udp).await;
}

async fn rollback_restores_selection(protocol: SocketProtocol) {
    let peer = Libp2pPeerId::random();
    let (_old_routes, _old_owner, old) = route_with_protocol(peer, 1, protocol).await;
    let (_new_routes, _new_owner, new) = route_with_protocol(peer, 2, protocol).await;
    let old_id = old.connection_id.unwrap();
    let new_id = new.connection_id.unwrap();
    let forwarder = forwarder(peer);
    let mut node =
        super::super::tests::membership_sync_test_node(NodeIdentity::generate_ed25519().unwrap());
    let mut epochs = ConnectionEpochs::default();
    let mut paths = PathSet::new();
    let metrics = RuntimeMetrics::default();
    let endpoint = listener_endpoint(protocol);
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
        replacement_protocol: Some(new.lease.context.protocol),
        epoch: new.lease.epoch(),
        anchor: old.clone(),
        attempts: 1,
        phase: Phase::Draining(new_id, Instant::now() + DRAIN_WINDOW),
        draining: HashSet::new(),
        recovery: Recovery::default(),
        circuit: None,
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
async fn promoted_path_and_fallback_survive_while_replacement_observer_audit_is_pending() {
    let peer = Libp2pPeerId::random();
    let forwarder = forwarder(peer);
    let mut node =
        super::super::tests::membership_sync_test_node(NodeIdentity::generate_ed25519().unwrap());
    let owners = node
        .swarm
        .behaviour()
        .connection_retention
        .physical_routes()
        .unwrap()
        .clone();
    let mut registrations = Vec::new();
    let mut routes = Vec::new();
    let mut epochs = ConnectionEpochs::default();
    let mut paths = PathSet::new();
    let metrics = RuntimeMetrics::default();
    let endpoint = ConnectedPoint::Listener {
        local_addr: "/ip4/127.0.0.1/tcp/4001".parse().unwrap(),
        send_back_addr: "/ip4/127.0.0.1/tcp/50000".parse().unwrap(),
    };
    let old = ConnectionId::new_unchecked(1);
    let promoted = ConnectionId::new_unchecked(2);
    for id in [old, promoted] {
        let (_, lease) = owners
            .egress
            .prepare_tcp("127.0.0.1:4001".parse().unwrap(), false, &[])
            .await
            .unwrap();
        let registration = owners.register(peer, lease).unwrap();
        registration.bind_connection(id).unwrap();
        registration.adopt().unwrap();
        routes.push(owners.connection(peer, id).unwrap());
        registrations.push(registration);
        epochs.record_started(id);
        assert!(epochs.record_established(id));
        record_path_established(&mut paths, &forwarder, &metrics, peer, id, &endpoint);
    }
    let now = Instant::now();
    let round = Round {
        replacement_protocol: Some(routes[1].lease.context.protocol),
        epoch: routes[1].lease.epoch(),
        anchor: routes[0].clone(),
        attempts: 1,
        phase: Phase::Draining(promoted, now + DRAIN_WINDOW),
        draining: HashSet::from([old]),
        recovery: Recovery::default(),
        circuit: None,
    };
    node.swarm
        .behaviour_mut()
        .connection_retention
        .physical_handoff
        .rounds
        .insert(peer, round);
    owners.egress.retire_observer_for_test();
    assert!(validated_path_awaits_audit(
        &owners.connection(peer, promoted).unwrap()
    ));
    let connections = HashMap::from([
        ((peer, old), endpoint.clone()),
        ((peer, promoted), endpoint),
    ]);
    drive(
        &mut node.swarm,
        &mut epochs,
        &forwarder,
        &ControlCapabilities::local("control-handoff", None, 1280),
        &[],
        &DiscoveredPeerAddresses::default(),
        &connections,
        &mut paths,
        &metrics,
        now + DRAIN_WINDOW,
    );
    let state = &node.swarm.behaviour().connection_retention.physical_handoff;
    let round = state
        .rounds
        .get(&peer)
        .expect("keep the validated round while its audit is pending");
    assert!(matches!(round.phase, Phase::Draining(id, _) if id == promoted));
    assert_eq!(round.draining, HashSet::from([old]));
    assert!(epochs.is_usable(old));
    assert!(epochs.is_usable(promoted));
    let selected = paths.best_for(PeerId::from_libp2p(peer)).unwrap();
    assert_eq!(selected.latest_connection_id, Some(promoted));
    assert_eq!(selected.established_connections, 2);
    drop(registrations);
}

#[tokio::test]
async fn next_route_change_preserves_sole_validated_path_after_fallbacks_are_drained() {
    sole_validated_path_is_preserved(SocketProtocol::Tcp).await;
}

#[tokio::test]
async fn next_route_change_preserves_sole_quic_path_after_fallbacks_are_drained() {
    sole_validated_path_is_preserved(SocketProtocol::Udp).await;
}

async fn sole_validated_path_is_preserved(protocol: SocketProtocol) {
    let peer = Libp2pPeerId::random();
    let (_old_routes, old_owner, old) = route_with_protocol(peer, 1, protocol).await;
    let (_new_routes, _new_owner, new) = route_with_protocol(peer, 2, protocol).await;
    let id = new.connection_id.unwrap();
    let forwarder = forwarder(peer);
    let mut node =
        super::super::tests::membership_sync_test_node(NodeIdentity::generate_ed25519().unwrap());
    let mut epochs = ConnectionEpochs::default();
    let mut paths = PathSet::new();
    let metrics = RuntimeMetrics::default();
    let endpoint = listener_endpoint(protocol);
    for connection in [old.connection_id.unwrap(), id] {
        epochs.record_started(connection);
        assert!(epochs.record_established(connection));
    }
    record_path_established(&mut paths, &forwarder, &metrics, peer, id, &endpoint);
    let round = Round {
        replacement_protocol: Some(new.lease.context.protocol),
        epoch: new.lease.epoch(),
        anchor: old.clone(),
        attempts: 1,
        phase: Phase::Draining(id, Instant::now() + DRAIN_WINDOW),
        draining: HashSet::new(),
        recovery: Recovery::default(),
        circuit: None,
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
        transport_path_kind(protocol),
        None,
        id
    ));
    assert!(!paths.contains_healthy_connection(
        PeerId::from_libp2p(peer),
        transport_path_kind(protocol),
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
    let epoch = route.lease.epoch();
    assert!(candidate_is_current(&route, &epoch));
    let (_other_routes, _other_owner, other) = self::route(peer, 3).await;
    assert_eq!(epoch.generation(), other.lease.epoch().generation());
    assert!(!candidate_is_current(&route, &other.lease.epoch()));
    let mut epochs = ConnectionEpochs::default();
    let id = ConnectionId::new_unchecked(2);
    epochs.record_started(id);
    epochs.record_established(id);
    let (cancellation, _) = AbortHandle::new_pair();
    let mut pending = Pending {
        peer,
        connection: id,
        epoch: epoch.clone(),
        owner: route.id,
        protocol: route.lease.context.protocol,
        deadline: Instant::now() + VALIDATION_WINDOW,
        cancellation,
        circuit: None,
    };
    let forwarder = forwarder(peer);
    assert!(pending_is_current(
        &pending,
        std::slice::from_ref(&route),
        &forwarder,
        &epochs
    ));
    pending.owner += 1;
    assert!(!pending_is_current(
        &pending,
        std::slice::from_ref(&route),
        &forwarder,
        &epochs
    ));
    pending.owner = route.id;
    pending.connection = ConnectionId::new_unchecked(3);
    assert!(!pending_is_current(
        &pending,
        std::slice::from_ref(&route),
        &forwarder,
        &epochs
    ));
    pending.connection = id;
    pending.peer = Libp2pPeerId::random();
    assert!(!pending_is_current(
        &pending,
        std::slice::from_ref(&route),
        &forwarder,
        &epochs
    ));
    pending.peer = peer;
    epochs.mark_retiring(id);
    assert!(!pending_is_current(
        &pending,
        std::slice::from_ref(&route),
        &forwarder,
        &epochs
    ));
    drop(registration);
    assert!(!candidate_is_current(&route, &epoch));
}

#[tokio::test]
async fn a_retired_observer_cannot_validate_a_new_candidate_with_the_same_numeric_generation() {
    let peer = Libp2pPeerId::random();
    let (routes, owner, original) = route(peer, 1).await;
    let stale = original.lease.epoch();
    routes.egress.retire_observer_for_test();
    let (_, lease) = routes
        .egress
        .prepare_tcp("127.0.0.1:4001".parse().unwrap(), false, &[])
        .await
        .unwrap();
    let candidate_owner = routes.register(peer, lease).unwrap();
    let id = ConnectionId::new_unchecked(2);
    candidate_owner.bind_connection(id).unwrap();
    candidate_owner.adopt().unwrap();
    let candidate = routes.connection(peer, id).unwrap();
    let current = candidate.lease.epoch();
    assert_eq!(stale.generation(), current.generation());
    assert_ne!(stale, current);
    assert!(!candidate_is_current(&candidate, &stale));
    assert!(candidate_is_current(&candidate, &current));
    let mut epochs = ConnectionEpochs::default();
    epochs.record_started(id);
    assert!(epochs.record_established(id));
    let (cancellation, _) = AbortHandle::new_pair();
    let mut pending = Pending {
        peer,
        connection: id,
        epoch: stale,
        owner: candidate.id,
        protocol: candidate.lease.context.protocol,
        deadline: Instant::now() + VALIDATION_WINDOW,
        cancellation,
        circuit: None,
    };
    let forwarder = forwarder(peer);
    assert!(!pending_is_current(
        &pending,
        std::slice::from_ref(&candidate),
        &forwarder,
        &epochs
    ));
    pending.epoch = current;
    assert!(pending_is_current(
        &pending,
        &[candidate],
        &forwarder,
        &epochs
    ));
    assert!(
        original.is_live(),
        "retiring the observer is not retiring its TCP owner"
    );
    drop(owner);
    drop(candidate_owner);
}

#[test]
#[ignore = "isolated Linux namespace; actual kernel route change and observer replacement, no remote connection"]
fn observer_replacement_dispatches_a_current_handoff_without_retiring_the_fallback() {
    use crate::runtime::physical_network::linux::{isolated_namespace, test_ip as ip};
    const NAME: &str = "runtime::runner::physical_control_handoff::tests::observer_replacement_dispatches_a_current_handoff_without_retiring_the_fallback";
    if !isolated_namespace(NAME) {
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    for (interface, address, metric) in [
        ("under-a", "192.0.2.1/24", "100"),
        ("under-b", "198.51.100.1/24", "200"),
    ] {
        ip(&["link", "add", interface, "type", "dummy"]);
        ip(&["addr", "add", address, "dev", interface]);
        ip(&["link", "set", interface, "up"]);
        ip(&[
            "route", "add", "default", "dev", interface, "metric", metric,
        ]);
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let peer = Libp2pPeerId::random();
            let forwarder = forwarder(peer);
            let mut node = super::super::tests::membership_sync_test_node(
                NodeIdentity::generate_ed25519().unwrap(),
            );
            let owners = node
                .swarm
                .behaviour()
                .connection_retention
                .physical_routes()
                .unwrap()
                .clone();
            let (_, lease) = owners
                .egress
                .prepare_tcp("203.0.113.9:4001".parse().unwrap(), false, &[])
                .await
                .unwrap();
            let registration = owners.register(peer, lease).unwrap();
            let id = DialOpts::peer_id(peer)
                .addresses(vec!["/ip4/203.0.113.9/tcp/4001".parse().unwrap()])
                .build()
                .connection_id();
            registration.bind_connection(id).unwrap();
            registration.adopt().unwrap();
            let mut observer =
                crate::runtime::physical_network::linux::control::reconcile::Reconciler::new(
                    owners.clone(),
                );
            let original = inspected(&mut observer, &owners, peer, id, false).await;
            let stale_round = Round {
                replacement_protocol: None,
                epoch: original.inspection_epoch().unwrap(),
                anchor: original.clone(),
                attempts: 0,
                phase: Phase::Waiting(Instant::now()),
                draining: HashSet::new(),
                recovery: Recovery::default(),
                circuit: None,
            };
            owners.egress.retire_observer_for_test();
            ip(&["route", "del", "default", "dev", "under-a", "metric", "100"]);
            let fresh = inspected(&mut observer, &owners, peer, id, true).await;
            let epoch = fresh.inspection_epoch().unwrap();
            assert_eq!(epoch.generation(), stale_round.epoch.generation());
            assert_ne!(epoch, stale_round.epoch);
            assert!(!original.lease.is_current());
            assert!(fresh.is_live());
            assert!(!stale_round.current(std::slice::from_ref(&fresh)));
            let endpoint = ConnectedPoint::Dialer {
                address: "/ip4/203.0.113.9/tcp/4001".parse().unwrap(),
                role_override: libp2p::core::Endpoint::Dialer,
                port_use: libp2p::core::transport::PortUse::New,
            };
            let connections = HashMap::from([((peer, id), endpoint.clone())]);
            let mut epochs = ConnectionEpochs::default();
            epochs.record_started(id);
            assert!(epochs.record_established(id));
            let mut paths = PathSet::new();
            let metrics = RuntimeMetrics::default();
            record_path_established(&mut paths, &forwarder, &metrics, peer, id, &endpoint);
            drive(
                &mut node.swarm,
                &mut epochs,
                &forwarder,
                &ControlCapabilities::local("control-handoff", None, 1280),
                &[(peer, "/ip4/203.0.113.9/tcp/4001".parse().unwrap())],
                &DiscoveredPeerAddresses::default(),
                &connections,
                &mut paths,
                &metrics,
                Instant::now(),
            );
            let state = &node.swarm.behaviour().connection_retention.physical_handoff;
            let round = &state.rounds[&peer];
            assert_eq!(round.epoch, epoch);
            assert!(matches!(round.phase, Phase::Dialing(candidate, _) if candidate != id));
            assert!(epochs.is_usable(id));
            assert_eq!(
                paths
                    .best_for(PeerId::from_libp2p(peer))
                    .unwrap()
                    .latest_connection_id,
                Some(id)
            );
            drop(registration);
            assert!(
                round.current(&[]),
                "owned recovery keeps its current observer after losing the old owner"
            );
        });
}

async fn inspected(
    observer: &mut crate::runtime::physical_network::linux::control::reconcile::Reconciler,
    owners: &ControlRoutes,
    peer: Libp2pPeerId,
    id: ConnectionId,
    replace: bool,
) -> Snapshot {
    tokio::time::timeout(
        Duration::from_secs(5),
        futures::future::poll_fn(|cx| {
            observer.poll(cx);
            match owners
                .connection(peer, id)
                .filter(|route| route.refresh_required() == Some(replace))
            {
                Some(route) => std::task::Poll::Ready(route),
                None => std::task::Poll::Pending,
            }
        }),
    )
    .await
    .expect("current event-driven route inspection")
}

#[test]
#[ignore = "isolated Linux namespace; delayed audit across an actual kernel route change, no remote connection"]
fn delayed_fallback_audit_keeps_drain_owned_until_retirement_can_resume() {
    use crate::runtime::physical_network::linux::{isolated_namespace, test_ip as ip};
    const NAME: &str = "runtime::runner::physical_control_handoff::tests::delayed_fallback_audit_keeps_drain_owned_until_retirement_can_resume";
    if !isolated_namespace(NAME) {
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    for (name, address, metric) in [
        ("under-a", "192.0.2.1/24", "100"),
        ("under-b", "198.51.100.1/24", "200"),
    ] {
        ip(&["link", "add", name, "type", "dummy"]);
        ip(&["addr", "add", address, "dev", name]);
        ip(&["link", "set", name, "up"]);
        ip(&["route", "add", "default", "dev", name, "metric", metric]);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let peer = Libp2pPeerId::random();
        let forwarder = forwarder(peer);
        let mut node = super::super::tests::membership_sync_test_node(
            NodeIdentity::generate_ed25519().unwrap(),
        );
        let owners = node
            .swarm
            .behaviour()
            .connection_retention
            .physical_routes()
            .unwrap()
            .clone();
        let (_, lease) = owners
            .egress
            .prepare_tcp("203.0.113.9:4001".parse().unwrap(), false, &[])
            .await
            .unwrap();
        let old_owner = owners.register(peer, lease).unwrap();
        let old = ConnectionId::new_unchecked(1);
        old_owner.bind_connection(old).unwrap();
        old_owner.adopt().unwrap();
        let anchor = owners.connection(peer, old).unwrap();
        ip(&["route", "del", "default", "dev", "under-a", "metric", "100"]);
        tokio::time::timeout(Duration::from_secs(3), async {
            while anchor.lease.is_current() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("observe the actual kernel route change");
        let (_, lease) = owners
            .egress
            .prepare_tcp("203.0.113.9:4001".parse().unwrap(), false, &[])
            .await
            .unwrap();
        let candidate_owner = owners.register(peer, lease).unwrap();
        let promoted = ConnectionId::new_unchecked(2);
        candidate_owner.bind_connection(promoted).unwrap();
        candidate_owner.adopt().unwrap();
        let candidate = owners.connection(peer, promoted).unwrap();
        let now = Instant::now();
        let round = Round {
            replacement_protocol: Some(candidate.lease.context.protocol),
            epoch: candidate.lease.epoch(),
            anchor,
            attempts: 1,
            phase: Phase::Draining(promoted, now),
            draining: HashSet::from([old]),
            recovery: Recovery::default(),
            circuit: None,
        };
        node.swarm
            .behaviour_mut()
            .connection_retention
            .physical_handoff
            .rounds
            .insert(peer, round);
        let endpoint = ConnectedPoint::Listener {
            local_addr: "/ip4/203.0.113.9/tcp/4001".parse().unwrap(),
            send_back_addr: "/ip4/198.51.100.1/tcp/50000".parse().unwrap(),
        };
        let connections = HashMap::from([
            ((peer, old), endpoint.clone()),
            ((peer, promoted), endpoint.clone()),
        ]);
        let mut epochs = ConnectionEpochs::default();
        let mut paths = PathSet::new();
        let metrics = RuntimeMetrics::default();
        for id in [old, promoted] {
            epochs.record_started(id);
            assert!(epochs.record_established(id));
            record_path_established(&mut paths, &forwarder, &metrics, peer, id, &endpoint);
        }
        for (offset, audited) in [(0, false), (1, true)] {
            if audited {
                let mut observer =
                    crate::runtime::physical_network::linux::control::reconcile::Reconciler::new(
                        owners.clone(),
                    );
                inspected(&mut observer, &owners, peer, old, true).await;
                inspected(&mut observer, &owners, peer, promoted, false).await;
            }
            drive(
                &mut node.swarm,
                &mut epochs,
                &forwarder,
                &ControlCapabilities::local("control-handoff", None, 1280),
                &[],
                &DiscoveredPeerAddresses::default(),
                &connections,
                &mut paths,
                &metrics,
                now + Duration::from_secs(offset),
            );
            let state = &node.swarm.behaviour().connection_retention.physical_handoff;
            let round = &state.rounds[&peer];
            if audited {
                assert!(matches!(round.phase, Phase::Exhausted));
                assert!(round.draining.is_empty());
                assert!(
                    !epochs.is_usable(old),
                    "retire the old owner when its audit arrives"
                );
            } else {
                assert!(
                    matches!(round.phase, Phase::Draining(id, _) if id == promoted),
                    "an elapsed deadline cannot abandon a tracked fallback with an unknown audit"
                );
                assert_eq!(round.draining, HashSet::from([old]));
                assert!(epochs.is_usable(old));
            }
            assert!(
                state.pending.is_empty(),
                "no replacement validation is needed"
            );
            assert_eq!(round.attempts, 1, "do not dial another candidate");
            assert!(epochs.is_usable(promoted));
            assert_eq!(
                paths
                    .best_for(PeerId::from_libp2p(peer))
                    .unwrap()
                    .latest_connection_id,
                Some(promoted)
            );
        }
        drop((old_owner, candidate_owner));
    });
}

#[tokio::test]
async fn losing_anchor_does_not_cancel_owned_recovery_but_stops_new_idle_retries() {
    let peer = Libp2pPeerId::random();
    let (_routes, owner, anchor) = route(peer, 1).await;
    let mut round = Round {
        replacement_protocol: Some(anchor.lease.context.protocol),
        epoch: anchor.lease.epoch(),
        anchor,
        attempts: 1,
        phase: Phase::Dialing(
            ConnectionId::new_unchecked(2),
            Instant::now() + CONNECT_WINDOW,
        ),
        draining: HashSet::new(),
        recovery: Recovery::default(),
        circuit: None,
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
            replacement_protocol: Some(anchor.lease.context.protocol),
            epoch: anchor.lease.epoch(),
            anchor,
            attempts: 1,
            phase: Phase::Draining(new, Instant::now() + DRAIN_WINDOW),
            draining: HashSet::from([old]),
            recovery: Recovery::default(),
            circuit: None,
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
    assert!(discovered.remove(peer, &"/ip4/127.0.0.1/tcp/4001".parse().unwrap()));
    discovered.insert(
        peer,
        "/ip4/127.0.0.1/tcp/4001"
            .parse::<Multiaddr>()
            .unwrap()
            .with(Protocol::P2p(peer)),
    );
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
        vec![
            "/ip4/127.0.0.1/tcp/4001"
                .parse::<Multiaddr>()
                .unwrap()
                .with(Protocol::P2p(peer))
        ]
    );
}

#[test]
fn quic_physical_addresses_require_plain_v1_and_the_exact_peer() {
    let peer = Libp2pPeerId::random();
    for host in [
        "ip4/127.0.0.1",
        "ip6/::1",
        "dns/example.invalid",
        "dns4/example.invalid",
        "dns6/example.invalid",
    ] {
        let address: Multiaddr = format!("/{host}/udp/4001/quic-v1").parse().unwrap();
        assert!(direct_address(&address, peer, SocketProtocol::Udp));
        assert!(!direct_address(&address, peer, SocketProtocol::Tcp));
        assert!(direct_address(
            &address.clone().with(Protocol::P2p(peer)),
            peer,
            SocketProtocol::Udp
        ));
        assert!(!direct_address(
            &address.clone().with(Protocol::P2p(Libp2pPeerId::random())),
            peer,
            SocketProtocol::Udp
        ));
        for suffix in [
            "/webtransport",
            "/webrtc-direct",
            "/p2p-circuit",
            "/tcp/4001",
        ] {
            let wrapped: Multiaddr = format!("{address}{suffix}").parse().unwrap();
            assert!(!direct_address(&wrapped, peer, SocketProtocol::Udp));
            let wrapped: Multiaddr = format!("{address}/p2p/{peer}{suffix}").parse().unwrap();
            assert!(!direct_address(&wrapped, peer, SocketProtocol::Udp));
        }
    }
    for address in [
        "/ip4/127.0.0.1/tcp/4001",
        "/ip4/127.0.0.1/udp/4001",
        "/ip4/127.0.0.1/udp/4001/quic",
        "/ip4/127.0.0.1/udp/4001/webrtc-direct",
        "/ip4/127.0.0.1/tcp/4001/quic-v1",
    ] {
        assert!(!direct_address(
            &address.parse().unwrap(),
            peer,
            SocketProtocol::Udp
        ));
    }
}

#[tokio::test]
async fn quic_candidates_include_tcp_fallback_without_changing_tcp_defaults() {
    let peer = Libp2pPeerId::random();
    let (_owners, _owner, anchor) = route_with_protocol(peer, 1, SocketProtocol::Udp).await;
    let now = Instant::now();
    let mut discovered = DiscoveredPeerAddresses::default();
    for (who, address) in [
        (peer, "/ip4/127.0.0.1/udp/4001/quic-v1"),
        (peer, "/ip4/127.0.0.1/udp/4002/quic-v1"),
        (peer, "/ip4/127.0.0.1/udp/4004/quic-v1/webtransport"),
        (peer, "/ip4/127.0.0.1/udp/4005/webrtc-direct"),
        (peer, "/ip4/127.0.0.1/udp/4006/quic-v1/p2p-circuit"),
        (Libp2pPeerId::random(), "/ip4/127.0.0.1/udp/4007/quic-v1"),
        (peer, "/ip4/127.0.0.1/udp/4008/quic-v1"),
    ] {
        discovered.insert(who, address.parse().unwrap());
    }
    discovered.addresses.last_mut().unwrap().quarantined_until = Some(now + DUPLICATE_GRACE);
    let configured = [
        (peer, "/ip4/127.0.0.1/tcp/4001".parse().unwrap()),
        (peer, "/ip4/127.0.0.1/udp/4001/quic-v1".parse().unwrap()),
    ];
    let connections = HashMap::from([
        (
            (peer, ConnectionId::new_unchecked(2)),
            ConnectedPoint::Dialer {
                address: "/ip4/127.0.0.1/udp/4003/quic-v1".parse().unwrap(),
                role_override: libp2p::core::Endpoint::Dialer,
                port_use: libp2p::core::transport::PortUse::New,
            },
        ),
        (
            (peer, ConnectionId::new_unchecked(3)),
            listener_endpoint(SocketProtocol::Udp),
        ),
    ]);
    let forwarder = forwarder(peer);
    let mut expected = (4001..=4003)
        .map(|port| {
            format!("/ip4/127.0.0.1/udp/{port}/quic-v1/p2p/{peer}")
                .parse()
                .unwrap()
        })
        .collect::<Vec<Multiaddr>>();
    expected.insert(
        1,
        format!("/ip4/127.0.0.1/tcp/4001/p2p/{peer}")
            .parse()
            .unwrap(),
    );
    assert_eq!(
        candidate_addresses_for(
            &anchor,
            peer,
            &configured,
            &discovered,
            &connections,
            &forwarder,
            now
        ),
        expected
    );
    assert_eq!(
        candidate_addresses(
            peer,
            &configured,
            &discovered,
            &connections,
            &forwarder,
            now
        ),
        vec![
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{peer}")
                .parse::<Multiaddr>()
                .unwrap()
        ]
    );
    for port in 4100..4140 {
        discovered.insert(
            peer,
            format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
                .parse()
                .unwrap(),
        );
    }
    assert_eq!(
        candidate_addresses_for(
            &anchor,
            peer,
            &configured,
            &discovered,
            &connections,
            &forwarder,
            now
        )
        .len(),
        recovery::MAX_ADDRESSES
    );
}

#[tokio::test]
async fn overlay_validation_requires_the_selected_protocol_and_exact_native_owner() {
    let peer = Libp2pPeerId::random();
    let (owners, _anchor_owner, anchor) = route_with_protocol(peer, 1, SocketProtocol::Udp).await;
    let mut registrations = Vec::new();
    for (protocol, id) in [(SocketProtocol::Tcp, 2), (SocketProtocol::Udp, 3)] {
        let destination = "127.0.0.1:4001".parse().unwrap();
        let lease = match protocol {
            SocketProtocol::Tcp => {
                owners
                    .egress
                    .prepare_tcp(destination, false, &[])
                    .await
                    .unwrap()
                    .1
            }
            SocketProtocol::Udp => owners.egress.prepare(destination).await.unwrap().1,
        };
        let owner = owners.register(peer, lease).unwrap();
        let id = ConnectionId::new_unchecked(id);
        owner.bind_connection(id).unwrap();
        owner.adopt().unwrap();
        registrations.push(owner);
        let candidate = owners.connection(peer, id).unwrap();
        let mut round = Round {
            replacement_protocol: Some(anchor.lease.context.protocol),
            epoch: anchor.lease.epoch(),
            anchor: anchor.clone(),
            attempts: 1,
            phase: Phase::Dialing(id, Instant::now() + CONNECT_WINDOW),
            draining: HashSet::new(),
            recovery: Recovery::default(),
            circuit: None,
        };
        let node = super::super::tests::membership_sync_test_node(
            NodeIdentity::generate_ed25519().unwrap(),
        );
        let routes = owners.snapshot();
        assert!(
            candidate_is_current(&candidate, &round.epoch),
            "both protocols share the native route epoch"
        );
        assert_eq!(
            round
                .candidate_route(node.swarm.behaviour(), &routes, peer)
                .is_some(),
            protocol == SocketProtocol::Udp
        );
        round.phase = Phase::Draining(id, Instant::now() + DRAIN_WINDOW);
        assert_eq!(round.current(&routes), protocol == SocketProtocol::Udp);
        let mut epochs = ConnectionEpochs::default();
        epochs.record_started(id);
        assert!(epochs.record_established(id));
        let (cancellation, _) = AbortHandle::new_pair();
        let mut pending = Pending {
            peer,
            connection: id,
            epoch: round.epoch.clone(),
            owner: candidate.id,
            protocol: SocketProtocol::Udp,
            deadline: Instant::now() + VALIDATION_WINDOW,
            cancellation,
            circuit: None,
        };
        let forwarder = forwarder(peer);
        assert_eq!(
            pending_is_current_on(
                &pending,
                node.swarm.behaviour(),
                &routes,
                &forwarder,
                &epochs
            ),
            protocol == SocketProtocol::Udp
        );
        round.replacement_protocol = Some(protocol);
        pending.protocol = protocol;
        assert!(
            round.current(&routes),
            "a selected alternate is valid despite its anchor kind"
        );
        assert!(pending_is_current_on(
            &pending,
            node.swarm.behaviour(),
            &routes,
            &forwarder,
            &epochs
        ));
        assert_eq!(
            round.event("tcp", "quic", "circuit"),
            if protocol == SocketProtocol::Tcp {
                "tcp"
            } else {
                "quic"
            }
        );
        pending.owner += 100;
        assert!(!pending_is_current_on(
            &pending,
            node.swarm.behaviour(),
            &routes,
            &forwarder,
            &epochs
        ));
        retry(&mut round, Instant::now());
        assert_eq!(round.replacement_protocol, None);
    }
}

#[tokio::test]
async fn one_peer_budget_reaches_either_transport_before_attempt_exhaustion() {
    let peer = Libp2pPeerId::random();
    let forwarder = forwarder(peer);
    let mut configured = (4000..4020)
        .flat_map(|port| {
            [
                (
                    peer,
                    format!("/ip4/127.0.0.1/tcp/{port}")
                        .parse::<Multiaddr>()
                        .unwrap(),
                ),
                (
                    peer,
                    format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
                        .parse()
                        .unwrap(),
                ),
            ]
        })
        .collect::<Vec<_>>();
    for transport in ["tcp/4001", "udp/4001/quic-v1"] {
        configured.push((
            peer,
            format!("/dns/example.invalid/{transport}").parse().unwrap(),
        ));
    }
    for preferred in [SocketProtocol::Tcp, SocketProtocol::Udp] {
        let (owners, _owner, anchor) = route_with_protocol(peer, 1, preferred).await;
        let now = Instant::now();
        let addresses = candidate_addresses_for(
            &anchor,
            peer,
            &configured,
            &DiscoveredPeerAddresses::default(),
            &HashMap::new(),
            &forwarder,
            now,
        );
        assert_eq!(addresses.len(), recovery::MAX_ADDRESSES);
        assert_eq!(address_protocol(&addresses[0], peer), Some(preferred));
        let alternate = address_protocol(&addresses[1], peer).unwrap();
        assert_ne!(
            alternate, preferred,
            "many preferred addresses must not hide the alternate"
        );
        for (index, address) in addresses.iter().enumerate() {
            assert!(
                matches!(address.iter().next(), Some(Protocol::Ip4(_))),
                "nearby candidates precede DNS candidates"
            );
            assert_eq!(
                address_protocol(address, peer),
                Some(if index % 2 == 0 { preferred } else { alternate })
            );
        }
        let mut round = Round {
            epoch: anchor.lease.epoch(),
            anchor,
            replacement_protocol: None,
            attempts: 0,
            phase: Phase::Waiting(now),
            draining: HashSet::new(),
            recovery: Recovery::default(),
            circuit: None,
        };
        let mut recovered = false;
        for attempt in 0..MAX_ATTEMPTS {
            let address = round.recovery.attempt(addresses.clone(), None).unwrap();
            round.replacement_protocol = address_protocol(&address, peer);
            round.attempts += 1;
            if round.replacement_protocol == Some(preferred) {
                retry(&mut round, now);
                assert_eq!(round.replacement_protocol, None);
                assert!(!matches!(round.phase, Phase::Exhausted));
                continue;
            }
            assert_eq!(
                attempt, 1,
                "the blocked primary consumes only the first attempt"
            );
            let destination = "127.0.0.1:4001".parse().unwrap();
            let lease = match alternate {
                SocketProtocol::Tcp => {
                    owners
                        .egress
                        .prepare_tcp(destination, false, &[])
                        .await
                        .unwrap()
                        .1
                }
                SocketProtocol::Udp => owners.egress.prepare(destination).await.unwrap().1,
            };
            let candidate = ConnectionId::new_unchecked(2);
            let registration = owners.register(peer, lease).unwrap();
            registration.bind_connection(candidate).unwrap();
            registration.adopt().unwrap();
            round.phase = Phase::Draining(candidate, now + DRAIN_WINDOW);
            let native = owners.connection(peer, candidate).unwrap();
            assert!(round.current(&owners.snapshot()));
            assert!(round.matches_replacement(&native));
            assert!(candidate_is_current(&native, &round.epoch));
            round.replacement_protocol = Some(preferred);
            assert!(
                !round.matches_replacement(&native),
                "an alternate snapshot cannot satisfy a primary-kind dial"
            );
            recovered = true;
            break;
        }
        assert!(recovered);
        assert!(round.attempts < MAX_ATTEMPTS);
    }
}
