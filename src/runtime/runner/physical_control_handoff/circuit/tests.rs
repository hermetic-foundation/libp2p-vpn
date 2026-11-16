use super::*;
use crate::runtime::physical_network::linux::control::{ControlRoutes, Registration};
use std::sync::Arc;

mod diagnostics;

fn draining_round(
    peer: Libp2pPeerId,
    inner: ConnectionId,
    candidate: ConnectionId,
    anchor: Snapshot,
    deadline: Instant,
) -> Round {
    Round {
        replacement_protocol: Some(anchor.lease.context.protocol),
        epoch: anchor.lease.epoch(),
        circuit: Some(Replacement {
            peer,
            old: inner,
            route: Route {
                relay: anchor.peer,
                outer: ConnectionId::new_unchecked(30),
            },
            pin: None,
        }),
        anchor,
        attempts: 1,
        phase: Phase::Draining(candidate, deadline),
        draining: HashSet::from([inner]),
        recovery: Recovery::default(),
    }
}

async fn audit(
    owners: &Arc<ControlRoutes>,
    peer: Libp2pPeerId,
    outer: ConnectionId,
    stale: bool,
) -> Snapshot {
    let mut observer = crate::runtime::physical_network::linux::control::reconcile::Reconciler::new(
        owners.clone(),
    );
    tokio::time::timeout(
        Duration::from_secs(5),
        futures::future::poll_fn(|cx| {
            observer.poll(cx);
            match owners
                .connection(peer, outer)
                .filter(|route| route.refresh_required() == Some(stale))
            {
                Some(route) => std::task::Poll::Ready(route),
                None => std::task::Poll::Pending,
            }
        }),
    )
    .await
    .expect("current exact-owner audit")
}

#[tokio::test]
async fn a_recovered_exact_fallback_releases_active_capacity_without_retirement() {
    let relay = Libp2pPeerId::random();
    let outer = ConnectionId::new_unchecked(10);
    let (owners, _registration, unknown) = super::super::tests::route(relay, 10).await;
    let now = Instant::now();
    let deadline = now + DRAIN_WINDOW;
    let mut epochs = ConnectionEpochs::default();
    epochs.record_started(outer);
    assert!(epochs.record_established(outer));
    let mut state = State::default();
    let mut selected = None;
    for index in 0..MAX_ACTIVE {
        let peer = Libp2pPeerId::random();
        let inner = ConnectionId::new_unchecked(100 + index);
        let candidate = ConnectionId::new_unchecked(200 + index);
        epochs.record_started(inner);
        assert!(epochs.record_established(inner));
        selected.get_or_insert((peer, inner));
        state.rounds.insert(
            peer,
            draining_round(peer, inner, candidate, unknown.clone(), deadline),
        );
    }
    assert_eq!(
        state.rounds.values().filter(|round| round.active()).count(),
        MAX_ACTIVE
    );
    let (peer, inner) = selected.unwrap();
    let owner = Some(Route { relay, outer });
    let round = state.rounds.get_mut(&peer).unwrap();
    assert!(
        release_recovered_fallback(round, std::slice::from_ref(&unknown), &epochs, inner, owner)
            .is_none(),
        "a current lease without an audit is not a recovered owner"
    );
    round.finish_drain(deadline, deadline, false);
    assert!(round.active());
    assert_eq!(round.draining, HashSet::from([inner]));

    // This is the policy transition after the native getter has supplied the
    // exact local binding. Native authentication/mapping has separate coverage.
    let current = audit(&owners, relay, outer, false).await;
    assert_eq!(
        release_recovered_fallback(round, std::slice::from_ref(&current), &epochs, inner, owner),
        owner
    );
    assert!(round.draining.is_empty());
    assert!(epochs.is_usable(inner));
    assert!(epochs.is_usable(outer));
    round.finish_drain(now, deadline, false);
    assert!(round.active(), "preserve the existing drain deadline");
    round.finish_drain(deadline, deadline, true);
    assert!(
        round.active(),
        "an outstanding audit still prevents completion"
    );
    round.finish_drain(deadline, deadline, false);
    assert!(matches!(round.phase, Phase::Exhausted));
    assert_eq!(
        state.rounds.values().filter(|round| round.active()).count(),
        MAX_ACTIVE - 1
    );
    assert!(!state.protects(peer, deadline));
    assert!(
        state.pending.is_empty(),
        "recovery must not start another validation"
    );
}

#[tokio::test]
async fn unknown_stale_mismatched_and_retiring_fallbacks_still_require_exact_closure() {
    let relay = Libp2pPeerId::random();
    let peer = Libp2pPeerId::random();
    let inner = ConnectionId::new_unchecked(100);
    let candidate = ConnectionId::new_unchecked(200);
    let outer = ConnectionId::new_unchecked(10);
    let stale_outer = ConnectionId::new_unchecked(11);
    let (owners, _registration, unknown) = super::super::tests::route(relay, 10).await;
    let current = audit(&owners, relay, outer, false).await;

    // Record a different original interface so the real reconciler produces a
    // stale audit without changing host routes or pretending to open a socket.
    let (_, mut lease) = owners
        .egress
        .prepare_tcp("127.0.0.1:4001".parse().unwrap(), false, &[])
        .await
        .unwrap();
    lease.route.interface_index = lease.route.interface_index.checked_add(1).unwrap();
    let stale_registration: Registration = owners.register(relay, lease).unwrap();
    stale_registration.bind_connection(stale_outer).unwrap();
    stale_registration.adopt().unwrap();
    let stale = audit(&owners, relay, stale_outer, true).await;
    let (_foreign_owners, _foreign_registration, foreign) =
        super::super::tests::route(relay, 12).await;
    let deadline = Instant::now();

    for mode in 0..8 {
        let mut source = current.clone();
        let mut owner = Some(Route { relay, outer });
        let mut epochs = ConnectionEpochs::default();
        for id in [
            inner,
            candidate,
            outer,
            stale_outer,
            ConnectionId::new_unchecked(999),
        ] {
            epochs.record_started(id);
            assert!(epochs.record_established(id));
        }
        match mode {
            0 => owner = None,
            1 => owner.as_mut().unwrap().relay = Libp2pPeerId::random(),
            2 => owner.as_mut().unwrap().outer = ConnectionId::new_unchecked(999),
            3 => source = unknown.clone(),
            4 => {
                source = stale.clone();
                owner.as_mut().unwrap().outer = stale_outer;
            }
            5 => {
                epochs.mark_retiring(inner);
            }
            6 => {
                epochs.mark_retiring(outer);
            }
            _ => {}
        }
        let mut round = draining_round(peer, inner, candidate, source.clone(), deadline);
        if mode == 7 {
            assert_ne!(round.epoch, foreign.lease.epoch());
            round.epoch = foreign.lease.epoch();
        }
        assert!(
            release_recovered_fallback(&mut round, &[source], &epochs, inner, owner).is_none(),
            "mode {mode} is not verified usable recovery"
        );
        round.finish_drain(deadline, deadline, false);
        assert!(round.active());
        assert_eq!(round.draining, HashSet::from([inner]));
        let mut state = State::default();
        state.rounds.insert(peer, round);
        observe_closed(&mut state, Libp2pPeerId::random(), inner);
        observe_closed(&mut state, peer, candidate);
        assert_eq!(state.rounds[&peer].draining, HashSet::from([inner]));
        observe_closed(&mut state, peer, inner);
        let round = state.rounds.get_mut(&peer).unwrap();
        assert!(round.draining.is_empty());
        round.finish_drain(deadline, deadline, false);
        assert!(
            !round.active(),
            "the exact observed close releases capacity"
        );
    }
}

#[tokio::test]
async fn current_physical_lease_alone_cannot_validate_an_unbound_circuit() {
    let peer = Libp2pPeerId::random();
    let relay = Libp2pPeerId::random();
    let (_owners, _registration, physical) = super::super::tests::route(relay, 10).await;
    let node = super::super::super::tests::membership_sync_test_node(
        NodeIdentity::generate_ed25519().unwrap(),
    );
    let inner = ConnectionId::new_unchecked(100);
    let expected = Route {
        relay,
        outer: ConnectionId::new_unchecked(10),
    };
    let routes = [physical.clone()];
    assert!(route_for(node.swarm.behaviour(), &routes, peer, inner, Some(expected)).is_none());
    assert!(
        route_for(
            node.swarm.behaviour(),
            &routes,
            relay,
            expected.outer,
            Some(expected)
        )
        .is_none()
    );
    assert!(route_for(node.swarm.behaviour(), &routes, relay, expected.outer, None).is_some());
    let mut epochs = ConnectionEpochs::default();
    epochs.record_started(inner);
    assert!(epochs.record_established(inner));
    let (cancellation, _) = AbortHandle::new_pair();
    let pending = Pending {
        peer,
        connection: inner,
        epoch: physical.lease.epoch(),
        owner: physical.id,
        protocol: physical.lease.context.protocol,
        deadline: Instant::now() + VALIDATION_WINDOW,
        cancellation,
        circuit: Some(expected),
    };
    assert!(!pending_is_current_on(
        &pending,
        node.swarm.behaviour(),
        &routes,
        &super::super::tests::forwarder(peer),
        &epochs
    ));
}

#[tokio::test]
async fn circuit_validation_cannot_be_reused_as_a_public_physical_service_proof() {
    let peer = Libp2pPeerId::random();
    let relay = Libp2pPeerId::random();
    let (_owners, _registration, anchor) = super::super::tests::route(relay, 10).await;
    let mut state = State::default();
    let candidate = ConnectionId::new_unchecked(100);
    state.rounds.insert(
        peer,
        Round {
            replacement_protocol: Some(anchor.lease.context.protocol),
            epoch: anchor.lease.epoch(),
            anchor,
            attempts: 1,
            phase: Phase::Dialing(candidate, Instant::now() + CONNECT_WINDOW),
            draining: HashSet::new(),
            recovery: Recovery::default(),
            circuit: Some(Replacement {
                peer,
                old: ConnectionId::new_unchecked(99),
                route: Route {
                    relay,
                    outer: ConnectionId::new_unchecked(10),
                },
                pin: None,
            }),
        },
    );
    assert!(state.is_candidate(peer, candidate));
    assert_eq!(state.validated_candidates().count(), 0);
    state.rounds.get_mut(&peer).unwrap().phase =
        Phase::Draining(candidate, Instant::now() + DRAIN_WINDOW);
    assert!(!state.is_candidate(peer, candidate));
    assert_eq!(state.validated_candidates().count(), 0);
}

#[tokio::test]
async fn a_circuit_replacement_uses_only_its_pinned_outer_endpoint() {
    pinned_outer_endpoint(SocketProtocol::Tcp).await;
}

#[tokio::test]
async fn a_circuit_replacement_can_use_a_native_quic_outer_without_becoming_a_direct_proof() {
    pinned_outer_endpoint(SocketProtocol::Udp).await;
}

async fn pinned_outer_endpoint(protocol: SocketProtocol) {
    let peer = Libp2pPeerId::random();
    let relay = Libp2pPeerId::random();
    let (_owners, _registration, anchor) =
        super::super::tests::route_with_protocol(relay, 10, protocol).await;
    let transport = match protocol {
        SocketProtocol::Tcp => "tcp/4002",
        SocketProtocol::Udp => "udp/4002/quic-v1",
    };
    let endpoint = |address: &str| ConnectedPoint::Dialer {
        address: address.parse().unwrap(),
        role_override: libp2p::core::Endpoint::Dialer,
        port_use: libp2p::core::transport::PortUse::New,
    };
    let mut connections = HashMap::new();
    connections.insert(
        (relay, ConnectionId::new_unchecked(9)),
        endpoint("/ip4/192.0.2.9/tcp/4001"),
    );
    connections.insert(
        (relay, ConnectionId::new_unchecked(10)),
        endpoint(&format!("/ip4/198.51.100.10/{transport}")),
    );
    let mut round = Round {
        replacement_protocol: Some(anchor.lease.context.protocol),
        epoch: anchor.lease.epoch(),
        anchor,
        attempts: 0,
        phase: Phase::Waiting(Instant::now()),
        draining: HashSet::new(),
        recovery: Recovery::default(),
        circuit: Some(Replacement {
            peer,
            old: ConnectionId::new_unchecked(99),
            route: Route {
                relay,
                outer: ConnectionId::new_unchecked(10),
            },
            pin: None,
        }),
    };
    let expected: Multiaddr =
        format!("/ip4/198.51.100.10/{transport}/p2p/{relay}/p2p-circuit/p2p/{peer}")
            .parse()
            .unwrap();
    assert_eq!(addresses(&round, &connections, peer), Some(vec![expected]));
    let candidate = ConnectionId::new_unchecked(100);
    round.phase = Phase::Draining(candidate, Instant::now() + DRAIN_WINDOW);
    let state = State {
        rounds: HashMap::from([(peer, round)]),
        ..Default::default()
    };
    assert_eq!(
        state.validated_candidates().count(),
        0,
        "circuit proof is not a public physical proof"
    );
    let round = &state.rounds[&peer];
    connections.remove(&(relay, ConnectionId::new_unchecked(10)));
    assert_eq!(
        addresses(round, &connections, peer),
        Some(Vec::new()),
        "cannot silently use another physical connection"
    );
}
