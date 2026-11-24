use super::*;
use crate::runtime::physical_network::{
    control::{ControlRoutes, Registration, Snapshot},
    platform::egress::RouteLease,
};

async fn routes_and_lease(remote: &str) -> (Arc<ControlRoutes>, socket2::Socket, RouteLease) {
    let routes = Arc::new(ControlRoutes::new((MAX_NATIVE_OWNERS + 4) as u32));
    let (socket, lease) = routes
        .egress
        .prepare_tcp(remote.parse().unwrap(), false, &[])
        .await
        .unwrap();
    (routes, socket, lease)
}

fn register(
    routes: &Arc<ControlRoutes>,
    lease: &RouteLease,
    peer: Libp2pPeerId,
    connection: usize,
) -> (Registration, Snapshot) {
    let registration = routes.register(peer, lease.clone()).unwrap();
    let connection = ConnectionId::new_unchecked(connection);
    registration.bind_connection(connection).unwrap();
    registration.adopt().unwrap();
    let snapshot = routes.connection(peer, connection).unwrap();
    (registration, snapshot)
}

fn alias(lease: &RouteLease, port: u16) -> SocketAddr {
    SocketAddr::new(lease.local_addr.ip(), port)
}

fn local() -> ControlCapabilities {
    ControlCapabilities::local("ownership", None, 1280)
}

#[derive(Debug, Eq, PartialEq)]
struct PendingDeliverySnapshot {
    peer: Libp2pPeerId,
    generation: Option<u64>,
    deadline: Option<Instant>,
    canceled: bool,
    retired: bool,
}

#[derive(Debug, Eq, PartialEq)]
struct PacketDeliverySnapshot {
    acknowledged: bool,
    occupied_slots: usize,
    recipients: HashSet<Libp2pPeerId>,
    pending: HashMap<request_response::OutboundRequestId, PendingDeliverySnapshot>,
    active_by_peer: HashMap<Libp2pPeerId, request_response::OutboundRequestId>,
    checked_policy_revision: Option<(u64, u64)>,
}

fn packet_delivery_snapshot(
    publication: &MembershipRecordSyncs,
    peer: Libp2pPeerId,
    local: &ControlCapabilities,
    forwarder: &Forwarder,
) -> PacketDeliverySnapshot {
    let pending = publication
        .pending
        .iter()
        .map(|(id, work)| {
            let snapshot = match work {
                PendingControlSync::Capabilities {
                    peer,
                    generation,
                    deadline,
                    cancellation,
                    ..
                } => PendingDeliverySnapshot {
                    peer: *peer,
                    generation: Some(*generation),
                    deadline: Some(*deadline),
                    canceled: cancellation.is_aborted(),
                    retired: false,
                },
                PendingControlSync::Records(work) => PendingDeliverySnapshot {
                    peer: work.peer,
                    generation: None,
                    deadline: Some(work.deadline),
                    canceled: work
                        .cancellation
                        .as_ref()
                        .is_some_and(|handle| handle.is_aborted()),
                    retired: false,
                },
                PendingControlSync::Retired { peer } => PendingDeliverySnapshot {
                    peer: *peer,
                    generation: None,
                    deadline: None,
                    canceled: false,
                    retired: true,
                },
            };
            (*id, snapshot)
        })
        .collect();
    PacketDeliverySnapshot {
        acknowledged: publication.packet_capabilities_acknowledged(peer, local, forwarder),
        occupied_slots: publication.occupied_slots(),
        recipients: publication.capabilities.peers.keys().copied().collect(),
        pending,
        active_by_peer: publication.active_by_peer.clone(),
        checked_policy_revision: publication.checked_policy_revision,
    }
}

fn render(
    state: &mut State,
    local: &mut ControlCapabilities,
    prepared: &[SocketAddr],
    observed: &[SocketAddr],
    observed_quic: &[SocketAddr],
    retained: &[SocketAddr],
) -> bool {
    // Match the runtime's union of already-validated source values. This helper
    // never manufactures a control owner or seeds the publication's base aliases.
    state.prune_native(|_| true);
    let udp = state
        .native
        .values()
        .filter_map(|claim| claim.udp)
        .chain(prepared.iter().copied())
        .chain(observed.iter().copied())
        .collect();
    let quic = state
        .native
        .values()
        .filter_map(|claim| claim.quic)
        .chain(observed_quic.iter().copied())
        .collect();
    state.render(
        local,
        udp,
        quic,
        retained,
        &[],
        &[],
        true,
        Some(vec![1, 2, 3]),
    )
}

#[tokio::test]
async fn native_aliases_withdraw_only_after_the_last_exact_owner_in_both_families() {
    for remote in ["127.0.0.1:4001", "[::1]:4001"] {
        let (routes, _socket, lease) = routes_and_lease(remote).await;
        let peer = Libp2pPeerId::random();
        let (first, first_snapshot) = register(&routes, &lease, peer, 101);
        let (last, last_snapshot) = register(&routes, &lease, peer, 102);
        let udp = alias(&lease, 51820);
        let quic = alias(&lease, 51821);
        let mut state = State::default();
        let mut local = local();
        assert!(state.record_native(first_snapshot.clone(), Some(udp), Some(quic)));
        assert!(state.record_native(last_snapshot.clone(), Some(udp), Some(quic)));
        assert!(render(&mut state, &mut local, &[], &[], &[], &[]));
        assert_eq!(local.packet_endpoint_candidates, [udp.to_string()]);
        assert_eq!(
            local.owned_quic_packet_endpoint_candidates,
            [quic.to_string()]
        );
        assert!(local.supports_owned_udp_packet_plane);
        assert!(local.supports_bound_owned_quic_packet_plane);
        let published = local.clone();

        drop(first);
        assert!(!first_snapshot.is_live());
        assert!(!render(&mut state, &mut local, &[], &[], &[], &[]));
        assert_eq!(state.native.len(), 1);
        assert_eq!(
            local, published,
            "one owner closing must not restart capability ACKs"
        );

        drop(last);
        assert!(
            !last_snapshot.is_live(),
            "claim snapshots must not retain registrations"
        );
        assert!(render(&mut state, &mut local, &[], &[], &[], &[]));
        assert!(state.native.is_empty());
        assert!(local.packet_endpoint_candidates.is_empty());
        assert!(local.owned_quic_packet_endpoint_candidates.is_empty());
        assert!(!local.supports_owned_udp_packet_plane);
        assert!(!local.supports_owned_quic_packet_plane);
        assert!(local.owned_quic_packet_plane_certificate_der.is_none());
        assert!(!render(&mut state, &mut local, &[], &[], &[], &[]));
    }
}

#[tokio::test]
async fn prepared_and_observed_claims_survive_native_owner_withdrawal() {
    for remote in ["127.0.0.1:4001", "[::1]:4001"] {
        let (routes, _socket, lease) = routes_and_lease(remote).await;
        let (registration, snapshot) = register(&routes, &lease, Libp2pPeerId::random(), 201);
        let udp = alias(&lease, 51820);
        let quic = alias(&lease, 51821);
        let mut state = State::default();
        let mut local = local();
        assert!(state.record_native(snapshot, Some(udp), Some(quic)));
        assert!(render(&mut state, &mut local, &[udp], &[udp], &[quic], &[]));
        let published = local.clone();
        drop(registration);

        assert!(!render(
            &mut state,
            &mut local,
            &[udp],
            &[udp],
            &[quic],
            &[]
        ));
        assert!(state.native.is_empty());
        assert_eq!(local, published);
        assert!(!render(&mut state, &mut local, &[udp], &[], &[quic], &[]));
        assert!(!render(&mut state, &mut local, &[], &[udp], &[quic], &[]));
        assert_eq!(
            local, published,
            "changing supporting owners is not metadata churn"
        );

        assert!(render(&mut state, &mut local, &[], &[], &[quic], &[]));
        assert!(local.packet_endpoint_candidates.is_empty());
        assert_eq!(
            local.owned_quic_packet_endpoint_candidates,
            [quic.to_string()]
        );
        assert!(local.supports_owned_quic_packet_plane);
        assert!(render(&mut state, &mut local, &[], &[], &[], &[]));
        assert!(local.owned_quic_packet_endpoint_candidates.is_empty());
    }
}

#[tokio::test]
async fn explicit_and_listener_aliases_are_not_owned_by_overlapping_native_claims() {
    for remote in ["127.0.0.1:4001", "[::1]:4001"] {
        let (routes, _socket, lease) = routes_and_lease(remote).await;
        let (registration, snapshot) = register(&routes, &lease, Libp2pPeerId::random(), 301);
        let udp = alias(&lease, 51820);
        let quic = alias(&lease, 51821);
        let mut local = local()
            .with_packet_endpoint_candidates(vec![
                udp.to_string(),
                "configured.example:51820".into(),
            ])
            .with_owned_udp_packet_plane(true)
            .with_owned_quic_packet_endpoint_candidates(vec![quic.to_string()])
            .with_owned_quic_packet_plane_certificate(vec![1, 2, 3]);
        let protected = local.clone();
        let mut state = State::default();
        assert!(state.record_native(snapshot, Some(udp), Some(quic)));
        assert!(!render(
            &mut state,
            &mut local,
            &[udp],
            &[udp],
            &[quic],
            &[]
        ));
        drop(registration);
        assert!(!render(&mut state, &mut local, &[], &[], &[], &[]));
        assert_eq!(local, protected);
        assert!(state.native.is_empty());
        assert!(state.udp.injected.is_empty());
        assert!(state.quic.injected.is_empty());
    }
}

#[tokio::test]
async fn withdrawing_one_native_source_preserves_other_families_and_same_port_aliases() {
    let (routes, _socket, lease) = routes_and_lease("127.0.0.1:4001").await;
    let (registration, snapshot) = register(&routes, &lease, Libp2pPeerId::random(), 401);
    let old = alias(&lease, 51820);
    let other_v4: SocketAddr = "192.0.2.9:51820".parse().unwrap();
    let other_v6: SocketAddr = "[2001:db8::9]:51820".parse().unwrap();
    let mut state = State::default();
    let mut local = local();
    assert!(state.record_native(snapshot, Some(old), Some(old)));
    assert!(render(
        &mut state,
        &mut local,
        &[other_v4],
        &[],
        &[other_v6],
        &[]
    ));
    drop(registration);
    assert!(render(
        &mut state,
        &mut local,
        &[other_v4],
        &[],
        &[other_v6],
        &[]
    ));
    assert_eq!(local.packet_endpoint_candidates, [other_v4.to_string()]);
    assert_eq!(
        local.owned_quic_packet_endpoint_candidates,
        [other_v6.to_string()]
    );
}

#[tokio::test]
async fn stale_registration_cannot_replace_the_successor_for_a_reused_connection_key() {
    let (routes, _socket, lease) = routes_and_lease("127.0.0.1:4001").await;
    let peer = Libp2pPeerId::random();
    let (old, stale) = register(&routes, &lease, peer, 501);
    let old_alias = alias(&lease, 51820);
    let new_alias = alias(&lease, 51821);
    let mut state = State::default();
    let mut local = local();
    assert!(state.record_native(stale.clone(), Some(old_alias), None));
    assert!(render(&mut state, &mut local, &[], &[], &[], &[]));
    drop(old);
    let (_current, current) = register(&routes, &lease, peer, 501);
    assert_ne!(stale.id, current.id);
    assert!(state.record_native(current.clone(), Some(new_alias), None));
    assert!(render(&mut state, &mut local, &[], &[], &[], &[]));
    assert_eq!(local.packet_endpoint_candidates, [new_alias.to_string()]);
    assert!(!state.record_native(stale, Some(old_alias), None));
    assert_eq!(
        state.native[&(peer, ConnectionId::new_unchecked(501))]
            .owner
            .id,
        current.id
    );
    assert!(!render(&mut state, &mut local, &[], &[], &[], &[]));
    assert_eq!(local.packet_endpoint_candidates, [new_alias.to_string()]);
}

#[tokio::test]
async fn native_claims_require_an_adopted_live_registration() {
    let (routes, _socket, lease) = routes_and_lease("127.0.0.1:4001").await;
    let peer = Libp2pPeerId::random();
    let registration = routes.register(peer, lease.clone()).unwrap();
    let unbound = routes
        .snapshot()
        .into_iter()
        .find(|owner| owner.peer == peer)
        .unwrap();
    let mut state = State::default();
    let endpoint = alias(&lease, 51820);
    assert!(!state.record_native(unbound, Some(endpoint), None));
    let connection = ConnectionId::new_unchecked(601);
    registration.bind_connection(connection).unwrap();
    let bound = routes.bound_connection(peer, connection).unwrap();
    assert!(!state.record_native(bound, Some(endpoint), None));
    registration.adopt().unwrap();
    let adopted = routes.connection(peer, connection).unwrap();
    assert!(state.record_native(adopted.clone(), Some(endpoint), None));
    drop(registration);
    assert!(!state.record_native(adopted, Some(endpoint), None));
    assert!(state.native.is_empty());
}

#[tokio::test]
async fn explicit_forget_and_authorization_pruning_remove_only_the_target_owner() {
    let (routes, _socket, lease) = routes_and_lease("127.0.0.1:4001").await;
    let peer = Libp2pPeerId::random();
    let sibling = Libp2pPeerId::random();
    let (_first_registration, first) = register(&routes, &lease, peer, 620);
    let (_second_registration, second) = register(&routes, &lease, peer, 621);
    let (_sibling_registration, other) = register(&routes, &lease, sibling, 622);
    let endpoint = alias(&lease, 51820);
    let mut state = State::default();
    let mut local = local();
    for owner in [first, second, other] {
        assert!(state.record_native(owner, Some(endpoint), Some(endpoint)));
    }
    assert!(render(&mut state, &mut local, &[], &[], &[], &[]));
    let published = local.clone();
    state.forget_native(peer, ConnectionId::new_unchecked(620));
    assert_eq!(state.native.len(), 2);
    assert!(!render(&mut state, &mut local, &[], &[], &[], &[]));
    state.forget_peer(PeerId::from_libp2p(peer));
    assert_eq!(state.native.len(), 1);
    assert!(
        state
            .native
            .contains_key(&(sibling, ConnectionId::new_unchecked(622)))
    );
    assert!(!render(&mut state, &mut local, &[], &[], &[], &[]));
    assert_eq!(local, published);
    state.prune_native(|candidate| candidate != sibling);
    assert!(render(&mut state, &mut local, &[], &[], &[], &[]));
    assert!(local.packet_endpoint_candidates.is_empty());
    assert!(local.owned_quic_packet_endpoint_candidates.is_empty());
}

#[tokio::test]
async fn stale_linux_epoch_does_not_withdraw_a_live_fallback_before_owner_retirement() {
    for remote in ["127.0.0.1:4001", "[::1]:4001"] {
        let (routes, _socket, lease) = routes_and_lease(remote).await;
        let (registration, snapshot) = register(&routes, &lease, Libp2pPeerId::random(), 650);
        let endpoint = alias(&lease, 51820);
        let mut state = State::default();
        let mut local = local();
        assert!(state.record_native(snapshot.clone(), Some(endpoint), Some(endpoint)));
        assert!(render(&mut state, &mut local, &[], &[], &[], &[]));
        let published = local.clone();
        routes.egress.retire_observer_for_test();
        assert!(!snapshot.lease.is_current());
        assert!(snapshot.is_live());
        assert!(!render(&mut state, &mut local, &[], &[], &[], &[]));
        assert_eq!(
            local, published,
            "epoch churn is not definitive fallback-owner loss"
        );
        drop(registration);
        assert!(render(&mut state, &mut local, &[], &[], &[], &[]));
        assert!(state.native.is_empty());
    }
}

#[tokio::test]
async fn native_owner_capacity_preserves_existing_claims_and_reuses_only_closed_slots() {
    let (routes, _socket, lease) = routes_and_lease("127.0.0.1:4001").await;
    let peer = Libp2pPeerId::random();
    let endpoint = alias(&lease, 51820);
    let mut state = State::default();
    let mut owners = Vec::new();
    for index in 0..MAX_NATIVE_OWNERS {
        let (registration, snapshot) = register(&routes, &lease, peer, 700 + index);
        assert!(state.record_native(snapshot.clone(), Some(endpoint), None));
        owners.push((Some(registration), snapshot));
    }
    let (_extra_registration, extra) = register(&routes, &lease, peer, 900);
    assert!(!state.record_native(extra.clone(), Some(endpoint), None));
    assert_eq!(state.native.len(), MAX_NATIVE_OWNERS);
    assert!(state.record_native(owners[1].1.clone(), Some(endpoint), None));
    let mut local = local();
    assert!(render(&mut state, &mut local, &[], &[], &[], &[]));
    let published = local.clone();
    drop(owners[0].0.take());
    assert!(state.record_native(extra, Some(endpoint), None));
    assert_eq!(state.native.len(), MAX_NATIVE_OWNERS);
    assert!(
        !state
            .native
            .contains_key(&(peer, ConnectionId::new_unchecked(700)))
    );
    assert!(!render(&mut state, &mut local, &[], &[], &[], &[]));
    assert_eq!(local, published);
}

#[tokio::test]
async fn unchanged_owners_and_union_order_do_not_churn_capability_publication() {
    let (routes, _socket, lease) = routes_and_lease("127.0.0.1:4001").await;
    let (_registration, snapshot) = register(&routes, &lease, Libp2pPeerId::random(), 1001);
    let native = alias(&lease, 51820);
    let v4: SocketAddr = "192.0.2.5:51820".parse().unwrap();
    let v6: SocketAddr = "[2001:db8::5]:51820".parse().unwrap();
    let mut state = State::default();
    let mut local = local();
    assert!(state.record_native(snapshot.clone(), Some(native), Some(native)));
    assert!(render(
        &mut state,
        &mut local,
        &[v4, v6],
        &[native],
        &[v4, v6],
        &[]
    ));
    let published = local.clone();
    for _ in 0..5 {
        assert!(state.record_native(snapshot.clone(), Some(native), Some(native)));
        assert!(!render(
            &mut state,
            &mut local,
            &[v6, v4, v4],
            &[native, v6],
            &[v6, v4],
            &[]
        ));
        assert_eq!(
            local, published,
            "stable metadata must keep its existing ACK barrier"
        );
    }
}

#[test]
fn udp_and_quic_alias_capacity_is_stable_and_does_not_consume_protected_aliases() {
    let mut state = State::default();
    let mut local = local()
        .with_packet_endpoint_candidates(vec!["configured.example:51820".into()])
        .with_owned_quic_packet_endpoint_candidates(vec!["quic.example:51821".into()]);
    let udp = (1..=96)
        .map(|port| SocketAddr::from(([192, 0, 2, 1], port)))
        .collect::<Vec<_>>();
    let quic = (1..=96)
        .map(|port| SocketAddr::new("2001:db8::1".parse().unwrap(), port))
        .collect::<Vec<_>>();
    assert!(render(&mut state, &mut local, &udp, &[], &quic, &[]));
    assert_eq!(state.udp.injected.len(), MAX_GENERATED_SOURCES);
    assert_eq!(state.quic.injected.len(), MAX_GENERATED_SOURCES);
    assert_eq!(
        local.packet_endpoint_candidates.len(),
        MAX_GENERATED_SOURCES + 1
    );
    assert_eq!(
        local.owned_quic_packet_endpoint_candidates.len(),
        MAX_GENERATED_SOURCES + 1
    );
    let published = local.clone();
    assert!(!render(
        &mut state,
        &mut local,
        &udp.into_iter().rev().collect::<Vec<_>>(),
        &[],
        &quic.into_iter().rev().collect::<Vec<_>>(),
        &[]
    ));
    assert_eq!(local, published);
    assert!(render(&mut state, &mut local, &[], &[], &[], &[]));
    assert_eq!(
        local.packet_endpoint_candidates,
        ["configured.example:51820"]
    );
    assert_eq!(
        local.owned_quic_packet_endpoint_candidates,
        ["quic.example:51821"]
    );
}

#[tokio::test]
async fn existing_fallback_claim_survives_retention_but_retention_cannot_create_aliases() {
    let (routes, _socket, lease) = routes_and_lease("127.0.0.1:4001").await;
    let peer = Libp2pPeerId::random();
    let (registration, snapshot) = register(&routes, &lease, peer, 1101);
    let endpoint = alias(&lease, 51820);
    let mut state = State::default();
    let mut local = local();
    assert!(state.record_native(snapshot, Some(endpoint), None));
    assert!(render(&mut state, &mut local, &[], &[], &[], &[]));
    drop(registration);
    assert!(!render(&mut state, &mut local, &[], &[], &[], &[endpoint]));
    assert_eq!(local.packet_endpoint_candidates, [endpoint.to_string()]);
    let unknown: SocketAddr = "192.0.2.77:51820".parse().unwrap();
    assert!(render(&mut state, &mut local, &[], &[], &[], &[unknown]));
    assert!(local.packet_endpoint_candidates.is_empty());
    assert!(!render(&mut state, &mut local, &[], &[], &[], &[unknown]));
}

#[tokio::test]
async fn active_payload_retains_only_previously_generated_udp_and_quic_aliases() {
    for remote in ["127.0.0.1:4001", "[::1]:4001"] {
        let (routes, _socket, lease) = routes_and_lease(remote).await;
        let (registration, snapshot) = register(&routes, &lease, Libp2pPeerId::random(), 1201);
        let udp = alias(&lease, 51820);
        let quic = alias(&lease, 51821);
        let unknown_udp = alias(&lease, 59998);
        let client_only_quic = alias(&lease, 59999);
        let mut state = State::default();
        let mut local = local();
        assert!(state.record_native(snapshot, Some(udp), Some(quic)));
        assert!(render(&mut state, &mut local, &[], &[], &[], &[]));
        let published = local.clone();
        drop(registration);
        state.prune_native(|_| true);
        assert!(state.native.is_empty());

        for _ in 0..3 {
            assert!(!state.render(
                &mut local,
                Vec::new(),
                Vec::new(),
                &[udp, unknown_udp],
                &[quic, client_only_quic],
                &[],
                true,
                Some(vec![1, 2, 3]),
            ));
            assert_eq!(
                local, published,
                "active payload retention must not reset ACKs"
            );
            assert_eq!(local.packet_endpoint_candidates, [udp.to_string()]);
            assert_eq!(
                local.owned_quic_packet_endpoint_candidates,
                [quic.to_string()]
            );
            assert!(!state.udp.injected.contains(&unknown_udp.to_string()));
            assert!(!state.quic.injected.contains(&client_only_quic.to_string()));
        }

        assert!(render(&mut state, &mut local, &[], &[], &[], &[]));
        assert!(local.packet_endpoint_candidates.is_empty());
        assert!(local.owned_quic_packet_endpoint_candidates.is_empty());
        assert!(!local.supports_owned_udp_packet_plane);
        assert!(!local.supports_owned_quic_packet_plane);
        assert!(local.owned_quic_packet_plane_certificate_der.is_none());
        assert!(!state.render(
            &mut local,
            Vec::new(),
            Vec::new(),
            &[unknown_udp],
            &[client_only_quic],
            &[],
            true,
            Some(vec![1, 2, 3]),
        ));
        assert!(local.packet_endpoint_candidates.is_empty());
        assert!(local.owned_quic_packet_endpoint_candidates.is_empty());
    }
}

#[tokio::test]
async fn unusable_listeners_remove_generated_aliases_and_cannot_admit_new_ones() {
    for remote in ["127.0.0.1:4001", "[::1]:4001"] {
        let (routes, _socket, lease) = routes_and_lease(remote).await;
        for (udp_listener, quic_certificate) in [(false, true), (true, false), (false, false)] {
            let (_registration, snapshot) = register(&routes, &lease, Libp2pPeerId::random(), 1301);
            let udp = alias(&lease, 51820);
            let quic = alias(&lease, 51821);
            let base_udp = alias(&lease, 41820).to_string();
            let base_quic = alias(&lease, 41821).to_string();
            let unknown_udp = alias(&lease, 59998);
            let unknown_quic = alias(&lease, 59999);
            let mut local = local()
                .with_packet_endpoint_candidates(vec![base_udp.clone()])
                .with_owned_udp_packet_plane(true)
                .with_owned_quic_packet_endpoint_candidates(vec![base_quic.clone()])
                .with_owned_quic_packet_plane_certificate(vec![1, 2, 3]);
            let mut state = State::default();
            assert!(state.record_native(snapshot.clone(), Some(udp), Some(quic)));
            assert!(render(&mut state, &mut local, &[], &[], &[], &[]));

            let certificate = quic_certificate.then(|| vec![1, 2, 3]);
            assert!(state.render(
                &mut local,
                vec![udp],
                vec![quic],
                &[udp],
                &[quic],
                &[],
                udp_listener,
                certificate.clone(),
            ));
            assert!(
                snapshot.is_live(),
                "listener loss must not depend on native-owner closure"
            );
            let expected_udp = if udp_listener {
                vec![base_udp, udp.to_string()]
            } else {
                vec![base_udp]
            };
            let expected_quic = if quic_certificate {
                vec![base_quic, quic.to_string()]
            } else {
                vec![base_quic]
            };
            assert_eq!(local.packet_endpoint_candidates, expected_udp);
            assert_eq!(local.owned_quic_packet_endpoint_candidates, expected_quic);
            assert_eq!(local.supports_owned_udp_packet_plane, udp_listener);
            assert_eq!(local.supports_owned_quic_packet_plane, quic_certificate);
            assert_eq!(state.udp.injected.is_empty(), !udp_listener);
            assert_eq!(state.quic.injected.is_empty(), !quic_certificate);
            let inactive = local.clone();

            let fresh_udp = if udp_listener {
                vec![udp]
            } else {
                vec![udp, unknown_udp]
            };
            let fresh_quic = if quic_certificate {
                vec![quic]
            } else {
                vec![quic, unknown_quic]
            };
            assert!(!state.render(
                &mut local,
                fresh_udp,
                fresh_quic,
                &[udp, unknown_udp],
                &[quic, unknown_quic],
                &[],
                udp_listener,
                certificate,
            ));
            assert_eq!(
                local, inactive,
                "inactive bases must not acquire automatic aliases"
            );
            assert!(
                !local
                    .packet_endpoint_candidates
                    .contains(&unknown_udp.to_string())
            );
            assert!(
                !local
                    .owned_quic_packet_endpoint_candidates
                    .contains(&unknown_quic.to_string())
            );
        }
    }
}

#[tokio::test]
async fn runtime_reconcile_merges_real_native_external_and_explicit_alias_owners() {
    use crate::runtime::runner::tests::{config_with_peer, membership_sync_test_node};

    for (listen, remote, observed_ip) in [
        ("0.0.0.0:0", "127.0.0.1:4001", "192.0.2.80"),
        ("[::]:0", "[::1]:4001", "2001:db8::80"),
    ] {
        let identity = NodeIdentity::generate_ed25519().unwrap();
        let peer = NodeIdentity::generate_ed25519()
            .unwrap()
            .peer_id
            .parse()
            .unwrap();
        let forwarder = Forwarder::from_config(&config_with_peer(&identity, peer)).unwrap();
        let mut node = membership_sync_test_node(identity);
        let routes = Arc::clone(
            node.swarm
                .behaviour()
                .connection_retention
                .physical_routes()
                .unwrap(),
        );
        let (_socket, lease) = routes
            .egress
            .prepare_tcp(remote.parse().unwrap(), false, &[])
            .await
            .unwrap();
        let (registration, owner) = register(&routes, &lease, peer, 1401);
        let runtime = PacketPlaneRuntime::bind(vec![listen.parse().unwrap()])
            .await
            .unwrap();
        let quic = PacketPlaneQuicRuntime::bind(listen.parse().unwrap()).unwrap();
        let udp_native = alias(&lease, runtime.primary_listener().unwrap().port());
        let quic_native = alias(&lease, quic.local_addr().port());
        let observed_ip: IpAddr = observed_ip.parse().unwrap();
        let protocol = if observed_ip.is_ipv4() { "ip4" } else { "ip6" };
        let first: Multiaddr = format!("/{protocol}/{observed_ip}/tcp/4001")
            .parse()
            .unwrap();
        let second: Multiaddr = format!("/{protocol}/{observed_ip}/tcp/4002")
            .parse()
            .unwrap();
        let udp_observed =
            SocketAddr::new(observed_ip, runtime.primary_listener().unwrap().port()).to_string();
        let quic_observed = SocketAddr::new(observed_ip, quic.local_addr().port()).to_string();
        node.swarm.add_external_address(first.clone());
        node.swarm.add_external_address(second.clone());
        let explicit_udp = vec!["configured.example:42000".to_owned()];
        let explicit_quic = vec!["quic.example:42001".to_owned()];
        let mut local = ControlCapabilities::local("lab", None, 1280)
            .with_packet_endpoint_candidates(explicit_udp.clone())
            .with_owned_udp_packet_plane(true)
            .with_owned_quic_packet_endpoint_candidates(explicit_quic.clone())
            .with_owned_quic_packet_plane_certificate(quic.server_certificate().as_ref().to_vec());
        let mut negotiator = PacketPlaneNegotiator::default();
        negotiator
            .udp_publication
            .initialize_base(&explicit_udp, &explicit_quic);
        assert!(negotiator.udp_publication.record_native(
            owner,
            Some(udp_native),
            Some(quic_native)
        ));
        let mut publication = MembershipRecordSyncs::default();
        let metrics = RuntimeMetrics::default();
        let apply = |node: &mut P2pNode,
                     negotiator: &mut PacketPlaneNegotiator,
                     local: &mut ControlCapabilities,
                     publication: &mut MembershipRecordSyncs| {
            super::reconcile(
                &mut node.swarm,
                &forwarder,
                &runtime,
                Some(&quic),
                negotiator,
                local,
                publication,
                &metrics,
            );
        };
        apply(&mut node, &mut negotiator, &mut local, &mut publication);
        assert!(
            local
                .packet_endpoint_candidates
                .contains(&udp_native.to_string())
        );
        assert!(
            local
                .owned_quic_packet_endpoint_candidates
                .contains(&quic_native.to_string())
        );
        assert!(local.packet_endpoint_candidates.contains(&udp_observed));
        assert!(
            local
                .owned_quic_packet_endpoint_candidates
                .contains(&quic_observed)
        );

        // Seed an acknowledged generation without polling/dialing the Swarm.
        // An unchanged real aggregation must preserve that exact delivery state.
        publication = MembershipRecordSyncs::with_acknowledged_packet_capabilities_for_test(
            peer,
            local.clone(),
            &forwarder,
        );
        assert!(publication.packet_capabilities_acknowledged(peer, &local, &forwarder));
        let published = local.clone();
        let acknowledged = packet_delivery_snapshot(&publication, peer, &local, &forwarder);
        apply(&mut node, &mut negotiator, &mut local, &mut publication);
        assert_eq!(local, published);
        assert_eq!(
            packet_delivery_snapshot(&publication, peer, &local, &forwarder),
            acknowledged
        );

        node.swarm.remove_external_address(&first);
        apply(&mut node, &mut negotiator, &mut local, &mut publication);
        assert_eq!(
            local, published,
            "the other external observation still owns both aliases"
        );
        assert_eq!(
            packet_delivery_snapshot(&publication, peer, &local, &forwarder),
            acknowledged
        );
        assert!(publication.packet_capabilities_acknowledged(peer, &local, &forwarder));

        drop(registration);
        apply(&mut node, &mut negotiator, &mut local, &mut publication);
        assert!(negotiator.udp_publication.native.is_empty());
        assert!(
            !local
                .packet_endpoint_candidates
                .contains(&udp_native.to_string())
        );
        assert!(
            !local
                .owned_quic_packet_endpoint_candidates
                .contains(&quic_native.to_string())
        );
        assert!(local.packet_endpoint_candidates.contains(&udp_observed));
        assert!(
            local
                .owned_quic_packet_endpoint_candidates
                .contains(&quic_observed)
        );
        assert!(!publication.packet_capabilities_acknowledged(peer, &local, &forwarder));

        node.swarm.remove_external_address(&second);
        apply(&mut node, &mut negotiator, &mut local, &mut publication);
        assert_eq!(local.packet_endpoint_candidates, explicit_udp);
        assert_eq!(local.owned_quic_packet_endpoint_candidates, explicit_quic);
        assert!(negotiator.udp_publication.udp.injected.is_empty());
        assert!(negotiator.udp_publication.quic.injected.is_empty());
        assert!(!publication.packet_capabilities_acknowledged(peer, &local, &forwarder));
        // ACK the final generation too, so an unintended no-op generation bump
        // is observable through the structured ACK predicate even with no work queued.
        publication = MembershipRecordSyncs::with_acknowledged_packet_capabilities_for_test(
            peer,
            local.clone(),
            &forwarder,
        );
        let final_capabilities = local.clone();
        let final_delivery = packet_delivery_snapshot(&publication, peer, &local, &forwarder);
        assert!(final_delivery.acknowledged);
        apply(&mut node, &mut negotiator, &mut local, &mut publication);
        assert_eq!(local, final_capabilities);
        assert_eq!(
            packet_delivery_snapshot(&publication, peer, &local, &forwarder),
            final_delivery
        );
    }
}
