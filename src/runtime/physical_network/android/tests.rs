use super::*;
use egress::{Availability, Egress, RouteEpoch, reconcile};
use std::{net::UdpSocket, sync::Mutex, time::Duration};

#[path = "tests/attempts.rs"]
mod attempts;

#[path = "tests/datagram.rs"]
mod datagram;

#[derive(Debug, Default)]
struct Binder {
    calls: Mutex<Vec<u64>>,
    fail: bool,
    state: std::sync::Weak<Networks>,
}

impl SocketBinder for Binder {
    fn bind(&self, handle: u64, _socket: BorrowedFd<'_>) -> io::Result<()> {
        self.calls.lock().unwrap().push(handle);
        if self.fail {
            Err(io::ErrorKind::PermissionDenied.into())
        } else {
            Ok(())
        }
    }

    fn source_for(&self, handle: u64, destination: SocketAddr) -> io::Result<SocketAddr> {
        if self.fail {
            return Err(io::ErrorKind::NetworkUnreachable.into());
        }
        self.state
            .upgrade()
            .and_then(|state| {
                let state = state.state.read().unwrap();
                state
                    .inventory
                    .networks
                    .iter()
                    .find(|network| network.network_handle == handle)
                    .and_then(|network| {
                        network
                            .addresses
                            .iter()
                            .find(|source| source.is_ipv4() == destination.is_ipv4())
                            .copied()
                    })
            })
            .map(|source| SocketAddr::new(source, 1234))
            .ok_or_else(|| io::ErrorKind::NetworkUnreachable.into())
    }
}

fn record(handle: u64, incarnation: u64, source: &str) -> NetworkRecord {
    NetworkRecord {
        network_handle: handle,
        incarnation,
        revision: 1,
        kind: PhysicalNetworkKind::Wifi,
        interface_name: format!("wlan{handle}"),
        interface_index: handle.try_into().unwrap(),
        validated: true,
        addresses: [source.parse().unwrap()].into(),
        dns_servers: Vec::new(),
        private_dns_active: false,
        routes: vec![NetworkRoute {
            destination: "0.0.0.0".parse().unwrap(),
            prefix_length: 0,
            gateway: Some("192.0.2.254".parse().unwrap()),
        }],
    }
}

use super::super::PhysicalNetworkKind;

fn inventory(revision: u64, preferred: Option<u64>) -> Inventory {
    Inventory {
        revision,
        preferred_network: preferred,
        networks: vec![record(1, 1, "192.0.2.1"), record(2, 2, "198.51.100.1")],
    }
}

fn owner() -> (Arc<Networks>, Arc<Binder>, Egress) {
    let networks = Arc::new(Networks::default());
    let binder = Arc::new(Binder {
        state: Arc::downgrade(&networks),
        ..Binder::default()
    });
    networks.binder.set(binder.clone()).unwrap();
    networks.publish(inventory(1, Some(1))).unwrap();
    let egress = Egress::with_networks(Arc::clone(&networks));
    (networks, binder, egress)
}

#[test]
fn inventory_validation_is_bounded_and_does_not_change_live_state() {
    let valid = inventory(1, Some(1));
    let json = serde_json::to_string(&valid).unwrap();
    assert_eq!(Inventory::parse(&json).unwrap(), valid);
    assert!(Inventory::parse(&" ".repeat(inventory::MAX_INVENTORY_BYTES + 1)).is_err());
    assert!(Inventory::parse(&json.replace("\"revision\":1", "\"revision\":0")).is_err());
    assert!(
        Inventory::parse(&json.replace("\"preferred_network\":1", "\"preferred_network\":3"))
            .is_err()
    );
    let (state, _, _) = owner();
    let mut invalid = inventory(2, Some(1));
    invalid.networks[0]
        .addresses
        .insert("127.0.0.1".parse().unwrap());
    assert!(state.publish(invalid).is_err());
    assert_eq!(state.revision(), 1);
    assert!(!state.publish(inventory(1, Some(2))).unwrap());
}

#[test]
fn private_dns_only_change_requires_record_revision_and_preserves_incarnation() {
    let (state, _, _) = owner();
    let mut changed = inventory(2, Some(1));
    changed.networks[0].private_dns_active = true;
    assert!(state.publish(changed.clone()).is_err());
    assert_eq!(state.revision(), 1);
    changed.networks[0].revision = 2;
    assert!(state.publish(changed.clone()).unwrap());
    assert_eq!(state.state.read().unwrap().inventory, changed);
    changed.revision = 3;
    changed.networks[0].revision = 3;
    changed.networks[0].private_dns_active = false;
    assert!(state.publish(changed.clone()).unwrap());
    assert_eq!(state.state.read().unwrap().inventory, changed);
}

#[test]
fn record_revision_and_incarnation_fence_late_callbacks_without_unbounded_tombstones() {
    let (state, _, _) = owner();
    let mut changed = inventory(2, Some(1));
    changed.networks[0]
        .addresses
        .insert("192.0.2.3".parse().unwrap());
    assert!(state.publish(changed.clone()).is_err());
    changed.networks[0].revision = 2;
    assert!(state.publish(changed).unwrap());
    let mut lost = inventory(3, Some(2));
    lost.networks.remove(0);
    assert!(state.publish(lost).unwrap());
    assert!(state.publish(inventory(4, Some(1))).is_err());
    let mut reincarnated = inventory(4, Some(1));
    reincarnated.networks[0].incarnation = 3;
    assert!(state.publish(reincarnated).unwrap());
    assert_eq!(state.state.read().unwrap().incarnation_watermark, 3);
}

#[test]
fn source_routes_and_default_preference_do_not_rank_transport_types() {
    let mut selected = inventory(1, Some(2));
    selected.networks[1].kind = PhysicalNetworkKind::Cellular;
    selected.networks[1].revision = 2;
    assert_eq!(
        selected.candidates("203.0.113.1".parse().unwrap())[0].network_handle,
        2
    );
    selected.networks[0].routes.push(NetworkRoute {
        destination: "10.10.0.0".parse().unwrap(),
        prefix_length: 16,
        gateway: None,
    });
    selected.networks[0].revision = 2;
    assert_eq!(
        selected.candidates("10.10.5.6".parse().unwrap())[0].network_handle,
        1
    );
    let (state, _, owner) = owner();
    state
        .publish(Inventory {
            revision: 2,
            ..selected.clone()
        })
        .unwrap();
    assert_eq!(
        owner
            .lease(
                "192.0.2.1:4000".parse().unwrap(),
                "203.0.113.1:4001".parse().unwrap(),
                SocketProtocol::Udp,
                0,
                false
            )
            .unwrap()
            .network_handle,
        1
    );
    selected.preferred_network = None;
    assert_eq!(
        selected.candidates("203.0.113.1".parse().unwrap())[0].network_handle,
        1
    );
    for network in &mut selected.networks {
        network.validated = false;
    }
    assert!(
        selected
            .candidates("203.0.113.1".parse().unwrap())
            .is_empty()
    );
    assert_eq!(
        selected.candidates("10.10.5.6".parse().unwrap())[0].network_handle,
        1
    );
}

#[test]
fn ipv6_prefixes_are_canonical_and_keep_family_specific_routes() {
    let mut selected = inventory(1, Some(1));
    selected.networks[0]
        .addresses
        .insert("2001:db8:1::1".parse().unwrap());
    selected.networks[0].routes.push(NetworkRoute {
        destination: "::".parse().unwrap(),
        prefix_length: 0,
        gateway: None,
    });
    selected.validate().unwrap();
    assert_eq!(
        selected.candidates("2001:db8:2::1".parse().unwrap())[0].network_handle,
        1
    );
    selected.networks[0].routes.push(NetworkRoute {
        destination: "2001:db8::1".parse().unwrap(),
        prefix_length: 64,
        gateway: None,
    });
    assert!(selected.validate().is_err());
}

#[tokio::test]
async fn preference_fences_new_handshakes_without_destroying_available_fallback() {
    let (state, binder, owner) = owner();
    let lease = owner
        .prepare_shared_datagram(
            "192.0.2.1:42000".parse().unwrap(),
            "203.0.113.1:4001".parse().unwrap(),
            0,
        )
        .await
        .unwrap();
    let guard = lease.socket_binding();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    guard.bind(&socket).unwrap();
    assert_eq!(binder.calls.lock().unwrap().as_slice(), &[1]);
    assert!(lease.is_current());
    state.publish(inventory(2, Some(2))).unwrap();
    assert!(!lease.is_current());
    assert!(lease.available_in(&state.state.read().unwrap().inventory));
    assert!(
        lease.is_available(),
        "a nonpreferred Network can remain available for rollback"
    );
    assert_eq!(
        guard.bind(&socket).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(binder.calls.lock().unwrap().len(), 1);
    assert_eq!(guard.identity(), [1, 1, 1]);
}

#[tokio::test]
async fn binding_failure_has_no_unselected_fallback_and_does_not_adopt_the_fd() {
    let networks = Arc::new(Networks::default());
    networks
        .binder
        .set(Arc::new(Binder {
            fail: true,
            ..Binder::default()
        }))
        .unwrap();
    networks.publish(inventory(1, Some(1))).unwrap();
    let owner = Egress::with_networks(networks);
    let lease = owner
        .prepare_incoming(
            "192.0.2.1:42000".parse().unwrap(),
            "203.0.113.1:4001".parse().unwrap(),
            0,
        )
        .await
        .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    assert_eq!(
        lease.socket_binding().bind(&socket).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(
        socket.local_addr().is_ok(),
        "binding borrowed, not adopted, the descriptor"
    );
}

#[tokio::test]
async fn address_loss_and_handle_reuse_invalidate_old_socket_preparation() {
    let (state, _, owner) = owner();
    let lease = owner
        .prepare_incoming(
            "192.0.2.1:42000".parse().unwrap(),
            "203.0.113.1:4001".parse().unwrap(),
            0,
        )
        .await
        .unwrap();
    let mut changed = inventory(2, Some(1));
    changed.networks[0].revision = 2;
    changed.networks[0].addresses = ["192.0.2.8".parse().unwrap()].into();
    state.publish(changed).unwrap();
    assert!(!lease.is_current());
    assert!(!lease.available_in(&state.state.read().unwrap().inventory));
    assert!(!lease.is_available());
    assert_eq!(
        owner
            .prepare_incoming(
                "192.0.2.1:42000".parse().unwrap(),
                "203.0.113.1:4001".parse().unwrap(),
                0
            )
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::NetworkUnreachable
    );
}

#[test]
fn epoch_identity_includes_inventory_owner_not_just_revision() {
    let (a, _, _) = owner();
    let (b, _, _) = owner();
    assert_ne!(RouteEpoch::new(a, 1), RouteEpoch::new(b, 1));
}

#[tokio::test]
async fn audit_uses_events_retains_fallback_and_fences_old_decisions() {
    let (state, _, owner) = owner();
    let lease = owner
        .prepare_shared_datagram(
            "192.0.2.1:42000".parse().unwrap(),
            "203.0.113.1:4001".parse().unwrap(),
            0,
        )
        .await
        .unwrap();
    let owner = Arc::new(owner);
    let mut audit = reconcile::Reconciler::new(Arc::clone(&owner));
    let target = reconcile::Target {
        peer: crate::PeerId::from_libp2p(libp2p::PeerId::random()),
        connection_id: 1,
        token: Arc::new(()),
        destination: lease.context.destination,
        lease: lease.clone(),
    };
    async fn decision(
        audit: &mut reconcile::Reconciler,
        target: &reconcile::Target,
    ) -> reconcile::Decision {
        tokio::time::timeout(Duration::from_secs(1), async {
            assert!(matches!(
                audit.next().await,
                Some(reconcile::Event::Snapshot)
            ));
            audit.submit(vec![target.clone()]);
            let Some(reconcile::Event::Checked(mut decisions)) = audit.next().await else {
                panic!("missing decision")
            };
            assert_eq!(decisions.len(), 1);
            decisions.remove(0)
        })
        .await
        .unwrap()
    }
    assert!(!decision(&mut audit, &target).await.replace);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), audit.next())
            .await
            .is_err(),
        "no idle audit timer"
    );
    state.publish(inventory(2, Some(2))).unwrap();
    let away = decision(&mut audit, &target).await;
    assert!(away.replace && away.is_current());
    assert!(lease.available_in(&state.state.read().unwrap().inventory));
    state.publish(inventory(3, Some(1))).unwrap();
    assert!(!away.is_current());
    assert!(!decision(&mut audit, &target).await.replace);
}

#[tokio::test]
async fn scoped_incoming_ipv6_disambiguates_networks_and_rejects_conflicts() {
    let (state, binder, owner) = owner();
    let mut next = inventory(2, Some(2));
    for network in &mut next.networks {
        network.revision = 2;
        network.addresses = ["fe80::1".parse().unwrap()].into();
        network.routes = vec![NetworkRoute {
            destination: "fe80::".parse().unwrap(),
            prefix_length: 64,
            gateway: None,
        }];
    }
    state.publish(next).unwrap();
    let remote = "[fe80::2%1]:4001".parse().unwrap();
    let lease = owner
        .prepare_incoming("[fe80::1%1]:42000".parse().unwrap(), remote, 0)
        .await
        .unwrap();
    assert_eq!(lease.network_identity(), [1, 1, 2]);
    assert_eq!(lease.socket_binding().ipv6_scope_id().unwrap().get(), 1);
    assert_eq!(
        owner
            .prepare_incoming("[fe80::1]:42000".parse().unwrap(), remote, 0)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::AddrNotAvailable
    );
    assert_eq!(
        owner
            .prepare_incoming("[fe80::1%3]:42000".parse().unwrap(), remote, 0)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::NetworkUnreachable
    );
    assert_eq!(
        owner
            .prepare_incoming(
                "[fe80::1%1]:42000".parse().unwrap(),
                "[fe80::2%2]:4001".parse().unwrap(),
                0
            )
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(binder.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn handle_reincarnation_cannot_resurrect_an_old_source_lease() {
    let (state, _, owner) = owner();
    let local = "192.0.2.1:42000".parse().unwrap();
    let remote = "203.0.113.1:4001".parse().unwrap();
    let old = owner
        .prepare_shared_datagram(local, remote, 0)
        .await
        .unwrap();
    let mut lost = inventory(2, Some(2));
    lost.networks.remove(0);
    state.publish(lost).unwrap();
    let mut returned = inventory(3, Some(1));
    returned.networks[0].incarnation = 3;
    state.publish(returned).unwrap();
    let current = owner
        .prepare_shared_datagram(local, remote, 0)
        .await
        .unwrap();
    assert!(!old.available_in(&state.state.read().unwrap().inventory));
    assert!(!old.is_current());
    assert!(
        !old.is_available(),
        "handle reuse does not make a retired owner rollback-eligible"
    );
    assert!(current.is_current());
    assert_ne!(old.network_identity(), current.network_identity());
}

#[tokio::test]
async fn preference_change_during_bind_is_rejected_before_a_socket_can_be_used() {
    #[derive(Debug)]
    struct ChangesPreference(std::sync::Weak<Networks>);
    impl SocketBinder for ChangesPreference {
        fn bind(&self, handle: u64, _socket: BorrowedFd<'_>) -> io::Result<()> {
            assert_eq!(handle, 1);
            self.0
                .upgrade()
                .unwrap()
                .publish(inventory(2, Some(2)))
                .unwrap();
            Ok(())
        }
    }
    let networks = Arc::new(Networks::default());
    networks
        .binder
        .set(Arc::new(ChangesPreference(Arc::downgrade(&networks))))
        .unwrap();
    networks.publish(inventory(1, Some(1))).unwrap();
    let owner = Egress::with_networks(Arc::clone(&networks));
    let lease = owner
        .prepare_shared_datagram(
            "192.0.2.1:42000".parse().unwrap(),
            "203.0.113.1:4001".parse().unwrap(),
            0,
        )
        .await
        .unwrap();
    let socket: UdpSocket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .unwrap()
    .into();
    assert_eq!(
        lease.socket_binding().bind(&socket).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(socket.local_addr().unwrap().port(), 0);
    assert_eq!(networks.revision(), 2);
}

#[derive(Debug, Default)]
struct SourceBinder {
    sources: Mutex<std::collections::BTreeMap<u64, IpAddr>>,
    probes: Mutex<Vec<u64>>,
    bindings: Mutex<Vec<u64>>,
}

impl SocketBinder for SourceBinder {
    fn bind(&self, network: u64, _socket: BorrowedFd<'_>) -> io::Result<()> {
        self.bindings.lock().unwrap().push(network);
        Ok(())
    }

    fn source_for(&self, network: u64, destination: SocketAddr) -> io::Result<SocketAddr> {
        self.probes.lock().unwrap().push(network);
        self.sources
            .lock()
            .unwrap()
            .get(&network)
            .copied()
            .filter(|source| source.is_ipv4() == destination.is_ipv4())
            .map(|source| SocketAddr::new(source, 1234))
            .ok_or_else(|| io::ErrorKind::NetworkUnreachable.into())
    }
}

fn clat_owner() -> (Arc<Networks>, Arc<SourceBinder>, Egress) {
    let networks = Arc::new(Networks::default());
    let binder = Arc::new(SourceBinder::default());
    networks.binder.set(binder.clone()).unwrap();
    let mut inventory = inventory(1, Some(1));
    inventory.networks[0].kind = PhysicalNetworkKind::Cellular;
    inventory.networks[0].addresses = ["2001:db8:1::1".parse().unwrap()].into();
    inventory.networks[0].routes = vec![NetworkRoute {
        destination: "::".parse().unwrap(),
        prefix_length: 0,
        gateway: None,
    }];
    networks.publish(inventory).unwrap();
    binder
        .sources
        .lock()
        .unwrap()
        .insert(1, "192.0.0.4".parse().unwrap());
    binder
        .sources
        .lock()
        .unwrap()
        .insert(2, "198.51.100.1".parse().unwrap());
    let egress = Egress::with_networks(Arc::clone(&networks));
    (networks, binder, egress)
}

#[tokio::test]
async fn clat_source_is_proven_by_network_not_base_family_metadata() {
    let (state, binder, owner) = clat_owner();
    let lease = owner
        .prepare_shared_datagram(
            "0.0.0.0:42000".parse().unwrap(),
            "203.0.113.1:4001".parse().unwrap(),
            0,
        )
        .await
        .unwrap();
    assert_eq!(lease.local_addr, "192.0.0.4:42000".parse().unwrap());
    assert_eq!(lease.network_identity(), [1, 1, 1]);
    assert!(lease.socket_binding().uses_platform_routing());
    assert_eq!(binder.probes.lock().unwrap().as_slice(), &[1]);
    let binding = lease.socket_binding();
    let bound = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bound_address = bound.local_addr().unwrap();
    binding.bind(&bound).unwrap();
    let mut next = state.state.read().unwrap().inventory.clone();
    next.revision = 2;
    next.preferred_network = Some(2);
    state.publish(next.clone()).unwrap();
    assert!(!lease.is_current());
    assert!(
        lease.available_in(&next),
        "preference alone keeps fallback available"
    );
    next.revision = 3;
    next.networks[0].revision = 2;
    next.networks[0].addresses = ["2001:db8:1::2".parse().unwrap()].into();
    state.publish(next.clone()).unwrap();
    assert!(
        lease.available_in(&next),
        "unrefreshed stacked-source proof retains already-bound fallback I/O"
    );
    assert_eq!(lease.availability_in(&next), Availability::Unknown);
    assert!(lease.is_available());
    assert!(!lease.is_current());
    let unbound: UdpSocket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .unwrap()
    .into();
    assert_eq!(
        binding.bind(&unbound).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(unbound.local_addr().unwrap().port(), 0);
    assert_eq!(bound.local_addr().unwrap(), bound_address);
    assert_eq!(binder.bindings.lock().unwrap().as_slice(), &[1]);
    assert_eq!(binder.probes.lock().unwrap().as_slice(), &[1]);
    let refreshed = owner
        .prepare_incoming(lease.local_addr, lease.context.destination, 0)
        .await
        .unwrap();
    assert!(refreshed.is_current());
    assert_eq!(refreshed.availability_in(&next), Availability::Available);
    assert_eq!(refreshed.network_identity(), [1, 1, 2]);
    assert_eq!(lease.network_identity(), [1, 1, 1]);
    refreshed.socket_binding().bind(&unbound).unwrap();
    assert_eq!(binder.bindings.lock().unwrap().as_slice(), &[1, 1]);
}

#[tokio::test]
async fn stacked_source_owner_loss_is_unavailable_not_unknown() {
    for loss in ["withdrawal", "reincarnation", "interface"] {
        let (state, binder, owner) = clat_owner();
        let local = "0.0.0.0:42000".parse().unwrap();
        let remote = "203.0.113.1:4001".parse().unwrap();
        let lease = owner
            .prepare_shared_datagram(local, remote, 0)
            .await
            .unwrap();
        let mut next = state.state.read().unwrap().inventory.clone();
        next.revision = 2;
        match loss {
            "withdrawal" => {
                next.networks.remove(0);
                next.preferred_network = Some(2);
            }
            "reincarnation" => next.networks[0].incarnation = 3,
            "interface" => {
                next.networks[0].revision = 2;
                next.networks[0].interface_index = 9;
            }
            _ => unreachable!(),
        }
        state.publish(next.clone()).unwrap();
        assert_eq!(
            lease.availability_in(&next),
            Availability::Unavailable,
            "{loss}"
        );
        assert!(!lease.is_available(), "{loss}");
        assert!(!lease.is_current(), "{loss}");
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(
            lease.socket_binding().bind(&socket).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(binder.bindings.lock().unwrap().is_empty());
        if loss == "reincarnation" {
            let returned = owner
                .prepare_shared_datagram(local, remote, 0)
                .await
                .unwrap();
            assert_eq!(returned.local_addr, lease.local_addr);
            assert_eq!(returned.network_identity(), [1, 3, 1]);
            assert!(returned.is_current());
            assert!(
                !lease.is_available(),
                "the same source cannot resurrect a retired owner"
            );
        }
    }
}

#[tokio::test]
async fn mixed_source_provenance_does_not_turn_published_address_loss_into_unknown() {
    let (state, _, owner) = clat_owner();
    let stacked = owner
        .prepare_shared_datagram(
            "0.0.0.0:42000".parse().unwrap(),
            "203.0.113.1:4001".parse().unwrap(),
            0,
        )
        .await
        .unwrap();
    let published = owner
        .prepare_incoming(
            "[2001:db8:1::1]:42000".parse().unwrap(),
            "[2001:db8:3::1]:4001".parse().unwrap(),
            0,
        )
        .await
        .unwrap();
    let mut next = state.state.read().unwrap().inventory.clone();
    next.revision = 2;
    next.networks[0].revision = 2;
    next.networks[0].validated = false;
    state.publish(next.clone()).unwrap();
    assert_eq!(stacked.availability_in(&next), Availability::Unknown);
    assert_eq!(published.availability_in(&next), Availability::Available);
    assert!(published.is_available());
    assert!(!published.is_current());
    next.revision = 3;
    next.networks[0].revision = 3;
    next.networks[0].addresses = ["2001:db8:1::2".parse().unwrap()].into();
    next.networks[1].revision = 2;
    next.networks[1].addresses.insert(published.local_addr.ip());
    state.publish(next.clone()).unwrap();
    assert_eq!(stacked.availability_in(&next), Availability::Unknown);
    assert!(stacked.is_available());
    assert!(!stacked.is_current());
    assert_eq!(published.availability_in(&next), Availability::Unavailable);
    assert!(
        !published.is_available(),
        "neither another address nor another Network owns the old published-source lease"
    );
    assert!(!published.is_current());
}

#[tokio::test]
async fn fresh_stacked_source_audit_requests_replacement_without_retiring_fallback() {
    let (state, binder, owner) = clat_owner();
    let remote = "203.0.113.1:4001".parse().unwrap();
    let dialed = owner
        .prepare_shared_datagram("0.0.0.0:42000".parse().unwrap(), remote, 0)
        .await
        .unwrap();
    let accepted = owner
        .prepare_incoming(dialed.local_addr, remote, 0)
        .await
        .unwrap();
    assert!(!dialed.source_fixed);
    assert!(accepted.source_fixed && !accepted.preferred_dial);
    let targets = [dialed, accepted]
        .into_iter()
        .enumerate()
        .map(|(id, lease)| reconcile::Target {
            peer: crate::PeerId::from_libp2p(libp2p::PeerId::random()),
            connection_id: id,
            token: Arc::new(()),
            lease,
            destination: remote,
        })
        .collect::<Vec<_>>();
    let owner = Arc::new(owner);
    let mut audit = reconcile::Reconciler::new(Arc::clone(&owner));
    async fn checked(
        audit: &mut reconcile::Reconciler,
        targets: &[reconcile::Target],
    ) -> Vec<reconcile::Decision> {
        tokio::time::timeout(Duration::from_secs(2), async {
            assert!(matches!(
                audit.next().await,
                Some(reconcile::Event::Snapshot)
            ));
            audit.submit(targets.to_vec());
            let Some(reconcile::Event::Checked(decisions)) = audit.next().await else {
                panic!("missing audit");
            };
            assert_eq!(decisions.len(), targets.len());
            decisions
        })
        .await
        .unwrap()
    }
    assert!(
        checked(&mut audit, &targets)
            .await
            .iter()
            .all(|decision| !decision.replace)
    );
    let mut next = state.state.read().unwrap().inventory.clone();
    next.revision = 2;
    next.networks[0].revision = 2;
    next.networks[0].validated = false;
    state.publish(next.clone()).unwrap();
    for target in &targets {
        assert_eq!(target.lease.availability_in(&next), Availability::Unknown);
        assert!(target.lease.is_available());
        assert!(!target.lease.is_current());
    }
    assert!(
        checked(&mut audit, &targets)
            .await
            .iter()
            .all(|decision| !decision.replace && decision.is_current()),
        "fresh proof of the same source does not replace a healthy fallback"
    );
    binder
        .sources
        .lock()
        .unwrap()
        .insert(1, "192.0.0.5".parse().unwrap());
    next.revision = 3;
    next.networks[0].revision = 3;
    next.networks[0].validated = true;
    state.publish(next).unwrap();
    let decisions = checked(&mut audit, &targets).await;
    assert!(
        decisions
            .iter()
            .all(|decision| decision.replace && decision.is_current())
    );
    for target in &targets {
        assert!(
            target.lease.is_available(),
            "replacement is a request for fresh path proof, not old owner loss"
        );
        assert!(
            !target.lease.is_current(),
            "an audit cannot promote old proof to new admission"
        );
    }
    let fresh = owner
        .prepare_shared_datagram("0.0.0.0:42000".parse().unwrap(), remote, 0)
        .await
        .unwrap();
    assert_eq!(
        fresh.local_addr.ip(),
        "192.0.0.5".parse::<IpAddr>().unwrap()
    );
    assert_eq!(fresh.network_identity(), [1, 1, 3]);
    assert!(fresh.is_current());
}

#[tokio::test]
async fn clat_incoming_identity_must_be_unique_even_when_only_one_network_is_preferred() {
    let (state, binder, owner) = clat_owner();
    let local = "192.0.0.4:42000".parse().unwrap();
    let remote = "203.0.113.1:4001".parse().unwrap();
    let lease = owner.prepare_incoming(local, remote, 0).await.unwrap();
    assert_eq!(lease.network_identity(), [1, 1, 1]);
    binder.sources.lock().unwrap().insert(2, local.ip());
    assert_eq!(
        owner
            .prepare_incoming(local, remote, 0)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::AddrNotAvailable
    );
    let mut next = state.state.read().unwrap().inventory.clone();
    next.revision = 2;
    next.networks[1].revision = 2;
    next.networks[1].addresses = [local.ip()].into();
    state.publish(next).unwrap();
    assert_eq!(
        owner
            .prepare_incoming(local, remote, 0)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::AddrNotAvailable,
        "a base address on one Network cannot hide a second Network's stacked source"
    );
}

#[tokio::test]
async fn kernel_family_failure_uses_fallback_and_audit_detects_clat_return() {
    let (state, binder, owner) = clat_owner();
    binder.sources.lock().unwrap().remove(&1);
    let remote = "203.0.113.1:4001".parse().unwrap();
    let lease = owner
        .prepare_shared_datagram("0.0.0.0:42000".parse().unwrap(), remote, 0)
        .await
        .unwrap();
    assert_eq!(lease.network_identity(), [2, 2, 1]);
    assert_eq!(binder.probes.lock().unwrap().as_slice(), &[1, 2]);
    let target = reconcile::Target {
        peer: crate::PeerId::from_libp2p(libp2p::PeerId::random()),
        connection_id: 8,
        token: Arc::new(()),
        lease,
        destination: remote,
    };
    let mut audit = reconcile::Reconciler::new(Arc::new(owner));
    async fn check(
        audit: &mut reconcile::Reconciler,
        target: &reconcile::Target,
    ) -> reconcile::Decision {
        tokio::time::timeout(Duration::from_secs(2), async {
            assert!(matches!(
                audit.next().await,
                Some(reconcile::Event::Snapshot)
            ));
            audit.submit(vec![target.clone()]);
            let Some(reconcile::Event::Checked(mut decisions)) = audit.next().await else {
                panic!("missing audit")
            };
            decisions.remove(0)
        })
        .await
        .unwrap()
    }
    assert!(!check(&mut audit, &target).await.replace);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), audit.next())
            .await
            .is_err()
    );
    binder
        .sources
        .lock()
        .unwrap()
        .insert(1, "192.0.0.4".parse().unwrap());
    let mut next = state.state.read().unwrap().inventory.clone();
    next.revision = 2;
    state.publish(next).unwrap();
    let returned = check(&mut audit, &target).await;
    assert!(returned.replace && returned.is_current());
    assert!(
        target
            .lease
            .available_in(&state.state.read().unwrap().inventory)
    );
}

#[test]
fn default_source_lookup_binds_before_kernel_connect_and_sends_no_packet() {
    #[derive(Debug, Default)]
    struct ProbeBinder(Mutex<usize>);
    impl SocketBinder for ProbeBinder {
        fn bind(&self, handle: u64, socket: BorrowedFd<'_>) -> io::Result<()> {
            assert_eq!(handle, 9);
            assert_eq!(
                socket2::SockRef::from(&socket)
                    .local_addr()?
                    .as_socket()
                    .unwrap()
                    .port(),
                0
            );
            *self.0.lock().unwrap() += 1;
            Ok(())
        }
    }
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let binder = ProbeBinder::default();
    let source = binder
        .source_for(9, receiver.local_addr().unwrap())
        .unwrap();
    assert!(source.ip().is_loopback());
    assert_eq!(*binder.0.lock().unwrap(), 1);
    assert!(matches!(
        receiver.recv(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ));
}

#[tokio::test]
async fn cancelled_and_timed_out_lookups_retain_capacity_until_blocking_work_retires() {
    use std::sync::{
        Condvar,
        atomic::{AtomicUsize, Ordering},
    };
    #[derive(Debug, Default)]
    struct Gate {
        entered: AtomicUsize,
        release: Mutex<bool>,
        changed: Condvar,
    }
    struct ReleaseOnDrop(Arc<Gate>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            *self.0.release.lock().unwrap() = true;
            self.0.changed.notify_all();
        }
    }
    impl SocketBinder for Gate {
        fn bind(&self, _handle: u64, _socket: BorrowedFd<'_>) -> io::Result<()> {
            Ok(())
        }
        fn source_for(&self, _handle: u64, _destination: SocketAddr) -> io::Result<SocketAddr> {
            self.entered.fetch_add(1, Ordering::SeqCst);
            let mut released = self.release.lock().unwrap();
            while !*released {
                released = self.changed.wait(released).unwrap();
            }
            Ok("192.0.2.1:1234".parse().unwrap())
        }
    }
    let state = Arc::new(Networks::default());
    state.publish(inventory(1, Some(1))).unwrap();
    let gate = Arc::new(Gate::default());
    let release = ReleaseOnDrop(Arc::clone(&gate));
    state.binder.set(gate.clone()).unwrap();
    let owner = Arc::new(Egress::with_networks(state));
    let local = "0.0.0.0:42000".parse().unwrap();
    let remote = "203.0.113.1:4001".parse().unwrap();
    let mut lookups = (0..egress::MAX_PREPARATIONS)
        .map(|_| {
            let owner = Arc::clone(&owner);
            tokio::spawn(async move { owner.prepare_shared_datagram(local, remote, 0).await })
        })
        .collect::<Vec<_>>();
    tokio::time::timeout(Duration::from_secs(2), async {
        while gate.entered.load(Ordering::SeqCst) < egress::MAX_PREPARATIONS {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    let timed_out = lookups.split_off(egress::MAX_PREPARATIONS / 2);
    for lookup in lookups {
        lookup.abort();
        assert!(lookup.await.unwrap_err().is_cancelled());
    }
    for lookup in timed_out {
        assert_eq!(
            lookup.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
    assert_eq!(
        owner
            .prepare_shared_datagram(local, remote, 0)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    drop(release);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match owner.prepare_shared_datagram(local, remote, 0).await {
                Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    tokio::task::yield_now().await
                }
                Err(error) => panic!("unexpected lookup failure: {error}"),
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn network_change_during_kernel_source_lookup_rejects_completion() {
    #[derive(Debug)]
    struct RacingSource(std::sync::Weak<Networks>);
    impl SocketBinder for RacingSource {
        fn bind(&self, _handle: u64, _socket: BorrowedFd<'_>) -> io::Result<()> {
            Ok(())
        }
        fn source_for(&self, handle: u64, _destination: SocketAddr) -> io::Result<SocketAddr> {
            assert_eq!(handle, 1);
            self.0
                .upgrade()
                .unwrap()
                .publish(inventory(2, Some(2)))
                .unwrap();
            Ok("192.0.2.1:1234".parse().unwrap())
        }
    }
    let state = Arc::new(Networks::default());
    state.publish(inventory(1, Some(1))).unwrap();
    state
        .binder
        .set(Arc::new(RacingSource(Arc::downgrade(&state))))
        .unwrap();
    let owner = Egress::with_networks(state);
    assert_eq!(
        owner
            .prepare_shared_datagram(
                "0.0.0.0:42000".parse().unwrap(),
                "203.0.113.1:4001".parse().unwrap(),
                0
            )
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
}

#[tokio::test]
async fn transient_source_failure_is_not_proof_of_unique_incoming_ownership() {
    #[derive(Debug)]
    struct Inconclusive;
    impl SocketBinder for Inconclusive {
        fn bind(&self, _handle: u64, _socket: BorrowedFd<'_>) -> io::Result<()> {
            Ok(())
        }
        fn source_for(&self, handle: u64, _destination: SocketAddr) -> io::Result<SocketAddr> {
            if handle == 1 {
                Ok("192.0.0.4:1234".parse().unwrap())
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            }
        }
    }
    let state = Arc::new(Networks::default());
    state.publish(inventory(1, Some(1))).unwrap();
    state.binder.set(Arc::new(Inconclusive)).unwrap();
    let owner = Egress::with_networks(state);
    assert_eq!(
        owner
            .prepare_incoming(
                "192.0.0.4:42000".parse().unwrap(),
                "203.0.113.1:4001".parse().unwrap(),
                0
            )
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn family_specific_fallback_returns_without_reranking_the_other_family() {
    let (state, _, owner) = owner();
    let mut next = inventory(2, Some(1));
    next.networks[1].revision = 2;
    next.networks[1]
        .addresses
        .insert("2001:db8:2::1".parse().unwrap());
    next.networks[1].routes.push(NetworkRoute {
        destination: "::".parse().unwrap(),
        prefix_length: 0,
        gateway: None,
    });
    state.publish(next.clone()).unwrap();
    async fn choose(owner: &Egress, v4: bool) -> u64 {
        owner
            .prepare_shared_datagram(
                if v4 { "0.0.0.0:42000" } else { "[::]:42000" }
                    .parse()
                    .unwrap(),
                if v4 {
                    "203.0.113.1:4001"
                } else {
                    "[2001:db8:3::1]:4001"
                }
                .parse()
                .unwrap(),
                0,
            )
            .await
            .unwrap()
            .network_handle
    }
    assert_eq!(choose(&owner, true).await, 1);
    assert_eq!(choose(&owner, false).await, 2);
    next.revision = 3;
    next.networks[0].revision = 2;
    next.networks[0]
        .addresses
        .insert("2001:db8:1::1".parse().unwrap());
    next.networks[0].routes.push(NetworkRoute {
        destination: "::".parse().unwrap(),
        prefix_length: 0,
        gateway: None,
    });
    state.publish(next).unwrap();
    assert_eq!(choose(&owner, true).await, 1);
    assert_eq!(choose(&owner, false).await, 1);
}
