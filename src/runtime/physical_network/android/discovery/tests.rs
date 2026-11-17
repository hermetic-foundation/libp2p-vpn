use super::*;
use crate::runtime::physical_network::android::{Inventory, SocketBinder};
use std::{
    collections::BTreeSet,
    os::fd::BorrowedFd,
    sync::{Condvar, Mutex, Weak},
};

#[derive(Debug, Default)]
struct Binder {
    networks: Weak<Networks>,
    lookups: Mutex<Vec<(u64, SocketAddr)>>,
    bindings: Mutex<Vec<u64>>,
    unavailable: Mutex<BTreeSet<(u64, bool)>>,
    override_source: Mutex<Option<SocketAddr>>,
    replace_during_lookup: AtomicBool,
    transient: AtomicBool,
    gate: Mutex<Option<Arc<Gate>>>,
    bind_gate: Mutex<Option<Arc<Gate>>>,
}

#[derive(Debug, Default)]
struct Gate {
    entered: tokio::sync::Notify,
    released: Mutex<bool>,
    changed: Condvar,
}

impl Gate {
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

struct ReleaseGate(Arc<Gate>);
impl Drop for ReleaseGate {
    fn drop(&mut self) {
        self.0.release();
    }
}

impl SocketBinder for Binder {
    fn bind(&self, network: u64, _: BorrowedFd<'_>) -> io::Result<()> {
        self.bindings.lock().unwrap().push(network);
        let gate = self.bind_gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            gate.entered.notify_one();
            let mut released = gate.released.lock().unwrap();
            while !*released {
                released = gate.changed.wait(released).unwrap();
            }
        }
        Ok(())
    }
    fn source_for(&self, network: u64, destination: SocketAddr) -> io::Result<SocketAddr> {
        self.lookups.lock().unwrap().push((network, destination));
        if self.transient.load(Ordering::Acquire) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let gate = self.gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            gate.entered.notify_one();
            let mut released = gate.released.lock().unwrap();
            while !*released {
                released = gate.changed.wait(released).unwrap();
            }
        }
        if self
            .unavailable
            .lock()
            .unwrap()
            .contains(&(network, destination.is_ipv6()))
        {
            return Err(io::ErrorKind::NetworkUnreachable.into());
        }
        if let Some(source) = *self.override_source.lock().unwrap() {
            return Ok(source);
        }
        let networks = self.networks.upgrade().unwrap();
        let mut inventory = networks.state.read().unwrap().inventory.clone();
        let record = inventory
            .networks
            .iter()
            .find(|record| record.network_handle == network)
            .unwrap();
        let source = record
            .addresses
            .iter()
            .find(|source| source.is_ipv6() == destination.is_ipv6())
            .copied()
            .ok_or(io::ErrorKind::NetworkUnreachable)?;
        if self.replace_during_lookup.swap(false, Ordering::AcqRel) {
            inventory.revision += 1;
            let record = inventory
                .networks
                .iter_mut()
                .find(|record| record.network_handle == network)
                .unwrap();
            record.revision += 1;
            record.addresses = ["198.51.100.30".parse().unwrap()].into();
            networks.publish(inventory).unwrap();
        }
        Ok(SocketAddr::new(source, 0))
    }
}

fn record(handle: u64, kind: PhysicalNetworkKind, source: &str) -> NetworkRecord {
    NetworkRecord {
        network_handle: handle,
        incarnation: handle,
        revision: 1,
        kind,
        interface_name: format!("under{handle}"),
        interface_index: handle.try_into().unwrap(),
        validated: false,
        addresses: [source.parse().unwrap()].into(),
        routes: vec![],
    }
}

fn fixture() -> (Arc<Networks>, Arc<Binder>) {
    let networks = Arc::new(Networks::default());
    let binder = Arc::new(Binder {
        networks: Arc::downgrade(&networks),
        ..Binder::default()
    });
    networks.binder.set(binder.clone()).unwrap();
    networks
        .publish(Inventory {
            revision: 1,
            preferred_network: Some(1),
            networks: vec![
                record(1, PhysicalNetworkKind::Cellular, "100.64.1.2"),
                record(2, PhysicalNetworkKind::Wifi, "198.51.100.2"),
            ],
        })
        .unwrap();
    (networks, binder)
}

fn latest(networks: &Networks) -> Inventory {
    networks.state.read().unwrap().inventory.clone()
}

#[test]
fn cellular_default_does_not_hide_a_gateway_free_unvalidated_lan() {
    let (networks, binder) = fixture();
    let original = latest(&networks);
    let selected = select(&networks, None, &AtomicBool::new(true))
        .unwrap()
        .unwrap();
    assert_eq!(selected.network.network_handle, 2);
    assert!(selected.source.is_ipv4());
    assert_eq!(
        latest(&networks),
        original,
        "discovery cannot rewrite Internet preference"
    );
    assert_eq!(
        binder
            .lookups
            .lock()
            .unwrap()
            .iter()
            .map(|(handle, _)| *handle)
            .collect::<Vec<_>>(),
        vec![2]
    );
    assert!(
        binder.bindings.lock().unwrap().is_empty(),
        "the model lookup must not create sender sockets"
    );
}

#[test]
fn os_preferred_lan_returns_before_a_surviving_fallback_without_transport_ranking() {
    let (networks, binder) = fixture();
    let fallback = select(&networks, None, &AtomicBool::new(true)).unwrap();
    let mut inventory = latest(&networks);
    inventory.revision = 2;
    inventory
        .networks
        .push(record(3, PhysicalNetworkKind::Bluetooth, "192.0.2.3"));
    inventory.preferred_network = Some(3);
    networks.publish(inventory).unwrap();
    let selected = select(&networks, fallback.as_ref(), &AtomicBool::new(true))
        .unwrap()
        .unwrap();
    assert_eq!(
        selected.network.network_handle, 3,
        "a hardcoded Wi-Fi priority must not win"
    );
    binder.unavailable.lock().unwrap().insert((3, false));
    let selected = select(&networks, Some(&selected), &AtomicBool::new(true))
        .unwrap()
        .unwrap();
    assert_eq!(selected.network.network_handle, 2);
    assert_eq!(latest(&networks).preferred_network, Some(3));
    binder.unavailable.lock().unwrap().clear();
    assert_eq!(
        select(&networks, Some(&selected), &AtomicBool::new(true))
            .unwrap()
            .unwrap()
            .network
            .network_handle,
        3
    );
}

#[test]
fn bound_ipv6_multicast_is_scoped_and_can_replace_an_unusable_ipv4_family() {
    let (networks, binder) = fixture();
    let mut inventory = latest(&networks);
    inventory.revision = 2;
    inventory.networks[1].revision = 2;
    inventory.networks[1]
        .addresses
        .insert("fe80::2".parse().unwrap());
    networks.publish(inventory).unwrap();
    binder.unavailable.lock().unwrap().insert((2, false));
    let selected = select(&networks, None, &AtomicBool::new(true))
        .unwrap()
        .unwrap();
    assert!(selected.source.is_ipv6());
    let lookups = binder.lookups.lock().unwrap();
    assert_eq!(lookups.len(), 2);
    let SocketAddr::V6(destination) = lookups[1].1 else {
        panic!("IPv6 route lookup")
    };
    assert_eq!(destination.scope_id(), 2);
    assert_eq!(*destination.ip(), libp2p::mdns::IPV6_MDNS_MULTICAST_ADDRESS);
}

#[test]
fn unlisted_sources_wrong_families_scopes_and_stale_completions_are_not_proof() {
    let (networks, binder) = fixture();
    for source in ["100.64.1.2:0", "[2001:db8::2]:0", "0.0.0.0:0"] {
        *binder.override_source.lock().unwrap() = Some(source.parse().unwrap());
        assert!(
            select(&networks, None, &AtomicBool::new(true))
                .unwrap()
                .is_none()
        );
    }
    *binder.override_source.lock().unwrap() = None;
    binder.replace_during_lookup.store(true, Ordering::Release);
    assert_eq!(
        select(&networks, None, &AtomicBool::new(true))
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
    let selected = select(&networks, None, &AtomicBool::new(true))
        .unwrap()
        .unwrap();
    assert!(
        selected
            .network
            .addresses
            .contains(&"198.51.100.30".parse().unwrap())
    );
    assert_eq!(
        select(&networks, None, &AtomicBool::new(false))
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
}

async fn wait_for(discovery: &mut AndroidDiscovery, handle: Option<u64>) -> Admission {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if discovery.receiver.borrow().snapshot.network_handle == handle {
                return discovery.admission(false);
            }
            discovery.changed().await.unwrap();
        }
    })
    .await
    .expect("event-driven LAN publication")
}

#[tokio::test]
async fn published_owners_reject_replacement_withdrawal_and_observer_teardown() {
    let (networks, binder) = fixture();
    let mut discovery = AndroidDiscovery::with_networks(Arc::clone(&networks));
    let initial = wait_for(&mut discovery, Some(2)).await;
    let binding = initial.bindings.unwrap().into_values().next().unwrap();
    assert!(binding.is_current());
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    binding.bind(&socket).unwrap();
    assert_eq!(*binder.bindings.lock().unwrap(), vec![2]);
    let mut inventory = latest(&networks);
    inventory.revision = 2;
    inventory.networks[1].revision = 2;
    inventory.networks[1].addresses = ["198.51.100.20".parse().unwrap()].into();
    networks.publish(inventory).unwrap();
    assert!(
        !binding.is_current(),
        "withdrawn record revision must fence old tasks immediately"
    );
    discovery.changed().await.unwrap();
    let next = wait_for(&mut discovery, Some(2)).await;
    assert!(next.allowed.contains(&"198.51.100.20".parse().unwrap()));
    let replacement = next.bindings.unwrap().into_values().next().unwrap();
    assert_ne!(binding.identity(), replacement.identity());
    assert!(replacement.is_current());
    drop(discovery);
    assert!(!replacement.is_current());
    assert_eq!(
        replacement.bind(&socket).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(*binder.bindings.lock().unwrap(), vec![2]);
}

#[tokio::test]
async fn unrelated_inventory_updates_do_not_restart_discovery_and_reincarnation_cannot_revive_an_owner()
 {
    let (networks, _) = fixture();
    let mut discovery = AndroidDiscovery::with_networks(Arc::clone(&networks));
    let first = wait_for(&mut discovery, Some(2)).await;
    let binding = first.bindings.unwrap().into_values().next().unwrap();
    let mut inventory = latest(&networks);
    inventory.revision = 2;
    inventory.networks[0].revision = 2;
    inventory.networks[0].validated = true;
    networks.publish(inventory).unwrap();
    tokio::time::timeout(Duration::from_secs(3), discovery.changed())
        .await
        .unwrap()
        .unwrap();
    let unchanged = discovery
        .admission(false)
        .bindings
        .unwrap()
        .into_values()
        .next()
        .unwrap();
    assert_eq!(
        unchanged.identity(),
        binding.identity(),
        "a fresh opportunity must not restart healthy socket owners"
    );
    assert!(binding.is_current());
    let mut inventory = latest(&networks);
    inventory.revision = 3;
    inventory
        .networks
        .retain(|record| record.network_handle != 2);
    networks.publish(inventory).unwrap();
    assert!(!binding.is_current());
    wait_for(&mut discovery, None).await;
    let mut inventory = latest(&networks);
    inventory.revision = 4;
    let mut returned = record(2, PhysicalNetworkKind::Ethernet, "198.51.100.2");
    returned.incarnation = 3;
    inventory.networks.push(returned);
    networks.publish(inventory).unwrap();
    let returned = wait_for(&mut discovery, Some(2)).await;
    let next = returned.bindings.unwrap().into_values().next().unwrap();
    assert_ne!(binding.identity(), next.identity());
    assert!(!binding.is_current());
}

#[tokio::test]
async fn native_overlay_pairing_and_profile_free_discovery_share_the_selected_lan() {
    let (networks, _) = fixture();
    let discovery = AndroidDiscovery::with_networks(networks);
    let mut policy = super::super::super::DiscoveryPolicy::new(discovery);
    let mut node = super::super::super::tests::node();
    assert_eq!(policy.reconcile(&mut node.swarm), Some((0, 0, false)));
    policy.changed().await;
    assert_eq!(policy.reconcile(&mut node.swarm).unwrap().1, 1);
    let peer = *node.swarm.local_peer_id();
    node.swarm.behaviour_mut().pairing_mdns =
        Some(libp2p::mdns::tokio::Behaviour::new(libp2p::mdns::Config::default(), peer).unwrap())
            .into();
    policy.reconcile(&mut node.swarm).unwrap();
    let expected: std::collections::HashSet<IpAddr> = ["198.51.100.2".parse().unwrap()].into();
    for mdns in [
        &node.swarm.behaviour().mdns,
        &node.swarm.behaviour().pairing_mdns,
    ] {
        assert_eq!(
            mdns.as_ref().unwrap().allowed_interfaces(),
            Some(expected.clone())
        );
    }
    let mut bootstrap =
        libp2p::mdns::tokio::Behaviour::new(libp2p::mdns::Config::default(), peer).unwrap();
    let discovery = AndroidDiscovery::with_networks(fixture().0);
    let mut bootstrap_policy = super::super::super::DiscoveryPolicy::new(discovery);
    bootstrap_policy.changed().await;
    bootstrap_policy.reconcile_bootstrap(&mut bootstrap);
    assert_eq!(bootstrap.allowed_interfaces(), Some(expected));
}

#[tokio::test]
async fn cancelling_lookup_retains_its_only_slot_until_the_backend_retires() {
    let (networks, binder) = fixture();
    let gate = Arc::new(Gate::default());
    let _release_on_unwind = ReleaseGate(Arc::clone(&gate));
    *binder.gate.lock().unwrap() = Some(Arc::clone(&gate));
    let capacity = Arc::new(Semaphore::new(1));
    let alive = Arc::new(AtomicBool::new(true));
    let work = tokio::spawn(prepare(
        Arc::clone(&networks),
        None,
        Arc::clone(&alive),
        Arc::clone(&capacity),
    ));
    tokio::time::timeout(Duration::from_secs(3), gate.entered.notified())
        .await
        .unwrap();
    work.abort();
    assert!(work.await.unwrap_err().is_cancelled());
    assert_eq!(capacity.available_permits(), 0);
    assert_eq!(networks.discovery_preparations.available_permits(), 3);
    assert_eq!(
        prepare(networks, None, alive, Arc::clone(&capacity))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    gate.release();
    tokio::time::timeout(Duration::from_secs(3), async {
        while capacity.available_permits() != 1 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(binder.lookups.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn stopped_observers_share_the_live_backend_budget_with_replacements() {
    let (networks, binder) = fixture();
    let gate = Arc::new(Gate::default());
    let _release_on_unwind = ReleaseGate(Arc::clone(&gate));
    *binder.gate.lock().unwrap() = Some(Arc::clone(&gate));
    let mut observers = Vec::new();
    for _ in 0..4 {
        observers.push(AndroidDiscovery::with_networks(Arc::clone(&networks)));
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        while binder.lookups.lock().unwrap().len() != 4 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    drop(observers);
    assert_eq!(networks.discovery_preparations.available_permits(), 0);
    let replacement = prepare(
        Arc::clone(&networks),
        None,
        Arc::new(AtomicBool::new(true)),
        Arc::new(Semaphore::new(1)),
    )
    .await;
    assert_eq!(replacement.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    assert_eq!(binder.lookups.lock().unwrap().len(), 4);
    gate.release();
    tokio::time::timeout(Duration::from_secs(3), async {
        while networks.discovery_preparations.available_permits() != 4 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn inconclusive_lookup_exhausts_three_attempts_until_an_inventory_event() {
    let (networks, binder) = fixture();
    binder.transient.store(true, Ordering::Release);
    let mut discovery = AndroidDiscovery::with_networks(Arc::clone(&networks));
    tokio::time::timeout(Duration::from_secs(5), async {
        while binder.lookups.lock().unwrap().len() < 3 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    binder.transient.store(false, Ordering::Release);
    tokio::time::sleep(Duration::from_millis(3_100)).await;
    assert_eq!(
        binder.lookups.lock().unwrap().len(),
        3,
        "idle polling must not renew the exhausted round"
    );
    let mut inventory = latest(&networks);
    inventory.revision += 1;
    networks.publish(inventory).unwrap();
    wait_for(&mut discovery, Some(2)).await;
    assert_eq!(binder.lookups.lock().unwrap().len(), 4);
}

#[tokio::test]
async fn one_kernel_selected_sender_advertises_all_addresses_of_its_lan() {
    let (networks, binder) = fixture();
    let mut inventory = latest(&networks);
    inventory.revision = 2;
    inventory.networks[1].revision = 2;
    inventory.networks[1].addresses.extend([
        "fe80::2".parse::<IpAddr>().unwrap(),
        "2001:db8::2".parse::<IpAddr>().unwrap(),
        "2001:db8::3".parse::<IpAddr>().unwrap(),
    ]);
    networks.publish(inventory).unwrap();
    binder.unavailable.lock().unwrap().insert((2, false));
    let mut discovery = AndroidDiscovery::with_networks(networks);
    let selected = wait_for(&mut discovery, Some(2)).await;
    assert_eq!(selected.ipv6, Some(true));
    assert_eq!(selected.allowed.len(), 4);
    let bindings = selected.bindings.unwrap();
    assert_eq!(
        bindings.len(),
        1,
        "IPv6 privacy addresses must not multiply sender tasks"
    );
    assert!(bindings.keys().all(IpAddr::is_ipv6));
    assert!(
        bindings
            .keys()
            .all(|source| selected.allowed.contains(source))
    );
}

#[test]
fn a_new_revision_resets_the_budget_even_when_a_retry_timer_consumed_it() {
    let mut round = RetryRound::default();
    assert_eq!(round.begin(1), 1);
    assert_eq!(round.begin(1), 2);
    // Watch publication may occur after the timer branch won but before borrow_and_update.
    assert_eq!(round.begin(2), 1);
    assert_eq!(round.begin(2), 2);
    assert_eq!(round.begin(2), 3);
}

#[tokio::test]
async fn socket_binding_is_offloaded_and_cancelled_work_keeps_shared_capacity() {
    let (networks, binder) = fixture();
    let mut discovery = AndroidDiscovery::with_networks(Arc::clone(&networks));
    let selected = wait_for(&mut discovery, Some(2)).await;
    let owner = selected.bindings.unwrap().into_values().next().unwrap();
    let gate = Arc::new(Gate::default());
    let _release_on_unwind = ReleaseGate(Arc::clone(&gate));
    *binder.bind_gate.lock().unwrap() = Some(Arc::clone(&gate));
    let work = tokio::spawn(owner.prepare_sockets("198.51.100.2".parse().unwrap()));
    // This is a single-threaded runtime. A synchronous binder here would deadlock it.
    tokio::time::timeout(Duration::from_secs(3), gate.entered.notified())
        .await
        .unwrap();
    assert_eq!(networks.discovery_preparations.available_permits(), 3);
    work.abort();
    assert!(work.await.unwrap_err().is_cancelled());
    drop(discovery);
    assert_eq!(networks.discovery_preparations.available_permits(), 3);
    gate.release();
    tokio::time::timeout(Duration::from_secs(3), async {
        while networks.discovery_preparations.available_permits() != 4 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        binder.bindings.lock().unwrap().len(),
        1,
        "revocation must fence the second socket bind"
    );
}
