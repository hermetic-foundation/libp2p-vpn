use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    num::NonZeroU32,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use super::{
    tokio::Behaviour, InterfaceTask, InterfaceTaskState, OwnedDiscovery, PendingEvent, TaskFinished,
};
use crate::{Config, InterfaceSocketBinding};
use if_watch::IfEvent;
use libp2p_core::Multiaddr;
use libp2p_identity::PeerId;
use libp2p_swarm::{NetworkBehaviour, ToSwarm};

fn addr(value: &str) -> IpAddr {
    value.parse().unwrap()
}

fn behaviour() -> Behaviour {
    Behaviour::new(Config::default(), PeerId::random()).unwrap()
}

#[test]
fn filtered_advertisements_exclude_other_interface_addresses() {
    let allowed = HashSet::from([addr("192.0.2.1"), addr("2001:db8::1")]);
    for value in [
        "/ip4/192.0.2.1/tcp/4001",
        "/ip6/2001:db8::1/udp/4001/quic-v1",
    ] {
        assert!(super::iface::advertisement_allowed(
            &value.parse().unwrap(),
            Some(&allowed)
        ));
    }
    for value in [
        "/ip4/100.64.0.1/tcp/4001",
        "/ip6/2001:db8::2/tcp/4001",
        "/dns4/example.test/tcp/4001",
    ] {
        assert!(!super::iface::advertisement_allowed(
            &value.parse().unwrap(),
            Some(&allowed)
        ));
        assert!(super::iface::advertisement_allowed(
            &value.parse().unwrap(),
            None
        ));
    }
}

#[tokio::test]
async fn default_admission_preserves_address_family_rules() {
    let b = behaviour();
    assert!(b.interface_allowed(addr("192.0.2.1")));
    assert!(b.interface_allowed(addr("100.64.0.1")));
    for invalid in ["127.0.0.1", "0.0.0.0", "224.0.0.251", "::1", "2001:db8::1"] {
        assert!(!b.interface_allowed(addr(invalid)));
    }
}

#[tokio::test]
async fn allowlist_admits_only_exact_addresses() {
    let mut b = behaviour();
    let lan = addr("192.0.2.1");
    assert!(!b.has_interface_filter());
    b.set_allowed_interfaces(Some(HashSet::from([lan])));
    assert!(b.has_interface_filter());
    assert!(b.interface_allowed(lan));
    assert!(!b.interface_allowed(addr("192.0.2.2")));
    assert!(!b.interface_allowed(addr("100.64.0.1")));
    b.set_allowed_interfaces(Some(HashSet::new()));
    assert!(b.has_interface_filter());
    assert!(!b.interface_allowed(lan));
    b.set_allowed_interfaces(None);
    assert!(!b.has_interface_filter());
    assert!(b.interface_allowed(lan));
}

#[tokio::test]
async fn allowlist_cannot_admit_invalid_addresses_or_wrong_family() {
    let mut b = behaviour();
    for invalid in ["127.0.0.1", "0.0.0.0", "224.0.0.251", "2001:db8::1"] {
        let invalid = addr(invalid);
        b.set_allowed_interfaces(Some(HashSet::from([invalid])));
        assert!(!b.interface_allowed(invalid));
    }
}

struct Retired(Option<tokio::sync::oneshot::Sender<()>>);

impl Drop for Retired {
    fn drop(&mut self) {
        let _ = self.0.take().unwrap().send(());
    }
}

async fn install_task(b: &mut Behaviour, ip: IpAddr) -> tokio::sync::oneshot::Receiver<()> {
    if let Some(task) = b.if_tasks.remove(&ip) {
        task.abort();
    }
    let (started, ready) = tokio::sync::oneshot::channel();
    let (retired, done) = tokio::sync::oneshot::channel();
    let state = b.interface_task_state(ip);
    state.installed.store(true, Ordering::Release);
    let finished = TaskFinished(state.clone());
    let handle = tokio::spawn(async move {
        let _finished = finished;
        let _retired = Retired(Some(retired));
        let _ = started.send(());
        std::future::pending::<()>().await;
    });
    b.if_tasks.insert(ip, InterfaceTask { handle, state });
    ready.await.unwrap();
    done
}

#[derive(Debug, Default)]
struct PendingBinding {
    started: tokio::sync::Notify,
    attempts: std::sync::atomic::AtomicUsize,
}

impl InterfaceSocketBinding for PendingBinding {
    fn identity(&self) -> [u64; 3] {
        [10, 20, 30]
    }
    fn interface_index(&self) -> NonZeroU32 {
        NonZeroU32::new(7).unwrap()
    }
    fn bind(&self, _: &std::net::UdpSocket) -> std::io::Result<()> {
        panic!("async preparation must not use the synchronous fallback")
    }
    fn is_current(&self) -> bool {
        true
    }
    fn prepare_sockets(self: Arc<Self>, _: IpAddr) -> crate::SocketPreparation {
        Box::pin(async move {
            self.attempts.fetch_add(1, Ordering::AcqRel);
            self.started.notify_one();
            std::future::pending().await
        })
    }
}

#[tokio::test]
async fn owned_preparation_never_blocks_policy_and_revocation_cancels_it() {
    let mut b = behaviour();
    let lan = addr("192.0.2.1");
    let binding = Arc::new(PendingBinding::default());
    b.set_allowed_interfaces(Some([lan].into()));
    b.set_interface_bindings(Some(
        [(lan, binding.clone() as Arc<dyn InterfaceSocketBinding>)].into(),
    ));
    tokio::time::timeout(Duration::from_secs(1), binding.started.notified())
        .await
        .unwrap();
    let state = b.if_tasks.get(&lan).unwrap().state.clone();
    b.set_allowed_interfaces(Some(HashSet::new()));
    tokio::time::timeout(Duration::from_secs(1), async {
        while !state.finished.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!state.is_current());
    assert_eq!(binding.attempts.load(Ordering::Acquire), 1);
}

#[derive(Debug, Default)]
struct RetryBinding(std::sync::atomic::AtomicUsize);

impl InterfaceSocketBinding for RetryBinding {
    fn identity(&self) -> [u64; 3] {
        [1, 5, 9]
    }
    fn interface_index(&self) -> NonZeroU32 {
        NonZeroU32::new(7).unwrap()
    }
    fn bind(&self, _: &std::net::UdpSocket) -> std::io::Result<()> {
        unreachable!()
    }
    fn is_current(&self) -> bool {
        true
    }
    fn prepare_sockets(self: Arc<Self>, _: IpAddr) -> crate::SocketPreparation {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::AcqRel);
            // Model a preparation result, not a failed kernel syscall.
            Err(std::io::ErrorKind::WouldBlock.into())
        })
    }
}

#[tokio::test]
async fn setup_retries_are_finite_and_a_fresh_opportunity_rearms_exhausted_work() {
    let mut b = behaviour();
    let lan = addr("192.0.2.1");
    let binding = Arc::new(RetryBinding::default());
    let bindings: HashMap<_, Arc<dyn InterfaceSocketBinding>> =
        [(lan, binding.clone() as Arc<dyn InterfaceSocketBinding>)].into();
    b.set_allowed_interfaces(Some([lan].into()));
    b.set_interface_bindings(Some(bindings.clone()));
    let state = b.if_tasks.get(&lan).unwrap().state.clone();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !state.finished.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(binding.0.load(Ordering::Acquire), 3);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        binding.0.load(Ordering::Acquire),
        3,
        "no idle setup retry loop"
    );
    b.set_interface_bindings(Some(bindings));
    tokio::time::timeout(Duration::from_secs(1), async {
        while binding.0.load(Ordering::Acquire) != 4 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!Arc::ptr_eq(&state, &b.if_tasks.get(&lan).unwrap().state));
}

#[tokio::test]
async fn an_opportunity_during_setup_backoff_gets_its_complete_retry_round() {
    let mut b = behaviour();
    let lan = addr("192.0.2.1");
    let binding = Arc::new(RetryBinding::default());
    let bindings: HashMap<_, Arc<dyn InterfaceSocketBinding>> =
        [(lan, binding.clone() as Arc<dyn InterfaceSocketBinding>)].into();
    b.set_allowed_interfaces(Some([lan].into()));
    b.set_interface_bindings(Some(bindings.clone()));
    let state = b.if_tasks[&lan].state.clone();
    tokio::time::timeout(Duration::from_secs(3), async {
        while binding.0.load(Ordering::Acquire) < 2 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    b.set_interface_bindings(Some(bindings));
    assert!(
        Arc::ptr_eq(&state, &b.if_tasks[&lan].state),
        "do not abort a live preparation"
    );
    tokio::time::timeout(Duration::from_secs(7), async {
        while !state.finished.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        binding.0.load(Ordering::Acquire),
        5,
        "two old attempts plus three from the new opportunity"
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(binding.0.load(Ordering::Acquire), 5);
}

#[tokio::test]
async fn terminal_exhaustion_is_rearmed_before_the_old_task_finished_guard_runs() {
    let mut b = behaviour();
    let lan = addr("192.0.2.1");
    let binding = Arc::new(PendingBinding::default());
    let bindings: HashMap<_, Arc<dyn InterfaceSocketBinding>> =
        [(lan, binding.clone() as Arc<dyn InterfaceSocketBinding>)].into();
    b.set_allowed_interfaces(Some([lan].into()));
    b.set_interface_bindings(Some(bindings.clone()));
    binding.started.notified().await;
    let old = b.if_tasks[&lan].state.clone();
    // Exact state between the final locked decision and TaskFinished::drop.
    old.preparation.lock().unwrap().exhausted = true;
    assert!(!old.finished.load(Ordering::Acquire));
    b.set_interface_bindings(Some(bindings));
    let new = b.if_tasks[&lan].state.clone();
    assert!(!Arc::ptr_eq(&old, &new));
    assert!(
        !old.is_current(),
        "replacement must revoke before asynchronous abort completes"
    );
    assert!(!new.preparation.lock().unwrap().exhausted);
    tokio::time::timeout(Duration::from_secs(1), binding.started.notified())
        .await
        .unwrap();
    assert_eq!(binding.attempts.load(Ordering::Acquire), 2);
}

#[derive(Debug, Default)]
struct OldFailureBinding {
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
    attempts: std::sync::atomic::AtomicUsize,
}

impl InterfaceSocketBinding for OldFailureBinding {
    fn identity(&self) -> [u64; 3] {
        [3, 6, 9]
    }
    fn interface_index(&self) -> NonZeroU32 {
        NonZeroU32::new(7).unwrap()
    }
    fn bind(&self, _: &std::net::UdpSocket) -> std::io::Result<()> {
        unreachable!()
    }
    fn is_current(&self) -> bool {
        true
    }
    fn prepare_sockets(self: Arc<Self>, _: IpAddr) -> crate::SocketPreparation {
        Box::pin(async move {
            let attempt = self.attempts.fetch_add(1, Ordering::AcqRel);
            self.started.notify_one();
            if attempt == 0 {
                self.release.notified().await;
            }
            Err(std::io::ErrorKind::PermissionDenied.into())
        })
    }
}

#[tokio::test]
async fn a_pending_old_permanent_failure_cannot_consume_a_fresh_opportunity() {
    let mut b = behaviour();
    let lan = addr("192.0.2.1");
    let binding = Arc::new(OldFailureBinding::default());
    let bindings: HashMap<_, Arc<dyn InterfaceSocketBinding>> =
        [(lan, binding.clone() as Arc<dyn InterfaceSocketBinding>)].into();
    b.set_allowed_interfaces(Some([lan].into()));
    b.set_interface_bindings(Some(bindings.clone()));
    binding.started.notified().await;
    let state = b.if_tasks[&lan].state.clone();
    b.set_interface_bindings(Some(bindings));
    binding.release.notify_one();
    tokio::time::timeout(Duration::from_secs(2), binding.started.notified())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !state.finished.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(binding.attempts.load(Ordering::Acquire), 2);
    assert!(state.preparation.lock().unwrap().exhausted);
}

#[tokio::test]
async fn replacing_allowlist_retires_only_disallowed_tasks() {
    let mut b = behaviour();
    let lan = addr("192.0.2.1");
    let cell = addr("100.64.0.1");
    b.set_allowed_interfaces(Some(HashSet::from([lan, cell])));
    let mut lan_done = install_task(&mut b, lan).await;
    let cell_done = install_task(&mut b, cell).await;
    b.set_allowed_interfaces(Some(HashSet::from([lan])));
    tokio::time::timeout(Duration::from_secs(1), cell_done)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(b.active_interfaces().collect::<Vec<_>>(), vec![lan]);
    assert!(matches!(
        lan_done.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    b.set_allowed_interfaces(Some(HashSet::new()));
    tokio::time::timeout(Duration::from_secs(1), lan_done)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(b.active_interfaces().count(), 0);
}

#[tokio::test]
#[ignore = "requires P2P_VPN_MDNS_TEST_SOURCE assigned to a multicast-capable IPv4 interface"]
async fn assigned_interface_resumes_without_a_new_up_event() {
    let lan = addr(&std::env::var("P2P_VPN_MDNS_TEST_SOURCE").expect("test source address"));
    let mut b = behaviour();
    b.available_interfaces.insert(lan);
    b.set_allowed_interfaces(Some(HashSet::new()));
    assert_eq!(b.active_interfaces().count(), 0);
    b.set_allowed_interfaces(Some(HashSet::from([lan])));
    assert_eq!(b.active_interfaces().collect::<Vec<_>>(), vec![lan]);
    let previous = b.if_tasks[&lan].state.clone();
    b.if_tasks[&lan].handle.abort();
    let _ = (&mut b.if_tasks.get_mut(&lan).unwrap().handle).await;
    b.set_allowed_interfaces(Some(HashSet::from([lan])));
    assert_eq!(b.active_interfaces().collect::<Vec<_>>(), vec![lan]);
    assert!(!Arc::ptr_eq(&previous, &b.if_tasks[&lan].state));
    b.set_allowed_interfaces(Some(HashSet::new()));
    assert_eq!(b.active_interfaces().count(), 0);
    tokio::task::yield_now().await;
    b.set_allowed_interfaces(Some(HashSet::from([lan])));
    assert_eq!(b.active_interfaces().collect::<Vec<_>>(), vec![lan]);
}

#[tokio::test]
async fn dropping_behaviour_aborts_interface_tasks() {
    let mut b = behaviour();
    let done = install_task(&mut b, addr("192.0.2.1")).await;
    drop(b);
    tokio::time::timeout(Duration::from_secs(1), done)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn identical_policy_does_not_restart_tasks() {
    let mut b = behaviour();
    let lan = addr("192.0.2.1");
    b.set_allowed_interfaces(Some(HashSet::from([lan])));
    let mut done = install_task(&mut b, lan).await;
    b.set_allowed_interfaces(Some(HashSet::from([lan])));
    assert_eq!(b.active_interfaces().count(), 1);
    assert!(matches!(
        done.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn filtered_inventory_is_retained_for_later_readmission() {
    let mut b = behaviour();
    let lan = addr("192.0.2.1");
    b.available_interfaces.insert(lan);
    b.set_allowed_interfaces(Some(HashSet::new()));
    assert!(b.available_interfaces.contains(&lan));
    assert_eq!(b.active_interfaces().count(), 0);
    // Restoring policy admits this known address; socket creation still requires
    // a real assigned address and is covered by platform integration tests.
    b.set_allowed_interfaces(None);
    assert!(b.available_interfaces.contains(&lan));
    assert!(b.interface_allowed(lan));
}

#[derive(Debug)]
struct Binding {
    identity: [u64; 3],
    index: NonZeroU32,
    current: AtomicBool,
}

impl Binding {
    fn new(generation: u64, index: u32) -> Arc<Self> {
        Arc::new(Self {
            identity: [1, 2, generation],
            index: NonZeroU32::new(index).unwrap(),
            current: AtomicBool::new(true),
        })
    }
}

impl InterfaceSocketBinding for Binding {
    fn identity(&self) -> [u64; 3] {
        self.identity
    }
    fn interface_index(&self) -> NonZeroU32 {
        self.index
    }
    fn bind(&self, _: &std::net::UdpSocket) -> std::io::Result<()> {
        Ok(())
    }
    fn is_current(&self) -> bool {
        self.current.load(Ordering::Acquire)
    }
}

fn bindings(
    entries: &[(IpAddr, Arc<Binding>)],
) -> Option<HashMap<IpAddr, Arc<dyn InterfaceSocketBinding>>> {
    Some(
        entries
            .iter()
            .map(|(ip, b)| (*ip, b.clone() as Arc<dyn InterfaceSocketBinding>))
            .collect(),
    )
}

async fn assert_retired(done: tokio::sync::oneshot::Receiver<()>) {
    tokio::time::timeout(Duration::from_secs(1), done)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn binding_policy_is_independent_and_deny_by_default() {
    let mut b = behaviour();
    let lan = addr("192.0.2.1");
    let other = addr("192.0.2.2");
    b.set_allowed_interfaces(Some(HashSet::from([lan, other])));
    b.set_interface_bindings(Some(HashMap::new()));
    assert!(!b.interface_allowed(lan));
    b.set_interface_bindings(bindings(&[(lan, Binding::new(1, 7))]));
    assert!(b.interface_allowed(lan));
    assert!(!b.interface_allowed(other));
    assert_eq!(b.allowed_interfaces(), Some(HashSet::from([lan, other])));
    b.set_allowed_interfaces(Some(HashSet::from([other])));
    assert!(!b.interface_allowed(lan));
    assert!(!b.interface_allowed(other));
    b.set_interface_bindings(None);
    assert!(b.interface_allowed(other));
}

#[tokio::test]
async fn identical_and_unrelated_binding_changes_preserve_tasks() {
    let mut b = behaviour();
    let lan = addr("192.0.2.1");
    b.set_interface_bindings(bindings(&[(lan, Binding::new(1, 7))]));
    let mut done = install_task(&mut b, lan).await;
    let state = b.if_tasks[&lan].state.clone();
    // Equality is by ownership identity, not Arc allocation.
    b.set_interface_bindings(bindings(&[(lan, Binding::new(1, 7))]));
    b.set_interface_bindings(bindings(&[
        (lan, Binding::new(1, 7)),
        (addr("192.0.2.2"), Binding::new(2, 8)),
    ]));
    b.set_allowed_interfaces(Some(HashSet::from([lan])));
    b.set_allowed_interfaces(None);
    b.set_ipv6(false);
    assert!(Arc::ptr_eq(&state, &b.if_tasks[&lan].state));
    assert!(matches!(
        done.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn same_ip_new_identity_or_index_retires_and_fences_old_task() {
    for (generation, index) in [(2, 7), (1, 8)] {
        let mut b = behaviour();
        let lan = addr("192.0.2.1");
        b.set_interface_bindings(bindings(&[(lan, Binding::new(1, 7))]));
        let done = install_task(&mut b, lan).await;
        let old = b.if_tasks[&lan].state.clone();
        b.set_interface_bindings(bindings(&[(lan, Binding::new(generation, index))]));
        assert!(!old.is_current());
        assert_eq!(b.active_interfaces().count(), 0);
        assert!(b.interface_allowed(lan));
        assert_retired(done).await;
    }
}

#[tokio::test]
async fn binding_mode_changes_and_removal_retire_tasks() {
    let lan = addr("192.0.2.1");
    let mut b = behaviour();
    let done = install_task(&mut b, lan).await;
    b.set_interface_bindings(bindings(&[(lan, Binding::new(1, 7))]));
    assert_retired(done).await;
    let done = install_task(&mut b, lan).await;
    b.set_interface_bindings(None);
    assert_retired(done).await;
    b.set_interface_bindings(bindings(&[(lan, Binding::new(1, 7))]));
    let done = install_task(&mut b, lan).await;
    b.set_interface_bindings(Some(HashMap::new()));
    assert_retired(done).await;
    assert!(!b.interface_allowed(lan));
}

#[tokio::test]
async fn revoked_binding_is_reaped_even_without_a_policy_change() {
    let lan = addr("192.0.2.1");
    let binding = Binding::new(1, 7);
    let mut b = behaviour();
    b.set_interface_bindings(bindings(&[(lan, binding.clone())]));
    let done = install_task(&mut b, lan).await;
    let old = b.if_tasks[&lan].state.clone();
    binding.current.store(false, Ordering::Release);
    assert!(!old.is_current());
    assert_eq!(b.active_interfaces().count(), 0);
    let mut cx = std::task::Context::from_waker(futures::task::noop_waker_ref());
    let _ = libp2p_swarm::NetworkBehaviour::poll(&mut b, &mut cx);
    assert!(!b.if_tasks.contains_key(&lan));
    assert_retired(done).await;
    b.set_interface_bindings(bindings(&[(lan, Binding::new(2, 7))]));
    assert!(b.interface_allowed(lan));
}

#[tokio::test]
async fn completed_tasks_are_reaped_and_identical_policy_can_reconcile() {
    let lan = addr("192.0.2.1");
    let mut b = behaviour();
    b.set_interface_bindings(bindings(&[(lan, Binding::new(1, 7))]));
    let state = Arc::new(InterfaceTaskState::new(
        b.interface_bindings.as_ref().unwrap().get(&lan).cloned(),
        b.task_waker.clone(),
    ));
    let finished = TaskFinished(state.clone());
    let handle = tokio::spawn(async move {
        let _finished = finished;
    });
    b.if_tasks.insert(
        lan,
        InterfaceTask {
            handle,
            state: state.clone(),
        },
    );
    (&mut b.if_tasks.get_mut(&lan).unwrap().handle)
        .await
        .unwrap();
    assert!(state.finished.load(Ordering::Acquire));
    b.set_interface_bindings(bindings(&[(lan, Binding::new(1, 7))]));
    assert!(!Arc::ptr_eq(&state, &b.if_tasks[&lan].state));
    assert_eq!(
        b.active_interfaces().count(),
        0,
        "preparation is not installed discovery"
    );
    let done = install_task(&mut b, lan).await;
    assert_eq!(b.active_interfaces().collect::<Vec<_>>(), vec![lan]);
    b.set_interface_bindings(Some(HashMap::new()));
    assert_retired(done).await;
}

#[tokio::test]
async fn behaviour_poll_reaps_completed_tasks_without_changing_policy() {
    let mut b = behaviour();
    let lan = addr("192.0.2.1");
    b.set_interface_bindings(Some(HashMap::new()));
    let state = Arc::new(InterfaceTaskState::new(None, b.task_waker.clone()));
    let finished = TaskFinished(state.clone());
    let handle = tokio::spawn(async move {
        drop(finished);
    });
    b.if_tasks.insert(lan, InterfaceTask { handle, state });
    (&mut b.if_tasks.get_mut(&lan).unwrap().handle)
        .await
        .unwrap();
    let mut cx = std::task::Context::from_waker(futures::task::noop_waker_ref());
    let _ = libp2p_swarm::NetworkBehaviour::poll(&mut b, &mut cx);
    assert!(!b.if_tasks.contains_key(&lan));
}

#[tokio::test]
async fn ipv6_switch_is_idempotent_and_preserves_lan_policy() {
    let mut b = behaviour();
    let v4 = addr("192.0.2.1");
    let v6 = addr("fe80::1234");
    let allowed = Some(HashSet::from([v4, v6]));
    b.set_allowed_interfaces(allowed.clone());
    b.set_interface_bindings(bindings(&[
        (v4, Binding::new(1, 7)),
        (v6, Binding::new(1, 7)),
    ]));
    let done = install_task(&mut b, v4).await;
    b.set_ipv6(true);
    assert_retired(done).await;
    assert!(b.interface_allowed(v6));
    assert!(!b.interface_allowed(v4));
    assert_eq!(b.allowed_interfaces(), allowed);
    let mut done = install_task(&mut b, v6).await;
    b.set_ipv6(true);
    assert!(matches!(
        done.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    b.set_ipv6(false);
    assert_retired(done).await;
    assert!(b.interface_allowed(v4));
    assert!(!b.interface_allowed(v6));
    assert_eq!(b.interface_bindings.as_ref().unwrap().len(), 2);
}

fn discovery(owner: &Arc<InterfaceTaskState>, peer: PeerId, ttl: u64) -> OwnedDiscovery {
    (
        (
            peer,
            "/ip4/192.0.2.100/tcp/4001".parse().unwrap(),
            Instant::now() + Duration::from_secs(ttl),
        ),
        owner.clone(),
    )
}

fn poll_behaviour(b: &mut Behaviour) -> Poll<ToSwarm<super::Event, std::convert::Infallible>> {
    NetworkBehaviour::poll(b, &mut Context::from_waker(futures::task::noop_waker_ref()))
}

fn assert_discovered(
    event: ToSwarm<super::Event, std::convert::Infallible>,
    peer: PeerId,
    address: &Multiaddr,
) {
    match event {
        ToSwarm::GenerateEvent(super::Event::Discovered(nodes)) => {
            assert_eq!(nodes, vec![(peer, address.clone())])
        }
        other => panic!("expected current discovery, got {other:?}"),
    }
}

fn assert_announced(
    event: ToSwarm<super::Event, std::convert::Infallible>,
    peer: PeerId,
    address: &Multiaddr,
) {
    match event {
        ToSwarm::NewExternalAddrOfPeer {
            peer_id,
            address: actual,
        } => {
            assert_eq!(peer_id, peer);
            assert_eq!(actual, *address);
        }
        other => panic!("expected current announcement, got {other:?}"),
    }
}

#[tokio::test]
async fn retired_queued_tuple_cannot_publish_or_refresh_current_ttl() {
    let lan = addr("192.0.2.1");
    let peer = PeerId::random();
    let mut b = behaviour();
    b.set_interface_bindings(bindings(&[(lan, Binding::new(1, 7))]));
    let old_done = install_task(&mut b, lan).await;
    let old_owner = b.if_tasks[&lan].state.clone();
    let old_discovery = discovery(&old_owner, peer, 3600);
    b.query_response_sender
        .try_send(old_discovery.clone())
        .unwrap();
    b.set_interface_bindings(bindings(&[(lan, Binding::new(2, 8))]));
    assert_retired(old_done).await;
    let _current_done = install_task(&mut b, lan).await;
    let current = discovery(&b.if_tasks[&lan].state, peer, 60);
    let expiration = current.0 .2;
    b.query_response_sender.try_send(current.clone()).unwrap();
    let event = poll_behaviour(&mut b);
    let Poll::Ready(event) = event else {
        panic!("fresh discovery was lost");
    };
    assert_discovered(event, peer, &current.0 .1);
    assert_eq!(b.discovered_nodes.len(), 1);
    assert_eq!(b.discovered_nodes[0].observations.len(), 1);
    assert_eq!(b.discovered_nodes[0].observations[0].0, expiration);
    assert!(Arc::ptr_eq(
        &b.discovered_nodes[0].observations[0].1,
        &current.1
    ));
    assert_announced(b.next_pending_event().unwrap(), peer, &current.0 .1);
    b.query_response_sender.try_send(old_discovery).unwrap();
    assert!(poll_behaviour(&mut b).is_pending());
    assert_eq!(b.discovered_nodes[0].observations[0].0, expiration);
    assert!(b.pending_events.is_empty());
}

#[tokio::test]
async fn pending_old_discovery_and_announcement_are_fenced_at_dispatch() {
    let lan = addr("192.0.2.1");
    let peer = PeerId::random();
    let binding = Binding::new(1, 7);
    let mut b = behaviour();
    b.set_interface_bindings(bindings(&[(lan, binding.clone())]));
    let _done = install_task(&mut b, lan).await;
    let old = discovery(&b.if_tasks[&lan].state, peer, 3600);
    let pending = b.accept_discovery(old).unwrap();
    b.pending_events
        .push_back(PendingEvent::Discovered(vec![pending.clone()]));
    b.pending_events.push_back(PendingEvent::Announce(pending));
    // No channel drain or policy reconciliation occurs between revocation and
    // dispatch: each queued event must independently validate its owner.
    binding.current.store(false, Ordering::Release);
    assert!(b.next_pending_event().is_none());
    assert!(b.pending_events.is_empty());
}

#[tokio::test]
async fn fresh_owner_reannounces_same_address_and_releases_superseded_owner() {
    let lan = addr("192.0.2.1");
    let peer = PeerId::random();
    let mut b = behaviour();
    b.set_interface_bindings(bindings(&[(lan, Binding::new(1, 7))]));
    let done = install_task(&mut b, lan).await;
    let old = discovery(&b.if_tasks[&lan].state, peer, 3600);
    let old_owner = Arc::downgrade(&old.1);
    let pending = b.accept_discovery(old).unwrap();
    b.pending_events
        .push_back(PendingEvent::Discovered(vec![pending.clone()]));
    b.pending_events.push_back(PendingEvent::Announce(pending));
    b.set_interface_bindings(bindings(&[(lan, Binding::new(2, 8))]));
    assert_retired(done).await;
    let _done = install_task(&mut b, lan).await;
    let current = discovery(&b.if_tasks[&lan].state, peer, 60);
    let pending = b.accept_discovery(current.clone()).unwrap();
    assert_eq!(b.discovered_nodes.len(), 1);
    assert_eq!(b.discovered_nodes[0].observations.len(), 1);
    assert_eq!(b.discovered_nodes[0].observations[0].0, current.0 .2);
    assert!(Arc::ptr_eq(
        &b.discovered_nodes[0].observations[0].1,
        &current.1
    ));
    b.pending_events
        .push_back(PendingEvent::Discovered(vec![pending.clone()]));
    b.pending_events.push_back(PendingEvent::Announce(pending));
    assert_discovered(b.next_pending_event().unwrap(), peer, &current.0 .1);
    assert_announced(b.next_pending_event().unwrap(), peer, &current.0 .1);
    assert!(b.next_pending_event().is_none());
    // Only the existing node record and event queue own discovery provenance;
    // no side registry keeps the superseded task state alive.
    assert!(old_owner.upgrade().is_none());
}

#[tokio::test]
async fn pending_announcement_is_dropped_after_discovered_event_was_emitted() {
    let lan = addr("192.0.2.1");
    let peer = PeerId::random();
    let mut b = behaviour();
    b.set_interface_bindings(bindings(&[(lan, Binding::new(1, 7))]));
    let done = install_task(&mut b, lan).await;
    let old = discovery(&b.if_tasks[&lan].state, peer, 60);
    b.query_response_sender.try_send(old.clone()).unwrap();
    let Poll::Ready(event) = poll_behaviour(&mut b) else {
        panic!("missing discovery");
    };
    assert_discovered(event, peer, &old.0 .1);
    b.set_interface_bindings(bindings(&[(lan, Binding::new(2, 8))]));
    assert_retired(done).await;
    let _done = install_task(&mut b, lan).await;
    let current = discovery(&b.if_tasks[&lan].state, peer, 30);
    b.query_response_sender.try_send(current.clone()).unwrap();
    let Poll::Ready(event) = poll_behaviour(&mut b) else {
        panic!("missing replacement discovery");
    };
    assert_discovered(event, peer, &current.0 .1);
    assert_announced(b.next_pending_event().unwrap(), peer, &current.0 .1);
    assert!(b.next_pending_event().is_none());
}

#[tokio::test]
async fn discovery_batch_filters_only_the_revoked_owner() {
    let lan = addr("192.0.2.1");
    let other = addr("192.0.2.2");
    let first = Binding::new(1, 7);
    let second = Binding::new(1, 8);
    let mut b = behaviour();
    b.set_interface_bindings(bindings(&[(lan, first.clone()), (other, second)]));
    let _first_done = install_task(&mut b, lan).await;
    let _second_done = install_task(&mut b, other).await;
    let old = discovery(&b.if_tasks[&lan].state, PeerId::random(), 60);
    let current = discovery(&b.if_tasks[&other].state, PeerId::random(), 60);
    let old = b.accept_discovery(old).unwrap();
    let pending = b.accept_discovery(current.clone()).unwrap();
    b.pending_events
        .push_back(PendingEvent::Discovered(vec![old, pending]));
    first.current.store(false, Ordering::Release);
    assert_discovered(b.next_pending_event().unwrap(), current.0 .0, &current.0 .1);
    assert!(b.next_pending_event().is_none());
}

#[tokio::test]
async fn completed_legacy_task_data_requires_current_source_policy() {
    let lan = addr("192.0.2.1");
    let mut b = behaviour();
    b.available_interfaces.insert(lan);
    let done = install_task(&mut b, lan).await;
    let owner = b.if_tasks[&lan].state.clone();
    let current = discovery(&owner, PeerId::random(), 60);
    b.if_tasks[&lan].handle.abort();
    assert_retired(done).await;
    b.reap_interfaces(false);
    assert!(b.if_tasks.is_empty());
    assert!(owner.is_current());
    let pending = b.accept_discovery(current.clone()).unwrap();
    b.pending_events.push_back(PendingEvent::Announce(pending));
    b.on_interface_event(IfEvent::Down("192.0.2.1/24".parse().unwrap()));
    assert!(!b.discovery_owner_current(&owner));
    assert!(b.accept_discovery(current).is_none());
    assert!(b.next_pending_event().is_none());
}

#[tokio::test]
async fn current_binding_survives_ambiguous_ip_only_down() {
    let lan = addr("192.0.2.1");
    let binding = Binding::new(1, 7);
    let mut b = behaviour();
    b.set_interface_bindings(bindings(&[(lan, binding.clone())]));
    let mut done = install_task(&mut b, lan).await;
    let state = b.if_tasks[&lan].state.clone();
    b.available_interfaces.insert(lan);
    b.on_interface_event(IfEvent::Down("192.0.2.1/24".parse().unwrap()));
    assert!(!b.available_interfaces.contains(&lan));
    assert_eq!(b.interface_candidates(), vec![lan]);
    assert!(Arc::ptr_eq(&state, &b.if_tasks[&lan].state));
    assert!(b.discovery_owner_current(&state));
    assert!(matches!(
        done.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    binding.current.store(false, Ordering::Release);
    b.on_interface_event(IfEvent::Down("192.0.2.1/24".parse().unwrap()));
    assert!(!b.if_tasks.contains_key(&lan));
    assert_retired(done).await;
}

#[tokio::test]
async fn selected_binding_is_inventory_without_an_ifwatch_up() {
    let lan = addr("192.0.2.1");
    let mut b = behaviour();
    b.set_interface_bindings(Some(HashMap::new()));
    b.available_interfaces.insert(addr("100.64.0.1"));
    assert!(b.interface_candidates().is_empty());
    b.set_interface_bindings(bindings(&[(lan, Binding::new(1, 7))]));
    assert!(!b.available_interfaces.contains(&lan));
    assert_eq!(b.interface_candidates(), vec![lan]);
    let done = install_task(&mut b, lan).await;
    let old = b.if_tasks[&lan].state.clone();
    b.set_interface_bindings(bindings(&[(lan, Binding::new(2, 8))]));
    assert_retired(done).await;
    assert!(!old.is_current());
    assert_eq!(b.interface_candidates(), vec![lan]);
    assert!(b.interface_allowed(lan));
    assert!(!b.available_interfaces.contains(&lan));
    let _done = install_task(&mut b, lan).await;
    assert_eq!(b.active_interfaces().collect::<Vec<_>>(), vec![lan]);
    assert!(b.discovery_owner_current(&b.if_tasks[&lan].state));
    b.set_interface_bindings(None);
    assert_eq!(b.interface_candidates(), vec![addr("100.64.0.1")]);
}

#[tokio::test]
async fn legacy_ip_only_down_still_retires_its_task() {
    let lan = addr("192.0.2.1");
    let mut b = behaviour();
    let done = install_task(&mut b, lan).await;
    b.available_interfaces.insert(lan);
    b.on_interface_event(IfEvent::Down("192.0.2.1/24".parse().unwrap()));
    assert!(!b.if_tasks.contains_key(&lan));
    assert!(b.available_interfaces.is_empty());
    assert_retired(done).await;
}

async fn legacy_observations() -> (Behaviour, OwnedDiscovery, OwnedDiscovery) {
    let first = addr("192.0.2.1");
    let second = addr("192.0.2.2");
    let mut b = behaviour();
    b.available_interfaces.extend([first, second]);
    let _first_done = install_task(&mut b, first).await;
    let _second_done = install_task(&mut b, second).await;
    let peer = PeerId::random();
    let first = discovery(&b.if_tasks[&first].state, peer, 60);
    let second = discovery(&b.if_tasks[&second].state, peer, 120);
    (b, first, second)
}

fn assert_expired(
    event: ToSwarm<super::Event, std::convert::Infallible>,
    peer: PeerId,
    address: &Multiaddr,
) {
    match event {
        ToSwarm::GenerateEvent(super::Event::Expired(nodes)) => {
            assert_eq!(nodes, vec![(peer, address.clone())]);
        }
        other => panic!("expected tuple expiration, got {other:?}"),
    }
}

#[tokio::test]
async fn legacy_duplicate_survives_either_interface_withdrawal() {
    for withdraw_first in [true, false] {
        let (mut b, first, second) = legacy_observations().await;
        assert!(b.accept_discovery(first.clone()).is_some());
        assert!(b.accept_discovery(second.clone()).is_none());
        assert_eq!(b.discovered_nodes.len(), 1);
        assert_eq!(b.discovered_nodes[0].observations.len(), 2);
        let (withdrawn, remaining) = if withdraw_first {
            ("192.0.2.1/24", &second)
        } else {
            ("192.0.2.2/24", &first)
        };
        b.on_interface_event(IfEvent::Down(withdrawn.parse().unwrap()));
        assert_eq!(b.prune_discoveries(Instant::now()), Some(remaining.0 .2));
        assert_eq!(
            b.discovered_nodes().collect::<Vec<_>>(),
            vec![&remaining.0 .0]
        );
        let observations = &b.discovered_nodes[0].observations;
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].0, remaining.0 .2);
        assert!(Arc::ptr_eq(&observations[0].1, &remaining.1));
        assert!(b.next_pending_event().is_none());
        let last = format!("{}/24", remaining.1.source.unwrap());
        b.on_interface_event(IfEvent::Down(last.parse().unwrap()));
        assert_eq!(b.prune_discoveries(Instant::now()), None);
        assert!(b.discovered_nodes.is_empty());
        assert_expired(
            b.next_pending_event().unwrap(),
            remaining.0 .0,
            &remaining.0 .1,
        );
        assert!(b.next_pending_event().is_none());
    }
}

#[tokio::test]
async fn legacy_observations_have_independent_monotonic_ttls() {
    let (mut b, mut first, mut second) = legacy_observations().await;
    let now = Instant::now();
    first.0 .2 = now + Duration::from_secs(10);
    second.0 .2 = now + Duration::from_secs(30);
    assert!(b.accept_discovery(first.clone()).is_some());
    assert!(b.accept_discovery(second.clone()).is_none());
    let mut refresh = first.clone();
    refresh.0 .2 = now + Duration::from_secs(5);
    assert!(b.accept_discovery(refresh.clone()).is_none());
    assert_eq!(b.discovered_nodes[0].observations[0].0, first.0 .2);
    refresh.0 .2 = now + Duration::from_secs(20);
    assert!(b.accept_discovery(refresh.clone()).is_none());
    assert_eq!(b.discovered_nodes[0].observations[0].0, refresh.0 .2);
    assert_eq!(b.discovered_nodes[0].observations[1].0, second.0 .2);
    assert_eq!(b.prune_discoveries(refresh.0 .2), Some(second.0 .2));
    assert_eq!(b.discovered_nodes.len(), 1);
    assert_eq!(b.discovered_nodes[0].observations.len(), 1);
    assert!(Arc::ptr_eq(
        &b.discovered_nodes[0].observations[0].1,
        &second.1
    ));
    assert!(b.next_pending_event().is_none());
    assert_eq!(b.prune_discoveries(second.0 .2), None);
    assert!(b.discovered_nodes.is_empty());
    assert_expired(b.next_pending_event().unwrap(), second.0 .0, &second.0 .1);
}

#[tokio::test]
async fn withdrawn_long_ttl_cannot_extend_a_surviving_short_observation() {
    let (mut b, mut first, mut second) = legacy_observations().await;
    let now = Instant::now();
    first.0 .2 = now + Duration::from_secs(3600);
    second.0 .2 = now + Duration::from_secs(10);
    assert!(b.accept_discovery(first.clone()).is_some());
    assert!(b.accept_discovery(second.clone()).is_none());
    b.on_interface_event(IfEvent::Down("192.0.2.1/24".parse().unwrap()));
    assert_eq!(b.prune_discoveries(now), Some(second.0 .2));
    assert_eq!(b.discovered_nodes[0].observations.len(), 1);
    // Stale queued data cannot restore the removed source or lend its long TTL.
    assert!(b.accept_discovery(first).is_none());
    assert_eq!(b.prune_discoveries(second.0 .2), None);
    assert_expired(b.next_pending_event().unwrap(), second.0 .0, &second.0 .1);
}

#[tokio::test]
async fn expired_tuple_cannot_create_or_refresh_a_cache_entry() {
    let (mut b, mut first, second) = legacy_observations().await;
    first.0 .2 = Instant::now() - Duration::from_secs(1);
    assert!(b.discovery_owner_current(&first.1));
    assert!(b.accept_discovery(first.clone()).is_none());
    assert!(b.discovered_nodes.is_empty());
    assert!(b.accept_discovery(second.clone()).is_some());
    assert!(b.accept_discovery(first).is_none());
    assert_eq!(b.discovered_nodes.len(), 1);
    let observations = &b.discovered_nodes[0].observations;
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].0, second.0 .2);
    assert!(Arc::ptr_eq(&observations[0].1, &second.1));
    assert_eq!(b.prune_discoveries(second.0 .2), None);
    assert_expired(b.next_pending_event().unwrap(), second.0 .0, &second.0 .1);
}

#[tokio::test]
async fn surviving_duplicate_delivers_the_first_pending_announcement() {
    for discovery_already_emitted in [false, true] {
        let (mut b, first, second) = legacy_observations().await;
        let pending = b.accept_discovery(first.clone()).unwrap();
        b.pending_events
            .push_back(PendingEvent::Discovered(vec![pending.clone()]));
        b.pending_events.push_back(PendingEvent::Announce(pending));
        if discovery_already_emitted {
            assert_discovered(b.next_pending_event().unwrap(), first.0 .0, &first.0 .1);
        }
        // B adds an observation without scheduling another public event.
        assert!(b.accept_discovery(second.clone()).is_none());
        b.on_interface_event(IfEvent::Down("192.0.2.1/24".parse().unwrap()));
        b.prune_discoveries(Instant::now());
        assert!(!b.discovery_owner_current(&first.1));
        assert_eq!(b.discovered_nodes[0].observations.len(), 1);
        if !discovery_already_emitted {
            assert_discovered(b.next_pending_event().unwrap(), second.0 .0, &second.0 .1);
        }
        assert_announced(b.next_pending_event().unwrap(), second.0 .0, &second.0 .1);
        assert!(b.next_pending_event().is_none());
    }
}

#[tokio::test]
async fn expired_entry_does_not_reattach_old_pending_events_to_the_same_owner() {
    let (mut b, first, _) = legacy_observations().await;
    let old = b.accept_discovery(first.clone()).unwrap();
    b.pending_events
        .push_back(PendingEvent::Discovered(vec![old.clone()]));
    b.pending_events
        .push_back(PendingEvent::Announce(old.clone()));
    assert_eq!(b.prune_discoveries(first.0 .2), None);
    let mut fresh = first.clone();
    fresh.0 .2 += Duration::from_secs(60);
    let pending = b.accept_discovery(fresh.clone()).unwrap();
    assert!(b.discovery_owner_current(&first.1));
    assert!(!b.announcement_current(&old));
    assert!(b.announcement_current(&pending));
    b.pending_events
        .push_back(PendingEvent::Discovered(vec![pending.clone()]));
    b.pending_events.push_back(PendingEvent::Announce(pending));
    assert_discovered(b.next_pending_event().unwrap(), fresh.0 .0, &fresh.0 .1);
    assert_announced(b.next_pending_event().unwrap(), fresh.0 .0, &fresh.0 .1);
    assert!(b.next_pending_event().is_none());
}

#[tokio::test]
async fn completed_task_observations_keep_no_per_source_owner_history() {
    let mut b = behaviour();
    let source = addr("192.0.2.1");
    b.available_interfaces.insert(source);
    let peer = PeerId::random();
    let mut previous: Option<std::sync::Weak<InterfaceTaskState>> = None;
    let now = Instant::now();
    for generation in 0..32 {
        let owner = b.interface_task_state(source);
        owner.finished.store(true, Ordering::Release);
        let mut observation = discovery(&owner, peer, 60);
        // A replacement observation must not inherit its predecessor's TTL.
        observation.0 .2 = now + Duration::from_secs(60 - generation);
        let expiration = observation.0 .2;
        let pending = b.accept_discovery(observation);
        assert_eq!(pending.is_some(), generation == 0);
        drop(pending);
        assert_eq!(b.discovered_nodes.len(), 1);
        let observations = &b.discovered_nodes[0].observations;
        assert_eq!(observations.len(), 1);
        assert!(!observations.spilled());
        assert_eq!(observations[0].0, expiration);
        assert!(Arc::ptr_eq(&observations[0].1, &owner));
        if let Some(previous) = previous.take() {
            assert!(previous.upgrade().is_none());
        }
        previous = Some(Arc::downgrade(&owner));
    }
    b.on_interface_event(IfEvent::Down("192.0.2.1/24".parse().unwrap()));
    b.prune_discoveries(now);
    assert!(b.discovered_nodes.is_empty());
    assert!(previous.unwrap().upgrade().is_none());
}
