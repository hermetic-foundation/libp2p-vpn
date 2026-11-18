use super::*;
use crate::runtime::physical_network::{
    PhysicalNetworkKind,
    android::{self, Inventory, NetworkRecord, NetworkRoute, SocketBinder},
};
use std::{
    os::fd::BorrowedFd,
    sync::{Condvar, OnceLock, atomic::AtomicU64},
};

// Use only Android's public publication/binder APIs, not its private fixtures.
// That API is process-global, so these model tests serialize their inventories.
static FIXTURE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static BINDER: OnceLock<Arc<Binder>> = OnceLock::new();
static REVISION: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Default)]
struct Binder {
    state: Mutex<SourceState>,
}

#[derive(Debug, Default)]
struct SourceState {
    sources: HashMap<u64, SocketAddr>,
    calls: Vec<u64>,
    error: Option<io::ErrorKind>,
    errors: HashMap<u64, io::ErrorKind>,
    gate: Option<Arc<Gate>>,
}

#[derive(Debug, Default)]
struct Gate {
    started: tokio::sync::Notify,
    finished: tokio::sync::Notify,
    released: Mutex<bool>,
    wake: Condvar,
}

impl Gate {
    async fn entered(&self) {
        tokio::time::timeout(Duration::from_secs(2), self.started.notified())
            .await
            .expect("bounded source lookup entered");
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }

    async fn exited(&self) {
        tokio::time::timeout(Duration::from_secs(2), self.finished.notified())
            .await
            .expect("bounded source lookup exited");
    }
}

impl SocketBinder for Binder {
    fn bind(&self, _: u64, _: BorrowedFd<'_>) -> io::Result<()> {
        panic!("retry ledger must not bind sockets or send packets");
    }

    fn source_for(&self, handle: u64, _: SocketAddr) -> io::Result<SocketAddr> {
        let (source, error, gate) = {
            let mut state = self.state.lock().unwrap();
            state.calls.push(handle);
            (
                state.sources[&handle],
                state.errors.get(&handle).copied().or(state.error),
                state.gate.take(),
            )
        };
        if let Some(gate) = gate {
            gate.started.notify_one();
            let (released, _) = gate
                .wake
                .wait_timeout_while(
                    gate.released.lock().unwrap(),
                    Duration::from_secs(2),
                    |released| !*released,
                )
                .unwrap();
            gate.finished.notify_one();
            if !*released {
                return Err(io::ErrorKind::TimedOut.into());
            }
        }
        match error {
            Some(kind) => Err(kind.into()),
            None => Ok(source),
        }
    }
}

struct Fixture {
    _guard: tokio::sync::MutexGuard<'static, ()>,
    binder: Arc<Binder>,
    owner: Arc<Egress>,
    inventory: Inventory,
}

impl Fixture {
    async fn new() -> Self {
        let guard = FIXTURE_LOCK.lock().await;
        let binder = Arc::clone(BINDER.get_or_init(|| {
            let binder = Arc::new(Binder::default());
            assert!(android::install_socket_binder(binder.clone()));
            binder
        }));
        *binder.state.lock().unwrap() = SourceState::default();
        let mut fixture = Self {
            _guard: guard,
            binder,
            owner: Arc::new(Egress::for_control()),
            inventory: Inventory {
                revision: 0,
                preferred_network: Some(1),
                networks: (1..=3)
                    .map(|handle| NetworkRecord {
                        network_handle: handle,
                        incarnation: handle,
                        revision: 0,
                        kind: PhysicalNetworkKind::Wifi,
                        interface_name: format!("wlan{handle}"),
                        interface_index: handle as u32,
                        validated: true,
                        addresses: [format!("192.0.2.{handle}").parse().unwrap()].into(),
                        dns_servers: Vec::new(),
                        private_dns_active: false,
                        routes: vec![NetworkRoute {
                            destination: "0.0.0.0".parse().unwrap(),
                            prefix_length: 0,
                            gateway: Some("192.0.2.254".parse().unwrap()),
                        }],
                    })
                    .collect(),
            },
        };
        fixture.publish();
        fixture
    }

    fn publish(&mut self) {
        let revision = REVISION.fetch_add(1, Ordering::Relaxed);
        self.inventory.revision = revision;
        for record in &mut self.inventory.networks {
            record.revision = revision;
        }
        self.binder.state.lock().unwrap().sources = self
            .inventory
            .networks
            .iter()
            .map(|record| {
                (
                    record.network_handle,
                    SocketAddr::new(*record.addresses.first().unwrap(), 1234),
                )
            })
            .collect();
        assert!(
            android::publish_inventory(&serde_json::to_string(&self.inventory).unwrap()).unwrap()
        );
    }

    fn model(&self) -> Model {
        Model {
            registry: Registry::default(),
            owner: Arc::clone(&self.owner),
            peer: PeerId::from_bytes([1; 32]),
            local: "0.0.0.0:9876".parse().unwrap(),
            destination: "203.0.113.1:4567".parse().unwrap(),
            mark: 0,
            failed_owner: Some(Arc::new(())),
            preferred_only: false,
            now: Instant::now(),
        }
    }

    fn calls(&self) -> Vec<u64> {
        self.binder.state.lock().unwrap().calls.clone()
    }

    fn block_lookup(&self) -> Arc<Gate> {
        let gate = Arc::new(Gate::default());
        self.binder.state.lock().unwrap().gate = Some(Arc::clone(&gate));
        gate
    }
}

struct Model {
    registry: Registry,
    owner: Arc<Egress>,
    peer: PeerId,
    local: SocketAddr,
    destination: SocketAddr,
    mark: u32,
    failed_owner: Option<Arc<()>>,
    preferred_only: bool,
    now: Instant,
}

impl Model {
    fn admit(&mut self, intent: UdpRecoveryIntent, active: Option<Arc<()>>) -> bool {
        self.registry
            .admit(
                Arc::clone(&self.owner),
                self.peer,
                self.local,
                self.destination,
                self.mark,
                self.failed_owner.clone(),
                self.preferred_only,
                false,
                intent,
                active,
                self.now,
            )
            .unwrap()
    }

    fn retry_at(&self) -> Instant {
        self.registry.peers[&self.peer]
            .entry
            .try_lock()
            .unwrap()
            .retry_at
            .unwrap()
    }

    fn preferred_at(&self) -> Instant {
        self.registry.peers[&self.peer]
            .entry
            .try_lock()
            .unwrap()
            .preferred_at
            .unwrap()
    }

    async fn exhaust(&mut self) -> Candidate {
        let mut last = None;
        for owner in 1..=3 {
            let candidate = self.attach();
            assert_eq!(
                candidate
                    .prepare(&self.owner)
                    .await
                    .unwrap()
                    .route
                    .interface_index,
                owner
            );
            candidate.failed(io::ErrorKind::TimedOut, self.now);
            last = Some(candidate);
        }
        last.unwrap()
    }

    async fn fallback(&mut self) -> (Candidate, RouteLease, Arc<()>) {
        let first = self.attach();
        first.prepare(&self.owner).await.unwrap();
        first.failed(io::ErrorKind::TimedOut, self.now);
        let active = Arc::new(());
        let candidate = self.attach_token(Arc::clone(&active)).unwrap();
        let lease = candidate.prepare(&self.owner).await.unwrap();
        assert_eq!(lease.route.interface_index, 2);
        candidate.confirm(deadline()).await.unwrap();
        self.failed_owner = None;
        (candidate, lease, active)
    }

    fn ready(&mut self, renewal: bool) -> bool {
        self.registry
            .admit(
                Arc::clone(&self.owner),
                self.peer,
                self.local,
                self.destination,
                self.mark,
                self.failed_owner.clone(),
                self.preferred_only,
                renewal,
                UdpRecoveryIntent::Maintenance,
                None,
                self.now,
            )
            .unwrap()
    }

    fn attach(&mut self) -> Candidate {
        self.attach_token(Arc::new(())).unwrap()
    }

    fn attach_token(&mut self, token: Arc<()>) -> io::Result<Candidate> {
        self.registry.attach(
            Arc::clone(&self.owner),
            self.peer,
            self.local,
            self.destination,
            self.mark,
            self.failed_owner.clone(),
            self.preferred_only,
            token,
            self.now,
        )
    }
}

#[tokio::test]
async fn fresh_application_work_rearms_only_after_cooldown_and_fences_old_callbacks() {
    use crate::runtime::lifecycle::activity::ApplicationDemand;
    let fixture = Fixture::new().await;
    let mut model = fixture.model();
    let demand = ApplicationDemand::new([model.peer], model.now);
    demand.record(model.peer, model.now);
    let original = UdpRecoveryIntent::application(demand.snapshot(model.peer));
    assert!(model.admit(original, None));
    let old = model.exhaust().await;
    let at = model.retry_at();
    assert_eq!(at - model.now, Duration::from_secs(30));
    demand.record(model.peer, model.now);
    let work = UdpRecoveryIntent::application(demand.snapshot(model.peer));
    assert!(!model.admit(work, None));
    model.now = at;
    assert!(
        !model.admit(original, None),
        "consumed demand cannot rearm work"
    );
    assert!(!model.admit(UdpRecoveryIntent::Maintenance, None));
    assert!(model.admit(work, None));
    let current = model.attach();
    assert_eq!(
        current
            .prepare(&model.owner)
            .await
            .unwrap()
            .route
            .interface_index,
        1
    );
    old.failed(io::ErrorKind::TimedOut, model.now);
    assert!(current.is_current());
    assert!(old.confirm(deadline()).await.is_err());
    demand.record(model.peer, model.now);
    assert!(
        !model.admit(
            UdpRecoveryIntent::application(demand.snapshot(model.peer)),
            None
        ),
        "new packets do not reset in-flight operations"
    );
    assert_eq!(fixture.calls(), [1, 2, 3, 1]);
}

#[tokio::test]
async fn only_new_authenticated_control_work_can_restart_an_exhausted_operation() {
    let fixture = Fixture::new().await;
    let mut model = fixture.model();
    model.exhaust().await;
    let received = model.now;
    assert!(!model.admit(UdpRecoveryIntent::AuthenticatedControl(received), None));
    model.now = model.retry_at();
    assert!(
        !model.admit(UdpRecoveryIntent::AuthenticatedControl(received), None),
        "deferred old delivery is not fresh control work"
    );
    assert!(model.admit(UdpRecoveryIntent::AuthenticatedControl(model.now), None));
    let current = model.attach();
    let lease = current.prepare(&model.owner).await.unwrap();
    let ticket = current.state.delivered.lock().unwrap().clone().unwrap();
    for _ in 0..4 {
        assert!(model.admit(UdpRecoveryIntent::AuthenticatedControl(model.now), None));
        let repeated = model.attach();
        assert_eq!(
            repeated.prepare(&model.owner).await.unwrap().context,
            lease.context
        );
        assert!(ticket.same_attempt(repeated.state.delivered.lock().unwrap().as_ref().unwrap()));
    }
    assert_eq!(fixture.calls(), [1, 2, 3, 1]);
}

#[tokio::test]
async fn preferred_validation_uses_an_independent_ticket_and_exact_active_anchor() {
    use crate::runtime::lifecycle::activity::ApplicationDemand;
    let fixture = Fixture::new().await;
    let mut model = fixture.model();
    let (old, fallback, active) = model.fallback().await;
    let demand = ApplicationDemand::new([model.peer], model.now);
    model.now = model.preferred_at();
    demand.record(model.peer, model.now);
    let work = UdpRecoveryIntent::application(demand.snapshot(model.peer));
    assert!(
        !model
            .registry
            .preferred_due(model.peer, None, work, model.now)
    );
    assert!(
        !model
            .registry
            .preferred_due(model.peer, Some(&Arc::new(())), work, model.now)
    );
    assert!(!model.registry.preferred_due(
        model.peer,
        Some(&active),
        UdpRecoveryIntent::Maintenance,
        model.now
    ));
    assert!(
        !model.registry.preferred_due(
            model.peer,
            Some(&active),
            UdpRecoveryIntent::AuthenticatedControl(model.now - Duration::from_secs(1)),
            model.now
        ),
        "a deferred pre-deadline control receipt cannot start preferred validation"
    );
    assert!(
        model
            .registry
            .preferred_due(model.peer, Some(&active), work, model.now)
    );
    assert!(model.admit(work, Some(Arc::clone(&active))));
    assert!(
        fallback.is_available(),
        "new validation cannot revoke the fallback lease"
    );
    assert!(!old.is_current());
    let preferred = model.attach();
    let lease = preferred.prepare(&model.owner).await.unwrap();
    assert_eq!(lease.route.interface_index, 1);
    assert!(preferred.entry.lock().await.preferred_only);
    assert!(old.confirm(deadline()).await.is_err());
    let promoted = AtomicBool::new(false);
    preferred
        .confirm_with(deadline(), || {
            assert!(!promoted.swap(true, Ordering::AcqRel))
        })
        .await
        .unwrap();
    assert!(promoted.load(Ordering::Acquire));
    assert!(!model.registry.preferred_due(
        model.peer,
        Some(&active),
        work,
        model.now + Duration::from_secs(600)
    ));
    assert_eq!(fixture.calls(), [1, 2, 1]);
}

#[tokio::test]
async fn failed_preferred_validation_retries_without_epoch_change_and_never_selects_an_alternate() {
    use crate::runtime::lifecycle::activity::ApplicationDemand;
    let fixture = Fixture::new().await;
    let mut model = fixture.model();
    let (_, fallback, active) = model.fallback().await;
    let epoch = model.owner.current_epoch().unwrap();
    let demand = ApplicationDemand::new([model.peer], model.now);
    model.now = model.preferred_at();
    demand.record(model.peer, model.now);
    assert!(model.admit(
        UdpRecoveryIntent::application(demand.snapshot(model.peer)),
        Some(Arc::clone(&active))
    ));
    let first = model.attach();
    first.prepare(&model.owner).await.unwrap();
    first.failed(io::ErrorKind::TimedOut, model.now);
    assert!(!model.registry.pending(model.peer));
    assert!(!model.ready(false));
    assert!(fallback.is_available());
    let at = model.retry_at();
    assert_eq!(at - model.now, Duration::from_secs(60));
    model.now = at;
    assert!(!model.admit(UdpRecoveryIntent::Maintenance, Some(Arc::clone(&active))));
    demand.record(model.peer, model.now);
    let work = UdpRecoveryIntent::application(demand.snapshot(model.peer));
    assert!(
        !model.admit(work, Some(Arc::new(()))),
        "replacement active owners cannot borrow an old preferred intent"
    );
    assert!(model.admit(work, Some(Arc::clone(&active))));
    let retry = model.attach();
    assert_eq!(
        retry
            .prepare(&model.owner)
            .await
            .unwrap()
            .route
            .interface_index,
        1
    );
    retry.confirm(deadline()).await.unwrap();
    assert_eq!(model.owner.current_epoch().unwrap(), epoch);
    assert!(fallback.is_available());
    assert_eq!(fixture.calls(), [1, 2, 1, 1]);
}

#[tokio::test]
async fn unproven_lookup_failure_restarts_at_preference_only_for_new_bounded_work() {
    use crate::runtime::lifecycle::activity::ApplicationDemand;
    let fixture = Fixture::new().await;
    let mut model = fixture.model();
    let demand = ApplicationDemand::new([model.peer], model.now);
    demand.record(model.peer, model.now);
    assert!(model.admit(
        UdpRecoveryIntent::application(demand.snapshot(model.peer)),
        None
    ));
    fixture.binder.state.lock().unwrap().error = Some(io::ErrorKind::PermissionDenied);
    let old = model.attach();
    let error = old.prepare(&model.owner).await.unwrap_err();
    old.failed(error.kind(), model.now);
    model.now = model.retry_at();
    assert!(!model.admit(UdpRecoveryIntent::Maintenance, None));
    demand.record(model.peer, model.now);
    fixture.binder.state.lock().unwrap().error = None;
    assert!(model.admit(
        UdpRecoveryIntent::application(demand.snapshot(model.peer)),
        None
    ));
    assert_eq!(
        model
            .attach()
            .prepare(&model.owner)
            .await
            .unwrap()
            .route
            .interface_index,
        1
    );
    assert_eq!(
        fixture.calls(),
        [1, 1],
        "an unknown failed owner never licenses an alternate"
    );
}

#[tokio::test]
async fn preferred_validation_rejects_a_first_success_that_skipped_the_preferred_network() {
    use crate::runtime::lifecycle::activity::ApplicationDemand;
    let fixture = Fixture::new().await;
    let mut model = fixture.model();
    let (_, fallback, active) = model.fallback().await;
    let demand = ApplicationDemand::new([model.peer], model.now);
    model.now = model.preferred_at();
    demand.record(model.peer, model.now);
    fixture
        .binder
        .state
        .lock()
        .unwrap()
        .errors
        .insert(1, io::ErrorKind::NetworkUnreachable);
    assert!(model.admit(
        UdpRecoveryIntent::application(demand.snapshot(model.peer)),
        Some(active)
    ));
    let candidate = model.attach();
    let error = candidate.prepare(&model.owner).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NetworkUnreachable);
    assert!(
        candidate.state.delivered.lock().unwrap().is_none(),
        "a fallback is not delivered to the preferred-only socket factory"
    );
    candidate.failed(error.kind(), model.now);
    assert!(!model.registry.pending(model.peer));
    assert!(fallback.is_available());
    assert_eq!(fixture.calls(), [1, 2, 1, 2]);
}

#[tokio::test]
async fn epoch_triggered_preferred_probe_retains_its_fallback_anchor_after_first_failure() {
    use crate::runtime::lifecycle::activity::ApplicationDemand;
    let mut fixture = Fixture::new().await;
    let mut model = fixture.model();
    let (_, fallback, active) = model.fallback().await;
    fixture.publish();
    model.preferred_only = true;
    let epoch = model.owner.current_epoch().unwrap();
    assert!(model.admit(UdpRecoveryIntent::Maintenance, Some(Arc::clone(&active))));
    let first = model.attach();
    assert_eq!(
        first
            .prepare(&model.owner)
            .await
            .unwrap()
            .route
            .interface_index,
        1
    );
    first.failed(io::ErrorKind::TimedOut, model.now);
    model.now = model.preferred_at();
    let demand = ApplicationDemand::new([model.peer], model.now);
    demand.record(model.peer, model.now);
    let work = UdpRecoveryIntent::application(demand.snapshot(model.peer));
    assert!(fallback.is_available());
    assert!(
        model
            .registry
            .preferred_due(model.peer, Some(&active), work, model.now)
    );
    assert!(model.admit(work, Some(active)));
    let retry = model.attach();
    assert_eq!(
        retry
            .prepare(&model.owner)
            .await
            .unwrap()
            .route
            .interface_index,
        1
    );
    retry.confirm(deadline()).await.unwrap();
    assert_eq!(model.owner.current_epoch().unwrap(), epoch);
    assert_eq!(fixture.calls(), [1, 2, 1, 1]);
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[tokio::test]
async fn ack_timeouts_visit_three_owners_and_hellos_or_ticks_never_reset_exhaustion() {
    let fixture = Fixture::new().await;
    let mut model = fixture.model();
    assert!(model.ready(false));
    assert!(!model.registry.pending(model.peer));
    for owner in 1..=3 {
        let candidate = model.attach();
        assert!(!model.registry.pending(model.peer));
        let lease = candidate.prepare(&model.owner).await.unwrap();
        assert_eq!(lease.route.interface_index, owner);
        for _ in 0..3 {
            model.now += Duration::from_secs(1);
            assert!(!model.ready(false));
            let hello = model.attach();
            assert!(!candidate.is_current());
            assert_eq!(
                hello.prepare(&model.owner).await.unwrap().context,
                lease.context
            );
        }
        let current = model.attach();
        current.prepare(&model.owner).await.unwrap();
        current.failed(io::ErrorKind::TimedOut, model.now);
        assert_eq!(model.registry.pending(model.peer), owner < 3);
        assert_eq!(model.ready(false), owner < 3);
    }
    for _ in 0..4 {
        assert_eq!(
            model.attach_token(Arc::new(())).unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        assert!(!model.ready(true));
        model.now += Duration::from_secs(60);
    }
    assert_eq!(fixture.calls(), vec![1, 2, 3]);
}

#[tokio::test]
async fn transcript_supersession_reuses_exact_ticket_and_fences_old_callbacks() {
    let fixture = Fixture::new().await;
    let mut model = fixture.model();
    let old = model.attach();
    let lease = old.prepare(&model.owner).await.unwrap();
    let old_ticket = old.state.delivered.lock().unwrap().clone().unwrap();
    let next = model.attach();
    assert!(!old.is_current());
    assert!(next.is_current());
    assert!(
        next.confirm(deadline()).await.is_err(),
        "must first deliver its lease"
    );
    assert_eq!(
        next.prepare(&model.owner).await.unwrap().context,
        lease.context
    );
    let new_ticket = next.state.delivered.lock().unwrap().clone().unwrap();
    assert!(old_ticket.same_attempt(&new_ticket));
    old.failed(io::ErrorKind::TimedOut, model.now);
    old.failed(io::ErrorKind::PermissionDenied, model.now);
    assert!(old.confirm(deadline()).await.is_err());
    assert!(next.is_current());
    next.confirm(deadline()).await.unwrap();
    assert!(next.entry.lock().await.established);
    assert_eq!(fixture.calls(), vec![1]);
    assert!(!model.registry.pending(model.peer));
}

#[tokio::test]
async fn preferred_only_failure_cannot_advance_even_if_later_hellos_allow_recovery() {
    let fixture = Fixture::new().await;
    let mut model = fixture.model();
    model.preferred_only = true;
    let first = model.attach();
    first.prepare(&model.owner).await.unwrap();
    model.preferred_only = false;
    assert!(!model.ready(false));
    let repeated_hello = model.attach();
    repeated_hello.prepare(&model.owner).await.unwrap();
    assert!(repeated_hello.entry.lock().await.preferred_only);
    first.failed(io::ErrorKind::TimedOut, model.now);
    repeated_hello.failed(io::ErrorKind::TimedOut, model.now);
    assert!(!model.ready(false));
    assert!(!model.registry.pending(model.peer));
    assert!(!model.ready(false));
    assert!(model.attach_token(Arc::new(())).is_err());
    assert_eq!(fixture.calls(), vec![1]);

    model.failed_owner = Some(Arc::new(()));
    assert!(model.ready(false));
    let fresh_operation = model.attach();
    fresh_operation.prepare(&model.owner).await.unwrap();
    assert!(!fresh_operation.entry.lock().await.preferred_only);
    fresh_operation.failed(io::ErrorKind::TimedOut, model.now);
    model.preferred_only = true;
    assert!(model.ready(false));
    let alternate = model.attach();
    assert_eq!(
        alternate
            .prepare(&model.owner)
            .await
            .unwrap()
            .route
            .interface_index,
        2
    );
    assert_eq!(fixture.calls(), vec![1, 1, 2]);
}

#[tokio::test]
async fn only_a_new_failed_active_owner_starts_a_new_operation() {
    let fixture = Fixture::new().await;
    let mut model = fixture.model();
    let first = model.attach();
    first.prepare(&model.owner).await.unwrap();
    first.failed(io::ErrorKind::TimedOut, model.now);
    let saved_failure = model.failed_owner.clone();
    model.failed_owner = None;
    assert!(model.ready(false));
    let second = model.attach();
    assert_eq!(
        second
            .prepare(&model.owner)
            .await
            .unwrap()
            .route
            .interface_index,
        2
    );
    assert!(Arc::ptr_eq(
        model.registry.peers[&model.peer]
            .failed_owner
            .as_ref()
            .unwrap(),
        saved_failure.as_ref().unwrap()
    ));
    model.failed_owner = saved_failure;
    assert!(!model.ready(false));
    assert!(second.is_current());
    model.failed_owner = Some(Arc::new(()));
    assert!(model.ready(false));
    assert!(!second.valid.load(Ordering::Acquire));
    assert_eq!(
        model
            .attach()
            .prepare(&model.owner)
            .await
            .unwrap()
            .route
            .interface_index,
        1
    );
    assert_eq!(fixture.calls(), vec![1, 2, 1]);
}

#[tokio::test]
async fn canonical_context_is_stable_but_local_destination_and_mark_changes_invalidate() {
    let fixture = Fixture::new().await;
    let mut model = fixture.model();
    let mut old = model.attach();
    old.prepare(&model.owner).await.unwrap();
    model.local = "[::ffff:0.0.0.0]:9876".parse().unwrap();
    model.destination = "[::ffff:203.0.113.1]:4567".parse().unwrap();
    assert!(!model.ready(false));
    assert!(old.is_current());
    for change in 0..3 {
        match change {
            0 => model.local.set_port(9877),
            1 => model.destination.set_port(4568),
            _ => model.mark = 42,
        }
        assert!(model.ready(false));
        assert!(!old.is_current());
        assert!(!old.valid.load(Ordering::Acquire));
        assert!(old.prepare(&model.owner).await.is_err());
        assert!(old.confirm(deadline()).await.is_err());
        old = model.attach();
        old.prepare(&model.owner).await.unwrap();
    }
    assert_eq!(fixture.calls(), vec![1, 1, 1, 1]);
}

#[tokio::test]
async fn source_epoch_refresh_prunes_all_stale_peers_and_fences_archived_rx() {
    let mut fixture = Fixture::new().await;
    let mut model = fixture.model();
    let first = model.attach();
    first.prepare(&model.owner).await.unwrap();
    let peer = model.peer;
    model.peer = PeerId::from_bytes([2; 32]);
    let second = model.attach();
    second.prepare(&model.owner).await.unwrap();
    fixture.inventory.networks[0].addresses = ["192.0.2.111".parse().unwrap()].into();
    fixture.publish();
    assert!(!first.is_current());
    assert!(!second.is_current());
    assert!(!model.registry.pending(peer));
    assert!(first.confirm(deadline()).await.is_err());
    assert!(model.ready(false));
    assert_eq!(model.registry.peers.len(), 1);
    assert!(!first.valid.load(Ordering::Acquire));
    assert!(!second.valid.load(Ordering::Acquire));
    let fresh = model.attach();
    assert_eq!(
        fresh
            .prepare(&model.owner)
            .await
            .unwrap()
            .local_addr
            .ip()
            .to_string(),
        "192.0.2.111"
    );
}

#[tokio::test]
async fn forget_clear_drop_and_replacement_invalidate_without_entry_lock_or_cycles() {
    let fixture = Fixture::new().await;
    let mut model = fixture.model();
    for action in 0..4 {
        let candidate = model.attach();
        candidate.prepare(&model.owner).await.unwrap();
        let weak_entry = Arc::downgrade(&candidate.entry);
        let weak_state = Arc::downgrade(&candidate.state);
        let guard = candidate.entry.lock().await;
        match action {
            0 => model.registry.forget(model.peer),
            1 => model.registry.clear(),
            2 => drop(std::mem::take(&mut model.registry)),
            _ => {
                model.destination.set_port(9999);
                assert!(model.ready(false));
            }
        }
        assert!(!candidate.valid.load(Ordering::Acquire));
        assert!(!candidate.is_current());
        drop(guard);
        assert!(candidate.prepare(&model.owner).await.is_err());
        drop(candidate);
        assert!(weak_entry.upgrade().is_none());
        assert!(weak_state.upgrade().is_none());
    }
}

#[tokio::test]
async fn renewal_keeps_the_established_ticket_and_cooldown_without_resetting_cursor() {
    let fixture = Fixture::new().await;
    let mut model = fixture.model();
    let first = model.attach();
    first.prepare(&model.owner).await.unwrap();
    first.failed(io::ErrorKind::TimedOut, model.now);
    let established = model.attach();
    let lease = established.prepare(&model.owner).await.unwrap();
    assert_eq!(lease.route.interface_index, 2);
    established.confirm(deadline()).await.unwrap();
    let ticket = established.state.delivered.lock().unwrap().clone().unwrap();
    model.failed_owner = None;
    assert!(!model.ready(false));
    assert!(model.ready(true));
    let renewal = model.attach();
    assert!(!established.is_current());
    assert_eq!(
        renewal.prepare(&model.owner).await.unwrap().context,
        lease.context
    );
    assert!(ticket.same_attempt(renewal.state.delivered.lock().unwrap().as_ref().unwrap()));
    assert!(!model.ready(true));
    renewal.failed(io::ErrorKind::TimedOut, model.now);
    assert!(!model.registry.pending(model.peer));
    assert!(!model.ready(true));
    assert_eq!(
        model.attach_token(Arc::new(())).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    model.now += RENEWAL_COOLDOWN - Duration::from_nanos(1);
    assert!(!model.ready(true));
    model.now += Duration::from_nanos(1);
    assert!(model.ready(true));
    let fresh_key = model.attach();
    assert_eq!(
        fresh_key.prepare(&model.owner).await.unwrap().context,
        lease.context
    );
    fresh_key.confirm(deadline()).await.unwrap();
    assert!(fresh_key.entry.lock().await.established);
    assert!(!fresh_key.entry.lock().await.cursor.can_prepare());
    renewal.failed(io::ErrorKind::TimedOut, model.now);
    assert!(fresh_key.is_current());
    assert!(model.ready(true));
    assert_eq!(fixture.calls(), vec![1, 2]);
}

#[tokio::test]
async fn bounded_map_rejects_new_peers_without_evicting_live_or_exhausted_operations() {
    let fixture = Fixture::new().await;
    let mut model = fixture.model();
    assert_eq!(model.registry.limit, 4096);
    model.registry.limit = 2;
    let first = model.attach();
    model.peer = PeerId::from_bytes([2; 32]);
    let second = model.attach();
    second.prepare(&model.owner).await.unwrap();
    second.failed(io::ErrorKind::PermissionDenied, model.now);
    model.peer = PeerId::from_bytes([3; 32]);
    assert_eq!(
        model.attach_token(Arc::new(())).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(first.is_current());
    assert_eq!(model.registry.peers.len(), 2);
    model.registry.forget(PeerId::from_bytes([1; 32]));
    assert!(model.ready(false));
    assert_eq!(model.registry.peers.len(), 2);
    assert!(!first.is_current());
    model.peer = PeerId::from_bytes([2; 32]);
    assert!(!model.ready(false));
}

#[tokio::test]
async fn deferred_failure_during_initial_or_alternate_lookup_is_not_lost() {
    let fixture = Fixture::new().await;
    for initial in [true, false] {
        let mut model = fixture.model();
        if !initial {
            let first = model.attach();
            first.prepare(&model.owner).await.unwrap();
            first.failed(io::ErrorKind::TimedOut, model.now);
        }
        let candidate = model.attach();
        let gate = fixture.block_lookup();
        let task_candidate = candidate.clone();
        let owner = Arc::clone(&model.owner);
        let lookup = tokio::spawn(async move { task_candidate.prepare(&owner).await });
        gate.entered().await;
        candidate.failed(io::ErrorKind::TimedOut, model.now);
        assert!(!candidate.is_current());
        assert!(!model.ready(false));
        assert!(!model.registry.pending(model.peer));
        let state = Arc::downgrade(&candidate.state);
        drop(candidate);
        gate.release();
        assert!(lookup.await.unwrap().is_err());
        assert!(
            state.upgrade().is_none(),
            "entry consumed its strong failure marker"
        );
        assert!(model.registry.pending(model.peer));
        assert!(model.ready(false));
        let alternate = model.attach();
        assert_eq!(
            alternate
                .prepare(&model.owner)
                .await
                .unwrap()
                .route
                .interface_index,
            if initial { 2 } else { 3 }
        );
    }
    assert_eq!(fixture.calls(), vec![1, 2, 1, 2, 3]);
}

#[tokio::test]
async fn deferred_first_failure_wins_and_ready_attach_pending_each_resolve_it() {
    let fixture = Fixture::new().await;
    for resolver in 0..3 {
        let mut model = fixture.model();
        let candidate = model.attach();
        candidate.prepare(&model.owner).await.unwrap();
        let guard = candidate.entry.lock().await;
        candidate.failed(io::ErrorKind::PermissionDenied, model.now);
        candidate.failed(io::ErrorKind::TimedOut, model.now + Duration::from_secs(1));
        assert_eq!(
            candidate.state.failure.lock().unwrap().unwrap().0,
            io::ErrorKind::PermissionDenied
        );
        drop(guard);
        match resolver {
            0 => assert!(!model.ready(false)),
            1 => assert!(model.attach_token(Arc::new(())).is_err()),
            _ => assert!(!model.registry.pending(model.peer)),
        }
        assert!(candidate.entry.lock().await.current_candidate.is_none());
        assert!(!model.ready(false));
    }
    assert_eq!(fixture.calls(), vec![1, 1, 1]);
}

#[tokio::test]
async fn deferred_failure_survives_dropping_all_external_candidate_handles() {
    let fixture = Fixture::new().await;
    let mut model = fixture.model();
    let candidate = model.attach();
    candidate.prepare(&model.owner).await.unwrap();
    let entry = Arc::clone(&candidate.entry);
    let guard = entry.lock().await;
    candidate.failed(io::ErrorKind::TimedOut, model.now);
    let state = Arc::downgrade(&candidate.state);
    drop(candidate);
    assert!(state.upgrade().is_some(), "Entry owns the deferred marker");
    drop(guard);
    assert!(model.registry.pending(model.peer));
    assert!(state.upgrade().is_none());
    assert_eq!(
        model
            .attach()
            .prepare(&model.owner)
            .await
            .unwrap()
            .route
            .interface_index,
        2
    );
}

#[tokio::test]
async fn unknown_lookup_failure_and_cancelled_preparation_cannot_guess_an_alternate() {
    let fixture = Fixture::new().await;
    let mut unknown = fixture.model();
    fixture.binder.state.lock().unwrap().error = Some(io::ErrorKind::PermissionDenied);
    let candidate = unknown.attach();
    assert_eq!(
        candidate.prepare(&unknown.owner).await.unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    candidate.failed(io::ErrorKind::TimedOut, unknown.now);
    assert!(!unknown.ready(false));
    assert!(!unknown.registry.pending(unknown.peer));
    assert!(unknown.attach_token(Arc::new(())).is_err());
    fixture.binder.state.lock().unwrap().error = None;

    let mut cancelled = fixture.model();
    let candidate = cancelled.attach();
    let gate = fixture.block_lookup();
    let copy = candidate.clone();
    let owner = Arc::clone(&cancelled.owner);
    let lookup = tokio::spawn(async move { copy.prepare(&owner).await });
    gate.entered().await;
    lookup.abort();
    assert!(lookup.await.unwrap_err().is_cancelled());
    candidate.failed(io::ErrorKind::TimedOut, cancelled.now);
    assert!(!cancelled.ready(false));
    assert!(!cancelled.registry.pending(cancelled.peer));
    assert!(cancelled.attach_token(Arc::new(())).is_err());
    gate.release();
    gate.exited().await;
    assert_eq!(fixture.calls(), vec![1, 1]);
}

#[tokio::test]
async fn confirmation_checks_deadline_after_waiting_for_entry_lock() {
    let fixture = Fixture::new().await;
    let mut model = fixture.model();
    let candidate = model.attach();
    candidate.prepare(&model.owner).await.unwrap();
    let guard = candidate.entry.lock().await;
    let deadline = Instant::now() + Duration::from_millis(10);
    let promoted = AtomicBool::new(false);
    let proof = candidate.confirm_with(deadline, || promoted.store(true, Ordering::Release));
    tokio::pin!(proof);
    assert!(futures::poll!(&mut proof).is_pending());
    tokio::time::sleep(Duration::from_millis(15)).await;
    drop(guard);
    assert_eq!(proof.await.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert!(!promoted.load(Ordering::Acquire));
    assert!(!candidate.entry.lock().await.established);
    assert!(!candidate.state.confirmed.load(Ordering::Acquire));
    assert!(!candidate.entry.lock().await.cursor.can_prepare());
    candidate.failed(io::ErrorKind::TimedOut, model.now);
    assert!(model.registry.pending(model.peer));
}

#[tokio::test]
async fn promotion_callback_is_exactly_once_and_runs_before_established_commit() {
    let fixture = Fixture::new().await;
    let mut model = fixture.model();
    let candidate = model.attach();
    candidate.prepare(&model.owner).await.unwrap();
    let calls = AtomicU64::new(0);
    assert_eq!(
        candidate
            .confirm_with(Instant::now(), || {
                calls.fetch_add(1, Ordering::Relaxed);
            })
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert!(!candidate.entry.lock().await.established);
    assert!(!candidate.state.confirmed.load(Ordering::Acquire));
    candidate
        .confirm_with(deadline(), || {
            assert!(candidate.entry.try_lock().is_err());
            assert!(candidate.state.failure.try_lock().is_err());
            assert!(!candidate.state.confirmed.load(Ordering::Acquire));
            calls.fetch_add(1, Ordering::Relaxed);
        })
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert!(candidate.entry.lock().await.established);
    assert!(candidate.state.confirmed.load(Ordering::Acquire));
    candidate
        .confirm_with(deadline(), || {
            calls.fetch_add(1, Ordering::Relaxed);
        })
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn superseded_and_failed_candidates_cannot_run_promotion_callbacks() {
    let fixture = Fixture::new().await;
    let mut model = fixture.model();
    let old = model.attach();
    old.prepare(&model.owner).await.unwrap();
    let current = model.attach();
    current.prepare(&model.owner).await.unwrap();
    let calls = AtomicU64::new(0);
    assert!(
        old.confirm_with(deadline(), || {
            calls.fetch_add(1, Ordering::Relaxed);
        })
        .await
        .is_err()
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert!(!current.entry.lock().await.established);
    current.failed(io::ErrorKind::PermissionDenied, model.now);
    assert!(
        current
            .confirm_with(deadline(), || {
                calls.fetch_add(1, Ordering::Relaxed);
            })
            .await
            .is_err()
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert!(!current.entry.lock().await.established);
}
