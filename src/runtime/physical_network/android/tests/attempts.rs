//! Host-only async operation models, not Android socket or device proof.

use super::super::egress::NetworkAttempts;
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn local() -> SocketAddr {
    "0.0.0.0:42000".parse().unwrap()
}

fn remote() -> SocketAddr {
    "203.0.113.9:443".parse().unwrap()
}

#[tokio::test]
async fn public_discovery_uses_only_default_and_rejects_a_stale_or_absent_default() {
    let (state, _, owner) = owner();
    let mut next = inventory(2, Some(1));
    next.networks[0] = record(1, 1, "2001:db8::1");
    next.networks[0].revision = 2;
    // Make the nondefault Network win ordinary local-route selection and be
    // the only Network that can supply the destination's source family.
    next.networks[1].routes.push(NetworkRoute {
        destination: "203.0.113.0".parse().unwrap(),
        prefix_length: 24,
        gateway: None,
    });
    next.networks[1].revision = 2;
    state.publish(next.clone()).unwrap();
    let epoch = owner.current_epoch().unwrap();
    assert_eq!(
        owner
            .prepare_shared_datagram(local(), remote(), 0)
            .await
            .unwrap()
            .network_handle,
        2
    );
    assert_eq!(
        owner
            .prepare_public_route(&epoch, local(), remote(), SocketProtocol::Udp, 0)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::NetworkUnreachable,
    );
    next.revision = 3;
    next.preferred_network = Some(2);
    state.publish(next.clone()).unwrap();
    assert_eq!(
        owner
            .prepare_public_route(&epoch, local(), remote(), SocketProtocol::Tcp, 0)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted,
    );
    let new_epoch = owner.current_epoch().unwrap();
    assert_eq!(
        owner
            .prepare_public_route(&new_epoch, local(), remote(), SocketProtocol::Tcp, 0)
            .await
            .unwrap()
            .network_handle,
        2
    );
    next.revision = 4;
    next.preferred_network = None;
    state.publish(next).unwrap();
    let absent = owner.current_epoch().unwrap();
    assert_eq!(
        owner
            .prepare_public_route(&absent, local(), remote(), SocketProtocol::Tcp, 0)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::NetworkUnreachable,
    );
}

#[tokio::test]
async fn cancelled_socket_preparations_share_lookup_capacity_until_backend_exit() {
    struct Gate {
        entered: AtomicUsize,
        exited: AtomicUsize,
        released: Mutex<bool>,
        ready: std::sync::Condvar,
    }
    struct Release(Arc<Gate>);
    impl Drop for Release {
        fn drop(&mut self) {
            *self.0.released.lock().unwrap() = true;
            self.0.ready.notify_all();
        }
    }
    let (_, _, owner) = owner();
    let owner = Arc::new(owner);
    let gate = Arc::new(Gate {
        entered: AtomicUsize::new(0),
        exited: AtomicUsize::new(0),
        released: Mutex::new(false),
        ready: std::sync::Condvar::new(),
    });
    let release = Release(Arc::clone(&gate));
    let jobs = (0..egress::MAX_PREPARATIONS)
        .map(|_| {
            let owner = Arc::clone(&owner);
            let gate = Arc::clone(&gate);
            tokio::spawn(async move {
                owner
                    .prepare_io(move || {
                        gate.entered.fetch_add(1, Ordering::SeqCst);
                        let mut released = gate.released.lock().unwrap();
                        while !*released {
                            released = gate.ready.wait(released).unwrap();
                        }
                        gate.exited.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })
                    .await
            })
        })
        .collect::<Vec<_>>();
    tokio::time::timeout(Duration::from_secs(2), async {
        while gate.entered.load(Ordering::SeqCst) != egress::MAX_PREPARATIONS {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    for job in jobs {
        job.abort();
        assert!(job.await.unwrap_err().is_cancelled());
    }
    assert_eq!(
        owner
            .prepare_shared_datagram(local(), remote(), 0)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    drop(release);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if gate.exited.load(Ordering::SeqCst) == egress::MAX_PREPARATIONS
                && owner
                    .prepare_shared_datagram(local(), remote(), 0)
                    .await
                    .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn resumable_ack_silence_consumes_three_distinct_owners_without_resetting() {
    let (state, _, owner) = owner();
    let mut next = inventory(2, Some(1));
    next.networks = (1..=4)
        .map(|handle| record(handle, handle, &format!("192.0.2.{handle}")))
        .collect();
    next.networks[1] = record(2, 2, "198.51.100.1");
    state.publish(next).unwrap();
    let mut attempts =
        NetworkAttempts::new(&owner, local(), remote(), SocketProtocol::Udp, 17).unwrap();
    for handle in 1..=3 {
        let attempt = attempts.prepare(&owner, || true).await.unwrap();
        assert_eq!(attempt.lease().network_handle, handle);
        assert_eq!(attempt.number(), handle as usize);
        assert_eq!(attempt.is_preferred(), handle == 1);
        assert_eq!(attempt.lease().context.protocol, SocketProtocol::Udp);
        assert_eq!(attempt.lease().context.mark, 17);
        assert_eq!(attempt.lease().local_addr.port(), local().port());
        assert_eq!(attempt.lease().context.destination, remote());
        assert_eq!(
            attempts.prepare(&owner, || true).await.unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "an unanswered candidate must not start another route under the same keys"
        );
        tokio::task::yield_now().await;
        assert_eq!(
            attempts
                .failed(&attempt, io::ErrorKind::TimedOut, true)
                .unwrap(),
            handle < 3
        );
        assert_eq!(
            state.state.read().unwrap().inventory.preferred_network,
            Some(1)
        );
    }
    for _ in 0..3 {
        assert_eq!(
            attempts.prepare(&owner, || true).await.unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
    }
}

#[tokio::test]
async fn resumable_completion_is_exact_and_does_not_admit_late_or_foreign_proof() {
    let (_, _, owner) = owner();
    let mut attempts =
        NetworkAttempts::new(&owner, local(), remote(), SocketProtocol::Udp, 0).unwrap();
    let first = attempts.prepare(&owner, || true).await.unwrap();
    assert!(
        attempts
            .failed(&first, io::ErrorKind::TimedOut, true)
            .unwrap()
    );
    let second = attempts.prepare(&owner, || true).await.unwrap();
    assert_eq!(
        attempts.confirm(&first, true).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(
        attempts
            .failed(&first, io::ErrorKind::TimedOut, true)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
    let mut sibling =
        NetworkAttempts::new(&owner, local(), remote(), SocketProtocol::Udp, 0).unwrap();
    let foreign = sibling.prepare(&owner, || true).await.unwrap();
    assert_eq!(
        attempts.confirm(&foreign, true).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    attempts.confirm(&second, true).unwrap();
    assert_eq!(
        attempts.confirm(&second, true).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(
        attempts.prepare(&owner, || true).await.unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
}

#[tokio::test]
async fn resumable_policy_withdrawal_and_non_connectivity_errors_do_not_advance() {
    for kind in [
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::InvalidData,
        io::ErrorKind::Interrupted,
        io::ErrorKind::WouldBlock,
    ] {
        let (_, _, owner) = owner();
        let mut attempts =
            NetworkAttempts::new(&owner, local(), remote(), SocketProtocol::Udp, 0).unwrap();
        let attempt = attempts.prepare(&owner, || false).await.unwrap();
        assert!(!attempts.failed(&attempt, kind, true).unwrap());
        assert!(attempts.prepare(&owner, || true).await.is_err());
    }
    let (_, _, owner) = owner();
    let mut attempts =
        NetworkAttempts::new(&owner, local(), remote(), SocketProtocol::Udp, 0).unwrap();
    let first = attempts.prepare(&owner, || false).await.unwrap();
    assert!(
        attempts
            .failed(&first, io::ErrorKind::TimedOut, true)
            .unwrap()
    );
    let second = attempts.prepare(&owner, || true).await.unwrap();
    assert_eq!(
        attempts.confirm(&second, false).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert!(attempts.prepare(&owner, || true).await.is_err());
}

#[tokio::test]
async fn resumable_epochs_follow_new_os_preference_without_reusing_old_proof() {
    let (state, _, owner) = owner();
    let mut attempts =
        NetworkAttempts::new(&owner, local(), remote(), SocketProtocol::Udp, 0).unwrap();
    let first = attempts.prepare(&owner, || true).await.unwrap();
    state.publish(inventory(2, Some(2))).unwrap();
    assert!(first.is_preferred());
    assert_eq!(
        attempts.confirm(&first, true).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(
        attempts.prepare(&owner, || true).await.unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    let mut next = NetworkAttempts::new(&owner, local(), remote(), SocketProtocol::Udp, 0).unwrap();
    let selected = next.prepare(&owner, || true).await.unwrap();
    assert_eq!(selected.number(), 1);
    assert!(selected.is_preferred());
    assert_eq!(selected.lease().network_handle, 2);
    assert_ne!(attempts.epoch(), next.epoch());
}

#[tokio::test]
async fn resumable_lookup_cancellation_cannot_guess_an_owner_or_overlap_backend_work() {
    #[derive(Debug)]
    struct HeldSource {
        entered: tokio::sync::Notify,
        released: std::sync::Condvar,
        release: Mutex<bool>,
        calls: AtomicUsize,
        completed: AtomicBool,
    }
    impl SocketBinder for HeldSource {
        fn bind(&self, _: u64, _: BorrowedFd<'_>) -> io::Result<()> {
            unreachable!()
        }
        fn source_for(&self, _: u64, _: SocketAddr) -> io::Result<SocketAddr> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            let mut release = self.release.lock().unwrap();
            while !*release {
                release = self.released.wait(release).unwrap();
            }
            self.completed.store(true, Ordering::SeqCst);
            Ok("192.0.2.1:42000".parse().unwrap())
        }
    }
    struct Release(Arc<HeldSource>);
    impl Drop for Release {
        fn drop(&mut self) {
            *self.0.release.lock().unwrap() = true;
            self.0.released.notify_all();
        }
    }
    let state = Arc::new(Networks::default());
    state.publish(inventory(1, Some(1))).unwrap();
    let binder = Arc::new(HeldSource {
        entered: tokio::sync::Notify::new(),
        released: std::sync::Condvar::new(),
        release: Mutex::new(false),
        calls: AtomicUsize::new(0),
        completed: AtomicBool::new(false),
    });
    let release = Release(Arc::clone(&binder));
    state.binder.set(binder.clone()).unwrap();
    let owner = Egress::with_networks(state);
    let mut attempts =
        NetworkAttempts::new(&owner, local(), remote(), SocketProtocol::Udp, 0).unwrap();
    let mut preparation = Box::pin(attempts.prepare(&owner, || true));
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            result = &mut preparation => panic!("held preparation returned {result:?}"),
            () = binder.entered.notified() => (),
        }
    })
    .await
    .unwrap();
    drop(preparation);
    assert_eq!(
        attempts.prepare(&owner, || true).await.unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(binder.calls.load(Ordering::SeqCst), 1);
    drop(release);
    tokio::time::timeout(Duration::from_secs(2), async {
        while !binder.completed.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

#[derive(Debug)]
struct SourceCounter {
    inner: Binder,
    lookups: Mutex<Vec<u64>>,
}

impl SocketBinder for SourceCounter {
    fn bind(&self, handle: u64, socket: BorrowedFd<'_>) -> io::Result<()> {
        self.inner.bind(handle, socket)
    }

    fn source_for(&self, handle: u64, destination: SocketAddr) -> io::Result<SocketAddr> {
        self.lookups.lock().unwrap().push(handle);
        self.inner.source_for(handle, destination)
    }
}

fn source_counted_owner() -> (Egress, Arc<SourceCounter>) {
    let state = Arc::new(Networks::default());
    state.publish(inventory(1, Some(1))).unwrap();
    let binder = Arc::new(SourceCounter {
        inner: Binder {
            state: Arc::downgrade(&state),
            ..Binder::default()
        },
        lookups: Mutex::new(Vec::new()),
    });
    state.binder.set(binder.clone()).unwrap();
    (Egress::with_networks(state), binder)
}

#[tokio::test]
async fn first_success_after_preferred_source_failure_is_not_preferred() {
    for (local_address, destination, preferred_source, fallback_source) in [
        (
            "0.0.0.0:42000",
            "203.0.113.9:443",
            "2001:db8:1::1",
            "198.51.100.1",
        ),
        (
            "[::]:42000",
            "[2001:db8:9::9]:443",
            "192.0.2.1",
            "2001:db8:2::1",
        ),
    ] {
        for permitted in [false, true] {
            let (owner, binder) = source_counted_owner();
            let mut next = inventory(2, Some(1));
            next.networks[0] = record(1, 1, preferred_source);
            next.networks[1] = record(2, 2, fallback_source);
            for network in &mut next.networks {
                network.revision = 2;
            }
            owner.networks.publish(next).unwrap();
            let mut attempts = NetworkAttempts::new(
                &owner,
                local_address.parse().unwrap(),
                destination.parse().unwrap(),
                SocketProtocol::Udp,
                0,
            )
            .unwrap();
            assert!(binder.lookups.lock().unwrap().is_empty());
            let selected = attempts.prepare(&owner, || permitted).await.unwrap();
            assert_eq!(selected.number(), 1);
            assert_eq!(selected.lease().network_handle, 2);
            assert!(!selected.is_preferred());
            assert!(!selected.clone().is_preferred());
            assert_eq!(binder.lookups.lock().unwrap().as_slice(), &[1, 2]);
            // Preserve the generic dial API's initial source-lookup fallback.
            // Strict preferred-only validation must inspect the policy flag.
            attempts.confirm(&selected, permitted).unwrap();
            assert!(!attempts.can_prepare());
        }
    }
}

#[tokio::test]
async fn preferred_identity_follows_destination_policy_not_exclusion_or_transport_kind() {
    let (owner, binder) = source_counted_owner();
    let mut next = inventory(2, Some(2));
    next.networks[0].addresses =
        ["10.10.0.1".parse().unwrap(), "fd00:10::1".parse().unwrap()].into();
    next.networks[0].routes.extend([
        NetworkRoute {
            destination: "10.10.0.0".parse().unwrap(),
            prefix_length: 16,
            gateway: None,
        },
        NetworkRoute {
            destination: "fd00:10::".parse().unwrap(),
            prefix_length: 64,
            gateway: None,
        },
    ]);
    next.networks[1].kind = PhysicalNetworkKind::Cellular;
    next.networks[1]
        .addresses
        .insert("2001:db8:2::1".parse().unwrap());
    for network in &mut next.networks {
        network.revision = 2;
    }
    owner.networks.publish(next).unwrap();
    for (local_address, destination, expected) in [
        ("0.0.0.0:42000", "10.10.5.6:443", 1),
        ("0.0.0.0:42000", "203.0.113.9:443", 2),
        ("[::]:42000", "[fd00:10::9]:443", 1),
        ("[::]:42000", "[2001:db8:9::9]:443", 2),
        ("[::ffff:0.0.0.0]:42000", "[::ffff:203.0.113.9]:443", 2),
    ] {
        binder.lookups.lock().unwrap().clear();
        let mut attempts = NetworkAttempts::new(
            &owner,
            local_address.parse().unwrap(),
            destination.parse().unwrap(),
            SocketProtocol::Udp,
            0,
        )
        .unwrap();
        assert!(binder.lookups.lock().unwrap().is_empty());
        let preferred = attempts.prepare(&owner, || false).await.unwrap();
        assert_eq!(preferred.lease().network_handle, expected);
        assert!(preferred.is_preferred());
        assert!(
            attempts
                .failed(&preferred, io::ErrorKind::TimedOut, true)
                .unwrap()
        );
        let fallback = attempts.prepare(&owner, || true).await.unwrap();
        assert_eq!(fallback.lease().network_handle, 3 - expected);
        assert_eq!(fallback.number(), 2);
        assert!(!fallback.is_preferred());
        assert_eq!(
            binder.lookups.lock().unwrap().as_slice(),
            &[expected, 3 - expected]
        );
        assert_eq!(
            attempts.confirm(&fallback, false).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
    }
}

#[tokio::test]
async fn preferred_identity_respects_original_ipv6_scope_constraints() {
    for (local_address, destination, expected) in [
        ("[::%2]:42000", "[fe80::9]:443", Some(2)),
        ("[::]:42000", "[fe80::9%2]:443", Some(2)),
        ("[::%2]:42000", "[fe80::9%2]:443", Some(2)),
        ("[::%1]:42000", "[fe80::9%2]:443", None),
        ("[::%99]:42000", "[fe80::9]:443", None),
        ("[::]:42000", "[fe80::9%99]:443", None),
        ("[::]:42000", "[2001:db8:9::9%2]:443", Some(1)),
    ] {
        let (owner, binder) = source_counted_owner();
        let mut next = inventory(2, Some(1));
        for network in &mut next.networks {
            network.revision = 2;
            network.addresses =
                [format!("fe80::{}", network.network_handle).parse().unwrap()].into();
        }
        owner.networks.publish(next).unwrap();
        let mut attempts = NetworkAttempts::new(
            &owner,
            local_address.parse().unwrap(),
            destination.parse().unwrap(),
            SocketProtocol::Udp,
            0,
        )
        .unwrap();
        assert!(binder.lookups.lock().unwrap().is_empty());
        match expected {
            Some(handle) => {
                let selected = attempts.prepare(&owner, || false).await.unwrap();
                assert_eq!(selected.number(), 1);
                assert_eq!(selected.lease().network_handle, handle);
                assert!(selected.is_preferred());
                assert_eq!(binder.lookups.lock().unwrap().as_slice(), &[handle]);
                attempts.confirm(&selected, false).unwrap();
            }
            None => {
                assert_eq!(
                    attempts.prepare(&owner, || true).await.unwrap_err().kind(),
                    io::ErrorKind::NetworkUnreachable
                );
                assert!(binder.lookups.lock().unwrap().is_empty());
            }
        }
    }
}

#[tokio::test]
async fn changed_epoch_before_first_prepare_cannot_reclassify_a_captured_preference() {
    let (owner, binder) = source_counted_owner();
    let mut old = NetworkAttempts::new(&owner, local(), remote(), SocketProtocol::Udp, 0).unwrap();
    owner.networks.publish(inventory(2, Some(2))).unwrap();
    assert_eq!(
        old.prepare(&owner, || true).await.unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert!(binder.lookups.lock().unwrap().is_empty());
    let mut fresh =
        NetworkAttempts::new(&owner, local(), remote(), SocketProtocol::Udp, 0).unwrap();
    let selected = fresh.prepare(&owner, || false).await.unwrap();
    assert_eq!(selected.lease().network_handle, 2);
    assert!(selected.is_preferred());
    fresh.confirm(&selected, false).unwrap();
}

#[tokio::test]
async fn publication_during_lookup_cannot_return_an_attempt_with_stale_preference() {
    #[derive(Debug)]
    struct PublishingSource {
        inner: Binder,
        publish: AtomicBool,
        calls: AtomicUsize,
    }
    impl SocketBinder for PublishingSource {
        fn bind(&self, handle: u64, socket: BorrowedFd<'_>) -> io::Result<()> {
            self.inner.bind(handle, socket)
        }

        fn source_for(&self, handle: u64, destination: SocketAddr) -> io::Result<SocketAddr> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.publish.swap(false, Ordering::SeqCst) {
                self.inner
                    .state
                    .upgrade()
                    .unwrap()
                    .publish(inventory(2, Some(2)))
                    .unwrap();
            }
            self.inner.source_for(handle, destination)
        }
    }
    let state = Arc::new(Networks::default());
    state.publish(inventory(1, Some(1))).unwrap();
    let binder = Arc::new(PublishingSource {
        inner: Binder {
            state: Arc::downgrade(&state),
            ..Binder::default()
        },
        publish: AtomicBool::new(true),
        calls: AtomicUsize::new(0),
    });
    state.binder.set(binder.clone()).unwrap();
    let owner = Egress::with_networks(state);
    let mut old = NetworkAttempts::new(&owner, local(), remote(), SocketProtocol::Udp, 0).unwrap();
    assert_eq!(binder.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        old.prepare(&owner, || true).await.unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(binder.calls.load(Ordering::SeqCst), 1);
    assert!(!old.can_prepare());
    let mut fresh =
        NetworkAttempts::new(&owner, local(), remote(), SocketProtocol::Udp, 0).unwrap();
    let selected = fresh.prepare(&owner, || false).await.unwrap();
    assert_eq!(selected.lease().network_handle, 2);
    assert!(selected.is_preferred());
    fresh.confirm(&selected, false).unwrap();
}

#[tokio::test]
async fn fallback_permission_denied_returns_original_failure_without_second_lookup() {
    let (owner, binder) = source_counted_owner();
    let mut attempted = Vec::new();
    let message = "preferred service refused; fallback permission denied";
    let error =
        tokio::time::timeout(
            Duration::from_secs(2),
            owner.attempt_networks_if(
                local(),
                remote(),
                SocketProtocol::Tcp,
                0,
                |lease| {
                    attempted.push(lease.network_handle);
                    async move {
                        Err::<(), _>(io::Error::new(io::ErrorKind::ConnectionRefused, message))
                    }
                },
                || false,
            ),
        )
        .await
        .expect("bounded denied-fallback operation")
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    assert_eq!(error.to_string(), message);
    assert_eq!(
        attempted,
        [1],
        "permission must not suppress the initial attempt"
    );
    assert_eq!(binder.lookups.lock().unwrap().as_slice(), &[1]);
}

#[tokio::test]
async fn fallback_permission_revoked_by_failure_prevents_second_source_lookup() {
    let (owner, binder) = source_counted_owner();
    let permitted = Arc::new(AtomicBool::new(true));
    let mut attempted = Vec::new();
    let message = "preferred connection reset after intent was withdrawn";
    let error = tokio::time::timeout(
        Duration::from_secs(2),
        owner.attempt_networks_if(
            local(),
            remote(),
            SocketProtocol::Tcp,
            0,
            |lease| {
                attempted.push(lease.network_handle);
                let permitted = Arc::clone(&permitted);
                async move {
                    assert!(permitted.swap(false, Ordering::SeqCst));
                    Err::<(), _>(io::Error::new(io::ErrorKind::ConnectionReset, message))
                }
            },
            || permitted.load(Ordering::SeqCst),
        ),
    )
    .await
    .expect("bounded revoked-fallback operation")
    .unwrap_err();
    assert!(!permitted.load(Ordering::SeqCst));
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(error.to_string(), message);
    assert_eq!(attempted, [1]);
    assert_eq!(binder.lookups.lock().unwrap().as_slice(), &[1]);
}

#[tokio::test]
async fn callback_connectivity_failure_tries_fallback_without_invalidating_live_lease() {
    let (_, _, owner) = owner();
    let existing = owner
        .prepare_shared_datagram(local(), remote(), 73)
        .await
        .unwrap();
    let epoch = owner.current_epoch().unwrap();
    let mut attempted = Vec::new();
    let selected = owner
        .attempt_networks(local(), remote(), SocketProtocol::Tcp, 73, |lease| {
            attempted.push(lease.network_handle);
            assert_eq!(lease.context.destination, remote());
            assert_eq!(lease.context.protocol, SocketProtocol::Tcp);
            assert_eq!(lease.context.mark, 73);
            assert_eq!(lease.local_addr.port(), local().port());
            assert!(lease.is_current());
            assert_eq!(lease.epoch(), epoch);
            async move {
                if lease.network_handle == 1 {
                    Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                } else {
                    Ok(lease)
                }
            }
        })
        .await
        .unwrap();
    assert_eq!(attempted, [1, 2]);
    assert_eq!(selected.network_handle, 2);
    assert_eq!(
        selected.local_addr.ip(),
        "198.51.100.1".parse::<IpAddr>().unwrap()
    );
    assert!(existing.is_available());
    assert!(existing.is_current());
    assert_eq!(owner.current_epoch().unwrap(), epoch);

    let next = owner
        .attempt_networks(
            local(),
            remote(),
            SocketProtocol::Tcp,
            73,
            |lease| async move { Ok(lease.network_handle) },
        )
        .await
        .unwrap();
    assert_eq!(next, 1, "a new dial must recheck OS preference");
}

#[tokio::test]
async fn all_connectivity_failures_stop_after_three_distinct_networks() {
    for count in [4_u64, 16] {
        let (state, _, owner) = owner();
        let mut next = inventory(2, Some(1));
        next.networks = (1..=count)
            .map(|handle| record(handle, handle, &format!("192.0.2.{handle}")))
            .collect();
        // Keep existing record metadata unchanged during this publication.
        next.networks[1] = record(2, 2, "198.51.100.1");
        state.publish(next).unwrap();
        let mut attempted = Vec::new();
        let error = owner
            .attempt_networks(local(), remote(), SocketProtocol::Tcp, 0, |lease| {
                attempted.push(lease.network_handle);
                async { Err::<(), _>(io::Error::from(io::ErrorKind::ConnectionReset)) }
            })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(attempted, [1, 2, 3]);
        assert!(!attempted.contains(&4));
    }
}

#[tokio::test]
async fn success_preserves_canonical_destination_and_family_without_other_attempts() {
    for (local, destination, canonical_destination, ipv6) in [
        ("0.0.0.0:42000", "203.0.113.9:443", "203.0.113.9:443", false),
        (
            "[::ffff:0.0.0.0]:42000",
            "[::ffff:203.0.113.9]:443",
            "203.0.113.9:443",
            false,
        ),
        (
            "[::]:42000",
            "[2001:db8:9::9]:443",
            "[2001:db8:9::9]:443",
            true,
        ),
    ] {
        let (state, _, owner) = owner();
        if ipv6 {
            let mut next = inventory(2, Some(1));
            for network in &mut next.networks {
                network.revision = 2;
                network.addresses.insert(
                    format!("2001:db8:{}::1", network.network_handle)
                        .parse()
                        .unwrap(),
                );
                network.routes.push(NetworkRoute {
                    destination: "::".parse().unwrap(),
                    prefix_length: 0,
                    gateway: None,
                });
            }
            state.publish(next).unwrap();
        }
        let destination: SocketAddr = destination.parse().unwrap();
        let expected: SocketAddr = canonical_destination.parse().unwrap();
        let mut attempted = Vec::new();
        let selected = owner
            .attempt_networks(
                local.parse().unwrap(),
                destination,
                SocketProtocol::Udp,
                91,
                |lease| {
                    attempted.push(lease.network_handle);
                    assert_eq!(lease.context.destination, expected);
                    assert_eq!(lease.context.protocol, SocketProtocol::Udp);
                    assert_eq!(lease.context.mark, 91);
                    assert_eq!(lease.local_addr.port(), 42000);
                    assert_eq!(lease.local_addr.is_ipv6(), ipv6);
                    async move { Ok(lease.network_handle) }
                },
            )
            .await
            .unwrap();
        assert_eq!(selected, 1);
        assert_eq!(attempted, [1]);
    }
}

#[tokio::test]
async fn authentication_and_policy_errors_do_not_try_another_network() {
    for kind in [
        io::ErrorKind::InvalidData,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::InvalidInput,
        io::ErrorKind::Interrupted,
        io::ErrorKind::WouldBlock,
    ] {
        let (_, _, owner) = owner();
        let mut attempted = Vec::new();
        let error = owner
            .attempt_networks(local(), remote(), SocketProtocol::Tcp, 0, |lease| {
                attempted.push(lease.network_handle);
                async move { Err::<(), _>(io::Error::from(kind)) }
            })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), kind);
        assert_eq!(attempted, [1], "{kind:?} is not connectivity evidence");
    }
}

#[tokio::test]
async fn attempts_require_wildcard_source_and_do_not_change_fixed_incoming_ownership() {
    let (_, _, owner) = owner();
    for source in ["192.0.2.1:42000", "[::ffff:192.0.2.1]:42000", "[::]:42000"] {
        let mut invoked = false;
        let error = owner
            .attempt_networks(
                source.parse().unwrap(),
                remote(),
                SocketProtocol::Tcp,
                0,
                |_| {
                    invoked = true;
                    async { Ok(()) }
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!invoked);
    }
    let mut invoked = false;
    let error = owner
        .attempt_networks_with_timeout(
            local(),
            remote(),
            SocketProtocol::Tcp,
            0,
            Duration::ZERO,
            |_| {
                invoked = true;
                async { Ok(()) }
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(!invoked);
    let incoming = owner
        .prepare_incoming("192.0.2.1:42000".parse().unwrap(), remote(), 17)
        .await
        .unwrap();
    assert_eq!(incoming.network_handle, 1);
    assert_eq!(
        incoming.local_addr,
        "192.0.2.1:42000".parse::<SocketAddr>().unwrap()
    );
    assert!(!incoming.preferred_dial);
}

#[tokio::test]
async fn publication_during_callback_rejects_both_failure_and_success_as_stale() {
    for succeeds in [false, true] {
        let (state, _, owner) = owner();
        let existing = owner
            .prepare_shared_datagram(local(), remote(), 0)
            .await
            .unwrap();
        let mut attempted = Vec::new();
        let error = owner
            .attempt_networks(local(), remote(), SocketProtocol::Tcp, 0, |lease| {
                attempted.push(lease.network_handle);
                let state = Arc::clone(&state);
                async move {
                    state.publish(inventory(2, Some(2))).unwrap();
                    if succeeds {
                        Ok(lease.network_handle)
                    } else {
                        Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                    }
                }
            })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(attempted, [1]);
        assert!(existing.is_available());
        assert!(!existing.is_current());
    }
}

#[tokio::test]
async fn dropping_active_attempt_cancels_operation_and_next_dial_starts_at_preferred() {
    struct Dropped(Arc<AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let (_, _, owner) = owner();
    let entered = Arc::new(tokio::sync::Notify::new());
    let dropped = Arc::new(AtomicBool::new(false));
    let mut attempted = Vec::new();
    let mut dial =
        Box::pin(
            owner.attempt_networks(local(), remote(), SocketProtocol::Tcp, 0, |lease| {
                attempted.push(lease.network_handle);
                let entered = Arc::clone(&entered);
                let dropped = Arc::clone(&dropped);
                async move {
                    let _guard = Dropped(dropped);
                    entered.notify_one();
                    std::future::pending::<io::Result<()>>().await
                }
            }),
        );
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            result = &mut dial => panic!("active operation unexpectedly completed: {result:?}"),
            () = entered.notified() => {},
        }
    })
    .await
    .expect("bounded admission of the cancellable callback");
    drop(dial);
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(attempted, [1]);
    let mut retried = Vec::new();
    let selected = owner
        .attempt_networks(local(), remote(), SocketProtocol::Tcp, 0, |lease| {
            retried.push(lease.network_handle);
            async move { Ok(lease.network_handle) }
        })
        .await
        .unwrap();
    assert_eq!(selected, 1);
    assert_eq!(retried, [1]);
}

#[tokio::test]
async fn timeout_includes_lookup_and_operation_but_unknown_owner_stops_retry() {
    #[derive(Debug)]
    struct SlowSource {
        delay: Duration,
        lookups: AtomicUsize,
        completed: AtomicUsize,
    }
    impl SocketBinder for SlowSource {
        fn bind(&self, _handle: u64, _socket: BorrowedFd<'_>) -> io::Result<()> {
            Ok(())
        }
        fn source_for(&self, handle: u64, _destination: SocketAddr) -> io::Result<SocketAddr> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            if handle == 1 {
                std::thread::sleep(self.delay);
            }
            self.completed.fetch_add(1, Ordering::SeqCst);
            Ok(if handle == 1 {
                "192.0.2.1:1234"
            } else {
                "198.51.100.1:1234"
            }
            .parse()
            .unwrap())
        }
    }
    let state = Arc::new(Networks::default());
    state.publish(inventory(1, Some(1))).unwrap();
    let binder = Arc::new(SlowSource {
        delay: Duration::from_millis(100),
        lookups: AtomicUsize::new(0),
        completed: AtomicUsize::new(0),
    });
    state.binder.set(binder.clone()).unwrap();
    let owner = Egress::with_networks(state);
    let mut attempted = Vec::new();
    let selected = tokio::time::timeout(
        Duration::from_secs(2),
        owner.attempt_networks_with_timeout(
            local(),
            remote(),
            SocketProtocol::Tcp,
            0,
            Duration::from_millis(400),
            |lease| {
                attempted.push(lease.network_handle);
                async move {
                    if lease.network_handle == 1 {
                        tokio::time::sleep(Duration::from_millis(350)).await;
                    }
                    Ok(lease.network_handle)
                }
            },
        ),
    )
    .await
    .expect("bounded known-owner timeout and fallback")
    .unwrap();
    assert_eq!(
        selected, 2,
        "lookup and operation must share one attempt budget"
    );
    assert_eq!(attempted, [1, 2]);
    assert_eq!(binder.lookups.load(Ordering::SeqCst), 2);

    let mut invoked = false;
    let error = owner
        .attempt_networks_with_timeout(
            local(),
            remote(),
            SocketProtocol::Tcp,
            0,
            Duration::from_millis(20),
            |_| {
                invoked = true;
                async { Ok(()) }
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(!invoked, "an unfinished lookup has no admitted operation");
    tokio::time::timeout(Duration::from_secs(2), async {
        while binder.completed.load(Ordering::SeqCst) < 3 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the detached bounded lookup finishes before model teardown");
    assert_eq!(
        binder.lookups.load(Ordering::SeqCst),
        3,
        "an unknown owner must not trigger guessed exclusion or another lookup"
    );
}
