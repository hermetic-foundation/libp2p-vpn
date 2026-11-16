//! Host-only async operation models, not Android socket or device proof.

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn local() -> SocketAddr {
    "0.0.0.0:42000".parse().unwrap()
}

fn remote() -> SocketAddr {
    "203.0.113.9:443".parse().unwrap()
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
