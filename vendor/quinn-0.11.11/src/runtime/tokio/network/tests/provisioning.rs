//! Gated binding models exercise cache synchronization, not Android NDK behavior.

use super::*;
use std::sync::mpsc;

#[derive(Clone, Copy, Debug)]
enum Outcome {
    Success,
    Error,
    Panic,
}

#[derive(Debug)]
struct GatedBinding {
    base: Weak<UdpSocket>,
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: Mutex<mpsc::Receiver<()>>,
    outcome: Outcome,
}

// Release the worker even if an assertion in the async test unwinds.
struct Release(Option<mpsc::Sender<()>>);

impl Release {
    fn open(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

impl Drop for Release {
    fn drop(&mut self) {
        self.open();
    }
}

impl GatedBinding {
    fn new(
        base: &Arc<UdpSocket>,
        outcome: Outcome,
    ) -> (Arc<Self>, tokio::sync::oneshot::Receiver<()>, Release) {
        let (entered, wait) = tokio::sync::oneshot::channel();
        let (release, gate) = mpsc::channel();
        (
            Arc::new(Self {
                base: Arc::downgrade(base),
                entered: Mutex::new(Some(entered)),
                release: Mutex::new(gate),
                outcome,
            }),
            wait,
            Release(Some(release)),
        )
    }

    fn assert_unlocked(&self) {
        let base = self.base.upgrade().unwrap();
        assert!(
            base.networks.0.try_lock().is_ok(),
            "binding callback under cache lock"
        );
    }
}

impl UdpSocketBinding for GatedBinding {
    fn identity(&self) -> [u64; 3] {
        self.assert_unlocked();
        [8, 9, 10]
    }

    fn uses_platform_routing(&self) -> bool {
        self.assert_unlocked();
        false
    }

    fn ipv6_scope_id(&self) -> Option<NonZeroU32> {
        self.assert_unlocked();
        None
    }

    fn bind(&self, _: &std::net::UdpSocket) -> io::Result<()> {
        self.assert_unlocked();
        self.entered
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .send(())
            .unwrap();
        self.release.lock().unwrap().recv().unwrap();
        match self.outcome {
            Outcome::Success => Ok(()),
            Outcome::Error => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "mock bind error",
            )),
            Outcome::Panic => panic!("mock bind unwind"),
        }
    }
}

#[tokio::test]
async fn blocked_bind_does_not_block_receive_and_counts_pending_with_live_capacity() {
    let base = base("0.0.0.0:0");
    let source = "127.0.0.2".parse().unwrap();
    let held: Vec<_> = (0..MAX_NETWORKS - 1)
        .map(|generation| {
            acquire(
                &base,
                "127.0.0.3".parse().unwrap(),
                Binding::new([1, 2, generation as u64]),
            )
        })
        .collect();
    let (binding, entered, mut release) = GatedBinding::new(&base, Outcome::Success);
    let worker_base = base.clone();
    let worker_binding = binding.clone();
    let worker = tokio::task::spawn_blocking(move || {
        worker_base.transmit_socket_with_binding(source, interface(), Some(worker_binding))
    });
    tokio::time::timeout(Duration::from_secs(2), entered)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(base.networks.0.lock().unwrap().pending.len(), 1);
    // A started blocking backend cannot be cancelled by its async waiter.
    worker.abort();
    for id in [[8, 9, 10], [80, 90, 100]] {
        assert_eq!(
            base.transmit_socket_with_binding(source, interface(), Some(Binding::new(id)))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }
    // Pending keys also protect immutable routing mode and source scope.
    let conflict = super::platform::RoutingBinding::new([8, 9, 10], true);
    assert_eq!(
        base.transmit_socket_with_binding(source, interface(), Some(conflict))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );

    let counter = Arc::new(Counter::default());
    let waker = Waker::from(counter.clone());
    let mut cx = Context::from_waker(&waker);
    let mut bytes = [0; 128];
    assert!(base
        .poll_recv(
            &mut cx,
            &mut [IoSliceMut::new(&mut bytes)],
            &mut [udp::RecvMeta::default()]
        )
        .is_pending());
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    peer.send_to(
        &[42],
        SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            base.local_addr().unwrap().port(),
        ),
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while counter.0.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(receive(&base, false).await, 42);
    assert!(counter.0.load(Ordering::Relaxed) > 0);
    assert!(base
        .poll_recv(
            &mut cx,
            &mut [IoSliceMut::new(&mut bytes)],
            &mut [udp::RecvMeta::default()]
        )
        .is_pending());
    let before = counter.0.load(Ordering::Relaxed);
    release.open();
    let helper = worker.await.unwrap().unwrap().unwrap();
    assert!(base.networks.0.lock().unwrap().pending.is_empty());
    assert_eq!(base.networks.0.lock().unwrap().sockets.len(), MAX_NETWORKS);
    assert!(counter.0.load(Ordering::Relaxed) > before);
    assert!(base
        .poll_recv(
            &mut cx,
            &mut [IoSliceMut::new(&mut bytes)],
            &mut [udp::RecvMeta::default()]
        )
        .is_pending());
    let before = counter.0.load(Ordering::Relaxed);
    let reused = base
        .transmit_socket_with_binding(source, interface(), Some(binding))
        .unwrap()
        .unwrap();
    assert!(Arc::ptr_eq(&helper, &reused));
    assert_eq!(
        counter.0.load(Ordering::Relaxed),
        before,
        "dedup must not wake receive again"
    );
    drop((helper, reused, held));
}

#[tokio::test]
async fn dropped_async_waiter_does_not_release_running_backend_reservation() {
    let base = base("0.0.0.0:0");
    let source = "127.0.0.2".parse().unwrap();
    let (binding, entered, mut release) = GatedBinding::new(&base, Outcome::Success);
    let (finished, done) = tokio::sync::oneshot::channel();
    let worker_base = base.clone();
    let worker = tokio::task::spawn_blocking(move || {
        drop(
            worker_base
                .transmit_socket_with_binding(source, interface(), Some(binding))
                .unwrap(),
        );
        finished.send(()).unwrap();
    });
    tokio::time::timeout(Duration::from_secs(2), entered)
        .await
        .unwrap()
        .unwrap();
    drop(worker);
    assert_eq!(base.networks.0.lock().unwrap().pending.len(), 1);
    assert_eq!(
        base.transmit_socket_with_binding(source, interface(), Some(Binding::new([8, 9, 10])))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    release.open();
    tokio::time::timeout(Duration::from_secs(2), done)
        .await
        .unwrap()
        .unwrap();
    assert!(base.networks.0.lock().unwrap().pending.is_empty());
    let _retry = acquire(&base, source, Binding::new([8, 9, 10]));
}

#[tokio::test]
async fn failed_or_panicking_backend_keeps_reservation_until_return_then_releases_it() {
    for outcome in [Outcome::Error, Outcome::Panic] {
        let base = base("0.0.0.0:0");
        let source = "127.0.0.2".parse().unwrap();
        let (binding, entered, mut release) = GatedBinding::new(&base, outcome);
        let retired = Arc::downgrade(&binding);
        let worker_base = base.clone();
        let worker = tokio::task::spawn_blocking(move || {
            worker_base.transmit_socket_with_binding(source, interface(), Some(binding))
        });
        tokio::time::timeout(Duration::from_secs(2), entered)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            base.transmit_socket_with_binding(source, interface(), Some(Binding::new([8, 9, 10])))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(base.networks.0.lock().unwrap().pending.len(), 1);
        release.open();
        match outcome {
            Outcome::Error => assert_eq!(
                worker.await.unwrap().unwrap_err().kind(),
                io::ErrorKind::NotConnected
            ),
            Outcome::Panic => assert!(worker.await.unwrap_err().is_panic()),
            Outcome::Success => unreachable!(),
        }
        assert!(retired.upgrade().is_none());
        assert!(base.networks.0.lock().unwrap().pending.is_empty());
        assert!(base.networks.0.lock().unwrap().sockets.is_empty());
        let _retry = acquire(&base, source, Binding::new([8, 9, 10]));
    }
}
