use super::*;
use std::{
    future::poll_fn,
    io::IoSliceMut,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::Wake,
    time::Duration,
};

#[derive(Debug)]
struct Binding {
    id: [u64; 3],
    calls: AtomicUsize,
    stale: AtomicBool,
}

impl Binding {
    fn new(id: [u64; 3]) -> Arc<Self> {
        Arc::new(Self {
            id,
            calls: AtomicUsize::new(0),
            stale: AtomicBool::new(false),
        })
    }
}

impl UdpSocketBinding for Binding {
    fn identity(&self) -> [u64; 3] {
        self.id
    }

    fn bind(&self, socket: &std::net::UdpSocket) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        assert_eq!(
            socket.local_addr()?.port(),
            0,
            "callback ran after local bind"
        );
        assert!(!socket2::SockRef::from(socket).reuse_address()?);
        if self.stale.load(Ordering::Relaxed) {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "stale Network"));
        }
        Ok(())
    }
}

fn interface() -> NonZeroU32 {
    #[cfg(target_os = "linux")]
    return std::fs::read_to_string("/sys/class/net/lo/ifindex")
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    #[cfg(target_os = "android")]
    NonZeroU32::new(1).unwrap()
}

fn base(local: &str) -> Arc<UdpSocket> {
    let local: SocketAddr = local.parse().unwrap();
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(local),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .unwrap();
    if local.is_ipv6() {
        socket.set_only_v6(false).unwrap();
    }
    socket.set_nonblocking(true).unwrap();
    socket.bind(&local.into()).unwrap();
    let socket: std::net::UdpSocket = socket.into();
    Arc::new(UdpSocket {
        inner: udp::UdpSocketState::new((&socket).into()).unwrap(),
        io: tokio::net::UdpSocket::from_std(socket).unwrap(),
        #[cfg(target_os = "linux")]
        routes: Default::default(),
        #[cfg(target_os = "linux")]
        selected: None,
        networks: Networks::default(),
        network_selection: None,
    })
}

fn acquire(base: &UdpSocket, source: IpAddr, binding: Arc<Binding>) -> Arc<dyn AsyncUdpSocket> {
    base.transmit_socket_with_binding(source, interface(), Some(binding))
        .unwrap()
        .unwrap()
}

async fn receive(socket: &UdpSocket, single: bool) -> u8 {
    let mut bytes = [0; 128];
    let mut buffers = [IoSliceMut::new(&mut bytes)];
    let mut meta = [udp::RecvMeta::default(); 1];
    let count = tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| {
            if single {
                socket.poll_recv_single(cx, &mut buffers, &mut meta)
            } else {
                socket.poll_recv(cx, &mut buffers, &mut meta)
            }
        }),
    )
    .await
    .expect("receive deadline")
    .unwrap();
    assert_eq!(count, 1);
    assert_eq!(meta[0].len, 1);
    bytes[0]
}

#[tokio::test]
async fn key_uses_every_network_identity_word_source_and_interface() {
    let base = base("0.0.0.0:0");
    let source = "127.0.0.1".parse().unwrap();
    let binding = Binding::new([1, 2, 3]);
    let first = acquire(&base, source, binding.clone());
    let same = acquire(&base, source, Binding::new([1, 2, 3]));
    assert!(Arc::ptr_eq(&first, &same));
    assert_eq!(binding.calls.load(Ordering::Relaxed), 1);
    let mut held = vec![first, same];
    for id in [[9, 2, 3], [1, 9, 3], [1, 2, 9]] {
        let other = acquire(&base, source, Binding::new(id));
        assert!(!Arc::ptr_eq(&held[0], &other));
        held.push(other);
    }
    held.push(acquire(
        &base,
        "127.0.0.2".parse().unwrap(),
        binding.clone(),
    ));
    held.push(
        base.transmit_socket_with_binding(
            source,
            NonZeroU32::new(interface().get() + 1).unwrap(),
            Some(binding.clone()),
        )
        .unwrap()
        .unwrap(),
    );
    assert_eq!(base.networks.0.lock().unwrap().sockets.len(), 6);
    assert_eq!(
        base.local_addr().unwrap().port(),
        held[0].local_addr().unwrap().port()
    );
    assert!(held[0]
        .transmit_socket_with_binding(source, interface(), Some(binding.clone()))
        .unwrap()
        .is_none());
    assert!(held[0]
        .transmit_socket_with_binding(source, interface(), None)
        .is_err());
    assert!(held[0].transmit_socket(source, interface()).is_err());
    assert!(held[0]
        .transmit_socket_with_binding(source, interface(), Some(Binding::new([1, 2, 4])))
        .is_err());
    let retired = Arc::downgrade(&held[0]);
    let binding_retired = Arc::downgrade(&binding);
    drop(binding);
    drop(held);
    assert!(retired.upgrade().is_none());
    assert!(binding_retired.upgrade().is_none());
}

#[tokio::test]
async fn both_families_and_dual_stack_send_and_receive_on_actual_companions() {
    for (local, source, peer_bind) in [
        ("0.0.0.0:0", "127.0.0.2", "127.0.0.1:0"),
        ("[::]:0", "127.0.0.2", "127.0.0.1:0"),
        ("[::]:0", "::1", "[::1]:0"),
    ] {
        let base = base(local);
        let source: IpAddr = source.parse().unwrap();
        let helper = acquire(&base, source, Binding::new([1, 2, 3]));
        let actual = base
            .networks
            .0
            .lock()
            .unwrap()
            .sockets
            .values()
            .next()
            .unwrap()
            .upgrade()
            .unwrap();
        assert_eq!(helper.local_addr().unwrap().ip(), source);
        assert!(!socket2::SockRef::from(&actual.io).reuse_address().unwrap());
        assert!(!socket2::SockRef::from(&base.io).reuse_address().unwrap());
        assert!(socket2::SockRef::from(&actual.io).reuse_port().unwrap());
        let peer = tokio::net::UdpSocket::bind(peer_bind).await.unwrap();
        let mut destination = peer.local_addr().unwrap();
        if base.local_addr().unwrap().is_ipv6() && destination.is_ipv4() {
            let IpAddr::V4(ip) = destination.ip() else {
                unreachable!()
            };
            destination = SocketAddr::V6(SocketAddrV6::new(
                ip.to_ipv6_mapped(),
                destination.port(),
                0,
                0,
            ));
        }
        helper
            .try_send_on_interface(
                &udp::Transmit {
                    destination,
                    ecn: None,
                    contents: &[7],
                    segment_size: None,
                    src_ip: Some(source),
                },
                Some(interface()),
            )
            .unwrap();
        let mut bytes = [0; 128];
        let (len, observed) =
            tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&bytes[..len], &[7]);
        assert_eq!(
            observed,
            SocketAddr::new(source, base.local_addr().unwrap().port())
        );
        peer.send_to(&[8], observed).await.unwrap();
        assert_eq!(receive(&actual, true).await, 8);
        peer.send_to(&[9], observed).await.unwrap();
        assert_eq!(receive(&base, false).await, 9);
    }
}

#[tokio::test]
async fn failed_binding_and_local_bind_retire_without_emission_or_pool_entry() {
    let base = base("0.0.0.0:0");
    let source: IpAddr = "127.0.0.1".parse().unwrap();
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let binding = Binding::new([1, 2, 3]);
    binding.stale.store(true, Ordering::Relaxed);
    let retired = Arc::downgrade(&binding);
    assert_eq!(
        base.transmit_socket_with_binding(source, interface(), Some(binding))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotConnected
    );
    assert!(retired.upgrade().is_none());
    assert!(!socket2::SockRef::from(&base.io).reuse_port().unwrap());
    assert!(base.networks.0.lock().unwrap().sockets.is_empty());
    // A nonlocal address fails after the callback, and still must not publish a helper.
    let binding = Binding::new([4, 5, 6]);
    assert!(base
        .transmit_socket_with_binding(
            "192.0.2.1".parse().unwrap(),
            interface(),
            Some(binding.clone())
        )
        .is_err());
    assert_eq!(binding.calls.load(Ordering::Relaxed), 1);
    assert_eq!(Arc::strong_count(&binding), 1);
    assert!(base.networks.0.lock().unwrap().sockets.is_empty());
    assert_eq!(
        peer.try_recv(&mut [0; 128]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn capacity_is_weak_bounded_and_reusable_after_retirement() {
    let base = base("0.0.0.0:0");
    let source = "127.0.0.1".parse().unwrap();
    let mut held = Vec::new();
    for generation in 0..MAX_NETWORKS {
        held.push(acquire(
            &base,
            source,
            Binding::new([1, 2, generation as u64]),
        ));
    }
    let overflow = Binding::new([1, 2, 99]);
    assert_eq!(
        base.transmit_socket_with_binding(source, interface(), Some(overflow.clone()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(overflow.calls.load(Ordering::Relaxed), 0);
    let retired = Arc::downgrade(&held[0]);
    held.remove(0);
    assert!(retired.upgrade().is_none());
    held.push(acquire(&base, source, overflow));
    assert_eq!(base.networks.0.lock().unwrap().sockets.len(), MAX_NETWORKS);
}

#[derive(Default)]
struct Counter(AtomicUsize);

impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[tokio::test]
async fn first_insertion_wakes_an_already_pending_receiver() {
    let base = base("0.0.0.0:0");
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
    let _helper = acquire(&base, "127.0.0.1".parse().unwrap(), Binding::new([1, 2, 3]));
    assert!(counter.0.load(Ordering::Relaxed) > 0);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn network_fanin_keeps_original_and_linux_strict_companions_receiving() {
    let base = base("[::]:0");
    let strict = base
        .transmit_socket("::1".parse().unwrap(), interface())
        .unwrap()
        .unwrap();
    let _network = acquire(&base, "127.0.0.2".parse().unwrap(), Binding::new([1, 2, 3]));
    let v6 = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let v4 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = base.local_addr().unwrap().port();
    for _ in 0..8 {
        v6.send_to(&[1], strict.local_addr().unwrap())
            .await
            .unwrap();
        v4.send_to(&[2], SocketAddr::new("127.0.0.2".parse().unwrap(), port))
            .await
            .unwrap();
        v4.send_to(&[3], SocketAddr::new("127.0.0.1".parse().unwrap(), port))
            .await
            .unwrap();
    }
    let mut seen = [false; 3];
    // Nested round-robin gives core traffic every other ready Network delivery.
    for _ in 0..6 {
        seen[receive(&base, false).await as usize - 1] = true;
    }
    assert_eq!(seen, [true; 3]);
}

#[tokio::test]
async fn none_binding_preserves_legacy_ipv4_acquisition_without_reuse_options() {
    let base = base("0.0.0.0:0");
    let source = "127.0.0.1".parse().unwrap();
    assert!(base.transmit_socket(source, interface()).unwrap().is_none());
    assert!(base
        .transmit_socket_with_binding(source, interface(), None)
        .unwrap()
        .is_none());
    assert!(!socket2::SockRef::from(&base.io).reuse_port().unwrap());
    assert!(base.networks.0.lock().unwrap().sockets.is_empty());
}

mod platform;
mod provisioning;
mod receive_scope;
