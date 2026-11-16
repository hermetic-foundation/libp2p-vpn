use super::*;
use std::{future::poll_fn, io::IoSliceMut, os::fd::AsRawFd, time::Duration};

fn loopback() -> NonZeroU32 {
    NonZeroU32::new(
        std::fs::read_to_string("/sys/class/net/lo/ifindex")
            .unwrap()
            .trim()
            .parse()
            .unwrap(),
    )
    .expect("loopback interface")
}

fn base() -> Arc<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .unwrap();
    socket.set_only_v6(false).unwrap();
    socket.set_nonblocking(true).unwrap();
    socket
        .bind(&"[::]:0".parse::<SocketAddr>().unwrap().into())
        .unwrap();
    let socket: std::net::UdpSocket = socket.into();
    Arc::new(UdpSocket {
        inner: udp::UdpSocketState::new((&socket).into()).unwrap(),
        io: tokio::net::UdpSocket::from_std(socket).unwrap(),
        routes: Routes::default(),
        selected: None,
        networks: network::Networks::default(),
        network_selection: None,
    })
}

fn route() -> Route {
    Route {
        source: Ipv6Addr::LOCALHOST,
        interface: loopback(),
    }
}

fn acquire(base: &UdpSocket) -> Arc<dyn AsyncUdpSocket> {
    base.transmit_socket(IpAddr::V6(route().source), route().interface)
        .unwrap()
        .unwrap()
}

fn inode(socket: &UdpSocket) -> String {
    std::fs::read_link(format!("/proc/self/fd/{}", socket.io.as_raw_fd()))
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("socket:[")
        .unwrap()
        .strip_suffix(']')
        .unwrap()
        .to_owned()
}

fn inode_exists(inode: &str) -> bool {
    std::fs::read_to_string("/proc/self/net/udp6")
        .unwrap()
        .lines()
        .skip(1)
        .any(|line| line.split_whitespace().nth(9) == Some(inode))
}

async fn receive(base: &UdpSocket) -> u8 {
    let mut bytes = [0; 128];
    let mut meta = [udp::RecvMeta::default(); 1];
    {
        let mut buffers = [IoSliceMut::new(&mut bytes)];
        let count = tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| base.poll_recv(cx, &mut buffers, &mut meta)),
        )
        .await
        .expect("receive deadline")
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(meta[0].len, 1);
    }
    bytes[0]
}

#[tokio::test]
async fn unselected_and_ipv4_paths_leave_socket_options_and_pool_untouched() {
    let base = base();
    assert!(!socket2::SockRef::from(&base.io).reuse_port().unwrap());
    assert!(!socket2::SockRef::from(&base.io).reuse_address().unwrap());
    assert!(base
        .transmit_socket("127.0.0.1".parse().unwrap(), loopback())
        .unwrap()
        .is_none());
    assert!(!socket2::SockRef::from(&base.io).reuse_port().unwrap());
    assert!(!socket2::SockRef::from(&base.io).reuse_address().unwrap());
    assert!(base.routes.0.lock().unwrap().sockets.is_empty());
}

#[tokio::test]
async fn route_reuse_is_strict_and_last_guard_releases_actual_socket() {
    let base = base();
    assert!(!socket2::SockRef::from(&base.io).only_v6().unwrap());
    let first = acquire(&base);
    let second = acquire(&base);
    assert!(!socket2::SockRef::from(&base.io).reuse_address().unwrap());
    assert!(Arc::ptr_eq(&first, &second));
    let derived = base.routes.live(route()).unwrap();
    assert!(!socket2::SockRef::from(&derived.io).reuse_address().unwrap());
    assert_eq!(
        derived.io.local_addr().unwrap().port(),
        base.io.local_addr().unwrap().port()
    );
    assert_eq!(
        derived.io.local_addr().unwrap().ip(),
        IpAddr::V6(route().source)
    );
    assert_eq!(
        socket2::SockRef::from(&derived.io)
            .device_index_v6()
            .unwrap(),
        Some(loopback())
    );
    assert_eq!(
        socket2::SockRef::from(&base.io).device_index_v6().unwrap(),
        None
    );
    assert_eq!(
        socket2::SockRef::from(&derived.io).mark().unwrap(),
        socket2::SockRef::from(&base.io).mark().unwrap()
    );
    assert!(socket2::SockRef::from(&derived.io).only_v6().unwrap());
    assert!(!socket2::SockRef::from(&base.io).only_v6().unwrap());
    let socket_inode = inode(&derived);
    assert!(inode_exists(&socket_inode));
    drop(derived);
    drop(first);
    assert!(base.routes.live(route()).is_ok());
    drop(second);
    assert_eq!(
        base.routes.live(route()).unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
    assert!(
        !inode_exists(&socket_inode),
        "weak pool retained the kernel socket"
    );
    assert!(base.routes.0.lock().unwrap().sockets.is_empty());
    let next = acquire(&base);
    assert_eq!(
        next.local_addr().unwrap().port(),
        base.io.local_addr().unwrap().port()
    );
}

#[tokio::test]
async fn acquisition_preserves_preexisting_base_reuse_address() {
    let base = base();
    socket2::SockRef::from(&base.io)
        .set_reuse_address(true)
        .unwrap();
    let _guard = acquire(&base);
    assert!(socket2::SockRef::from(&base.io).reuse_address().unwrap());
    let derived = base.routes.live(route()).unwrap();
    assert!(!socket2::SockRef::from(&derived.io).reuse_address().unwrap());
}

#[tokio::test]
async fn cached_send_does_not_create_a_route_and_rejects_retargeting() {
    let base = base();
    let destination = "[::1]:9".parse().unwrap();
    let transmit = udp::Transmit {
        destination,
        ecn: None,
        contents: &[1],
        segment_size: None,
        src_ip: Some(IpAddr::V6(route().source)),
    };
    assert_eq!(
        base.try_send_on_interface(&transmit, Some(loopback()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotConnected
    );
    assert!(base.routes.0.lock().unwrap().sockets.is_empty());
    assert!(!socket2::SockRef::from(&base.io).reuse_port().unwrap());
    let selected = acquire(&base);
    let other = NonZeroU32::new(loopback().get() + 1).unwrap();
    assert_eq!(
        selected
            .try_send_on_interface(&transmit, Some(other))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        selected
            .transmit_socket("::2".parse().unwrap(), loopback())
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    drop(selected);
    assert_eq!(
        base.try_send_on_interface(&transmit, Some(loopback()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotConnected
    );
}

#[tokio::test]
async fn capacity_counts_live_entries_and_reclaims_all_expired_slots() {
    let base = base();
    let guard = acquire(&base);
    let derived = base.routes.live(route()).unwrap();
    let socket_inode = inode(&derived);
    {
        let mut state = base.routes.0.lock().unwrap();
        state.sockets.clear();
        // Exercise bookkeeping capacity independently of host address configuration.
        for index in 1..=MAX_ROUTES {
            let key = Route {
                source: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, index as u16),
                interface: loopback(),
            };
            state.sockets.insert(key, Arc::downgrade(&derived));
        }
    }
    assert_eq!(
        base.transmit_socket(IpAddr::V6(route().source), loopback())
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    drop(derived);
    drop(guard);
    assert!(!inode_exists(&socket_inode));
    let guard = acquire(&base);
    assert_eq!(base.routes.0.lock().unwrap().sockets.len(), 1);
    drop(guard);
    assert!(base.routes.live(route()).is_err());
    assert!(base.routes.0.lock().unwrap().sockets.is_empty());
}

#[tokio::test]
async fn receive_fan_in_is_fair_and_survives_companion_retirement() {
    let base = base();
    let selected = acquire(&base);
    let port = base.io.local_addr().unwrap().port();
    let peer4 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer6 = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    for _ in 0..3 {
        peer4
            .send_to(&[4], (std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        peer6
            .send_to(&[6], (Ipv6Addr::LOCALHOST, port))
            .await
            .unwrap();
        assert_eq!(receive(&base).await, 4);
        assert_eq!(receive(&base).await, 6);
    }
    let transmit = udp::Transmit {
        destination: peer6.local_addr().unwrap(),
        ecn: None,
        contents: &[8],
        segment_size: None,
        src_ip: Some(IpAddr::V6(route().source)),
    };
    let mut writable = selected.clone().create_io_poller();
    tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| loop {
            ready!(writable.as_mut().poll_writable(cx))?;
            match selected.try_send_on_interface(&transmit, Some(loopback())) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                result => return Poll::Ready(result),
            }
        }),
    )
    .await
    .unwrap()
    .unwrap();
    let mut bytes = [0; 1];
    let (len, source) = tokio::time::timeout(Duration::from_secs(2), peer6.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(len, 1);
    assert_eq!(bytes, [8]);
    assert_eq!(source, selected.local_addr().unwrap());
    drop(writable);
    drop(selected);
    assert!(base.routes.live(route()).is_err());
    peer6
        .send_to(&[9], (Ipv6Addr::LOCALHOST, port))
        .await
        .unwrap();
    assert_eq!(receive(&base).await, 9);
}

#[tokio::test]
async fn fresh_guards_send_before_the_first_writable_readiness_event() {
    let base = base();
    let peer = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    for value in 1..=3 {
        let selected = acquire(&base);
        let local = selected.local_addr().unwrap();
        let transmit = udp::Transmit {
            destination: peer.local_addr().unwrap(),
            ecn: None,
            contents: &[value],
            segment_size: None,
            src_ip: Some(IpAddr::V6(route().source)),
        };
        // No await or writable poll occurs between acquisition and this send.
        if value == 2 {
            selected.try_send(&transmit).unwrap();
        } else {
            selected
                .try_send_on_interface(&transmit, Some(loopback()))
                .unwrap();
        }
        let mut bytes = [0; 1];
        let (len, source) =
            tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(len, 1);
        assert_eq!(bytes, [value]);
        assert_eq!(source, local);
        peer.send_to(&[value + 10], source).await.unwrap();
        assert_eq!(receive(&base).await, value + 10);
        drop(selected);
        assert!(base.routes.live(route()).is_err());
    }
}

#[tokio::test]
async fn insertion_wakes_an_already_pending_receiver() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;
    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let base = base();
    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(counter.clone());
    let mut cx = Context::from_waker(&waker);
    let mut bytes = [0; 128];
    let mut buffers = [IoSliceMut::new(&mut bytes)];
    let mut meta = [udp::RecvMeta::default(); 1];
    assert!(base
        .poll_recv(&mut cx, &mut buffers, &mut meta)
        .is_pending());
    let previous = counter.0.load(Ordering::SeqCst);
    let _guard = acquire(&base);
    assert!(counter.0.load(Ordering::SeqCst) > previous);
}
