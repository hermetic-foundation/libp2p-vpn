//! Real loopback packet-info with model Network bindings, not NDK/CLAT proof.

use super::*;
use crate::UdpRecvScope;

async fn scoped_receive(socket: &dyn AsyncUdpSocket) -> (u8, udp::RecvMeta, UdpRecvScope) {
    let mut bytes = [0; 128];
    let mut bufs = [IoSliceMut::new(&mut bytes)];
    let mut meta = [udp::RecvMeta::default()];
    let mut scopes = [UdpRecvScope {
        network: Some([99; 3]),
        interface_index: NonZeroU32::new(99),
    }; 2];
    let count = tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| socket.poll_recv_scoped(cx, &mut bufs, &mut meta, &mut scopes)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(count, 1);
    assert_eq!(scopes[1], UdpRecvScope::default());
    (bytes[0], meta[0], scopes[0])
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn overlapping_local_addresses_report_exact_companion_and_kernel_iif_not_route_hint() {
    for (local, source, peer_bind) in [
        ("0.0.0.0:0", "127.0.0.2", "127.0.0.1:0"),
        ("[::]:0", "::1", "[::1]:0"),
    ] {
        let base = base(local);
        let source: IpAddr = source.parse().unwrap();
        let mut held = Vec::new();
        let mut peers = Vec::new();
        // Each word can distinguish an immutable Network/incarnation/owner.
        for id in [[1, 2, 3], [9, 2, 3], [1, 9, 3], [1, 2, 9]] {
            let binding = super::platform::RoutingBinding::new(id, true);
            let helper = super::platform::acquire_routed(&base, source, binding);
            let actual = {
                let state = base.networks.0.lock().unwrap();
                state
                    .sockets
                    .iter()
                    .find(|(key, _)| key.identity == id)
                    .unwrap()
                    .1
                    .upgrade()
                    .unwrap()
            };
            let peer = tokio::net::UdpSocket::bind(peer_bind).await.unwrap();
            // A unique connected peer tuple deterministically selects this FD
            // despite every companion sharing the same local IP and port.
            actual.io.connect(peer.local_addr().unwrap()).await.unwrap();
            peers.push((peer, id));
            held.push(helper);
        }
        for helper in &held {
            assert_eq!(helper.local_addr().unwrap(), held[0].local_addr().unwrap());
        }
        for (index, (peer, id)) in peers.iter().enumerate() {
            peer.send_to(&[index as u8], held[index].local_addr().unwrap())
                .await
                .unwrap();
            let (byte, meta, scope) = scoped_receive(&*base).await;
            assert_eq!(byte, index as u8);
            assert_eq!(meta.dst_ip, Some(source));
            assert_eq!(scope.network, Some(*id));
            assert_eq!(scope.interface_index, Some(interface()));
            assert_ne!(
                scope.interface_index,
                Some(super::platform::nonexistent_interface())
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn sources_base_and_strict_fanin_preserve_kernel_iif_without_inventing_network() {
    let base = base("[::]:0");
    let id = [4, 5, 6];
    let mut held = Vec::new();
    for source in ["127.0.0.2", "127.0.0.3"] {
        held.push(acquire(&base, source.parse().unwrap(), Binding::new(id)));
    }
    let strict = base
        .transmit_socket("::1".parse().unwrap(), interface())
        .unwrap()
        .unwrap();
    let port = base.local_addr().unwrap().port();
    for (index, (destination, network)) in [
        (SocketAddr::new("127.0.0.1".parse().unwrap(), port), None),
        (held[0].local_addr().unwrap(), Some(id)),
        (held[1].local_addr().unwrap(), Some(id)),
        (strict.local_addr().unwrap(), None),
    ]
    .into_iter()
    .enumerate()
    {
        let peer = tokio::net::UdpSocket::bind(if destination.is_ipv4() {
            "127.0.0.1:0"
        } else {
            "[::1]:0"
        })
        .await
        .unwrap();
        peer.send_to(&[index as u8], destination).await.unwrap();
        let (byte, meta, scope) = scoped_receive(&*base).await;
        assert_eq!(byte, index as u8);
        assert_eq!(
            meta.dst_ip.map(|ip| ip.to_canonical()),
            Some(destination.ip())
        );
        assert_eq!(scope.network, network);
        assert_eq!(scope.interface_index, Some(interface()));
    }
}

#[derive(Debug, Default)]
struct LegacySocket(AtomicUsize);

impl AsyncUdpSocket for LegacySocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn crate::UdpPoller>> {
        unreachable!()
    }
    fn try_send(&self, _: &udp::Transmit<'_>) -> io::Result<()> {
        unreachable!()
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok("127.0.0.1:1234".parse().unwrap())
    }
    fn poll_recv(
        &self,
        _: &mut Context<'_>,
        _: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.0.fetch_add(1, Ordering::Relaxed);
        // Keep the public RecvMeta literal contract unchanged.
        meta[0] = udp::RecvMeta {
            addr: "127.0.0.1:4321".parse().unwrap(),
            len: 1,
            stride: 1,
            ecn: None,
            dst_ip: None,
        };
        Poll::Ready(Ok(1))
    }
}

#[test]
fn legacy_implementor_defaults_to_no_scope_and_rejects_short_scope_output() {
    let socket = LegacySocket::default();
    let waker = Waker::from(Arc::new(Counter::default()));
    let mut cx = Context::from_waker(&waker);
    let mut bytes = [0; 1];
    let mut bufs = [IoSliceMut::new(&mut bytes)];
    let mut meta = [udp::RecvMeta::default()];
    let mut scopes = [UdpRecvScope {
        network: Some([1, 2, 3]),
        interface_index: Some(interface()),
    }];
    assert!(matches!(
        socket.poll_recv_scoped(&mut cx, &mut bufs, &mut meta, &mut scopes),
        Poll::Ready(Ok(1))
    ));
    assert_eq!(scopes, [UdpRecvScope::default()]);
    assert!(
        matches!(socket.poll_recv_scoped(&mut cx, &mut bufs, &mut meta, &mut []), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidInput)
    );
    assert_eq!(socket.0.load(Ordering::Relaxed), 1);
}
