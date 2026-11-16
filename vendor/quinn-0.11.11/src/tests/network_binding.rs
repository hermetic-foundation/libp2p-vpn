use super::*;
use crate::{AsyncUdpSocket, UdpPoller, UdpSocketBinding};
use std::{io::IoSliceMut, num::NonZeroU32, pin::Pin, sync::atomic::AtomicBool};

#[derive(Debug, Default)]
struct Binding {
    calls: AtomicUsize,
    stale: AtomicBool,
    generation: AtomicUsize,
    platform: AtomicBool,
    ipv6_scope: AtomicUsize,
}

impl UdpSocketBinding for Binding {
    fn identity(&self) -> [u64; 3] {
        [42, 7, self.generation.load(Ordering::Relaxed) as u64]
    }

    fn uses_platform_routing(&self) -> bool {
        self.platform.load(Ordering::Relaxed)
    }

    fn ipv6_scope_id(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(self.ipv6_scope.load(Ordering::Relaxed) as u32)
    }

    fn bind(&self, socket: &UdpSocket) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        assert_eq!(socket.local_addr()?.port(), 0);
        if self.stale.load(Ordering::Relaxed) {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "stale Network"));
        }
        Ok(())
    }
}

fn interface() -> NonZeroU32 {
    std::fs::read_to_string("/sys/class/net/lo/ifindex")
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

async fn exchange(sender: &crate::Connection, receiver: &crate::Connection) {
    let mut stream = sender.open_uni().await.unwrap();
    stream.write_all(b"Network-bound").await.unwrap();
    stream.finish().unwrap();
    let bytes = receiver
        .accept_uni()
        .await
        .unwrap()
        .read_to_end(128)
        .await
        .unwrap();
    assert_eq!(bytes, b"Network-bound");
}

#[tokio::test]
async fn acquisition_failures_emit_nothing_and_create_no_protocol_or_probe_owner() {
    let client = EndpointFactory::new().endpoint();
    client
        .rebind(UdpSocket::bind("0.0.0.0:0").unwrap())
        .unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_nonblocking(true).unwrap();
    let remote = peer.local_addr().unwrap();
    let source = "127.0.0.1".parse().unwrap();
    let binding = Arc::new(Binding::default());
    binding.stale.store(true, Ordering::Relaxed);
    let retired = Arc::downgrade(&binding);
    assert_eq!(
        client
            .connect_with_on_interface_and_binding(
                client.default_client_config.clone().unwrap(),
                remote,
                "localhost",
                source,
                interface(),
                Some(binding.clone()),
            )
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotConnected
    );
    assert_eq!(
        client
            .prepare_send_on_interface_and_binding(
                remote,
                source,
                interface(),
                Some(binding.clone()),
            )
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotConnected
    );
    assert_eq!(client.stats().outgoing_handshakes, 0);
    assert_eq!(client.open_connections(), 0);
    assert_eq!(binding.calls.load(Ordering::Relaxed), 2);
    drop(binding);
    assert!(retired.upgrade().is_none());
    tokio::task::yield_now().await;
    assert_eq!(
        peer.recv_from(&mut [0; 2048]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn incoming_binding_failure_is_ignored_before_protocol_acceptance() {
    timeout(Duration::from_secs(5), async {
        let factory = EndpointFactory::new();
        let client = factory.endpoint();
        let server = factory.endpoint();
        let connecting = client
            .connect(server.local_addr().unwrap(), "localhost")
            .unwrap();
        let binding = Arc::new(Binding::default());
        binding.stale.store(true, Ordering::Relaxed);
        assert!(server
            .accept()
            .await
            .unwrap()
            .accept_on_interface_and_binding(interface(), Some(binding.clone()),)
            .is_err());
        assert_eq!(server.open_connections(), 0);
        assert_eq!(server.stats().accepted_handshakes, 0);
        assert_eq!(binding.calls.load(Ordering::Relaxed), 1);
        assert_eq!(Arc::strong_count(&binding), 1);
        drop(connecting);
        client.close(0u32.into(), b"done");
        server.close(0u32.into(), b"done");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn both_families_bind_outgoing_incoming_and_probe_then_release_through_drain() {
    timeout(Duration::from_secs(20), async {
        for (local, source) in [("127.0.0.1:0", "127.0.0.1"), ("[::1]:0", "::1")] {
            let factory = EndpointFactory::new();
            let client = factory.endpoint();
            let server = factory.endpoint();
            client.rebind(UdpSocket::bind(local).unwrap()).unwrap();
            server.rebind(UdpSocket::bind(local).unwrap()).unwrap();
            let remote = server.local_addr().unwrap();
            let source = source.parse().unwrap();
            let client_binding = Arc::new(Binding::default());
            let server_binding = Arc::new(Binding::default());
            let retired_client = Arc::downgrade(&client_binding);
            let retired_server = Arc::downgrade(&server_binding);
            let guard = client
                .prepare_send_on_interface_and_binding(
                    remote,
                    source,
                    interface(),
                    Some(client_binding.clone()),
                )
                .unwrap();
            let helper = guard.socket_weak();
            let (connected, accepted) = tokio::join!(
                client
                    .connect_with_on_interface_and_binding(
                        client.default_client_config.clone().unwrap(),
                        remote,
                        "localhost",
                        source,
                        interface(),
                        Some(client_binding.clone()),
                    )
                    .unwrap(),
                async {
                    server
                        .accept()
                        .await
                        .unwrap()
                        .accept_on_interface_and_binding(interface(), Some(server_binding.clone()))
                        .unwrap()
                        .await
                }
            );
            let connected = connected.unwrap();
            let accepted = accepted.unwrap();
            assert_eq!(client_binding.calls.load(Ordering::Relaxed), 1);
            assert_eq!(server_binding.calls.load(Ordering::Relaxed), 1);
            drop(client_binding);
            drop(server_binding);
            drop(guard);
            assert!(helper.upgrade().is_some());
            exchange(&connected, &accepted).await;
            exchange(&accepted, &connected).await;
            connected.close(0u32.into(), b"done");
            accepted.closed().await;
            client.wait_idle().await;
            server.wait_idle().await;
            while helper.upgrade().is_some()
                || retired_client.upgrade().is_some()
                || retired_server.upgrade().is_some()
            {
                sleep(Duration::from_millis(10)).await;
            }
            assert!(connected.close_reason().is_some());
            assert!(accepted.close_reason().is_some());
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rebind_reacquires_the_same_network_and_releases_the_old_helper() {
    timeout(Duration::from_secs(15), async {
        let factory = EndpointFactory::new();
        let client = factory.endpoint();
        let server = factory.endpoint();
        client
            .rebind(UdpSocket::bind("0.0.0.0:0").unwrap())
            .unwrap();
        server
            .rebind(UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let source = "127.0.0.1".parse().unwrap();
        let remote = server.local_addr().unwrap();
        let binding = Arc::new(Binding::default());
        let guard = client
            .prepare_send_on_interface_and_binding(
                remote,
                source,
                interface(),
                Some(binding.clone()),
            )
            .unwrap();
        let old = guard.socket_weak();
        let (connected, accepted) = tokio::join!(
            client
                .connect_with_on_interface_and_binding(
                    client.default_client_config.clone().unwrap(),
                    remote,
                    "localhost",
                    source,
                    interface(),
                    Some(binding.clone()),
                )
                .unwrap(),
            async { server.accept().await.unwrap().await }
        );
        let connected = connected.unwrap();
        let accepted = accepted.unwrap();
        drop(guard);
        client
            .rebind(UdpSocket::bind("0.0.0.0:0").unwrap())
            .unwrap();
        while binding.calls.load(Ordering::Relaxed) < 2 || old.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
        exchange(&connected, &accepted).await;
        let retired = Arc::downgrade(&binding);
        drop(binding);
        connected.close(0u32.into(), b"done");
        accepted.closed().await;
        client.wait_idle().await;
        while retired.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

/// Models an existing runtime that has not opted into platform Network bindings.
#[derive(Debug)]
struct LegacySocket(Arc<dyn AsyncUdpSocket>);

impl AsyncUdpSocket for LegacySocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.0.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &udp::Transmit<'_>) -> io::Result<()> {
        self.0.try_send(transmit)
    }
    fn supports_interface_selection(&self) -> bool {
        true
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.0.poll_recv(cx, bufs, meta)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

#[tokio::test]
async fn default_runtime_method_preserves_none_and_rejects_some() {
    use crate::Runtime as _;
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    let socket = LegacySocket(TokioRuntime.wrap_udp_socket(socket).unwrap());
    let source = "127.0.0.1".parse().unwrap();
    assert!(socket
        .transmit_socket_with_binding(source, interface(), None)
        .unwrap()
        .is_none());
    let binding = Arc::new(Binding::default());
    assert_eq!(
        socket
            .transmit_socket_with_binding(source, interface(), Some(binding.clone()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::Unsupported
    );
    assert_eq!(binding.calls.load(Ordering::Relaxed), 0);
    binding.platform.store(true, Ordering::Relaxed);
    assert_eq!(
        socket
            .transmit_socket_with_binding(source, interface(), Some(binding.clone()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::Unsupported
    );
    assert_eq!(binding.calls.load(Ordering::Relaxed), 0);
    assert_eq!(
        socket
            .transmit_socket_with_binding("::1".parse().unwrap(), interface(), None)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Unsupported
    );
}

#[tokio::test]
async fn unsupported_rebind_cannot_discard_binding_and_error_handles_release_resources() {
    use crate::Runtime as _;
    timeout(Duration::from_secs(10), async {
        let factory = EndpointFactory::new();
        let client = factory.endpoint();
        let server = factory.endpoint();
        client
            .rebind(UdpSocket::bind("0.0.0.0:0").unwrap())
            .unwrap();
        server
            .rebind(UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let remote = server.local_addr().unwrap();
        let source = "127.0.0.1".parse().unwrap();
        let binding = Arc::new(Binding::default());
        let retired = Arc::downgrade(&binding);
        let guard = client
            .prepare_send_on_interface_and_binding(
                remote,
                source,
                interface(),
                Some(binding.clone()),
            )
            .unwrap();
        let helper = guard.socket_weak();
        let (connected, accepted) = tokio::join!(
            client
                .connect_with_on_interface_and_binding(
                    client.default_client_config.clone().unwrap(),
                    remote,
                    "localhost",
                    source,
                    interface(),
                    Some(binding.clone()),
                )
                .unwrap(),
            async { server.accept().await.unwrap().await }
        );
        let connected = connected.unwrap();
        let accepted = accepted.unwrap();
        // Exercise both drivers before rebind so a handshake failure cannot be
        // mistaken for rejection of the replacement runtime's binding support.
        exchange(&connected, &accepted).await;
        exchange(&accepted, &connected).await;
        assert!(
            connected.close_reason().is_none(),
            "client closed before rebind: {:?}",
            connected.close_reason()
        );
        assert!(
            accepted.close_reason().is_none(),
            "server closed before rebind: {:?}",
            accepted.close_reason()
        );
        drop(binding);
        drop(guard);
        assert!(helper.upgrade().is_some());
        assert!(retired.upgrade().is_some());
        let replacement = UdpSocket::bind("0.0.0.0:0").unwrap();
        replacement.set_nonblocking(true).unwrap();
        client
            .rebind_abstract(Arc::new(LegacySocket(
                TokioRuntime.wrap_udp_socket(replacement).unwrap(),
            )))
            .unwrap();
        let error = connected.closed().await;
        assert!(
            matches!(error, crate::ConnectionError::TransportError(ref error)
            if error.reason.contains("selected UDP rebind failed")),
            "unexpected rebind close reason: {error:?}"
        );
        client.wait_idle().await;
        assert!(
            helper.upgrade().is_none(),
            "retained error handle kept Network helper alive"
        );
        assert!(
            retired.upgrade().is_none(),
            "retained error handle kept Network binding alive"
        );
        assert_eq!(client.open_connections(), 0);
        assert!(connected.close_reason().is_some());
        connected.close(0u32.into(), b"cleanup after failure");
        assert_eq!(connected.closed().await.to_string(), error.to_string());
        accepted.close(0u32.into(), b"done");
        server.close(0u32.into(), b"done");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn platform_routing_handshake_accept_probe_and_rebind_ignore_base_interface() {
    timeout(Duration::from_secs(20), async {
        for (local, source) in [("127.0.0.1:0", "127.0.0.1"), ("[::1]:0", "::1")] {
            let factory = EndpointFactory::new();
            let client = factory.endpoint();
            let server = factory.endpoint();
            client.rebind(UdpSocket::bind(local).unwrap()).unwrap();
            server.rebind(UdpSocket::bind(local).unwrap()).unwrap();
            let remote = server.local_addr().unwrap();
            let source = source.parse().unwrap();
            let metadata_interface = NonZeroU32::new(i32::MAX as u32).unwrap();
            let client_binding = Arc::new(Binding::default());
            let server_binding = Arc::new(Binding::default());
            client_binding.platform.store(true, Ordering::Relaxed);
            server_binding.platform.store(true, Ordering::Relaxed);
            // A no-op callback on loopback tests independent routing, not NDK binding.
            let guard = client
                .prepare_send_on_interface_and_binding(
                    remote,
                    source,
                    metadata_interface,
                    Some(client_binding.clone()),
                )
                .unwrap();
            guard.send(&[7; 64]).unwrap();
            let (connected, accepted) = tokio::join!(
                client
                    .connect_with_on_interface_and_binding(
                        client.default_client_config.clone().unwrap(),
                        remote,
                        "localhost",
                        source,
                        metadata_interface,
                        Some(client_binding.clone()),
                    )
                    .unwrap(),
                async {
                    server
                        .accept()
                        .await
                        .unwrap()
                        .accept_on_interface_and_binding(
                            metadata_interface,
                            Some(server_binding.clone()),
                        )
                        .unwrap()
                        .await
                }
            );
            let connected = connected.unwrap();
            let accepted = accepted.unwrap();
            exchange(&connected, &accepted).await;
            exchange(&accepted, &connected).await;
            assert_eq!(client_binding.calls.load(Ordering::Relaxed), 1);
            assert_eq!(server_binding.calls.load(Ordering::Relaxed), 1);
            drop(guard);
            client.rebind(UdpSocket::bind(local).unwrap()).unwrap();
            while client_binding.calls.load(Ordering::Relaxed) < 2 {
                tokio::task::yield_now().await;
            }
            exchange(&connected, &accepted).await;
            exchange(&accepted, &connected).await;
            connected.close(0u32.into(), b"done");
            accepted.closed().await;
            client.wait_idle().await;
            server.wait_idle().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rebind_rejects_changed_platform_mode_before_creating_replacement_helper() {
    timeout(Duration::from_secs(10), async {
        let factory = EndpointFactory::new();
        let client = factory.endpoint();
        let server = factory.endpoint();
        let remote = server.local_addr().unwrap();
        let source = "127.0.0.1".parse().unwrap();
        let metadata_interface = NonZeroU32::new(i32::MAX as u32).unwrap();
        let binding = Arc::new(Binding::default());
        binding.platform.store(true, Ordering::Relaxed);
        let guard = client
            .prepare_send_on_interface_and_binding(
                remote,
                source,
                metadata_interface,
                Some(binding.clone()),
            )
            .unwrap();
        let helper = guard.socket_weak();
        let (connected, accepted) = tokio::join!(
            client
                .connect_with_on_interface_and_binding(
                    client.default_client_config.clone().unwrap(),
                    remote,
                    "localhost",
                    source,
                    metadata_interface,
                    Some(binding.clone()),
                )
                .unwrap(),
            async { server.accept().await.unwrap().await }
        );
        let connected = connected.unwrap();
        let accepted = accepted.unwrap();
        exchange(&connected, &accepted).await;
        drop(guard);
        binding.platform.store(false, Ordering::Relaxed);
        client
            .rebind(UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let error = connected.closed().await;
        assert!(
            matches!(error, crate::ConnectionError::TransportError(ref error)
            if error.reason.contains("selected UDP rebind failed")
                && error.reason.contains("routing mode changed")),
            "unexpected rebind error: {error:?}"
        );
        client.wait_idle().await;
        assert_eq!(binding.calls.load(Ordering::Relaxed), 1);
        assert!(helper.upgrade().is_none());
        assert_eq!(Arc::strong_count(&binding), 1);
        accepted.close(0u32.into(), b"done");
        server.close(0u32.into(), b"done");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rebind_retains_explicit_scope_and_rejects_mutation_before_reacquisition() {
    timeout(Duration::from_secs(20), async {
        // Assigned loopback exercises rebind ownership; the pure bind-plan test
        // separately proves that wildcard fe80 companions receive the scope.
        for mutate in [false, true] {
            let factory = EndpointFactory::new();
            let client = factory.endpoint();
            let server = factory.endpoint();
            client.rebind(UdpSocket::bind("[::1]:0").unwrap()).unwrap();
            server.rebind(UdpSocket::bind("[::1]:0").unwrap()).unwrap();
            let remote = server.local_addr().unwrap();
            let source = "::1".parse().unwrap();
            let index = NonZeroU32::new(i32::MAX as u32).unwrap();
            let binding = Arc::new(Binding::default());
            binding.platform.store(true, Ordering::Relaxed);
            binding.ipv6_scope.store(7, Ordering::Relaxed);
            let guard = client
                .prepare_send_on_interface_and_binding(remote, source, index, Some(binding.clone()))
                .unwrap();
            let helper = guard.socket_weak();
            let (connected, accepted) = tokio::join!(
                client
                    .connect_with_on_interface_and_binding(
                        client.default_client_config.clone().unwrap(),
                        remote,
                        "localhost",
                        source,
                        index,
                        Some(binding.clone()),
                    )
                    .unwrap(),
                async { server.accept().await.unwrap().await }
            );
            let connected = connected.unwrap();
            let accepted = accepted.unwrap();
            exchange(&connected, &accepted).await;
            drop(guard);
            if mutate {
                binding.ipv6_scope.store(8, Ordering::Relaxed);
            }
            client.rebind(UdpSocket::bind("[::1]:0").unwrap()).unwrap();
            if mutate {
                let error = connected.closed().await;
                assert!(
                    matches!(error, crate::ConnectionError::TransportError(ref error)
                    if error.reason.contains("selected UDP rebind failed")
                        && error.reason.contains("IPv6 scope changed")),
                    "unexpected error: {error:?}"
                );
                client.wait_idle().await;
                assert_eq!(binding.calls.load(Ordering::Relaxed), 1);
                assert!(helper.upgrade().is_none());
                assert_eq!(Arc::strong_count(&binding), 1);
                accepted.close(0u32.into(), b"done");
                server.close(0u32.into(), b"done");
            } else {
                while binding.calls.load(Ordering::Relaxed) < 2 {
                    tokio::task::yield_now().await;
                }
                assert!(helper.upgrade().is_none());
                exchange(&connected, &accepted).await;
                exchange(&accepted, &connected).await;
                assert_eq!(binding.ipv6_scope_id(), NonZeroU32::new(7));
                connected.close(0u32.into(), b"done");
                accepted.closed().await;
                client.wait_idle().await;
                server.wait_idle().await;
            }
        }
    })
    .await
    .unwrap();
}
