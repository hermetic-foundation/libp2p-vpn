use super::*;
use std::sync::atomic::AtomicU32;

#[derive(Debug)]
pub(super) struct RoutingBinding {
    inner: Arc<Binding>,
    platform: AtomicBool,
    flip_on_bind: AtomicBool,
    ipv6_scope: AtomicU32,
    scope_on_bind: AtomicU32,
}

impl RoutingBinding {
    pub(super) fn new(id: [u64; 3], platform: bool) -> Arc<Self> {
        Arc::new(Self {
            inner: Binding::new(id),
            platform: AtomicBool::new(platform),
            flip_on_bind: AtomicBool::new(false),
            ipv6_scope: AtomicU32::new(0),
            scope_on_bind: AtomicU32::new(0),
        })
    }
}

impl UdpSocketBinding for RoutingBinding {
    fn identity(&self) -> [u64; 3] {
        self.inner.identity()
    }

    fn uses_platform_routing(&self) -> bool {
        self.platform.load(Ordering::Relaxed)
    }

    fn ipv6_scope_id(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(self.ipv6_scope.load(Ordering::Relaxed))
    }

    fn bind(&self, socket: &std::net::UdpSocket) -> io::Result<()> {
        // No-op binding on loopback simulates an independent platform route;
        // this is not proof of Android Network/device acquisition.
        self.inner.bind(socket)?;
        if self.flip_on_bind.load(Ordering::Relaxed) {
            self.platform.fetch_xor(true, Ordering::Relaxed);
        }
        let scope = self.scope_on_bind.load(Ordering::Relaxed);
        if scope != 0 {
            self.ipv6_scope.store(scope, Ordering::Relaxed);
        }
        Ok(())
    }
}

pub(super) fn nonexistent_interface() -> NonZeroU32 {
    NonZeroU32::new(i32::MAX as u32).unwrap()
}

pub(super) fn acquire_routed(
    base: &UdpSocket,
    source: IpAddr,
    binding: Arc<RoutingBinding>,
) -> Arc<dyn AsyncUdpSocket> {
    base.transmit_socket_with_binding(source, nonexistent_interface(), Some(binding))
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn platform_route_ignores_metadata_ifindex_for_both_families_and_dual_stack() {
    for (local, source, peer_bind) in [
        ("0.0.0.0:0", "127.0.0.2", "127.0.0.1:0"),
        ("[::]:0", "127.0.0.2", "127.0.0.1:0"),
        ("[::]:0", "::1", "[::1]:0"),
    ] {
        let base = base(local);
        let source: IpAddr = source.parse().unwrap();
        let binding = RoutingBinding::new([1, 2, 3], true);
        let helper = acquire_routed(&base, source, binding.clone());
        assert_eq!(binding.inner.calls.load(Ordering::Relaxed), 1);
        assert_eq!(helper.local_addr().unwrap().ip(), source);
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
        assert!(!socket2::SockRef::from(&actual.io).reuse_address().unwrap());
        assert!(!socket2::SockRef::from(&base.io).reuse_address().unwrap());
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
        let transmit = udp::Transmit {
            destination,
            ecn: None,
            contents: &[7],
            segment_size: None,
            src_ip: Some(source),
        };
        // Both entry points must honor the same immutable platform mode.
        for selected in [false, true] {
            if selected {
                helper
                    .try_send_on_interface(&transmit, Some(nonexistent_interface()))
                    .unwrap();
            } else {
                helper.try_send(&transmit).unwrap();
            }
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
            assert_eq!(receive(&base, false).await, 8);
        }
        for invalid in [
            udp::Transmit {
                src_ip: None,
                ..transmit
            },
            udp::Transmit {
                src_ip: Some("192.0.2.1".parse().unwrap()),
                ..transmit
            },
            udp::Transmit {
                destination: if source.is_ipv4() {
                    "[::1]:9"
                } else {
                    "127.0.0.1:9"
                }
                .parse()
                .unwrap(),
                ..transmit
            },
        ] {
            assert_eq!(
                helper.try_send(&invalid).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(
            helper
                .try_send_on_interface(&transmit, Some(interface()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            peer.try_recv(&mut [0; 128]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}

#[tokio::test]
async fn default_forced_route_still_rejects_nonexistent_interfaces() {
    for (local, source, peer_bind) in [
        ("0.0.0.0:0", "127.0.0.2", "127.0.0.1:0"),
        ("[::]:0", "::1", "[::1]:0"),
    ] {
        let base = base(local);
        let binding = Binding::new([1, 2, 3]);
        assert!(!binding.uses_platform_routing());
        let helper = base
            .transmit_socket_with_binding(
                source.parse().unwrap(),
                nonexistent_interface(),
                Some(binding),
            )
            .unwrap()
            .unwrap();
        let peer = tokio::net::UdpSocket::bind(peer_bind).await.unwrap();
        let transmit = udp::Transmit {
            destination: peer.local_addr().unwrap(),
            ecn: None,
            contents: &[7],
            segment_size: None,
            src_ip: Some(source.parse().unwrap()),
        };
        assert!(helper
            .try_send_on_interface(&transmit, Some(nonexistent_interface()))
            .is_err());
        assert_eq!(
            peer.try_recv(&mut [0; 128]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}

#[tokio::test]
async fn cache_and_existing_helper_reject_routing_mode_changes_for_live_identity() {
    let base = base("0.0.0.0:0");
    let source = "127.0.0.1".parse().unwrap();
    let binding = RoutingBinding::new([1, 2, 3], true);
    let helper = acquire_routed(&base, source, binding.clone());
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let transmit = udp::Transmit {
        destination: peer.local_addr().unwrap(),
        ecn: None,
        contents: &[7],
        segment_size: None,
        src_ip: Some(source),
    };
    let key = *base
        .networks
        .0
        .lock()
        .unwrap()
        .sockets
        .keys()
        .next()
        .unwrap();
    assert!(key.platform_routing);
    assert_ne!(
        key,
        Key {
            platform_routing: false,
            ..key
        }
    );
    let conflicting = RoutingBinding::new([1, 2, 3], false);
    for (source, index) in [
        (source, nonexistent_interface()),
        ("127.0.0.2".parse().unwrap(), interface()),
    ] {
        assert_eq!(
            base.transmit_socket_with_binding(source, index, Some(conflicting.clone()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
    assert_eq!(conflicting.inner.calls.load(Ordering::Relaxed), 0);
    binding.platform.store(false, Ordering::Relaxed);
    assert_eq!(
        base.transmit_socket_with_binding(
            source,
            nonexistent_interface(),
            Some(RoutingBinding::new([1, 2, 3], true)),
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::NotConnected
    );
    assert_eq!(
        helper.try_send(&transmit).unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
    assert!(base
        .transmit_socket_with_binding(source, nonexistent_interface(), Some(binding.clone()))
        .is_err());
    assert!(helper
        .transmit_socket_with_binding(source, nonexistent_interface(), Some(binding.clone()))
        .is_err());
    assert_eq!(
        peer.try_recv(&mut [0; 128]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    binding.platform.store(true, Ordering::Relaxed);
    let reused = acquire_routed(&base, source, binding.clone());
    assert!(Arc::ptr_eq(&helper, &reused));
    assert_eq!(binding.inner.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn mixed_routing_modes_share_capacity_and_retire_without_extra_slots() {
    let base = base("0.0.0.0:0");
    let source = "127.0.0.1".parse().unwrap();
    let mut held = Vec::new();
    for generation in 0..MAX_NETWORKS {
        held.push(acquire_routed(
            &base,
            source,
            RoutingBinding::new([1, 2, generation as u64], generation % 2 == 0),
        ));
    }
    let overflow = RoutingBinding::new([1, 2, 99], true);
    assert_eq!(
        base.transmit_socket_with_binding(source, nonexistent_interface(), Some(overflow.clone()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(overflow.inner.calls.load(Ordering::Relaxed), 0);
    let retired = Arc::downgrade(&held[0]);
    held.remove(0);
    assert!(retired.upgrade().is_none());
    held.push(acquire_routed(&base, source, overflow));
    assert_eq!(base.networks.0.lock().unwrap().sockets.len(), MAX_NETWORKS);
}

#[tokio::test]
async fn routing_mode_change_inside_callback_is_rejected_before_local_bind() {
    let base = base("0.0.0.0:0");
    let binding = RoutingBinding::new([1, 2, 3], true);
    binding.flip_on_bind.store(true, Ordering::Relaxed);
    assert_eq!(
        base.transmit_socket_with_binding(
            "127.0.0.1".parse().unwrap(),
            nonexistent_interface(),
            Some(binding.clone())
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::NotConnected
    );
    assert_eq!(binding.inner.calls.load(Ordering::Relaxed), 1);
    assert_eq!(Arc::strong_count(&binding), 1);
    assert!(base.networks.0.lock().unwrap().sockets.is_empty());
    assert!(!socket2::SockRef::from(&base.io).reuse_port().unwrap());
}

#[test]
fn link_local_scope_validation_uses_only_known_platform_scopes() {
    let binding = RoutingBinding::new([1, 2, 3], true);
    let key = Key {
        identity: binding.identity(),
        platform_routing: true,
        ipv6_scope_id: None,
        source: "fe80::1".parse().unwrap(),
        interface: nonexistent_interface(),
    };
    let mut selection = Selection {
        key,
        binding,
        scope: 0,
    };
    let mut transmit = udp::Transmit {
        destination: "[fe80::2%7]:9".parse().unwrap(),
        ecn: None,
        contents: &[7],
        segment_size: None,
        src_ip: Some(key.source),
    };
    selection.validate(&transmit, Some(key.interface)).unwrap();
    selection.scope = 7;
    selection.validate(&transmit, Some(key.interface)).unwrap();
    transmit.destination = "[fe80::2%8]:9".parse().unwrap();
    assert_eq!(
        selection
            .validate(&transmit, Some(key.interface))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    transmit.destination = "[fe80::2]:9".parse().unwrap();
    selection.validate(&transmit, Some(key.interface)).unwrap();
}

#[derive(Debug)]
struct ScopedSocket(SocketAddr);

impl AsyncUdpSocket for ScopedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn crate::UdpPoller>> {
        unreachable!()
    }
    fn try_send(&self, _: &udp::Transmit<'_>) -> io::Result<()> {
        unreachable!()
    }
    fn supports_interface_selection(&self) -> bool {
        true
    }
    fn poll_recv(
        &self,
        _: &mut Context<'_>,
        _: &mut [IoSliceMut<'_>],
        _: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        unreachable!()
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.0)
    }
}

#[test]
fn endpoint_scopes_are_checked_against_known_scope_not_platform_metadata() {
    let local = ScopedSocket("[fe80::1%7]:1234".parse().unwrap());
    let source = "fe80::1".parse().unwrap();
    let remote = "[fe80::2%7]:4321".parse().unwrap();
    crate::endpoint::validate_egress_selection(
        &local,
        remote,
        source,
        nonexistent_interface(),
        true,
        None,
    )
    .unwrap();
    assert!(crate::endpoint::validate_egress_selection(
        &local,
        remote,
        source,
        nonexistent_interface(),
        false,
        None,
    )
    .is_err());
    assert!(crate::endpoint::validate_egress_selection(
        &local,
        "[fe80::2%8]:4321".parse().unwrap(),
        source,
        nonexistent_interface(),
        true,
        None,
    )
    .is_err());
    let wildcard = ScopedSocket("[::]:1234".parse().unwrap());
    crate::endpoint::validate_egress_selection(
        &wildcard,
        remote,
        source,
        nonexistent_interface(),
        true,
        None,
    )
    .unwrap();
}

mod scopes;
