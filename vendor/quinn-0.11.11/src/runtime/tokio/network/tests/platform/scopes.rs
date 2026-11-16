use super::*;

fn binding_with_scope(scope: u32) -> Arc<RoutingBinding> {
    let binding = RoutingBinding::new([1, 2, 3], true);
    binding.ipv6_scope.store(scope, Ordering::Relaxed);
    binding
}

fn link_local_key(scope: Option<NonZeroU32>) -> Key {
    Key {
        identity: [1, 2, 3],
        platform_routing: true,
        ipv6_scope_id: scope,
        source: "fe80::1".parse().unwrap(),
        interface: nonexistent_interface(),
    }
}

#[test]
fn wildcard_link_local_bind_address_retains_explicit_binding_scope() {
    let key = link_local_key(NonZeroU32::new(7));
    let wildcard = "[::]:1234".parse().unwrap();
    let expected = "[fe80::1%7]:1234".parse().unwrap();
    assert_eq!(bind_address(wildcard, key).unwrap(), (expected, 7));
    assert_eq!(bind_address(expected, key).unwrap(), (expected, 7));
    crate::endpoint::validate_egress_selection(
        &ScopedSocket(wildcard),
        "[fe80::2%7]:4321".parse().unwrap(),
        key.source,
        key.interface,
        true,
        key.ipv6_scope_id,
    )
    .unwrap();
    // A known explicit base scope is sufficient without an accessor override.
    assert_eq!(
        bind_address(
            expected,
            Key {
                ipv6_scope_id: None,
                ..key
            }
        )
        .unwrap(),
        (expected, 7)
    );
}

#[test]
fn explicit_binding_base_and_destination_scopes_must_agree() {
    let key = link_local_key(NonZeroU32::new(7));
    let conflicting = "[fe80::1%8]:1234".parse().unwrap();
    assert_eq!(
        bind_address(conflicting, key).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    for (local, remote) in [
        (conflicting, "[fe80::2%7]:4321".parse().unwrap()),
        (
            "[::]:1234".parse().unwrap(),
            "[fe80::2%8]:4321".parse().unwrap(),
        ),
    ] {
        assert_eq!(
            crate::endpoint::validate_egress_selection(
                &ScopedSocket(local),
                remote,
                key.source,
                key.interface,
                true,
                key.ipv6_scope_id,
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidInput
        );
    }
    let binding = binding_with_scope(7);
    let selection = Selection {
        key,
        binding,
        scope: 7,
    };
    let transmit = udp::Transmit {
        destination: "[fe80::2%8]:4321".parse().unwrap(),
        ecn: None,
        contents: &[7],
        segment_size: None,
        src_ip: Some(key.source),
    };
    assert_eq!(
        selection
            .validate(&transmit, Some(key.interface))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
}

#[tokio::test]
async fn platform_link_local_without_explicit_scope_fails_before_binding() {
    let base = base("[::]:0");
    let binding = binding_with_scope(0);
    assert_eq!(
        base.transmit_socket_with_binding(
            "fe80::1".parse().unwrap(),
            nonexistent_interface(),
            Some(binding.clone()),
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(binding.inner.calls.load(Ordering::Relaxed), 0);
    assert!(base.networks.0.lock().unwrap().sockets.is_empty());
    assert!(!socket2::SockRef::from(&base.io).reuse_port().unwrap());
}

#[tokio::test]
async fn immutable_scope_is_keyed_and_checked_on_reuse_and_send() {
    // Loopback exercises ownership without assuming a host-assigned fe80 address.
    // The exact link-local bind address is checked in the pure bind-plan test.
    let base = base("[::]:0");
    let source = "::1".parse().unwrap();
    let binding = binding_with_scope(7);
    let helper = acquire_routed(&base, source, binding.clone());
    let key = *base
        .networks
        .0
        .lock()
        .unwrap()
        .sockets
        .keys()
        .next()
        .unwrap();
    assert_eq!(key.ipv6_scope_id, NonZeroU32::new(7));
    assert_ne!(
        key,
        Key {
            ipv6_scope_id: NonZeroU32::new(8),
            ..key
        }
    );
    let same = acquire_routed(&base, source, binding_with_scope(7));
    assert!(Arc::ptr_eq(&helper, &same));
    assert_eq!(
        base.transmit_socket_with_binding(
            source,
            nonexistent_interface(),
            Some(binding_with_scope(8)),
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        base.transmit_socket_with_binding(source, interface(), Some(binding_with_scope(8)))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    binding.ipv6_scope.store(8, Ordering::Relaxed);
    let peer = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let transmit = udp::Transmit {
        destination: peer.local_addr().unwrap(),
        ecn: None,
        contents: &[7],
        segment_size: None,
        src_ip: Some(source),
    };
    assert_eq!(
        helper.try_send(&transmit).unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
    assert_eq!(
        base.transmit_socket_with_binding(
            source,
            nonexistent_interface(),
            Some(binding_with_scope(7)),
        )
        .unwrap_err()
        .kind(),
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
    assert_eq!(base.networks.0.lock().unwrap().sockets.len(), 1);
    assert_eq!(binding.inner.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn scope_change_in_callback_retires_unpublished_socket_and_binding() {
    let base = base("[::]:0");
    let binding = binding_with_scope(7);
    binding.scope_on_bind.store(8, Ordering::Relaxed);
    assert_eq!(
        base.transmit_socket_with_binding(
            "::1".parse().unwrap(),
            nonexistent_interface(),
            Some(binding.clone()),
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::NotConnected
    );
    assert_eq!(binding.inner.calls.load(Ordering::Relaxed), 1);
    assert_eq!(Arc::strong_count(&binding), 1);
    assert!(base.networks.0.lock().unwrap().sockets.is_empty());
    assert!(!socket2::SockRef::from(&base.io).reuse_port().unwrap());
    let retired = Arc::downgrade(&binding);
    drop(binding);
    assert!(retired.upgrade().is_none());
}

#[test]
fn default_scope_preserves_forced_interface_routing() {
    assert!(Binding::new([1, 2, 3]).ipv6_scope_id().is_none());
    let key = Key {
        platform_routing: false,
        interface: NonZeroU32::new(7).unwrap(),
        ..link_local_key(None)
    };
    assert_eq!(
        bind_address("[::]:1234".parse().unwrap(), key).unwrap(),
        ("[fe80::1%7]:1234".parse().unwrap(), 7)
    );
    assert!(bind_address(
        "[::]:1234".parse().unwrap(),
        Key {
            ipv6_scope_id: NonZeroU32::new(8),
            ..key
        }
    )
    .is_err());
}
