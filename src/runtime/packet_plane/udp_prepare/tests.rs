use super::*;

async fn fixture(local: &str, remote: &str) -> (PacketPlaneRuntime, tokio::net::UdpSocket, PeerId) {
    let mut runtime = PacketPlaneRuntime::bind(vec![local.parse().unwrap()])
        .await
        .unwrap();
    runtime.follow_physical_routes("absent-pv".into());
    let remote = tokio::net::UdpSocket::bind(remote).await.unwrap();
    let peer = NodeIdentity::generate_ed25519()
        .unwrap()
        .peer_id
        .parse()
        .unwrap();
    (runtime, remote, peer)
}

#[tokio::test]
async fn preparation_is_silent_and_adoption_preserves_exact_socket_tuple_once() {
    for (local, remote) in [
        ("0.0.0.0:0", "127.0.0.1:0"),
        ("[::]:0", "[::1]:0"),
        ("[::]:0", "127.0.0.1:0"),
    ] {
        let (runtime, receiver, peer) = fixture(local, remote).await;
        let destination = receiver.local_addr().unwrap();
        let prepared = runtime
            .udp_preparation(peer, destination, false)
            .unwrap()
            .prepare()
            .await
            .unwrap();
        assert_eq!(
            prepared.source().port(),
            runtime.primary_listener().unwrap().port()
        );
        assert_eq!(prepared.source().is_ipv4(), destination.is_ipv4());
        assert_eq!(
            receiver.try_recv(&mut [0; 32]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(!runtime.has_session(peer));
        let binding = prepared.bind_endpoint(prepared.source(), &[]).unwrap();
        let duplicate = binding.clone();
        let routes = binding
            .adopt(&runtime, peer, prepared.source(), destination)
            .unwrap();
        let route = routes.sockets[0].path.get().unwrap();
        assert_eq!(route.lease.local_addr, prepared.source());
        assert_eq!(route.lease.context.destination, destination);
        assert_eq!(
            duplicate
                .adopt(&runtime, peer, prepared.source(), destination)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        route.send(b"adopted").await.unwrap();
        let mut bytes = [0; 32];
        let (len, source) =
            tokio::time::timeout(Duration::from_secs(2), receiver.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&bytes[..len], b"adopted");
        assert_eq!(source, prepared.source());
    }
}

#[tokio::test]
async fn foreign_source_mapping_requires_explicit_configuration_and_never_transmits_during_binding()
{
    let (runtime, receiver, peer) = fixture("0.0.0.0:0", "127.0.0.1:0").await;
    let prepared = runtime
        .udp_preparation(peer, receiver.local_addr().unwrap(), false)
        .unwrap()
        .prepare()
        .await
        .unwrap();
    let claimed: SocketAddr = "203.0.113.9:45000".parse().unwrap();
    assert_eq!(
        prepared.bind_endpoint(claimed, &[]).unwrap_err().kind(),
        io::ErrorKind::AddrNotAvailable
    );
    let explicit = prepared.bind_endpoint(claimed, &[claimed]).unwrap();
    assert_eq!(explicit.endpoint(), claimed);
    assert_eq!(explicit.source(), prepared.source());
    assert_ne!(explicit.source(), claimed);
    assert!(explicit.is_current());
    assert!(!runtime.has_session(peer));
    assert_eq!(
        receiver.try_recv(&mut [0; 32]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    for invalid in [
        "0.0.0.0:45000",
        "224.0.0.1:45000",
        "127.0.0.1:0",
        "[2001:db8::1]:45000",
    ] {
        let invalid = invalid.parse().unwrap();
        assert_eq!(
            prepared
                .bind_endpoint(invalid, &[invalid])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}

#[tokio::test]
async fn wrong_peer_runtime_or_tuple_cannot_consume_prepared_owner() {
    let (runtime, receiver, peer) = fixture("127.0.0.1:0", "127.0.0.1:0").await;
    let destination = receiver.local_addr().unwrap();
    let prepared = runtime
        .udp_preparation(peer, destination, false)
        .unwrap()
        .prepare()
        .await
        .unwrap();
    let binding = prepared.bind_endpoint(prepared.source(), &[]).unwrap();
    let (other, _, other_peer) = fixture("127.0.0.1:0", "127.0.0.1:0").await;
    let wrong = SocketAddr::new(
        destination.ip(),
        if destination.port() == 1 { 2 } else { 1 },
    );
    assert!(
        binding
            .clone()
            .adopt(&other, peer, prepared.source(), destination)
            .is_err()
    );
    assert!(
        binding
            .clone()
            .adopt(&runtime, other_peer, prepared.source(), destination)
            .is_err()
    );
    assert!(
        binding
            .clone()
            .adopt(&runtime, peer, wrong, destination)
            .is_err()
    );
    assert!(
        binding
            .clone()
            .adopt(&runtime, peer, prepared.source(), wrong)
            .is_err()
    );
    assert!(
        binding
            .adopt(&runtime, peer, prepared.source(), destination)
            .is_ok()
    );
}

#[tokio::test]
async fn cancellation_or_epoch_retirement_fences_every_prepared_clone() {
    for cancel in [true, false] {
        let (runtime, receiver, peer) = fixture("127.0.0.1:0", "127.0.0.1:0").await;
        let destination = receiver.local_addr().unwrap();
        let work = runtime.udp_preparation(peer, destination, false).unwrap();
        let prepared = work.clone().prepare().await.unwrap();
        let source = prepared.source();
        let binding = prepared.bind_endpoint(source, &[]).unwrap();
        if cancel {
            work.cancel();
        } else {
            runtime
                .udp_owner
                .as_ref()
                .unwrap()
                .retire_observer_for_test();
        }
        assert!(!work.is_current());
        assert!(!prepared.is_current());
        assert!(!binding.is_current());
        assert!(prepared.bind_endpoint(source, &[]).is_err());
        assert!(binding.adopt(&runtime, peer, source, destination).is_err());
        assert_eq!(
            receiver.try_recv(&mut [0; 32]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}

#[tokio::test]
async fn same_destination_transfer_preserves_the_prepared_owner_and_one_time_adoption() {
    for (local, remote) in [
        ("0.0.0.0:0", "127.0.0.1:0"),
        ("[::]:0", "[::1]:0"),
        ("[::]:0", "127.0.0.1:0"),
    ] {
        let (runtime, receiver, peer) = fixture(local, remote).await;
        let destination = receiver.local_addr().unwrap();
        let prepared = runtime
            .udp_preparation(peer, destination, false)
            .unwrap()
            .prepare()
            .await
            .unwrap();
        let source = prepared.source();
        let binding = prepared.bind_endpoint(source, &[]).unwrap();
        let duplicate = binding.clone();
        let adopted_duplicate = binding.clone();
        drop(prepared);

        let transferred = binding.into_preparation(destination).unwrap();
        assert!(transferred.is_current());
        assert_eq!(transferred.destination(), destination);
        assert!(duplicate.is_current());
        let prepared = transferred.prepare().await.unwrap();
        assert_eq!(prepared.source(), source);
        assert_eq!(
            receiver.try_recv(&mut [0; 32]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let routes = prepared
            .bind_endpoint(source, &[])
            .unwrap()
            .adopt(&runtime, peer, source, destination)
            .unwrap();
        assert_eq!(
            duplicate
                .adopt(&runtime, peer, source, destination)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(adopted_duplicate.into_preparation(destination).is_none());
        let route = routes.sockets[0].path.get().unwrap();
        assert_eq!(route.lease.local_addr, source);
        assert_eq!(route.lease.context.destination, destination);
        route.send(b"transferred").await.unwrap();
        let mut bytes = [0; 32];
        let (len, actual_source) =
            tokio::time::timeout(Duration::from_secs(2), receiver.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&bytes[..len], b"transferred");
        assert_eq!(actual_source, source);
    }
}

#[tokio::test]
async fn transfer_rejects_changed_destination_or_retired_owner() {
    for retirement in [None, Some(true), Some(false)] {
        let (runtime, receiver, peer) = fixture("127.0.0.1:0", "127.0.0.1:0").await;
        let destination = receiver.local_addr().unwrap();
        let work = runtime.udp_preparation(peer, destination, false).unwrap();
        let prepared = work.clone().prepare().await.unwrap();
        let binding = prepared.bind_endpoint(prepared.source(), &[]).unwrap();
        let requested = match retirement {
            None => SocketAddr::new(
                destination.ip(),
                if destination.port() == 1 { 2 } else { 1 },
            ),
            Some(true) => {
                work.cancel();
                destination
            }
            Some(false) => {
                runtime
                    .udp_owner
                    .as_ref()
                    .unwrap()
                    .retire_observer_for_test();
                destination
            }
        };
        drop(work);
        drop(prepared);
        assert!(binding.into_preparation(requested).is_none());
        assert!(!runtime.has_session(peer));
        assert_eq!(
            receiver.try_recv(&mut [0; 32]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}

#[tokio::test]
async fn explicit_failure_fences_preparation_route_and_binding_clones() {
    for fail_binding in [false, true] {
        for kind in [io::ErrorKind::TimedOut, io::ErrorKind::ConnectionReset] {
            let (runtime, receiver, peer) = fixture("127.0.0.1:0", "127.0.0.1:0").await;
            let destination = receiver.local_addr().unwrap();
            let work = runtime.udp_preparation(peer, destination, false).unwrap();
            let work_clone = work.clone();
            let prepared = work.clone().prepare().await.unwrap();
            let route_clone = prepared.clone();
            let source = prepared.source();
            let binding = prepared.bind_endpoint(source, &[]).unwrap();
            let binding_clone = binding.clone();
            let now = Instant::now();
            if fail_binding {
                binding.failed(kind, now);
            } else {
                work.failed(kind, now);
            }
            drop(binding);
            drop(work);

            assert!(!work_clone.is_current());
            assert!(!prepared.is_current());
            assert!(!route_clone.is_current());
            assert!(!binding_clone.is_current());
            assert!(prepared.bind_endpoint(source, &[]).is_err());
            assert!(work_clone.prepare().await.is_err());
            assert!(
                binding_clone
                    .clone()
                    .into_preparation(destination)
                    .is_none()
            );
            assert!(
                binding_clone
                    .adopt(&runtime, peer, source, destination)
                    .is_err()
            );
            assert_eq!(
                receiver.try_recv(&mut [0; 32]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }
}

#[tokio::test]
async fn explicit_failure_before_preparation_fences_every_work_clone() {
    let (runtime, receiver, peer) = fixture("127.0.0.1:0", "127.0.0.1:0").await;
    let work = runtime
        .udp_preparation(peer, receiver.local_addr().unwrap(), false)
        .unwrap();
    let duplicate = work.clone();
    work.failed(io::ErrorKind::TimedOut, Instant::now());
    drop(work);
    assert!(!duplicate.is_current());
    assert!(duplicate.prepare().await.is_err());
    assert_eq!(
        receiver.try_recv(&mut [0; 32]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

async fn source_candidate(
    local: &str,
    remote: &str,
) -> (
    PacketPlaneRuntime,
    tokio::net::UdpSocket,
    PeerId,
    PreparedUdpBinding,
) {
    let (mut runtime, receiver, _) = fixture(local, remote).await;
    let local_identity = NodeIdentity::generate_ed25519().unwrap();
    let remote_identity = NodeIdentity::generate_ed25519().unwrap();
    let peer = remote_identity.peer_id.parse().unwrap();
    let destination = receiver.local_addr().unwrap();
    let prepared = runtime
        .udp_preparation(peer, destination, false)
        .unwrap()
        .prepare()
        .await
        .unwrap();
    let alias = if destination.is_ipv4() {
        "203.0.113.9:45000"
    } else {
        "[2001:db8::9]:45000"
    }
    .parse()
    .unwrap();
    let binding = prepared.bind_endpoint(alias, &[alias]).unwrap();
    assert_eq!(binding.source(), prepared.source());
    assert!(runtime.udp_source_endpoints().is_empty());
    let local_secret = PacketPlaneEphemeralSecret::generate();
    let remote_secret = PacketPlaneEphemeralSecret::generate();
    let signed = |kind,
                  identity: &NodeIdentity,
                  secret: &PacketPlaneEphemeralSecret,
                  session_id,
                  endpoint| {
        PacketPlaneHandshake::signed(
            kind,
            identity,
            PacketPlaneHandshakeParams {
                network_name: "lab".into(),
                session_id,
                nonce: u64::from(session_id),
                mtu: 1280,
                ephemeral_public_key: secret.public_key(),
                endpoint,
            },
        )
        .unwrap()
        .verify("lab", None)
        .unwrap()
    };
    let hello = signed(
        PacketPlaneHandshakeKind::Hello,
        &local_identity,
        &local_secret,
        1,
        binding.endpoint(),
    );
    let accept = signed(
        PacketPlaneHandshakeKind::Accept,
        &remote_identity,
        &remote_secret,
        2,
        destination,
    );
    runtime
        .install_prepared_udp_session(
            PacketPlaneSessionRole::Initiator,
            &local_secret,
            &hello,
            &accept,
            false,
            Some(binding.clone()),
        )
        .unwrap();
    (runtime, receiver, peer, binding)
}

#[tokio::test]
async fn adopted_candidate_publishes_only_actual_sources_without_retaining_owners() {
    for (local, remote) in [
        ("0.0.0.0:0", "127.0.0.1:0"),
        ("[::]:0", "[::1]:0"),
        ("[::]:0", "127.0.0.1:0"),
    ] {
        let (mut runtime, receiver, peer, binding) = source_candidate(local, remote).await;
        let source = binding.source();
        assert_ne!(source, binding.endpoint());
        let routes = runtime
            .udp_scoped_routes(peer, udp_handoff::Phase::Candidate)
            .unwrap();
        let weak = Arc::downgrade(routes);
        let owners = Arc::strong_count(routes);
        let endpoints = runtime.udp_source_endpoints();
        assert_eq!(endpoints, vec![source]);
        assert!(runtime.udp_retained_source_endpoints().is_empty());
        for _ in 0..4 {
            assert_eq!(runtime.udp_source_endpoints(), endpoints);
        }
        assert_eq!(Arc::strong_count(routes), owners);
        assert_eq!(
            receiver.try_recv(&mut [0; 32]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(binding);
        runtime.forget_all_sessions();
        assert!(runtime.udp_source_endpoints().is_empty());
        assert!(weak.upgrade().is_none());
        assert_eq!(endpoints, vec![source]);
    }
}

#[tokio::test]
async fn canceled_candidate_withdraws_source_without_waiting_for_cleanup() {
    let (runtime, _, peer, binding) = source_candidate("0.0.0.0:0", "127.0.0.1:0").await;
    assert_eq!(runtime.udp_source_endpoints(), vec![binding.source()]);
    binding.failed(io::ErrorKind::Interrupted, Instant::now());
    assert!(runtime.udp_source_endpoints().is_empty());
    assert!(
        runtime
            .udp_scoped_routes(peer, udp_handoff::Phase::Candidate)
            .is_some()
    );
}

#[tokio::test]
async fn expired_candidate_withdraws_source_before_cleanup_and_releases_owner() {
    let (mut runtime, _, peer, binding) = source_candidate("[::]:0", "[::1]:0").await;
    assert_eq!(runtime.udp_source_endpoints(), vec![binding.source()]);
    assert!(
        runtime
            .udp_handoffs
            .source_endpoints(Instant::now() + Duration::from_secs(21))
            .next()
            .is_none()
    );
    let weak = Arc::downgrade(
        runtime
            .udp_scoped_routes(peer, udp_handoff::Phase::Candidate)
            .unwrap(),
    );
    runtime.set_session_ttl(Duration::ZERO);
    assert!(runtime.udp_source_endpoints().is_empty());
    assert!(weak.upgrade().is_some());
    drop(binding);
    runtime.expire_udp_handoffs(Instant::now());
    assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn retired_epoch_withdraws_candidate_source_without_removing_its_slot() {
    let (runtime, _, peer, binding) = source_candidate("0.0.0.0:0", "127.0.0.1:0").await;
    assert_eq!(runtime.udp_source_endpoints(), vec![binding.source()]);
    runtime
        .udp_owner
        .as_ref()
        .unwrap()
        .retire_observer_for_test();
    assert!(runtime.udp_source_endpoints().is_empty());
    assert!(
        runtime
            .udp_scoped_routes(peer, udp_handoff::Phase::Candidate)
            .is_some()
    );
}

#[tokio::test]
async fn active_and_candidate_sources_are_deduped_and_active_lifetime_is_enforced() {
    let (mut runtime, _, peer, binding) = source_candidate("0.0.0.0:0", "127.0.0.1:0").await;
    let source = binding.source();
    let session = runtime
        .udp_scoped_session(peer, udp_handoff::Phase::Candidate, Instant::now())
        .unwrap()
        .clone();
    let routes = Arc::clone(
        runtime
            .udp_scoped_routes(peer, udp_handoff::Phase::Candidate)
            .unwrap(),
    );
    runtime.sessions.insert(peer, session);
    runtime.session_lifetimes.insert(peer, runtime.session_ttl);
    runtime.udp_routes.insert(peer, routes);
    assert_eq!(runtime.udp_source_endpoints(), vec![source]);
    assert_eq!(runtime.udp_retained_source_endpoints(), vec![source]);
    runtime.udp_handoffs.clear();
    assert_eq!(runtime.udp_source_endpoints(), vec![source]);
    assert_eq!(runtime.udp_retained_source_endpoints(), vec![source]);
    runtime.sessions.get_mut(&peer).unwrap().established_at = Instant::now() - runtime.session_ttl;
    assert!(runtime.udp_source_endpoints().is_empty());
    assert!(runtime.udp_retained_source_endpoints().is_empty());
    runtime.sessions.get_mut(&peer).unwrap().established_at = Instant::now();
    assert_eq!(runtime.udp_source_endpoints(), vec![source]);
    assert_eq!(runtime.udp_retained_source_endpoints(), vec![source]);
    runtime.session_lifetimes.insert(peer, Duration::ZERO);
    assert!(runtime.udp_source_endpoints().is_empty());
    assert!(runtime.udp_retained_source_endpoints().is_empty());
}

#[tokio::test]
async fn receive_only_owners_do_not_publish_sources_or_extend_ownership() {
    let (mut runtime, _, peer, binding) = source_candidate("[::]:0", "[::1]:0").await;
    let session = runtime
        .udp_scoped_session(peer, udp_handoff::Phase::Candidate, Instant::now())
        .unwrap()
        .clone();
    let routes = Arc::clone(
        runtime
            .udp_scoped_routes(peer, udp_handoff::Phase::Candidate)
            .unwrap(),
    );
    let weak = Arc::downgrade(&routes);
    let endpoints = runtime.udp_source_endpoints();
    runtime.retiring_sessions.insert(
        peer,
        RetiringPacketPlaneSession {
            session,
            lifetime: runtime.session_ttl,
            use_for_tx: false,
            routes: Some(routes),
        },
    );
    runtime.udp_handoffs.clear();
    drop(binding);
    assert!(runtime.udp_source_endpoints().is_empty());
    assert!(runtime.udp_retained_source_endpoints().is_empty());
    assert!(weak.upgrade().is_some());
    runtime.forget_all_sessions();
    assert!(weak.upgrade().is_none());
    assert_eq!(endpoints.len(), 1);
}

#[tokio::test]
async fn retained_active_sources_do_not_retain_owners_or_transmit() {
    for (local, remote) in [("0.0.0.0:0", "127.0.0.1:0"), ("[::]:0", "[::1]:0")] {
        let (mut runtime, receiver, peer, binding) = source_candidate(local, remote).await;
        let session = runtime
            .udp_scoped_session(peer, udp_handoff::Phase::Candidate, Instant::now())
            .unwrap()
            .clone();
        let routes = Arc::clone(
            runtime
                .udp_scoped_routes(peer, udp_handoff::Phase::Candidate)
                .unwrap(),
        );
        let weak = Arc::downgrade(&routes);
        runtime.sessions.insert(peer, session);
        runtime.session_lifetimes.insert(peer, runtime.session_ttl);
        runtime.udp_routes.insert(peer, routes);
        runtime.udp_handoffs.clear();
        let routes = &runtime.udp_routes[&peer];
        let owners = Arc::strong_count(routes);
        let endpoints = runtime.udp_retained_source_endpoints();
        assert_eq!(endpoints, vec![binding.source()]);
        assert_ne!(endpoints, vec![binding.endpoint()]);
        for _ in 0..4 {
            assert_eq!(runtime.udp_retained_source_endpoints(), endpoints);
        }
        assert_eq!(Arc::strong_count(routes), owners);
        assert_eq!(
            receiver.try_recv(&mut [0; 32]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(binding);
        runtime.forget_all_sessions();
        assert!(runtime.udp_retained_source_endpoints().is_empty());
        assert!(weak.upgrade().is_none());
        assert_eq!(endpoints.len(), 1);
    }
}

#[tokio::test]
async fn retained_active_sources_withdraw_on_cancellation_or_linux_epoch_retirement() {
    for cancel in [false, true] {
        let (mut runtime, _, peer, binding) = source_candidate("0.0.0.0:0", "127.0.0.1:0").await;
        let session = runtime
            .udp_scoped_session(peer, udp_handoff::Phase::Candidate, Instant::now())
            .unwrap()
            .clone();
        let routes = Arc::clone(
            runtime
                .udp_scoped_routes(peer, udp_handoff::Phase::Candidate)
                .unwrap(),
        );
        runtime.sessions.insert(peer, session);
        runtime.session_lifetimes.insert(peer, runtime.session_ttl);
        runtime.udp_routes.insert(peer, routes);
        runtime.udp_handoffs.clear();
        assert_eq!(
            runtime.udp_retained_source_endpoints(),
            vec![binding.source()]
        );
        if cancel {
            binding.failed(io::ErrorKind::Interrupted, Instant::now());
        } else {
            runtime
                .udp_owner
                .as_ref()
                .unwrap()
                .retire_observer_for_test();
        }
        assert!(runtime.udp_retained_source_endpoints().is_empty());
        assert!(runtime.has_session(peer));
    }
}
