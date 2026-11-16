use super::*;
use tokio::time::timeout;

#[test]
fn unscoped_link_local_destination_uses_only_the_already_selected_scope() {
    let selected = "[fe80::2%7]:4001".parse().unwrap();
    for (requested, expected) in [
        ("[fe80::2]:4001", true),
        ("[fe80::2%7]:4001", true),
        ("[fe80::2%8]:4001", false),
        ("[fe80::3]:4001", false),
        ("[fe80::2]:4002", false),
        ("[2001:db8::2]:4001", false),
    ] {
        assert_eq!(
            same_destination(requested.parse().unwrap(), selected),
            expected
        );
    }
}

#[tokio::test]
async fn both_families_share_listener_ports_receive_replies_and_release_route_owners() {
    for (local, peer) in [
        ("0.0.0.0:0", "127.0.0.1:0"),
        ("[::]:0", "[::1]:0"),
        ("[::]:0", "127.0.0.1:0"),
    ] {
        let socket = udp_socket::Socket::bind(local.parse().unwrap())
            .await
            .unwrap();
        let peer = tokio::net::UdpSocket::bind(peer).await.unwrap();
        let owner = Egress::new("absent-pv".into());
        let destination = peer.local_addr().unwrap();
        let route = Route::prepare(&socket, &owner, destination, None)
            .await
            .unwrap();
        assert!(route.lease.is_current());
        assert_eq!(
            route.lease.local_addr.port(),
            socket.local_addr().unwrap().port()
        );
        assert_eq!(
            peer.try_recv(&mut [0; 32]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        route.send(b"selected").await.unwrap();
        let mut bytes = [0; 32];
        let (len, source) = timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..len], b"selected");
        assert_eq!(source, route.lease.local_addr);
        peer.send_to(b"reply", source).await.unwrap();
        let received = timeout(Duration::from_secs(2), socket.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.local, source);
        assert_eq!(&bytes[..received.len], b"reply");
        let guard = Arc::downgrade(&route.io);
        let companion = source.is_ipv6();
        drop(route);
        if companion {
            assert!(
                guard.upgrade().is_none(),
                "last route drops strict socket, not listener"
            );
        }
        assert!(socket.local_addr().is_ok());
    }
}

#[tokio::test]
async fn cached_route_survives_preference_epoch_change_without_a_per_packet_lookup() {
    let socket = udp_socket::Socket::bind("[::]:0".parse().unwrap())
        .await
        .unwrap();
    let peer = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let owner = Egress::new("absent-pv".into());
    let slot = Slot::default();
    let route = slot
        .prepare(&socket, &owner, peer.local_addr().unwrap(), None)
        .await
        .unwrap();
    let epoch = route.lease.epoch();
    let io = Arc::downgrade(&route.io);
    owner.retire_observer_for_test();
    assert!(!epoch.is_current());
    let cached = slot
        .prepare(&socket, &owner, peer.local_addr().unwrap(), None)
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&io.upgrade().unwrap(), &cached.io));
    assert_eq!(cached.lease.epoch(), epoch);
    cached.send(b"fallback").await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), peer.recv(&mut [0; 32]))
            .await
            .unwrap()
            .unwrap(),
        8
    );
}

#[tokio::test]
async fn failed_preparation_is_silent_and_repeated_packets_use_a_bounded_cooldown() {
    let socket = udp_socket::Socket::bind("0.0.0.0:0".parse().unwrap())
        .await
        .unwrap();
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let owner = Egress::new("lo".into());
    let slot = Slot::default();
    assert!(
        slot.prepare(&socket, &owner, peer.local_addr().unwrap(), None)
            .await
            .is_err()
    );
    assert!(slot.path.get().is_none());
    assert_eq!(
        slot.prepare(&socket, &owner, peer.local_addr().unwrap(), None)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(slot.retry.lock().unwrap().delay, Duration::from_secs(2));
    assert_eq!(
        peer.try_recv(&mut [0; 32]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn cached_incoming_owner_rejects_changed_local_and_remote_tuples_without_retargeting() {
    let socket = udp_socket::Socket::bind("0.0.0.0:0".parse().unwrap())
        .await
        .unwrap();
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let owner = Egress::new("absent-pv".into());
    let slot = Slot::default();
    let local = SocketAddr::new(
        "127.0.0.1".parse().unwrap(),
        socket.local_addr().unwrap().port(),
    );
    let remote = peer.local_addr().unwrap();
    slot.prepare(&socket, &owner, remote, Some(local))
        .await
        .unwrap();
    let changed_local = SocketAddr::new("127.0.0.2".parse().unwrap(), local.port());
    assert_eq!(
        slot.prepare(&socket, &owner, remote, Some(changed_local))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::AddrNotAvailable
    );
    let changed_remote = SocketAddr::new(remote.ip(), if remote.port() == 1 { 2 } else { 1 });
    assert_eq!(
        slot.prepare(&socket, &owner, changed_remote, Some(local))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::AddrNotAvailable
    );
    assert_eq!(slot.path.get().unwrap().lease.local_addr, local);
    assert_eq!(slot.path.get().unwrap().lease.context.destination, remote);
    assert!(
        slot.prepare(&socket, &owner, remote, Some(local))
            .await
            .is_ok()
    );
}

struct Peers {
    sender: PacketPlaneRuntime,
    receiver: PacketPlaneRuntime,
    hello: VerifiedPacketPlaneHandshake,
    accept: VerifiedPacketPlaneHandshake,
}

impl Peers {
    async fn new() -> Self {
        let mut sender = PacketPlaneRuntime::bind(vec!["127.0.0.1:0".parse().unwrap()])
            .await
            .unwrap();
        let mut receiver = PacketPlaneRuntime::bind(vec!["127.0.0.1:0".parse().unwrap()])
            .await
            .unwrap();
        let (a, b, hello, accept) = super::super::tests::verified_session_pair_with_endpoints(
            sender.primary_listener().unwrap(),
            receiver.primary_listener().unwrap(),
            1280,
        );
        sender
            .establish_session(PacketPlaneSessionRole::Initiator, &a, &hello, &accept)
            .unwrap();
        receiver
            .establish_session(PacketPlaneSessionRole::Responder, &b, &accept, &hello)
            .unwrap();
        sender.follow_physical_routes("absent-pv".into());
        receiver.follow_physical_routes("absent-pv".into());
        Self {
            sender,
            receiver,
            hello,
            accept,
        }
    }

    async fn send(&self, sequence: u64) {
        self.sender
            .send_frame_to_peer(
                self.accept.peer,
                &Frame::packet(77, sequence, vec![0x45; 20]).unwrap(),
            )
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn only_authenticated_receive_can_prepare_reply_and_forgetting_releases_exact_owners() {
    let mut peers = Peers::new().await;
    let slot = peers.receiver.udp_routes[&peers.hello.peer].clone();
    peers.send(1).await;
    let scoped = timeout(
        Duration::from_secs(2),
        peers.receiver.recv_frame_from_session_scoped(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        slot.sockets[0].path.get().is_none(),
        "cancelable receive never awaits route preparation"
    );
    peers
        .receiver
        .remember_incoming_route(&scoped)
        .await
        .unwrap();
    let route = slot.sockets[0].path.get().unwrap();
    assert!(!route.lease.preferred_dial);
    assert_eq!(route.lease.local_addr, scoped.received.local_addr);
    let sender_routes = peers.sender.udp_routes[&peers.accept.peer].clone();
    let receiver_token = Arc::downgrade(&slot.token);
    peers.receiver.forget_peer(peers.hello.peer);
    assert_eq!(
        peers
            .receiver
            .remember_incoming_route(&scoped)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
    drop(scoped);
    drop(slot);
    assert!(receiver_token.upgrade().is_none());
    assert!(
        sender_routes.sockets[0].path.get().is_some(),
        "sibling daemon is untouched"
    );
}

#[tokio::test]
async fn managed_anonymous_sends_are_rejected_without_any_unselected_fallback() {
    let mut peers = Peers::new().await;
    let error = peers
        .sender
        .send_frame_from(
            0,
            peers.accept.endpoint,
            &peers.sender.sessions[&peers.accept.peer].keys.seal,
            &Frame::packet(77, 1, vec![0x45; 20]).unwrap(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, PacketPlaneIoError::Io(ref error) if error.kind() == io::ErrorKind::PermissionDenied)
    );
    assert!(
        timeout(
            Duration::from_millis(20),
            peers.receiver.recv_frame_from_session()
        )
        .await
        .is_err()
    );
    peers.send(2).await;
}
