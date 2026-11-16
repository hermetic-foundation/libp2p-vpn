use super::*;
use crate::identity::NodeIdentity;

#[test]
fn session_lifetime_cap_handles_zero_and_unrepresentable_expiry() {
    let established = Instant::now();
    let phase = established + RECEIVE_DRAIN;
    assert_eq!(
        cap_to_session_lifetime(phase, established, Duration::ZERO),
        established
    );
    assert_eq!(
        cap_to_session_lifetime(phase, established, Duration::from_secs(1)),
        established + Duration::from_secs(1)
    );
    assert_eq!(
        cap_to_session_lifetime(phase, established, Duration::MAX),
        phase
    );
}

struct Peers {
    a: PacketPlaneQuicRuntime,
    b: PacketPlaneQuicRuntime,
    a_identity: NodeIdentity,
    b_identity: NodeIdentity,
}

impl Peers {
    async fn new() -> Self {
        let mut peers = Self {
            a: PacketPlaneQuicRuntime::bind("127.0.0.1:0".parse().unwrap()).unwrap(),
            b: PacketPlaneQuicRuntime::bind("127.0.0.1:0".parse().unwrap()).unwrap(),
            a_identity: NodeIdentity::generate_ed25519().unwrap(),
            b_identity: NodeIdentity::generate_ed25519().unwrap(),
        };
        peers.replace(1).await;
        peers
    }

    #[cfg(target_os = "linux")]
    async fn routed() -> Self {
        let mut peers = Self {
            a: PacketPlaneQuicRuntime::bind("0.0.0.0:0".parse().unwrap()).unwrap(),
            b: PacketPlaneQuicRuntime::bind("127.0.0.1:0".parse().unwrap()).unwrap(),
            a_identity: NodeIdentity::generate_ed25519().unwrap(),
            b_identity: NodeIdentity::generate_ed25519().unwrap(),
        };
        peers.a.follow_linux_routes("absent-pv".into());
        peers.replace(1).await;
        peers
    }

    fn a_peer(&self) -> PeerId {
        self.a_identity.peer_id.parse().unwrap()
    }
    fn b_peer(&self) -> PeerId {
        self.b_identity.peer_id.parse().unwrap()
    }

    async fn connections(&self) -> (PacketPlaneQuicConnection, PacketPlaneQuicConnection) {
        let a = self.a.connector();
        let b = self.b.connector();
        tokio::time::timeout(Duration::from_secs(2), async {
            let (a, b) = tokio::join!(
                a.connect(self.b.local_addr(), self.b.server_certificate()),
                b.accept()
            );
            (a.unwrap(), b.unwrap())
        })
        .await
        .expect("bounded real QUIC handshake")
    }

    async fn replace(
        &mut self,
        epoch: u32,
    ) -> (
        PacketPlaneEphemeralSecret,
        PacketPlaneEphemeralSecret,
        VerifiedPacketPlaneHandshake,
        VerifiedPacketPlaneHandshake,
    ) {
        let a_secret = PacketPlaneEphemeralSecret::generate();
        let b_secret = PacketPlaneEphemeralSecret::generate();
        let handshake =
            |kind, identity: &NodeIdentity, secret: &PacketPlaneEphemeralSecret, endpoint| {
                PacketPlaneHandshake::signed(
                    kind,
                    identity,
                    PacketPlaneHandshakeParams {
                        network_name: "lab".into(),
                        session_id: epoch,
                        nonce: u64::from(epoch),
                        mtu: 1280,
                        ephemeral_public_key: secret.public_key(),
                        endpoint,
                    },
                )
                .unwrap()
                .verify("lab", None)
                .unwrap()
            };
        let hello = handshake(
            PacketPlaneHandshakeKind::Hello,
            &self.a_identity,
            &a_secret,
            advertised_endpoint(&self.a),
        );
        let accept = handshake(
            PacketPlaneHandshakeKind::Accept,
            &self.b_identity,
            &b_secret,
            advertised_endpoint(&self.b),
        );
        let (a, b) = self.connections().await;
        self.a
            .install_connection_with_session(
                self.b_peer(),
                a,
                PacketPlaneSessionRole::Initiator,
                &a_secret,
                &hello,
                &accept,
            )
            .unwrap();
        self.b
            .install_connection_with_session(
                self.a_peer(),
                b,
                PacketPlaneSessionRole::Responder,
                &b_secret,
                &accept,
                &hello,
            )
            .unwrap();
        (a_secret, b_secret, hello, accept)
    }

    async fn promote(&mut self, sequence: u64) {
        let probe = probe(sequence);
        self.a
            .send_path_probe_to_peer(self.b_peer(), &probe)
            .unwrap();
        self.b
            .send_path_probe_to_peer(self.a_peer(), &probe)
            .unwrap();
        assert_eq!(receive(&mut self.b).await.received.frame, probe);
        assert_eq!(receive(&mut self.a).await.received.frame, probe);
    }
}

fn advertised_endpoint(runtime: &PacketPlaneQuicRuntime) -> SocketAddr {
    let mut endpoint = runtime.local_addr();
    if endpoint.ip().is_unspecified() {
        endpoint.set_ip("127.0.0.1".parse().unwrap());
    }
    endpoint
}

fn packet(sequence: u64) -> Frame {
    Frame::packet(77, sequence, vec![0x45; 20]).unwrap()
}

fn probe(sequence: u64) -> Frame {
    let mut frame = packet(sequence);
    frame.header.payload_type = PayloadType::PathProbe;
    frame
}

async fn receive(runtime: &mut PacketPlaneQuicRuntime) -> ScopedQuicFrame {
    tokio::time::timeout(
        Duration::from_secs(1),
        runtime.recv_frame_from_session_scoped(),
    )
    .await
    .expect("bounded datagram receive")
    .unwrap()
}

#[tokio::test]
async fn staged_replacement_preserves_data_until_authenticated_promotion() {
    let mut peers = Peers::new().await;
    let a_peer = peers.a_peer();
    let b_peer = peers.b_peer();
    let old_a = peers.a.connection_id(b_peer).unwrap();
    let old_b = peers.b.connection_id(a_peer).unwrap();
    peers.replace(2).await;
    assert!(peers.a.has_pending_replacement(b_peer));
    assert!(peers.b.has_pending_replacement(a_peer));
    assert_eq!(peers.a.connection_id(b_peer), Some(old_a));
    assert_eq!(peers.b.connection_id(a_peer), Some(old_b));

    let before = packet(1);
    peers.a.send_frame_to_peer(b_peer, &before).unwrap();
    peers.b.send_frame_to_peer(a_peer, &before).unwrap();
    let received_b = receive(&mut peers.b).await;
    let received_a = receive(&mut peers.a).await;
    assert_eq!(received_b.received.frame, before);
    assert_eq!(received_a.received.frame, before);
    assert_eq!(received_b.connection_id, old_b);
    assert_eq!(received_a.connection_id, old_a);
    assert!(peers.a.has_pending_replacement(b_peer));

    peers.promote(2).await;
    assert!(!peers.a.has_pending_replacement(b_peer));
    assert!(!peers.b.has_pending_replacement(a_peer));
    assert_ne!(peers.a.connection_id(b_peer), Some(old_a));
    assert_ne!(peers.b.connection_id(a_peer), Some(old_b));
    assert_eq!(peers.a.handoffs.retiring.len(), 1);
    assert_eq!(peers.b.handoffs.retiring.len(), 1);

    let after = packet(3);
    peers.a.send_frame_to_peer(b_peer, &after).unwrap();
    peers.b.send_frame_to_peer(a_peer, &after).unwrap();
    assert_eq!(receive(&mut peers.b).await.received.frame, after);
    assert_eq!(receive(&mut peers.a).await.received.frame, after);

    // Queued old-path data may drain, but cannot reset the old replay window.
    let old = &peers.a.handoffs.retiring[&b_peer];
    send_on(&old.connection, &old.session, &packet(4)).unwrap();
    let drained = receive(&mut peers.b).await;
    assert_eq!(drained.connection_id, old_b);
    assert_eq!(drained.received.frame, packet(4));
    let old = &peers.a.handoffs.retiring[&b_peer];
    send_on(&old.connection, &old.session, &before).unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), peers.b.recv_frame_from_session())
            .await
            .unwrap(),
        Err(PacketPlaneQuicError::Datagram(
            PacketPlaneDatagramError::ReplayedDatagram { .. }
        ))
    ));
    peers.a.send_frame_to_peer(b_peer, &packet(5)).unwrap();
    assert_eq!(receive(&mut peers.b).await.received.frame, packet(5));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn route_refresh_fences_connection_identity_and_finishes_only_after_promotion() {
    use super::super::quic_route::{Event, Reconciler};
    let mut peers = Peers::routed().await;
    let peer = peers.b_peer();
    let old = peers.a.connection_id(peer).unwrap();
    let mut routes = Reconciler::new(&peers.a).unwrap();
    let snapshot = routes.next().await.unwrap();
    assert!(routes.apply(snapshot, &mut peers.a).is_empty());
    let Event::Checked(mut decisions) = routes.next().await.unwrap() else {
        panic!("route check")
    };
    assert_eq!(decisions.len(), 1);
    let mut decision = decisions.pop().unwrap();
    decision.replace = true;
    let mut wrong_connection = decision.clone();
    wrong_connection.connection_id = old.wrapping_add(1);
    assert!(
        routes
            .apply(Event::Checked(vec![wrong_connection]), &mut peers.a)
            .is_empty()
    );
    assert!(!peers.a.route_refresh_needed(peer));

    let mut wrong_lifetime = decision.clone();
    wrong_lifetime.token = Arc::new(());
    assert!(
        routes
            .apply(Event::Checked(vec![wrong_lifetime]), &mut peers.a)
            .is_empty(),
        "a recycled stable ID must not match a decision for an older path lifetime"
    );
    assert!(!peers.a.route_refresh_needed(peer));

    // Use the live connection's lease to isolate negotiation-state behavior
    // from kernel preference selection, which has a real namespace fixture.
    assert_eq!(
        routes.apply(Event::Checked(vec![decision]), &mut peers.a),
        vec![peer]
    );
    assert!(peers.a.route_refresh_needed(peer));
    let (secret, _, hello, accept) = peers.replace(2).await;
    let a = peers.a.connector();
    let b = peers.b.connector();
    let (incoming, remote) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            a.accept(),
            b.connect(advertised_endpoint(&peers.a), peers.a.server_certificate())
        )
    })
    .await
    .unwrap();
    let _remote = remote.unwrap();
    let error = peers
        .a
        .install_connection_with_session(
            peer,
            incoming.unwrap(),
            PacketPlaneSessionRole::Initiator,
            &secret,
            &hello,
            &accept,
        )
        .unwrap_err();
    assert!(
        matches!(error, PacketPlaneQuicError::Io(ref error) if error.to_string().contains("requires preferred dial egress"))
    );
    assert!(
        peers.a.has_pending_replacement(peer),
        "rejecting reverse fallback must not discard the selected-route candidate"
    );
    assert!(peers.a.route_refresh_needed(peer));
    let before = packet(1);
    peers.a.send_frame_to_peer(peer, &before).unwrap();
    assert_eq!(receive(&mut peers.b).await.received.frame, before);
    assert_eq!(peers.a.connection_id(peer), Some(old));
    peers.promote(2).await;
    assert!(!peers.a.route_refresh_needed(peer));
    peers.a.forget_peer(peer);
    assert!(!peers.a.route_refresh.contains_key(&peer));
}

#[tokio::test]
async fn invalid_candidate_is_discarded_without_demoting_active_connection() {
    let mut peers = Peers::new().await;
    let a_peer = peers.a_peer();
    let b_peer = peers.b_peer();
    let active = peers.b.connection_id(a_peer);
    peers.replace(2).await;
    peers.a.handoffs.candidates[&b_peer]
        .connection
        .send_datagram(vec![0; 24].into())
        .unwrap();
    // No active frame yet: poll the receiver until the bad candidate is removed.
    assert!(
        tokio::time::timeout(Duration::from_millis(40), peers.b.recv_frame_from_session())
            .await
            .is_err()
    );
    assert!(!peers.b.has_pending_replacement(a_peer));
    assert_eq!(peers.b.connection_id(a_peer), active);
    peers.a.send_frame_to_peer(b_peer, &packet(1)).unwrap();
    assert_eq!(receive(&mut peers.b).await.received.frame, packet(1));
    peers.b.send_frame_to_peer(a_peer, &packet(2)).unwrap();
    // The remote candidate's connection error must not spin or hide active data.
    assert_eq!(receive(&mut peers.a).await.received.frame, packet(2));
    assert!(!peers.a.has_pending_replacement(b_peer));
}

#[tokio::test]
async fn candidate_deadline_wakes_idle_receiver_and_leaves_active_usable() {
    let mut peers = Peers::new().await;
    let a_peer = peers.a_peer();
    let b_peer = peers.b_peer();
    let active = peers.a.connection_id(b_peer);
    peers.replace(2).await;
    peers
        .a
        .handoffs
        .candidates
        .get_mut(&b_peer)
        .unwrap()
        .deadline = Instant::now() + Duration::from_millis(10);
    assert!(
        tokio::time::timeout(Duration::from_millis(60), peers.a.recv_frame_from_session())
            .await
            .is_err()
    );
    assert!(!peers.a.has_pending_replacement(b_peer));
    assert_eq!(peers.a.connection_id(b_peer), active);
    peers.b.send_frame_to_peer(a_peer, &packet(1)).unwrap();
    assert_eq!(receive(&mut peers.a).await.received.frame, packet(1));
}

#[tokio::test]
async fn retiring_connection_closes_on_deadline_without_idle_maintenance() {
    let mut peers = Peers::new().await;
    let b_peer = peers.b_peer();
    peers.replace(2).await;
    peers.promote(1).await;
    let old = peers.a.handoffs.retiring[&b_peer].connection.clone();
    let active = peers.a.connections[&b_peer].clone();
    peers.a.handoffs.retiring.get_mut(&b_peer).unwrap().deadline =
        Instant::now() + Duration::from_millis(10);
    assert!(
        tokio::time::timeout(Duration::from_millis(60), peers.a.recv_frame_from_session())
            .await
            .is_err()
    );
    assert!(peers.a.handoffs.retiring.is_empty());
    assert!(old.close_reason().is_some());
    assert!(active.close_reason().is_none());
    assert!(peers.a.handoffs.deadline(None).is_none());
}

#[tokio::test]
async fn replacement_failure_rolls_back_without_resetting_old_replay_state() {
    let mut peers = Peers::new().await;
    let a_peer = peers.a_peer();
    let b_peer = peers.b_peer();
    let old = peers.a.connection_id(b_peer);
    peers.b.send_frame_to_peer(a_peer, &packet(1)).unwrap();
    assert_eq!(receive(&mut peers.a).await.received.frame, packet(1));
    peers.replace(2).await;
    peers.promote(2).await;
    peers.a.connections[&b_peer].close(0_u32.into(), b"replacement failed");
    // Rollback processes the failure, then waits for actual old-path traffic.
    assert!(
        tokio::time::timeout(Duration::from_millis(30), peers.a.recv_frame_from_session())
            .await
            .is_err()
    );
    assert_eq!(peers.a.connection_id(b_peer), old);
    let remote_old = &peers.b.handoffs.retiring[&a_peer];
    send_on(&remote_old.connection, &remote_old.session, &packet(1)).unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), peers.a.recv_frame_from_session())
            .await
            .unwrap(),
        Err(PacketPlaneQuicError::Datagram(
            PacketPlaneDatagramError::ReplayedDatagram { .. }
        ))
    ));
    let remote_old = &peers.b.handoffs.retiring[&a_peer];
    send_on(&remote_old.connection, &remote_old.session, &packet(3)).unwrap();
    assert_eq!(receive(&mut peers.a).await.received.frame, packet(3));
}

#[tokio::test]
async fn cancellation_closes_candidates_and_draining_connections() {
    let mut peers = Peers::new().await;
    let b_peer = peers.b_peer();
    peers.replace(2).await;
    peers.promote(1).await;
    peers.replace(3).await;
    let candidate = peers.a.handoffs.candidates[&b_peer].connection.clone();
    let retiring = peers.a.handoffs.retiring[&b_peer].connection.clone();
    let active = peers.a.connections[&b_peer].clone();
    assert!(peers.a.forget_peer(b_peer));
    assert!(!peers.a.can_receive());
    for connection in [candidate, retiring, active] {
        assert!(connection.close_reason().is_some());
    }
}

#[tokio::test]
async fn draining_keys_and_validation_cannot_outlive_original_session_expiry() {
    let mut peers = Peers::new().await;
    let b_peer = peers.b_peer();
    peers.a.set_session_ttl(Duration::from_secs(2));
    let established = peers.a.sessions[&b_peer].established_at;
    peers.replace(2).await;
    let candidate = &peers.a.handoffs.candidates[&b_peer];
    assert_eq!(
        candidate.deadline,
        candidate.session.established_at + Duration::from_secs(2)
    );
    peers.promote(1).await;
    assert_eq!(
        peers.a.handoffs.retiring[&b_peer].deadline,
        established + Duration::from_secs(2)
    );
    peers.a.set_session_ttl(Duration::from_secs(1));
    assert_eq!(
        peers.a.handoffs.retiring[&b_peer].deadline,
        established + Duration::from_secs(1)
    );
}

#[tokio::test]
async fn superseding_candidate_closes_only_the_superseded_connection() {
    let mut peers = Peers::new().await;
    let b_peer = peers.b_peer();
    let active = peers.a.connections[&b_peer].clone();
    peers.replace(2).await;
    let superseded = peers.a.handoffs.candidates[&b_peer].connection.clone();
    peers.replace(3).await;
    assert!(superseded.close_reason().is_some());
    assert!(active.close_reason().is_none());
    assert_eq!(peers.a.handoffs.candidates.len(), 1);
    peers.promote(1).await;
    assert!(peers.a.handoffs.candidates.is_empty());
}

#[tokio::test]
async fn candidate_rejects_application_packets_and_draining_path_rejects_new_data() {
    let mut peers = Peers::new().await;
    let b_peer = peers.b_peer();
    peers.replace(2).await;
    assert!(peers.a.send_path_probe_to_peer(b_peer, &packet(1)).is_err());
    peers.promote(2).await;
    let old_id = peers.a.handoffs.retiring[&b_peer].connection.stable_id();
    assert!(
        peers
            .a
            .send_frame_on_connection(b_peer, old_id, &packet(3))
            .is_err()
    );
    // A valid probe response is sent through exactly the connection that asked.
    peers
        .a
        .send_frame_on_connection(b_peer, old_id, &probe(4))
        .unwrap();
    let received = receive(&mut peers.b).await;
    assert_eq!(received.received.frame, probe(4));
    assert_eq!(
        received.connection_id,
        peers.b.handoffs.retiring[&peers.a_peer()]
            .connection
            .stable_id()
    );
}

#[tokio::test]
async fn duplicate_handshake_keys_cannot_reset_any_live_replay_window() {
    let mut peers = Peers::new().await;
    let b_peer = peers.b_peer();
    let (secret, _, hello, accept) = peers.replace(2).await;
    for phase in 0..3 {
        if phase == 1 {
            peers.promote(1).await;
        }
        if phase == 2 {
            peers.replace(3).await;
            peers.promote(2).await;
        }
        let active = peers.a.connection_id(b_peer);
        let candidate = peers.a.probe_connection_id(b_peer);
        let (a, _b) = peers.connections().await;
        let rejected = a.connection.clone();
        let error = peers
            .a
            .install_connection_with_session(
                b_peer,
                a,
                PacketPlaneSessionRole::Initiator,
                &secret,
                &hello,
                &accept,
            )
            .unwrap_err();
        assert!(
            matches!(error, PacketPlaneQuicError::Io(ref error) if error.kind() == io::ErrorKind::InvalidData)
        );
        assert!(rejected.close_reason().is_some());
        assert_eq!(peers.a.connection_id(b_peer), active);
        assert_eq!(peers.a.probe_connection_id(b_peer), candidate);
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn routed_quic_reports_actual_client_source_and_keeps_driver_alive() {
    let mut peers = Peers::routed().await;
    let a_peer = peers.a_peer();
    let b_peer = peers.b_peer();
    let client = peers.a.connections[&b_peer].local_socket_addr(peers.a.local_addr());
    assert!(client.ip().is_loopback());
    assert!(peers.a.connections[&b_peer].route_is_current());
    peers.a.send_frame_to_peer(b_peer, &packet(1)).unwrap();
    assert_eq!(receive(&mut peers.b).await.received.remote_addr, client);
    peers.b.send_frame_to_peer(a_peer, &packet(2)).unwrap();
    assert_eq!(receive(&mut peers.a).await.received.local_addr, client);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "isolated Linux route notifications and real QUIC sockets; no host route changes"]
fn routed_candidates_reject_stale_install_and_promotion_without_dropping_active() {
    use crate::runtime::physical_network::linux::{isolated_namespace, test_ip as ip};
    let test = "runtime::packet_plane::quic_handoff::tests::routed_candidates_reject_stale_install_and_promotion_without_dropping_active";
    if !isolated_namespace(test) {
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut peers = Peers::routed().await;
            let a_peer = peers.a_peer();
            let b_peer = peers.b_peer();
            let old = peers.a.connection_id(b_peer);
            let old_local = peers.a.connections[&b_peer].local_socket_addr(peers.a.local_addr());
            let (secret, _, hello, accept) = peers.replace(2).await;
            let (stale, _remote) = peers.connections().await;
            ip(&["link", "add", "route-change", "type", "dummy"]);
            tokio::time::timeout(Duration::from_secs(1), async {
                while stale.connection.route_is_current() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let rejected = stale.connection.clone();
            assert!(
                peers
                    .a
                    .install_connection_with_session(
                        b_peer,
                        stale,
                        PacketPlaneSessionRole::Initiator,
                        &secret,
                        &hello,
                        &accept
                    )
                    .is_err()
            );
            assert!(rejected.close_reason().is_some());
            assert_eq!(peers.a.connection_id(b_peer), old);
            let old_b = peers.b.connection_id(a_peer);
            // A stale unvalidated socket must not keep sending probes. Use the
            // established fallback instead, without promoting the remote candidate.
            peers.a.send_path_probe_to_peer(b_peer, &probe(1)).unwrap();
            let still_active = receive(&mut peers.b).await;
            assert_eq!(Some(still_active.connection_id), old_b);
            assert!(peers.b.has_pending_replacement(a_peer));
            peers.b.send_path_probe_to_peer(a_peer, &probe(1)).unwrap();
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(100),
                    peers.a.recv_frame_from_session()
                )
                .await
                .is_err()
            );
            assert!(!peers.a.has_pending_replacement(b_peer));
            assert_eq!(peers.a.connection_id(b_peer), old);
            peers.b.send_frame_to_peer(a_peer, &packet(2)).unwrap();
            assert_eq!(receive(&mut peers.a).await.received.frame, packet(2));
            peers.a.send_frame_to_peer(b_peer, &packet(3)).unwrap();
            assert_eq!(receive(&mut peers.b).await.received.frame, packet(3));
            peers.replace(3).await;
            peers.promote(4).await;
            assert_ne!(peers.a.connection_id(b_peer), old);
            assert!(peers.a.connections[&b_peer].route_is_current());
            assert_eq!(
                peers.a.handoffs.retiring[&b_peer]
                    .connection
                    .local_socket_addr(peers.a.local_addr()),
                old_local
            );
        });
}
