use super::*;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::runtime::path_probe::{mtu_sized_path_probe_payload, path_probe_ack_payload};
    use tokio::time::timeout;

    const IO_TIMEOUT: Duration = Duration::from_secs(3);
    const A_TOKEN: u64 = 0x1234_5678_90ab_cdef;
    const B_TOKEN: u64 = 0xfedc_ba09_8765_4321;

    struct Peers {
        a: PacketPlaneRuntime,
        b: PacketPlaneRuntime,
        a_identity: NodeIdentity,
        b_identity: NodeIdentity,
        generation: u32,
    }

    impl Peers {
        async fn new(address: &str, listeners: usize) -> Self {
            let mut peers = Self {
                a: PacketPlaneRuntime::bind(vec![address.parse().unwrap(); listeners])
                    .await
                    .unwrap(),
                b: PacketPlaneRuntime::bind(vec![address.parse().unwrap(); listeners])
                    .await
                    .unwrap(),
                a_identity: NodeIdentity::generate_ed25519().unwrap(),
                b_identity: NodeIdentity::generate_ed25519().unwrap(),
                generation: 0,
            };
            peers.a.follow_physical_routes("absent-pv".into());
            peers.b.follow_physical_routes("absent-pv".into());
            peers.stage(None);
            peers.payload(1).await;
            peers
        }

        fn a_peer(&self) -> PeerId {
            self.a_identity.peer_id.parse().unwrap()
        }
        fn b_peer(&self) -> PeerId {
            self.b_identity.peer_id.parse().unwrap()
        }

        fn stage(&mut self, b_endpoint: Option<SocketAddr>) {
            self.try_stage(b_endpoint).unwrap();
        }

        fn try_stage(&mut self, b_endpoint: Option<SocketAddr>) -> Result<(), String> {
            self.generation += 1;
            let a_secret = PacketPlaneEphemeralSecret::generate();
            let b_secret = PacketPlaneEphemeralSecret::generate();
            let signed = |kind,
                          identity: &NodeIdentity,
                          secret: &PacketPlaneEphemeralSecret,
                          id,
                          endpoint| {
                PacketPlaneHandshake::signed(
                    kind,
                    identity,
                    PacketPlaneHandshakeParams {
                        network_name: "lab".into(),
                        session_id: id,
                        nonce: u64::from(id),
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
                &self.a_identity,
                &a_secret,
                self.generation * 2,
                self.a.primary_listener().unwrap(),
            );
            let accept = signed(
                PacketPlaneHandshakeKind::Accept,
                &self.b_identity,
                &b_secret,
                self.generation * 2 + 1,
                b_endpoint.unwrap_or_else(|| self.b.primary_listener().unwrap()),
            );
            self.a
                .install_udp_session(
                    PacketPlaneSessionRole::Initiator,
                    &a_secret,
                    &hello,
                    &accept,
                )
                .map_err(|error| format!("A: {error}"))?;
            self.b
                .install_udp_session(
                    PacketPlaneSessionRole::Responder,
                    &b_secret,
                    &accept,
                    &hello,
                )
                .map_err(|error| format!("B: {error}"))?;
            Ok(())
        }

        async fn payload(&mut self, sequence: u64) {
            let a_peer = self.a_peer();
            let b_peer = self.b_peer();
            let frame = packet(sequence);
            timeout(IO_TIMEOUT, self.a.send_frame_to_peer(b_peer, &frame))
                .await
                .unwrap()
                .unwrap();
            let received = receive(&mut self.b, 0).await;
            assert_eq!(received.phase, Phase::Active);
            assert_eq!(received.received.frame, frame);
            assert!(!self.b.accept_udp_frame(&received).await.unwrap());
            assert_eq!(received.owner_id(), self.b.udp_owner_id(a_peer));
            timeout(IO_TIMEOUT, self.b.send_frame_to_peer(a_peer, &frame))
                .await
                .unwrap()
                .unwrap();
            let received = receive(&mut self.a, 0).await;
            assert_eq!(received.phase, Phase::Active);
            assert_eq!(received.received.frame, frame);
            assert!(!self.a.accept_udp_frame(&received).await.unwrap());
            assert_eq!(received.owner_id(), self.a.udp_owner_id(b_peer));
        }

        async fn challenge(&mut self) -> ScopedUdpFrame {
            timeout(
                IO_TIMEOUT,
                self.a
                    .send_udp_path_probe(self.b_peer(), &request(100, A_TOKEN)),
            )
            .await
            .unwrap()
            .unwrap();
            let received = receive(&mut self.b, 0).await;
            assert_eq!(received.phase, Phase::Candidate);
            assert_eq!(
                path_probe_request_token(&received.received.frame.payload),
                Some(A_TOKEN)
            );
            assert!(!self.b.accept_udp_frame(&received).await.unwrap());
            received
        }

        async fn promote_a_only(&mut self) {
            let challenge = self.challenge().await;
            self.b
                .send_udp_probe_reply(&challenge, &ack(101, A_TOKEN))
                .await
                .unwrap();
            let received = receive(&mut self.a, 0).await;
            assert!(self.a.accept_udp_frame(&received).await.unwrap());
            assert!(self.b.has_pending_udp_replacement(self.a_peer()));
        }

        async fn promote(&mut self) {
            timeout(
                IO_TIMEOUT,
                self.a
                    .send_udp_path_probe(self.b_peer(), &request(100, A_TOKEN)),
            )
            .await
            .unwrap()
            .unwrap();
            timeout(
                IO_TIMEOUT,
                self.b
                    .send_udp_path_probe(self.a_peer(), &request(100, B_TOKEN)),
            )
            .await
            .unwrap()
            .unwrap();
            let at_b = receive(&mut self.b, 0).await;
            let at_a = receive(&mut self.a, 0).await;
            assert_eq!(at_b.phase, Phase::Candidate);
            assert_eq!(at_a.phase, Phase::Candidate);
            assert!(!self.b.accept_udp_frame(&at_b).await.unwrap());
            assert!(!self.a.accept_udp_frame(&at_a).await.unwrap());
            timeout(
                IO_TIMEOUT,
                self.b.send_udp_probe_reply(&at_b, &ack(101, A_TOKEN)),
            )
            .await
            .unwrap()
            .unwrap();
            timeout(
                IO_TIMEOUT,
                self.a.send_udp_probe_reply(&at_a, &ack(101, B_TOKEN)),
            )
            .await
            .unwrap()
            .unwrap();
            let at_a = receive(&mut self.a, 0).await;
            let at_b = receive(&mut self.b, 0).await;
            assert!(self.a.accept_udp_frame(&at_a).await.unwrap());
            assert!(self.b.accept_udp_frame(&at_b).await.unwrap());
        }
    }

    fn packet(sequence: u64) -> Frame {
        Frame::packet(77, sequence, vec![0x45; 20]).unwrap()
    }
    fn request(sequence: u64, token: u64) -> Frame {
        Frame::path_probe(
            77,
            sequence,
            mtu_sized_path_probe_payload(1280, Some(token)),
        )
        .unwrap()
    }
    fn ack(sequence: u64, token: u64) -> Frame {
        Frame::path_probe(77, sequence, path_probe_ack_payload(1280, Some(token))).unwrap()
    }
    async fn receive(runtime: &mut PacketPlaneRuntime, listener: usize) -> ScopedUdpFrame {
        timeout(IO_TIMEOUT, runtime.recv_session_scoped_on(listener))
            .await
            .expect("bounded encrypted UDP receive")
            .unwrap()
    }
    fn assert_interrupted(error: PacketPlaneIoError) {
        assert!(
            matches!(error, PacketPlaneIoError::Io(ref error) if error.kind() == io::ErrorKind::Interrupted),
            "{error:?}"
        );
    }
    fn sole_retiring_phase(runtime: &PacketPlaneRuntime, peer: PeerId) -> Phase {
        let mut owners = runtime
            .udp_handoffs
            .retiring
            .keys()
            .filter_map(|(candidate, token)| (*candidate == peer).then_some(*token));
        let token = owners.next().expect("one retained receive owner");
        assert!(owners.next().is_none(), "ambiguous retained receive owner");
        Phase::Retiring(token)
    }
    async fn send_phase(runtime: &PacketPlaneRuntime, peer: PeerId, phase: Phase, frame: &Frame) {
        // Emit valid ciphertext with deliberately invalid phase content, using
        // the real socket without relaxing the public candidate-probe API.
        let session = runtime
            .udp_scoped_session(peer, phase, Instant::now())
            .unwrap();
        let routes = runtime.udp_scoped_routes(peer, phase).unwrap();
        let bytes = session.keys.seal.seal_frame(frame).unwrap();
        timeout(
            IO_TIMEOUT,
            runtime.send_route_datagram(routes, 0, session.endpoint, &bytes, false, None),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[tokio::test]
    async fn candidates_preserve_payload_until_exact_ack_promotion_for_both_families() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let mut peers = Peers::new(address, 1).await;
            let a_peer = peers.a_peer();
            let b_peer = peers.b_peer();
            let old_a = peers.a.udp_owner_id(b_peer);
            let old_b = peers.b.udp_owner_id(a_peer);
            peers.stage(None);
            let next_a = peers.a.udp_probe_owner_id(b_peer);
            let next_b = peers.b.udp_probe_owner_id(a_peer);
            assert_ne!(old_a, next_a);
            assert_ne!(old_b, next_b);
            peers.payload(2).await;
            assert_eq!(peers.a.udp_owner_id(b_peer), old_a);
            assert_eq!(peers.b.udp_owner_id(a_peer), old_b);
            peers.promote().await;
            assert_eq!(peers.a.udp_owner_id(b_peer), next_a);
            assert_eq!(peers.b.udp_owner_id(a_peer), next_b);
            assert!(!peers.a.has_pending_udp_replacement(b_peer));
            assert!(!peers.b.has_pending_udp_replacement(a_peer));
            assert_eq!(peers.a.udp_handoffs.retiring.len(), 1);
            assert_eq!(peers.b.udp_handoffs.retiring.len(), 1);
            peers.payload(103).await;
            let retired_b = sole_retiring_phase(&peers.b, a_peer);
            let retired_a = sole_retiring_phase(&peers.a, b_peer);
            send_phase(&peers.b, a_peer, retired_b, &packet(4)).await;
            let late = receive(&mut peers.a, 0).await;
            assert_eq!(late.phase, retired_a);
            assert!(!peers.a.accept_udp_frame(&late).await.unwrap());
            assert_eq!(late.received.frame, packet(4));
            assert_eq!(peers.a.udp_owner_id(b_peer), next_a);
            send_phase(&peers.b, a_peer, retired_b, &packet(4)).await;
            let duplicate = receive(&mut peers.a, 0).await;
            assert!(matches!(
                peers.a.accept_udp_frame(&duplicate).await,
                Err(PacketPlaneIoError::Datagram(
                    PacketPlaneDatagramError::ReplayedDatagram { .. }
                ))
            ));
        }
    }

    #[tokio::test]
    async fn asymmetric_promotion_receives_authorized_payload_before_delayed_reverse_ack() {
        timeout(Duration::from_secs(12), async {
            let mut peers = Peers::new("127.0.0.1:0", 1).await;
            let a_peer = peers.a_peer();
            let b_peer = peers.b_peer();
            let old_a = peers.a.udp_owner_id(b_peer);
            let old_b = peers.b.udp_owner_id(a_peer);
            peers.stage(None);
            let next_a = peers.a.udp_probe_owner_id(b_peer);
            let next_b = peers.b.udp_probe_owner_id(a_peer);
            peers.payload(2).await;

            let a_challenge = peers.challenge().await;
            peers
                .b
                .send_udp_path_probe(a_peer, &request(100, B_TOKEN))
                .await
                .unwrap();
            let unanswered = receive(&mut peers.a, 0).await;
            assert_eq!(unanswered.phase, Phase::Candidate);
            assert!(!peers.a.accept_udp_frame(&unanswered).await.unwrap());
            assert_eq!(peers.a.udp_owner_id(b_peer), old_a);
            assert_eq!(peers.b.udp_owner_id(a_peer), old_b);

            // Model the pending reverse challenge without a runner/timer race:
            // A's ACK reaches it, but B's own challenge remains unanswered.
            peers
                .b
                .send_udp_probe_reply(&a_challenge, &ack(101, A_TOKEN))
                .await
                .unwrap();
            let a_ack = receive(&mut peers.a, 0).await;
            assert!(peers.a.accept_udp_frame(&a_ack).await.unwrap());
            assert_eq!(peers.a.udp_owner_id(b_peer), next_a);
            let nominal_drain_end = Instant::now() + Duration::from_secs(3);

            let first = packet(102);
            peers.a.send_frame_to_peer(b_peer, &first).await.unwrap();
            let at_b = timeout(IO_TIMEOUT, peers.b.recv_session_scoped_on(0))
                .await
                .expect("bounded asymmetric-promotion payload receive")
                .expect(
                    "asymmetric promotion: B must receive A's authorized new-key payload \
                     while B's own challenge is pending",
                );
            assert_eq!(at_b.phase, Phase::Candidate);
            assert_eq!(at_b.received.frame, first);
            assert_eq!(at_b.owner_id(), next_b);
            assert!(!peers.b.accept_udp_frame(&at_b).await.unwrap());
            assert_eq!(peers.b.udp_owner_id(a_peer), old_b);
            assert!(peers.b.has_pending_udp_replacement(a_peer));

            // Receiving authorized candidate data must not switch B's TX keys.
            let old_payload = packet(3);
            peers
                .b
                .send_frame_to_peer(a_peer, &old_payload)
                .await
                .unwrap();
            let at_a = receive(&mut peers.a, 0).await;
            assert_eq!(at_a.phase, Phase::Retiring(old_a.unwrap()));
            assert_eq!(at_a.received.frame, old_payload);
            assert!(!peers.a.accept_udp_frame(&at_a).await.unwrap());

            tokio::time::sleep_until(tokio::time::Instant::from_std(
                nominal_drain_end + Duration::from_millis(20),
            ))
            .await;
            assert!(Instant::now() > nominal_drain_end);
            peers.a.expire_udp_handoffs(Instant::now());
            peers
                .b
                .send_frame_to_peer(a_peer, &packet(4))
                .await
                .unwrap();
            let late_old = receive(&mut peers.a, 0).await;
            assert_eq!(late_old.phase, Phase::Retiring(old_a.unwrap()));
            assert!(!peers.a.accept_udp_frame(&late_old).await.unwrap());
            let later = packet(103);
            peers.a.send_frame_to_peer(b_peer, &later).await.unwrap();
            let at_b = receive(&mut peers.b, 0).await;
            assert_eq!(at_b.received.frame, later);
            assert_eq!(at_b.phase, Phase::Candidate);
            assert!(!peers.b.accept_udp_frame(&at_b).await.unwrap());
            assert_eq!(peers.b.udp_owner_id(a_peer), old_b);
            assert!(peers.b.has_pending_udp_replacement(a_peer));
            assert_eq!(
                peers.b.udp_handoffs.candidates[&a_peer]
                    .probe
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .token,
                B_TOKEN,
            );

            // Only B's matching outbound proof permits its eventual promotion.
            // Reuse the unanswered token with a fresh frame sequence, not the
            // old ciphertext (which must remain subject to replay protection).
            peers
                .b
                .send_udp_path_probe(a_peer, &request(104, B_TOKEN))
                .await
                .unwrap();
            let reverse = receive(&mut peers.a, 0).await;
            assert_eq!(reverse.phase, Phase::Active);
            assert!(!peers.a.accept_udp_frame(&reverse).await.unwrap());
            peers
                .a
                .send_udp_probe_reply(&reverse, &ack(105, B_TOKEN))
                .await
                .unwrap();
            let b_ack = receive(&mut peers.b, 0).await;
            assert_eq!(b_ack.phase, Phase::Candidate);
            assert!(peers.b.accept_udp_frame(&b_ack).await.unwrap());
            assert_eq!(peers.b.udp_owner_id(a_peer), next_b);
            assert!(!peers.b.has_pending_udp_replacement(a_peer));
            peers.payload(106).await;
        })
        .await
        .expect("bounded asymmetric promotion and delayed reverse proof");
    }

    #[tokio::test]
    async fn authorized_candidate_validation_timeout_keeps_receive_owner_without_tx_probes() {
        let mut peers = Peers::new("127.0.0.1:0", 1).await;
        let a_peer = peers.a_peer();
        let b_peer = peers.b_peer();
        let old_b = peers.b.udp_owner_id(a_peer);
        peers.stage(None);
        let candidate_owner = peers.b.udp_probe_owner_id(a_peer).unwrap();
        peers.promote_a_only().await;
        let candidate = peers.b.udp_handoffs.candidates.get_mut(&a_peer).unwrap();
        assert!(candidate.receive_authorized.load(Ordering::Acquire));
        let receive_deadline = candidate.receive_deadline;
        let routes = Arc::downgrade(&candidate.routes);
        // Advance only the validation deadline, not the original key lifetime.
        candidate.deadline = Instant::now() - Duration::from_millis(1);
        peers.b.expire_udp_handoffs(Instant::now());
        assert!(!peers.b.has_pending_udp_replacement(a_peer));
        assert!(!peers.b.udp_handoffs.candidates.contains_key(&a_peer));
        let retained = &peers.b.udp_handoffs.retiring[&(a_peer, candidate_owner)];
        assert_eq!(retained.receive_deadline, receive_deadline);
        assert!(retained.probe.lock().unwrap().is_none());
        assert!(routes.upgrade().is_some());

        peers
            .a
            .send_frame_to_peer(b_peer, &packet(102))
            .await
            .unwrap();
        let received = receive(&mut peers.b, 0).await;
        assert_eq!(received.phase, Phase::Retiring(candidate_owner));
        assert_eq!(received.received.frame, packet(102));
        assert!(!peers.b.accept_udp_frame(&received).await.unwrap());
        assert_eq!(peers.b.udp_owner_id(a_peer), old_b);

        let token = A_TOKEN ^ 2;
        peers
            .a
            .send_frame_to_peer(b_peer, &request(103, token))
            .await
            .unwrap();
        let request = receive(&mut peers.b, 0).await;
        assert_eq!(request.phase, Phase::Retiring(candidate_owner));
        assert!(!peers.b.accept_udp_frame(&request).await.unwrap());
        peers
            .b
            .send_udp_probe_reply(&request, &ack(104, token))
            .await
            .unwrap();
        let reply = receive(&mut peers.a, 0).await;
        assert_eq!(reply.phase, Phase::Active);
        assert!(!peers.a.accept_udp_frame(&reply).await.unwrap());
        assert_eq!(peers.b.udp_owner_id(a_peer), old_b);
        assert!(!peers.b.has_pending_udp_replacement(a_peer));
        assert_eq!(
            peers.b.udp_handoffs.retiring[&(a_peer, candidate_owner)].receive_deadline,
            receive_deadline
        );
        let established = peers.b.udp_handoffs.retiring[&(a_peer, candidate_owner)]
            .session
            .established_at;
        peers.b.set_session_ttl(Duration::from_secs(1));
        let reduced = established + Duration::from_secs(1);
        assert_eq!(
            peers.b.udp_handoffs.retiring[&(a_peer, candidate_owner)].receive_deadline,
            reduced
        );
        peers.b.set_session_ttl(Duration::from_secs(600));
        assert_eq!(
            peers.b.udp_handoffs.retiring[&(a_peer, candidate_owner)].receive_deadline,
            reduced
        );
        assert_eq!(
            peers.b.udp_handoffs.retiring[&(a_peer, candidate_owner)].lifetime,
            Duration::from_secs(1)
        );
        drop(received);
        drop(request);
        peers
            .b
            .expire_sessions_at(reduced, Duration::from_secs(600));
        assert!(routes.upgrade().is_none());
    }

    #[tokio::test]
    async fn authorized_candidate_supersession_preserves_exact_receive_keys_and_replay() {
        let mut peers = Peers::new("127.0.0.1:0", 1).await;
        let a_peer = peers.a_peer();
        let b_peer = peers.b_peer();
        let old_b = peers.b.udp_owner_id(a_peer);
        peers.stage(None);
        let candidate_owner = peers.b.udp_probe_owner_id(a_peer).unwrap();
        peers.promote_a_only().await;
        let routes = Arc::downgrade(&peers.b.udp_handoffs.candidates[&a_peer].routes);
        peers
            .a
            .send_frame_to_peer(b_peer, &packet(102))
            .await
            .unwrap();
        let accepted = receive(&mut peers.b, 0).await;
        assert!(!peers.b.accept_udp_frame(&accepted).await.unwrap());
        drop(accepted);

        peers.stage(None);
        assert_ne!(peers.b.udp_probe_owner_id(a_peer), Some(candidate_owner));
        assert!(routes.upgrade().is_some());
        assert!(
            peers
                .b
                .udp_handoffs
                .retiring
                .contains_key(&(a_peer, candidate_owner))
        );
        peers
            .a
            .send_frame_to_peer(b_peer, &packet(103))
            .await
            .unwrap();
        let received = receive(&mut peers.b, 0).await;
        assert_eq!(received.phase, Phase::Retiring(candidate_owner));
        assert!(!peers.b.accept_udp_frame(&received).await.unwrap());
        assert_eq!(peers.b.udp_owner_id(a_peer), old_b);

        // Archiving a receive owner must move, not recreate, its replay window.
        send_phase(&peers.a, b_peer, Phase::Active, &packet(102)).await;
        let replay = receive(&mut peers.b, 0).await;
        assert!(matches!(
            peers.b.accept_udp_frame(&replay).await,
            Err(PacketPlaneIoError::Datagram(
                PacketPlaneDatagramError::ReplayedDatagram { .. }
            ))
        ));
        assert_eq!(peers.b.udp_owner_id(a_peer), old_b);
    }

    #[tokio::test]
    async fn active_tx_expiry_preserves_younger_authorized_receive_keys_and_endpoint() {
        let mut peers = Peers::new("127.0.0.1:0", 1).await;
        let a_peer = peers.a_peer();
        let b_peer = peers.b_peer();
        peers.stage(None);
        let candidate_owner = peers.b.udp_probe_owner_id(a_peer).unwrap();
        peers.promote_a_only().await;
        let routes = Arc::downgrade(&peers.b.udp_handoffs.candidates[&a_peer].routes);
        let endpoint = peers.b.udp_handoffs.candidates[&a_peer].session.endpoint;
        let now = Instant::now();
        peers.b.sessions.get_mut(&a_peer).unwrap().established_at = now - Duration::from_secs(2);
        peers
            .b
            .session_lifetimes
            .insert(a_peer, Duration::from_secs(1));
        peers
            .b
            .udp_handoffs
            .candidates
            .get_mut(&a_peer)
            .unwrap()
            .deadline = now - Duration::from_millis(1);
        assert_eq!(
            peers
                .b
                .expire_sessions_at(now, Duration::from_secs(600))
                .len(),
            1
        );
        assert!(!peers.b.sessions.contains_key(&a_peer));
        assert_eq!(peers.b.udp_owner_id(a_peer), None);
        assert!(peers.b.session_endpoints[&endpoint].contains(&a_peer));
        assert!(routes.upgrade().is_some());
        assert!(!peers.b.has_pending_udp_replacement(a_peer));

        peers
            .a
            .send_frame_to_peer(b_peer, &packet(102))
            .await
            .unwrap();
        let received = receive(&mut peers.b, 0).await;
        assert_eq!(received.phase, Phase::Retiring(candidate_owner));
        assert!(!peers.b.accept_udp_frame(&received).await.unwrap());
        assert_eq!(received.received.frame, packet(102));
        drop(received);
        assert!(
            peers
                .b
                .send_frame_to_peer(a_peer, &packet(103))
                .await
                .is_err()
        );
        assert!(peers.b.forget_peer(a_peer));
        assert!(routes.upgrade().is_none());
        assert!(!peers.b.session_endpoints.contains_key(&endpoint));
    }

    #[tokio::test]
    async fn delayed_nonce_ack_promotes_once_beyond_candidate_data_replay_window() {
        let mut peers = Peers::new("127.0.0.1:0", 1).await;
        let a_peer = peers.a_peer();
        let b_peer = peers.b_peer();
        let old_b = peers.b.udp_owner_id(a_peer);
        peers.stage(None);
        let next_b = peers.b.udp_probe_owner_id(a_peer);
        let a_challenge = peers.challenge().await;
        peers
            .b
            .send_udp_path_probe(a_peer, &request(100, B_TOKEN))
            .await
            .unwrap();
        let b_challenge = receive(&mut peers.a, 0).await;
        assert!(!peers.a.accept_udp_frame(&b_challenge).await.unwrap());
        peers
            .a
            .send_udp_probe_reply(&b_challenge, &ack(101, B_TOKEN))
            .await
            .unwrap();
        let delayed_ack = receive(&mut peers.b, 0).await;
        assert_eq!(delayed_ack.phase, Phase::Candidate);
        peers
            .b
            .send_udp_probe_reply(&a_challenge, &ack(101, A_TOKEN))
            .await
            .unwrap();
        let a_ack = receive(&mut peers.a, 0).await;
        assert!(peers.a.accept_udp_frame(&a_ack).await.unwrap());

        for sequence in 102..=172 {
            peers
                .a
                .send_frame_to_peer(b_peer, &packet(sequence))
                .await
                .unwrap();
            let received = receive(&mut peers.b, 0).await;
            assert_eq!(received.phase, Phase::Candidate);
            assert!(!peers.b.accept_udp_frame(&received).await.unwrap());
            assert_eq!(peers.b.udp_owner_id(a_peer), old_b);
        }
        assert!(peers.b.accept_udp_frame(&delayed_ack).await.unwrap());
        assert_eq!(peers.b.udp_owner_id(a_peer), next_b);
        assert!(!peers.b.has_pending_udp_replacement(a_peer));
        assert_interrupted(peers.b.accept_udp_frame(&delayed_ack).await.unwrap_err());

        send_phase(&peers.a, b_peer, Phase::Active, &packet(102)).await;
        let old_data = receive(&mut peers.b, 0).await;
        assert!(matches!(
            peers.b.accept_udp_frame(&old_data).await,
            Err(PacketPlaneIoError::Datagram(
                PacketPlaneDatagramError::DatagramOutsideReplayWindow { .. }
            ))
        ));
        peers.payload(173).await;
    }

    #[tokio::test]
    async fn receive_capacity_rejects_install_before_mutation_without_evicting_keys() {
        timeout(Duration::from_secs(20), async {
            let mut peers = Peers::new("127.0.0.1:0", 1).await;
            let a_peer = peers.a_peer();
            let b_peer = peers.b_peer();
            let mut required = Vec::new();
            let mut rejected = false;
            for _ in 0..=MAX_RETIRING {
                let old_owner = peers.a.udp_owner_id(b_peer);
                let old_candidate = peers.a.udp_probe_owner_id(b_peer);
                let old_retained = peers.a.udp_handoffs.retiring.len();
                let old_endpoints = peers.a.session_endpoints.clone();
                match peers.try_stage(None) {
                    Ok(()) => {
                        peers.promote_a_only().await;
                        required.push(Arc::downgrade(
                            &peers.b.udp_handoffs.candidates[&a_peer].routes,
                        ));
                        assert!(required.iter().all(|routes| routes.upgrade().is_some()));
                        assert!(
                            peers.a.udp_handoffs.retiring.len()
                                + 2 * peers.a.udp_handoffs.candidates.len()
                                <= MAX_RETIRING
                        );
                        assert!(
                            peers.b.udp_handoffs.retiring.len()
                                + 2 * peers.b.udp_handoffs.candidates.len()
                                <= MAX_RETIRING
                        );
                    }
                    Err(error) => {
                        assert!(
                            error.starts_with("A: UDP receive ownership limit"),
                            "{error}"
                        );
                        assert_eq!(peers.a.udp_owner_id(b_peer), old_owner);
                        assert_eq!(peers.a.udp_probe_owner_id(b_peer), old_candidate);
                        assert_eq!(peers.a.udp_handoffs.retiring.len(), old_retained);
                        assert_eq!(peers.a.session_endpoints, old_endpoints);
                        assert!(required.iter().all(|routes| routes.upgrade().is_some()));
                        rejected = true;
                        break;
                    }
                }
            }
            assert!(rejected, "bounded ownership must refuse new negotiation");
            peers
                .a
                .send_frame_to_peer(b_peer, &packet(102))
                .await
                .unwrap();
            let received = receive(&mut peers.b, 0).await;
            assert!(!peers.b.accept_udp_frame(&received).await.unwrap());
            drop(received);
            assert!(peers.b.forget_peer(a_peer));
            assert!(required.iter().all(|routes| routes.upgrade().is_none()));
        })
        .await
        .expect("bounded receive-owner capacity regression");
    }

    #[tokio::test]
    async fn rejected_high_sequence_candidate_payload_cannot_poison_exact_ack_window() {
        let mut peers = Peers::new("127.0.0.1:0", 1).await;
        let old = peers.a.udp_owner_id(peers.b_peer());
        peers.stage(None);
        assert!(
            peers
                .a
                .send_udp_path_probe(peers.b_peer(), &packet(10))
                .await
                .is_err()
        );
        let challenge = peers.challenge().await;
        send_phase(
            &peers.b,
            peers.a_peer(),
            Phase::Candidate,
            &packet(u64::MAX - 1),
        )
        .await;
        assert!(matches!(
            timeout(IO_TIMEOUT, peers.a.recv_frame_from_session_scoped())
                .await
                .unwrap(),
            Err(PacketPlaneIoError::Datagram(
                PacketPlaneDatagramError::Decrypt
            ))
        ));
        peers
            .b
            .send_udp_probe_reply(&challenge, &ack(101, A_TOKEN ^ 1))
            .await
            .unwrap();
        let wrong = receive(&mut peers.a, 0).await;
        assert_eq!(wrong.phase, Phase::Candidate);
        assert!(!peers.a.accept_udp_frame(&wrong).await.unwrap());
        assert_eq!(peers.a.udp_owner_id(peers.b_peer()), old);
        assert!(
            !peers.b.udp_handoffs.candidates[&peers.a_peer()]
                .receive_authorized
                .load(Ordering::Acquire)
        );
        peers.payload(2).await;
        peers
            .b
            .send_udp_probe_reply(&challenge, &ack(102, A_TOKEN))
            .await
            .unwrap();
        let correct = receive(&mut peers.a, 0).await;
        assert!(peers.a.accept_udp_frame(&correct).await.unwrap());
        assert_ne!(peers.a.udp_owner_id(peers.b_peer()), old);
        assert!(
            peers.b.udp_handoffs.candidates[&peers.a_peer()]
                .receive_authorized
                .load(Ordering::Acquire)
        );
    }

    #[tokio::test]
    async fn wrong_listener_ack_cannot_promote_or_consume_replay_on_the_right_listener() {
        let mut peers = Peers::new("127.0.0.1:0", 2).await;
        let old = peers.a.udp_owner_id(peers.b_peer());
        peers.stage(None);
        let challenge = peers.challenge().await;
        let candidate = &peers.b.udp_handoffs.candidates[&peers.a_peer()];
        let wire = candidate
            .session
            .keys
            .seal
            .seal_frame(&ack(101, A_TOKEN))
            .unwrap();
        peers.b.sockets[0]
            .send_to(&wire, peers.a.listeners[1])
            .await
            .unwrap();
        let wrong = receive(&mut peers.a, 1).await;
        assert_eq!(wrong.phase, Phase::Candidate);
        assert_eq!(wrong.listener, 1);
        assert!(!peers.a.accept_udp_frame(&wrong).await.unwrap());
        assert_eq!(peers.a.udp_owner_id(peers.b_peer()), old);
        peers.b.sockets[0]
            .send_to(&wire, peers.a.listeners[0])
            .await
            .unwrap();
        let correct = receive(&mut peers.a, 0).await;
        assert!(peers.a.accept_udp_frame(&correct).await.unwrap());
        drop(challenge);
    }

    #[tokio::test]
    async fn wrong_local_tuple_does_not_consume_the_exact_candidate_ack() {
        let mut peers = Peers::new("127.0.0.1:0", 1).await;
        let old = peers.a.udp_owner_id(peers.b_peer());
        peers.stage(None);
        let challenge = peers.challenge().await;
        peers
            .b
            .send_udp_probe_reply(&challenge, &ack(101, A_TOKEN))
            .await
            .unwrap();
        let mut received = receive(&mut peers.a, 0).await;
        let actual = received.received.local_addr;
        for wrong in [
            SocketAddr::new("127.0.0.2".parse().unwrap(), actual.port()),
            SocketAddr::new(actual.ip(), if actual.port() == 1 { 2 } else { 1 }),
        ] {
            received.received.local_addr = wrong;
            assert!(matches!(peers.a.accept_udp_frame(&received).await,
                Err(PacketPlaneIoError::Io(ref error)) if error.kind() == io::ErrorKind::AddrNotAvailable));
            assert_eq!(peers.a.udp_owner_id(peers.b_peer()), old);
        }
        received.received.local_addr = actual;
        assert!(peers.a.accept_udp_frame(&received).await.unwrap());
        assert_ne!(peers.a.udp_owner_id(peers.b_peer()), old);
    }

    #[tokio::test]
    async fn matching_ack_cannot_promote_a_stale_prepared_route() {
        let mut peers = Peers::new("127.0.0.1:0", 1).await;
        let peer = peers.b_peer();
        let old = peers.a.udp_owner_id(peer);
        peers.stage(None);
        let challenge = peers.challenge().await;
        peers
            .b
            .send_udp_probe_reply(&challenge, &ack(101, A_TOKEN))
            .await
            .unwrap();
        let received = receive(&mut peers.a, 0).await;
        let epoch = peers.a.udp_handoffs.candidates[&peer].routes.sockets[0]
            .path
            .get()
            .unwrap()
            .lease
            .epoch();
        peers
            .a
            .udp_owner
            .as_ref()
            .unwrap()
            .retire_observer_for_test();
        assert!(!epoch.is_current());
        assert_interrupted(peers.a.accept_udp_frame(&received).await.unwrap_err());
        assert_eq!(peers.a.udp_owner_id(peer), old);
        assert!(peers.a.has_pending_udp_replacement(peer));
        peers.payload(2).await;
    }

    #[tokio::test]
    async fn ack_captured_before_supersession_cannot_promote_a_new_session_owner() {
        let mut peers = Peers::new("127.0.0.1:0", 1).await;
        let peer = peers.b_peer();
        let old = peers.a.udp_owner_id(peer);
        peers.stage(None);
        let challenge = peers.challenge().await;
        peers
            .b
            .send_udp_probe_reply(&challenge, &ack(101, A_TOKEN))
            .await
            .unwrap();
        let captured = receive(&mut peers.a, 0).await;
        let retired = Arc::downgrade(captured.routes.as_ref().unwrap());
        peers.stage(None);
        assert_ne!(captured.owner_id(), peers.a.udp_probe_owner_id(peer));
        assert_interrupted(peers.a.accept_udp_frame(&captured).await.unwrap_err());
        assert_eq!(peers.a.udp_owner_id(peer), old);
        drop(captured);
        assert!(retired.upgrade().is_none());
        peers.payload(2).await;
    }

    #[tokio::test]
    async fn idle_validation_timeout_releases_candidate_and_distinct_endpoint_without_touching_active()
     {
        let mut peers = Peers::new("127.0.0.1:0", 2).await;
        let peer = peers.b_peer();
        let old = peers.a.udp_owner_id(peer);
        let active_endpoint = peers.a.sessions[&peer].endpoint;
        let candidate_endpoint = peers.b.listeners[1];
        peers.stage(Some(candidate_endpoint));
        assert_ne!(active_endpoint, candidate_endpoint);
        let candidate = peers.a.udp_handoffs.candidates.get_mut(&peer).unwrap();
        let lifetime = Arc::downgrade(&candidate.routes);
        candidate.deadline = Instant::now() + Duration::from_millis(30);
        assert!(peers.a.session_endpoints[&candidate_endpoint].contains(&peer));
        assert!(
            timeout(
                Duration::from_millis(120),
                peers.a.recv_frame_from_session_scoped()
            )
            .await
            .is_err()
        );
        assert!(peers.a.udp_handoffs.candidates.is_empty());
        assert!(!peers.a.session_endpoints.contains_key(&candidate_endpoint));
        assert!(peers.a.session_endpoints[&active_endpoint].contains(&peer));
        assert_eq!(peers.a.udp_owner_id(peer), old);
        assert!(lifetime.upgrade().is_none());
        assert!(peers.a.udp_handoffs.deadline().is_none());
        peers.payload(2).await;
    }

    #[tokio::test]
    async fn receive_key_expiry_releases_old_owner_but_keeps_shared_endpoint_and_new_payload() {
        let mut peers = Peers::new("[::1]:0", 1).await;
        let peer = peers.b_peer();
        let endpoint = peers.a.sessions[&peer].endpoint;
        let old_routes = Arc::downgrade(&peers.a.udp_routes[&peer]);
        let old_owner = peers.a.udp_owner_id(peer).unwrap();
        peers.stage(None);
        peers.promote().await;
        let promoted = peers.a.udp_owner_id(peer);
        assert!(old_routes.upgrade().is_some());
        let retired = peers
            .a
            .udp_handoffs
            .retiring
            .get_mut(&(peer, old_owner))
            .unwrap();
        let expiry = Instant::now() + Duration::from_millis(30);
        retired.receive_deadline = expiry;
        retired.deadline = expiry;
        assert!(
            timeout(
                Duration::from_millis(120),
                peers.a.recv_frame_from_session_scoped()
            )
            .await
            .is_err()
        );
        assert!(peers.a.udp_handoffs.retiring.is_empty());
        assert!(old_routes.upgrade().is_none());
        assert!(peers.a.udp_handoffs.deadline().is_none());
        assert_eq!(peers.a.session_endpoints[&endpoint], vec![peer]);
        assert_eq!(peers.a.udp_owner_id(peer), promoted);
        peers.payload(103).await;
    }

    #[tokio::test]
    async fn ttl_and_revocation_release_all_phase_owners_without_extending_keys() {
        let mut peers = Peers::new("127.0.0.1:0", 1).await;
        let peer = peers.b_peer();
        peers.a.set_session_ttl(Duration::from_secs(1));
        peers.stage(None);
        let candidate = &peers.a.udp_handoffs.candidates[&peer];
        let established = candidate.session.established_at;
        let deadline = candidate.deadline;
        let receive_deadline = candidate.receive_deadline;
        assert!(deadline <= established + Duration::from_secs(1));
        assert_eq!(receive_deadline, established + Duration::from_secs(1));
        peers.a.set_session_ttl(Duration::from_secs(60));
        assert_eq!(peers.a.udp_handoffs.candidates[&peer].deadline, deadline);
        assert_eq!(
            peers.a.udp_handoffs.candidates[&peer].receive_deadline,
            receive_deadline
        );
        assert_eq!(
            peers.a.udp_handoffs.candidates[&peer].lifetime,
            Duration::from_secs(1)
        );
        let candidate_routes = Arc::downgrade(&peers.a.udp_handoffs.candidates[&peer].routes);
        let active_routes = Arc::downgrade(&peers.a.udp_routes[&peer]);
        assert_eq!(
            peers
                .a
                .expire_sessions_at(
                    established + Duration::from_secs(1),
                    Duration::from_secs(60)
                )
                .len(),
            1
        );
        assert!(candidate_routes.upgrade().is_none());
        assert!(active_routes.upgrade().is_none());
        assert!(peers.a.sessions.is_empty());
        assert!(peers.a.session_endpoints.is_empty());
        assert!(peers.a.udp_handoffs.deadline().is_none());

        peers.stage(None);
        peers.stage(None);
        peers.promote().await;
        peers.stage(None);
        let challenge = peers.challenge().await;
        peers
            .b
            .send_udp_probe_reply(&challenge, &ack(101, A_TOKEN))
            .await
            .unwrap();
        let captured = receive(&mut peers.a, 0).await;
        let candidate_routes = Arc::downgrade(captured.routes.as_ref().unwrap());
        let active_routes = Arc::downgrade(&peers.a.udp_routes[&peer]);
        let retiring_routes: Vec<_> = peers
            .a
            .udp_handoffs
            .retiring
            .iter()
            .filter(|((candidate, _), _)| *candidate == peer)
            .map(|(_, slot)| Arc::downgrade(&slot.routes))
            .collect();
        assert!(!retiring_routes.is_empty());
        assert!(peers.a.forget_peer(peer));
        assert!(peers.a.sessions.is_empty());
        assert!(peers.a.session_endpoints.is_empty());
        assert!(peers.a.udp_routes.is_empty());
        assert!(peers.a.udp_route_refresh.is_empty());
        assert!(peers.a.udp_handoffs.deadline().is_none());
        assert!(active_routes.upgrade().is_none());
        assert!(
            retiring_routes
                .iter()
                .all(|routes| routes.upgrade().is_none())
        );
        assert_interrupted(peers.a.accept_udp_frame(&captured).await.unwrap_err());
        assert!(
            peers
                .a
                .send_udp_probe_reply(&captured, &ack(105, A_TOKEN))
                .await
                .is_err()
        );
        drop(captured);
        assert!(candidate_routes.upgrade().is_none());
        assert!(
            peers.b.has_session(peers.a_peer()),
            "remote runtime is not revoked"
        );
    }
}

#[tokio::test]
async fn expired_send_deadline_never_polls_operation_and_pending_work_is_cancelled() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let polled = AtomicBool::new(false);
    let result = udp_path::before_deadline(Some(Instant::now()), async {
        polled.store(true, Ordering::SeqCst);
        Ok::<_, io::Error>(())
    })
    .await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert!(!polled.load(Ordering::SeqCst));

    struct Guard(Arc<AtomicBool>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let dropped = Arc::new(AtomicBool::new(false));
    let guard = Guard(Arc::clone(&dropped));
    let operation = async move {
        let _guard = guard;
        std::future::pending::<io::Result<()>>().await
    };
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        udp_path::before_deadline(Some(Instant::now() + Duration::from_millis(15)), operation),
    )
    .await
    .expect("bounded pending operation");
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert!(dropped.load(Ordering::SeqCst));
}

#[test]
fn idle_handoffs_have_no_deadline_and_phase_lifetimes_never_extend_keys() {
    assert!(Handoffs::default().deadline().is_none());
    let now = Instant::now();
    assert_eq!(
        cap(now + VALIDATION_TIMEOUT, now, Duration::from_secs(1)),
        now + Duration::from_secs(1)
    );
    assert_eq!(
        cap(now + VALIDATION_TIMEOUT, now, Duration::MAX),
        now + VALIDATION_TIMEOUT
    );
}
