#[cfg(target_os = "linux")]
mod udp_startup {
    use super::*;

    struct End {
        identity: NodeIdentity,
        peer: PeerId,
        remote: PeerId,
        forwarder: Forwarder,
        node: P2pNode,
        packets: PacketPlaneRuntime,
        capabilities: ControlCapabilities,
        peers: PeerCapabilities,
        paths: PathSet,
        negotiator: PacketPlaneNegotiator,
        publication: MembershipRecordSyncs,
        probes: PathProbeTracker,
        metrics: RuntimeMetrics,
        received_hello_endpoint: Option<SocketAddr>,
        accepted_endpoint: Option<SocketAddr>,
        prepared_sources: usize,
        deferred_accepts: usize,
        hostname_only_peer_view: bool,
    }

    impl End {
        async fn new(identity: NodeIdentity, remote: Libp2pPeerId, address: &str) -> Self {
            let mut packets = PacketPlaneRuntime::bind(vec![address.parse().unwrap()])
                .await
                .unwrap();
            let config = config_with_peer(&identity, remote);
            packets.follow_physical_routes(config.interface.name.clone());
            let capabilities = ControlCapabilities::local("lab", None, 1280)
                .with_packet_endpoint_candidates(vec![
                    packets.primary_listener().unwrap().to_string(),
                ])
                .with_owned_udp_packet_plane(true);
            let mut paths = PathSet::new();
            paths.record_established(PeerId::from_libp2p(remote), PathKind::DirectTcpStream);
            let forwarder = Forwarder::from_config(&config).unwrap();
            let publication = MembershipRecordSyncs::with_acknowledged_packet_capabilities_for_test(
                remote,
                capabilities.clone(),
                &forwarder,
            );
            Self {
                peer: identity.peer_id.parse().unwrap(),
                remote: PeerId::from_libp2p(remote),
                node: membership_sync_test_node(identity.clone()),
                forwarder,
                identity,
                packets,
                capabilities,
                peers: PeerCapabilities::default(),
                paths,
                negotiator: PacketPlaneNegotiator::default(),
                publication,
                probes: PathProbeTracker::default(),
                metrics: RuntimeMetrics::default(),
                received_hello_endpoint: None,
                accepted_endpoint: None,
                prepared_sources: 0,
                deferred_accepts: 0,
                hostname_only_peer_view: false,
            }
        }

        fn record_caps(&mut self, mut capabilities: ControlCapabilities) {
            if self.hostname_only_peer_view {
                capabilities
                    .packet_endpoint_candidates
                    .retain(|candidate| candidate.parse::<SocketAddr>().is_err());
                capabilities
                    .owned_quic_packet_endpoint_candidates
                    .retain(|candidate| candidate.parse::<SocketAddr>().is_err());
            }
            self.peers.record(self.remote, capabilities);
        }

        fn assert_unvalidated(&self) {
            assert!(self.packets.has_pending_udp_replacement(self.remote));
            assert!(!self.packets.has_session(self.remote));
            assert!(self.packets.can_receive());
            assert_eq!(self.packets.udp_owner_id(self.remote), None);
            assert_eq!(self.packets.session_mtu_for(self.remote), None);
            assert_eq!(
                local_packet_datagram_backend(
                    &self.paths,
                    &self.peers,
                    Some(&self.packets),
                    None,
                    self.remote,
                ),
                None,
                "an unproven candidate must not become the payload backend"
            );
            assert!(!has_healthy_path_kind(
                &self.paths,
                self.remote,
                PathKind::DirectUdpDatagram,
            ));
            assert!(matches!(
                packet_transport_decision(
                    &self.paths,
                    &self.peers,
                    Some(&self.packets),
                    None,
                    self.remote,
                ),
                PacketTransportDecision::StreamFallback { .. }
            ));
        }

        async fn receive(&mut self) -> ScopedUdpFrame {
            timeout(
                TokioDuration::from_secs(2),
                self.packets.recv_frame_from_session_scoped(),
            )
            .await
            .expect("bounded startup datagram")
            .unwrap()
        }

        async fn handle(&mut self, scoped: &ScopedUdpFrame) -> bool {
            let promoted = self.packets.accept_udp_frame(scoped).await.unwrap();
            if promoted {
                record_packet_plane_path_established(
                    &mut self.paths,
                    &self.metrics,
                    self.remote,
                    PacketDatagramBackend::OwnedUdp,
                    self.packets.session_mtu_for(self.remote).unwrap(),
                );
            }
            handle_packet_plane_path_probe_scoped(
                &mut self.forwarder,
                &mut self.paths,
                &self.peers,
                Some(&self.packets),
                None,
                PacketDatagramBackend::OwnedUdp,
                &mut self.probes,
                &self.metrics,
                self.remote,
                &scoped.received,
                scoped.owner_id(),
                Some(scoped),
            )
            .await;
            promoted
        }

        fn retry(&mut self) {
            retry_packet_plane_negotiation(
                &mut PacketPlaneExpiryContext {
                    membership_record_syncs: &mut self.publication,
                    active_connections: &HashMap::new(),
                    swarm: &mut self.node.swarm,
                    forwarder: &self.forwarder,
                    paths: &mut self.paths,
                    peer_capabilities: &self.peers,
                    packet_plane: &mut self.packets,
                    packet_plane_quic: None,
                    negotiator: &mut self.negotiator,
                    identity: &self.identity,
                    local_capabilities: &mut self.capabilities,
                    metrics: &self.metrics,
                    session_ttl: Duration::from_secs(60),
                },
                self.remote,
            );
        }

        async fn resume_dns(&mut self) {
            udp_preparation::resume_dns(
                &mut PacketPlaneExpiryContext {
                    membership_record_syncs: &mut self.publication,
                    active_connections: &HashMap::new(),
                    swarm: &mut self.node.swarm,
                    forwarder: &self.forwarder,
                    paths: &mut self.paths,
                    peer_capabilities: &self.peers,
                    packet_plane: &mut self.packets,
                    packet_plane_quic: None,
                    negotiator: &mut self.negotiator,
                    identity: &self.identity,
                    local_capabilities: &mut self.capabilities,
                    metrics: &self.metrics,
                    session_ttl: Duration::from_secs(60),
                },
                &mut self.probes,
            )
            .await;
        }

        async fn finish_preparation(&mut self) {
            assert!(!self.negotiator.udp_preparations.tasks.is_empty());
            while !self.negotiator.udp_preparations.tasks.is_empty() {
                let completion = timeout(
                    TokioDuration::from_secs(2),
                    self.negotiator.udp_preparations.tasks.join_next(),
                )
                .await
                .expect("bounded source preparation")
                .expect("one preparation task");
                self.prepared_sources += 1;
                udp_preparation::handle(
                    &mut PacketPlaneExpiryContext {
                        membership_record_syncs: &mut self.publication,
                        active_connections: &HashMap::new(),
                        swarm: &mut self.node.swarm,
                        forwarder: &self.forwarder,
                        paths: &mut self.paths,
                        peer_capabilities: &self.peers,
                        packet_plane: &mut self.packets,
                        packet_plane_quic: None,
                        negotiator: &mut self.negotiator,
                        identity: &self.identity,
                        local_capabilities: &mut self.capabilities,
                        metrics: &self.metrics,
                        session_ttl: Duration::from_secs(60),
                    },
                    &mut self.probes,
                    completion,
                )
                .await;
            }
        }

        async fn accept(&mut self, hello: &[u8]) -> Option<ControlResponse> {
            packet_plane_accept_result_for_peer(
                PacketPlaneAcceptContext {
                    active_connections: &HashMap::new(),
                    forwarder: &self.forwarder,
                    peer_capabilities: &self.peers,
                    paths: &mut self.paths,
                    metrics: &self.metrics,
                    packet_plane: &mut self.packets,
                    packet_plane_quic: None,
                    negotiator: &mut self.negotiator,
                    identity: &self.identity,
                    local_capabilities: &self.capabilities,
                    publication: &self.publication,
                    path_probe_tracker: &mut self.probes,
                },
                self.forwarder
                    .transport_peer_for_overlay(self.remote)
                    .unwrap(),
                hello,
            )
            .await
        }

        async fn control_event(
            &mut self,
            event: request_response::Event<ControlRequest, ControlResponse>,
        ) {
            let completion = self.publication.finish_capability_event(
                &event,
                &self.forwarder,
                &self.capabilities,
                &[],
                true,
                Instant::now(),
            );
            if matches!(completion, control_delivery::Completion::Discard) {
                return;
            }
            match event {
                request_response::Event::Message {
                    peer,
                    message:
                        Message::Request {
                            request, channel, ..
                        },
                    ..
                } => {
                    assert_eq!(PeerId::from_libp2p(peer), self.remote);
                    let response = match request {
                        ControlRequest::Capabilities(capabilities) => {
                            assert!(
                                crate::runtime::control::validate_capabilities(
                                    &capabilities,
                                    "lab",
                                    None,
                                    &[]
                                )
                                .is_none()
                            );
                            self.record_caps(capabilities);
                            Some(ControlResponse::CapabilitiesAccepted(
                                self.capabilities.clone(),
                            ))
                        }
                        ControlRequest::PacketPlaneHello(hello) => {
                            self.received_hello_endpoint = Some(
                                PacketPlaneHandshake::decode(&hello)
                                    .unwrap()
                                    .verify("lab", Some(self.remote))
                                    .unwrap()
                                    .endpoint,
                            );
                            match self.accept(&hello).await {
                                Some(response) => Some(response),
                                None => {
                                    self.deferred_accepts += 1;
                                    assert!(
                                        self.negotiator
                                            .defer_response(udp_preparation::DeferredResponse {
                                                peer,
                                                handshake: hello,
                                                channel
                                            })
                                            .is_ok()
                                    );
                                    return;
                                }
                            }
                        }
                        request => panic!("unexpected request {request:?}"),
                    };
                    self.node
                        .swarm
                        .behaviour_mut()
                        .control
                        .send_response(channel, response.unwrap())
                        .unwrap();
                }
                request_response::Event::Message {
                    peer,
                    message: Message::Response { response, .. },
                    ..
                } => match response {
                    ControlResponse::CapabilitiesAccepted(capabilities) => {
                        self.record_caps(capabilities);
                        if let control_delivery::Completion::Reply(ticket) = completion {
                            self.publication.acknowledge_capabilities(
                                ticket,
                                &self.forwarder,
                                true,
                                Instant::now(),
                            );
                            udp_preparation::resume(
                                &mut PacketPlaneExpiryContext {
                                    membership_record_syncs: &mut self.publication,
                                    active_connections: &HashMap::new(),
                                    swarm: &mut self.node.swarm,
                                    forwarder: &self.forwarder,
                                    paths: &mut self.paths,
                                    peer_capabilities: &self.peers,
                                    packet_plane: &mut self.packets,
                                    packet_plane_quic: None,
                                    negotiator: &mut self.negotiator,
                                    identity: &self.identity,
                                    local_capabilities: &mut self.capabilities,
                                    metrics: &self.metrics,
                                    session_ttl: Duration::from_secs(60),
                                },
                                &mut self.probes,
                                peer,
                            )
                            .await;
                            self.retry();
                        }
                    }
                    ControlResponse::PacketPlaneAccepted(accept) => {
                        self.accepted_endpoint = Some(
                            PacketPlaneHandshake::decode(&accept)
                                .unwrap()
                                .verify("lab", Some(self.remote))
                                .unwrap()
                                .endpoint,
                        );
                        complete_packet_plane_hello(
                            &mut PacketPlaneCompleteContext {
                                forwarder: &self.forwarder,
                                peer_capabilities: &self.peers,
                                packet_plane: &mut self.packets,
                                packet_plane_quic: None,
                                negotiator: &mut self.negotiator,
                                paths: &mut self.paths,
                                metrics: &self.metrics,
                                local_capabilities: &self.capabilities,
                                path_probe_tracker: &mut self.probes,
                            },
                            peer,
                            &accept,
                        )
                        .unwrap();
                    }
                    response => panic!("unexpected response {response:?}"),
                },
                request_response::Event::OutboundFailure { error, .. } => {
                    panic!("control failed: {error}")
                }
                _ => {}
            }
        }
    }

    async fn connect_control(a: &mut End, b: &mut End) {
        b.node
            .swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let address = timeout(TokioDuration::from_secs(2), async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } =
                    b.node.swarm.select_next_some().await
                {
                    break address;
                }
            }
        })
        .await
        .unwrap();
        a.node
            .swarm
            .add_peer_address(b.identity.peer_id.parse().unwrap(), address);
        a.node
            .swarm
            .dial(b.identity.peer_id.parse::<Libp2pPeerId>().unwrap())
            .unwrap();
        timeout(TokioDuration::from_secs(5), async {
            while !a
                .node
                .swarm
                .is_connected(&b.identity.peer_id.parse().unwrap())
                || !b
                    .node
                    .swarm
                    .is_connected(&a.identity.peer_id.parse().unwrap())
            {
                tokio::select! {
                    _ = a.node.swarm.select_next_some() => {},
                    _ = b.node.swarm.select_next_some() => {},
                }
            }
        })
        .await
        .expect("fixture's healthy direct control path must really be connected");
    }

    async fn drive_control_pair(a: &mut End, b: &mut End) {
        drive_control_pair_with_dns(a, b, None).await;
    }

    async fn drive_control_pair_with_dns(
        a: &mut End,
        b: &mut End,
        mut dns_updates: Option<tokio::sync::watch::Receiver<()>>,
    ) {
        timeout(TokioDuration::from_secs(8), async {
            loop {
                if !a.negotiator.udp_preparations.tasks.is_empty() { a.finish_preparation().await; }
                if !b.negotiator.udp_preparations.tasks.is_empty() { b.finish_preparation().await; }
                if a.packets.has_pending_udp_replacement(b.peer) && b.packets.has_pending_udp_replacement(a.peer) { return; }
                tokio::select! {
                    event = a.node.swarm.select_next_some() => {
                        if let SwarmEvent::Behaviour(BehaviourEvent::Control(event)) = event { a.control_event(event).await; }
                    }
                    event = b.node.swarm.select_next_some() => {
                        if let SwarmEvent::Behaviour(BehaviourEvent::Control(event)) = event { b.control_event(event).await; }
                    }
                    () = packet_endpoint_dns_changed(&mut dns_updates), if dns_updates.is_some() => {
                        a.resume_dns().await;
                        b.resume_dns().await;
                    }
                }
            }
        }).await.expect("source publication, real ACK and deferred negotiation");
    }

    async fn hostname_only_zero_ttl_prepared_udp(ip: IpAddr) {
        use crate::runtime::physical_network::android::dns::fixture::EndpointFixture;

        let dns = EndpointFixture::install(ip).await;
        let mut identities = [
            NodeIdentity::generate_ed25519().unwrap(),
            NodeIdentity::generate_ed25519().unwrap(),
        ];
        identities.sort_by_key(|identity| identity.peer_id.parse::<PeerId>().unwrap().as_bytes());
        let [a_identity, b_identity] = identities;
        let address = SocketAddr::new(ip, 0).to_string();
        let mut a = End::new(a_identity, b_identity.peer_id.parse().unwrap(), &address).await;
        let mut b = End::new(b_identity, a.identity.peer_id.parse().unwrap(), &address).await;
        let a_endpoint = a.packets.primary_listener().unwrap();
        let b_endpoint = b.packets.primary_listener().unwrap();
        for (end, hostname) in [
            (&mut a, "initiator-zero-ttl.example"),
            (&mut b, "responder-zero-ttl.example"),
        ] {
            end.packets.enable_udp_preparation_for_test();
            // Model a receiver-selected hostname-only peer view. Local source
            // aliases and their real publication barrier remain untouched, so
            // final Accept matching must use retained DNS evidence, not aliases.
            end.hostname_only_peer_view = true;
            end.capabilities.packet_endpoint_candidates = vec![format!(
                "{hostname}:{}",
                end.packets.primary_listener().unwrap().port()
            )];
            assert!(crate::runtime::control::validate_capabilities(
                &end.capabilities, "lab", None, &[],
            ).is_none());
            assert!(
                end.capabilities
                    .packet_endpoint_candidates
                    .iter()
                    .all(|candidate| { candidate.parse::<SocketAddr>().is_err() })
            );
            end.publication = MembershipRecordSyncs::with_acknowledged_packet_capabilities_for_test(
                end.forwarder
                    .transport_peer_for_overlay(end.remote)
                    .unwrap(),
                end.capabilities.clone(),
                &end.forwarder,
            );
        }
        let a_hostnames = a.capabilities.packet_endpoint_candidates.clone();
        let b_hostnames = b.capabilities.packet_endpoint_candidates.clone();
        a.record_caps(b.capabilities.clone());
        b.record_caps(a.capabilities.clone());
        assert_eq!(
            a.peers.get(b.peer).unwrap().packet_endpoint_candidates,
            b.capabilities.packet_endpoint_candidates
        );
        assert_eq!(
            b.peers.get(a.peer).unwrap().packet_endpoint_candidates,
            a.capabilities.packet_endpoint_candidates
        );
        connect_control(&mut a, &mut b).await;

        let updates = Some(dns.updates());
        // Prime only once, without consuming either zero-TTL answer. Subsequent
        // Hello/Accept stages must retain snapshots or resume from DNS events.
        dns.ready(&[
            &a.capabilities.packet_endpoint_candidates[0],
            &b.capabilities.packet_endpoint_candidates[0],
        ])
        .await;
        a.retry();
        assert!(
            !a.negotiator.has_pending(b.peer),
            "no Hello before source preparation"
        );
        assert!(!a.negotiator.udp_preparations.tasks.is_empty());
        drive_control_pair_with_dns(&mut a, &mut b, updates).await;
        assert!(a.prepared_sources > 0 && b.prepared_sources > 0);
        assert!(
            b.deferred_accepts > 0,
            "Accept must cross an asynchronous boundary"
        );
        assert_eq!(b.received_hello_endpoint, Some(a_endpoint));
        assert_eq!(a.accepted_endpoint, Some(b_endpoint));
        assert!(dns.requests() > 0);
        for end in [&a, &b] {
            assert!(
                end.publication.packet_capabilities_acknowledged(
                    end.forwarder
                        .transport_peer_for_overlay(end.remote)
                        .unwrap(),
                    &end.capabilities,
                    &end.forwarder,
                )
            );
        }
        a.assert_unvalidated();
        b.assert_unvalidated();

        let packet = Frame::packet(194, 1000, vec![0x45; 20]).unwrap();
        for (end, remote) in [(&a, b.peer), (&b, a.peer)] {
            assert!(matches!(
                end.packets.send_frame_to_peer(remote, &packet).await,
                Err(PacketPlaneIoError::NoSession { .. })
            ));
        }
        send_path_probes(
            &mut a.node.swarm,
            &mut a.forwarder,
            &mut a.paths,
            &a.peers,
            Some(&a.packets),
            None,
            &mut PacketInFlight::new(256),
            &mut a.probes,
            &a.metrics,
        )
        .await;
        let request = b.receive().await;
        assert!(!b.handle(&request).await);
        b.assert_unvalidated();
        let ack = a.receive().await;
        assert!(a.handle(&ack).await);
        assert!(a.packets.has_session(b.peer));
        b.assert_unvalidated();
        let reverse_request = a.receive().await;
        assert!(!a.handle(&reverse_request).await);
        let reverse_ack = b.receive().await;
        assert!(b.handle(&reverse_ack).await);
        assert_eq!(a.packets.session_endpoint_for(b.peer), Some(b_endpoint));
        assert_eq!(b.packets.session_endpoint_for(a.peer), Some(a_endpoint));
        for end in [&a, &b] {
            assert!(!end.packets.has_pending_udp_replacement(end.remote));
            assert_eq!(
                local_packet_datagram_backend(
                    &end.paths,
                    &end.peers,
                    Some(&end.packets),
                    None,
                    end.remote,
                ),
                Some(PacketDatagramBackend::OwnedUdp)
            );
        }
        a.packets.send_frame_to_peer(b.peer, &packet).await.unwrap();
        assert_eq!(b.receive().await.received.frame, packet);
        b.packets.send_frame_to_peer(a.peer, &packet).await.unwrap();
        assert_eq!(a.receive().await.received.frame, packet);
        assert_eq!(
            a.peers.get(b.peer).unwrap().packet_endpoint_candidates,
            b_hostnames,
            "final peer view must contain only the original received hostnames"
        );
        assert_eq!(
            b.peers.get(a.peer).unwrap().packet_endpoint_candidates,
            a_hostnames,
            "final peer view must contain only the original received hostnames"
        );
        dns.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hostname_only_zero_ttl_ipv4_crosses_source_preparation_and_requires_udp_ack() {
        hostname_only_zero_ttl_prepared_udp("127.0.0.1".parse().unwrap()).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hostname_only_zero_ttl_ipv6_crosses_source_preparation_and_requires_udp_ack() {
        hostname_only_zero_ttl_prepared_udp("::1".parse().unwrap()).await;
    }

    #[tokio::test]
    async fn missing_initiator_source_is_published_before_hello_and_waits_for_real_ack() {
        for (wildcard, remote) in [("0.0.0.0:0", "127.0.0.1:0"), ("[::]:0", "[::1]:0")] {
            let mut identities = [
                NodeIdentity::generate_ed25519().unwrap(),
                NodeIdentity::generate_ed25519().unwrap(),
            ];
            identities
                .sort_by_key(|identity| identity.peer_id.parse::<PeerId>().unwrap().as_bytes());
            let [a_identity, b_identity] = identities;
            let mut a = End::new(a_identity, b_identity.peer_id.parse().unwrap(), wildcard).await;
            let mut b = End::new(b_identity, a.identity.peer_id.parse().unwrap(), remote).await;
            a.packets.enable_udp_preparation_for_test();
            b.packets.enable_udp_preparation_for_test();
            a.capabilities.packet_endpoint_candidates.clear();
            a.capabilities = a.capabilities.clone().with_owned_udp_packet_plane(false);
            a.publication = MembershipRecordSyncs::with_acknowledged_packet_capabilities_for_test(
                b.identity.peer_id.parse().unwrap(),
                a.capabilities.clone(),
                &a.forwarder,
            );
            a.peers.record(b.peer, b.capabilities.clone());
            b.peers.record(a.peer, a.capabilities.clone());
            connect_control(&mut a, &mut b).await;
            a.retry();
            a.finish_preparation().await;
            assert!(
                !a.negotiator.has_pending(b.peer),
                "source lookup is not metadata ACK"
            );
            assert!(a.capabilities.supports_owned_udp_packet_plane);
            assert_eq!(a.capabilities.packet_endpoint_candidates.len(), 1);
            assert!(!a.publication.packet_capabilities_acknowledged(
                b.identity.peer_id.parse().unwrap(),
                &a.capabilities,
                &a.forwarder
            ));
            drive_control_pair(&mut a, &mut b).await;
            a.assert_unvalidated();
            b.assert_unvalidated();
            assert!(a.publication.packet_capabilities_acknowledged(
                b.identity.peer_id.parse().unwrap(),
                &a.capabilities,
                &a.forwarder
            ));
            assert_eq!(
                b.peers.get(a.peer).unwrap().packet_endpoint_candidates,
                a.capabilities.packet_endpoint_candidates
            );
        }
    }

    #[tokio::test]
    async fn missing_responder_source_defers_accept_until_real_publication_ack() {
        for (local, wildcard) in [("127.0.0.1:0", "0.0.0.0:0"), ("[::1]:0", "[::]:0")] {
            let a_identity = NodeIdentity::generate_ed25519().unwrap();
            let b_identity = NodeIdentity::generate_ed25519().unwrap();
            let mut a = End::new(a_identity, b_identity.peer_id.parse().unwrap(), local).await;
            let mut b = End::new(b_identity, a.identity.peer_id.parse().unwrap(), wildcard).await;
            b.packets.enable_udp_preparation_for_test();
            b.capabilities.packet_endpoint_candidates.clear();
            b.capabilities = b.capabilities.clone().with_owned_udp_packet_plane(false);
            b.publication = MembershipRecordSyncs::with_acknowledged_packet_capabilities_for_test(
                a.identity.peer_id.parse().unwrap(),
                b.capabilities.clone(),
                &b.forwarder,
            );
            a.peers.record(b.peer, b.capabilities.clone());
            b.peers.record(a.peer, a.capabilities.clone());
            connect_control(&mut a, &mut b).await;
            let (secret, hello, verified) = signed_packet_plane_handshake(
                PacketPlaneHandshakeKind::Hello,
                &a.identity,
                &a.capabilities,
                PacketDatagramBackend::OwnedUdp,
            )
            .unwrap();
            a.negotiator
                .insert(b.peer, secret, verified, PacketDatagramBackend::OwnedUdp);
            let request = a.node.swarm.behaviour_mut().control.send_request(
                &b.identity.peer_id.parse().unwrap(),
                ControlRequest::PacketPlaneHello(hello.encode().unwrap()),
            );
            a.negotiator.pending.get_mut(&b.peer).unwrap().request_id = Some(request);
            timeout(TokioDuration::from_secs(5), async {
                while !b.negotiator.udp_preparations.contains(a.peer, udp_preparation::Role::Responder) {
                    tokio::select! {
                        _ = a.node.swarm.select_next_some() => {},
                        event = b.node.swarm.select_next_some() => {
                            if let SwarmEvent::Behaviour(BehaviourEvent::Control(event)) = event { b.control_event(event).await; }
                        }
                    }
                }
            }).await.unwrap();
            b.finish_preparation().await;
            assert!(
                !b.packets.has_pending_udp_replacement(a.peer),
                "prepared source cannot install or sign before metadata ACK"
            );
            assert!(!b.publication.packet_capabilities_acknowledged(
                a.identity.peer_id.parse().unwrap(),
                &b.capabilities,
                &b.forwarder
            ));
            drive_control_pair(&mut a, &mut b).await;
            a.assert_unvalidated();
            b.assert_unvalidated();
            assert!(b.publication.packet_capabilities_acknowledged(
                a.identity.peer_id.parse().unwrap(),
                &b.capabilities,
                &b.forwarder
            ));
        }
    }

    #[tokio::test]
    async fn prepared_udp_negotiation_defers_both_signers_and_preserves_fallback_until_ack() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let mut identities = [
                NodeIdentity::generate_ed25519().unwrap(),
                NodeIdentity::generate_ed25519().unwrap(),
            ];
            identities
                .sort_by_key(|identity| identity.peer_id.parse::<PeerId>().unwrap().as_bytes());
            let [a_identity, b_identity] = identities;
            let mut a = End::new(a_identity, b_identity.peer_id.parse().unwrap(), address).await;
            let mut b = End::new(b_identity, a.identity.peer_id.parse().unwrap(), address).await;
            a.packets.enable_udp_preparation_for_test();
            b.packets.enable_udp_preparation_for_test();
            // An automatic public hint from a different socket is not source proof.
            for end in [&mut a] {
                let hint = if address.starts_with('[') {
                    "[2001:db8::1]:42000"
                } else {
                    "203.0.113.1:42000"
                };
                end.capabilities
                    .packet_endpoint_candidates
                    .push(hint.to_owned());
                end.publication =
                    MembershipRecordSyncs::with_acknowledged_packet_capabilities_for_test(
                        end.forwarder
                            .transport_peer_for_overlay(end.remote)
                            .unwrap(),
                        end.capabilities.clone(),
                        &end.forwarder,
                    );
            }
            a.peers.record(b.peer, b.capabilities.clone());
            b.peers.record(a.peer, a.capabilities.clone());
            b.node
                .swarm
                .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .unwrap();
            let listen = timeout(TokioDuration::from_secs(2), async {
                loop {
                    if let SwarmEvent::NewListenAddr { address, .. } =
                        b.node.swarm.select_next_some().await
                    {
                        break address;
                    }
                }
            })
            .await
            .unwrap();
            a.node
                .swarm
                .add_peer_address(b.identity.peer_id.parse().unwrap(), listen);
            a.retry();
            assert!(
                !a.negotiator.has_pending(b.peer),
                "no Hello before source preparation"
            );
            assert!(!a.node.swarm.behaviour().control.has_any_pending_requests());
            a.finish_preparation().await;
            let pending = &a.negotiator.pending[&b.peer];
            assert_eq!(
                pending.hello.endpoint,
                a.packets.primary_listener().unwrap()
            );
            let request_id = pending.request_id.unwrap();
            let (peer, hello, channel) = timeout(TokioDuration::from_secs(5), async {
                loop {
                    tokio::select! {
                        event = a.node.swarm.select_next_some() => {
                            if let SwarmEvent::Behaviour(BehaviourEvent::Control(request_response::Event::OutboundFailure { error, .. })) = event {
                                panic!("loopback Hello failed: {error}");
                            }
                        }
                        event = b.node.swarm.select_next_some() => {
                            if let SwarmEvent::Behaviour(BehaviourEvent::Control(request_response::Event::Message {
                                peer, message: Message::Request { request: ControlRequest::PacketPlaneHello(hello), channel, .. }, ..
                            })) = event {
                                break (peer, hello, channel);
                            }
                        }
                    }
                }
            }).await.expect("real control Hello");
            assert!(
                b.accept(&hello).await.is_none(),
                "no Accept before responder source preparation"
            );
            assert!(!b.packets.has_pending_udp_replacement(a.peer));
            assert!(
                b.negotiator
                    .udp_preparations
                    .defer(udp_preparation::DeferredResponse {
                        peer,
                        handshake: hello,
                        channel
                    })
                    .is_ok()
            );
            b.finish_preparation().await;
            let accept = timeout(TokioDuration::from_secs(5), async {
                loop {
                    tokio::select! {
                        _ = b.node.swarm.select_next_some() => {},
                        event = a.node.swarm.select_next_some() => {
                            if let SwarmEvent::Behaviour(BehaviourEvent::Control(request_response::Event::Message {
                                message: Message::Response { request_id: received_id, response }, ..
                            })) = event {
                                assert_eq!(received_id, request_id);
                                match response {
                                    ControlResponse::PacketPlaneAccepted(accept) => break accept,
                                    response => panic!("expected deferred Accept, got {response:?}"),
                                }
                            }
                        }
                    }
                }
            }).await.expect("deferred response delivered");
            let verified = PacketPlaneHandshake::decode(&accept)
                .unwrap()
                .verify("lab", Some(b.peer))
                .unwrap();
            assert_eq!(verified.endpoint, b.packets.primary_listener().unwrap());
            complete_packet_plane_hello(
                &mut PacketPlaneCompleteContext {
                    forwarder: &a.forwarder,
                    peer_capabilities: &a.peers,
                    packet_plane: &mut a.packets,
                    packet_plane_quic: None,
                    negotiator: &mut a.negotiator,
                    paths: &mut a.paths,
                    metrics: &a.metrics,
                    local_capabilities: &a.capabilities,
                    path_probe_tracker: &mut a.probes,
                },
                b.identity.peer_id.parse().unwrap(),
                &accept,
            )
            .unwrap();
            a.assert_unvalidated();
            b.assert_unvalidated();
            send_path_probes(
                &mut a.node.swarm,
                &mut a.forwarder,
                &mut a.paths,
                &a.peers,
                Some(&a.packets),
                None,
                &mut PacketInFlight::new(256),
                &mut a.probes,
                &a.metrics,
            )
            .await;
            let request = b.receive().await;
            assert!(!b.handle(&request).await);
            let ack = a.receive().await;
            assert!(a.handle(&ack).await);
            let reverse_request = a.receive().await;
            assert!(!a.handle(&reverse_request).await);
            let reverse_ack = b.receive().await;
            assert!(b.handle(&reverse_ack).await);
            let packet = Frame::packet(93, 1000, vec![0x45; 20]).unwrap();
            a.packets.send_frame_to_peer(b.peer, &packet).await.unwrap();
            assert_eq!(b.receive().await.received.frame, packet);
            b.packets.send_frame_to_peer(a.peer, &packet).await.unwrap();
            assert_eq!(a.receive().await.received.frame, packet);
        }
    }

    #[tokio::test]
    async fn prepared_recovery_owner_can_finish_even_when_local_peer_sorts_last() {
        let mut identities = [
            NodeIdentity::generate_ed25519().unwrap(),
            NodeIdentity::generate_ed25519().unwrap(),
        ];
        identities.sort_by_key(|identity| identity.peer_id.parse::<PeerId>().unwrap().as_bytes());
        let [remote, local] = identities;
        let mut end = End::new(local, remote.peer_id.parse().unwrap(), "127.0.0.1:0").await;
        end.packets.enable_udp_preparation_for_test();
        let destination = end.packets.primary_listener().unwrap();
        end.peers.record(end.remote, end.capabilities.clone());
        end.negotiator
            .udp_preparations
            .get_or_start(
                end.remote,
                udp_preparation::Role::Initiator,
                destination,
                || end.packets.udp_preparation(end.remote, destination, true),
            )
            .unwrap();
        end.finish_preparation().await;
        assert!(
            end.negotiator.has_pending(end.remote),
            "already-admitted preparation must reach signing despite peer ordering"
        );
    }

    #[tokio::test]
    async fn prepared_crossed_hello_can_change_role_before_or_after_signing() {
        for signed in [false, true] {
            let mut identities = [
                NodeIdentity::generate_ed25519().unwrap(),
                NodeIdentity::generate_ed25519().unwrap(),
            ];
            identities
                .sort_by_key(|identity| identity.peer_id.parse::<PeerId>().unwrap().as_bytes());
            let [remote, local] = identities;
            let mut local = End::new(local, remote.peer_id.parse().unwrap(), "127.0.0.1:0").await;
            let remote = End::new(
                remote,
                local.identity.peer_id.parse().unwrap(),
                "127.0.0.1:0",
            )
            .await;
            local.packets.enable_udp_preparation_for_test();
            local.peers.record(remote.peer, remote.capabilities.clone());
            local
                .negotiator
                .udp_preparations
                .get_or_start(
                    remote.peer,
                    udp_preparation::Role::Initiator,
                    remote.packets.primary_listener().unwrap(),
                    || {
                        local.packets.udp_preparation(
                            remote.peer,
                            remote.packets.primary_listener().unwrap(),
                            true,
                        )
                    },
                )
                .unwrap();
            if signed {
                local.finish_preparation().await;
                assert!(local.negotiator.has_pending(remote.peer));
            }
            let (_, hello, _) = signed_packet_plane_handshake(
                PacketPlaneHandshakeKind::Hello,
                &remote.identity,
                &remote.capabilities,
                PacketDatagramBackend::OwnedUdp,
            )
            .unwrap();
            let hello = hello.encode().unwrap();
            assert!(local.accept(&hello).await.is_none());
            assert!(!local.negotiator.has_pending(remote.peer));
            local.finish_preparation().await;
            let response = local.accept(&hello).await.unwrap();
            assert!(
                matches!(response, ControlResponse::PacketPlaneAccepted(_)),
                "role transfer after signing={signed}: {response:?}"
            );
            local.assert_unvalidated();
        }
    }

    async fn validate_pair(a: &mut End, b: &mut End) {
        send_path_probes(
            &mut a.node.swarm,
            &mut a.forwarder,
            &mut a.paths,
            &a.peers,
            Some(&a.packets),
            None,
            &mut PacketInFlight::new(256),
            &mut a.probes,
            &a.metrics,
        )
        .await;
        let request = b.receive().await;
        assert!(!b.handle(&request).await);
        let ack = a.receive().await;
        assert!(a.handle(&ack).await);
        let request = a.receive().await;
        assert!(!a.handle(&request).await);
        let ack = b.receive().await;
        assert!(b.handle(&ack).await);
    }

    #[tokio::test]
    async fn admitted_preferred_validation_finishes_with_same_endpoint_and_preserves_payload_until_ack()
     {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let [mut a, mut b] = pending_pair(address).await;
            validate_pair(&mut a, &mut b).await;
            let active_a = a.packets.udp_owner_id(b.peer).unwrap();
            let active_b = b.packets.udp_owner_id(a.peer).unwrap();
            let endpoint = a.packets.session_endpoint_for(b.peer).unwrap();
            assert!(!a.packets.route_refresh_needed(b.peer));
            connect_control(&mut a, &mut b).await;
            a.packets.enable_udp_preparation_for_test();
            a.negotiator
                .udp_preparations
                .get_or_start(b.peer, udp_preparation::Role::Initiator, endpoint, || {
                    a.packets.udp_preparation(b.peer, endpoint, false)
                })
                .unwrap();
            a.finish_preparation().await;
            assert!(
                a.negotiator.has_pending(b.peer),
                "already-admitted work must sign despite an unchanged healthy fallback"
            );
            assert_eq!(a.packets.udp_owner_id(b.peer), Some(active_a));
            assert!(!a.packets.route_refresh_needed(b.peer));
            drive_control_pair(&mut a, &mut b).await;
            assert_eq!(a.packets.udp_owner_id(b.peer), Some(active_a));
            assert_eq!(b.packets.udp_owner_id(a.peer), Some(active_b));
            let packet = Frame::packet(183, 1000, vec![0x45; 20]).unwrap();
            a.packets.send_frame_to_peer(b.peer, &packet).await.unwrap();
            let data = b.receive().await;
            assert_eq!(data.received.frame, packet);
            assert!(!b.packets.accept_udp_frame(&data).await.unwrap());
            b.packets.send_frame_to_peer(a.peer, &packet).await.unwrap();
            let data = a.receive().await;
            assert_eq!(data.received.frame, packet);
            assert!(!a.packets.accept_udp_frame(&data).await.unwrap());
            validate_pair(&mut a, &mut b).await;
            assert_ne!(a.packets.udp_owner_id(b.peer), Some(active_a));
            assert_ne!(b.packets.udp_owner_id(a.peer), Some(active_b));
            assert_eq!(a.packets.session_endpoint_for(b.peer), Some(endpoint));
            a.packets.send_frame_to_peer(b.peer, &packet).await.unwrap();
            assert_eq!(b.receive().await.received.frame, packet);
        }
    }

    async fn pending_pair(address: &str) -> [End; 2] {
        let a = NodeIdentity::generate_ed25519().unwrap();
        let b = NodeIdentity::generate_ed25519().unwrap();
        let mut a = End::new(a, b.peer_id.parse().unwrap(), address).await;
        let mut b = End::new(b, a.identity.peer_id.parse().unwrap(), address).await;
        a.peers.record(b.peer, b.capabilities.clone());
        b.peers.record(a.peer, a.capabilities.clone());
        let (secret, hello, verified) = signed_packet_plane_handshake(
            PacketPlaneHandshakeKind::Hello,
            &a.identity,
            &a.capabilities,
            PacketDatagramBackend::OwnedUdp,
        )
        .unwrap();
        a.negotiator
            .insert(b.peer, secret, verified, PacketDatagramBackend::OwnedUdp);
        let accept = accept_packet_plane_hello(
            &mut PacketPlaneAcceptContext {
                active_connections: &HashMap::new(),
                forwarder: &b.forwarder,
                peer_capabilities: &b.peers,
                paths: &mut b.paths,
                metrics: &b.metrics,
                packet_plane: &mut b.packets,
                packet_plane_quic: None,
                negotiator: &mut b.negotiator,
                identity: &b.identity,
                local_capabilities: &b.capabilities,
                publication: &b.publication,
                path_probe_tracker: &mut b.probes,
            },
            a.identity.peer_id.parse().unwrap(),
            &hello.encode().unwrap(),
        )
        .unwrap();
        complete_packet_plane_hello(
            &mut PacketPlaneCompleteContext {
                forwarder: &a.forwarder,
                peer_capabilities: &a.peers,
                packet_plane: &mut a.packets,
                packet_plane_quic: None,
                negotiator: &mut a.negotiator,
                paths: &mut a.paths,
                metrics: &a.metrics,
                local_capabilities: &a.capabilities,
                path_probe_tracker: &mut a.probes,
            },
            b.identity.peer_id.parse().unwrap(),
            &accept,
        )
        .unwrap();
        [a, b]
    }

    #[tokio::test]
    async fn first_managed_udp_session_needs_exact_ack_and_keeps_stream_fallback() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let [mut a, mut b] = pending_pair(address).await;
            a.assert_unvalidated();
            b.assert_unvalidated();
            let packet = Frame::packet(77, 1000, vec![0x45; 20]).unwrap();
            assert!(matches!(
                a.packets.send_frame_to_peer(b.peer, &packet).await,
                Err(PacketPlaneIoError::NoSession { .. })
            ));
            send_path_probes(
                &mut a.node.swarm,
                &mut a.forwarder,
                &mut a.paths,
                &a.peers,
                Some(&a.packets),
                None,
                &mut PacketInFlight::new(256),
                &mut a.probes,
                &a.metrics,
            )
            .await;
            a.assert_unvalidated();
            let request = b.receive().await;
            assert!(!b.handle(&request).await);
            b.assert_unvalidated();
            let ack = a.receive().await;
            assert!(a.handle(&ack).await);
            assert!(a.packets.has_session(b.peer));
            b.assert_unvalidated();

            // The responder validates its own direction through the request
            // queued by the scoped ACK handler, not by the original send result.
            let reverse_request = a.receive().await;
            assert!(!a.handle(&reverse_request).await);
            let reverse_ack = b.receive().await;
            assert!(b.handle(&reverse_ack).await);
            for end in [&a, &b] {
                assert!(!end.packets.has_pending_udp_replacement(end.remote));
                assert_eq!(
                    local_packet_datagram_backend(
                        &end.paths,
                        &end.peers,
                        Some(&end.packets),
                        None,
                        end.remote,
                    ),
                    Some(PacketDatagramBackend::OwnedUdp)
                );
            }
            a.packets.send_frame_to_peer(b.peer, &packet).await.unwrap();
            let data = b.receive().await;
            assert_eq!(data.received.frame, packet);
            assert!(!b.packets.accept_udp_frame(&data).await.unwrap());
            b.packets.send_frame_to_peer(a.peer, &packet).await.unwrap();
            let data = a.receive().await;
            assert_eq!(data.received.frame, packet);
            assert!(!a.packets.accept_udp_frame(&data).await.unwrap());
        }
    }

    #[tokio::test]
    async fn expired_first_candidate_retries_once_without_an_external_event_and_respects_pause() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let [mut a, mut b] = pending_pair(address).await;
            let end = if a.peer.as_bytes() < b.peer.as_bytes() {
                &mut a
            } else {
                &mut b
            };
            end.assert_unvalidated();
            assert!(end.packets.expire_sessions(Duration::ZERO).is_empty());
            assert!(!end.packets.has_pending_udp_replacement(end.remote));
            assert!(!end.packets.has_session(end.remote));
            assert!(!end.packets.can_receive());
            end.retry();
            let pending = &end.negotiator.pending[&end.remote];
            assert_eq!(pending.backend, PacketDatagramBackend::OwnedUdp);
            let request = pending.request_id.expect("fresh recovery Hello");
            for _ in 0..5 {
                end.retry();
                assert_eq!(
                    end.negotiator.pending[&end.remote].request_id,
                    Some(request)
                );
            }
            assert_eq!(
                end.metrics
                    .snapshot(crate::queue::QueueStats::default())
                    .control_requests_sent,
                1
            );
            end.negotiator.cancel_pending_for_peer(end.remote);
            let demand = end.forwarder.application_demand(end.remote).unwrap();
            assert!(
                end.forwarder
                    .pause_data_path_maintenance(end.remote, demand.version.unwrap())
            );
            end.retry();
            assert!(!end.negotiator.has_pending(end.remote));
            assert_eq!(
                end.metrics
                    .snapshot(crate::queue::QueueStats::default())
                    .control_requests_sent,
                1
            );
        }
    }

    #[tokio::test]
    async fn hello_waits_for_packet_publication_ack_not_just_queueing() {
        let [mut a, mut b] = pending_pair("127.0.0.1:0").await;
        let end = if a.peer.as_bytes() < b.peer.as_bytes() {
            &mut a
        } else {
            &mut b
        };
        end.packets.forget_peer(end.remote);
        end.publication = MembershipRecordSyncs::default();
        end.retry();
        assert!(!end.negotiator.has_pending(end.remote));
        end.publication
            .queue_capabilities(end.capabilities.clone(), &end.forwarder);
        end.retry();
        assert!(!end.negotiator.has_pending(end.remote));
        assert!(!end.negotiator.has_quic_connection_tasks());
        assert!(
            !end.node
                .swarm
                .behaviour()
                .control
                .has_any_pending_requests()
        );
        end.publication = MembershipRecordSyncs::with_acknowledged_packet_capabilities_for_test(
            end.forwarder
                .transport_peer_for_overlay(end.remote)
                .unwrap(),
            end.capabilities.clone(),
            &end.forwarder,
        );
        end.retry();
        assert!(end.negotiator.has_pending(end.remote));
        assert_eq!(
            end.metrics
                .snapshot(crate::queue::QueueStats::default())
                .control_requests_sent,
            1
        );

        end.negotiator.cancel_pending_for_peer(end.remote);
        let mut changed: SocketAddr = end.capabilities.packet_endpoint_candidates[0]
            .parse()
            .unwrap();
        changed.set_port(if changed.port() == u16::MAX {
            u16::MAX - 1
        } else {
            changed.port() + 1
        });
        end.capabilities.packet_endpoint_candidates = vec![changed.to_string()];
        end.retry();
        assert!(
            !end.negotiator.has_pending(end.remote),
            "unqueued endpoint changes cannot reuse an old ACK"
        );
        end.publication
            .queue_capabilities(end.capabilities.clone(), &end.forwarder);
        end.retry();
        assert!(
            !end.negotiator.has_pending(end.remote),
            "queueing a new endpoint is not acknowledgement"
        );
        assert_eq!(
            end.metrics
                .snapshot(crate::queue::QueueStats::default())
                .control_requests_sent,
            1
        );
    }

    #[tokio::test]
    async fn accept_waits_for_its_publication_ack_without_replacing_the_existing_candidate() {
        let [a, mut b] = pending_pair("127.0.0.1:0").await;
        let previous = b.packets.udp_probe_owner_id(a.peer).unwrap();
        let (_, hello, _) = signed_packet_plane_handshake(
            PacketPlaneHandshakeKind::Hello,
            &a.identity,
            &a.capabilities,
            PacketDatagramBackend::OwnedUdp,
        )
        .unwrap();
        b.publication = MembershipRecordSyncs::default();
        b.publication
            .queue_capabilities(b.capabilities.clone(), &b.forwarder);
        let result = accept_packet_plane_hello(
            &mut PacketPlaneAcceptContext {
                active_connections: &HashMap::new(),
                forwarder: &b.forwarder,
                peer_capabilities: &b.peers,
                paths: &mut b.paths,
                metrics: &b.metrics,
                packet_plane: &mut b.packets,
                packet_plane_quic: None,
                negotiator: &mut b.negotiator,
                identity: &b.identity,
                local_capabilities: &b.capabilities,
                publication: &b.publication,
                path_probe_tracker: &mut b.probes,
            },
            a.identity.peer_id.parse().unwrap(),
            &hello.encode().unwrap(),
        );
        assert!(matches!(
            result,
            Err(PacketPlaneNegotiationError::UnacknowledgedLocalCapabilities)
        ));
        assert_eq!(b.packets.udp_probe_owner_id(a.peer), Some(previous));
        assert!(!b.negotiator.has_quic_connection_tasks());
        b.assert_unvalidated();
    }
}
