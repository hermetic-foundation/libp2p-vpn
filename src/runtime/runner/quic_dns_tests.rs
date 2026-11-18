#[cfg(target_os = "linux")]
mod quic_dns {
    use super::*;
    use crate::runtime::physical_network::android::dns::fixture::EndpointFixture;

    #[tokio::test(flavor = "current_thread")]
    async fn hostname_only_zero_ttl_quic_task_retains_resolution_and_binds_the_signed_handshake() {
        for ip in [
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            "::1".parse().unwrap(),
        ] {
            let dns = EndpointFixture::install(ip).await;
            let local_identity = NodeIdentity::generate_ed25519().unwrap();
            let remote_identity = NodeIdentity::generate_ed25519().unwrap();
            let local_peer = local_identity.peer_id.parse().unwrap();
            let remote_peer = remote_identity.peer_id.parse().unwrap();
            let mut local = PacketPlaneQuicRuntime::bind(SocketAddr::new(ip, 0)).unwrap();
            let mut remote = PacketPlaneQuicRuntime::bind(SocketAddr::new(ip, 0)).unwrap();
            let local_caps = ControlCapabilities::local("lab", None, 1200)
                .with_owned_quic_packet_endpoint_candidates(vec![local.local_addr().to_string()])
                .with_owned_quic_packet_plane_certificate(local.server_certificate().to_vec());
            let candidate = format!("quic-zero-ttl.example:{}", remote.local_addr().port());
            let remote_caps = ControlCapabilities::local("lab", None, 1200)
                .with_owned_quic_packet_endpoint_candidates(vec![candidate.clone()])
                .with_owned_quic_packet_plane_certificate(remote.server_certificate().to_vec());
            dns.ready(&[&candidate]).await;
            let requests = dns.requests();
            let (local_secret, _, hello) = signed_packet_plane_handshake(
                PacketPlaneHandshakeKind::Hello,
                &local_identity,
                &local_caps,
                PacketDatagramBackend::OwnedQuic,
            )
            .unwrap();
            let binding = PacketPlaneQuicBinding::from_handshake(&hello);
            let mut negotiator = PacketPlaneNegotiator::default();
            let (remote_secret, _, accept) = {
                let _delivery = packet_dns_delivery();
                let accept = signed_packet_plane_handshake(
                    PacketPlaneHandshakeKind::Accept,
                    &remote_identity,
                    &remote_caps,
                    PacketDatagramBackend::OwnedQuic,
                )
                .unwrap();
                assert_eq!(accept.2.endpoint, remote.local_addr());
                negotiator.start_quic_connection(
                    local.connector(),
                    remote_peer,
                    remote_caps.clone(),
                    PacketPlaneQuicNegotiationRole::Initiator,
                    PacketPlaneQuicConnectionDirection::ConnectSelectedRoute,
                    binding,
                );
                accept
            };
            // The synchronous delivery scope is gone before the spawned task
            // polls. It must use its copied numeric destinations and epoch.
            let connector = remote.connector();
            let (completed, accepted) = timeout(TokioDuration::from_secs(3), async {
                tokio::join!(
                    negotiator.quic_connection_tasks.join_next(),
                    connector.accept_bound(binding)
                )
            })
            .await
            .expect("hostname-only bound QUIC connection");
            let completed = completed.unwrap().unwrap();
            assert!(negotiator.finish_quic_connection_task(
                completed.peer,
                completed.role,
                completed.generation,
            ));
            assert!(!local.has_session(remote_peer));
            assert!(!remote.has_session(local_peer));
            local.install_connection(remote_peer, completed.result.unwrap());
            remote.install_connection(local_peer, accepted.unwrap());
            local
                .establish_session(
                    PacketPlaneSessionRole::Initiator,
                    &local_secret,
                    &hello,
                    &accept,
                )
                .unwrap();
            remote
                .establish_session(
                    PacketPlaneSessionRole::Responder,
                    &remote_secret,
                    &accept,
                    &hello,
                )
                .unwrap();
            let frame = Frame::packet(197, 1000, vec![0x45; 20]).unwrap();
            local.send_frame_to_peer(remote_peer, &frame).unwrap();
            assert_eq!(
                timeout(
                    TokioDuration::from_secs(1),
                    remote.recv_frame_from_peer(local_peer)
                )
                .await
                .unwrap()
                .unwrap()
                .frame,
                frame
            );
            remote.send_frame_to_peer(local_peer, &frame).unwrap();
            assert_eq!(
                timeout(
                    TokioDuration::from_secs(1),
                    local.recv_frame_from_peer(remote_peer)
                )
                .await
                .unwrap()
                .unwrap()
                .frame,
                frame
            );
            assert_eq!(
                dns.requests(),
                requests,
                "spawned tasks must not resolve the name again"
            );
            assert_eq!(
                remote_caps.owned_quic_packet_endpoint_candidates,
                [candidate]
            );
            assert!(negotiator.quic_connection_task_handles.is_empty());
            dns.shutdown().await;
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hostname_only_zero_ttl_quic_task_rejects_a_retired_dns_epoch_before_connecting() {
        let ip = "127.0.0.1".parse().unwrap();
        let dns = EndpointFixture::install(ip).await;
        let local = PacketPlaneQuicRuntime::bind(SocketAddr::new(ip, 0)).unwrap();
        let remote = PacketPlaneQuicRuntime::bind(SocketAddr::new(ip, 0)).unwrap();
        let candidate = format!("stale-quic-zero-ttl.example:{}", remote.local_addr().port());
        let remote_caps = ControlCapabilities::local("lab", None, 1200)
            .with_owned_quic_packet_endpoint_candidates(vec![candidate.clone()])
            .with_owned_quic_packet_plane_certificate(remote.server_certificate().to_vec());
        dns.ready(&[&candidate]).await;
        let requests = dns.requests();
        let mut negotiator = PacketPlaneNegotiator::default();
        {
            let _delivery = packet_dns_delivery();
            negotiator.start_quic_connection(
                local.connector(),
                PeerId::from_libp2p(Libp2pPeerId::random()),
                remote_caps,
                PacketPlaneQuicNegotiationRole::Initiator,
                PacketPlaneQuicConnectionDirection::ConnectSelectedRoute,
                PacketPlaneQuicBinding::from_bytes([33; 32]),
            );
        }
        dns.invalidate();
        let completed = timeout(
            TokioDuration::from_secs(1),
            negotiator.quic_connection_tasks.join_next(),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert!(matches!(
            completed.result,
            Err(PacketPlaneNegotiationError::MissingRemoteEndpoint)
        ));
        assert!(negotiator.finish_quic_connection_task(
            completed.peer,
            completed.role,
            completed.generation
        ));
        assert_eq!(dns.requests(), requests);
        assert!(
            timeout(TokioDuration::from_millis(100), remote.connector().accept())
                .await
                .is_err(),
            "a retired DNS epoch must not send a QUIC connection to the old destination"
        );
        dns.shutdown().await;
    }
}
