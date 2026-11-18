#[cfg(target_os = "linux")]
mod endpoint_source {
    use super::*;
    use crate::runtime::physical_network::control::reconcile::Reconciler;
    use std::task::Poll;

    #[test]
    fn wildcard_hints_use_native_source_not_a_new_default_route_lookup() {
        for (listener, remote, source, expected) in [
            (
                "0.0.0.0:51820",
                "/ip4/127.0.0.1/tcp/4001",
                "198.51.100.2:47000",
                "198.51.100.2:51820",
            ),
            (
                "[::]:51820",
                "/ip6/::1/tcp/4001",
                "[fd00::2]:47000",
                "[fd00::2]:51820",
            ),
        ] {
            let endpoint = ConnectedPoint::Dialer {
                address: remote.parse().unwrap(),
                role_override: Endpoint::Dialer,
                port_use: PortUse::New,
            };
            let listener = Some(listener.parse().unwrap());
            assert_eq!(
                direct_packet_plane_endpoint_from_path(listener, &endpoint, &[], None),
                None
            );
            assert_eq!(
                direct_packet_plane_endpoint_from_path(
                    listener,
                    &endpoint,
                    &[],
                    Some(source.parse().unwrap())
                ),
                Some(expected.to_owned())
            );
        }
    }

    #[test]
    fn native_hints_keep_family_overlay_and_relay_guards() {
        let mut endpoint = ConnectedPoint::Dialer {
            address: "/ip4/127.0.0.1/tcp/4001".parse().unwrap(),
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        };
        let listener = Some("0.0.0.0:51820".parse().unwrap());
        for source in ["[fd00::2]:4001", "0.0.0.0:4001", "224.0.0.251:4001"] {
            assert_eq!(
                direct_packet_plane_endpoint_from_path(
                    listener,
                    &endpoint,
                    &[],
                    Some(source.parse().unwrap())
                ),
                None
            );
        }
        let source = Some("198.51.100.2:4001".parse().unwrap());
        let overlay = [IpCidr::new("198.51.100.0".parse().unwrap(), 24).unwrap()];
        assert_eq!(
            direct_packet_plane_endpoint_from_path(listener, &endpoint, &overlay, source),
            None
        );
        if let ConnectedPoint::Dialer { address, .. } = &mut endpoint {
            address.push(Protocol::P2pCircuit);
        }
        assert_eq!(
            direct_packet_plane_endpoint_from_path(listener, &endpoint, &[], source),
            None
        );
    }

    #[tokio::test]
    async fn native_source_requires_the_exact_live_adopted_connection_owner() {
        let node = membership_sync_test_node(NodeIdentity::generate_ed25519().unwrap());
        let routes = node
            .swarm
            .behaviour()
            .connection_retention
            .physical_routes()
            .unwrap();
        let peer = Libp2pPeerId::random();
        let connection = ConnectionId::new_unchecked(100);
        let (_, lease) = routes
            .egress
            .prepare_tcp("127.0.0.1:4001".parse().unwrap(), false, &[])
            .await
            .unwrap();
        let source = lease.local_addr;
        let registration = routes.register(peer, lease).unwrap();
        assert_eq!(
            native_packet_plane_source(node.swarm.behaviour(), peer, connection),
            None
        );
        registration.bind_connection(connection).unwrap();
        assert_eq!(
            native_packet_plane_source(node.swarm.behaviour(), peer, connection),
            None
        );
        registration.adopt().unwrap();
        assert_eq!(
            native_packet_plane_source(node.swarm.behaviour(), peer, connection),
            Some(source)
        );
        assert_eq!(
            native_packet_plane_source(node.swarm.behaviour(), Libp2pPeerId::random(), connection),
            None
        );
        assert_eq!(
            native_packet_plane_source(
                node.swarm.behaviour(),
                peer,
                ConnectionId::new_unchecked(101)
            ),
            None
        );
        routes.egress.retire_observer_for_test();
        assert!(
            !routes
                .connection(peer, connection)
                .unwrap()
                .lease
                .is_current()
        );
        assert_eq!(
            native_packet_plane_source(node.swarm.behaviour(), peer, connection),
            None
        );
        let mut audit = Reconciler::new(Arc::clone(routes));
        timeout(
            TokioDuration::from_secs(3),
            futures::future::poll_fn(|cx| {
                audit.poll(cx);
                if routes
                    .connection(peer, connection)
                    .unwrap()
                    .refresh_required()
                    == Some(false)
                {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }),
        )
        .await
        .expect("fresh audit preserves the unchanged native source");
        assert!(
            !routes
                .connection(peer, connection)
                .unwrap()
                .lease
                .is_current()
        );
        assert_eq!(
            native_packet_plane_source(node.swarm.behaviour(), peer, connection),
            Some(source)
        );
        routes.egress.retire_observer_for_test();
        assert_eq!(
            native_packet_plane_source(node.swarm.behaviour(), peer, connection),
            None
        );
        drop(registration);
        assert_eq!(
            native_packet_plane_source(node.swarm.behaviour(), peer, connection),
            None
        );
    }
}
