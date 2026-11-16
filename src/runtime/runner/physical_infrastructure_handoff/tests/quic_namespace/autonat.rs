//! Real AutoNAT dispatch and dial-back across native QUIC physical handoffs.

use super::*;
use libp2p::autonat as native_autonat;

const PROBE_WINDOW: Duration = Duration::from_secs(6);

#[test]
#[ignore = "isolated namespace; native QUIC AutoNAT responses and source return with real UDP retirement"]
fn native_quic_autonat_source_return_dispatches_on_replacement() {
    const NAME: &str = "runtime::runner::physical_infrastructure_handoff::tests::quic_namespace::autonat::native_quic_autonat_source_return_dispatches_on_replacement";
    source_return_autonat(NAME, false);
}

#[test]
#[ignore = "isolated namespace; native IPv6 QUIC AutoNAT responses and source return with real UDP retirement"]
fn native_ipv6_quic_autonat_source_return_dispatches_on_replacement() {
    const NAME: &str = "runtime::runner::physical_infrastructure_handoff::tests::quic_namespace::autonat::native_ipv6_quic_autonat_source_return_dispatches_on_replacement";
    source_return_autonat(NAME, true);
}

fn install_autonat(node: &mut P2pNode) {
    let mut behaviour = native_autonat::Behaviour::new(
        node.local_peer_id,
        native_autonat::Config {
            boot_delay: Duration::ZERO,
            retry_interval: Duration::from_millis(50),
            refresh_interval: Duration::from_millis(50),
            timeout: Duration::from_secs(4),
            throttle_server_period: Duration::ZERO,
            use_connected: false,
            only_global_ips: false,
            ..Default::default()
        },
    );
    behaviour.set_client_probes_paused(true);
    node.swarm.behaviour_mut().autonat = Some(behaviour).into();
}

fn native(node: &P2pNode) -> &native_autonat::Behaviour {
    node.swarm.behaviour().autonat.as_ref().unwrap()
}

fn native_mut(node: &mut P2pNode) -> &mut native_autonat::Behaviour {
    node.swarm.behaviour_mut().autonat.as_mut().unwrap()
}

fn physical_owner(node: &P2pNode, peer: Libp2pPeerId, id: ConnectionId) -> Snapshot {
    let route = node
        .swarm
        .behaviour()
        .connection_retention
        .physical_routes()
        .unwrap()
        .connection(peer, id)
        .expect("exact authenticated native control owner");
    assert!(route.is_live() && route.is_adopted());
    assert_eq!(route.lease.context.protocol, SocketProtocol::Udp);
    route
}

fn acceptor_owner(server: &P2pNode, client: Libp2pPeerId, source: SocketAddr) -> ConnectionId {
    let owners = server
        .swarm
        .behaviour()
        .connection_retention
        .physical_routes()
        .unwrap()
        .snapshot();
    let matched = owners
        .iter()
        .filter(|route| {
            route.peer == client
                && route.is_adopted()
                && !route.lease.preferred_dial
                && route.lease.context.destination == source
        })
        .collect::<Vec<_>>();
    assert_eq!(
        matched.len(),
        1,
        "TLS acceptor must observe the exact selected source tuple"
    );
    assert_eq!(matched[0].lease.context.protocol, SocketProtocol::Udp);
    matched[0].connection_id.unwrap()
}

async fn listen_quic(node: &mut P2pNode, address: Multiaddr) -> Multiaddr {
    let listener = node.swarm.listen_on(address).unwrap();
    tokio::time::timeout(PROBE_WINDOW, async {
        loop {
            if let SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } = node.swarm.select_next_some().await
                && listener_id == listener
            {
                assert_eq!(
                    physical_control_handoff::address_protocol(&address, node.local_peer_id),
                    Some(SocketProtocol::Udp)
                );
                return address;
            }
        }
    })
    .await
    .expect("native QUIC listener address")
}

fn source_return_autonat(name: &str, ipv6: bool) {
    let Some(routes) = setup_sources(name, ipv6) else {
        return;
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut server = crate::runtime::runner::tests::membership_sync_test_node(
                NodeIdentity::generate_ed25519().unwrap(),
            );
            isolated_dht(&mut server);
            install_autonat(&mut server);
            let family = if routes.ipv6 { "ip6" } else { "ip4" };
            let server_address = listen_quic(
                &mut server,
                format!("/{family}/{}/udp/0/quic-v1", routes.destination)
                    .parse()
                    .unwrap(),
            )
            .await;
            let peer = server.local_peer_id;
            let mut fixture = Fixture::new(peer);
            install_autonat(&mut fixture.node);
            let wildcard = if routes.ipv6 { "::" } else { "0.0.0.0" };
            let probe_address = listen_quic(
                &mut fixture.node,
                format!("/{family}/{wildcard}/udp/0/quic-v1")
                    .parse()
                    .unwrap(),
            )
            .await;
            fixture.bootstrap.push((peer, server_address.clone()));
            fixture
                .node
                .swarm
                .behaviour_mut()
                .kad
                .add_address(&peer, server_address.clone());
            let options = DialOpts::peer_id(peer)
                .addresses(vec![server_address])
                .allocate_new_port()
                .build();
            let mut current = options.connection_id();
            fixture
                .epochs
                .dial(&mut fixture.node.swarm, options)
                .unwrap();
            fixture
                .until(&mut server, |fixture| {
                    fixture
                        .node
                        .swarm
                        .behaviour()
                        .connection_retention
                        .services(peer, current)
                        .is_some_and(|services| services.primary_dht && services.autonat)
                        && fixture
                            .node
                            .swarm
                            .behaviour()
                            .connection_retention
                            .physical_routes()
                            .unwrap()
                            .connection(peer, current)
                            .is_some_and(|route| route.refresh_required() == Some(false))
                })
                .await;
            let initial = physical_owner(&fixture.node, peer, current);
            assert_eq!(initial.lease.local_addr.ip().to_string(), routes.sources[0]);
            native_mut(&mut fixture.node).add_server(peer, None);
            native_mut(&mut fixture.node).probe_address(probe_address);
            let mut probes = HashSet::new();
            assert!(
                probes.insert(successful_probe(&mut fixture, &mut server, current, None).await)
            );

            for source in [routes.sources[1], routes.sources[0]] {
                assert!(native(&fixture.node).client_probes_paused());
                assert!(!native(&fixture.node).has_pending_work());
                let previous = physical_owner(&fixture.node, peer, current);
                assert!(UdpSocket::bind(previous.lease.local_addr).is_err());
                routes.select(source);
                fixture
                    .until(&mut server, |fixture| {
                        fixture
                            .node
                            .swarm
                            .behaviour()
                            .connection_retention
                            .infrastructure_handoff
                            .rounds
                            .get(&peer)
                            .is_some_and(|round| matches!(round.phase, Phase::Draining(..)))
                    })
                    .await;
                let replacement = fixture
                    .node
                    .swarm
                    .behaviour()
                    .connection_retention
                    .infrastructure_handoff
                    .rounds[&peer]
                    .candidate()
                    .unwrap();
                assert_ne!(replacement, current);
                let selected = physical_owner(&fixture.node, peer, replacement);
                assert_eq!(selected.lease.local_addr.ip().to_string(), source);
                assert!(previous.is_live());
                assert!(probes.insert(
                    successful_probe(&mut fixture, &mut server, replacement, Some(current)).await
                ));
                assert!(
                    previous.is_live(),
                    "a real replacement response precedes fallback retirement"
                );
                fixture
                    .until(&mut server, |fixture| {
                        !fixture.connections.contains_key(&(peer, current))
                    })
                    .await;
                assert!(
                    fixture
                        .node
                        .swarm
                        .behaviour()
                        .connection_retention
                        .physical_routes()
                        .unwrap()
                        .connection(peer, current)
                        .is_none()
                );
                tokio::time::timeout(Duration::from_secs(12), async {
                    loop {
                        if UdpSocket::bind(previous.lease.local_addr).is_ok() {
                            break;
                        }
                        tokio::select! {
                            event = fixture.node.swarm.select_next_some() => fixture.event(event),
                            _ = server.swarm.select_next_some() => {},
                            _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                        }
                        fixture.drive();
                    }
                })
                .await
                .expect("retired native QUIC socket releases its actual UDP port");
                assert!(!previous.is_live());
                assert!(fixture.epochs.is_usable(replacement));
                assert!(
                    probes.insert(
                        successful_probe(&mut fixture, &mut server, replacement, None).await
                    )
                );
                current = replacement;
            }
            assert_eq!(
                probes.len(),
                5,
                "each stage needs a fresh native probe response"
            );
        });
}

async fn successful_probe(
    fixture: &mut Fixture,
    server: &mut P2pNode,
    owner: ConnectionId,
    fallback: Option<ConnectionId>,
) -> native_autonat::ProbeId {
    let peer = server.local_peer_id;
    let client = fixture.node.local_peer_id;
    let selected = physical_owner(&fixture.node, peer, owner);
    let server_owner = acceptor_owner(server, client, selected.lease.local_addr);
    assert!(native(&fixture.node).client_probes_paused());
    assert!(native(server).client_probes_paused());
    assert!(!native(&fixture.node).has_pending_work());
    assert!(!native(server).has_pending_work());
    native_mut(&mut fixture.node).set_client_probes_paused(false);
    let mut request = None;
    let mut inbound = None;
    let mut response = None;
    let mut server_response = false;
    let mut client_callback = None;
    let mut server_callback = None;
    // Hold only pre-retirement observations at the promotion boundary. Other
    // probes run the controller normally; both real Swarms always keep polling.
    tokio::time::timeout(PROBE_WINDOW, async {
        loop {
            tokio::select! {
                event = fixture.node.swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(BehaviourEvent::Autonat(native_autonat::Event::OutboundProbe(
                        native_autonat::OutboundProbeEvent::Request { probe_id, peer: target }
                    ))) => {
                        assert_eq!(target, peer);
                        assert!(request.replace(probe_id).is_none());
                        native_mut(&mut fixture.node).set_client_probes_paused(true);
                        assert!(native(&fixture.node).has_pending_requests_on_connection(&peer, owner), "probe dispatch must belong to the selected native connection");
                        for ((other, id), _) in &fixture.connections {
                            if *other == peer && *id != owner {
                                assert!(!native(&fixture.node).has_pending_requests_on_connection(&peer, *id), "a sibling must not own the replacement probe");
                            }
                        }
                        if let Some(fallback) = fallback {
                            assert!(fixture.connections.contains_key(&(peer, fallback)));
                            assert!(physical_owner(&fixture.node, peer, fallback).is_live());
                        }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Autonat(native_autonat::Event::OutboundProbe(
                        native_autonat::OutboundProbeEvent::Response { probe_id, peer: target, address }
                    ))) => {
                        assert_eq!(target, peer);
                        assert_eq!(Some(probe_id), request);
                        assert!(response.replace(probe_id).is_none());
                        assert_eq!(physical_control_handoff::address_protocol(&address, client), Some(SocketProtocol::Udp));
                        if fallback.is_none() {
                            assert_eq!(first_ip_in_multiaddr(&address), Some(selected.lease.local_addr.ip()));
                        }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Autonat(native_autonat::Event::OutboundProbe(
                        native_autonat::OutboundProbeEvent::Error { error, .. }
                    ))) => panic!("fresh native AutoNAT probe failed: {error:?}"),
                    event => {
                        if let SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint: ConnectedPoint::Listener { .. }, .. } = &event {
                            assert_eq!(*peer_id, peer);
                            assert!(client_callback.replace(*connection_id).is_none());
                            physical_owner(&fixture.node, peer, *connection_id);
                        }
                        if let SwarmEvent::ConnectionClosed { connection_id, .. } = &event {
                            assert_ne!(*connection_id, owner, "selected owner closed during the real probe");
                            assert_ne!(Some(*connection_id), fallback, "pre-retirement probe must retain its fallback");
                        }
                        fixture.event(event);
                    }
                },
                event = server.swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(BehaviourEvent::Autonat(native_autonat::Event::InboundProbe(
                        native_autonat::InboundProbeEvent::Request { probe_id, peer: target, addresses }
                    ))) => {
                        assert_eq!(target, client);
                        assert!(inbound.replace(probe_id).is_none());
                        assert!(native(server).has_pending_requests_on_connection(&client, server_owner), "real inbound request must retain the exact authenticated reply owner");
                        assert!(!addresses.is_empty());
                        assert!(addresses.iter().all(|address| physical_control_handoff::address_protocol(address, client) == Some(SocketProtocol::Udp)));
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Autonat(native_autonat::Event::InboundProbe(
                        native_autonat::InboundProbeEvent::Response { probe_id, peer: target, .. }
                    ))) => {
                        assert_eq!(target, client);
                        assert_eq!(Some(probe_id), inbound);
                        assert!(!server_response);
                        server_response = true;
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Autonat(native_autonat::Event::InboundProbe(
                        native_autonat::InboundProbeEvent::Error { error, .. }
                    ))) => panic!("real native AutoNAT dial-back failed: {error:?}"),
                    SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint: ConnectedPoint::Dialer { .. }, .. } => {
                        assert_eq!(peer_id, client);
                        assert!(server_callback.replace(connection_id).is_none());
                        physical_owner(server, client, connection_id);
                    }
                    SwarmEvent::ConnectionClosed { connection_id, .. } => assert_ne!(connection_id, server_owner),
                    _ => {},
                },
                _ = tokio::time::sleep(Duration::from_millis(1)) => {},
            }
            if fallback.is_none() {
                fixture.drive();
            }
            if response.is_some() && server_response && client_callback.is_some() && server_callback.is_some()
                && !native(&fixture.node).has_pending_work() && !native(server).has_pending_work()
                && fixture.node.swarm.network_info().connection_counters().num_pending() == 0
                && server.swarm.network_info().connection_counters().num_pending() == 0
            { break; }
        }
    }).await.expect("exact-owner native AutoNAT request, dial-back, and successful response");
    assert!(matches!(
        native(&fixture.node).nat_status(),
        native_autonat::NatStatus::Public(_)
    ));
    assert!(!native(&fixture.node).has_pending_requests_on_connection(&peer, owner));
    let client_callback = client_callback.unwrap();
    let server_callback = server_callback.unwrap();
    // Dial-back connections are genuine, but must not become a later probe's
    // control owner and hide a broken promotion on the original connection.
    fixture.epochs.mark_retiring(client_callback);
    assert!(fixture.node.swarm.close_connection(client_callback));
    assert!(server.swarm.close_connection(server_callback));
    tokio::time::timeout(PROBE_WINDOW, async {
        while fixture.connections.contains_key(&(peer, client_callback))
            || server
                .swarm
                .behaviour()
                .connection_retention
                .physical_routes()
                .unwrap()
                .connection(client, server_callback)
                .is_some()
        {
            tokio::select! {
                event = fixture.node.swarm.select_next_some() => fixture.event(event),
                _ = server.swarm.select_next_some() => {},
                _ = tokio::time::sleep(Duration::from_millis(1)) => {},
            }
        }
    })
    .await
    .expect("native dial-back siblings close before the next probe");
    assert!(fixture.epochs.is_usable(owner));
    response.unwrap()
}
