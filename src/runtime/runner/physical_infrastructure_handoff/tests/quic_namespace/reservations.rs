//! Real incoming circuits must remain usable after native QUIC reservation moves.

use super::*;
use libp2p::ping;

#[test]
#[ignore = "isolated namespace; configured native QUIC reservation return and incoming circuits"]
fn configured_ipv4_quic_reservations_return_with_incoming_access() {
    reservation_return(
        concat!(
            module_path!(),
            "::configured_ipv4_quic_reservations_return_with_incoming_access"
        ),
        false,
        false,
    );
}

#[test]
#[ignore = "isolated namespace; automatic native QUIC reservation return and incoming circuits"]
fn automatic_ipv4_quic_reservations_return_with_incoming_access() {
    reservation_return(
        concat!(
            module_path!(),
            "::automatic_ipv4_quic_reservations_return_with_incoming_access"
        ),
        false,
        true,
    );
}

#[test]
#[ignore = "isolated namespace; configured IPv6 native QUIC reservation return and incoming circuits"]
fn configured_ipv6_quic_reservations_return_with_incoming_access() {
    reservation_return(
        concat!(
            module_path!(),
            "::configured_ipv6_quic_reservations_return_with_incoming_access"
        ),
        true,
        false,
    );
}

#[test]
#[ignore = "isolated namespace; automatic IPv6 native QUIC reservation return and incoming circuits"]
fn automatic_ipv6_quic_reservations_return_with_incoming_access() {
    reservation_return(
        concat!(
            module_path!(),
            "::automatic_ipv6_quic_reservations_return_with_incoming_access"
        ),
        true,
        true,
    );
}

fn reservation_return(name: &str, ipv6: bool, automatic: bool) {
    // module_path includes the crate; libtest's exact names do not.
    let name = name.strip_prefix("p2p_vpn::").unwrap();
    let Some(routes) = setup_sources(name, ipv6) else {
        return;
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut server = super::super::super::super::tests::membership_sync_test_node(
                NodeIdentity::generate_ed25519().unwrap(),
            );
            isolated_dht(&mut server);
            server.swarm.behaviour_mut().relay_server = Some(relay::Behaviour::new(
                server.local_peer_id,
                relay::Config {
                    reservation_rate_limiters: Vec::new(),
                    circuit_src_rate_limiters: Vec::new(),
                    ..Default::default()
                },
            ))
            .into();
            let family = if ipv6 { "ip6" } else { "ip4" };
            server
                .swarm
                .listen_on(
                    format!("/{family}/{}/udp/0/quic-v1", routes.destination)
                        .parse()
                        .unwrap(),
                )
                .unwrap();
            let address = loop {
                if let SwarmEvent::NewListenAddr { address, .. } =
                    server.swarm.select_next_some().await
                {
                    break address;
                }
            };
            server.swarm.add_external_address(address.clone());
            let peer = server.local_peer_id;
            let mut fixture = Fixture::new(peer);
            fixture.bootstrap.push((peer, address.clone()));
            fixture.relays.push((peer, address.clone()));
            let options = DialOpts::peer_id(peer)
                .addresses(vec![address.clone()])
                .allocate_new_port()
                .build();
            let mut old = options.connection_id();
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
                        .services(peer, old)
                        .is_some_and(|services| services.relay)
                })
                .await;
            let base = address.with(Protocol::P2p(peer)).with(Protocol::P2pCircuit);
            let listener = fixture.node.swarm.listen_on(base.clone()).unwrap();
            assert!(
                fixture
                    .node
                    .swarm
                    .behaviour_mut()
                    .relay
                    .pin_reservation_listener(peer, listener, old)
            );
            if automatic {
                fixture.auto_relay.reservation_listeners.insert(
                    peer,
                    AutoRelayListener {
                        id: listener,
                        connection: old,
                    },
                );
            } else {
                fixture
                    .node
                    .configured_relay_reservation_listeners
                    .insert(listener);
            }
            fixture
                .until(&mut server, |fixture| fixture.readiness.relay_ready(peer))
                .await;
            if automatic {
                fixture.auto_relay.record_reservation_accepted(peer);
            }
            fixture.require_incoming = true;
            let initial = fixture
                .node
                .swarm
                .behaviour()
                .connection_retention
                .physical_routes()
                .unwrap()
                .connection(peer, old)
                .unwrap();
            assert_eq!(initial.lease.context.protocol, SocketProtocol::Udp);
            assert_eq!(initial.lease.local_addr.ip().to_string(), routes.sources[0]);
            incoming_ping(&mut fixture, &mut server, &base, old).await;
            assert_reservation_diagnostic(&fixture, peer, old);
            let owners = fixture
                .node
                .swarm
                .behaviour()
                .connection_retention
                .physical_routes()
                .unwrap()
                .clone();
            for source in [routes.sources[1], routes.sources[0]] {
                let previous = owners.connection(peer, old).unwrap();
                let old_listener = fixture.readiness.relayed_listen_addresses[&peer][0].0;
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
                assert!(
                    owners.connection(peer, old).is_some(),
                    "fallback remains until replacement validation"
                );
                fixture
                    .until(&mut server, |fixture| {
                        !fixture.connections.contains_key(&(peer, old))
                            && fixture.readiness.relay_ready(peer)
                            && fixture
                                .node
                                .swarm
                                .behaviour()
                                .relay
                                .confirmed_reservation_connections(peer)
                                .any(|id| id != old)
                    })
                    .await;
                let replacement = fixture
                    .node
                    .swarm
                    .behaviour()
                    .relay
                    .confirmed_reservation_connections(peer)
                    .next()
                    .unwrap();
                assert_ne!(replacement, old);
                let current = owners.connection(peer, replacement).unwrap();
                assert_eq!(
                    current.lease.context.protocol,
                    SocketProtocol::Udp,
                    "a TCP replacement cannot satisfy native QUIC reservation coverage"
                );
                assert_eq!(current.lease.local_addr.ip().to_string(), source);
                assert!(
                    server
                        .swarm
                        .behaviour()
                        .connection_retention
                        .physical_routes()
                        .unwrap()
                        .snapshot()
                        .iter()
                        .any(|route| route.peer == fixture.node.local_peer_id
                            && route.is_adopted()
                            && !route.lease.preferred_dial
                            && route.lease.context.destination == current.lease.local_addr),
                    "relay observes the replacement source on the wire"
                );
                assert!(owners.connection(peer, old).is_none());
                assert!(!previous.is_live());
                assert_reservation_diagnostic(&fixture, peer, replacement);
                let bindings = &fixture.readiness.relayed_listen_addresses[&peer];
                assert_eq!(
                    bindings.len(),
                    1,
                    "retired reservation listener remains advertised"
                );
                let listener = bindings[0].0;
                assert_ne!(listener, old_listener);
                assert_eq!(
                    fixture
                        .node
                        .swarm
                        .behaviour()
                        .relay
                        .reservation_listener_connection(peer, listener),
                    Some(replacement)
                );
                assert_eq!(
                    fixture
                        .node
                        .swarm
                        .behaviour()
                        .relay
                        .reservation_listener_connection(peer, old_listener),
                    None
                );
                if automatic {
                    assert_eq!(
                        fixture.auto_relay.reservation_listeners[&peer].connection,
                        replacement
                    );
                } else {
                    assert!(
                        fixture
                            .node
                            .configured_relay_reservation_listeners
                            .contains(&listener)
                    );
                }
                tokio::time::timeout(Duration::from_secs(12), async {
                    loop {
                        let remote_retired = !server
                            .swarm
                            .behaviour()
                            .connection_retention
                            .physical_routes()
                            .unwrap()
                            .snapshot()
                            .iter()
                            .any(|route| {
                                route.peer == fixture.node.local_peer_id
                                    && route.lease.context.destination == previous.lease.local_addr
                            });
                        if remote_retired && UdpSocket::bind(previous.lease.local_addr).is_ok() {
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
                .expect("retired QUIC reservation socket and remote owner must close");
                incoming_ping(&mut fixture, &mut server, &base, replacement).await;
                old = replacement;
            }
        });
}

fn assert_reservation_diagnostic(fixture: &Fixture, peer: Libp2pPeerId, owner: ConnectionId) {
    let rows = crate::runtime::runner::transport_diagnostics::capture(
        fixture.node.swarm.behaviour(),
        &fixture.connections,
        &fixture.epochs,
    );
    let prefix = format!("physical reservation state: peer={peer} connection_id=");
    let mut reservations = rows.iter().filter(|row| row.starts_with(&prefix));
    assert!(reservations.next().is_some_and(|row| {
        row.starts_with(&format!("{prefix}{owner} reservation=confirmed "))
            && row.contains("/quic-v1")
            && row.ends_with("outer_usable=true outer_retiring=false")
    }));
    assert!(reservations.next().is_none(), "{rows:?}");
}

async fn incoming_ping(
    fixture: &mut Fixture,
    server: &mut P2pNode,
    base: &Multiaddr,
    outer: ConnectionId,
) {
    let mut visitor = super::super::super::super::tests::membership_sync_test_node(
        NodeIdentity::generate_ed25519().unwrap(),
    );
    isolated_dht(&mut visitor);
    let target = fixture.node.local_peer_id;
    let peer = visitor.local_peer_id;
    let options = DialOpts::peer_id(target)
        .addresses(vec![base.clone().with(Protocol::P2p(target))])
        .allocate_new_port()
        .build();
    let id = options.connection_id();
    visitor.swarm.dial(options).unwrap();
    let mut accepted = None;
    let mut pinged = false;
    tokio::time::timeout(Duration::from_secs(8), async {
        while accepted.is_none() || !pinged {
            tokio::select! {
                event = fixture.node.swarm.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, connection_id, ref endpoint, .. } = event
                        && peer_id == peer {
                        assert!(endpoint.is_relayed());
                        assert_eq!(fixture.node.swarm.behaviour().relay.circuit_connection_owner(peer, connection_id), Some((server.local_peer_id, outer)));
                        accepted = Some(connection_id);
                    }
                    fixture.event(event);
                },
                event = visitor.swarm.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } if peer_id == target => {
                        assert_eq!(connection_id, id);
                        assert!(endpoint.is_relayed());
                    },
                    SwarmEvent::Behaviour(BehaviourEvent::Ping(ping::Event { peer: remote, connection, result: Ok(_), .. })) if remote == target => {
                        assert_eq!(connection, id);
                        pinged = true;
                    },
                    SwarmEvent::OutgoingConnectionError { error, .. } => panic!("incoming relay probe failed: {error}"),
                    _ => {},
                },
                _ = server.swarm.select_next_some() => {},
                _ = tokio::time::sleep(Duration::from_millis(10)) => {},
            }
            fixture.drive();
        }
    }).await.expect("incoming QUIC-backed circuit must authenticate and carry a ping");
    assert!(visitor.swarm.close_connection(id));
    let accepted = accepted.unwrap();
    tokio::time::timeout(Duration::from_secs(8), async {
        while fixture.connections.contains_key(&(peer, accepted)) {
            tokio::select! {
                event = fixture.node.swarm.select_next_some() => fixture.event(event),
                _ = visitor.swarm.select_next_some() => {},
                _ = server.swarm.select_next_some() => {},
                _ = tokio::time::sleep(Duration::from_millis(10)) => {},
            }
            fixture.drive();
        }
    })
    .await
    .expect("completed incoming probe must release its circuit dependency");
}
