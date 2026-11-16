//! Real native TLS, kernel source preference, DHT work, and UDP socket release.

use super::*;
use crate::runtime::physical_network::linux::{isolated_namespace, test_ip as ip};
use std::net::UdpSocket;

#[test]
#[ignore = "isolated namespace; native QUIC-only control source preference and actual UDP socket retirement"]
fn native_quic_source_return_validates_services_and_releases_old_udp_socket() {
    const NAME: &str = "runtime::runner::physical_infrastructure_handoff::tests::quic_namespace::native_quic_source_return_validates_services_and_releases_old_udp_socket";
    source_return(NAME, false);
}

#[test]
#[ignore = "isolated namespace; native IPv6 QUIC-only control source preference and actual UDP socket retirement"]
fn native_ipv6_quic_source_return_validates_services_and_releases_old_udp_socket() {
    const NAME: &str = "runtime::runner::physical_infrastructure_handoff::tests::quic_namespace::native_ipv6_quic_source_return_validates_services_and_releases_old_udp_socket";
    source_return(NAME, true);
}

fn source_return(name: &str, ipv6: bool) {
    if !isolated_namespace(name) {
        return;
    }
    let sources = if ipv6 {
        ["2001:db8::1", "2001:db8:1::1"]
    } else {
        ["192.0.2.1", "198.51.100.1"]
    };
    let destination = if ipv6 { "2001:db8:2::9" } else { "203.0.113.9" };
    let prefix = if ipv6 { "128" } else { "32" };
    ip(&["link", "set", "lo", "up"]);
    for address in [sources[0], sources[1], destination] {
        let address = format!("{address}/{prefix}");
        if ipv6 {
            ip(&["-6", "addr", "add", &address, "dev", "lo", "nodad"]);
        } else {
            ip(&["addr", "add", &address, "dev", "lo"]);
        }
    }
    if ipv6 {
        // IPv6 keeps the implicit metric-0 local route alongside replacements.
        // Remove only that destination route so the fixture controls its source.
        ip(&[
            "-6",
            "route",
            "del",
            "local",
            &format!("{destination}/{prefix}"),
            "dev",
            "lo",
            "table",
            "local",
            "metric",
            "0",
        ]);
    }
    select_source(sources[0], destination, prefix, ipv6);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut server = super::super::super::tests::membership_sync_test_node(
                NodeIdentity::generate_ed25519().unwrap(),
            );
            isolated_dht(&mut server);
            let family = if ipv6 { "ip6" } else { "ip4" };
            server
                .swarm
                .listen_on(
                    format!("/{family}/{destination}/udp/0/quic-v1")
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
            let peer = server.local_peer_id;
            let mut fixture = Fixture::new(peer);
            fixture.bootstrap.push((peer, address.clone()));
            fixture
                .node
                .swarm
                .behaviour_mut()
                .kad
                .add_address(&peer, address.clone());
            let options = DialOpts::peer_id(peer)
                .addresses(vec![address])
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
                        .is_some()
                        && fixture
                            .node
                            .swarm
                            .behaviour()
                            .connection_retention
                            .physical_routes()
                            .unwrap()
                            .connection(peer, old)
                            .is_some_and(|route| route.refresh_required() == Some(false))
                })
                .await;
            let owners = fixture
                .node
                .swarm
                .behaviour()
                .connection_retention
                .physical_routes()
                .unwrap()
                .clone();
            for source in [sources[1], sources[0]] {
                let previous = owners.connection(peer, old).unwrap();
                assert_eq!(previous.lease.context.protocol, SocketProtocol::Udp);
                assert!(
                    UdpSocket::bind(previous.lease.local_addr).is_err(),
                    "fixture must observe a real retained UDP socket"
                );
                select_source(source, destination, prefix, ipv6);
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
                assert_ne!(replacement, old);
                let current = owners.connection(peer, replacement).unwrap();
                assert_eq!(
                    current.lease.context.protocol,
                    SocketProtocol::Udp,
                    "TCP cannot satisfy this QUIC-only fixture"
                );
                assert_eq!(current.lease.local_addr.ip().to_string(), source);
                let observed = server
                    .swarm
                    .behaviour()
                    .connection_retention
                    .physical_routes()
                    .unwrap()
                    .snapshot();
                assert!(
                    observed.iter().any(|route| {
                        route.peer == fixture.node.local_peer_id
                            && route.is_adopted()
                            && !route.lease.preferred_dial
                            && route.lease.context.destination == current.lease.local_addr
                    }),
                    "the TLS acceptor must observe the selected source on the wire"
                );
                assert!(
                    owners.connection(peer, old).is_some(),
                    "retain fallback through authenticated service validation"
                );
                exchange_dht(&mut fixture, &mut server, peer).await;
                fixture
                    .until(&mut server, |fixture| {
                        !fixture.connections.contains_key(&(peer, old))
                    })
                    .await;
                assert!(owners.connection(peer, old).is_none());
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
                .expect("old UDP socket must finish native draining, not just logical close");
                assert!(!previous.is_live());
                assert!(fixture.epochs.is_usable(replacement));
                old = replacement;
            }
        });
}

fn select_source(source: &str, destination: &str, prefix: &str, ipv6: bool) {
    let target = format!("{destination}/{prefix}");
    let mut args = Vec::new();
    if ipv6 {
        args.push("-6");
    }
    args.extend([
        "route", "replace", "local", &target, "dev", "lo", "table", "local", "src", source,
    ]);
    ip(&args);
}

async fn exchange_dht(fixture: &mut Fixture, server: &mut P2pNode, peer: Libp2pPeerId) {
    let query = fixture
        .node
        .swarm
        .behaviour_mut()
        .kad
        .get_closest_peers(peer.to_bytes());
    let mut inbound = false;
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            tokio::select! {
                event = fixture.node.swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { id, result, step, .. })) if id == query && step.last => {
                        assert!(matches!(result, kad::QueryResult::GetClosestPeers(Ok(_))), "{result:?}");
                        break;
                    },
                    event => fixture.event(event),
                },
                event = server.swarm.select_next_some() => if matches!(event, SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::InboundRequest { .. }))) { inbound = true; },
                _ = tokio::time::sleep(Duration::from_millis(10)) => {},
            }
            fixture.drive();
        }
    }).await.expect("DHT work crosses promoted native QUIC owner");
    assert!(inbound, "DHT completion must not be cache-only");
}
