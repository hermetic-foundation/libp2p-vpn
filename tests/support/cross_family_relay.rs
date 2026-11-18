//! Two VPN members with disjoint TCP entrances, sharing one real circuit relay.
//! Each member can use only its configured entrance in this loopback fixture.
//! This does not assert host or namespace IPv4/IPv6 isolation.

use super::*;
use libp2p::{Multiaddr, multiaddr::Protocol};
use p2p_vpn::config::BootstrapPeerConfig;

#[path = "cross_family_relay/observations.rs"]
mod observations;
use observations::{Live, wait_until};

const RELAY_PACKETS: &str = "outbound_relay_stream_fallback_packets";

#[test]
fn cross_family_relay_ipv4_reserves_ipv6_dials() {
    run(true);
}

#[test]
fn cross_family_relay_ipv6_reserves_ipv4_dials() {
    run(false);
}

fn run(reserver_uses_ipv4: bool) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(8 * 1024 * 1024)
                .enable_all()
                .build()
                .unwrap()
                .block_on(scenario(reserver_uses_ipv4));
        })
        .unwrap()
        .join()
        .unwrap();
}

fn config_without_direct_paths(local: &NodeIdentity, remote: &NodeIdentity) -> Config {
    let mut config = config(local, remote, "127.0.0.1:0".parse().unwrap(), vec![]);
    config.network.listen_addresses.clear();
    assert!(config.network.external_addresses.is_empty());
    assert!(config.network.bootstrap_peers.is_empty());
    assert!(config.network.relay.reservations.is_empty());
    config
}

async fn scenario(reserver_uses_ipv4: bool) {
    let receiver = NodeIdentity::generate_ed25519().unwrap();
    let receiver_ip = builtin_ipv4(PeerId::from_libp2p(receiver.peer_id.parse().unwrap()));
    let sender = loop {
        let candidate = NodeIdentity::generate_ed25519().unwrap();
        if builtin_ipv4(PeerId::from_libp2p(candidate.peer_id.parse().unwrap())) != receiver_ip {
            break candidate;
        }
    };
    let relay_id = NodeIdentity::generate_ed25519().unwrap();
    let sender_peer: libp2p::PeerId = sender.peer_id.parse().unwrap();
    let relay_peer: libp2p::PeerId = relay_id.peer_id.parse().unwrap();
    let receiver_peer: libp2p::PeerId = receiver.peer_id.parse().unwrap();

    let mut relay_config = config_without_direct_paths(&relay_id, &receiver);
    relay_config.peers.clear();
    relay_config.network.listen_addresses = vec![
        "/ip4/127.0.0.1/tcp/0".to_owned(),
        "/ip6/::1/tcp/0".to_owned(),
    ];
    relay_config.network.relay.server = true;
    let relay = Node::start(relay_config);
    let live = wait_until("two relay entrances", &relay, |live| {
        relay_entrances(live, relay_peer).is_some()
    })
    .await;
    let [v4, v6] = relay_entrances(&live, relay_peer).unwrap();
    let (reserved, dialing) = if reserver_uses_ipv4 {
        (v4, v6)
    } else {
        (v6, v4)
    };
    let destination = |address: &Multiaddr| {
        address
            .clone()
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(receiver_peer))
    };

    let mut receiver_config = config_without_direct_paths(&receiver, &sender);
    receiver_config.network.relay.auto.max_candidates = 1;
    receiver_config.network.relay.auto.max_reservations = 1;
    // Seed only one native transport, never a reservation or a peer circuit address.
    receiver_config
        .network
        .bootstrap_peers
        .push(BootstrapPeerConfig {
            id: relay_id.peer_id.clone(),
            address: reserved.to_string(),
        });
    let mut reserver = Node::start(receiver_config);
    let reserved_publication = destination(&reserved);
    let opposite_publication = destination(&dialing);
    let readiness = wait_until(
        "one automatic reservation with both HOP addresses",
        &reserver,
        |live| {
            live.metric("auto_relay_active_reservations") == 1
                && live
                    .relay_listen_addresses()
                    .contains(&reserved_publication)
                && live
                    .relay_listen_addresses()
                    .contains(&opposite_publication)
        },
    )
    .await;
    assert_eq!(readiness.metric("relay_reservations_accepted"), 1);
    let published = readiness.relay_listen_addresses();
    assert_eq!(
        published.len(),
        2,
        "unexpected reservation addresses: {published:?}"
    );

    let mut sender_config = config_without_direct_paths(&sender, &receiver);
    // Use only what the member published for the opposite entrance. No
    // direct routes, DNS, discovery, second relay, or dialer reservation.
    sender_config.peers[0].addresses = published
        .iter()
        .filter(|address| **address == opposite_publication)
        .map(ToString::to_string)
        .collect();
    let mut dialer = Node::start(sender_config);
    let dialing_path = |live: &Live| live.selected_circuit(receiver_peer, &dialing, "dialer");
    let reserved_path = |live: &Live| live.selected_circuit(sender_peer, &reserved, "listener");
    // A packet on each side also drives configured-peer connection acquisition.
    let baseline_dialer = Live::read(&dialer).await.metric(RELAY_PACKETS);
    let baseline_reserver = Live::read(&reserver).await.metric(RELAY_PACKETS);
    let mut sequence = 0;
    let mut successes = 0;
    let mut observations = None;
    let deadline = Instant::now() + Duration::from_secs(25);
    while Instant::now() < deadline {
        sequence += 1;
        let delivered = probe(
            &mut dialer,
            &mut reserver,
            sequence,
            Duration::from_millis(500),
        )
        .await;
        let a = Live::read(&dialer).await;
        let b = Live::read(&reserver).await;
        if delivered && dialing_path(&a) && reserved_path(&b) {
            successes += 1;
            if successes == 3 {
                observations = Some((a, b));
                break;
            }
        } else {
            successes = 0;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (a, b) = match observations {
        Some(observations) => observations,
        None => panic!(
            "cross-family relay did not deliver: dialer={:?}, reserver={:?}",
            Live::read(&dialer).await,
            Live::read(&reserver).await
        ),
    };
    assert!(a.metric(RELAY_PACKETS) >= baseline_dialer + 3);
    assert!(b.metric(RELAY_PACKETS) >= baseline_reserver + 3);
    assert_eq!(a.metric("relay_reservations_accepted"), 0);
    assert_eq!(b.metric("auto_relay_active_reservations"), 1);
    for live in [&a, &b] {
        assert_eq!(
            live.metric("outbound_direct_tcp_stream_fallback_packets"),
            0
        );
        assert_eq!(
            live.metric("outbound_direct_quic_stream_fallback_packets"),
            0
        );
    }
    let server = Live::read(&relay).await;
    assert_eq!(server.metric("relay_server_reservations_accepted"), 1);
    assert!(server.metric("relay_server_circuits_accepted") > 0);

    stop(relay).await;
    wait_until("dialer loses circuit on relay shutdown", &dialer, |live| {
        !dialing_path(live)
    })
    .await;
    wait_until(
        "reserver loses circuit on relay shutdown",
        &reserver,
        |live| !reserved_path(live),
    )
    .await;
    for _ in 0..3 {
        sequence += 1;
        assert_neither_delivers(&mut dialer, &mut reserver, sequence).await;
    }
    stop(dialer).await;
    stop(reserver).await;
}

fn relay_entrances(live: &Live, relay: libp2p::PeerId) -> Option<[Multiaddr; 2]> {
    let mut v4 = None;
    let mut v6 = None;
    for address in live.events("relay_server_external_address_advertised") {
        match address.iter().next() {
            Some(Protocol::Ip4(ip)) if ip == Ipv4Addr::LOCALHOST => {
                v4 = address.with_p2p(relay).ok()
            }
            Some(Protocol::Ip6(ip)) if ip.is_loopback() => v6 = address.with_p2p(relay).ok(),
            _ => panic!("test relay announced a non-loopback entrance: {address}"),
        }
    }
    Some([v4?, v6?])
}

async fn assert_neither_delivers(a: &mut Node, b: &mut Node, sequence: u64) {
    let ab = packet(a.ip, b.ip, sequence);
    let ba = packet(b.ip, a.ip, sequence);
    a.input.send(Some(ab.clone())).unwrap();
    b.input.send(Some(ba.clone())).unwrap();
    let deadline = tokio::time::sleep(Duration::from_millis(400));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            received = a.output.recv() => assert_ne!(received.expect("dialer still running"), ba),
            received = b.output.recv() => assert_ne!(received.expect("reserver still running"), ab),
            _ = &mut deadline => break,
        }
    }
}

async fn stop(mut node: Node) {
    node.shutdown.take().unwrap().send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), node.daemon)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
