//! Runtime hint plumbing on real loopback transports, not physical migration evidence.

use super::*;
use p2p_vpn::runtime::control_socket::RuntimeNetworkChange;

const CONTROL_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug)]
struct Observation {
    state: Vec<String>,
    status: Vec<String>,
    paths: Vec<String>,
    peers: Vec<String>,
}

impl Observation {
    async fn read(node: &Node) -> Self {
        tokio::time::timeout(CONTROL_TIMEOUT, async {
            Self {
                state: node.control.state().await.unwrap(),
                status: node.control.status().await.unwrap(),
                paths: node.control.paths().await.unwrap(),
                peers: node.control.peers().await.unwrap(),
            }
        })
        .await
        .expect("runtime control must remain responsive")
    }

    fn counter(&self, name: &str) -> u64 {
        self.status
            .iter()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(' ')?.parse().ok())
            .unwrap_or_else(|| panic!("missing metric {name}: {:?}", self.status))
    }

    fn session_lines(&self) -> Vec<&str> {
        self.state
            .iter()
            .filter(|line| line.starts_with("packet_plane_session "))
            .map(String::as_str)
            .collect()
    }

    fn tcp_owner(&self, peer: PeerId) -> Option<&str> {
        self.paths
            .iter()
            .find(|line| {
                line.starts_with(&format!("peer path: {peer} direct_tcp_stream "))
                    && line.contains(" healthy true ")
            })
            .map(String::as_str)
    }

    fn ready(&self, peer: PeerId, udp: bool) -> bool {
        self.tcp_owner(peer).is_some()
            && self
                .state
                .iter()
                .any(|line| line == "connected_overlay_peers 1")
            && self.peers.iter().any(|line| {
                line.starts_with(&format!("peer: {peer} "))
                    && line.contains(" validated true ")
                    && line.contains(&format!("owned_udp_packet_plane {udp} "))
                    && line.ends_with(if udp {
                        "selected_path direct_udp_datagram"
                    } else {
                        "selected_path direct_tcp_stream"
                    })
            })
            && self.session_lines().len() == usize::from(udp)
    }
}

fn field<'a>(line: &'a str, name: &str) -> &'a str {
    let mut words = line.split_whitespace();
    while let Some(word) = words.next() {
        if word == name {
            return words
                .next()
                .unwrap_or_else(|| panic!("missing {name} value: {line}"));
        }
    }
    panic!("missing {name}: {line}");
}

fn assert_retained(before: &Observation, after: &Observation, peer: PeerId, udp: bool) {
    assert!(
        after.ready(peer, udp),
        "established service changed: {after:?}"
    );
    let old = before.tcp_owner(peer).unwrap();
    let current = after.tcp_owner(peer).unwrap();
    for name in [
        "connection_id",
        "established_connections",
        "first_seen_unix_seconds",
        "last_established_unix_seconds",
    ] {
        assert_ne!(
            field(old, name),
            "unknown",
            "baseline lacks exact owner: {old}"
        );
        assert_eq!(
            field(current, name),
            field(old, name),
            "hint changed {name}: {after:?}"
        );
    }
    assert_eq!(
        after.session_lines(),
        before.session_lines(),
        "hint renegotiated UDP keys or endpoint"
    );
    for name in [
        "direct_connections_established",
        "relayed_connections_established",
        "control_requests_sent",
        "packet_plane_sessions_expired",
        "packet_plane_path_demotions",
        "stream_fallback_path_demotions",
        "packet_plane_path_recovery_dial_attempts",
    ] {
        assert_eq!(
            after.counter(name),
            before.counter(name),
            "unexpected {name} delta: {after:?}"
        );
    }
}

fn carrier(udp: bool) -> &'static str {
    if udp {
        "outbound_owned_udp_datagram_packets"
    } else {
        "outbound_direct_tcp_stream_fallback_packets"
    }
}

async fn scenario(udp: bool) {
    let alice = NodeIdentity::generate_ed25519().unwrap();
    let bob = loop {
        let identity = NodeIdentity::generate_ed25519().unwrap();
        if builtin_ipv4(PeerId::from_libp2p(identity.peer_id.parse().unwrap()))
            != builtin_ipv4(PeerId::from_libp2p(alice.peer_id.parse().unwrap()))
        {
            break identity;
        }
    };
    let a_peer = PeerId::from_libp2p(alice.peer_id.parse().unwrap());
    let b_peer = PeerId::from_libp2p(bob.peer_id.parse().unwrap());
    let backend = free_address();
    let a_listener = loop {
        let address = free_address();
        if address != backend {
            break address;
        }
    };
    let proxy = Proxy::new(Ipv4Addr::LOCALHOST, backend, Link::Up).await;
    let mut a_config = config(
        &alice,
        &bob,
        a_listener,
        vec![format!("/ip4/127.0.0.1/tcp/{}", proxy.address.port())],
    );
    let mut b_config = config(&bob, &alice, backend, vec![]);
    if udp {
        for config in [&mut a_config, &mut b_config] {
            config.network.packet_plane.listen = vec!["127.0.0.1:0".to_owned()];
        }
    }
    let (mut a, mut b) = (Node::start(a_config), Node::start(b_config));
    let mut sequence = 2_900_000;
    let name = if udp {
        "physical_hint_owned_udp"
    } else {
        "physical_hint_stream"
    };
    stage(name, &mut a, &mut b, &mut sequence, Duration::from_secs(25)).await;

    // Require fresh delivery on the intended backend and settled authenticated
    // owners before measuring hints. No test-side health or capability injection.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut qualified = 0;
    let baseline = loop {
        let before = [Observation::read(&a).await, Observation::read(&b).await];
        sequence += 1;
        let delivered = probe(&mut a, &mut b, sequence, Duration::from_millis(500)).await;
        let after = [Observation::read(&a).await, Observation::read(&b).await];
        let ready = delivered
            && after
                .iter()
                .zip([b_peer, a_peer])
                .enumerate()
                .all(|(i, (state, peer))| {
                    state.ready(peer, udp)
                        && state.counter(carrier(udp)) > before[i].counter(carrier(udp))
                        && state.counter("control_requests_sent")
                            == before[i].counter("control_requests_sent")
                        && state.session_lines() == before[i].session_lines()
                });
        qualified = if ready { qualified + 1 } else { 0 };
        if qualified == 3 {
            break after;
        }
        assert!(
            Instant::now() < deadline,
            "real baseline did not settle: {after:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let accepted = proxy.accepted.load(Ordering::Relaxed);
    let completed = proxy.bytes.load(Ordering::Relaxed);
    assert!(accepted > 0, "baseline must traverse the real TCP proxy");
    assert_eq!(completed, 0, "baseline stream unexpectedly closed");
    for state in &baseline {
        assert!(state.counter("direct_connections_established") > 0);
        assert!(state.counter("control_requests_sent") > 0);
    }

    let mut sent = baseline.each_ref().map(|state| state.counter(carrier(udp)));
    for _ in 0..8 {
        for node in [&a, &b] {
            let result =
                tokio::time::timeout(CONTROL_TIMEOUT, node.control.physical_network_changed())
                    .await
                    .expect("bounded physical hint acknowledgement")
                    .unwrap();
            assert_eq!(
                result,
                RuntimeNetworkChange::default(),
                "a hint must not perform a full reset"
            );
        }
        sequence += 1;
        assert!(
            probe(&mut a, &mut b, sequence, Duration::from_secs(1)).await,
            "payload must survive each hint without a recovery stage"
        );
        let current = [Observation::read(&a).await, Observation::read(&b).await];
        for (i, peer) in [b_peer, a_peer].into_iter().enumerate() {
            assert_retained(&baseline[i], &current[i], peer, udp);
            let packets = current[i].counter(carrier(udp));
            assert!(
                packets > sent[i],
                "fresh payload used another backend: {:?}",
                current[i]
            );
            sent[i] = packets;
        }
        assert_eq!(
            proxy.accepted.load(Ordering::Relaxed),
            accepted,
            "hint redialed TCP"
        );
        assert_eq!(
            proxy.bytes.load(Ordering::Relaxed),
            completed,
            "hint closed established TCP"
        );
    }

    // The existing explicitly destructive API remains distinct and usable.
    let reset = tokio::time::timeout(CONTROL_TIMEOUT, a.control.network_changed())
        .await
        .unwrap()
        .unwrap();
    assert!(reset.disconnected_peers > 0);
    assert!(reset.invalidated_paths > 0);
    assert_eq!(reset.invalidated_packet_plane_sessions, usize::from(udp));
    for node in [&mut a, &mut b] {
        let _ = node.shutdown.take().unwrap().send(());
    }
    for node in [a, b] {
        tokio::time::timeout(Duration::from_secs(10), node.daemon)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    proxy.set(Link::Stop);
    tokio::time::timeout(CONTROL_TIMEOUT, proxy.task)
        .await
        .unwrap()
        .unwrap();
}

fn run(udp: bool) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(8 * 1024 * 1024)
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    tokio::time::timeout(Duration::from_secs(65), scenario(udp))
                        .await
                        .expect("bounded physical hint integration regression");
                });
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn physical_hints_preserve_established_authenticated_tcp_stream() {
    run(false);
}

#[test]
fn physical_hints_preserve_established_owned_udp_session_and_control_stream() {
    run(true);
}
