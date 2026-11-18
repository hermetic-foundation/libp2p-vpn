//! Real circuit expiry with production actors and no direct/datagram escape path.

use super::*;
use std::collections::BTreeSet;

const CIRCUIT_LIFETIME: Duration = Duration::from_secs(12);
// The successor needs time for relay admission and LAN-first recovery while the
// original is live. Keep the shorter negotiated lifetime for ordinary expiry.
const OVERLAP_CIRCUIT_LIFETIME: Duration = Duration::from_secs(30);
const RECOVERY_WINDOW: Duration = Duration::from_secs(45);
const CIRCUIT_BYTES: u64 = 32 * 1024;

#[derive(Debug)]
struct Observation {
    state: Vec<String>,
    paths: Vec<String>,
    peers: Vec<String>,
    status: Vec<String>,
}

impl Observation {
    fn received_circuit_limit(&self, lifetime: Duration) -> bool {
        self.state.iter().any(|line| {
            line.starts_with("transport event:")
                && line.contains("event=relay_client_limit")
                && line.contains("_circuit ")
                && line.contains(&format!("duration_seconds={} ", lifetime.as_secs()))
                && line.split_whitespace().any(|token| {
                    token
                        .strip_prefix("data_bytes=")
                        .is_some_and(|value| value.parse::<u64>() == Ok(CIRCUIT_BYTES))
                })
        })
    }

    async fn read(node: &Node) -> Self {
        tokio::time::timeout(Duration::from_secs(3), async {
            Self {
                state: node.control.state().await.unwrap(),
                paths: node.control.paths().await.unwrap(),
                peers: node.control.peers().await.unwrap(),
                status: node.control.status().await.unwrap(),
            }
        })
        .await
        .expect("circuit expiry must not stall runtime control")
    }

    fn metric(&self, name: &str) -> u64 {
        self.status
            .iter()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(' ')?.parse().ok())
            .unwrap_or_else(|| panic!("missing metric {name}"))
    }

    fn owner(&self, peer: PeerId) -> Option<u64> {
        self.paths.iter().find_map(|line| {
            if !line.starts_with(&format!("peer path: {peer} circuit_relay "))
                || !line.contains(" healthy true ")
            {
                return None;
            }
            let words = line.split_whitespace().collect::<Vec<_>>();
            words.windows(2).find_map(|pair| {
                (pair[0] == "connection_id")
                    .then(|| pair[1].parse().ok())
                    .flatten()
            })
        })
    }

    fn connections(&self, peer: PeerId) -> u64 {
        self.paths
            .iter()
            .find_map(|line| {
                if !line.starts_with(&format!("peer path: {peer} circuit_relay "))
                    || !line.contains(" healthy true ")
                {
                    return None;
                }
                let words = line.split_whitespace().collect::<Vec<_>>();
                words.windows(2).find_map(|pair| {
                    (pair[0] == "established_connections")
                        .then(|| pair[1].parse().ok())
                        .flatten()
                })
            })
            .unwrap_or(0)
    }

    fn ready(&self, peer: PeerId) -> bool {
        self.owner(peer).is_some()
            && self.peers.iter().any(|line| {
                line.starts_with(&format!("peer: {peer} "))
                    && line.contains(" validated true ")
                    && line.contains(" quic_datagrams false ")
                    && line.contains(" native_quic_datagrams false ")
                    && line.contains(" owned_udp_packet_plane false ")
                    && line.contains(" owned_quic_packet_plane false ")
                    && line.ends_with("selected_path circuit_relay")
            })
    }

    fn evidence(&self) -> serde_json::Value {
        serde_json::json!({
            "state": self.state, "paths": self.paths,
            "peers": self.peers, "status": self.status,
        })
    }
}

#[test]
fn negotiated_limit_assertion_requires_the_exact_byte_count() {
    let mut observation = Observation {
        state: vec!["transport event: event=relay_client_limit role=outbound_circuit duration_seconds=12 data_bytes=327680".to_owned()],
        paths: Vec::new(), peers: Vec::new(), status: Vec::new(),
    };
    assert!(!observation.received_circuit_limit(CIRCUIT_LIFETIME));
    observation.state[0] = "transport event: event=relay_client_limit role=outbound_circuit duration_seconds=12 data_bytes=32768".to_owned();
    assert!(observation.received_circuit_limit(CIRCUIT_LIFETIME));
}

async fn stop(nodes: Vec<Node>) {
    for mut node in nodes {
        let _ = node.shutdown.take().unwrap().send(());
        tokio::time::timeout(Duration::from_secs(15), node.daemon)
            .await
            .expect("runtime must stop after circuit-expiry regression")
            .expect("runtime task panicked")
            .expect("runtime failed during circuit-expiry regression");
    }
}

async fn scenario() -> Result<(), String> {
    let alice = NodeIdentity::generate_ed25519().unwrap();
    let bob = loop {
        let identity = NodeIdentity::generate_ed25519().unwrap();
        if builtin_ipv4(PeerId::from_libp2p(identity.peer_id.parse().unwrap()))
            != builtin_ipv4(PeerId::from_libp2p(alice.peer_id.parse().unwrap()))
        {
            break identity;
        }
    };
    let bridge = NodeIdentity::generate_ed25519().unwrap();
    let bridge_address = free_address();
    let relay_base = format!(
        "/ip4/127.0.0.1/tcp/{}/p2p/{}/p2p-circuit",
        bridge_address.port(),
        bridge.peer_id,
    );
    let bob_relay = format!("{relay_base}/p2p/{}", bob.peer_id);
    let mut relay_config = config(&bridge, &alice, bridge_address, vec![]);
    relay_config.peers.clear();
    relay_config.network.relay.server = true;
    relay_config
        .network
        .relay
        .resources
        .max_circuit_duration_secs = CIRCUIT_LIFETIME.as_secs();
    relay_config.network.relay.resources.max_circuit_bytes = CIRCUIT_BYTES;
    let relay = Node::start(relay_config);
    let mut a_config = config(&alice, &bob, free_address(), vec![bob_relay.clone()]);
    let mut b_config = config(&bob, &alice, free_address(), vec![]);
    // No listener may be learned through Identify and bypass the relay after expiry.
    a_config.network.listen_addresses.clear();
    b_config.network.listen_addresses.clear();
    b_config.network.relay.reservations = vec![relay_base];
    b_config.network.external_addresses = vec![bob_relay];
    let mut a = Node::start(a_config);
    let mut b = Node::start(b_config);
    let a_peer = PeerId::from_libp2p(alice.peer_id.parse().unwrap());
    let b_peer = PeerId::from_libp2p(bob.peer_id.parse().unwrap());

    let result = async {
        let mut sequence = 7_000_000;
        let started = Instant::now();
        let (baseline_a, baseline_b) = loop {
            sequence += 1;
            let delivered = probe(&mut a, &mut b, sequence, Duration::from_millis(500)).await;
            let left = Observation::read(&a).await;
            let right = Observation::read(&b).await;
            if delivered && left.ready(b_peer) && right.ready(a_peer) {
                break (left, right);
            }
            if started.elapsed() >= RECOVERY_WINDOW {
                return Err(format!("initial relay metadata/payload never became ready: {left:?}; {right:?}"));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        let old_a = baseline_a.owner(b_peer).unwrap();
        let old_b = baseline_b.owner(a_peer).unwrap();
        if !baseline_a.received_circuit_limit(CIRCUIT_LIFETIME)
            || !baseline_b.received_circuit_limit(CIRCUIT_LIFETIME)
        {
            return Err("actual negotiated relay limits missing from live State history".into());
        }
        let closed_before = Observation::read(&relay).await.metric("relay_server_circuits_closed");
        let mut owners_a = BTreeSet::from([old_a]);
        let mut owners_b = BTreeSet::from([old_b]);
        let started = Instant::now();
        let mut last_delivery = Instant::now();
        let mut replacement_pairs = 0;
        let mut samples = Vec::new();
        loop {
            sequence += 1;
            let delivered = probe(&mut a, &mut b, sequence, Duration::from_millis(500)).await;
            let left = Observation::read(&a).await;
            let right = Observation::read(&b).await;
            let bridge = Observation::read(&relay).await;
            owners_a.extend(left.owner(b_peer));
            owners_b.extend(right.owner(a_peer));
            if delivered {
                last_delivery = Instant::now();
            }
            let replaced = left.ready(b_peer) && right.ready(a_peer)
                && left.owner(b_peer) != Some(old_a) && right.owner(a_peer) != Some(old_b)
                && bridge.metric("relay_server_circuits_closed") > closed_before;
            replacement_pairs = if delivered && replaced { replacement_pairs + 1 } else { 0 };
            samples.push(serde_json::json!({
                "elapsed_seconds": started.elapsed().as_secs_f64(), "delivered": delivered,
                "a_owner": left.owner(b_peer), "b_owner": right.owner(a_peer),
                "a_validated_relay": left.ready(b_peer), "b_validated_relay": right.ready(a_peer),
                "circuits_closed": bridge.metric("relay_server_circuits_closed"),
            }));
            if started.elapsed() >= CIRCUIT_LIFETIME + Duration::from_secs(2)
                && replacement_pairs >= 10
            {
                if left.metric("outbound_relay_stream_fallback_packets") <= baseline_a.metric("outbound_relay_stream_fallback_packets")
                    || right.metric("outbound_relay_stream_fallback_packets") <= baseline_b.metric("outbound_relay_stream_fallback_packets")
                {
                    return Err("replacement payload did not use relay streams in both directions".into());
                }
                write_evidence("relay-circuit-expiry", &serde_json::json!({
                    "manual_physical_notifications": 0, "circuit_lifetime_seconds": CIRCUIT_LIFETIME.as_secs(),
                    "circuit_bytes": CIRCUIT_BYTES, "a_owners": owners_a, "b_owners": owners_b,
                    "samples": samples, "a": left.evidence(), "b": right.evidence(), "relay": bridge.evidence(),
                }));
                return Ok(());
            }
            if started.elapsed() >= CIRCUIT_LIFETIME + RECOVERY_WINDOW
                || last_delivery.elapsed() >= RECOVERY_WINDOW
            {
                write_evidence("relay-circuit-expiry-failure", &serde_json::json!({
                    "manual_physical_notifications": 0, "a_old_owner": old_a, "b_old_owner": old_b,
                    "a_owners": owners_a, "b_owners": owners_b, "samples": samples,
                    "a": left.evidence(), "b": right.evidence(), "relay": bridge.evidence(),
                }));
                return Err(format!("relay expiry did not recover validated bidirectional streams within {RECOVERY_WINDOW:?}: {left:?}; {right:?}"));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }.await;
    stop(vec![a, b, relay]).await;
    result
}

async fn late_close_scenario() -> Result<(), String> {
    let alice = NodeIdentity::generate_ed25519().unwrap();
    let bob = loop {
        let identity = NodeIdentity::generate_ed25519().unwrap();
        if builtin_ipv4(PeerId::from_libp2p(identity.peer_id.parse().unwrap()))
            != builtin_ipv4(PeerId::from_libp2p(alice.peer_id.parse().unwrap()))
        {
            break identity;
        }
    };
    let bridge = NodeIdentity::generate_ed25519().unwrap();
    let bridge_address = free_address();
    let base = |port| {
        format!(
            "/ip4/127.0.0.1/tcp/{port}/p2p/{}/p2p-circuit",
            bridge.peer_id,
        )
    };
    let bob_relay = format!("{}/p2p/{}", base(bridge_address.port()), bob.peer_id);
    let mut bridge_config = config(&bridge, &alice, bridge_address, vec![]);
    bridge_config.peers.clear();
    bridge_config.network.relay.server = true;
    bridge_config
        .network
        .relay
        .resources
        .max_circuit_duration_secs = OVERLAP_CIRCUIT_LIFETIME.as_secs();
    bridge_config.network.relay.resources.max_circuit_bytes = CIRCUIT_BYTES;
    let relay = Node::start(bridge_config);
    let gate_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let gate_address = gate_listener.local_addr().unwrap();
    let (release, released) = watch::channel(false);
    let accepted = Arc::new(AtomicU64::new(0));
    let gate_accepted = Arc::clone(&accepted);
    let gate_task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                result = gate_listener.accept() => {
                    let (mut incoming, _) = result.unwrap();
                    gate_accepted.fetch_add(1, Ordering::Relaxed);
                    let mut released = released.clone();
                    connections.spawn(async move {
                        while !*released.borrow_and_update() {
                            if released.changed().await.is_err() { return; }
                        }
                        let Ok(mut outgoing) = TcpStream::connect(bridge_address).await else { return; };
                        let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    });
    let mut old_config = config(&alice, &bob, free_address(), vec![bob_relay.clone()]);
    let mut new_config = config(
        &alice,
        &bob,
        free_address(),
        vec![format!("{}/p2p/{}", base(gate_address.port()), bob.peer_id,)],
    );
    let mut b_config = config(&bob, &alice, free_address(), vec![]);
    for config in [&mut old_config, &mut new_config, &mut b_config] {
        config.network.listen_addresses.clear();
    }
    new_config.network.relay.reservations = vec![base(gate_address.port())];
    b_config.network.relay.reservations = vec![base(bridge_address.port())];
    b_config.network.external_addresses = vec![bob_relay];
    let mut b = Node::start(b_config);
    let mut old = Node::start(old_config);
    // Hold the successor's encrypted relay handshake, rather than fail it
    // and measure connection-error backoff instead of late circuit closure.
    let mut replacement = Some(Node::start(new_config));
    let a_peer = PeerId::from_libp2p(alice.peer_id.parse().unwrap());
    let b_peer = PeerId::from_libp2p(bob.peer_id.parse().unwrap());
    replacement
        .as_ref()
        .unwrap()
        .input
        .send(Some(packet(old.ip, b.ip, 7_999_999)))
        .unwrap();
    let result = async {
        let mut sequence = 8_000_000;
        let start = Instant::now();
        let (old_local, old_remote) = loop {
            sequence += 1;
            let delivered = probe(&mut old, &mut b, sequence, Duration::from_millis(500)).await;
            let left = Observation::read(&old).await;
            let right = Observation::read(&b).await;
            if delivered && left.ready(b_peer) && right.ready(a_peer) {
                if !left.received_circuit_limit(OVERLAP_CIRCUIT_LIFETIME)
                    || !right.received_circuit_limit(OVERLAP_CIRCUIT_LIFETIME)
                {
                    return Err("actual negotiated relay limits missing from overlapping circuit history".into());
                }
                break (left.owner(b_peer).unwrap(), right.owner(a_peer).unwrap());
            }
            if start.elapsed() >= RECOVERY_WINDOW {
                return Err("original circuit did not establish bidirectional payload".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        let before = Observation::read(&relay).await.metric("relay_server_circuits_closed");
        // Separate the two actual server deadlines without changing either limit.
        tokio::time::sleep(Duration::from_secs(4)).await;
        if accepted.load(Ordering::Relaxed) == 0 {
            return Err("successor never entered the held relay handshake".into());
        }
        release.send_replace(true);
        // Release the same member's pending connection only after old payload
        // works; both runtimes retain the production LAN-first admission policy.
        let successor = replacement.as_mut().unwrap();
        let start = Instant::now();
        let successor_remote = loop {
            sequence += 1;
            let delivered = probe(successor, &mut b, sequence, Duration::from_millis(300)).await;
            let original = Observation::read(&old).await;
            let left = Observation::read(successor).await;
            let right = Observation::read(&b).await;
            if delivered && left.ready(b_peer) && right.ready(a_peer)
                && right.owner(a_peer) != Some(old_remote) && right.connections(a_peer) >= 2
                && original.owner(b_peer) == Some(old_local)
            {
                if !left.received_circuit_limit(OVERLAP_CIRCUIT_LIFETIME) {
                    return Err("successor did not negotiate the relay circuit limits".into());
                }
                break right.owner(a_peer).unwrap();
            }
            if start.elapsed() >= OVERLAP_CIRCUIT_LIFETIME {
                return Err("successor never overlapped the original live circuit; late-close ordering was not exercised".into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let start = Instant::now();
        let mut after_close_pairs = 0;
        loop {
            let original = Observation::read(&old).await;
            let left = Observation::read(successor).await;
            let right = Observation::read(&b).await;
            let bridge = Observation::read(&relay).await;
            let old_closed = original.owner(b_peer) != Some(old_local)
                && bridge.metric("relay_server_circuits_closed") > before
                && right.connections(a_peer) == 1;
            if old_closed && (!right.ready(a_peer) || right.owner(a_peer) != Some(successor_remote)) {
                return Err("old circuit closure removed the authenticated successor or its metadata".into());
            }
            // While both circuits are live, observe expiry without spending
            // the successor's data budget on repeated probe streams.
            if old_closed {
                sequence += 1;
                let delivered = probe(successor, &mut b, sequence, Duration::from_millis(300)).await;
                after_close_pairs = if delivered && left.ready(b_peer) {
                    after_close_pairs + 1
                } else {
                    0
                };
            } else {
                after_close_pairs = 0;
            }
            if after_close_pairs == 5 {
                write_evidence("relay-circuit-late-close", &serde_json::json!({
                    "manual_physical_notifications": 0, "old_remote_owner": old_remote,
                    "successor_remote_owner": successor_remote, "overlap_required": true,
                    "circuit_lifetime_seconds": OVERLAP_CIRCUIT_LIFETIME.as_secs(), "circuit_bytes": CIRCUIT_BYTES,
                    "fresh_bidirectional_pairs_after_old_close": after_close_pairs,
                    "a": left.evidence(), "b": right.evidence(), "relay": bridge.evidence(),
                }));
                return Ok(());
            }
            if start.elapsed() >= OVERLAP_CIRCUIT_LIFETIME {
                return Err("old expiry did not leave sustained bidirectional payload on its overlapping successor".into());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }.await;
    if let Err(error) = &result {
        let successor = match &replacement {
            Some(node) => Observation::read(node).await.evidence(),
            None => serde_json::Value::Null,
        };
        write_evidence(
            "relay-circuit-late-close-failure",
            &serde_json::json!({
                "error": error, "old": Observation::read(&old).await.evidence(),
                "successor": successor,
                "b": Observation::read(&b).await.evidence(),
                "relay": Observation::read(&relay).await.evidence(),
                "held_handshakes": accepted.load(Ordering::Relaxed),
            }),
        );
    }
    let mut nodes = vec![old];
    nodes.extend(replacement);
    nodes.extend([b, relay]);
    stop(nodes).await;
    gate_task.abort();
    let _ = gate_task.await;
    result
}

#[test]
fn expired_relay_circuit_recovers_bidirectional_streams_without_physical_event() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(8 * 1024 * 1024)
                .enable_all()
                .build()
                .unwrap()
                .block_on(scenario())
                .unwrap();
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn late_expiry_of_old_circuit_preserves_overlapping_authenticated_successor() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(8 * 1024 * 1024)
                .enable_all()
                .build()
                .unwrap()
                .block_on(late_close_scenario())
                .unwrap();
        })
        .unwrap()
        .join()
        .unwrap();
}
