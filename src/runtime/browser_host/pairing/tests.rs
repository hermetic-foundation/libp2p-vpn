use super::*;
use libp2p::kad::store::RecordStore as _;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::Ipv4Addr,
    process::{Child, Command, Stdio},
};
use tokio::{net::UdpSocket, time::timeout};

use crate::{
    identity::NodeIdentity,
    peer_address_record,
    runtime::{
        browser_host::http::tests::Fixture,
        p2p::{controlled_kademlia_config, kademlia_peer_addresses_key},
        physical_network::linux::{isolated_namespace, test_ip as ip},
    },
};

const CERT: &str = "uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g";
const NAMESPACE_TEST: &str =
    "runtime::browser_host::pairing::tests::locator_circuit_uses_the_same_default_network";
const SERVER_ENV: &str = "P2P_VPN_BROWSER_PAIRING_RELAY_TEST_SERVER";
const MEMBER_NETWORK: &str = "browser-pairing-relay-shared-budget";

fn locator(value: u8) -> String {
    URL_SAFE_NO_PAD.encode([value; 32])
}

fn entrance(host: &str, port: u16, relay: PeerId) -> Multiaddr {
    format!("/{host}/udp/{port}/webrtc-direct/certhash/{CERT}/p2p/{relay}")
        .parse()
        .unwrap()
}

fn circuit(address: Multiaddr, provider: PeerId) -> Multiaddr {
    address
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(provider))
}

#[test]
fn only_canonical_sha256_locators_select_existing_provider_keys() {
    let encoded = locator(0);
    let locator = Locator::parse(&encoded).unwrap();
    assert_eq!(
        locator.key(KeySpace::Global),
        kademlia_pairing_code_v2_key(&encoded)
    );
    assert_eq!(
        locator.key(KeySpace::Scoped),
        kademlia_pairing_code_key(&encoded)
    );
    for invalid in [
        format!("{encoded}="),
        format!("{}B", &encoded[..42]),
        format!("{}+", &encoded[..42]),
        "1234-5678-ABCD-EFGH".into(),
    ] {
        assert!(Locator::parse(&invalid).is_none());
    }
}

#[test]
fn provider_routes_can_select_but_cannot_change_the_pinned_entrance() {
    let relay = PeerId::random();
    let provider = PeerId::random();
    let pin = entrance("ip4/8.8.8.8", 4001, relay);
    let gateway = Gateway::new(vec![pin.clone()]).unwrap();
    let expected = circuit(pin.clone(), provider);
    let approve = |route| circuit_hint(&gateway, provider, route);
    assert_eq!(
        approve(expected.clone()),
        Some(RelayHint::Pinned(expected.clone()))
    );
    for native in ["ip4/8.8.4.4/tcp/12345", "ip6/2606:4700::1/udp/443/quic-v1"] {
        let hint = format!("/{native}/p2p/{relay}/p2p-circuit/p2p/{provider}")
            .parse()
            .unwrap();
        assert_eq!(approve(hint), Some(RelayHint::Pinned(expected.clone())));
    }

    for native in [
        "ip4/127.0.0.1/tcp/1",
        "ip4/100.64.1.1/tcp/1",
        "ip4/8.8.8.8/tcp/0",
        "ip4/8.8.8.8/udp/0/quic-v1",
        "ip4/8.8.8.8/udp/4001",
        "ip6/::ffff:8.8.8.8/tcp/1",
        "ip6/64:ff9b::808:808/tcp/1",
        "ip6/2002:0808:0808::1/tcp/1",
        "ip6/3fff::1/tcp/1",
        "dns4/relay.example/tcp/4001",
    ] {
        let hint = format!("/{native}/p2p/{relay}/p2p-circuit/p2p/{provider}")
            .parse()
            .unwrap();
        assert_eq!(approve(hint), None, "{native}");
    }
    let alternate_cert = libp2p::multihash::Multihash::wrap(0x12, &[0; 32]).unwrap();
    let mismatched_cert = "/ip4/8.8.8.8/udp/4001/webrtc-direct"
        .parse::<Multiaddr>()
        .unwrap()
        .with(Protocol::Certhash(alternate_cert))
        .with(Protocol::P2p(relay));
    for invalid in [
        circuit(mismatched_cert, provider),
        circuit(entrance("ip4/8.8.4.4", 4001, relay), provider),
        circuit(entrance("ip4/8.8.8.8", 4002, relay), provider),
        circuit(entrance("ip4/8.8.8.8", 4001, PeerId::random()), provider),
        circuit(pin.clone(), PeerId::random()),
        circuit(expected.clone(), provider),
        pin.with(Protocol::P2pCircuit),
    ] {
        assert_eq!(approve(invalid), None);
    }
}

#[test]
fn unpinned_provider_only_nominates_a_relay_identity() {
    let relay = PeerId::random();
    let provider = PeerId::random();
    let gateway = Gateway::new(vec![]).unwrap();
    let hint = |route| circuit_hint(&gateway, provider, route);
    assert_eq!(
        hint(circuit(entrance("ip4/8.8.8.8", 4001, relay), provider)),
        Some(RelayHint::Discover {
            relay,
            provider,
            advertised_webrtc: true
        }),
    );
    assert_eq!(
        hint(circuit(entrance("ip4/127.0.0.1", 4001, relay), provider)),
        None,
    );
    assert_eq!(
        hint(circuit(entrance("ip4/8.8.8.8", 4001, provider), provider)),
        None,
    );
}

#[test]
fn relay_hints_keep_distinct_candidates_and_prefer_webrtc() {
    let provider = PeerId::random();
    let first = PeerId::random();
    let make = |relay, advertised_webrtc| RelayHint::Discover {
        relay,
        provider,
        advertised_webrtc,
    };
    let mut hints = Hints::default();
    hints.remember_circuit(make(first, false));
    hints.remember_circuit(make(first, true));
    hints.remember_circuit(make(first, false));
    assert_eq!(hints.circuits, vec![make(first, true)]);

    for _ in 0..MAX_RELAY_HINTS {
        hints.remember_circuit(make(PeerId::random(), false));
    }
    let replacement = PeerId::random();
    hints.remember_circuit(make(replacement, true));
    hints.circuits.sort_by_key(|hint| !hint.preferred());
    assert_eq!(hints.circuits.len(), MAX_RELAY_HINTS);
    assert_eq!(hints.circuits[0], make(first, true));
    assert_eq!(hints.circuits[1], make(replacement, true));
    assert!(!hints.circuits[2].preferred());
}

#[test]
fn provider_pool_and_direct_hints_are_bounded() {
    let gateway = Gateway::new(vec![]).unwrap();
    let local = PeerId::random();
    let mut admitted = HashSet::new();
    let mut hints = Hints::default();
    let providers: HashSet<_> = (0..MAX_PROVIDERS * 2)
        .map(|_| PeerId::random())
        .chain([local])
        .collect();
    provider_hints(
        local,
        &mut admitted,
        providers,
        &gateway,
        &mut hints,
        |peer| {
            assert_ne!(peer, local);
            Vec::new()
        },
    );
    assert_eq!(admitted.len(), MAX_PROVIDERS);
    provider_hints(
        local,
        &mut admitted,
        [PeerId::random()].into(),
        &gateway,
        &mut hints,
        |_| panic!("a new provider must not be considered after saturation"),
    );

    let chosen: HashSet<_> = admitted.iter().copied().take(3).collect();
    provider_hints(local, &mut admitted, chosen, &gateway, &mut hints, |peer| {
        (4001..4010)
            .map(|port| entrance("ip4/8.8.8.8", port, peer))
            .flat_map(|address| [address.clone(), address])
            .collect()
    });
    assert_eq!(hints.addresses.len(), MAX_HINTS);
    let counts = hints
        .addresses
        .iter()
        .fold(HashMap::new(), |mut counts, address| {
            let Some(Protocol::P2p(peer)) = address.iter().last() else {
                panic!("direct hint must pin its provider");
            };
            *counts.entry(peer).or_insert(0usize) += 1;
            counts
        });
    assert_eq!(counts.len(), MAX_HINTS / MAX_HINTS_PER_PROVIDER);
    assert!(
        counts
            .values()
            .all(|count| *count == MAX_HINTS_PER_PROVIDER)
    );
}

struct TestSeed(Child);

impl Drop for TestSeed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "isolated Linux network namespaces and iproute2; no Internet traffic"]
fn locator_circuit_uses_the_same_default_network() {
    if !isolated_namespace(NAMESPACE_TEST) {
        return;
    }
    if std::env::var_os(SERVER_ENV).is_some() {
        serve_provider();
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    let mut seed = TestSeed(
        Command::new("unshare")
            .arg("--net")
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", NAMESPACE_TEST, "--ignored", "--nocapture"])
            .env(SERVER_ENV, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut stdout = BufReader::new(seed.0.stdout.take().unwrap());
    let mut output = |prefix: &str| {
        (&mut stdout)
            .lines()
            .map(Result::unwrap)
            .find_map(|line| line.strip_prefix(prefix).map(str::to_owned))
            .expect("pairing provider fixture exited early")
    };
    output("pairing-provider-namespace-ready");
    let pid = seed.0.id().to_string();
    for (local, remote, address) in [
        ("primary", "seed", "11.252.0.1/24"),
        ("secondary", "other", "11.253.0.1/24"),
    ] {
        ip(&[
            "link", "add", local, "type", "veth", "peer", "name", remote, "netns", &pid,
        ]);
        // Link-local IPv6 DAD can otherwise invalidate the IPv4 lookup
        // before this fixture deliberately changes its default route.
        ip(&["link", "set", local, "addrgenmode", "none"]);
        ip(&["addr", "add", address, "dev", local]);
        ip(&["link", "set", local, "up"]);
    }
    ip(&["route", "add", "default", "dev", "primary"]);
    let mut input = seed.0.stdin.take().unwrap();
    input.write_all(&[1]).unwrap();
    let line = output("pairing-provider-listening ");
    let mut fields = line.split_whitespace();
    let bootstrap = [fields.next().unwrap().parse().unwrap()];
    let pin: Multiaddr = fields.next().unwrap().parse().unwrap();
    let provider = fields.next().unwrap().parse().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(exercise_locator(&bootstrap, pin, provider, || {
            input.write_all(&[2]).unwrap();
            output("pairing-provider-withdrawn");
        }));
}

async fn exercise_locator(
    bootstrap: &[Multiaddr],
    pin: Multiaddr,
    provider: PeerId,
    withdraw: impl FnOnce(),
) {
    let protocol = StreamProtocol::new(PUBLIC_IPFS_KADEMLIA_PROTOCOL);
    let no_pins = Fixture::start(protocol.clone(), bootstrap.to_vec()).await;
    let gateway =
        Fixture::start_with_relays(protocol, bootstrap.to_vec(), None, vec![pin.clone()]).await;
    let global = locator(1);
    let scoped = locator(2);
    let direct = entrance("ip4/11.252.0.2", 5000, provider).to_string();
    assert_eq!(
        no_pins.lookup_pairing(false, &global).await,
        (200, json!({"addresses": []}))
    );
    assert_eq!(
        gateway.lookup_pairing(true, &global).await,
        (200, json!({"addresses": []}))
    );
    let (status, mixed) = gateway.lookup_pairing(true, &scoped).await;
    assert_eq!(status, 200, "{mixed}");
    assert_eq!(mixed["addresses"], json!([direct]));
    let (address, id) = pairing_lease(&mixed);
    assert_eq!(
        gateway.release_relay(id).await,
        (200, json!({"released": true}))
    );
    assert_eq!(
        gateway.release_relay(id).await,
        (200, json!({"released": false}))
    );
    wait_for_closed(loopback_port(&address)).await;

    assert_no_secondary(bootstrap, &pin, &global).await;

    let (status, member) = gateway.lookup(MEMBER_NETWORK, provider).await;
    assert_eq!(status, 200, "{member}");
    let (status, reply) = gateway.lookup_pairing(false, &global).await;
    assert_eq!(status, 200, "{reply}");
    let (loopback, lease_id) = pairing_lease(&reply);
    assert_eq!(
        reply,
        json!({
            "addresses": [],
            "relay_source": "approved",
            "relay_address": loopback.to_string(),
            "relay_lease_id": lease_id,
        })
    );
    assert_eq!(
        gateway.lookup_pairing(false, &global).await,
        (429, json!({"error": "relay_busy"}))
    );
    assert_eq!(
        gateway.lookup_pairing(true, &scoped).await,
        (200, json!({"addresses": [direct]}))
    );
    let port = loopback_port(&loopback);
    let mut expected = Multiaddr::empty()
        .with(Protocol::Ip4(Ipv4Addr::LOCALHOST))
        .with(Protocol::Udp(port));
    for part in pin.iter().skip(2) {
        expected.push(part);
    }
    assert_eq!(loopback, circuit(expected, provider));
    let new_port = exercise_handoff(&gateway, &reply, &member, &global, withdraw).await;
    ip(&["route", "replace", "default", "dev", "secondary"]);
    wait_for_closed(new_port).await;
}

async fn exercise_handoff(
    gateway: &Fixture,
    initial: &Value,
    member: &Value,
    locator: &str,
    withdraw: impl FnOnce(),
) -> u16 {
    let (loopback, lease_id) = pairing_lease(initial);
    let selected = initial["relay_address"].as_str().unwrap();
    let member_lease = member["relay_lease_id"].as_str().unwrap();
    let port = loopback_port(&loopback);
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    client.connect((Ipv4Addr::LOCALHOST, port)).await.unwrap();
    assert_echo(&client, b"pairing ingress").await;

    let data = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    assert_ne!(data.local_addr().unwrap(), client.local_addr().unwrap());
    data.connect((Ipv4Addr::LOCALHOST, port)).await.unwrap();
    data.send(b"new tuple before handoff").await.unwrap();
    assert!(
        timeout(Duration::from_millis(150), data.recv(&mut [0; 32]))
            .await
            .is_err()
    );
    assert_echo(&client, b"pairing still owns the tuple").await;

    let unavailable = (404, json!({"error": "relay_lease_unavailable"}));
    assert_eq!(
        gateway.handoff_relay(member_lease, selected).await,
        unavailable
    );
    let wrong_address = member["relay_address"].as_str().unwrap();
    assert_eq!(
        gateway.handoff_relay(lease_id, wrong_address).await,
        unavailable
    );
    withdraw();
    assert_eq!(
        gateway.lookup_pairing(false, locator).await,
        (200, json!({"addresses": []}))
    );
    let (first, second) = tokio::join!(
        gateway.handoff_relay(lease_id, selected),
        gateway.handoff_relay(lease_id, selected),
    );
    let (accepted, rejected) = if first.0 == 200 {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!(rejected, unavailable);
    let (status, replacement) = accepted;
    assert_eq!(status, 200, "{replacement}");
    let new_id = replacement["relay_lease_id"].as_str().unwrap();
    assert_eq!(new_id.len(), 32);
    assert_ne!(new_id, lease_id);
    let new_address: Multiaddr = replacement["relay_address"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let new_port = loopback_port(&new_address);
    assert_ne!(port, new_port);
    assert_eq!(
        new_address.iter().skip(2).collect::<Vec<_>>(),
        loopback.iter().skip(2).collect::<Vec<_>>(),
    );
    assert_eq!(
        replacement,
        json!({"relay_address": new_address.to_string(), "relay_lease_id": new_id})
    );
    wait_for_closed(port).await;
    assert_eq!(
        gateway.release_relay(lease_id).await,
        (200, json!({"released": false}))
    );
    assert_eq!(
        gateway
            .handoff_relay(new_id, replacement["relay_address"].as_str().unwrap())
            .await,
        unavailable
    );
    assert_eq!(
        gateway.release_relay(member_lease).await,
        (200, json!({"released": true}))
    );
    data.connect((Ipv4Addr::LOCALHOST, new_port)).await.unwrap();
    assert_echo(&data, b"data ingress after handoff").await;

    new_port
}

fn pairing_lease(reply: &Value) -> (Multiaddr, &str) {
    assert_eq!(reply["relay_source"], "approved");
    let address = reply["relay_address"].as_str().unwrap().parse().unwrap();
    let id = reply["relay_lease_id"].as_str().unwrap();
    assert_eq!(id.len(), 32);
    (address, id)
}

async fn assert_no_secondary(bootstrap: &[Multiaddr], pin: &Multiaddr, locator: &str) {
    let Some(Protocol::P2p(relay)) = pin.iter().last() else {
        panic!("pinned test relay");
    };
    let wrong_network = Fixture::start_with_relays(
        StreamProtocol::new(PUBLIC_IPFS_KADEMLIA_PROTOCOL),
        bootstrap.to_vec(),
        None,
        vec![entrance("ip4/11.253.0.2", 5001, relay)],
    )
    .await;
    let secondary = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
    secondary.connect("11.253.0.2:5001").await.unwrap();
    assert_echo(&secondary, b"secondary is reachable").await;
    let (status, reply) = wrong_network.lookup_pairing(false, locator).await;
    if status != 200 {
        assert!(matches!(status, 409 | 503), "{status}: {reply}");
        return;
    }
    let (loopback, id) = pairing_lease(&reply);
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    client
        .connect((Ipv4Addr::LOCALHOST, loopback_port(&loopback)))
        .await
        .unwrap();
    client.send(b"must not leave on secondary").await.unwrap();
    assert!(!matches!(
        timeout(Duration::from_millis(250), client.recv(&mut [0; 32])).await,
        Ok(Ok(_)),
    ));
    assert_eq!(
        wrong_network.release_relay(id).await,
        (200, json!({"released": true}))
    );
}

async fn assert_echo(client: &UdpSocket, payload: &[u8]) {
    let mut buffer = [0; 32];
    client.send(payload).await.unwrap();
    let len = timeout(Duration::from_secs(2), client.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..len], payload);
}

async fn wait_for_closed(port: u16) {
    timeout(Duration::from_secs(2), async {
        while UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).await.is_err() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("released or invalidated lease must close the forwarding socket");
}

fn loopback_port(address: &Multiaddr) -> u16 {
    let mut parts = address.iter();
    let (Some(Protocol::Ip4(Ipv4Addr::LOCALHOST)), Some(Protocol::Udp(port))) =
        (parts.next(), parts.next())
    else {
        panic!("pairing relay must bind IPv4 loopback");
    };
    port
}

async fn echo(socket: UdpSocket) {
    let mut bytes = [0; 32];
    while let Ok((len, client)) = socket.recv_from(&mut bytes).await {
        socket.send_to(&bytes[..len], client).await.unwrap();
    }
}

fn serve_provider() {
    println!("pairing-provider-namespace-ready");
    io::stdin().read_exact(&mut [0]).unwrap();
    let (withdraw, mut withdrawn) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        if io::stdin().read_exact(&mut [0]).is_ok() {
            let _ = withdraw.send(());
        }
    });
    ip(&["addr", "add", "11.252.0.2/24", "dev", "seed"]);
    ip(&["link", "set", "seed", "up"]);
    ip(&["addr", "add", "11.253.0.2/24", "dev", "other"]);
    ip(&["link", "set", "other", "up"]);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let identity = NodeIdentity::generate_ed25519().unwrap();
            let provider = identity.peer_id.parse().unwrap();
            let relay = PeerId::random();
            let socket = UdpSocket::bind("11.252.0.2:0").await.unwrap();
            let pin = entrance("ip4/11.252.0.2", socket.local_addr().unwrap().port(), relay);
            tokio::spawn(echo(socket));
            let secondary = UdpSocket::bind("11.253.0.2:5001").await.unwrap();
            socket2::SockRef::from(&secondary)
                .bind_device(Some(b"other"))
                .unwrap();
            tokio::spawn(echo(secondary));
            let mut swarm = libp2p::SwarmBuilder::with_new_identity()
                .with_tokio()
                .with_tcp(
                    libp2p::tcp::Config::default(),
                    libp2p::noise::Config::new,
                    libp2p::yamux::Config::default,
                )
                .unwrap()
                .with_behaviour(|key| {
                    let seed = key.public().to_peer_id();
                    let mut store = kad::store::MemoryStore::new(seed);
                    let native: Multiaddr =
                        format!("/ip4/11.252.0.2/tcp/4001/p2p/{relay}/p2p-circuit/p2p/{provider}")
                            .parse()
                            .unwrap();
                    let value = peer_address_record::encode(
                        MEMBER_NETWORK,
                        None,
                        &identity,
                        vec![native.clone()],
                        std::time::UNIX_EPOCH.elapsed().unwrap().as_secs(),
                    )
                    .unwrap();
                    store
                        .put(kad::Record::new(
                            kademlia_peer_addresses_key(MEMBER_NETWORK, None, provider),
                            value,
                        ))
                        .unwrap();
                    for (key, hints) in [
                        (kademlia_pairing_code_v2_key(&locator(1)), vec![native]),
                        (
                            kademlia_pairing_code_key(&locator(2)),
                            vec![
                                circuit(pin.clone(), provider),
                                entrance("ip4/11.252.0.2", 5000, provider),
                            ],
                        ),
                    ] {
                        store
                            .add_provider(kad::ProviderRecord::new(key, provider, hints))
                            .unwrap();
                    }
                    let mut kad = kad::Behaviour::with_config(
                        seed,
                        store,
                        controlled_kademlia_config(StreamProtocol::new(
                            PUBLIC_IPFS_KADEMLIA_PROTOCOL,
                        )),
                    );
                    kad.set_mode(Some(kad::Mode::Server));
                    kad
                })
                .unwrap()
                .build();
            swarm
                .listen_on("/ip4/11.252.0.2/tcp/0".parse().unwrap())
                .unwrap();
            let mut removed = false;
            loop {
                tokio::select! {
                    Ok(()) = &mut withdrawn, if !removed => {
                        let store = swarm.behaviour_mut().store_mut();
                        store.remove_provider(&kademlia_pairing_code_v2_key(&locator(1)), &provider);
                        store.remove_provider(&kademlia_pairing_code_key(&locator(2)), &provider);
                        removed = true;
                        println!("pairing-provider-withdrawn");
                    }
                    event = swarm.select_next_some() => {
                        if let SwarmEvent::NewListenAddr { address, .. } = event {
                            let bootstrap = address.with_p2p(*swarm.local_peer_id()).unwrap();
                            println!("pairing-provider-listening {bootstrap} {pin} {provider}");
                        }
                    }
                }
            }
        });
}
