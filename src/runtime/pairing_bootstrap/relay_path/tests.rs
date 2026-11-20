use std::{
    io::{BufRead as _, BufReader, Write as _},
    process::{Child, Command, Stdio},
};

use futures::StreamExt as _;
use libp2p::{StreamProtocol, SwarmBuilder, kad, request_response, swarm::NetworkBehaviour, tcp};

use crate::{
    config::PUBLIC_IPFS_KADEMLIA_PROTOCOL,
    identity::NodeIdentity,
    pairing_code::PairingCode,
    runtime::{
        pairing_code::{
            self, PairingCodeRejectionReason, PairingCodeV2Codec, PairingCodeV2Request,
            PairingCodeV2Response,
        },
        physical_network::linux::{isolated_namespace, test_ip as ip},
    },
};

use super::{
    super::{
        BootstrapState, PairingBootstrapBehaviourEvent, PairingBootstrapOptions,
        build_bootstrap_path, controlled_kademlia_config, drive_hellos, drive_public_lookup,
        handle_swarm_event, kademlia_pairing_code_v2_key,
    },
    *,
};

const TEST_NAME: &str =
    "runtime::pairing_bootstrap::relay_path::tests::provider_circuit_uses_current_default_only";
const SEED_ENV: &str = "P2P_VPN_BOOTSTRAP_RELAY_TEST_SEED";

#[test]
fn circuit_requires_an_exact_public_native_route() {
    let relay = PeerId::random();
    let provider = PeerId::random();
    let valid: Multiaddr =
        format!("/ip4/11.253.0.2/tcp/4001/p2p/{relay}/p2p-circuit/p2p/{provider}")
            .parse()
            .unwrap();
    assert!(eligible(&valid, provider));
    assert!(!eligible(&valid, PeerId::random()));
    assert!(!eligible(
        &valid.clone().with(Protocol::P2pCircuit),
        provider
    ));
    let mut missing = valid;
    missing.pop();
    assert!(!eligible(&missing, provider));
    for base in [
        "/ip4/127.0.0.1/tcp/4001",
        "/ip4/10.0.0.1/tcp/4001",
        "/ip4/11.253.0.2/tcp/0",
        "/dns4/relay.example/tcp/4001",
    ] {
        let address = format!("{base}/p2p/{relay}/p2p-circuit/p2p/{provider}")
            .parse()
            .unwrap();
        assert!(!eligible(&address, provider));
    }
}

struct SeedProcess(Child);

impl Drop for SeedProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "requires isolated Linux namespaces and iproute2; no public network"]
fn provider_circuit_uses_current_default_only() {
    if !isolated_namespace(TEST_NAME) {
        return;
    }
    if std::env::var_os(SEED_ENV).is_some() {
        seed();
        return;
    }
    let valid = PairingCode::generate();
    let secondary = PairingCode::generate();
    let mut seed = SeedProcess(
        Command::new("unshare")
            .arg("--net")
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--ignored", "--nocapture"])
            .env(SEED_ENV, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut lines = BufReader::new(seed.0.stdout.take().unwrap())
        .lines()
        .map(Result::unwrap);
    assert!(lines.by_ref().any(|line| line == "bootstrap-relay-ready"));
    let pid = seed.0.id().to_string();
    for (local, remote, address) in [
        ("physical", "seed", "11.253.0.1/24"),
        ("secondary", "alternate", "11.254.0.1/24"),
    ] {
        ip(&[
            "link", "add", local, "type", "veth", "peer", "name", remote, "netns", &pid,
        ]);
        ip(&["link", "set", local, "addrgenmode", "none"]);
        ip(&["addr", "add", address, "dev", local]);
        ip(&["link", "set", local, "up"]);
    }
    ip(&["route", "add", "default", "dev", "physical"]);
    writeln!(
        seed.0.stdin.take().unwrap(),
        "{} {}",
        valid.global_locator(),
        secondary.global_locator()
    )
    .unwrap();
    let line = lines
        .by_ref()
        .find_map(|line| {
            line.strip_prefix("bootstrap-relay-listening ")
                .map(str::to_owned)
        })
        .expect("seed failed to reserve");
    let mut fields = line.split_whitespace();
    let bootstrap = fields.next().unwrap().parse::<Multiaddr>().unwrap();
    let provider = fields.next().unwrap().parse::<PeerId>().unwrap();
    let circuit = fields.next().unwrap().parse::<Multiaddr>().unwrap();
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let (mut client, mut state, id) = discover(&bootstrap, &secondary, provider).await;
        let hint = &state.candidates[&provider].relay_hint.as_ref().unwrap().address;
        let mut parts = hint.iter();
        let (Some(Protocol::Ip4(alternate_ip)), Some(Protocol::Tcp(port))) = (parts.next(), parts.next()) else {
            panic!("expected alternate TCP listener");
        };
        assert_eq!(alternate_ip.octets(), [11, 254, 0, 2]);
        tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect((alternate_ip, port)))
            .await.unwrap().expect("fixture's secondary listener is reachable by the secondary route");
        drive_hellos(&mut client, &mut state, &id, &secondary, client_peer(&id));
        assert!(state.relay_gate.as_ref().unwrap().busy());
        let terminal = await_circuit(&mut client, &mut state, &id, &secondary, provider).await;
        assert!(terminal.is_none(), "secondary link must not carry the circuit");
        drop(client);
        drop(state);

        let (stale_client, mut state, _) = discover(&bootstrap, &valid, provider).await;
        let stale = state.candidates.get_mut(&provider).unwrap().relay_hint.take().unwrap();
        assert_eq!(stale.address, circuit);
        let gate = state.relay_gate.as_ref().unwrap();
        let later = Instant::now() + HINT_TTL;
        let retry = stale.for_poll_retry(later);
        let id = ConnectionId::new_unchecked(1);
        assert!(!gate.reserve(id, provider, stale.clone(), later));
        assert_eq!(retry.address, circuit);
        assert!(gate.reserve(id, provider, retry, later));
        gate.finish(id);
        ip(&["route", "replace", "default", "dev", "secondary"]);
        tokio::time::timeout(Duration::from_secs(3), stale.scope.invalidated()).await.unwrap();
        let now = Instant::now();
        assert!(!gate.reserve(id, provider, stale.for_poll_retry(now), now));
        ip(&["route", "replace", "default", "dev", "physical"]);
        drop(stale_client);
        drop(state);

        let (mut client, mut state, id) = discover(&bootstrap, &valid, provider).await;
        let local = client_peer(&id);
        assert_eq!(state.candidates[&provider].relay_hint.as_ref().unwrap().address, circuit);
        drive_hellos(&mut client, &mut state, &id, &valid, local);
        assert!(state.relay_gate.as_ref().unwrap().busy());
        let id_on_circuit = await_circuit(&mut client, &mut state, &id, &valid, provider)
            .await.expect("default-link reserved circuit");
        drive_hellos(&mut client, &mut state, &id, &valid, local);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let event = client.select_next_some().await;
                let answered = matches!(&event,
                    SwarmEvent::Behaviour(PairingBootstrapBehaviourEvent::PairingCodeV2(
                        request_response::Event::Message { peer, connection_id, message: request_response::Message::Response {
                            response: PairingCodeV2Response::Rejected { reason: PairingCodeRejectionReason::InvalidRequest }, ..
                        }, .. }
                    )) if *peer == provider && *connection_id == id_on_circuit);
                assert!(handle_swarm_event(&mut client, &mut state, &id, &valid, &PairingBootstrapOptions::default(), event)
                    .unwrap().is_none());
                if answered { break; }
            }
        }).await.unwrap();
        assert!(state.selected_peer.is_none(), "a DHT provider is not membership or approval");
    });
}

fn client_peer(id: &NodeIdentity) -> PeerId {
    id.peer_id.parse().unwrap()
}

async fn discover(
    bootstrap: &Multiaddr,
    code: &PairingCode,
    provider: PeerId,
) -> (
    libp2p::Swarm<super::super::PairingBootstrapBehaviour>,
    BootstrapState,
    NodeIdentity,
) {
    let id = NodeIdentity::generate_ed25519().unwrap();
    let (mut client, gate) = build_bootstrap_path(&id).unwrap();
    client
        .behaviour_mut()
        .mdns
        .set_allowed_interfaces(Some(Default::default()));
    let local = *client.local_peer_id();
    let routes = client
        .behaviour()
        .connection_retention
        .physical_routes()
        .unwrap()
        .clone();
    let mut kad = kad::Behaviour::with_config(
        local,
        kad::store::MemoryStore::new(local),
        controlled_kademlia_config(StreamProtocol::new(PUBLIC_IPFS_KADEMLIA_PROTOCOL)),
    );
    kad.set_mode(Some(kad::Mode::Client));
    kad.set_outbound_discovery_policy(routes);
    let Some(Protocol::P2p(seed)) = bootstrap.iter().last() else {
        panic!("unpinned seed")
    };
    kad.add_protected_address(&seed, bootstrap.clone());
    client.behaviour_mut().kad = kad;
    let mut state = BootstrapState::new(Instant::now(), Duration::ZERO);
    state.relay_gate = Some(gate);
    drive_public_lookup(&mut client, &mut state, code, Instant::now());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let event = client.select_next_some().await;
            handle_swarm_event(
                &mut client,
                &mut state,
                &id,
                code,
                &PairingBootstrapOptions::default(),
                event,
            )
            .unwrap();
            if state
                .candidates
                .get(&provider)
                .is_some_and(|candidate| candidate.relay_hint.is_some())
            {
                break;
            }
        }
    })
    .await
    .expect("provider hint from live DHT");
    (client, state, id)
}

async fn await_circuit(
    client: &mut libp2p::Swarm<super::super::PairingBootstrapBehaviour>,
    state: &mut BootstrapState,
    identity: &NodeIdentity,
    code: &PairingCode,
    provider: PeerId,
) -> Option<ConnectionId> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = client.select_next_some().await;
            let established = match &event {
                SwarmEvent::ConnectionEstablished {
                    connection_id,
                    peer_id,
                    endpoint,
                    ..
                } if *peer_id == provider && endpoint.is_relayed() => Some(*connection_id),
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    eprintln!("fixture dial failed for {peer_id:?}: {error:?}");
                    None
                }
                _ => None,
            };
            handle_swarm_event(
                client,
                state,
                identity,
                code,
                &PairingBootstrapOptions::default(),
                event,
            )
            .unwrap();
            if !state.relay_gate.as_ref().unwrap().busy() {
                return established.filter(|id| state.relay_connections.contains_key(id));
            }
        }
    })
    .await
    .expect("bounded circuit attempt")
}

#[derive(NetworkBehaviour)]
struct Seed {
    kad: kad::Behaviour<kad::store::MemoryStore>,
    relay: relay::Behaviour,
}

#[derive(NetworkBehaviour)]
struct Provider {
    relay: relay::client::Behaviour,
    pairing: request_response::Behaviour<PairingCodeV2Codec>,
}

fn seed() {
    println!("bootstrap-relay-ready");
    let mut locators = String::new();
    std::io::stdin().read_line(&mut locators).unwrap();
    ip(&["link", "set", "lo", "up"]);
    // Stop the shared namespace from answering ARP for the alternate IP on the primary link.
    assert!(
        Command::new("sysctl")
            .args(["-w", "net.ipv4.conf.all.arp_ignore=1"])
            .stdout(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    for (device, address) in [("seed", "11.253.0.2/24"), ("alternate", "11.254.0.2/24")] {
        ip(&["link", "set", device, "addrgenmode", "none"]);
        ip(&["addr", "add", address, "dev", device]);
        ip(&["link", "set", device, "up"]);
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        use kad::store::RecordStore as _;
        let mut relay = SwarmBuilder::with_new_identity().with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default).unwrap()
            .with_behaviour(|keys| {
                let peer = keys.public().to_peer_id();
                let mut kad = kad::Behaviour::with_config(
                    peer, kad::store::MemoryStore::new(peer),
                    kad::Config::new(StreamProtocol::new(PUBLIC_IPFS_KADEMLIA_PROTOCOL)),
                );
                kad.set_mode(Some(kad::Mode::Server));
                Seed { kad, relay: relay::Behaviour::new(peer, relay::Config::default()) }
            }).unwrap().build();
        let primary = relay.listen_on("/ip4/11.253.0.2/tcp/0".parse().unwrap()).unwrap();
        let secondary = relay.listen_on("/ip4/11.254.0.2/tcp/0".parse().unwrap()).unwrap();
        let (mut a, mut b) = (None, None);
        while a.is_none() || b.is_none() {
            if let SwarmEvent::NewListenAddr { listener_id, address } = relay.select_next_some().await {
                let address = address.with_p2p(*relay.local_peer_id()).unwrap();
                relay.add_external_address(address.clone());
                if listener_id == primary { a = Some(address); }
                else if listener_id == secondary { b = Some(address); }
            }
        }
        let [primary, secondary] = [a.unwrap(), b.unwrap()];
        let mut provider = SwarmBuilder::with_new_identity().with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default).unwrap()
            .with_relay_client(noise::Config::new, yamux::Config::default).unwrap()
            .with_behaviour(|_, relay| Provider { relay, pairing: pairing_code::behaviour_v2(2) })
            .unwrap().build();
        let peer = *provider.local_peer_id();
        let circuit = |base: Multiaddr| base.with(Protocol::P2pCircuit).with(Protocol::P2p(peer));
        let expected = circuit(primary.clone());
        let listener = provider.listen_on(primary.clone().with(Protocol::P2pCircuit)).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
            tokio::select! {
                _ = relay.select_next_some() => {}
                event = provider.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { listener_id, address }
                            if listener_id == listener && address == expected => break,
                        SwarmEvent::OutgoingConnectionError { error, .. } => panic!("{error}"),
                        SwarmEvent::ListenerClosed { reason, .. } => panic!("{reason:?}"),
                        _ => {}
                    }
                }
            }
            }
        }).await.expect("reservation listener");
        for (locator, route) in locators.split_whitespace().zip([expected.clone(), circuit(secondary)]) {
            relay.behaviour_mut().kad.store_mut().add_provider(kad::ProviderRecord::new(
                kademlia_pairing_code_v2_key(locator), peer, vec![route],
            )).unwrap();
        }
        println!("bootstrap-relay-listening {primary} {peer} {expected}");
        loop {
            tokio::select! {
                _ = relay.select_next_some() => {}
                event = provider.select_next_some() => {
                    if let SwarmEvent::Behaviour(ProviderEvent::Pairing(request_response::Event::Message {
                        message: request_response::Message::Request { request: PairingCodeV2Request::Hello { .. }, channel, .. }, ..
                    })) = event {
                        provider.behaviour_mut().pairing.send_response(channel,
                            PairingCodeV2Response::Rejected { reason: PairingCodeRejectionReason::InvalidRequest }).unwrap();
                    }
                }
            }
        }
    });
}
