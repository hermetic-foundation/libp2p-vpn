use super::http::tests::Fixture;
use super::*;
use crate::{
    identity::NodeIdentity,
    runtime::p2p::{kademlia_pairing_code_key, kademlia_pairing_code_v2_key},
    runtime::physical_network::linux::{isolated_namespace, test_ip as ip},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use libp2p::{
    core::transport::ListenerId,
    kad::store::RecordStore as _,
    mdns,
    swarm::{
        NetworkBehaviour as _,
        behaviour::{FromSwarm, NewListenAddr},
    },
};
use std::{
    io::{BufRead as _, BufReader, Read as _, Write as _},
    process::{Child, Command, Stdio},
};

const NETWORK: &str = "browser-host-test";
const DHT: &str = PUBLIC_IPFS_KADEMLIA_PROTOCOL;
const CERT: &str = "uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g";
const SERVER_ENV: &str = "P2P_VPN_BROWSER_HOST_TEST_SERVER";
const NAMESPACE_TEST: &str =
    "runtime::browser_host::tests::member_and_pairing_lookups_use_current_default_network";

fn pairing_locator(scoped: bool) -> String {
    URL_SAFE_NO_PAD.encode([u8::from(scoped); 32])
}

fn signed_value(identity: &NodeIdentity, addresses: Vec<Multiaddr>) -> Vec<u8> {
    let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
    peer_address_record::encode(NETWORK, None, identity, addresses, now).unwrap()
}

fn hint() -> Multiaddr {
    format!("/ip4/8.8.8.8/udp/4001/webrtc-direct/certhash/{CERT}")
        .parse()
        .unwrap()
}

fn lan_hint(peer: PeerId) -> Multiaddr {
    format!("/ip4/11.250.0.2/udp/4002/webrtc-direct/certhash/{CERT}/p2p/{peer}")
        .parse()
        .unwrap()
}

fn relay_entrance(port: u16, peer: PeerId) -> Multiaddr {
    format!("/ip4/11.250.0.2/udp/{port}/webrtc-direct/certhash/{CERT}/p2p/{peer}")
        .parse()
        .unwrap()
}

fn advertised_circuit(relay: PeerId, destination: PeerId) -> Multiaddr {
    format!("/ip4/11.250.0.2/tcp/49000/p2p/{relay}/p2p-circuit/p2p/{destination}")
        .parse()
        .unwrap()
}

#[test]
fn signed_hints_are_bound_to_one_peer_and_filtered_for_browser_transport() {
    let signer = NodeIdentity::generate_ed25519().unwrap();
    let peer: PeerId = signer.peer_id.parse().unwrap();
    let other = Keypair::generate_ed25519().public().to_peer_id();
    let request = DiscoveryRequest {
        network_name: NETWORK,
        membership_tag: None,
        peer,
        protocol: StreamProtocol::new(DHT),
        owned_interface: None,
        bootstrap: Vec::new(),
    };
    let address = hint().with_p2p(peer).unwrap();
    let value = signed_value(
        &signer,
        vec![
            hint(),
            address.clone(),
            hint().with_p2p(other).unwrap(),
            format!("/ip4/192.168.1.2/udp/4001/webrtc-direct/certhash/{CERT}")
                .parse()
                .unwrap(),
            format!("/dns4/peer.example/udp/4001/webrtc-direct/certhash/{CERT}")
                .parse()
                .unwrap(),
            format!("/ip4/8.8.8.8/udp/0/webrtc-direct/certhash/{CERT}")
                .parse()
                .unwrap(),
            format!("/ip4/8.8.8.8/tcp/4001/p2p/{other}/p2p-circuit/p2p/{peer}")
                .parse()
                .unwrap(),
        ],
    );
    assert_eq!(verified_candidates(&request, &value), vec![address]);
    let wrong_target = DiscoveryRequest {
        peer: other,
        ..request
    };
    assert!(verified_candidates(&wrong_target, &value).is_empty());
    let wrong_scope = DiscoveryRequest {
        network_name: "another-network",
        peer,
        ..wrong_target
    };
    assert!(verified_candidates(&wrong_scope, &value).is_empty());
}

struct TestServer(Child);

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "isolated Linux network namespaces and iproute2; no Internet traffic"]
fn member_and_pairing_lookups_use_current_default_network() {
    if !isolated_namespace(NAMESPACE_TEST) {
        return;
    }
    if std::env::var_os(SERVER_ENV).is_some() {
        serve_record();
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    let server = Command::new("unshare")
        .arg("--net")
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", NAMESPACE_TEST, "--ignored", "--nocapture"])
        .env(SERVER_ENV, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut server = TestServer(server);
    let mut output = BufReader::new(server.0.stdout.take().unwrap());
    let await_output = |output: &mut BufReader<_>, label: &str| -> String {
        output
            .lines()
            .map(Result::unwrap)
            .find_map(|line| line.strip_prefix(label).map(str::to_owned))
            .expect("DHT fixture closed without reporting readiness")
    };
    await_output(&mut output, "browser-host-namespace-ready");
    let pid = server.0.id().to_string();
    for (client, remote, address) in [
        ("primary", "seed", "11.250.0.1/24"),
        ("secondary", "unused", "11.251.0.1/24"),
    ] {
        ip(&[
            "link", "add", client, "type", "veth", "peer", "name", remote, "netns", &pid,
        ]);
        ip(&["link", "set", "dev", client, "addrgenmode", "none"]);
        ip(&["addr", "add", address, "dev", client]);
        ip(&["link", "set", client, "up"]);
    }
    ip(&["route", "add", "default", "dev", "primary"]);
    ip(&["route", "add", "224.0.0.251/32", "dev", "primary"]);
    server.0.stdin.take().unwrap().write_all(&[1]).unwrap();
    let line = await_output(&mut output, "browser-host-listening ");
    let mut fields = line.split_whitespace();
    let bootstrap = fields.next().unwrap();
    let peer: PeerId = fields.next().unwrap().parse().unwrap();
    let dht_only_peer: PeerId = fields.next().unwrap().parse().unwrap();
    let relay_only_peer: PeerId = fields.next().unwrap().parse().unwrap();
    let relay_port = fields.next().unwrap().parse().unwrap();
    let seed: Multiaddr = bootstrap.parse().unwrap();
    let Some(Protocol::P2p(relay_peer)) = seed.iter().last() else {
        panic!("test seed must pin its relay peer");
    };
    let request = || DiscoveryRequest {
        network_name: NETWORK,
        membership_tag: None,
        peer,
        protocol: StreamProtocol::new(DHT),
        owned_interface: None,
        bootstrap: vec![bootstrap.parse().unwrap()],
    };

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            assert_eq!(
                discover(request()).await.unwrap(),
                vec![hint().with_p2p(peer).unwrap()]
            );
            let http = Fixture::start(StreamProtocol::new(DHT), request().bootstrap).await;
            let gateway = Fixture::start_with_relays(
                StreamProtocol::new(DHT),
                request().bootstrap,
                None,
                vec![relay_entrance(relay_port, relay_peer)],
            )
            .await;
            let (code, reply) = http.lookup(NETWORK, relay_only_peer).await;
            assert_eq!(code, 404, "{reply}");
            exercise_relay_reply(&gateway, peer, relay_peer, true).await;
            exercise_relay_reply(&gateway, relay_only_peer, relay_peer, false).await;
            let lan_request = |kademlia| {
                serde_json::json!({
                    "network_name": NETWORK,
                    "peer": peer.to_string(),
                    "lan": true,
                    "kademlia": kademlia,
                })
            };
            let (code, reply) = http.lookup_request(lan_request(true)).await;
            assert_eq!(code, 200, "{reply}");
            assert_eq!(
                reply,
                serde_json::json!({"addresses":[lan_hint(peer).to_string()], "source":"lan"})
            );
            let (code, reply) = http.lookup(NETWORK, peer).await;
            assert_eq!(code, 200, "{reply}");
            assert_eq!(
                reply,
                serde_json::json!({
                    "addresses": [hint().with_p2p(peer).unwrap().to_string()],
                    "source": "public_dht",
                })
            );
            let (code, reply) = http
                .lookup_request(serde_json::json!({
                    "network_name": NETWORK,
                    "peer": dht_only_peer.to_string(),
                    "lan": true,
                    "kademlia": true,
                }))
                .await;
            assert_eq!(code, 200, "{reply}");
            assert_eq!(
                reply,
                serde_json::json!({
                    "addresses": [hint().with_p2p(dht_only_peer).unwrap().to_string()],
                    "source": "public_dht",
                })
            );
            for scoped in [false, true] {
                let (code, reply) = http.lookup_pairing(scoped, &pairing_locator(scoped)).await;
                assert_eq!(code, 200, "{reply}");
                assert_eq!(
                    reply,
                    serde_json::json!({"addresses":[hint().with_p2p(peer).unwrap().to_string()]})
                );
            }
            let (code, reply) = http.lookup_pairing(true, &pairing_locator(false)).await;
            assert_eq!(code, 200, "{reply}");
            assert_eq!(reply, serde_json::json!({"addresses":[]}));
            assert_eq!(
                discover(DiscoveryRequest {
                    owned_interface: Some("primary"),
                    ..request()
                })
                .await
                .unwrap_err()
                .kind(),
                io::ErrorKind::NetworkUnreachable,
            );

            ip(&["link", "set", "secondary", "up"]);
            ip(&["-6", "route", "add", "default", "dev", "secondary"]);
            assert_eq!(
                discover(request()).await.unwrap_err().kind(),
                io::ErrorKind::NetworkUnreachable
            );
            let (code, reply) = http.lookup(NETWORK, peer).await;
            assert_eq!(code, 503, "{reply}");
            assert_eq!(reply, serde_json::json!({"error":"no_default_network"}));
            let (code, reply) = gateway.lookup(NETWORK, relay_only_peer).await;
            assert_eq!(code, 503, "{reply}");
            assert_eq!(reply, serde_json::json!({"error":"no_default_network"}));
            let (code, reply) = http.lookup_pairing(false, &pairing_locator(false)).await;
            assert_eq!(code, 503, "{reply}");
            assert_eq!(reply, serde_json::json!({"error":"no_default_network"}));
            let (code, reply) = http.lookup_pairing_lan().await;
            assert_eq!(code, 200, "{reply}");
            assert_eq!(
                reply,
                serde_json::json!({"addresses":[lan_hint(peer).to_string()]})
            );
            let (code, reply) = http.lookup_request(lan_request(false)).await;
            assert_eq!(code, 200, "{reply}");
            assert_eq!(
                reply,
                serde_json::json!({"addresses":[lan_hint(peer).to_string()], "source":"lan"})
            );
            let excluded = Fixture::start_excluding(
                StreamProtocol::new(DHT),
                request().bootstrap,
                Some("primary".into()),
            )
            .await;
            let (code, reply) = excluded.lookup_request(lan_request(false)).await;
            assert_eq!(code, 200, "{reply}");
            assert_eq!(reply, serde_json::json!({"addresses":[], "source":null}));
            let (code, reply) = excluded.lookup_pairing_lan().await;
            assert_eq!(code, 200, "{reply}");
            assert_eq!(reply, serde_json::json!({"addresses":[]}));
            ip(&["-6", "route", "del", "default", "dev", "secondary"]);

            let options = request();
            let result = with_default_dht(&options.protocol, &options.bootstrap, None, |_| async {
                ip(&["route", "replace", "default", "dev", "secondary"]);
                std::future::pending::<io::Result<()>>().await
            })
            .await;
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        });
}

async fn exercise_relay_reply(gateway: &Fixture, peer: PeerId, relay: PeerId, direct: bool) {
    let (code, reply) = gateway.lookup(NETWORK, peer).await;
    assert_eq!(code, 200, "{reply}");
    assert_eq!(reply["source"], "public_dht");
    let expected = if direct {
        vec![hint().with_p2p(peer).unwrap().to_string()]
    } else {
        Vec::new()
    };
    assert_eq!(reply["addresses"], serde_json::json!(expected));
    let loopback: Multiaddr = reply["relay_address"].as_str().unwrap().parse().unwrap();
    let mut parts = loopback.iter();
    assert_eq!(
        parts.next(),
        Some(Protocol::Ip4(std::net::Ipv4Addr::LOCALHOST))
    );
    let Some(Protocol::Udp(port)) = parts.next() else {
        panic!("relay candidate must have a loopback UDP port");
    };
    assert_eq!(
        loopback.to_string(),
        format!(
            "/ip4/127.0.0.1/udp/{port}/webrtc-direct/certhash/{CERT}/p2p/{relay}/p2p-circuit/p2p/{peer}"
        )
    );
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    client.send(b"scoped relay").await.unwrap();
    let mut bytes = [0; 32];
    let length = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..length], b"scoped relay");
    let lease = reply["relay_lease_id"].as_str().unwrap();
    let (code, reply) = gateway.release_relay(lease).await;
    assert_eq!(code, 200, "{reply}");
    assert_eq!(reply, serde_json::json!({"released":true}));
    tokio::time::timeout(Duration::from_secs(2), async {
        let addr = (std::net::Ipv4Addr::LOCALHOST, port);
        while tokio::net::UdpSocket::bind(addr).await.is_err() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("released relay must close the forwarding socket");
    let (code, reply) = gateway.release_relay(lease).await;
    assert_eq!(code, 200, "{reply}");
    assert_eq!(reply, serde_json::json!({"released":false}));
}

fn serve_record() {
    println!("browser-host-namespace-ready");
    io::stdin().read_exact(&mut [0]).unwrap();
    ip(&["link", "set", "dev", "seed", "addrgenmode", "none"]);
    ip(&["addr", "add", "11.250.0.2/24", "dev", "seed"]);
    ip(&["link", "set", "seed", "up"]);
    ip(&["route", "add", "224.0.0.251/32", "dev", "seed"]);
    ip(&["link", "set", "unused", "up"]);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let identity = NodeIdentity::generate_ed25519().unwrap();
            let peer: PeerId = identity.peer_id.parse().unwrap();
            let dht_only_identity = NodeIdentity::generate_ed25519().unwrap();
            let dht_only_peer: PeerId = dht_only_identity.peer_id.parse().unwrap();
            let relay_only_identity = NodeIdentity::generate_ed25519().unwrap();
            let relay_only_peer: PeerId = relay_only_identity.peer_id.parse().unwrap();
            let udp = tokio::net::UdpSocket::bind("11.250.0.2:0").await.unwrap();
            let relay_port = udp.local_addr().unwrap().port();
            tokio::spawn(async move {
                let mut bytes = [0; 2048];
                while let Ok((length, target)) = udp.recv_from(&mut bytes).await {
                    udp.send_to(&bytes[..length], target).await.unwrap();
                }
            });
            let mut announcer = mdns::tokio::Behaviour::new(mdns::Config::default(), peer).unwrap();
            announcer.set_allowed_interfaces(Some(["11.250.0.2".parse().unwrap()].into()));
            announcer.on_swarm_event(FromSwarm::NewListenAddr(NewListenAddr {
                listener_id: ListenerId::next(),
                addr: &lan_hint(peer),
            }));
            let mut swarm = libp2p::SwarmBuilder::with_new_identity()
                .with_tokio()
                .with_tcp(
                    libp2p::tcp::Config::default(),
                    libp2p::noise::Config::new,
                    libp2p::yamux::Config::default,
                )
                .unwrap()
                .with_behaviour(|key| {
                    let server = key.public().to_peer_id();
                    let mut store = kad::store::MemoryStore::new(server);
                    store
                        .put(kad::Record::new(
                            kademlia_peer_addresses_key(NETWORK, None, peer),
                            signed_value(&identity, vec![hint(), advertised_circuit(server, peer)]),
                        ))
                        .unwrap();
                    store
                        .put(kad::Record::new(
                            kademlia_peer_addresses_key(NETWORK, None, dht_only_peer),
                            signed_value(&dht_only_identity, vec![hint()]),
                        ))
                        .unwrap();
                    store
                        .put(kad::Record::new(
                            kademlia_peer_addresses_key(NETWORK, None, relay_only_peer),
                            signed_value(&relay_only_identity, vec![advertised_circuit(server, relay_only_peer)]),
                        ))
                        .unwrap();
                    let unpinned_hint = hint();
                    let private_hint =
                        format!("/ip4/192.168.1.2/udp/4001/webrtc-direct/certhash/{CERT}")
                            .parse()
                            .unwrap();
                    let wrong_peer_hint = unpinned_hint.clone().with_p2p(server).unwrap();
                    let candidates = vec![
                        unpinned_hint,
                        private_hint,
                        wrong_peer_hint,
                        "/ip4/8.8.8.8/tcp/4001".parse().unwrap(),
                    ];
                    for key in [
                        kademlia_pairing_code_v2_key(&pairing_locator(false)),
                        kademlia_pairing_code_key(&pairing_locator(true)),
                    ] {
                        store
                            .add_provider(kad::ProviderRecord::new(key, peer, candidates.clone()))
                            .unwrap();
                    }
                    let mut kad = kad::Behaviour::with_config(
                        server,
                        store,
                        controlled_kademlia_config(StreamProtocol::new(DHT)),
                    );
                    kad.set_mode(Some(kad::Mode::Server));
                    kad
                })
                .unwrap()
                .build();
            swarm
                .listen_on("/ip4/11.250.0.2/tcp/0".parse().unwrap())
                .unwrap();
            loop {
                tokio::select! {
                    event = swarm.select_next_some() => {
                        if let SwarmEvent::NewListenAddr { address, .. } = event {
                            let bootstrap = address.with_p2p(*swarm.local_peer_id()).unwrap();
                            println!("browser-host-listening {bootstrap} {peer} {dht_only_peer} {relay_only_peer} {relay_port}");
                        }
                    }
                    _ = std::future::poll_fn(|cx| announcer.poll(cx)) => {}
                }
            }
        });
}
