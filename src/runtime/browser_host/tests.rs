use super::*;
use crate::{
    identity::NodeIdentity,
    runtime::physical_network::linux::{isolated_namespace, test_ip as ip},
};
use libp2p::kad::store::RecordStore as _;
use std::{
    io::{BufRead as _, BufReader, Read as _, Write as _},
    process::{Child, Command, Stdio},
};

const NETWORK: &str = "browser-host-test";
const DHT: &str = "/p2p-vpn/kad/browser-host-test/1";
const CERT: &str = "uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g";
const SERVER_ENV: &str = "P2P_VPN_BROWSER_HOST_TEST_SERVER";
const NAMESPACE_TEST: &str =
    "runtime::browser_host::tests::signed_lookup_uses_current_default_network";

fn signed_value(identity: &NodeIdentity, addresses: Vec<Multiaddr>) -> Vec<u8> {
    let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
    peer_address_record::encode(NETWORK, None, identity, addresses, now).unwrap()
}

fn hint() -> Multiaddr {
    format!("/ip4/8.8.8.8/udp/4001/webrtc-direct/certhash/{CERT}")
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
fn signed_lookup_uses_current_default_network() {
    if !isolated_namespace(NAMESPACE_TEST) {
        return;
    }
    if std::env::var_os(SERVER_ENV).is_some() {
        serve_record();
        return;
    }
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
    server.0.stdin.take().unwrap().write_all(&[1]).unwrap();
    let line = await_output(&mut output, "browser-host-listening ");
    let (bootstrap, peer) = line.split_once(' ').unwrap();
    let peer: PeerId = peer.parse().unwrap();
    let request = || DiscoveryRequest {
        network_name: NETWORK,
        membership_tag: None,
        peer,
        protocol: StreamProtocol::new(DHT),
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

            ip(&["link", "set", "secondary", "up"]);
            ip(&["-6", "route", "add", "default", "dev", "secondary"]);
            assert_eq!(
                discover(request()).await.unwrap_err().kind(),
                io::ErrorKind::NetworkUnreachable
            );
            ip(&["-6", "route", "del", "default", "dev", "secondary"]);

            let routes = ControlRoutes::new(1);
            let scope = Scope::new(Arc::clone(&routes.egress)).unwrap();
            scope.link().await.unwrap();
            let result = while_current(&scope, async {
                ip(&["route", "replace", "default", "dev", "secondary"]);
                std::future::pending::<io::Result<()>>().await
            })
            .await;
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        });
}

fn serve_record() {
    println!("browser-host-namespace-ready");
    io::stdin().read_exact(&mut [0]).unwrap();
    ip(&["link", "set", "dev", "seed", "addrgenmode", "none"]);
    ip(&["addr", "add", "11.250.0.2/24", "dev", "seed"]);
    ip(&["link", "set", "seed", "up"]);
    ip(&["link", "set", "unused", "up"]);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let identity = NodeIdentity::generate_ed25519().unwrap();
            let peer: PeerId = identity.peer_id.parse().unwrap();
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
                            signed_value(&identity, vec![hint()]),
                        ))
                        .unwrap();
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
            while let Some(event) = swarm.next().await {
                if let SwarmEvent::NewListenAddr { address, .. } = event {
                    let bootstrap = address.with_p2p(*swarm.local_peer_id()).unwrap();
                    println!("browser-host-listening {bootstrap} {peer}");
                }
            }
        });
}
