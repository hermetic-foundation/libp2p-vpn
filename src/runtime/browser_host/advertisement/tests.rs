use std::{
    io::{BufRead as _, BufReader, Read as _, Write as _},
    process::{Child, Command, Stdio},
};

use libp2p::{SwarmBuilder, identity::Keypair, noise, tcp, yamux};

use crate::{
    identity::NodeIdentity,
    peer_address_record,
    runtime::physical_network::linux::{isolated_namespace, test_ip as ip},
};

use super::{
    super::{DiscoveryRequest, lookup},
    *,
};

const DHT: &str = "/browser-advertisement-test/kad/1";
const NAMESPACE_TEST: &str = "runtime::browser_host::advertisement::tests::publishes_and_reads_back_on_default_physical_network";
const SERVER_ENV: &str = "P2P_VPN_BROWSER_ADVERTISEMENT_TEST_SERVER";

fn permit(identity: &NodeIdentity) -> Permit {
    Permit {
        network_name: "lab".into(),
        membership_tag: Some("current".into()),
        protocol: StreamProtocol::new(DHT),
        browser_peer: identity.peer_id.parse().unwrap(),
        destination: PeerId::random(),
        address: format!(
            "/ip4/11.253.0.2/tcp/4001/p2p/{}/p2p-circuit/p2p/{}",
            PeerId::random(),
            identity.peer_id,
        )
        .parse()
        .unwrap(),
    }
}

fn sign(challenge: &Challenge, browser: &NodeIdentity) -> String {
    Submission::sign(challenge, browser, unix_seconds().unwrap()).unwrap()
}

#[tokio::test]
async fn publication_is_opt_in_rate_limited_and_not_replayable() {
    let browser = NodeIdentity::generate_ed25519().unwrap();
    let permit = permit(&browser);
    let publisher = Publisher::new(None).unwrap();
    assert_eq!(
        publisher.challenge().unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        publisher
            .publish(b"{}", &[], None)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied,
    );
    publisher.replace_permit(Some(permit.clone())).unwrap();
    let body = sign(&publisher.challenge().unwrap(), &browser);
    assert_eq!(
        publisher.challenge().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    // Correct evidence reaches transport setup; this private DHT has no seeds.
    assert_eq!(
        publisher
            .publish(body.as_bytes(), &[], None)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput,
    );
    assert_eq!(
        publisher
            .publish(body.as_bytes(), &[], None)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied,
    );

    let publisher = Publisher::new(Some(permit.clone())).unwrap();
    let body = sign(&publisher.challenge().unwrap(), &browser);
    publisher
        .replace_permit(Some(Permit {
            membership_tag: None,
            ..permit.clone()
        }))
        .unwrap();
    assert_eq!(
        publisher
            .publish(body.as_bytes(), &[], None)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied,
    );
    assert_eq!(
        Publisher::new(Some(Permit {
            protocol: StreamProtocol::new(PUBLIC_IPFS_KADEMLIA_PROTOCOL),
            ..permit
        }))
        .err()
        .unwrap()
        .kind(),
        io::ErrorKind::Unsupported,
    );
}

struct TestServer(Child);

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "requires isolated Linux network namespaces and iproute2; no Internet"]
fn publishes_and_reads_back_on_default_physical_network() {
    if !isolated_namespace(NAMESPACE_TEST) {
        return;
    }
    if std::env::var_os(SERVER_ENV).is_some() {
        serve_dht();
        return;
    }
    let mut server = TestServer(
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
    let mut lines = BufReader::new(server.0.stdout.take().unwrap()).lines();
    assert!(
        lines
            .by_ref()
            .map(Result::unwrap)
            .any(|line| line == "advertisement-test-ready")
    );
    let pid = server.0.id().to_string();
    ip(&[
        "link", "add", "physical", "type", "veth", "peer", "name", "seed", "netns", &pid,
    ]);
    ip(&["addr", "add", "11.253.0.1/24", "dev", "physical"]);
    ip(&["link", "set", "physical", "up"]);
    server.0.stdin.take().unwrap().write_all(&[1]).unwrap();
    let seed = lines
        .by_ref()
        .map(Result::unwrap)
        .find_map(|line| {
            line.strip_prefix("advertisement-test-seed ")
                .map(str::to_owned)
        })
        .unwrap()
        .parse::<Multiaddr>()
        .unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let browser = NodeIdentity::generate_ed25519().unwrap();
            let permit = permit(&browser);
            let seeds = [seed];
            let publisher = Publisher::new(Some(permit.clone())).unwrap();
            let body = sign(&publisher.challenge().unwrap(), &browser);
            assert_eq!(
                publisher
                    .publish(body.as_bytes(), &seeds, None)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::NetworkUnreachable,
                "a reachable seed is insufficient without an OS default",
            );
            ip(&["route", "add", "default", "dev", "physical"]);
            let publisher = Publisher::new(Some(permit.clone())).unwrap();
            let body = sign(&publisher.challenge().unwrap(), &browser);
            publisher
                .publish(body.as_bytes(), &seeds, None)
                .await
                .unwrap();

            let request = DiscoveryRequest {
                network_name: &permit.network_name,
                membership_tag: permit.membership_tag.as_deref(),
                peer: permit.browser_peer,
                protocol: permit.protocol.clone(),
                owned_interface: None,
                bootstrap: seeds.to_vec(),
            };
            let (owner, addresses) = with_default_dht(&permit.protocol, &seeds, None, |swarm| {
                lookup(&request, swarm, |value| {
                    peer_address_record::decode(
                        request.network_name,
                        request.membership_tag,
                        &[],
                        value,
                        || unix_seconds().unwrap(),
                        |peer| peer == permit.browser_peer,
                    )
                    .ok()
                })
            })
            .await
            .unwrap();
            assert_eq!(owner, permit.browser_peer);
            assert_eq!(addresses, [permit.address]);
        });
}

fn serve_dht() {
    println!("advertisement-test-ready");
    std::io::stdin().read_exact(&mut [0]).unwrap();
    ip(&["addr", "add", "11.253.0.2/24", "dev", "seed"]);
    ip(&["link", "set", "seed", "up"]);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let keys = Keypair::generate_ed25519();
            let peer = keys.public().to_peer_id();
            let mut swarm = SwarmBuilder::with_existing_identity(keys)
                .with_tokio()
                .with_tcp(
                    tcp::Config::default(),
                    noise::Config::new,
                    yamux::Config::default,
                )
                .unwrap()
                .with_behaviour(|_| {
                    let mut kad = kad::Behaviour::with_config(
                        peer,
                        kad::store::MemoryStore::new(peer),
                        kad::Config::new(StreamProtocol::new(DHT)),
                    );
                    kad.set_mode(Some(kad::Mode::Server));
                    kad
                })
                .unwrap()
                .build();
            swarm
                .listen_on("/ip4/11.253.0.2/tcp/0".parse().unwrap())
                .unwrap();
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                    println!("advertisement-test-seed {address}/p2p/{peer}");
                }
            }
        });
}
