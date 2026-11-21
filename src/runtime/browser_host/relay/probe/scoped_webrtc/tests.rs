use std::{
    io::{BufRead as _, BufReader, Write as _},
    process::{Child, Command, Stdio},
};

use libp2p::{
    SwarmBuilder, noise, relay,
    swarm::{NetworkBehaviour, behaviour::toggle::Toggle},
    tcp, yamux,
};

use super::super::{identify_relay, native_contact};
use super::*;
use crate::runtime::{
    browser_host::{relay::LeaseManager, with_default_path},
    physical_network::linux::{isolated_namespace, test_ip as ip},
};

const FIXTURE: &str = "runtime::browser_host::relay::probe::scoped_webrtc::tests::identify_candidate_requires_scoped_webrtc_proof";
const SERVER: &str = "P2P_VPN_SCOPED_WEBRTC_PROOF_SERVER";
const TCP_HOST: &str = "11.253.0.2";

#[tokio::test]
#[ignore = "live public WebRTC/HOP check; requires P2P_VPN_LIVE_WEBRTC_RELAY"]
async fn live_public_webrtc_relay_uses_default_network() {
    let Ok(address) = std::env::var("P2P_VPN_LIVE_WEBRTC_RELAY") else {
        eprintln!("set P2P_VPN_LIVE_WEBRTC_RELAY to run the live public relay check");
        return;
    };
    let entrance: Multiaddr = address.parse().expect("relay multiaddr");
    let relay = peer(&entrance);
    assert!(
        public_discovery_transport_is_publicly_dialable(&entrance),
        "expected a public relay address"
    );
    with_default_path(None, Duration::from_secs(12), |path| async move {
        let _verified = authenticate(path.scope, relay, &entrance).await?;
        Ok(())
    })
    .await
    .expect("authenticated WebRTC Direct connection and HOP negotiation");
}

struct SeedProcess(Child);

impl Drop for SeedProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "requires isolated Linux user/network namespaces and iproute2"]
fn identify_candidate_requires_scoped_webrtc_proof() {
    if !isolated_namespace(FIXTURE) {
        return;
    }
    if std::env::var_os(SERVER).is_some() {
        serve();
        return;
    }
    let mut server = SeedProcess(
        Command::new("unshare")
            .arg("--net")
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", FIXTURE, "--ignored", "--nocapture"])
            .env(SERVER, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut lines = BufReader::new(server.0.stdout.take().unwrap())
        .lines()
        .map(Result::unwrap);
    assert!(lines.by_ref().any(|line| line == "scoped-webrtc-ready"));
    let pid = server.0.id().to_string();
    ip(&["link", "set", "lo", "up"]);
    ip(&[
        "link", "add", "physical", "type", "veth", "peer", "name", "seed", "netns", &pid,
    ]);
    ip(&["link", "add", "secondary", "type", "dummy"]);
    for (link, address) in [
        ("physical", "11.253.0.1/24"),
        ("secondary", "11.254.0.1/24"),
    ] {
        ip(&["link", "set", link, "addrgenmode", "none"]);
        ip(&["addr", "add", address, "dev", link]);
        ip(&["link", "set", link, "up"]);
    }
    ip(&["route", "add", "default", "dev", "physical"]);
    writeln!(server.0.stdin.take().unwrap(), "ready").unwrap();
    let routes = lines
        .find_map(|line| {
            line.strip_prefix("scoped-webrtc-listeners ")
                .map(str::to_owned)
        })
        .expect("fixture did not listen");
    let [native, webrtc, other_native, other_webrtc]: [Multiaddr; 4] = routes
        .split_whitespace()
        .map(|route| route.parse().unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(exercise(native, webrtc, other_native, other_webrtc));
}

async fn exercise(
    native: Multiaddr,
    webrtc: Multiaddr,
    other_native: Multiaddr,
    other_webrtc: Multiaddr,
) {
    let relay = peer(&native);
    let other = peer(&other_native);
    let native = native_contact(relay, native).unwrap();
    let manager = LeaseManager::new();
    let (lease, staged, original_scope) =
        with_default_path(None, Duration::from_secs(18), |path| {
            let native = &native;
            let manager = &manager;
            async move {
                let suggested = identify_relay(&path, relay, vec![native.clone()], None).await?;
                assert_eq!(suggested, webrtc);

                let wrong_hash = other_webrtc
                    .iter()
                    .find(|part| matches!(part, Protocol::Certhash(_)))
                    .unwrap();
                let wrong_cert = suggested
                    .iter()
                    .map(|part| match part {
                        Protocol::Certhash(_) => wrong_hash.clone(),
                        _ => part,
                    })
                    .collect();
                let mut wrong_peer = other_webrtc.clone();
                wrong_peer.pop();
                wrong_peer.push(Protocol::P2p(relay));
                let error = authenticate(path.scope.clone(), relay, &wrong_peer)
                    .await
                    .err()
                    .expect("wrong peer");
                assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
                assert!(
                    authenticate(path.scope.clone(), relay, &wrong_cert)
                        .await
                        .is_err(),
                    "certificate mismatch"
                );
                assert!(
                    identify_relay(&path, other, vec![other_native], None)
                        .await
                        .is_err(),
                    "native role check"
                );
                let error = authenticate(path.scope.clone(), other, &other_webrtc)
                    .await
                    .err()
                    .expect("WebRTC HOP negotiation");
                assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{error}");

                let proof = authenticate(path.scope.clone(), relay, &suggested).await?;
                // The stopped probe sockets still hold both ports, so the kernel
                // cannot allocate either tuple to the fresh browser lease.
                let prepared = manager
                    .prepare_inviter(path.scope.clone(), &suggested, manager.reserve()?)
                    .await?;
                let probe_address = proof._ingress.address.to_string();
                let staged = manager
                    .prepare_inviter(path.scope.clone(), &suggested, manager.reserve()?)
                    .await?;
                drop(proof);
                let lease = prepared.publish()?;
                assert_ne!(lease.relay_address, probe_address);
                Ok((lease, staged, path.scope))
            }
        })
        .await
        .expect("verified default-path WebRTC relay");

    ip(&["route", "replace", "default", "dev", "secondary"]);
    tokio::time::timeout(Duration::from_secs(2), original_scope.invalidated())
        .await
        .unwrap();
    let error = staged
        .publish()
        .err()
        .expect("stale lease must not publish");
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    let result = with_default_path(None, Duration::from_secs(2), |path| async move {
        identify_relay(&path, relay, vec![native], None).await
    })
    .await;
    assert!(
        result.is_err(),
        "no fallback to the connected secondary path"
    );
    assert!(manager.release(&lease.relay_lease_id).unwrap());
}

fn peer(address: &Multiaddr) -> PeerId {
    let Some(Protocol::P2p(peer)) = address.iter().last() else {
        panic!("fixture address is not pinned");
    };
    peer
}

#[derive(NetworkBehaviour)]
struct Server {
    identify: identify::Behaviour,
    relay: Toggle<relay::Behaviour>,
}

async fn listen(hop: bool) -> (Swarm<Server>, Multiaddr, Multiaddr) {
    let keys = Keypair::generate_ed25519();
    let local = keys.public().to_peer_id();
    let cert = Certificate::generate(&mut rand_core::OsRng).unwrap();
    let mut swarm = SwarmBuilder::with_existing_identity(keys)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_other_transport(|keys| Transport::new(keys.clone(), cert))
        .unwrap()
        .with_behaviour(|keys| Server {
            identify: identify::Behaviour::new(identify::Config::new(
                "/scoped-webrtc-proof/1".into(),
                keys.public(),
            )),
            relay: hop
                .then(|| relay::Behaviour::new(local, relay::Config::default()))
                .into(),
        })
        .unwrap()
        .build();
    let tcp = swarm
        .listen_on(format!("/ip4/{TCP_HOST}/tcp/0").parse().unwrap())
        .unwrap();
    let rtc = swarm
        .listen_on(
            format!("/ip4/{TCP_HOST}/udp/0/webrtc-direct")
                .parse()
                .unwrap(),
        )
        .unwrap();
    let (mut a, mut b) = (None, None);
    while a.is_none() || b.is_none() {
        if let SwarmEvent::NewListenAddr {
            listener_id,
            address,
        } = swarm.select_next_some().await
        {
            let address = address.with_p2p(local).unwrap();
            swarm.add_external_address(address.clone());
            if listener_id == tcp {
                a = Some(address);
            } else if listener_id == rtc {
                b = Some(address);
            }
        }
    }
    (swarm, a.unwrap(), b.unwrap())
}

fn serve() {
    println!("scoped-webrtc-ready");
    let mut ready = String::new();
    std::io::stdin().read_line(&mut ready).unwrap();
    ip(&["link", "set", "lo", "up"]);
    ip(&["link", "set", "seed", "addrgenmode", "none"]);
    ip(&["addr", "add", "11.253.0.2/24", "dev", "seed"]);
    ip(&["link", "set", "seed", "up"]);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let (mut relay, native, webrtc) = listen(true).await;
            let (mut other, other_native, other_webrtc) = listen(false).await;
            println!("scoped-webrtc-listeners {native} {webrtc} {other_native} {other_webrtc}");
            loop {
                tokio::select! {
                    _ = relay.select_next_some() => {}
                    _ = other.select_next_some() => {}
                }
            }
        });
}
