use super::*;
use libp2p::{
    core::transport::ListenerId,
    swarm::behaviour::{FromSwarm, NewListenAddr},
};
use std::{
    env, fs,
    io::{BufRead as _, BufReader, Write as _},
    process::{Command, Stdio},
};

use crate::runtime::physical_network::{PhysicalNetworkKind, PhysicalNetworkPublisher};

const TARGET: &str = "12D3KooWCupnXPCUzwXD2Dr6yJZKhRx26FAad5cWqUuk7A93RDsj";
const CERTHASH: &str = "uEiDgdEalG4A72M0SlnycaSlO8aFHumNZZsJDK6uy_kpUzQ";
const TEST: &str = "runtime::browser_lan::tests::isolated_interface_discovery";
const PARENT_NETNS: &str = "P2P_VPN_BROWSER_LAN_PARENT_NETNS";
const PEER_SIDE: &str = "P2P_VPN_BROWSER_LAN_PEER_SIDE";

fn webrtc(ip: &str, port: u16, peer: PeerId) -> Multiaddr {
    format!("/ip4/{ip}/udp/{port}/webrtc-direct/certhash/{CERTHASH}/p2p/{peer}")
        .parse()
        .unwrap()
}

#[test]
fn only_the_requested_peers_web_rtc_direct_endpoints_on_the_selected_lan_are_hints() {
    let target = TARGET.parse().unwrap();
    let other = PeerId::random();
    let sources = [Ifv4Addr {
        ip: "192.168.42.1".parse().unwrap(),
        netmask: "255.255.255.0".parse().unwrap(),
        prefixlen: 24,
        broadcast: None,
    }];
    let valid = webrtc("192.168.42.2", 4001, target);
    assert_eq!(
        candidate(target, target, valid.clone(), &sources),
        Some(valid.clone()),
    );
    assert_eq!(candidate(target, other, valid.clone(), &sources), None);
    for invalid in [
        webrtc("192.168.42.2", 4001, other),
        webrtc("192.168.42.2", 0, target),
        webrtc("192.168.42.1", 4001, target),
        webrtc("192.168.42.255", 4001, target),
        webrtc("8.8.8.8", 4001, target),
        valid.with(Protocol::P2pCircuit),
        format!("/ip4/192.168.42.2/tcp/4001/p2p/{target}")
            .parse()
            .unwrap(),
    ] {
        assert_eq!(candidate(target, target, invalid, &sources), None);
    }
}

#[test]
#[ignore = "uses isolated Linux user and network namespaces and iproute2"]
fn isolated_interface_discovery() {
    let own = fs::read_link("/proc/self/ns/net").unwrap();
    let Some(parent) = env::var_os(PARENT_NETNS) else {
        let output = Command::new("timeout")
            .args([
                "--signal=KILL",
                "20",
                "unshare",
                "--user",
                "--map-root-user",
                "--net",
            ])
            .arg(env::current_exe().unwrap())
            .args(["--exact", TEST, "--ignored", "--nocapture"])
            .env(PARENT_NETNS, own)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "LAN fixture failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    };
    assert_ne!(
        own.as_os_str(),
        parent,
        "refusing to change the parent network"
    );
    if env::var_os(PEER_SIDE).is_some() {
        announce_from_peer();
        return;
    }

    ip(&[
        "link", "add", "under-a", "type", "veth", "peer", "name", "peer-a",
    ]);
    let mut child = Command::new("unshare")
        .arg("--net")
        .arg(env::current_exe().unwrap())
        .args(["--exact", TEST, "--ignored", "--nocapture"])
        .env(PARENT_NETNS, own)
        .env(PEER_SIDE, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let pid = (&mut output)
        .lines()
        .map(Result::unwrap)
        .find_map(|line| line.strip_prefix("lan-peer-pid:")?.parse::<u32>().ok())
        .expect("isolated peer process");
    ip(&["link", "set", "peer-a", "netns", &pid.to_string()]);
    configure_interface("under-a", "192.168.42.1/24");
    writeln!(child.stdin.take().unwrap(), "ready").unwrap();

    let target = TARGET.parse().unwrap();
    runtime().block_on(async {
        let result = tokio::spawn(discover(target, None)).await.unwrap().unwrap();
        assert_eq!(result, [webrtc("192.168.42.2", 4001, target)]);
        assert!(discover(target, Some("under-a")).await.unwrap().is_empty());
    });
    child.kill().unwrap();
    child.wait().unwrap();
}

fn announce_from_peer() {
    println!("lan-peer-pid:{}", std::process::id());
    io::stdout().flush().unwrap();
    let mut line = String::new();
    io::stdin().read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "ready");
    configure_interface("peer-a", "192.168.42.2/24");
    runtime().block_on(async {
        let target = TARGET.parse().unwrap();
        let address = webrtc("192.168.42.2", 4001, target);
        let source = IpAddr::V4(Ipv4Addr::new(192, 168, 42, 2));
        let index = if_addrs::get_if_addrs()
            .unwrap()
            .into_iter()
            .find(|entry| entry.name == "peer-a" && entry.ip() == source)
            .and_then(|entry| entry.index)
            .and_then(NonZeroU32::new)
            .unwrap();
        let publisher = PhysicalNetworkPublisher::default();
        publisher
            .publish(PhysicalNetworkSnapshot {
                generation: 1,
                kind: PhysicalNetworkKind::Ethernet,
                interface_name: Some("peer-a".into()),
                addresses: [source].into(),
                ..Default::default()
            })
            .unwrap();
        let binding: Arc<dyn InterfaceSocketBinding> = Arc::new(LanBinding {
            generation: 1,
            index,
            name: "peer-a".into(),
            selection: publisher.subscribe(),
        });
        let mut mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), target).unwrap();
        mdns.set_allowed_interfaces(Some(HashSet::new()));
        mdns.set_interface_bindings(Some([(source, binding)].into()));
        mdns.set_allowed_interfaces(Some([source].into()));
        mdns.on_swarm_event(FromSwarm::NewListenAddr(NewListenAddr {
            listener_id: ListenerId::next(),
            addr: &address,
        }));
        let _ = timeout(Duration::from_secs(12), async {
            loop {
                let _ = poll_fn(|cx| mdns.poll(cx)).await;
            }
        })
        .await;
    });
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn configure_interface(name: &str, address: &str) {
    ip(&["addr", "add", address, "dev", name]);
    ip(&["link", "set", name, "up"]);
    ip(&["route", "add", "224.0.0.251/32", "dev", name]);
}

fn ip(arguments: &[&str]) {
    let output = Command::new("ip").args(arguments).output().unwrap();
    assert!(
        output.status.success(),
        "ip {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr),
    );
}
