use super::*;
use if_addrs::{Ifv4Addr, Ifv6Addr};
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
const IPV4_TEST: &str = "runtime::browser_lan::tests::isolated_interface_discovery";
const IPV6_TEST: &str = "runtime::browser_lan::tests::isolated_ipv6_interface_discovery";
const PARENT_NETNS: &str = "P2P_VPN_BROWSER_LAN_PARENT_NETNS";
const PEER_SIDE: &str = "P2P_VPN_BROWSER_LAN_PEER_SIDE";

fn webrtc(ip: &str, port: u16, peer: PeerId) -> Multiaddr {
    let family = if ip.contains(':') { "ip6" } else { "ip4" };
    format!("/{family}/{ip}/udp/{port}/webrtc-direct/certhash/{CERTHASH}/p2p/{peer}")
        .parse()
        .unwrap()
}

#[test]
fn only_the_requested_peers_web_rtc_direct_endpoints_on_the_selected_lan_are_hints() {
    let target = TARGET.parse().unwrap();
    let other = PeerId::random();
    let sources = [IfAddr::V4(Ifv4Addr {
        ip: "192.168.42.1".parse().unwrap(),
        netmask: "255.255.255.0".parse().unwrap(),
        prefixlen: 24,
        broadcast: None,
    })];
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
fn ipv6_hints_require_an_on_link_endpoint_that_does_not_need_a_zone() {
    let target = TARGET.parse().unwrap();
    let sources = ["fd42::1", "fe80::1"].map(|ip| {
        IfAddr::V6(Ifv6Addr {
            ip: ip.parse().unwrap(),
            netmask: "ffff:ffff:ffff:ffff::".parse().unwrap(),
            prefixlen: 64,
            broadcast: None,
        })
    });
    let valid = webrtc("fd42::2", 4001, target);
    assert_eq!(
        candidate(target, target, valid.clone(), &sources),
        Some(valid)
    );
    for ip in [
        "fd42::1",
        "fd43::2",
        "fe80::2",
        "ff02::fb",
        "::ffff:192.168.42.2",
    ] {
        assert_eq!(
            candidate(target, target, webrtc(ip, 4001, target), &sources),
            None
        );
    }
    let zoned = format!(
        "/ip6/fe80::2/ip6zone/under-a/udp/4001/webrtc-direct/certhash/{CERTHASH}/p2p/{target}"
    )
    .parse()
    .unwrap();
    assert_eq!(candidate(target, target, zoned, &sources), None);
}

#[test]
#[ignore = "uses isolated Linux user and network namespaces and iproute2"]
fn isolated_interface_discovery() {
    isolated_fixture(IPV4_TEST, false);
}

#[test]
#[ignore = "uses isolated Linux user and network namespaces, iproute2, and /dev/net/tun"]
fn isolated_ipv6_interface_discovery() {
    isolated_fixture(IPV6_TEST, true);
}

fn isolated_fixture(test: &str, ipv6: bool) {
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
            .args(["--exact", test, "--ignored", "--nocapture"])
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
        announce_from_peer(ipv6);
        return;
    }

    ip(&[
        "link", "add", "under-a", "type", "veth", "peer", "name", "peer-a",
    ]);
    let mut child = Command::new("unshare")
        .arg("--net")
        .arg(env::current_exe().unwrap())
        .args(["--exact", test, "--ignored", "--nocapture"])
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
    let (source, remote) = if ipv6 {
        configure_ipv6("under-a", "fd42::1/64");
        ip(&[
            "link",
            "add",
            "decoy",
            "type",
            "veth",
            "peer",
            "name",
            "decoy-peer",
        ]);
        ip(&["link", "set", "decoy-peer", "up"]);
        configure_ipv6("decoy", "fd42::1/64");
        ("fd42::1", "fd42::2")
    } else {
        configure_ipv4("under-a", "192.168.42.1/24");
        ("192.168.42.1", "192.168.42.2")
    };
    writeln!(child.stdin.take().unwrap(), "ready").unwrap();

    let target = TARGET.parse().unwrap();
    let expected = [webrtc(remote, 4001, target)];
    runtime().block_on(async {
        if ipv6 {
            // The native socket policy can use IPv6-only sources. Supply a
            // snapshot directly because LinuxDiscovery still selects via IPv4.
            let selected = publish_selection("under-a", source.parse().unwrap());
            assert_eq!(
                timeout(LOOKUP_BUDGET, lookup(target, selected.subscribe()))
                    .await
                    .unwrap()
                    .unwrap(),
                expected,
            );
            let decoy = publish_selection("decoy", source.parse().unwrap());
            assert!(
                timeout(LOOKUP_BUDGET, lookup(target, decoy.subscribe()))
                    .await
                    .is_err(),
                "the exact link must be honored even with a duplicate IPv6 source address",
            );
            ip(&["tuntap", "add", "dev", "tun-owned", "mode", "tun"]);
            ip(&[
                "link",
                "set",
                "dev",
                "tun-owned",
                "alias",
                "p2p-vpn:overlay:v1",
            ]);
            configure_ipv4("tun-owned", "10.42.0.1/24");
            assert!(
                discover(target, None).await.unwrap().is_empty(),
                "a VPN-owned IPv4 multicast route must not authorize the IPv6-only LAN",
            );
            // Give the unchanged Linux selector an IPv4 route. The peer and
            // its announcement remain IPv6-only.
            ip(&["route", "del", "224.0.0.251/32", "dev", "tun-owned"]);
            configure_ipv4("under-a", "192.168.42.1/24");
        }
        let result = tokio::spawn(discover(target, None)).await.unwrap().unwrap();
        assert_eq!(result, expected);
        assert!(discover(target, Some("under-a")).await.unwrap().is_empty());
    });
    child.kill().unwrap();
    child.wait().unwrap();
}

fn announce_from_peer(ipv6: bool) {
    println!("lan-peer-pid:{}", std::process::id());
    io::stdout().flush().unwrap();
    let mut line = String::new();
    io::stdin().read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "ready");
    let ip = if ipv6 {
        configure_ipv6("peer-a", "fd42::2/64");
        "fd42::2"
    } else {
        configure_ipv4("peer-a", "192.168.42.2/24");
        "192.168.42.2"
    };
    runtime().block_on(async {
        let target = TARGET.parse().unwrap();
        let address = webrtc(ip, 4001, target);
        let source = ip.parse().unwrap();
        let interface = if_addrs::get_if_addrs()
            .unwrap()
            .into_iter()
            .find(|entry| entry.name == "peer-a" && entry.ip() == source)
            .unwrap();
        let publisher = publish_selection("peer-a", source);
        let binding = Arc::new(LanBinding {
            generation: 1,
            index: interface.index.and_then(NonZeroU32::new).unwrap(),
            name: "peer-a".into(),
            selection: publisher.subscribe(),
        });
        let mut mdns = mdns_on_link(target, ipv6, &[interface.addr], &binding)
            .unwrap()
            .unwrap();
        mdns.on_swarm_event(FromSwarm::NewListenAddr(NewListenAddr {
            listener_id: ListenerId::next(),
            addr: &address,
        }));
        let _ = timeout(Duration::from_secs(16), async {
            loop {
                let _ = poll_fn(|cx| mdns.poll(cx)).await;
            }
        })
        .await;
    });
}

fn publish_selection(name: &str, source: IpAddr) -> PhysicalNetworkPublisher {
    let publisher = PhysicalNetworkPublisher::default();
    publisher
        .publish(PhysicalNetworkSnapshot {
            generation: 1,
            kind: PhysicalNetworkKind::Ethernet,
            interface_name: Some(name.into()),
            addresses: [source].into(),
            ..Default::default()
        })
        .unwrap();
    publisher
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn configure_ipv4(name: &str, address: &str) {
    ip(&["addr", "add", address, "dev", name]);
    ip(&["link", "set", name, "up"]);
    ip(&["route", "add", "224.0.0.251/32", "dev", name]);
}

fn configure_ipv6(name: &str, address: &str) {
    ip(&["link", "set", "dev", name, "addrgenmode", "none"]);
    ip(&["-6", "addr", "add", address, "dev", name, "nodad"]);
    ip(&["link", "set", name, "up"]);
}

fn ip(arguments: &[&str]) {
    let output = Command::new("ip").args(arguments).output().unwrap();
    assert!(
        output.status.success(),
        "ip {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr),
    );
}
