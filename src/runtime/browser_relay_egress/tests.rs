use super::*;
use crate::runtime::physical_network::linux::{
    egress::LinuxEgress, isolated_namespace, test_ip as ip,
};
use libp2p::{PeerId, multihash::Multihash};
use socket2::{Domain, Socket, Type};
use std::{
    env, fs,
    io::{BufRead, BufReader, Write},
    net::{IpAddr, Ipv6Addr},
    process::{Child, Command, Stdio},
    sync::Arc,
};
use tokio::time::timeout;

const TEST: &str = "runtime::browser_relay_egress::tests::pinned_egress_stops_at_generation_change_without_crossing_routes";
const RECEIVER_PARENT_NS: &str = "P2P_VPN_BROWSER_RELAY_RECEIVER_PARENT_NS";
const RELAY_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 77);
const WAIT: Duration = Duration::from_secs(2);
const QUIET: Duration = Duration::from_millis(100);

fn route(destination: SocketAddr) -> Multiaddr {
    let ip = match destination.ip() {
        IpAddr::V4(ip) => Protocol::Ip4(ip),
        IpAddr::V6(ip) => Protocol::Ip6(ip),
    };
    Multiaddr::empty()
        .with(ip)
        .with(Protocol::Udp(destination.port()))
        .with(Protocol::WebRTCDirect)
        .with(Protocol::Certhash(
            Multihash::wrap(0x12, &[42; 32]).unwrap(),
        ))
        .with(Protocol::P2p(PeerId::random()))
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(PeerId::random()))
}

#[test]
fn only_numeric_different_peers_and_sha256_circuit_pins_are_accepted() {
    for address in [
        "203.0.113.77:4389".parse::<SocketAddr>().unwrap(),
        "[2001:db8::77]:4389".parse().unwrap(),
    ] {
        let route = route(address);
        let (target, suffix) = pinned_relay(&route).unwrap();
        assert_eq!(target, address);
        assert!(suffix.iter().eq(route.iter().skip(2)));
        let mut unpinned = route.clone();
        unpinned.pop();
        assert!(pinned_relay(&unpinned).is_err());
        assert!(pinned_relay(&route.clone().with(Protocol::P2pCircuit)).is_err());
        let mut same_peer = unpinned;
        let relay = route.iter().nth(4).unwrap().acquire();
        same_peer.push(relay);
        assert!(pinned_relay(&same_peer).is_err());
        let wrong_hash: Multiaddr = route
            .iter()
            .enumerate()
            .map(|(i, part)| match i {
                3 => Protocol::Certhash(Multihash::wrap(0x13, &[42; 32]).unwrap()),
                _ => part,
            })
            .collect();
        assert!(pinned_relay(&wrong_hash).is_err());
        let dns: Multiaddr = std::iter::once(Protocol::Dns("relay.example".into()))
            .chain(route.iter().skip(1))
            .collect();
        assert!(pinned_relay(&dns).is_err());
    }
    for address in [
        (Ipv4Addr::LOCALHOST, 4389).into(),
        (Ipv4Addr::UNSPECIFIED, 4389).into(),
        (Ipv4Addr::BROADCAST, 4389).into(),
        (Ipv6Addr::LOCALHOST, 4389).into(),
        (RELAY_IP, 0).into(),
    ] {
        assert!(pinned_relay(&route(address)).is_err(), "{address}");
    }
}

#[test]
#[ignore = "requires isolated Linux user/network namespaces, unshare and iproute2; no Internet traffic"]
fn pinned_egress_stops_at_generation_change_without_crossing_routes() {
    if let Some(parent) = env::var_os(RECEIVER_PARENT_NS) {
        assert_ne!(
            fs::read_link("/proc/self/ns/net").unwrap().as_os_str(),
            parent
        );
        receiver();
        return;
    }
    if !isolated_namespace(TEST) {
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    let (_receiver, port) = RelayReceiver::start();
    ip(&[
        "route",
        "add",
        "default",
        "via",
        "10.187.1.2",
        "dev",
        "under-a",
        "metric",
        "100",
    ]);
    ip(&[
        "route",
        "add",
        "default",
        "via",
        "10.187.2.2",
        "dev",
        "under-b",
        "metric",
        "200",
    ]);
    runtime().block_on(async {
        let owner = Arc::new(LinuxEgress::for_control());
        let original = route((RELAY_IP, port).into());
        let scope = Scope::new(Arc::clone(&owner)).unwrap();
        let (candidate, pump) = prepare(scope.clone(), &original).await.unwrap();
        let loopback = local_candidate(&candidate, &original);
        let old = tokio::spawn(pump);
        let browser = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let other = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();

        exchange(&browser, loopback, b"opaque-first", b"Aopaque-first").await;
        other.send_to(b"not-owned", loopback).await.unwrap();
        browser
            .send_to(&[7; MAX_DATAGRAM + 32], loopback)
            .await
            .unwrap();
        no_reply(&browser).await;
        no_reply(&other).await;
        // A valid-size request asking the fixture to send a too-large reply.
        browser.send_to(b"oversized-reply", loopback).await.unwrap();
        no_reply(&browser).await;
        exchange(
            &browser,
            loopback,
            b"opaque-after-drops",
            b"Aopaque-after-drops",
        )
        .await;

        ip(&[
            "route",
            "del",
            "default",
            "via",
            "10.187.1.2",
            "dev",
            "under-a",
            "metric",
            "100",
        ]);
        let error = timeout(WAIT, old).await.unwrap().unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(!scope.is_current());
        assert!(prepare(scope, &original).await.is_err());
        let retired_port = UdpSocket::bind(loopback).await.unwrap();
        browser.send_to(b"old-port", loopback).await.unwrap();
        no_reply(&browser).await;
        // Keep the retired port bound so a fresh operation cannot reuse it.

        let (candidate, pump) = prepare(Scope::new(Arc::clone(&owner)).unwrap(), &original)
            .await
            .unwrap();
        let fresh = local_candidate(&candidate, &original);
        let task = tokio::spawn(pump);
        exchange(&browser, fresh, b"opaque-fresh", b"Bopaque-fresh").await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(UdpSocket::bind(fresh).await.is_ok());
        exercise_time_bounds(&owner, &original, &browser).await;
        drop(retired_port);
    });
}

async fn exercise_time_bounds(owner: &Arc<LinuxEgress>, original: &Multiaddr, browser: &UdpSocket) {
    let open = |idle, lifetime| {
        prepare_with_limits(
            Scope::new(Arc::clone(owner)).unwrap(),
            original,
            Limits { idle, lifetime },
        )
    };
    let (_, pump) = open(Duration::from_millis(50), WAIT).await.unwrap();
    let idle = timeout(WAIT, pump).await.unwrap().unwrap_err();
    assert_eq!(idle.kind(), io::ErrorKind::TimedOut);
    assert!(idle.to_string().contains("idle"));

    let (candidate, pump) = open(Duration::from_millis(200), Duration::from_millis(500))
        .await
        .unwrap();
    let target = local_candidate(&candidate, original);
    let life = timeout(WAIT, async {
        tokio::select! {
            result = pump => result,
            () = async {
                loop {
                    exchange(browser, target, b"ongoing", b"Bongoing").await;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            } => unreachable!(),
        }
    })
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(life.kind(), io::ErrorKind::TimedOut);
    assert!(life.to_string().contains("lifetime"));
}

fn local_candidate(candidate: &Multiaddr, original: &Multiaddr) -> SocketAddr {
    let mut parts = candidate.iter();
    assert_eq!(parts.next(), Some(Protocol::Ip4(Ipv4Addr::LOCALHOST)));
    let Some(Protocol::Udp(port)) = parts.next() else {
        panic!("not UDP")
    };
    assert_ne!(port, 0);
    assert!(
        parts.eq(original.iter().skip(2)),
        "pin or circuit suffix changed"
    );
    (Ipv4Addr::LOCALHOST, port).into()
}

async fn exchange(socket: &UdpSocket, candidate: SocketAddr, sent: &[u8], expected: &[u8]) {
    socket.send_to(sent, candidate).await.unwrap();
    let mut data = [0; MAX_DATAGRAM + 1];
    let (len, from) = timeout(WAIT, socket.recv_from(&mut data))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, candidate);
    assert_eq!(&data[..len], expected);
}

async fn no_reply(socket: &UdpSocket) {
    let mut data = [0; MAX_DATAGRAM + 1];
    assert!(timeout(QUIET, socket.recv_from(&mut data)).await.is_err());
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

struct RelayReceiver(Child);

impl RelayReceiver {
    fn start() -> (Self, u16) {
        let ns = fs::read_link("/proc/self/ns/net").unwrap();
        let child = Command::new("unshare")
            .args(["--net"])
            .arg(env::current_exe().unwrap())
            .args(["--exact", TEST, "--ignored", "--nocapture"])
            .env(RECEIVER_PARENT_NS, ns)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut child = Self(child);
        let mut stdout = BufReader::new(child.0.stdout.take().unwrap());
        announcement(&mut stdout, "receiver-netns-ready");
        let pid = child.0.id().to_string();
        for (local, remote, address) in [
            ("under-a", "relay-a", "10.187.1.1/24"),
            ("under-b", "relay-b", "10.187.2.1/24"),
        ] {
            ip(&["link", "add", local, "type", "veth", "peer", "name", remote]);
            ip(&["link", "set", remote, "netns", &pid]);
            ip(&["link", "set", "dev", local, "addrgenmode", "none"]);
            ip(&["addr", "add", address, "dev", local]);
            ip(&["link", "set", local, "up"]);
        }
        child.0.stdin.take().unwrap().write_all(b"go\n").unwrap();
        let port = announcement(&mut stdout, "relay-port=").parse().unwrap();
        (child, port)
    }
}

impl Drop for RelayReceiver {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn announcement(output: &mut impl BufRead, prefix: &str) -> String {
    let mut line = String::new();
    loop {
        assert_ne!(
            output.read_line(&mut line).unwrap(),
            0,
            "receiver failed before {prefix}"
        );
        if let Some((_, value)) = line.split_once(prefix) {
            return value.trim().to_owned();
        }
        line.clear();
    }
}

fn receiver() {
    println!("receiver-netns-ready");
    let mut start = String::new();
    io::stdin().read_line(&mut start).unwrap();
    assert_eq!(start, "go\n");
    ip(&["link", "set", "lo", "up"]);
    ip(&["addr", "add", "203.0.113.77/32", "dev", "lo"]);
    for (interface, address) in [("relay-a", "10.187.1.2/24"), ("relay-b", "10.187.2.2/24")] {
        ip(&["link", "set", "dev", interface, "addrgenmode", "none"]);
        ip(&["addr", "add", address, "dev", interface]);
        ip(&["link", "set", interface, "up"]);
    }
    runtime().block_on(async {
        let a = receiver_socket(b"relay-a", 0);
        let port = a.local_addr().unwrap().port();
        let b = receiver_socket(b"relay-b", port);
        println!("relay-port={port}");
        let mut a_buf = [0; 4096];
        let mut b_buf = [0; 4096];
        loop {
            let (socket, label, data, from) = tokio::select! {
                result = a.recv_from(&mut a_buf) => {
                    let (len, from) = result.unwrap();
                    (&a, b'A', &a_buf[..len], from)
                }
                result = b.recv_from(&mut b_buf) => {
                    let (len, from) = result.unwrap();
                    (&b, b'B', &b_buf[..len], from)
                }
            };
            assert_eq!(
                from.ip().to_string(),
                if label == b'A' {
                    "10.187.1.1"
                } else {
                    "10.187.2.1"
                }
            );
            if data == b"oversized-reply" {
                socket.send_to(&[9; MAX_DATAGRAM + 32], from).await.unwrap();
            } else {
                let response: Vec<_> = std::iter::once(label).chain(data.iter().copied()).collect();
                socket.send_to(&response, from).await.unwrap();
            }
        }
    });
}

fn receiver_socket(interface: &[u8], port: u16) -> UdpSocket {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(socket2::Protocol::UDP)).unwrap();
    socket.set_reuse_address(true).unwrap();
    socket.bind_device(Some(interface)).unwrap();
    socket
        .bind(&SockAddr::from(SocketAddr::from((RELAY_IP, port))))
        .unwrap();
    socket.set_nonblocking(true).unwrap();
    UdpSocket::from_std(socket.into()).unwrap()
}
