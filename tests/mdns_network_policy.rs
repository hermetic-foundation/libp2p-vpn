//! Real multicast on isolated links; mock binding is not Android netd evidence.
#![cfg(target_os = "linux")]

use futures::StreamExt;
use libp2p::{PeerId, Swarm, SwarmBuilder, mdns, noise, swarm::SwarmEvent, tcp, yamux};
use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, UdpSocket},
    num::NonZeroU32,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

#[derive(Debug)]
struct Binding {
    id: u64,
    index: NonZeroU32,
    current: AtomicBool,
    calls: AtomicUsize,
    preparations: AtomicUsize,
}

impl mdns::InterfaceSocketBinding for Binding {
    fn identity(&self) -> [u64; 3] {
        [self.id, 1, 1]
    }
    fn interface_index(&self) -> NonZeroU32 {
        self.index
    }
    fn is_current(&self) -> bool {
        self.current.load(Ordering::Acquire)
    }
    fn bind(&self, socket: &UdpSocket) -> io::Result<()> {
        assert_eq!(
            socket.local_addr()?.port(),
            0,
            "ownership precedes address binding"
        );
        self.calls.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
    fn prepare_sockets(self: Arc<Self>, source: IpAddr) -> mdns::SocketPreparation {
        Box::pin(async move {
            if self.preparations.fetch_add(1, Ordering::AcqRel) == 0 {
                // A callback model, not a failed/injected socket syscall.
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let socket = || {
                socket2::Socket::new(
                    if source.is_ipv4() {
                        socket2::Domain::IPV4
                    } else {
                        socket2::Domain::IPV6
                    },
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::UDP),
                )
                .map(UdpSocket::from)
            };
            let recv = socket()?;
            let send = socket()?;
            self.bind(&recv)?;
            self.bind(&send)?;
            Ok((recv, send))
        })
    }
}

fn ip(args: &[&str]) -> String {
    let output = Command::new("ip").args(args).output().unwrap();
    assert!(
        output.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn index(name: &str) -> NonZeroU32 {
    let links: Vec<serde_json::Value> =
        serde_json::from_str(&ip(&["-j", "link", "show", "dev", name])).unwrap();
    NonZeroU32::new(links[0]["ifindex"].as_u64().unwrap().try_into().unwrap()).unwrap()
}

fn binding(id: u64, index: NonZeroU32) -> Arc<Binding> {
    Arc::new(Binding {
        id,
        index,
        current: AtomicBool::new(true),
        calls: AtomicUsize::new(0),
        preparations: AtomicUsize::new(0),
    })
}

fn policy(node: &mut Swarm<mdns::tokio::Behaviour>, source: IpAddr, owner: &Arc<Binding>) {
    let bindings: HashMap<_, Arc<dyn mdns::InterfaceSocketBinding>> = [(
        source,
        owner.clone() as Arc<dyn mdns::InterfaceSocketBinding>,
    )]
    .into();
    node.behaviour_mut()
        .set_allowed_interfaces(Some(HashSet::new()));
    node.behaviour_mut().set_interface_bindings(Some(bindings));
    node.behaviour_mut()
        .set_allowed_interfaces(Some([source].into()));
}

fn node(source: IpAddr, owner: &Arc<Binding>) -> Swarm<mdns::tokio::Behaviour> {
    let ipv6 = source.is_ipv6();
    let mut node = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|key: &libp2p::identity::Keypair| {
            mdns::tokio::Behaviour::new(
                mdns::Config {
                    enable_ipv6: ipv6,
                    query_interval: Duration::from_secs(1),
                    ..mdns::Config::default()
                },
                key.public().to_peer_id(),
            )
            .unwrap()
        })
        .unwrap()
        .build();
    policy(&mut node, source, owner);
    let family = if ipv6 { "ip6" } else { "ip4" };
    node.listen_on(format!("/{family}/{source}/tcp/0").parse().unwrap())
        .unwrap();
    node
}

fn discovered(event: SwarmEvent<mdns::Event>, expected: PeerId, forbidden: PeerId) -> bool {
    if let SwarmEvent::Behaviour(mdns::Event::Discovered(peers)) = event {
        assert!(
            !peers.iter().any(|(peer, _)| *peer == forbidden),
            "discovery crossed an unselected link"
        );
        peers.iter().any(|(peer, _)| *peer == expected)
    } else {
        false
    }
}

async fn expect_links(
    a: &mut Swarm<mdns::tokio::Behaviour>,
    b: &mut Swarm<mdns::tokio::Behaviour>,
    c: &mut Swarm<mdns::tokio::Behaviour>,
    selected: bool,
) {
    let [a_peer, b_peer, c_peer] = [*a.local_peer_id(), *b.local_peer_id(), *c.local_peer_id()];
    let mut seen = [false; 2];
    let deadline = tokio::time::sleep(Duration::from_secs(8));
    tokio::pin!(deadline);
    let mut quiet_until = None;
    loop {
        tokio::select! {
            () = &mut deadline => panic!("selected multicast peers did not discover each other: {seen:?}"),
            event = a.select_next_some() => { seen[0] |= discovered(event, if selected { b_peer } else { c_peer }, if selected { c_peer } else { b_peer }); }
            event = b.select_next_some() => { let found = discovered(event, a_peer, c_peer); if selected { seen[1] |= found; } }
            event = c.select_next_some() => { let found = discovered(event, a_peer, b_peer); if !selected { seen[1] |= found; } }
            () = async { tokio::time::sleep_until(quiet_until.unwrap()).await }, if quiet_until.is_some() => break,
        }
        if seen == [true, true] && quiet_until.is_none() {
            quiet_until = Some(tokio::time::Instant::now() + Duration::from_secs(2));
        }
    }
}

fn namespace(test: &str) -> bool {
    const OWNER: &str = "P2P_VPN_MDNS_NETWORK_POLICY_PARENT";
    let own = std::fs::read_link("/proc/self/ns/net").unwrap();
    if let Some(parent) = std::env::var_os(OWNER) {
        assert_ne!(own.as_os_str(), parent, "refusing host network mutation");
        return true;
    }
    let output = Command::new("timeout")
        .args([
            "--signal=KILL",
            "40",
            "unshare",
            "--user",
            "--map-root-user",
            "--net",
        ])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", test, "--ignored", "--nocapture"])
        .env(OWNER, own.as_os_str())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "namespace failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    false
}

fn run(test: &str, ipv6: bool) {
    if !namespace(test) {
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    let sources = if ipv6 {
        ["fd00::1", "fd00::2", "fd00::3"]
    } else {
        ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    };
    let prefix = if ipv6 { 64 } else { 24 };
    // The duplicate source exists first on the decoy link. IP-only selection
    // cannot establish which multicast link the caller actually owns.
    for (name, peer) in [("mdns-decoy", sources[2]), ("mdns-lan", sources[1])] {
        ip(&["link", "add", name, "type", "dummy"]);
        ip(&["link", "set", "dev", name, "addrgenmode", "none"]);
        ip(&["link", "set", "dev", name, "multicast", "on"]);
        for source in [sources[0], peer] {
            let address = format!("{source}/{prefix}");
            if ipv6 {
                ip(&["-6", "addr", "add", &address, "dev", name, "nodad"]);
            } else {
                ip(&["addr", "add", &address, "dev", name]);
            }
        }
        ip(&["link", "set", name, "up"]);
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let lan = index("mdns-lan");
            let decoy = index("mdns-decoy");
            let a_owner = binding(1, lan);
            let b_owner = binding(2, lan);
            let c_owner = binding(3, decoy);
            let mut a = node(sources[0].parse().unwrap(), &a_owner);
            let mut b = node(sources[1].parse().unwrap(), &b_owner);
            let mut c = node(sources[2].parse().unwrap(), &c_owner);
            expect_links(&mut a, &mut b, &mut c, true).await;
            assert_eq!(a_owner.calls.load(Ordering::Acquire), 2);
            assert_eq!(a_owner.preparations.load(Ordering::Acquire), 2);
            a_owner.current.store(false, Ordering::Release);
            let fallback = binding(4, decoy);
            policy(&mut a, sources[0].parse().unwrap(), &fallback);
            expect_links(&mut a, &mut b, &mut c, false).await;
            assert_eq!(fallback.calls.load(Ordering::Acquire), 2);
            assert_eq!(fallback.preparations.load(Ordering::Acquire), 2);
            // A fresh LAN identity makes return observable without expiring A's cache.
            b_owner.current.store(false, Ordering::Release);
            drop(b);
            let return_peer = binding(5, lan);
            let mut b = node(sources[1].parse().unwrap(), &return_peer);
            fallback.current.store(false, Ordering::Release);
            let returned = binding(6, lan);
            policy(&mut a, sources[0].parse().unwrap(), &returned);
            expect_links(&mut a, &mut b, &mut c, true).await;
            assert_eq!(returned.calls.load(Ordering::Acquire), 2);
            assert_eq!(returned.preparations.load(Ordering::Acquire), 2);
        });
}

#[test]
#[ignore = "isolated Linux multicast links, duplicate source IPs, selection loss/return; no Internet or TUN"]
fn ipv4_multicast_uses_exact_owned_link_and_returns() {
    run("ipv4_multicast_uses_exact_owned_link_and_returns", false);
}

#[test]
#[ignore = "isolated IPv6 multicast links, scoped RX/TX, duplicate source IPs and selection return; no Internet or TUN"]
fn ipv6_multicast_uses_exact_owned_link_and_returns() {
    run("ipv6_multicast_uses_exact_owned_link_and_returns", true);
}
