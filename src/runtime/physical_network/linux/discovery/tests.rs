use super::super::tests::{index, ip, isolated_mount_namespace, isolated_namespace};
use super::*;
use crate::runtime::physical_network::DiscoveryPolicy;
use futures::StreamExt;
use hickory_proto::{
    op::{Message, MessageType, Query},
    rr::{Name, RData, RecordType},
};
use std::{
    fs,
    net::{Ipv4Addr, SocketAddr},
    os::unix::fs::symlink,
    process::Command,
};
use tokio::time::Instant;

fn link(kind: Option<InfoKind>) -> LinkMessage {
    let mut link = LinkMessage::default();
    link.header.index = 7;
    link.header.link_layer_type = LinkLayerType::Ether;
    link.header.flags = LinkFlags::Up | LinkFlags::Multicast;
    link.attributes
        .push(LinkAttribute::IfName("not-a-priority-hint".into()));
    if let Some(kind) = kind {
        link.attributes
            .push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(kind)]));
    }
    link
}

#[test]
fn lan_admission_uses_link_metadata_not_interface_prefixes_or_address_ranges() {
    for kind in [
        None,
        Some(InfoKind::Veth),
        Some(InfoKind::Bridge),
        Some(InfoKind::Vlan),
        Some(InfoKind::Bond),
    ] {
        let candidate = link(kind);
        assert!(eligible_link(&candidate, false));
        assert!(!eligible_link(&candidate, true));
    }
    for kind in [
        InfoKind::Tun,
        InfoKind::Wireguard,
        InfoKind::Gtp,
        InfoKind::Xfrm,
        InfoKind::Dummy,
        InfoKind::Other("wwan".into()),
    ] {
        assert!(!eligible_link(&link(Some(kind)), false));
    }
    for layer in [
        LinkLayerType::Rawip,
        LinkLayerType::Ppp,
        LinkLayerType::None,
    ] {
        let mut candidate = link(None);
        candidate.header.link_layer_type = layer;
        assert!(!eligible_link(&candidate, false));
    }
    for flags in [
        LinkFlags::Multicast,
        LinkFlags::Up,
        LinkFlags::Up | LinkFlags::Multicast | LinkFlags::Loopback,
        LinkFlags::Up | LinkFlags::Multicast | LinkFlags::Pointopoint,
    ] {
        let mut candidate = link(None);
        candidate.header.flags = flags;
        assert!(!eligible_link(&candidate, false));
    }
    let mut candidate = link(None);
    candidate.attributes = vec![LinkAttribute::IfName("wwan0".into())];
    assert!(
        eligible_link(&candidate, false),
        "a name alone is not hardware classification"
    );
}

fn address(ip: &str) -> AddressMessage {
    let mut address = AddressMessage::default();
    address.header.index = 7;
    address
        .attributes
        .push(AddressAttribute::Address(ip.parse().unwrap()));
    address
}

#[test]
fn address_inventory_preserves_families_and_filters_unusable_sources() {
    let mut sources = BTreeSet::new();
    for ip in ["100.64.1.2", "192.168.1.2", "fe80::1", "2001:db8::1"] {
        collect_address(&address(ip), &mut sources).unwrap();
    }
    assert_eq!(sources.len(), 4);
    for ip in [
        "127.0.0.1",
        "0.0.0.0",
        "224.0.0.251",
        "::",
        "::1",
        "ff02::fb",
    ] {
        collect_address(&address(ip), &mut sources).unwrap();
    }
    assert_eq!(sources.len(), 4);
    for flag in [
        AddressHeaderFlags::Tentative,
        AddressHeaderFlags::Dadfailed,
        AddressHeaderFlags::Deprecated,
    ] {
        let mut tentative = address("192.0.2.99");
        tentative.header.flags = flag;
        collect_address(&tentative, &mut sources).unwrap();
    }
    let mut tentative = address("192.0.2.99");
    tentative
        .attributes
        .push(AddressAttribute::Flags(AddressFlags::Tentative));
    collect_address(&tentative, &mut sources).unwrap();
    assert!(!sources.contains(&"192.0.2.99".parse().unwrap()));
    let mut point_to_point = address("192.0.2.100");
    point_to_point
        .attributes
        .push(AddressAttribute::Local("192.0.2.101".parse().unwrap()));
    collect_address(&point_to_point, &mut sources).unwrap();
    assert!(!sources.contains(&"192.0.2.100".parse().unwrap()));
    assert!(sources.contains(&"192.0.2.101".parse().unwrap()));
    for last in 1..=64 {
        let result = collect_address(&address(&format!("198.51.100.{last}")), &mut sources);
        if sources.len() > MAX_SOURCE_ADDRESSES {
            assert!(result.is_err());
            break;
        }
        result.unwrap();
    }
    assert_eq!(sources.len(), MAX_SOURCE_ADDRESSES + 1);
}

#[test]
fn publications_are_stable_and_monotonic_across_observer_recreation() {
    let publisher = PhysicalNetworkPublisher::default();
    let receiver = publisher.subscribe();
    let mut state = Publications {
        publisher,
        last: PhysicalNetworkSnapshot::default(),
    };
    state.update(PhysicalNetworkSnapshot::default()).unwrap();
    assert!(!receiver.has_changed().unwrap());
    let mut selection = PhysicalNetworkSnapshot {
        generation: 9000,
        kind: PhysicalNetworkKind::Ethernet,
        interface_name: Some("under-a".into()),
        network_handle: None,
        addresses: ["100.64.1.2".parse().unwrap()].into(),
    };
    state.update(selection.clone()).unwrap();
    assert_eq!(receiver.borrow().generation, 1);
    selection.generation = 1;
    state.update(selection.clone()).unwrap();
    assert_eq!(receiver.borrow().generation, 1);
    state.update(PhysicalNetworkSnapshot::default()).unwrap();
    assert_eq!(receiver.borrow().generation, 2);
    state.update(selection).unwrap();
    assert_eq!(receiver.borrow().generation, 3);
    state.last.generation = u64::MAX;
    assert_eq!(
        state.update(PhysicalNetworkSnapshot::default()),
        Err("generation_exhausted")
    );
}

#[test]
fn retry_delay_is_bounded_and_not_an_idle_poll() {
    let mut retry = Retry::default();
    let values: Vec<_> = (0..10).map(|_| retry.next().as_secs()).collect();
    assert_eq!(values, [1, 2, 4, 8, 16, 30, 30, 30, 30, 30]);
}

#[test]
fn interface_names_cannot_escape_kernel_metadata_paths() {
    let mut candidate = link(None);
    for name in ["", ".", "..", "../wwan", "bad\0name", "bad\nname"] {
        candidate.attributes = vec![LinkAttribute::IfName(name.into())];
        assert!(interface_name(&candidate).is_none());
    }
}

#[tokio::test]
async fn owner_shutdown_and_drop_close_the_selection_channel() {
    let discovery = LinuxDiscovery::start(None);
    let receiver = discovery.subscribe();
    discovery.shutdown().await;
    assert!(receiver.has_changed().is_err());
    let discovery = LinuxDiscovery::start(None);
    let mut receiver = discovery.subscribe();
    drop(discovery);
    timeout(Duration::from_secs(1), async {
        while receiver.changed().await.is_ok() {}
    })
    .await
    .unwrap();
}

const TEST: &str = "runtime::physical_network::linux::discovery::tests::linux_discovery_follows_routes_and_retires_old_sources";
const CELLULAR_TEST: &str = "runtime::physical_network::linux::discovery::tests::linux_cellular_metadata_blocks_and_retires_mdns_binding";

#[test]
#[ignore = "requires Linux user, mount and network namespaces, mount and iproute2"]
fn linux_cellular_metadata_blocks_and_retires_mdns_binding() {
    if !isolated_mount_namespace(CELLULAR_TEST) {
        return;
    }
    let mount = Command::new("mount")
        .args(["-t", "tmpfs", "-o", "size=64k", "tmpfs", "/sys/class/net"])
        .output()
        .unwrap();
    assert!(
        mount.status.success(),
        "{}",
        String::from_utf8_lossy(&mount.stderr)
    );
    let device = Path::new("/sys/class/net/under-a/device");
    fs::create_dir_all(device).unwrap();
    let driver = device.join("driver");
    let mark_cellular = || symlink("/sys/bus/usb/drivers/qmi_wwan", &driver).unwrap();
    mark_cellular();

    ip(&[
        "link", "add", "under-a", "type", "veth", "peer", "name", "peer-a",
    ]);
    for interface in ["under-a", "peer-a"] {
        ip(&["link", "set", "dev", interface, "addrgenmode", "none"]);
        ip(&["link", "set", interface, "up"]);
    }
    ip(&["addr", "add", "192.0.2.1/24", "dev", "under-a"]);
    ip(&["route", "add", "224.0.0.251/32", "dev", "under-a"]);

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let monitor = LinuxRouteMonitor::new().unwrap();
            let route = monitor
                .lookup_route(MDNS_DESTINATION, &HashSet::new())
                .await
                .unwrap();
            assert_eq!(route.interface_index, index("under-a"));
            assert_eq!(route.preferred_source, Some("192.0.2.1".parse().unwrap()));
            assert!(cellular_device("under-a"));
            assert_eq!(
                snapshot(&monitor, None).await,
                Err(RouteLookupError::UnsupportedRoute)
            );

            let discovery = LinuxDiscovery::start(None);
            let mut selection = discovery.subscribe();
            let mut policy = DiscoveryPolicy::new(discovery.subscribe());
            let mut node = crate::runtime::physical_network::tests::node();
            node.swarm
                .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
                .unwrap();
            assert_mdns_stays_unbound(&mut policy, &mut node.swarm).await;

            // The alias change emits a netlink notification without changing the
            // multicast route, address, or hardware type of the veth.
            fs::remove_file(&driver).unwrap();
            ip(&["link", "set", "dev", "under-a", "alias", "fixture-lan"]);
            wait_selected(&mut selection, "under-a").await;
            let generation = selection.borrow().generation;
            let expected = ["192.0.2.1".parse().unwrap()].into();
            let mut tick = tokio::time::interval(Duration::from_millis(10));
            timeout(Duration::from_secs(5), async {
                loop {
                    policy.reconcile(&mut node.swarm);
                    let mdns = node.swarm.behaviour().mdns.as_ref().unwrap();
                    if mdns.active_interfaces().collect::<HashSet<_>>() == expected {
                        assert_eq!(mdns.allowed_interfaces(), Some(expected));
                        assert!(mdns_port_is_bound());
                        break;
                    }
                    tokio::select! {
                        _ = tick.tick() => {},
                        _ = node.swarm.select_next_some() => {},
                        () = policy.changed() => {},
                    }
                }
            })
            .await
            .expect("eligible LAN did not bind the normal mDNS listener");

            mark_cellular();
            ip(&["link", "set", "dev", "under-a", "alias", "fixture-cellular"]);
            timeout(
                Duration::from_secs(5),
                selection.wait_for(|value| {
                    value.generation > generation && value.kind == PhysicalNetworkKind::None
                }),
            )
            .await
            .expect("selector did not withdraw the cellular path")
            .unwrap();
            policy.reconcile(&mut node.swarm);
            timeout(Duration::from_secs(1), async {
                while mdns_port_is_bound() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("withdrawn mDNS socket did not close");
            assert_mdns_stays_unbound(&mut policy, &mut node.swarm).await;
            assert_eq!(
                snapshot(&monitor, None).await,
                Err(RouteLookupError::UnsupportedRoute)
            );
            discovery.shutdown().await;
            monitor.shutdown().await;
        });
}

fn mdns_port_is_bound() -> bool {
    ["/proc/net/udp", "/proc/net/udp6"]
        .into_iter()
        .any(|table| {
            fs::read_to_string(table)
                .unwrap()
                .lines()
                .skip(1)
                .any(|row| {
                    let local = row.split_whitespace().nth(1).unwrap();
                    let (_, port) = local.rsplit_once(':').unwrap();
                    u16::from_str_radix(port, 16).unwrap() == 5353
                })
        })
}

async fn assert_mdns_stays_unbound(
    policy: &mut DiscoveryPolicy,
    swarm: &mut libp2p::Swarm<crate::runtime::p2p::Behaviour>,
) {
    let end = Instant::now() + Duration::from_millis(700);
    let mut tick = tokio::time::interval(Duration::from_millis(10));
    loop {
        policy.reconcile(swarm);
        let mdns = swarm.behaviour().mdns.as_ref().unwrap();
        assert_eq!(mdns.allowed_interfaces(), Some(HashSet::new()));
        assert!(mdns.active_interfaces().next().is_none());
        assert!(!mdns_port_is_bound(), "excluded link still owns UDP/5353");
        tokio::select! {
            () = tokio::time::sleep_until(end) => break,
            _ = tick.tick() => {},
            _ = swarm.select_next_some() => {},
            () = policy.changed() => {},
        }
    }
}

#[test]
#[ignore = "requires user/network namespaces and iproute2; no host routes or Internet access"]
fn linux_discovery_follows_routes_and_retires_old_sources() {
    if !isolated_namespace(TEST) {
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    for (name, peer, source, other) in [
        ("under-a", "peer-a", "192.0.2.1/24", "192.0.2.2/24"),
        ("under-b", "peer-b", "198.51.100.1/24", "198.51.100.2/24"),
    ] {
        ip(&["link", "add", name, "type", "veth", "peer", "name", peer]);
        for (interface, address) in [(name, source), (peer, other)] {
            ip(&["link", "set", "dev", interface, "addrgenmode", "none"]);
            ip(&["addr", "add", address, "dev", interface]);
            ip(&["link", "set", interface, "up"]);
        }
    }
    ip(&["route", "add", "default", "dev", "under-a", "metric", "100"]);
    ip(&["route", "add", "default", "dev", "under-b", "metric", "200"]);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let discovery = LinuxDiscovery::start(None);
            let probe_a = probe_socket("192.0.2.1".parse().unwrap());
            let probe_b = probe_socket("198.51.100.1".parse().unwrap());
            let mut receiver = discovery.subscribe();
            let mut node = crate::runtime::physical_network::tests::node();
            node.swarm
                .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
                .unwrap();
            node.swarm.behaviour_mut().pairing_mdns = Some(
                libp2p::mdns::tokio::Behaviour::new(
                    libp2p::mdns::Config::default(),
                    *node.swarm.local_peer_id(),
                )
                .unwrap(),
            )
            .into();
            let mut policy = DiscoveryPolicy::new(discovery.subscribe());
            wait_selected(&mut receiver, "under-a").await;
            wait_admitted(&mut policy, &mut node.swarm, "192.0.2.1").await;
            packet_scope(
                &mut policy,
                &mut node.swarm,
                &probe_a,
                &probe_b,
                "192.0.2.1",
                1000,
            )
            .await;
            // A destination-specific multicast route overrides the default.
            ip(&["route", "add", "224.0.0.251/32", "dev", "under-b"]);
            wait_selected(&mut receiver, "under-b").await;
            wait_admitted(&mut policy, &mut node.swarm, "198.51.100.1").await;
            ip(&["route", "del", "224.0.0.251/32", "dev", "under-b"]);
            wait_selected(&mut receiver, "under-a").await;
            wait_admitted(&mut policy, &mut node.swarm, "192.0.2.1").await;
            ip(&["route", "del", "default", "dev", "under-a", "metric", "100"]);
            wait_selected(&mut receiver, "under-b").await;
            wait_admitted(&mut policy, &mut node.swarm, "198.51.100.1").await;
            packet_scope(
                &mut policy,
                &mut node.swarm,
                &probe_b,
                &probe_a,
                "198.51.100.1",
                2000,
            )
            .await;
            let fallback_generation = receiver.borrow().generation;
            ip(&["route", "add", "default", "dev", "under-a", "metric", "100"]);
            wait_selected(&mut receiver, "under-a").await;
            assert!(receiver.borrow().generation > fallback_generation);
            wait_admitted(&mut policy, &mut node.swarm, "192.0.2.1").await;
            packet_scope(
                &mut policy,
                &mut node.swarm,
                &probe_a,
                &probe_b,
                "192.0.2.1",
                3000,
            )
            .await;

            ip(&["addr", "add", "192.0.3.3/24", "dev", "under-a"]);
            ip(&["addr", "del", "192.0.2.1/24", "dev", "under-a"]);
            wait_selected(&mut receiver, "under-a").await;
            wait_admitted(&mut policy, &mut node.swarm, "192.0.3.3").await;
            assert!(
                !receiver
                    .borrow()
                    .addresses
                    .contains(&"192.0.2.1".parse().unwrap())
            );

            ip(&["route", "del", "default", "dev", "under-a", "metric", "100"]);
            ip(&["route", "del", "default", "dev", "under-b", "metric", "200"]);
            let candidates = [
                ("under-a", "192.0.3.3"),
                ("peer-a", "192.0.2.2"),
                ("under-b", "198.51.100.1"),
                ("peer-b", "198.51.100.2"),
            ];
            let (fallback_name, fallback_source) = candidates
                .into_iter()
                .min_by_key(|(name, _)| index(name))
                .unwrap();
            let lan_only = LinuxDiscovery::start(None);
            let mut lan_selection = lan_only.subscribe();
            wait_selected(&mut lan_selection, fallback_name).await;
            assert!(
                lan_selection
                    .borrow()
                    .addresses
                    .contains(&fallback_source.parse().unwrap())
            );
            lan_only.shutdown().await;
            wait_admitted(&mut policy, &mut node.swarm, fallback_source).await;
            let probe_new = probe_socket(fallback_source.parse().unwrap());
            packet_scope(
                &mut policy,
                &mut node.swarm,
                &probe_new,
                &probe_b,
                fallback_source,
                4000,
            )
            .await;

            let owned = LinuxDiscovery::start(Some("under-a".into()));
            let observer = LinuxRouteMonitor::new().unwrap();
            let selection = snapshot(&observer, Some("under-a")).await.unwrap();
            assert_ne!(selection.interface_name.as_deref(), Some("under-a"));
            assert!(!selection.addresses.contains(&"192.0.3.3".parse().unwrap()));
            observer.shutdown().await;
            let mut excluded = owned.subscribe();
            let excluded_name = candidates
                .into_iter()
                .filter(|(name, _)| *name != "under-a")
                .min_by_key(|(name, _)| index(name))
                .unwrap()
                .0;
            wait_selected(&mut excluded, excluded_name).await;
            assert!(
                !excluded
                    .borrow()
                    .addresses
                    .contains(&"192.0.3.3".parse().unwrap())
            );
            owned.shutdown().await;

            let mut tun_config = ::tun::Configuration::default();
            tun_config
                .tun_name("other-instance")
                .address(Ipv4Addr::new(100, 64, 9, 1))
                .netmask(Ipv4Addr::BROADCAST)
                .up()
                .layer(::tun::Layer::L3);
            let other_overlay = ::tun::create(&tun_config).unwrap();
            ip(&[
                "link",
                "set",
                "dev",
                "other-instance",
                "alias",
                super::super::ownership::OVERLAY_MARKER,
            ]);
            ip(&["route", "add", "224.0.0.251/32", "dev", "other-instance"]);
            let observer = LinuxRouteMonitor::new().unwrap();
            assert_eq!(
                observer
                    .lookup_route(MDNS_DESTINATION, &HashSet::new())
                    .await,
                Err(RouteLookupError::OwnOverlay),
                "another instance is excluded without its configured interface name"
            );
            let selection = snapshot(&observer, None).await.unwrap();
            assert_eq!(selection.interface_name.as_deref(), Some(fallback_name));
            wait_admitted(&mut policy, &mut node.swarm, fallback_source).await;
            packet_scope(
                &mut policy,
                &mut node.swarm,
                &probe_new,
                &probe_b,
                fallback_source,
                5000,
            )
            .await;
            ip(&["route", "del", "224.0.0.251/32", "dev", "other-instance"]);
            drop(other_overlay);
            observer.shutdown().await;
            receiver.borrow_and_update();
            let generation = receiver.borrow().generation;
            assert!(
                timeout(Duration::from_millis(200), receiver.changed())
                    .await
                    .is_err()
            );
            assert_eq!(receiver.borrow().generation, generation);
            discovery.shutdown().await;
            assert!(receiver.has_changed().is_err());
            policy.reconcile(&mut node.swarm);
            assert!(
                node.swarm
                    .behaviour()
                    .mdns
                    .as_ref()
                    .unwrap()
                    .allowed_interfaces()
                    .unwrap()
                    .is_empty()
            );
        });
}

fn probe_socket(source: Ipv4Addr) -> tokio::net::UdpSocket {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    socket.set_reuse_address(true).unwrap();
    socket.set_reuse_port(true).unwrap();
    socket
        .bind(&SocketAddr::from(([0, 0, 0, 0], 5353)).into())
        .unwrap();
    socket.set_multicast_all_v4(false).unwrap();
    socket
        .join_multicast_v4(&libp2p::mdns::IPV4_MDNS_MULTICAST_ADDRESS, &source)
        .unwrap();
    socket.set_multicast_if_v4(&source).unwrap();
    socket.set_multicast_loop_v4(true).unwrap();
    socket.set_multicast_ttl_v4(255).unwrap();
    socket.set_nonblocking(true).unwrap();
    tokio::net::UdpSocket::from_std(socket.into()).unwrap()
}

fn query(id: u16) -> Vec<u8> {
    let mut message = Message::new();
    message.set_id(id).add_query(Query::query(
        Name::from_ascii("_p2p._udp.local.").unwrap(),
        RecordType::PTR,
    ));
    message.to_vec().unwrap()
}

async fn packet_scope(
    policy: &mut DiscoveryPolicy,
    swarm: &mut libp2p::Swarm<crate::runtime::p2p::Behaviour>,
    selected: &tokio::net::UdpSocket,
    retired: &tokio::net::UdpSocket,
    source: &str,
    id: u16,
) {
    // Drain bounded in-flight work after ownership changes and give wildcard
    // listen-address notifications time to populate the response records.
    let settle = Instant::now() + Duration::from_millis(200);
    loop {
        policy.reconcile(swarm);
        tokio::select! {
            () = tokio::time::sleep_until(settle) => break,
            _ = swarm.select_next_some() => {},
            () = policy.changed() => {},
        }
    }
    let mut a = [0; 9000];
    let mut b = [0; 9000];
    for socket in [selected, retired] {
        for _ in 0..1000 {
            if socket.try_recv_from(&mut a).is_err() {
                break;
            }
        }
    }
    let destination = SocketAddr::from((libp2p::mdns::IPV4_MDNS_MULTICAST_ADDRESS, 5353));
    selected.send_to(&query(id), destination).await.unwrap();
    retired.send_to(&query(id + 1), destination).await.unwrap();
    let deadline = Instant::now() + Duration::from_millis(700);
    let mut responses = 0;
    let mut txt_records = 0;
    let mut program_queries = HashSet::new();
    loop {
        policy.reconcile(swarm);
        let received = tokio::select! {
            () = tokio::time::sleep_until(deadline) => break,
            incoming = selected.recv_from(&mut a) => {
                let (size, from) = incoming.unwrap();
                Some((Message::from_vec(&a[..size]).unwrap(), from, true))
            },
            incoming = retired.recv_from(&mut b) => {
                let (size, from) = incoming.unwrap();
                Some((Message::from_vec(&b[..size]).unwrap(), from, false))
            },
            _ = swarm.select_next_some() => None,
            () = policy.changed() => None,
        };
        let Some((message, from, on_selected)) = received else {
            continue;
        };
        // Probe queries use port 5353. Library senders have distinct ephemeral
        // ports, so random background transaction IDs cannot spoof correlation.
        if from.port() == 5353 {
            continue;
        }
        assert_eq!(
            from.ip(),
            source.parse::<IpAddr>().unwrap(),
            "traffic still uses retired source: {from}"
        );
        assert!(
            on_selected,
            "program traffic crossed the discovery interface boundary"
        );
        if message.message_type() == MessageType::Query {
            program_queries.insert(message.id());
            continue;
        }
        assert!(
            message.id() != id + 1 || program_queries.contains(&message.id()),
            "cross-interface query generated a reply"
        );
        if message.id() != id {
            continue;
        }
        responses += 1;
        for record in message.answers().iter().chain(message.additionals()) {
            if let RData::TXT(txt) = record.data() {
                for data in txt.txt_data() {
                    let text = std::str::from_utf8(data).unwrap();
                    let address: libp2p::Multiaddr =
                        text.strip_prefix("dnsaddr=").unwrap().parse().unwrap();
                    assert_eq!(
                        address.iter().next(),
                        Some(libp2p::multiaddr::Protocol::Ip4(source.parse().unwrap())),
                        "non-selected address advertised"
                    );
                    txt_records += 1;
                }
            }
        }
    }
    assert!(responses > 0, "selected interface did not answer query");
    assert!(
        txt_records > 0,
        "selected interface did not advertise its listener"
    );
}

async fn wait_selected(receiver: &mut watch::Receiver<PhysicalNetworkSnapshot>, name: &str) {
    timeout(Duration::from_secs(5), async {
        loop {
            if receiver.borrow_and_update().interface_name.as_deref() == Some(name) {
                break;
            }
            receiver.changed().await.unwrap();
        }
    })
    .await
    .expect("Linux selection did not converge");
}

async fn wait_admitted(
    policy: &mut DiscoveryPolicy,
    swarm: &mut libp2p::Swarm<crate::runtime::p2p::Behaviour>,
    source: &str,
) {
    let expected: HashSet<IpAddr> = [source.parse().unwrap()].into();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        policy.reconcile(swarm);
        if [
            swarm.behaviour().mdns.as_ref(),
            swarm.behaviour().pairing_mdns.as_ref(),
        ]
        .into_iter()
        .all(|mdns| {
            mdns.is_some_and(|mdns| mdns.active_interfaces().collect::<HashSet<_>>() == expected)
        }) {
            return;
        }
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => panic!("mDNS interface tasks did not converge to {expected:?}"),
            _ = swarm.select_next_some() => {},
            () = policy.changed() => {},
        }
    }
}
