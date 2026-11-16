mod asymmetric;

use super::*;
use crate::runtime::physical_network::linux::egress::MAX_PREPARATIONS;
use crate::runtime::physical_network::linux::tests::{index, ip, isolated_namespace};
use std::{
    io::Read,
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn concurrent_preparations_serialize_inventory_dumps_without_losing_capacity() {
    use futures::{StreamExt, stream};
    let owner = LinuxEgress::for_control();
    let prepared = stream::iter(0..16)
        .map(|index| {
            let owner = &owner;
            async move {
                let destination = if index % 2 == 0 {
                    "127.0.0.1:4001"
                } else {
                    "[::1]:4001"
                };
                owner
                    .prepare_tcp(destination.parse().unwrap(), false, &[])
                    .await
            }
        })
        .buffer_unordered(MAX_PREPARATIONS)
        .collect::<Vec<_>>()
        .await;
    assert_eq!(prepared.len(), 16);
    for result in prepared {
        let (socket, lease) =
            result.expect("concurrent inventory dumps must not return kernel EBUSY");
        assert_prepared(&socket, &lease, "lo", lease.local_addr.ip());
    }
    let (_, lease) = owner
        .prepare_tcp("127.0.0.1:4001".parse().unwrap(), false, &[])
        .await
        .unwrap();
    assert!(lease.is_current());
}

#[test]
fn listener_selection_is_concrete_normalized_scoped_and_order_independent() {
    let source = "127.0.0.1:0".parse().unwrap();
    let mut listeners = [
        "127.0.0.2:1",
        "0.0.0.0:2",
        "[::1]:3",
        "127.0.0.1:0",
        "127.0.0.1:4002",
        "[::ffff:127.0.0.1]:4001",
    ]
    .map(|address| address.parse().unwrap());
    assert_eq!(tcp_listener_port(source, &listeners), 4001);
    listeners.reverse();
    assert_eq!(tcp_listener_port(source, &listeners), 4001);
    assert_eq!(
        tcp_listener_port("127.0.0.3:0".parse().unwrap(), &listeners),
        1
    );
    assert_eq!(
        tcp_listener_port("192.0.2.1:0".parse().unwrap(), &listeners),
        2
    );
    assert_eq!(
        tcp_listener_port(
            "[fe80::1%7]:0".parse().unwrap(),
            &[
                "[fe80::1%8]:1".parse().unwrap(),
                "[fe80::1%7]:4001".parse().unwrap(),
            ],
        ),
        4001
    );
    assert_eq!(
        tcp_listener_port(
            "[fe80::1%7]:0".parse().unwrap(),
            &["[fe80::1%8]:4001".parse().unwrap()]
        ),
        0
    );
}

#[test]
fn preferred_source_requires_concrete_matching_family_and_preserves_link_scope() {
    let mut route = ResolvedRoute {
        generation: 1,
        destination: "fe80::2".parse().unwrap(),
        interface_index: 7,
        preferred_source: Some("fe80::1".parse().unwrap()),
        gateway: None,
        table: 254,
    };
    let destination = "[fe80::2%7]:4001".parse().unwrap();
    assert_eq!(
        tcp_source(&route, destination).unwrap(),
        "[fe80::1%7]:0".parse().unwrap()
    );
    for source in [None, Some("::"), Some("ff02::1"), Some("192.0.2.1")] {
        route.preferred_source = source.map(|source| source.parse().unwrap());
        assert_eq!(
            tcp_source(&route, destination).unwrap_err().kind(),
            io::ErrorKind::AddrNotAvailable
        );
    }
}

#[tokio::test]
async fn preparations_wait_for_the_shared_limit_before_opening_the_monitor() {
    let owner = LinuxEgress::new("absent-pv".into());
    let mut permits = (0..MAX_PREPARATIONS)
        .map(|_| owner.preparations.try_acquire().unwrap())
        .collect::<Vec<_>>();
    let mut prepared = Box::pin(owner.prepare_tcp("127.0.0.1:4001".parse().unwrap(), false, &[]));
    assert!(
        timeout(Duration::from_millis(10), prepared.as_mut())
            .await
            .is_err()
    );
    assert!(owner.monitor.lock().unwrap().is_none());
    permits.pop();
    assert!(
        timeout(Duration::from_secs(3), prepared)
            .await
            .unwrap()
            .is_ok()
    );
}

#[tokio::test]
async fn loopback_preparation_is_unconnected_concrete_and_reuses_only_when_requested() {
    for address in ["127.0.0.1:0", "[::1]:0"] {
        let first = listener(address);
        let second = listener(address);
        let destination = first.local_addr().unwrap();
        let listeners = [second.local_addr().unwrap(), destination];
        let owner = LinuxEgress::for_control();
        for reuse in [true, false] {
            let (socket, lease) = owner
                .prepare_tcp(destination, reuse, &listeners)
                .await
                .unwrap();
            assert_prepared(&socket, &lease, "lo", destination.ip());
            assert_eq!(socket.reuse_port().unwrap(), reuse);
            if reuse {
                assert_eq!(
                    lease.local_addr.port(),
                    listeners.iter().map(SocketAddr::port).min().unwrap()
                );
            } else {
                assert!(!listeners.contains(&lease.local_addr));
            }
            assert_eq!(
                first.accept().unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            assert_eq!(
                second.accept().unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }
}

#[tokio::test]
async fn reuse_failure_requires_a_fresh_preparation_not_an_unscoped_socket() {
    let listener = tcp_socket(true, false).unwrap();
    listener
        .bind(&SockAddr::from(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        ))
        .unwrap();
    listener.listen(8).unwrap();
    let destination = listener.local_addr().unwrap().as_socket().unwrap();
    let owner = LinuxEgress::new("absent-pv".into());
    assert_eq!(
        owner
            .prepare_tcp(destination, true, &[destination])
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::AddrInUse
    );
    let (socket, lease) = owner
        .prepare_tcp(destination, false, &[destination])
        .await
        .unwrap();
    assert_prepared(&socket, &lease, "lo", destination.ip());
    assert_ne!(lease.local_addr.port(), destination.port());
}

#[tokio::test]
async fn accepted_preparation_preserves_receive_routing_listener_and_siblings() {
    timeout(Duration::from_secs(3), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut first_client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut first, _) = listener.accept().await.unwrap();
        let mut second_client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut second, _) = listener.accept().await.unwrap();
        let owner = LinuxEgress::new("absent-pv".into());
        let lease = owner.prepare_tcp_stream(&first).await.unwrap();
        assert!(!lease.preferred_dial);
        assert_eq!(lease.context.protocol, SocketProtocol::Tcp);
        assert_eq!(lease.local_addr, first.local_addr().unwrap());
        assert_eq!(
            lease.context.destination,
            first_client.local_addr().unwrap()
        );
        assert_eq!(SockRef::from(&first).device().unwrap(), None);
        assert_eq!(lease.context.interface_index, None);
        assert_eq!(SockRef::from(&listener).device().unwrap(), None);
        assert_eq!(SockRef::from(&second).device().unwrap(), None);
        assert_eq!(SockRef::from(&second_client).device().unwrap(), None);
        assert!(lease.is_current());
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (server, client) in [
            (&mut first, &mut first_client),
            (&mut second, &mut second_client),
        ] {
            client.write_all(b"request").await.unwrap();
            let mut request = [0; 7];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"request");
            server.write_all(b"reply").await.unwrap();
            let mut reply = [0; 5];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"reply");
        }
    })
    .await
    .unwrap();
}

#[test]
#[ignore = "isolated Linux namespace, raw TCP capture, iproute2, and real owned TUN; no Internet traffic"]
fn namespace_tcp_preparation_obeys_exact_policy_and_never_sends_a_syn() {
    const NAME: &str = "runtime::physical_network::linux::egress::tcp::tests::namespace_tcp_preparation_obeys_exact_policy_and_never_sends_a_syn";
    if !isolated_namespace(NAME) {
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    for (name, v4, v6) in [
        ("under-a", "192.0.2.1/24", "2001:db8:1::1/64"),
        ("under-b", "198.51.100.1/24", "2001:db8:2::1/64"),
    ] {
        ip(&["link", "add", name, "type", "dummy"]);
        ip(&["link", "set", "dev", name, "addrgenmode", "none"]);
        ip(&["addr", "add", v4, "dev", name]);
        ip(&["-6", "addr", "add", v6, "dev", name, "nodad"]);
        ip(&["link", "set", name, "up"]);
    }
    ip(&["route", "add", "default", "dev", "under-a"]);
    ip(&["-6", "route", "add", "default", "dev", "under-a"]);
    ip(&["-6", "addr", "add", "fe80::1/64", "dev", "under-a", "nodad"]);
    ip(&["route", "add", "table", "100", "default", "dev", "under-b"]);
    ip(&[
        "rule",
        "add",
        "priority",
        "100",
        "from",
        "192.0.2.1/32",
        "ipproto",
        "tcp",
        "sport",
        "26001",
        "dport",
        "4001",
        "fwmark",
        "0",
        "lookup",
        "100",
    ]);
    ip(&["route", "add", "table", "101", "127.0.0.0/8", "dev", "lo"]);
    // Override the normal local-table rule so the accepted marked reply tuple
    // proves that the stream's real mark and source/peer ports reached Netlink.
    ip(&["rule", "add", "priority", "10", "lookup", "local"]);
    ip(&["rule", "del", "priority", "0"]);
    let mut config = ::tun::Configuration::default();
    config
        .tun_name("other-owned")
        .address("10.42.0.1".parse::<Ipv4Addr>().unwrap())
        .netmask(Ipv4Addr::new(255, 255, 255, 0))
        .up()
        .layer(::tun::Layer::L3);
    let _owned = ::tun::create(&config).unwrap();
    ip(&[
        "link",
        "set",
        "dev",
        "other-owned",
        "alias",
        "p2p-vpn:overlay:v1",
    ]);
    ip(&["route", "add", "203.0.113.128/25", "dev", "other-owned"]);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let owner = LinuxEgress::for_control();
            let capture = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)).unwrap();
            capture.set_nonblocking(true).unwrap();
            capture
                .bind(&SockAddr::from(
                    "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
                ))
                .unwrap();
            let receiver = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let destination = receiver.local_addr().unwrap();
            let (socket, lease) = owner.prepare_tcp(destination, false, &[]).await.unwrap();
            assert_prepared(&socket, &lease, "lo", destination.ip());
            let mut packet = [0; 1500];
            assert_eq!(
                (&capture).read(&mut packet).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            let _client = timeout(Duration::from_secs(1), TcpStream::connect(destination))
                .await
                .unwrap()
                .unwrap();
            let (accepted, _) = timeout(Duration::from_secs(1), receiver.accept())
                .await
                .unwrap()
                .unwrap();
            let count = (&capture).read(&mut packet).unwrap();
            let tcp_offset = usize::from(packet[0] & 0x0f) * 4;
            assert!(count > tcp_offset + 13);
            assert_ne!(
                packet[tcp_offset + 13] & 0x02,
                0,
                "capture must see the control connection SYN"
            );

            let preferred_listener = listener("192.0.2.1:26001");
            let preferred = preferred_listener.local_addr().unwrap();
            for (reuse, device, table) in [(true, "under-b", 100), (false, "under-a", 254)] {
                let (socket, lease) = owner
                    .prepare_tcp("203.0.113.9:4001".parse().unwrap(), reuse, &[preferred])
                    .await
                    .unwrap();
                assert_prepared(&socket, &lease, device, "192.0.2.1".parse().unwrap());
                assert_eq!(lease.route.table, table);
                assert_eq!(lease.local_addr.port() == 26001, reuse);
            }
            for destination in ["203.0.113.9:4002", "[2001:db8:ffff::9]:4001"] {
                let (socket, lease) = owner
                    .prepare_tcp(destination.parse().unwrap(), true, &[preferred])
                    .await
                    .unwrap();
                let source = if lease.local_addr.is_ipv4() {
                    "192.0.2.1"
                } else {
                    "2001:db8:1::1"
                };
                assert_prepared(&socket, &lease, "under-a", source.parse().unwrap());
            }
            let scoped = format!("[fe80::2%{}]:4001", index("under-a"))
                .parse()
                .unwrap();
            let (_, lease) = owner.prepare_tcp(scoped, false, &[]).await.unwrap();
            let SocketAddr::V6(source) = lease.local_addr else {
                panic!("expected IPv6 source")
            };
            assert_eq!(source.scope_id(), index("under-a"));
            assert_eq!(source.ip(), &"fe80::1".parse::<Ipv6Addr>().unwrap());
            assert!(
                owner
                    .prepare_tcp("203.0.113.129:4001".parse().unwrap(), false, &[])
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("owned VPN")
            );

            SockRef::from(&accepted).set_mark(73).unwrap();
            let sport = accepted.local_addr().unwrap().port().to_string();
            let dport = accepted.peer_addr().unwrap().port().to_string();
            ip(&[
                "rule",
                "add",
                "priority",
                "1",
                "from",
                "127.0.0.1/32",
                "ipproto",
                "tcp",
                "sport",
                &sport,
                "dport",
                &dport,
                "fwmark",
                "73",
                "lookup",
                "101",
            ]);
            // A fresh monitor subscribes after fixture changes, avoiding event races.
            let replies = LinuxEgress::new("absent-pv".into());
            let lease = replies.prepare_tcp_stream(&accepted).await.unwrap();
            assert_eq!(lease.context.mark, 73);
            assert_eq!(lease.route.table, 101);
            assert!(!lease.preferred_dial);
            assert_eq!(SockRef::from(&receiver).device().unwrap(), None);
            assert_eq!(SockRef::from(&receiver).mark().unwrap(), 0);

            for address in ["192.0.2.1:0", "[2001:db8:1::1]:0"] {
                let local_listener = TcpListener::bind(address).await.unwrap();
                let local_owner = LinuxEgress::for_control();
                let destination = local_listener.local_addr().unwrap();
                let (socket, lease) = local_owner
                    .prepare_tcp(destination, false, &[])
                    .await
                    .unwrap();
                assert_prepared(&socket, &lease, "lo", destination.ip());
                let client = tokio::net::TcpSocket::from_std_stream(socket.into());
                let _client = timeout(Duration::from_secs(1), client.connect(destination))
                    .await
                    .unwrap_or_else(|_| {
                        panic!("prepared same-host TCP connect timed out: {destination}, {lease:?}")
                    })
                    .unwrap();
                let (accepted, _) = local_listener.accept().await.unwrap();
                let lease = local_owner.prepare_tcp_stream(&accepted).await.unwrap();
                assert_eq!(lease.route.interface_index, index("lo"));
                assert_eq!(SockRef::from(&accepted).device().unwrap(), None);
            }

            let owned_listener = TcpListener::bind("10.42.0.1:0").await.unwrap();
            assert!(
                replies
                    .prepare_tcp(owned_listener.local_addr().unwrap(), false, &[])
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("owned VPN")
            );
            let client = tokio::net::TcpSocket::new_v4().unwrap();
            client.bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let _client = timeout(
                Duration::from_secs(1),
                client.connect(owned_listener.local_addr().unwrap()),
            )
            .await
            .unwrap()
            .unwrap();
            let (stream, _) = timeout(Duration::from_secs(1), owned_listener.accept())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                replies
                    .prepare_tcp_stream(&stream)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::AddrNotAvailable
            );
        });
}

fn listener(address: &str) -> std::net::TcpListener {
    let address = address.parse::<SocketAddr>().unwrap();
    let socket = tcp_socket(address.is_ipv4(), true).unwrap();
    socket.bind(&SockAddr::from(address)).unwrap();
    socket.listen(8).unwrap();
    socket.into()
}

fn assert_prepared(socket: &Socket, lease: &RouteLease, device: &str, source: IpAddr) {
    assert_eq!(socket.r#type().unwrap(), Type::STREAM);
    assert_eq!(socket.protocol().unwrap(), Some(Protocol::TCP));
    assert!(socket.nonblocking().unwrap());
    assert!(socket.tcp_nodelay().unwrap());
    assert!(socket.reuse_address().unwrap());
    if source.is_ipv6() {
        assert!(socket.only_v6().unwrap());
    }
    assert!(socket.peer_addr().is_err(), "preparation must not connect");
    assert_eq!(
        socket.local_addr().unwrap().as_socket().unwrap(),
        lease.local_addr
    );
    assert_eq!(lease.local_addr.ip(), source);
    assert_ne!(lease.local_addr.port(), 0);
    assert_eq!(lease.context.source, lease.local_addr);
    assert_eq!(lease.context.protocol, SocketProtocol::Tcp);
    assert_eq!(lease.context.mark, socket.mark().unwrap());
    assert_eq!(lease.context.interface_index, None);
    assert_eq!(lease.route.interface_index, index(device));
    assert_eq!(socket.device().unwrap(), None);
    assert!(lease.preferred_dial);
    assert!(lease.is_current());
}
