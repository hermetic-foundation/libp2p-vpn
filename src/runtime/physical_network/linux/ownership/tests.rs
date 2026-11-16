use super::super::tests::{index, ip, isolated_namespace};
use super::*;
use std::net::IpAddr;

fn device(name: &str, source: &str) -> ::tun::Device {
    let mut config = ::tun::Configuration::default();
    config
        .tun_name(name)
        .address(source.parse::<std::net::Ipv4Addr>().unwrap())
        .netmask(std::net::Ipv4Addr::BROADCAST)
        .up()
        .layer(::tun::Layer::L3);
    ::tun::create(&config).unwrap()
}

#[test]
fn ownership_requires_exact_marker_and_tun_metadata_not_names_or_addresses() {
    let mut link = LinkMessage::default();
    link.attributes.push(LinkAttribute::IfName("pv0".into()));
    assert!(!is_owned_link(&link));
    link.attributes
        .push(LinkAttribute::IfAlias(OVERLAY_MARKER.into()));
    assert!(
        !is_owned_link(&link),
        "physical aliases alone do not claim ownership"
    );
    link.attributes
        .push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Tun)]));
    assert!(is_owned_link(&link));
    for alias in [
        "",
        "p2p-vpn",
        "p2p-vpn:overlay:v1-extra",
        "p2p-vpn:overlay:v2",
    ] {
        link.attributes
            .retain(|value| !matches!(value, LinkAttribute::IfAlias(_)));
        link.attributes.push(LinkAttribute::IfAlias(alias.into()));
        assert!(!is_owned_link(&link));
    }
    link.attributes
        .retain(|value| !matches!(value, LinkAttribute::IfName(_) | LinkAttribute::IfAlias(_)));
    link.attributes
        .push(LinkAttribute::IfName("arbitrary-renamed-link".into()));
    link.attributes
        .push(LinkAttribute::IfAlias(OVERLAY_MARKER.into()));
    assert!(is_owned_link(&link), "names do not define kernel ownership");
}

#[test]
#[ignore = "isolated real TUN ownership and IPv4/IPv6 route queries; no Internet traffic"]
fn routes_exclude_other_instances_across_rename_and_recreation() {
    const NAME: &str = "runtime::physical_network::linux::ownership::tests::routes_exclude_other_instances_across_rename_and_recreation";
    if !isolated_namespace(NAME) {
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    let mut devices = Vec::new();
    for (name, v4, v6) in [
        ("owned-one", "192.0.2.11", "2001:db8:1::11/128"),
        ("owned-two", "192.0.2.12", "2001:db8:1::12/128"),
        ("parent-vpn", "192.0.2.13", "2001:db8:1::13/128"),
    ] {
        devices.push(device(name, v4));
        ip(&["link", "set", "dev", name, "addrgenmode", "none"]);
        ip(&["-6", "addr", "add", v6, "dev", name, "nodad"]);
    }
    for name in ["owned-one", "owned-two"] {
        ip(&["link", "set", "dev", name, "alias", OVERLAY_MARKER]);
    }
    for (family, destination, name) in [
        ("-4", "203.0.113.1/32", "owned-one"),
        ("-6", "2001:db8:ffff::1/128", "owned-one"),
        ("-4", "203.0.113.2/32", "owned-two"),
        ("-6", "2001:db8:ffff::2/128", "owned-two"),
        ("-4", "203.0.113.3/32", "parent-vpn"),
        ("-6", "2001:db8:ffff::3/128", "parent-vpn"),
    ] {
        ip(&[family, "route", "add", destination, "dev", name]);
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut monitor = LinuxRouteMonitor::new().unwrap();
            let own_one = index("owned-one");
            let own_two = index("owned-two");
            let parent = index("parent-vpn");
            assert_eq!(
                indices(&monitor).await.unwrap(),
                HashSet::from([own_one, own_two])
            );
            for destination in [
                "203.0.113.1",
                "2001:db8:ffff::1",
                "203.0.113.2",
                "2001:db8:ffff::2",
            ] {
                assert_eq!(
                    monitor
                        .route_to(destination.parse().unwrap(), &HashSet::new())
                        .await,
                    Err(RouteLookupError::OwnOverlay)
                );
            }
            for destination in ["203.0.113.3", "2001:db8:ffff::3"] {
                assert_eq!(
                    monitor
                        .route_to(destination.parse::<IpAddr>().unwrap(), &HashSet::new())
                        .await
                        .unwrap()
                        .interface_index,
                    parent
                );
            }

            let owner = super::super::egress::LinuxEgress::new("local-instance".into());
            for (source, destination) in [
                ("192.0.2.11:41000", "203.0.113.3:4001"),
                ("[2001:db8:1::11]:41000", "[2001:db8:ffff::3]:4001"),
                ("192.0.2.12:41000", "203.0.113.3:4001"),
                ("[2001:db8:1::12]:41000", "[2001:db8:ffff::3]:4001"),
            ] {
                let source: std::net::SocketAddr = source.parse().unwrap();
                assert!(
                    !owner
                        .source_is_assigned(&monitor, source.ip())
                        .await
                        .unwrap()
                );
                assert_eq!(
                    owner
                        .prepare_incoming(source, destination.parse().unwrap(), 0)
                        .await
                        .unwrap_err()
                        .kind(),
                    std::io::ErrorKind::AddrNotAvailable,
                    "a physical reply route cannot legitimize an owned-overlay source"
                );
            }
            for (source, destination) in [
                ("192.0.2.13:41000", "203.0.113.3:4001"),
                ("[2001:db8:1::13]:41000", "[2001:db8:ffff::3]:4001"),
            ] {
                let source: std::net::SocketAddr = source.parse().unwrap();
                assert!(
                    owner
                        .source_is_assigned(&monitor, source.ip())
                        .await
                        .unwrap()
                );
                assert_eq!(
                    owner
                        .prepare_incoming(source, destination.parse().unwrap(), 0)
                        .await
                        .unwrap()
                        .route
                        .interface_index,
                    parent
                );
            }

            ip(&["link", "set", "dev", "owned-one", "down"]);
            ip(&["link", "set", "dev", "owned-one", "name", "renamed"]);
            ip(&["link", "set", "dev", "renamed", "up"]);
            // Taking a TUN down removes these kernel routes. Restore the
            // fixture destinations; ownership must still follow the same index.
            ip(&["addr", "replace", "192.0.2.11/32", "dev", "renamed"]);
            ip(&[
                "-6",
                "addr",
                "replace",
                "2001:db8:1::11/128",
                "dev",
                "renamed",
                "nodad",
            ]);
            ip(&["route", "replace", "203.0.113.1/32", "dev", "renamed"]);
            ip(&[
                "-6",
                "route",
                "replace",
                "2001:db8:ffff::1/128",
                "dev",
                "renamed",
            ]);
            monitor.changed().await.unwrap();
            assert_eq!(
                indices(&monitor).await.unwrap(),
                HashSet::from([own_one, own_two])
            );
            for destination in ["203.0.113.1", "2001:db8:ffff::1"] {
                assert_eq!(
                    monitor
                        .route_to(destination.parse().unwrap(), &HashSet::new())
                        .await,
                    Err(RouteLookupError::OwnOverlay)
                );
            }

            drop(devices.remove(0));
            devices.push(device("owned-one", "192.0.2.21"));
            ip(&["route", "add", "203.0.113.1/32", "dev", "owned-one"]);
            monitor.changed().await.unwrap();
            assert_eq!(indices(&monitor).await.unwrap(), HashSet::from([own_two]));
            assert_eq!(
                monitor
                    .route_to("203.0.113.1".parse().unwrap(), &HashSet::new())
                    .await
                    .unwrap()
                    .interface_index,
                index("owned-one")
            );
        });
}
