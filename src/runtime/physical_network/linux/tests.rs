use super::*;
use netlink_packet_route::{
    address::AddressMessage, link::LinkMessage, neighbour::NeighbourMessage, rule::RuleMessage,
};
use std::{env, process::Command};

fn channel() -> (watch::Sender<Revision>, watch::Receiver<Revision>) {
    watch::channel(Revision {
        generation: 1,
        available: true,
    })
}

#[test]
fn lookup_requests_are_full_destination_queries_with_effective_uid() {
    for destination in ["203.0.113.9", "2001:db8::9"] {
        let destination: IpAddr = destination.parse().unwrap();
        let request = route_request(destination, 1234);
        assert_eq!(request.header.table, 0);
        assert_eq!(request.header.kind, RouteType::Unspec);
        assert!(request.header.flags.contains(RouteFlags::LookupTable));
        assert_eq!(
            request.header.destination_prefix_length,
            if destination.is_ipv4() { 32 } else { 128 }
        );
        assert_eq!(
            request.attributes,
            [
                RouteAttribute::Destination(destination.into()),
                RouteAttribute::Uid(1234)
            ]
        );
    }
}

#[test]
fn link_address_route_and_rule_changes_invalidate_both_families() {
    for message in [
        RouteNetlinkMessage::NewLink(LinkMessage::default()),
        RouteNetlinkMessage::DelLink(LinkMessage::default()),
        RouteNetlinkMessage::NewAddress(AddressMessage::default()),
        RouteNetlinkMessage::DelAddress(AddressMessage::default()),
        RouteNetlinkMessage::NewRoute(RouteMessage::default()),
        RouteNetlinkMessage::DelRoute(RouteMessage::default()),
        RouteNetlinkMessage::NewRule(RuleMessage::default()),
        RouteNetlinkMessage::DelRule(RuleMessage::default()),
    ] {
        assert!(invalidates_routes(&message));
    }
    assert!(!invalidates_routes(&RouteNetlinkMessage::NewNeighbour(
        NeighbourMessage::default()
    )));
}

fn reply(destination: IpAddr) -> RouteMessage {
    let mut message = route_request(destination, 1234);
    message.header.kind = RouteType::Unicast;
    message.header.table = 254;
    message.attributes.push(RouteAttribute::Oif(42));
    message
}

#[test]
fn resolved_routes_preserve_kernel_decision_and_overlay_exclusion() {
    let destination = "203.0.113.9".parse().unwrap();
    let mut message = reply(destination);
    let source = "192.0.2.9".parse::<IpAddr>().unwrap();
    let gateway = "192.0.2.1".parse::<IpAddr>().unwrap();
    message.attributes.extend([
        RouteAttribute::PrefSource(source.into()),
        RouteAttribute::Gateway(gateway.into()),
        RouteAttribute::Table(1000),
    ]);
    let route = decode_route(message.clone(), 7, destination, &HashSet::new()).unwrap();
    assert_eq!(route.interface_index, 42);
    assert_eq!(route.table, 1000);
    assert_eq!(route.preferred_source, Some(source));
    assert_eq!(route.gateway, Some(gateway));
    assert_eq!(route.generation, 7);
    assert_eq!(
        decode_route(message, 7, destination, &[42].into()),
        Err(RouteLookupError::OwnOverlay)
    );
}

#[test]
fn unresolved_multipath_nonunicast_and_wrong_family_are_not_promoted() {
    let destination = "203.0.113.9".parse().unwrap();
    let mut multipath = reply(destination);
    multipath.attributes.push(RouteAttribute::MultiPath(vec![]));
    let mut no_interface = reply(destination);
    no_interface
        .attributes
        .retain(|attr| !matches!(attr, RouteAttribute::Oif(_)));
    let mut zero_interface = reply(destination);
    zero_interface.attributes.push(RouteAttribute::Oif(0));
    let mut wrong_family = reply(destination);
    wrong_family.header.address_family = AddressFamily::Inet6;
    for message in [multipath, no_interface, zero_interface, wrong_family] {
        assert_eq!(
            decode_route(message, 1, destination, &HashSet::new()),
            Err(RouteLookupError::UnsupportedRoute)
        );
    }
    for kind in [
        RouteType::Local,
        RouteType::BlackHole,
        RouteType::Unreachable,
        RouteType::Prohibit,
        RouteType::Throw,
    ] {
        let mut message = reply(destination);
        message.header.kind = kind;
        assert_eq!(
            decode_route(message, 1, destination, &HashSet::new()),
            Err(RouteLookupError::UnsupportedRoute)
        );
    }
}

#[test]
fn revisions_reject_stale_results_and_monitor_loss() {
    let (sender, receiver) = channel();
    assert_eq!(check_generation(&receiver, 1), Ok(()));
    for _ in 0..10_000 {
        assert!(advance_revision(&sender));
    }
    assert_eq!(current_generation(&receiver), Ok(10_001));
    assert_eq!(
        check_generation(&receiver, 1),
        Err(RouteLookupError::StaleGeneration)
    );
    assert_eq!(check_generation(&receiver, 10_001), Ok(()));
    drop(sender);
    assert_eq!(
        current_generation(&receiver),
        Err(RouteLookupError::MonitorUnavailable)
    );
}

#[test]
fn revision_exhaustion_fails_closed_instead_of_wrapping() {
    let (sender, receiver) = channel();
    sender.send_modify(|state| state.generation = u64::MAX);
    assert!(!advance_revision(&sender));
    assert_eq!(
        current_generation(&receiver),
        Err(RouteLookupError::MonitorUnavailable)
    );
}

#[tokio::test]
async fn changes_are_coalesced_and_idle_monitor_has_no_periodic_wakes() {
    let (sender, mut receiver) = channel();
    for _ in 0..100 {
        advance_revision(&sender);
    }
    assert_eq!(coalesced_change(&mut receiver).await, Ok(101));
    assert!(
        timeout(Duration::from_millis(100), coalesced_change(&mut receiver))
            .await
            .is_err()
    );
    sender.send_modify(|state| state.available = false);
    assert_eq!(
        coalesced_change(&mut receiver).await,
        Err(RouteLookupError::MonitorUnavailable)
    );
}

#[tokio::test]
async fn continuous_events_cannot_postpone_a_change_forever() {
    let (sender, mut receiver) = channel();
    let producer = tokio::spawn(async move {
        for _ in 0..100 {
            advance_revision(&sender);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    let start = Instant::now();
    let generation = timeout(Duration::from_secs(2), coalesced_change(&mut receiver))
        .await
        .unwrap()
        .unwrap();
    assert!(generation > 1);
    assert!(start.elapsed() < Duration::from_millis(500));
    producer.abort();
    let _ = producer.await;
}

#[tokio::test]
async fn incomplete_or_timed_out_lookups_retire_the_observer() {
    let mut monitor = LinuxRouteMonitor::new().unwrap();
    drop(PendingLookup {
        monitor: &monitor,
        complete: false,
    });
    assert_eq!(
        monitor.generation(),
        Err(RouteLookupError::MonitorUnavailable)
    );
    assert_eq!(
        monitor.changed().await,
        Err(RouteLookupError::MonitorUnavailable)
    );
    assert_eq!(
        monitor
            .route_to("203.0.113.9".parse().unwrap(), &HashSet::new())
            .await,
        Err(RouteLookupError::MonitorUnavailable)
    );
    monitor.shutdown().await;

    let monitor = LinuxRouteMonitor::new().unwrap();
    let mut receiver = monitor.revision.clone();
    assert!(
        timeout(Duration::from_millis(1), async {
            let _pending = PendingLookup {
                monitor: &monitor,
                complete: false,
            };
            std::future::pending::<()>().await;
        })
        .await
        .is_err()
    );
    assert_eq!(
        monitor.generation(),
        Err(RouteLookupError::MonitorUnavailable)
    );
    assert!(
        timeout(Duration::from_secs(1), receiver.changed())
            .await
            .unwrap()
            .is_err()
    );
    monitor.shutdown().await;
}

#[tokio::test]
async fn completed_responses_including_kernel_errors_keep_observer_usable() {
    let monitor = LinuxRouteMonitor::new().unwrap();
    drop(PendingLookup {
        monitor: &monitor,
        complete: true,
    });
    assert!(monitor.generation().is_ok());
    let mut pending = PendingLookup {
        monitor: &monitor,
        complete: false,
    };
    let mut message = netlink_packet_core::ErrorMessage::default();
    message.code = std::num::NonZeroI32::new(-101);
    assert_eq!(
        pending.response_error(rtnetlink::Error::NetlinkError(message)),
        RouteLookupError::Kernel(Some(-101))
    );
    drop(pending);
    assert!(monitor.generation().is_ok());
    monitor.shutdown().await;
}

const NAMESPACE_TEST: &str =
    "runtime::physical_network::linux::tests::kernel_routes_follow_metrics_rules_loss_and_return";
const PARENT_NAMESPACE: &str = "P2P_VPN_ROUTE_PARENT_NAMESPACE";

fn ip(args: &[&str]) -> String {
    let output = Command::new("ip").args(args).output().expect("execute ip");
    assert!(
        output.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn index(name: &str) -> u32 {
    let value: serde_json::Value =
        serde_json::from_str(&ip(&["-j", "link", "show", name])).unwrap();
    u32::try_from(value[0]["ifindex"].as_u64().unwrap()).unwrap()
}

async fn update(monitor: &mut LinuxRouteMonitor, args: &[&str]) {
    eprintln!("kernel transition: ip {args:?}");
    let generation = monitor.generation().unwrap();
    ip(args);
    let observed = timeout(Duration::from_secs(3), monitor.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(observed > generation, "missing kernel event for {args:?}");
}

async fn selected(monitor: &LinuxRouteMonitor, destination: &str, name: &str) -> ResolvedRoute {
    let route = monitor
        .route_to(destination.parse().unwrap(), &HashSet::new())
        .await
        .unwrap();
    assert_eq!(
        route.interface_index,
        index(name),
        "wrong kernel decision for {destination}: {route:?}; iproute2: {}",
        ip(&["-j", "route", "get", destination])
    );
    monitor.validate_generation(&route).unwrap();
    route
}

#[test]
#[ignore = "requires Linux user/network namespaces and iproute2; no TUN, privileges, or Internet traffic"]
fn kernel_routes_follow_metrics_rules_loss_and_return() {
    let own_namespace = std::fs::read_link("/proc/self/ns/net").unwrap();
    let Some(parent) = env::var_os(PARENT_NAMESPACE) else {
        let output = Command::new("timeout")
            .args([
                "--signal=KILL",
                "30",
                "unshare",
                "--user",
                "--map-root-user",
                "--net",
            ])
            .arg(env::current_exe().unwrap())
            .args(["--exact", NAMESPACE_TEST, "--ignored", "--nocapture"])
            .env(PARENT_NAMESPACE, own_namespace.as_os_str())
            .output()
            .expect("run isolated route fixture");
        assert!(
            output.status.success(),
            "namespace fixture failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    };
    assert_ne!(
        own_namespace.as_os_str(),
        &parent,
        "refusing to mutate the host network"
    );
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
    ip(&["link", "add", "owned-vpn", "type", "dummy"]);
    ip(&["link", "set", "dev", "owned-vpn", "addrgenmode", "none"]);
    ip(&["addr", "add", "10.42.0.1/24", "dev", "owned-vpn"]);
    ip(&["link", "set", "owned-vpn", "up"]);
    for (family, first, second) in [("-4", "under-a", "under-b"), ("-6", "under-b", "under-a")] {
        ip(&[
            family, "route", "add", "default", "dev", first, "metric", "100",
        ]);
        ip(&[
            family, "route", "add", "default", "dev", second, "metric", "200",
        ]);
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut monitor = LinuxRouteMonitor::new().unwrap();
            let original = selected(&monitor, "203.0.113.9", "under-a").await;
            assert_eq!(
                original.preferred_source,
                Some("192.0.2.1".parse().unwrap())
            );
            selected(&monitor, "2001:db8:ffff::9", "under-b").await;
            assert!(
                timeout(Duration::from_millis(100), monitor.changed())
                    .await
                    .is_err()
            );

            update(
                &mut monitor,
                &["-4", "route", "add", "203.0.113.0/24", "dev", "under-b"],
            )
            .await;
            assert_eq!(
                monitor.validate_generation(&original),
                Err(RouteLookupError::StaleGeneration)
            );
            selected(&monitor, "203.0.113.9", "under-b").await;
            selected(&monitor, "203.0.114.9", "under-a").await;
            update(
                &mut monitor,
                &["-4", "route", "del", "203.0.113.0/24", "dev", "under-b"],
            )
            .await;
            selected(&monitor, "203.0.113.9", "under-a").await;

            update(
                &mut monitor,
                &[
                    "-4", "route", "del", "default", "dev", "under-a", "metric", "100",
                ],
            )
            .await;
            selected(&monitor, "203.0.113.9", "under-b").await;
            selected(&monitor, "2001:db8:ffff::9", "under-b").await;
            update(
                &mut monitor,
                &[
                    "-4", "route", "add", "default", "dev", "under-a", "metric", "100",
                ],
            )
            .await;
            selected(&monitor, "203.0.113.9", "under-a").await;

            for (family, destination, prefix, alternate, primary) in [
                ("-4", "203.0.113.9", "203.0.113.0/24", "under-b", "under-a"),
                (
                    "-6",
                    "2001:db8:ffff::9",
                    "2001:db8:ffff::/64",
                    "under-a",
                    "under-b",
                ),
            ] {
                update(
                    &mut monitor,
                    &[
                        family, "route", "add", "table", "100", "default", "dev", alternate,
                    ],
                )
                .await;
                selected(&monitor, destination, primary).await;
                update(
                    &mut monitor,
                    &[
                        family, "rule", "add", "priority", "100", "to", prefix, "lookup", "100",
                    ],
                )
                .await;
                let policy = selected(&monitor, destination, alternate).await;
                assert_eq!(policy.table, 100);
                update(&mut monitor, &[family, "rule", "del", "priority", "100"]).await;
                selected(&monitor, destination, primary).await;
            }

            update(
                &mut monitor,
                &["addr", "del", "192.0.2.1/24", "dev", "under-a"],
            )
            .await;
            selected(&monitor, "203.0.113.9", "under-b").await;
            update(
                &mut monitor,
                &["addr", "add", "192.0.2.22/24", "dev", "under-a"],
            )
            .await;
            // Removing the last IPv4 address also removes this link's default
            // route. Model the OS network manager restoring it after addressing.
            selected(&monitor, "203.0.113.9", "under-b").await;
            update(
                &mut monitor,
                &[
                    "-4", "route", "add", "default", "dev", "under-a", "metric", "100",
                ],
            )
            .await;
            let replacement = selected(&monitor, "203.0.113.9", "under-a").await;
            assert_eq!(
                replacement.preferred_source,
                Some("192.0.2.22".parse().unwrap())
            );
            update(&mut monitor, &["link", "set", "under-a", "down"]).await;
            selected(&monitor, "203.0.113.9", "under-b").await;
            update(&mut monitor, &["link", "set", "under-a", "up"]).await;
            selected(&monitor, "203.0.113.9", "under-b").await;
            update(
                &mut monitor,
                &[
                    "-4", "route", "add", "default", "dev", "under-a", "metric", "100",
                ],
            )
            .await;
            selected(&monitor, "203.0.113.9", "under-a").await;

            assert_eq!(
                monitor
                    .route_to("10.42.0.2".parse().unwrap(), &[index("owned-vpn")].into())
                    .await,
                Err(RouteLookupError::OwnOverlay)
            );
            assert_eq!(
                monitor
                    .route_to("0.0.0.0".parse().unwrap(), &HashSet::new())
                    .await,
                Err(RouteLookupError::InvalidDestination)
            );
            assert_eq!(
                monitor
                    .route_to("fe80::1".parse().unwrap(), &HashSet::new())
                    .await,
                Err(RouteLookupError::InvalidDestination)
            );
            let permits = monitor.lookups.acquire_many(4).await.unwrap();
            assert_eq!(
                monitor
                    .route_to("203.0.113.9".parse().unwrap(), &HashSet::new())
                    .await,
                Err(RouteLookupError::Busy)
            );
            drop(permits);
            let receiver = monitor.revision.clone();
            monitor.shutdown().await;
            assert_eq!(
                current_generation(&receiver),
                Err(RouteLookupError::MonitorUnavailable)
            );

            let monitor = LinuxRouteMonitor::new().unwrap();
            let mut receiver = monitor.revision.clone();
            drop(monitor);
            assert!(
                timeout(Duration::from_secs(1), receiver.changed())
                    .await
                    .unwrap()
                    .is_err()
            );
        });
}
