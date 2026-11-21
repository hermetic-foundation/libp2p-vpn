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
fn watcher_distinguishes_kernel_multicast_changes_from_unmatched_replies() {
    for event in [
        RouteNetlinkMessage::NewLink(LinkMessage::default()),
        RouteNetlinkMessage::NewAddress(AddressMessage::default()),
        RouteNetlinkMessage::NewRoute(RouteMessage::default()),
        RouteNetlinkMessage::NewRule(RuleMessage::default()),
    ] {
        let mut message = NetlinkMessage::from(event);
        for sequence in [0, 1, 123, u32::MAX] {
            message.header.sequence_number = sequence;
            assert_eq!(
                classify_route_message(0, 0, &message),
                MonitorAction::Ignore
            );
            assert_eq!(
                classify_route_message(0, 1, &message),
                MonitorAction::Changed,
                "real kernel notifications may retain the triggering request's sequence"
            );
            assert_eq!(
                classify_route_message(42, 1, &message),
                MonitorAction::Ignore
            );
        }
    }
    let ack = NetlinkMessage::new(
        Default::default(),
        NetlinkPayload::Error(netlink_packet_core::ErrorMessage::default()),
    );
    for groups in [0, 1] {
        assert_eq!(
            classify_route_message(0, groups, &ack),
            MonitorAction::Ignore
        );
    }
    let mut error = netlink_packet_core::ErrorMessage::default();
    error.code = std::num::NonZeroI32::new(-22);
    let error = NetlinkMessage::new(Default::default(), NetlinkPayload::Error(error));
    assert_eq!(classify_route_message(0, 0, &error), MonitorAction::Ignore);
    assert_eq!(
        classify_route_message(0, 1, &error),
        MonitorAction::Unavailable
    );
    let overrun = NetlinkMessage::new(Default::default(), NetlinkPayload::Overrun(Vec::new()));
    assert_eq!(
        classify_route_message(0, 0, &overrun),
        MonitorAction::Unavailable
    );
    assert_eq!(
        classify_route_message(42, 1, &overrun),
        MonitorAction::Ignore
    );
}

#[test]
fn watcher_groups_fit_the_received_multicast_mask() {
    for group in GROUPS {
        assert!(
            (1..=32).contains(&(*group as u32)),
            "larger groups require packet-info ancillary data, not a truncated sockaddr mask"
        );
    }
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
fn socket_queries_include_actual_tuple_mark_uid_and_device() {
    for (source, destination, prefix) in [
        ("192.0.2.7:17700", "203.0.113.9:4001", 32),
        ("[2001:db8::7]:17700", "[2001:db8:1::9]:4001", 128),
    ] {
        let context = SocketRouteContext {
            source: source.parse().unwrap(),
            destination: destination.parse().unwrap(),
            protocol: SocketProtocol::Udp,
            mark: 71,
            interface_index: Some(42),
        };
        let request = socket_route_request(context, 1000).unwrap();
        assert_eq!(request.header.source_prefix_length, prefix);
        for attribute in [
            RouteAttribute::Source(context.source.ip().into()),
            RouteAttribute::Uid(1000),
            RouteAttribute::Mark(71),
            RouteAttribute::Oif(42),
            RouteAttribute::Other(DefaultNla::new(27, vec![17])),
            RouteAttribute::Other(DefaultNla::new(28, 17700_u16.to_be_bytes().to_vec())),
            RouteAttribute::Other(DefaultNla::new(29, 4001_u16.to_be_bytes().to_vec())),
        ] {
            assert!(
                request.attributes.contains(&attribute),
                "missing {attribute:?}"
            );
        }
        let tcp = socket_route_request(
            SocketRouteContext {
                protocol: SocketProtocol::Tcp,
                ..context
            },
            1000,
        )
        .unwrap();
        assert!(
            tcp.attributes
                .contains(&RouteAttribute::Other(DefaultNla::new(27, vec![6])))
        );
    }
}

#[test]
fn socket_queries_reject_ambiguous_families_and_link_local_scope() {
    let base = SocketRouteContext {
        source: "[::]:0".parse().unwrap(),
        destination: "[fe80::9%42]:4001".parse().unwrap(),
        protocol: SocketProtocol::Udp,
        mark: 0,
        interface_index: None,
    };
    assert!(
        socket_route_request(base, 1000)
            .unwrap()
            .attributes
            .contains(&RouteAttribute::Oif(42))
    );
    for invalid in [
        SocketRouteContext {
            destination: "[fe80::9]:4001".parse().unwrap(),
            ..base
        },
        SocketRouteContext {
            interface_index: Some(43),
            ..base
        },
        SocketRouteContext {
            interface_index: Some(0),
            ..base
        },
        SocketRouteContext {
            source: "0.0.0.0:17000".parse().unwrap(),
            ..base
        },
        SocketRouteContext {
            source: "[fe80::1]:17000".parse().unwrap(),
            ..base
        },
        SocketRouteContext {
            source: "[fe80::1%43]:17000".parse().unwrap(),
            ..base
        },
    ] {
        assert!(
            socket_route_request(invalid, 1000).is_err(),
            "accepted {invalid:?}"
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
fn ipv6_selected_source_accepts_rta_src_but_prefers_rta_prefsrc() {
    let destination = "2001:db8::9".parse().unwrap();
    let source = "2001:db8:1::1".parse::<IpAddr>().unwrap();
    let preferred = "2001:db8:1::2".parse::<IpAddr>().unwrap();
    let mut message = reply(destination);
    message
        .attributes
        .push(RouteAttribute::Source(source.into()));
    assert_eq!(
        decode_route(message.clone(), 1, destination, &HashSet::new())
            .unwrap()
            .preferred_source,
        Some(source)
    );
    message
        .attributes
        .push(RouteAttribute::PrefSource(preferred.into()));
    assert_eq!(
        decode_route(message, 1, destination, &HashSet::new())
            .unwrap()
            .preferred_source,
        Some(preferred)
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
    let mut local = reply(destination);
    local.header.kind = RouteType::Local;
    assert!(decode_route(local, 1, destination, &HashSet::new()).is_ok());
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
async fn incomplete_or_timed_out_lookups_replace_only_the_request_socket() {
    let monitor = LinuxRouteMonitor::new().unwrap();
    let generation = monitor.generation().unwrap();
    let mut sibling = monitor.request().unwrap();
    let original = Arc::clone(&sibling.requests);
    assert!(
        timeout(Duration::from_millis(1), async {
            let mut pending = monitor.request().unwrap();
            assert!(Arc::ptr_eq(&pending.requests, &original));
            let _links = pending.handle().unwrap().link().get().execute();
            std::future::pending::<()>().await;
        })
        .await
        .is_err()
    );
    assert_eq!(sibling.finish(), Err(RouteLookupError::MonitorUnavailable));
    assert_eq!(monitor.generation(), Ok(generation));
    let mut fresh = monitor.request().unwrap();
    assert!(!Arc::ptr_eq(&fresh.requests, &original));
    let mut links = fresh
        .handle()
        .unwrap()
        .link()
        .get()
        .match_index(1)
        .execute();
    assert!(links.try_next().await.unwrap().is_some());
    assert!(links.try_next().await.unwrap().is_none());
    assert_eq!(fresh.finish(), Ok(()));
    monitor.shutdown().await;
}

#[tokio::test]
async fn completed_responses_including_kernel_errors_keep_observer_usable() {
    let monitor = LinuxRouteMonitor::new().unwrap();
    let unused = monitor.request().unwrap();
    let original = Arc::clone(&unused.requests);
    drop(unused);
    let mut pending = monitor.request().unwrap();
    drop(pending.handle().unwrap());
    let mut message = netlink_packet_core::ErrorMessage::default();
    message.code = std::num::NonZeroI32::new(-101);
    assert_eq!(
        pending.response_error(rtnetlink::Error::NetlinkError(message)),
        RouteLookupError::Kernel(Some(-101))
    );
    drop(pending);
    assert!(Arc::ptr_eq(&monitor.request().unwrap().requests, &original));
    assert!(monitor.generation().is_ok());
    monitor.shutdown().await;
}

const NAMESPACE_TEST: &str =
    "runtime::physical_network::linux::tests::kernel_routes_follow_metrics_rules_loss_and_return";
const PARENT_NAMESPACE: &str = "P2P_VPN_ROUTE_PARENT_NAMESPACE";

pub(crate) fn ip(args: &[&str]) -> String {
    let output = Command::new("ip").args(args).output().expect("execute ip");
    assert!(
        output.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

pub(super) fn index(name: &str) -> u32 {
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
    if !isolated_namespace(NAMESPACE_TEST) {
        return;
    }
    kernel_route_fixture();
}

pub(crate) fn isolated_namespace(test: &str) -> bool {
    isolated_fixture(test, false)
}

pub(super) fn isolated_mount_namespace(test: &str) -> bool {
    isolated_fixture(test, true)
}

fn isolated_fixture(test: &str, isolate_mounts: bool) -> bool {
    const PARENT_MOUNT_NAMESPACE: &str = "P2P_VPN_ROUTE_PARENT_MOUNT_NAMESPACE";
    let own_namespace = std::fs::read_link("/proc/self/ns/net").unwrap();
    let own_mount_namespace =
        isolate_mounts.then(|| std::fs::read_link("/proc/self/ns/mnt").unwrap());
    let Some(parent) = env::var_os(PARENT_NAMESPACE) else {
        let mut command = Command::new("timeout");
        command.args([
            "--signal=KILL",
            "30",
            "unshare",
            "--user",
            "--map-root-user",
            "--net",
        ]);
        if let Some(mount_namespace) = own_mount_namespace {
            command
                .args(["--mount", "--propagation", "private"])
                .env(PARENT_MOUNT_NAMESPACE, mount_namespace);
        }
        let output = command
            .arg(env::current_exe().unwrap())
            .args(["--exact", test, "--ignored", "--nocapture"])
            .env(PARENT_NAMESPACE, own_namespace.as_os_str())
            .output()
            .expect("run isolated route fixture");
        assert!(
            output.status.success(),
            "namespace fixture failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return false;
    };
    assert_ne!(
        own_namespace.as_os_str(),
        &parent,
        "refusing to mutate the host network"
    );
    if let Some(own_mount_namespace) = own_mount_namespace {
        let parent = env::var_os(PARENT_MOUNT_NAMESPACE).expect("parent mount namespace");
        assert_ne!(
            own_mount_namespace.as_os_str(),
            &parent,
            "refusing to mount over host sysfs"
        );
    }
    true
}

fn kernel_route_fixture() {
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
