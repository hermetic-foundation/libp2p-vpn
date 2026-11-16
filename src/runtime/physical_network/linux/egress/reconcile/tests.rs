use super::super::super::tests::{ip, isolated_namespace};
use super::super::{PendingLookup, link};
use super::*;
use netlink_packet_route::link::LinkAttribute;
use tokio::time::timeout;

#[test]
#[ignore = "isolated Linux namespace, route preference and source replacement; no Internet traffic"]
fn route_events_recheck_unchanged_destinations_and_preserve_bound_sockets() {
    const NAME: &str = "runtime::physical_network::linux::egress::reconcile::tests::route_events_recheck_unchanged_destinations_and_preserve_bound_sockets";
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
    for family in ["-4", "-6"] {
        ip(&[
            family, "route", "add", "default", "dev", "under-a", "metric", "100",
        ]);
        ip(&[
            family, "route", "add", "default", "dev", "under-b", "metric", "200",
        ]);
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let owner = Arc::new(LinuxEgress::new("absent-pv".into()));
            let (v4_socket, v4) = owner
                .prepare("203.0.113.9:4001".parse().unwrap())
                .await
                .unwrap();
            let (v6_socket, v6) = owner
                .prepare("[2001:db8:ffff::9]:4001".parse().unwrap())
                .await
                .unwrap();
            let targets = vec![target(1, v4), target(2, v6)];
            let monitor = owner.monitor().unwrap();
            for target in &targets {
                assert_eq!(
                    preferred_route(&owner, &monitor, target)
                        .await
                        .unwrap()
                        .source,
                    Some(target.lease.local_addr.ip()),
                    "kernel-selected source is observable for both families"
                );
            }
            let mut driver = Reconciler::new(Arc::clone(&owner));
            let initial = recheck(&mut driver, &targets).await;
            assert_eq!(initial.len(), 2);
            assert!(
                initial
                    .iter()
                    .all(|decision| !decision.replace && decision.is_current())
            );
            assert!(
                timeout(Duration::from_millis(100), driver.next())
                    .await
                    .is_err(),
                "no idle polling"
            );

            // A route event unrelated to either destination must not churn a path.
            ip(&["route", "add", "192.0.3.0/24", "dev", "under-b"]);
            assert!(
                recheck(&mut driver, &targets)
                    .await
                    .iter()
                    .all(|decision| !decision.replace)
            );

            for family in ["-4", "-6"] {
                ip(&[
                    family, "route", "del", "default", "dev", "under-a", "metric", "100",
                ]);
            }
            let changed = recheck(&mut driver, &targets).await;
            assert!(
                changed
                    .iter()
                    .all(|decision| decision.replace && decision.is_current())
            );
            for socket in [&v4_socket, &v6_socket] {
                assert_eq!(
                    socket2::SockRef::from(socket).device().unwrap(),
                    Some(b"under-a".to_vec())
                );
            }
            assert_eq!(
                v4_socket.local_addr().unwrap().ip().to_string(),
                "192.0.2.1"
            );
            assert_eq!(
                v6_socket.local_addr().unwrap().ip().to_string(),
                "2001:db8:1::1"
            );

            for family in ["-4", "-6"] {
                ip(&[
                    family, "route", "add", "default", "dev", "under-a", "metric", "100",
                ]);
            }
            let returned = recheck(&mut driver, &targets).await;
            assert!(changed.iter().all(|decision| !decision.is_current()));
            assert!(returned.iter().all(|decision| !decision.replace));

            // Source replacement on the same interface also requires a new path.
            ip(&["addr", "del", "192.0.2.1/24", "dev", "under-a"]);
            ip(&["addr", "add", "192.0.2.22/24", "dev", "under-a"]);
            ip(&["route", "add", "default", "dev", "under-a", "metric", "100"]);
            let replaced = recheck(&mut driver, &targets).await;
            assert!(
                replaced
                    .iter()
                    .find(|decision| decision.peer == targets[0].peer)
                    .unwrap()
                    .replace
            );
            assert!(
                !replaced
                    .iter()
                    .find(|decision| decision.peer == targets[1].peer)
                    .unwrap()
                    .replace
            );

            // No data, keepalive, or discovery packet was needed for these checks.
            for name in ["under-a", "under-b"] {
                let interface = link(&monitor, None, Some(name.into()))
                    .await
                    .unwrap()
                    .unwrap();
                let sent = interface
                    .attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        LinkAttribute::Stats64(stats) => Some(stats.tx_packets),
                        _ => None,
                    })
                    .expect("namespace-local kernel link statistics");
                assert_eq!(sent, 0);
            }
            let monitor = owner.monitor().unwrap();
            drop(PendingLookup {
                monitor: &monitor,
                complete: false,
            });
            assert!(matches!(
                timeout(Duration::from_secs(2), driver.next())
                    .await
                    .unwrap(),
                Some(Event::Unavailable)
            ));
            assert!(replaced.iter().all(|decision| !decision.is_current()));
            let recovered = recheck(&mut driver, &targets).await;
            assert!(recovered.iter().all(Decision::is_current));
            drop(driver);
        });
}

#[test]
#[ignore = "isolated IPv4/IPv6 source-policy routes and aliases; no Internet traffic"]
fn accepted_reply_routes_preserve_aliases_and_follow_source_policy() {
    const NAME: &str = "runtime::physical_network::linux::egress::reconcile::tests::accepted_reply_routes_preserve_aliases_and_follow_source_policy";
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
    ip(&["addr", "add", "192.0.2.99/32", "dev", "under-a"]);
    ip(&[
        "-6",
        "addr",
        "add",
        "2001:db8:1::99/128",
        "dev",
        "under-a",
        "nodad",
    ]);
    for family in ["-4", "-6"] {
        ip(&[family, "route", "add", "default", "dev", "under-a"]);
        ip(&[
            family, "route", "add", "default", "dev", "under-b", "table", "101",
        ]);
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let owner = Arc::new(LinuxEgress::new("absent-pv".into()));
            let mut targets = Vec::new();
            for (id, local, remote) in [
                (1, "192.0.2.99:41000", "203.0.113.9:4001"),
                (2, "[2001:db8:1::99]:41000", "[2001:db8:ffff::9]:4001"),
            ] {
                let lease = owner
                    .prepare_incoming(local.parse().unwrap(), remote.parse().unwrap(), 0)
                    .await
                    .unwrap();
                targets.push(target(id, lease));
            }
            let mut driver = Reconciler::new(Arc::clone(&owner));
            let initial = recheck(&mut driver, &targets).await;
            assert!(initial.iter().all(|decision| !decision.replace));

            for (family, alias) in [("-4", "192.0.2.99/32"), ("-6", "2001:db8:1::99/128")] {
                ip(&[
                    family, "rule", "add", "priority", "100", "from", alias, "lookup", "101",
                ]);
            }
            let redirected = recheck(&mut driver, &targets).await;
            assert!(initial.iter().all(|decision| !decision.is_current()));
            assert!(
                redirected.iter().all(|decision| decision.replace),
                "concrete reply source policy redirects both accepted paths"
            );
            let monitor = owner.monitor().unwrap();
            for target in &targets {
                let mut wildcard = target.clone();
                wildcard.lease.preferred_dial = true;
                let fixed = preferred_route(&owner, &monitor, &wildcard).await.unwrap();
                let reply = owner
                    .prepare_incoming(target.lease.local_addr, target.destination, 0)
                    .await
                    .unwrap();
                assert_eq!(fixed.route.interface_index, reply.route.interface_index);
                assert_eq!(fixed.source, None, "explicit dial sources remain fixed");
                // A wildcard dial reselects its source, unlike an explicit bind.
                wildcard.lease.source_fixed = false;
                let (_, actual) = owner.prepare(target.destination).await.unwrap();
                let preferred = preferred_route(&owner, &monitor, &wildcard).await.unwrap();
                assert_eq!(
                    preferred.route.interface_index,
                    actual.route.interface_index,
                    "reconciliation must match actual source-bound socket policy, not only the wildcard lookup"
                );
                assert_eq!(preferred.source, Some(actual.local_addr.ip()));
            }

            for family in ["-4", "-6"] {
                ip(&[family, "rule", "del", "priority", "100"]);
            }
            assert!(
                recheck(&mut driver, &targets)
                    .await
                    .iter()
                    .all(|decision| !decision.replace),
                "assigned aliases remain valid after source policy returns"
            );
            ip(&["addr", "del", "192.0.2.99/32", "dev", "under-a"]);
            ip(&["-6", "addr", "del", "2001:db8:1::99/128", "dev", "under-a"]);
            assert!(
                recheck(&mut driver, &targets)
                    .await
                    .iter()
                    .all(|decision| decision.replace),
                "removed aliases require replacement even on the same interface"
            );
            for name in ["under-a", "under-b"] {
                let interface = link(&monitor, None, Some(name.into()))
                    .await
                    .unwrap()
                    .unwrap();
                let sent = interface
                    .attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        LinkAttribute::Stats64(stats) => Some(stats.tx_packets),
                        _ => None,
                    });
                assert_eq!(sent, Some(0), "route checks must not transmit packets");
            }
        });
}

fn target(id: u8, lease: RouteLease) -> Target {
    Target {
        peer: PeerId::from_bytes([id; 32]),
        connection_id: usize::from(id),
        token: Arc::new(()),
        destination: lease.context.destination,
        lease,
    }
}

async fn recheck(driver: &mut Reconciler, targets: &[Target]) -> Vec<Decision> {
    timeout(Duration::from_secs(3), async {
        loop {
            match driver.next().await.expect("live driver") {
                Event::Snapshot => driver.submit(targets.to_vec()),
                Event::Checked(decisions) => return decisions,
                Event::Unavailable => panic!("unexpected unavailable observer"),
            }
        }
    })
    .await
    .expect("bounded event-driven recheck")
}

#[tokio::test]
async fn dropping_reconciler_aborts_its_waiting_worker() {
    let owner = Arc::new(LinuxEgress::new("absent-pv".into()));
    let mut driver = Reconciler::new(owner);
    assert!(matches!(driver.next().await, Some(Event::Snapshot)));
    let aborted = driver.driver.abort_handle();
    drop(driver);
    timeout(Duration::from_secs(1), async {
        while !aborted.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn lookup_contention_does_not_request_peer_replacement() {
    let owner = LinuxEgress::new("absent-pv".into());
    let (_socket, lease) = owner
        .prepare("127.0.0.1:4001".parse().unwrap())
        .await
        .unwrap();
    let monitor = owner.monitor().unwrap();
    let generation = monitor.generation().unwrap();
    let permits = (0..4)
        .map(|_| monitor.lookups.try_acquire().unwrap())
        .collect::<Vec<_>>();
    assert!(matches!(
        check(
            &owner,
            Arc::clone(&monitor),
            generation,
            target(1, lease.clone())
        )
        .await,
        Err(RouteLookupError::Busy)
    ));
    drop(permits);
    let checked = check(&owner, Arc::clone(&monitor), generation, target(1, lease))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(!checked.replace);
}

#[tokio::test]
async fn path_installation_requests_one_snapshot_without_a_kernel_event() {
    let owner = Arc::new(LinuxEgress::new("absent-pv".into()));
    let mut driver = Reconciler::new(Arc::clone(&owner));
    assert!(matches!(driver.next().await, Some(Event::Snapshot)));
    driver.submit(Vec::new());
    assert!(matches!(driver.next().await, Some(Event::Checked(_))));
    owner.paths_changed();
    assert!(matches!(
        timeout(Duration::from_secs(1), driver.next())
            .await
            .unwrap(),
        Some(Event::Snapshot)
    ));
    driver.submit(Vec::new());
    assert!(matches!(driver.next().await, Some(Event::Checked(_))));
    assert!(
        timeout(Duration::from_millis(100), driver.next())
            .await
            .is_err(),
        "no recurring path-change work"
    );
}
