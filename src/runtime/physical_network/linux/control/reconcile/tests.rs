use super::*;
use crate::runtime::physical_network::linux::{
    control::Registration,
    tests::{ip, isolated_namespace},
};
use libp2p::{PeerId, swarm::ConnectionId};
use std::time::Duration;

async fn register(
    routes: &Arc<ControlRoutes>,
    peer: PeerId,
    id: usize,
    destination: &str,
) -> Registration {
    let (_, lease) = routes
        .egress
        .prepare_tcp(destination.parse().unwrap(), false, &[])
        .await
        .unwrap();
    let registration = routes.register(peer, lease).unwrap();
    registration
        .bind_connection(ConnectionId::new_unchecked(id))
        .unwrap();
    registration.adopt().unwrap();
    registration
}

async fn checked(routes: &Arc<ControlRoutes>) -> Vec<reconcile::Decision> {
    let mut driver = reconcile::Reconciler::new(Arc::clone(&routes.egress));
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match driver.next().await.unwrap() {
                reconcile::Event::Snapshot => {
                    driver.submit(routes.snapshot().iter().filter_map(target).collect())
                }
                reconcile::Event::Checked(decisions) => return decisions,
                reconcile::Event::Unavailable => panic!("route monitor unavailable"),
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn only_exact_adopted_owners_enter_inspection_and_mismatched_results_are_ignored() {
    let routes = Arc::new(ControlRoutes::new(2));
    let peer = PeerId::random();
    let (_, lease) = routes
        .egress
        .prepare_tcp("127.0.0.1:4001".parse().unwrap(), false, &[])
        .await
        .unwrap();
    let registration = routes.register(peer, lease).unwrap();
    assert!(target(&routes.snapshot()[0]).is_none());
    let connection = ConnectionId::new_unchecked(23);
    registration.bind_connection(connection).unwrap();
    assert!(target(&routes.snapshot()[0]).is_none());
    registration.adopt().unwrap();
    let mut decisions = checked(&routes).await;
    assert_eq!(decisions.len(), 1);
    let decision = decisions.pop().unwrap();
    let driver = Reconciler::new(Arc::clone(&routes));
    for mismatch in 0..4 {
        let mut wrong = decision.clone();
        match mismatch {
            0 => wrong.peer = crate::PeerId::from_libp2p(PeerId::random()),
            1 => wrong.connection_id += 1,
            2 => wrong.token = Arc::new(()),
            _ => wrong.destination.set_port(4002),
        }
        driver.apply(&wrong);
        assert!(
            routes
                .connection(peer, connection)
                .unwrap()
                .inspection
                .is_none()
        );
    }
    driver.apply(&decision);
    let snapshot = routes.connection(peer, connection).unwrap();
    assert_eq!(snapshot.refresh_required(), Some(false));
    drop(registration);
    assert!(target(&snapshot).is_none());
    assert_eq!(snapshot.refresh_required(), None);
    let replacement = register(&routes, peer, 23, "127.0.0.1:4001").await;
    driver.apply(&decision);
    assert!(
        routes
            .connection(peer, connection)
            .unwrap()
            .inspection
            .is_none()
    );
    drop(replacement);
}

#[tokio::test]
async fn replacement_observer_refreshes_live_owners_and_rejects_retired_observer_results() {
    let routes = Arc::new(ControlRoutes::new(2));
    let peer = PeerId::random();
    let id = ConnectionId::new_unchecked(41);
    let registration = register(&routes, peer, 41, "127.0.0.1:4001").await;
    let driver = Reconciler::new(Arc::clone(&routes));
    let old = checked(&routes).await.remove(0);
    driver.apply(&old);
    assert_eq!(
        routes.connection(peer, id).unwrap().refresh_required(),
        Some(false)
    );

    routes.egress.retire_observer_for_test();
    assert!(!old.is_current());
    assert_eq!(
        routes.connection(peer, id).unwrap().refresh_required(),
        None
    );
    let fresh = checked(&routes).await.remove(0);
    assert!(fresh.is_current());
    assert_eq!(
        old.generation(),
        fresh.generation(),
        "numeric generations repeat across observers"
    );
    driver.apply(&fresh);
    assert_eq!(
        routes.connection(peer, id).unwrap().refresh_required(),
        Some(false),
        "a replacement observer must renew audit validity for live old owners"
    );
    driver.apply(&old);
    assert_eq!(
        routes.connection(peer, id).unwrap().refresh_required(),
        Some(false)
    );

    routes.egress.retire_observer_for_test();
    assert!(!fresh.is_current());
    let newest = checked(&routes).await.remove(0);
    driver.apply(&fresh);
    assert_eq!(
        routes.connection(peer, id).unwrap().refresh_required(),
        None
    );
    driver.apply(&newest);
    assert_eq!(
        routes.connection(peer, id).unwrap().refresh_required(),
        Some(false)
    );
    assert!(routes.connection(peer, id).unwrap().is_live());
    drop(registration);
    assert!(routes.connection(peer, id).is_none());
}

async fn expect_inspections(
    driver: &mut Reconciler,
    routes: &ControlRoutes,
    expected: &[(PeerId, usize, bool)],
) {
    tokio::time::timeout(
        Duration::from_secs(4),
        futures::future::poll_fn(|cx| {
            driver.poll(cx);
            if expected.iter().all(|(peer, id, value)| {
                routes
                    .connection(*peer, ConnectionId::new_unchecked(*id))
                    .is_some_and(|route| route.refresh_required() == Some(*value))
            }) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }),
    )
    .await
    .expect("event-driven exact route inspection");
}

#[test]
#[ignore = "isolated Linux namespace with IPv4/IPv6 route loss, return, source policy and replacement; no Internet traffic"]
fn kernel_changes_preserve_fallback_and_inspect_only_affected_exact_control_owners() {
    const NAME: &str = "runtime::physical_network::linux::control::reconcile::tests::kernel_changes_preserve_fallback_and_inspect_only_affected_exact_control_owners";
    if !isolated_namespace(NAME) {
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    for (name, v4, v6, metric) in [
        ("under-a", "192.0.2.1/24", "2001:db8:1::1/64", "100"),
        ("under-b", "198.51.100.1/24", "2001:db8:2::1/64", "200"),
    ] {
        ip(&["link", "add", name, "type", "dummy"]);
        ip(&["link", "set", "dev", name, "addrgenmode", "none"]);
        ip(&["addr", "add", v4, "dev", name]);
        ip(&["-6", "addr", "add", v6, "dev", name, "nodad"]);
        ip(&["link", "set", name, "up"]);
        for family in ["-4", "-6"] {
            ip(&[
                family, "route", "add", "default", "dev", name, "metric", metric,
            ]);
        }
    }
    ip(&[
        "route",
        "add",
        "192.0.2.2/32",
        "dev",
        "under-a",
        "src",
        "192.0.2.1",
    ]);
    ip(&["route", "add", "table", "101", "default", "dev", "under-b"]);
    // Initial source selection uses under-a, but the concrete TCP tuple is
    // deliberately redirected. Stable policy is not a replacement request.
    ip(&[
        "rule",
        "add",
        "priority",
        "100",
        "from",
        "192.0.2.1/32",
        "ipproto",
        "tcp",
        "dport",
        "4002",
        "lookup",
        "101",
    ]);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let routes = Arc::new(ControlRoutes::new(4));
            let peer = PeerId::random();
            let lan_peer = PeerId::random();
            let registrations = [
                register(&routes, peer, 21, "203.0.113.9:4001").await,
                register(&routes, peer, 22, "[2001:db8:ffff::9]:4001").await,
                register(&routes, lan_peer, 23, "192.0.2.2:4001").await,
                register(&routes, peer, 24, "203.0.113.9:4002").await,
            ];
            let mut driver = Reconciler::new(Arc::clone(&routes));
            let all_preferred = [
                (peer, 21, false),
                (peer, 22, false),
                (lan_peer, 23, false),
                (peer, 24, false),
            ];
            expect_inspections(&mut driver, &routes, &all_preferred).await;
            let stale = checked(&routes).await;
            let held = routes
                .connection(peer, ConnectionId::new_unchecked(21))
                .unwrap();
            ip(&["route", "del", "default", "dev", "under-a", "metric", "100"]);
            tokio::time::timeout(Duration::from_secs(3), async {
                while stale.iter().any(reconcile::Decision::is_current) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("kernel route event fences old decisions");
            for decision in &stale {
                driver.apply(decision);
            }
            assert_eq!(
                held.refresh_required(),
                None,
                "old generation cannot authorize inspection"
            );
            expect_inspections(
                &mut driver,
                &routes,
                &[
                    (peer, 21, true),
                    (peer, 22, false),
                    (lan_peer, 23, false),
                    (peer, 24, true),
                ],
            )
            .await;
            assert!(
                routes
                    .snapshot()
                    .iter()
                    .all(|route| route.is_live() && route.is_adopted())
            );
            ip(&["route", "add", "default", "dev", "under-a", "metric", "100"]);
            expect_inspections(&mut driver, &routes, &all_preferred).await;
            ip(&["addr", "add", "192.0.2.99/32", "dev", "under-a"]);
            ip(&[
                "route",
                "replace",
                "default",
                "dev",
                "under-a",
                "src",
                "192.0.2.99",
                "metric",
                "100",
            ]);
            expect_inspections(
                &mut driver,
                &routes,
                &[
                    (peer, 21, true),
                    (peer, 22, false),
                    (lan_peer, 23, false),
                    (peer, 24, true),
                ],
            )
            .await;
            assert!(
                routes
                    .snapshot()
                    .iter()
                    .all(|route| route.is_live() && route.is_adopted()),
                "inspection must not close fallback service"
            );
            drop(registrations);
            assert!(routes.snapshot().is_empty());
        });
}
