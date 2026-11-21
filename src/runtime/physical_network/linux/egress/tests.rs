use super::super::coalesced_change;
use super::super::tests::{index, ip, isolated_namespace};
use super::*;
use std::time::Duration;

#[tokio::test]
async fn route_epochs_require_observer_identity_and_generation_and_retire_with_the_observer() {
    let owner = LinuxEgress::for_control();
    let first = owner.monitor().unwrap();
    let generation = first.generation().unwrap();
    let epoch = RouteEpoch::new(Arc::clone(&first), generation);
    let changed = RouteEpoch::new(Arc::clone(&first), generation + 1);
    let other = Arc::new(LinuxRouteMonitor::new().unwrap());
    let same_number = RouteEpoch::new(other, generation);
    assert_eq!(epoch, epoch.clone());
    assert_ne!(epoch, changed);
    assert_ne!(epoch, same_number);
    assert_eq!(epoch.generation(), same_number.generation());
    assert!(epoch.is_current());
    owner.retire_observer_for_test();
    assert!(!epoch.is_current());
    let replacement = owner.monitor().unwrap();
    let fresh = RouteEpoch::new(Arc::clone(&replacement), replacement.generation().unwrap());
    assert!(fresh.is_current());
    assert_ne!(epoch, fresh);
}

#[tokio::test]
async fn cancelled_public_preparation_drains_without_revoking_live_routes() {
    use tokio::sync::oneshot;

    let owner = Arc::new(LinuxEgress::for_control());
    let epoch = owner.current_epoch().unwrap();
    let monitor = Arc::clone(&epoch.monitor);
    let (started, observed_start) = oneshot::channel();
    let (reply, kernel_reply) = oneshot::channel();
    let (drained, observed_drain) = oneshot::channel();
    let dial = tokio::spawn({
        let owner = Arc::clone(&owner);
        async move {
            owner
                .run_public_preparation(async move {
                    let mut pending = PendingLookup {
                        monitor: &monitor,
                        complete: false,
                    };
                    started.send(()).unwrap();
                    kernel_reply.await.unwrap();
                    pending.complete = true;
                    drop(pending);
                    drained.send(()).unwrap();
                    Ok(())
                })
                .await
        }
    });
    timeout(Duration::from_secs(1), observed_start)
        .await
        .unwrap()
        .unwrap();
    dial.abort();
    assert!(dial.await.unwrap_err().is_cancelled());
    assert!(epoch.is_current());
    assert_eq!(owner.preparations.available_permits(), MAX_PREPARATIONS - 1);

    reply.send(()).unwrap();
    timeout(Duration::from_secs(1), observed_drain)
        .await
        .unwrap()
        .unwrap();
    assert!(epoch.is_current());
    assert_eq!(owner.preparations.available_permits(), MAX_PREPARATIONS);
}

const NAMESPACE_TEST: &str = "runtime::physical_network::linux::egress::tests::socket_routes_pin_sources_and_follow_loss_and_return";

#[test]
fn connection_attempts_are_bounded_and_release_capacity() {
    let owner = LinuxEgress::new("absent-pv".into());
    let mut permits = (0..MAX_CONNECTING)
        .map(|_| owner.connect_permit().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        owner.connect_permit().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    permits.pop();
    assert!(owner.connect_permit().is_ok());
}

#[tokio::test]
async fn queued_preparation_waits_without_opening_sockets_or_submitting_lookups() {
    let owner = LinuxEgress::new("absent-pv".into());
    let mut permits = (0..MAX_PREPARATIONS)
        .map(|_| owner.preparations.try_acquire().unwrap())
        .collect::<Vec<_>>();
    let mut prepared = Box::pin(owner.prepare("127.0.0.1:4001".parse().unwrap()));
    assert!(
        timeout(Duration::from_millis(10), prepared.as_mut())
            .await
            .is_err()
    );
    assert!(owner.monitor.lock().unwrap().is_none());
    permits.pop();
    assert!(
        timeout(Duration::from_secs(1), prepared)
            .await
            .unwrap()
            .is_ok()
    );
}

#[tokio::test]
async fn source_binding_works_without_privileges_on_loopback() {
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver.set_nonblocking(true).unwrap();
    let receiver = tokio::net::UdpSocket::from_std(receiver).unwrap();
    let owner = LinuxEgress::new("absent-pv".into());
    let (sender, lease) = owner.prepare(receiver.local_addr().unwrap()).await.unwrap();
    assert_eq!(sender.local_addr().unwrap(), lease.local_addr);
    assert!(lease.local_addr.ip().is_loopback());
    assert!(lease.is_current());
    assert_eq!(
        socket2::SockRef::from(&sender).device().unwrap(),
        Some(b"lo".to_vec())
    );
    let sender = tokio::net::UdpSocket::from_std(sender).unwrap();
    sender
        .send_to(b"bound-source", receiver.local_addr().unwrap())
        .await
        .unwrap();
    let mut packet = [0; 64];
    let (length, source) = timeout(Duration::from_secs(1), receiver.recv_from(&mut packet))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&packet[..length], b"bound-source");
    assert_eq!(source, lease.local_addr);
}

#[test]
#[ignore = "isolated Linux network namespaces, iproute2, and interface binding; no Internet traffic"]
fn socket_routes_pin_sources_and_follow_loss_and_return() {
    if !isolated_namespace(NAMESPACE_TEST) {
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
    ip(&["link", "add", "owned-vpn", "type", "dummy"]);
    ip(&["link", "set", "owned-vpn", "up"]);
    ip(&["addr", "add", "10.42.0.1/24", "dev", "owned-vpn"]);
    ip(&["route", "add", "default", "dev", "under-a", "metric", "100"]);
    ip(&["route", "add", "default", "dev", "under-b", "metric", "200"]);
    ip(&["-6", "route", "add", "default", "dev", "under-b"]);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let owner = LinuxEgress::new("owned-vpn".into());
            let (old, old_lease) =
                prepared(&owner, "203.0.113.9:4001", "under-a", "192.0.2.1").await;
            prepared(
                &owner,
                "[2001:db8:ffff::9]:4001",
                "under-b",
                "2001:db8:2::1",
            )
            .await;
            assert!(
                owner
                    .prepare("10.42.0.2:4001".parse().unwrap())
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("owned VPN")
            );

            // Restore/revoke OS preference, not an application transport ranking.
            ip(&["route", "del", "default", "dev", "under-a", "metric", "100"]);
            invalidated(&old_lease).await;
            prepared(&owner, "203.0.113.9:4001", "under-b", "198.51.100.1").await;
            assert_eq!(
                socket2::SockRef::from(&old).device().unwrap(),
                Some(b"under-a".to_vec())
            );
            assert_eq!(old.local_addr().unwrap().ip().to_string(), "192.0.2.1");
            ip(&["route", "add", "default", "dev", "under-a", "metric", "100"]);
            let (_, returned) = prepared(&owner, "203.0.113.9:4001", "under-a", "192.0.2.1").await;

            ip(&["addr", "del", "192.0.2.1/24", "dev", "under-a"]);
            invalidated(&returned).await;
            prepared(&owner, "203.0.113.9:4001", "under-b", "198.51.100.1").await;
            ip(&["addr", "add", "192.0.2.22/24", "dev", "under-a"]);
            ip(&["route", "add", "default", "dev", "under-a", "metric", "100"]);
            prepared(&owner, "203.0.113.9:4001", "under-a", "192.0.2.22").await;
            ip(&["route", "add", "203.0.113.0/24", "dev", "under-b"]);
            prepared(&owner, "203.0.113.9:4001", "under-b", "198.51.100.1").await;
            ip(&["route", "del", "203.0.113.0/24", "dev", "under-b"]);

            socket_policy_rules(&owner).await;

            // Cancelled requests retire their observer; the next dial creates a
            // new observer without making an old generation number current again.
            let previous = owner.monitor().unwrap();
            drop(PendingLookup {
                monitor: &previous,
                complete: false,
            });
            let (_, recreated) =
                prepared(&owner, "203.0.113.9:4001", "under-a", "192.0.2.22").await;
            assert!(!Arc::ptr_eq(&previous, &recreated.monitor));
            assert!(!old_lease.is_current());
        });
}

async fn invalidated(lease: &RouteLease) {
    timeout(Duration::from_secs(1), async {
        while lease.is_current() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

async fn prepared(
    owner: &LinuxEgress,
    destination: &str,
    name: &str,
    source: &str,
) -> (UdpSocket, RouteLease) {
    // A just-installed route can notify the monitor while lookup is running.
    // Production retries are owned by the normal negotiation/backoff controller.
    for _ in 0..8 {
        match owner.prepare(destination.parse().unwrap()).await {
            Ok((socket, lease)) => {
                assert_eq!(lease.route.interface_index, index(name));
                assert_eq!(socket.local_addr().unwrap().ip().to_string(), source);
                assert_eq!(
                    socket2::SockRef::from(&socket).device().unwrap(),
                    Some(name.as_bytes().to_vec())
                );
                assert!(lease.is_current());
                return (socket, lease);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                tokio::task::yield_now().await
            }
            Err(error) => panic!("prepare {destination}: {error}"),
        }
    }
    panic!("route did not stabilize for {destination}");
}

async fn socket_policy_rules(owner: &LinuxEgress) {
    ip(&["route", "add", "table", "100", "default", "dev", "under-b"]);
    ip(&[
        "rule", "add", "priority", "100", "ipproto", "udp", "sport", "17000", "dport", "4001",
        "fwmark", "71", "lookup", "100",
    ]);
    let monitor = owner.monitor().unwrap();
    let context = SocketRouteContext {
        source: "0.0.0.0:17000".parse().unwrap(),
        destination: "203.0.113.9:4001".parse().unwrap(),
        protocol: SocketProtocol::Udp,
        mark: 71,
        interface_index: None,
    };
    // Let the observer consume the rule update; do not infer from a dump.
    let mut revision = monitor.revision.clone();
    timeout(Duration::from_secs(1), coalesced_change(&mut revision))
        .await
        .unwrap()
        .unwrap();
    let route = monitor
        .route_for_socket(context, &HashSet::new())
        .await
        .unwrap();
    assert_eq!(route.interface_index, index("under-b"));
    assert_eq!(route.table, 100);
    for different in [
        SocketRouteContext {
            protocol: SocketProtocol::Tcp,
            ..context
        },
        SocketRouteContext { mark: 0, ..context },
        SocketRouteContext {
            source: "0.0.0.0:17001".parse().unwrap(),
            ..context
        },
        SocketRouteContext {
            destination: "203.0.113.9:4002".parse().unwrap(),
            ..context
        },
    ] {
        let route = monitor
            .route_for_socket(different, &HashSet::new())
            .await
            .unwrap();
        assert_eq!(route.interface_index, index("under-a"));
    }
    ip(&["rule", "del", "priority", "100"]);
}
