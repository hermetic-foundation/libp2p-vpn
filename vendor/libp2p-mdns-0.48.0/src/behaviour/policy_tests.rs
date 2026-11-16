use std::{collections::HashSet, net::IpAddr, time::Duration};

use super::tokio::Behaviour;
use crate::Config;
use libp2p_identity::PeerId;

fn addr(value: &str) -> IpAddr {
    value.parse().unwrap()
}

fn behaviour() -> Behaviour {
    Behaviour::new(Config::default(), PeerId::random()).unwrap()
}

#[test]
fn filtered_advertisements_exclude_other_interface_addresses() {
    let allowed = HashSet::from([addr("192.0.2.1"), addr("2001:db8::1")]);
    for value in [
        "/ip4/192.0.2.1/tcp/4001",
        "/ip6/2001:db8::1/udp/4001/quic-v1",
    ] {
        assert!(super::iface::advertisement_allowed(
            &value.parse().unwrap(),
            Some(&allowed)
        ));
    }
    for value in [
        "/ip4/100.64.0.1/tcp/4001",
        "/ip6/2001:db8::2/tcp/4001",
        "/dns4/example.test/tcp/4001",
    ] {
        assert!(!super::iface::advertisement_allowed(
            &value.parse().unwrap(),
            Some(&allowed)
        ));
        assert!(super::iface::advertisement_allowed(
            &value.parse().unwrap(),
            None
        ));
    }
}

#[tokio::test]
async fn default_admission_preserves_address_family_rules() {
    let b = behaviour();
    assert!(b.interface_allowed(addr("192.0.2.1")));
    assert!(b.interface_allowed(addr("100.64.0.1")));
    for invalid in ["127.0.0.1", "0.0.0.0", "224.0.0.251", "::1", "2001:db8::1"] {
        assert!(!b.interface_allowed(addr(invalid)));
    }
}

#[tokio::test]
async fn allowlist_admits_only_exact_addresses() {
    let mut b = behaviour();
    let lan = addr("192.0.2.1");
    b.set_allowed_interfaces(Some(HashSet::from([lan])));
    assert!(b.interface_allowed(lan));
    assert!(!b.interface_allowed(addr("192.0.2.2")));
    assert!(!b.interface_allowed(addr("100.64.0.1")));
    b.set_allowed_interfaces(Some(HashSet::new()));
    assert!(!b.interface_allowed(lan));
    b.set_allowed_interfaces(None);
    assert!(b.interface_allowed(lan));
}

#[tokio::test]
async fn allowlist_cannot_admit_invalid_addresses_or_wrong_family() {
    let mut b = behaviour();
    for invalid in ["127.0.0.1", "0.0.0.0", "224.0.0.251", "2001:db8::1"] {
        let invalid = addr(invalid);
        b.set_allowed_interfaces(Some(HashSet::from([invalid])));
        assert!(!b.interface_allowed(invalid));
    }
}

struct Retired(Option<tokio::sync::oneshot::Sender<()>>);

impl Drop for Retired {
    fn drop(&mut self) {
        let _ = self.0.take().unwrap().send(());
    }
}

async fn install_task(b: &mut Behaviour, ip: IpAddr) -> tokio::sync::oneshot::Receiver<()> {
    let (started, ready) = tokio::sync::oneshot::channel();
    let (retired, done) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        let _retired = Retired(Some(retired));
        let _ = started.send(());
        std::future::pending::<()>().await;
    });
    b.if_tasks.insert(ip, handle);
    ready.await.unwrap();
    done
}

#[tokio::test]
async fn replacing_allowlist_retires_only_disallowed_tasks() {
    let mut b = behaviour();
    let lan = addr("192.0.2.1");
    let cell = addr("100.64.0.1");
    b.set_allowed_interfaces(Some(HashSet::from([lan, cell])));
    let mut lan_done = install_task(&mut b, lan).await;
    let cell_done = install_task(&mut b, cell).await;
    b.set_allowed_interfaces(Some(HashSet::from([lan])));
    tokio::time::timeout(Duration::from_secs(1), cell_done)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(b.active_interfaces().collect::<Vec<_>>(), vec![lan]);
    assert!(matches!(
        lan_done.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    b.set_allowed_interfaces(Some(HashSet::new()));
    tokio::time::timeout(Duration::from_secs(1), lan_done)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(b.active_interfaces().count(), 0);
}

#[tokio::test]
#[ignore = "requires P2P_VPN_MDNS_TEST_SOURCE assigned to a multicast-capable IPv4 interface"]
async fn assigned_interface_resumes_without_a_new_up_event() {
    let lan = addr(&std::env::var("P2P_VPN_MDNS_TEST_SOURCE").expect("test source address"));
    let mut b = behaviour();
    b.available_interfaces.insert(lan);
    b.set_allowed_interfaces(Some(HashSet::new()));
    assert_eq!(b.active_interfaces().count(), 0);
    b.set_allowed_interfaces(Some(HashSet::from([lan])));
    assert_eq!(b.active_interfaces().collect::<Vec<_>>(), vec![lan]);
    b.set_allowed_interfaces(Some(HashSet::new()));
    assert_eq!(b.active_interfaces().count(), 0);
    tokio::task::yield_now().await;
    b.set_allowed_interfaces(Some(HashSet::from([lan])));
    assert_eq!(b.active_interfaces().collect::<Vec<_>>(), vec![lan]);
}

#[tokio::test]
async fn dropping_behaviour_aborts_interface_tasks() {
    let mut b = behaviour();
    let done = install_task(&mut b, addr("192.0.2.1")).await;
    drop(b);
    tokio::time::timeout(Duration::from_secs(1), done)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn identical_policy_does_not_restart_tasks() {
    let mut b = behaviour();
    let lan = addr("192.0.2.1");
    b.set_allowed_interfaces(Some(HashSet::from([lan])));
    let mut done = install_task(&mut b, lan).await;
    b.set_allowed_interfaces(Some(HashSet::from([lan])));
    assert_eq!(b.active_interfaces().count(), 1);
    assert!(matches!(
        done.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn filtered_inventory_is_retained_for_later_readmission() {
    let mut b = behaviour();
    let lan = addr("192.0.2.1");
    b.available_interfaces.insert(lan);
    b.set_allowed_interfaces(Some(HashSet::new()));
    assert!(b.available_interfaces.contains(&lan));
    assert_eq!(b.active_interfaces().count(), 0);
    // Restoring policy admits this known address; socket creation still requires
    // a real assigned address and is covered by platform integration tests.
    b.set_allowed_interfaces(None);
    assert!(b.available_interfaces.contains(&lan));
    assert!(b.interface_allowed(lan));
}
