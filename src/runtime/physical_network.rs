//! Ephemeral host network selection; never part of persisted VPN configuration.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(any(target_os = "android", all(test, target_os = "linux")))]
pub mod android;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) mod control;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) mod public_discovery;

#[cfg(target_os = "linux")]
pub(crate) mod platform {
    pub(crate) use super::linux::SocketProtocol;
    pub(crate) mod egress {
        pub(crate) use super::super::linux::egress::{
            LinuxEgress as Egress, RouteEpoch, RouteLease, canonical_socket_address, reconcile,
        };
    }
}

#[cfg(target_os = "android")]
pub(crate) mod platform {
    pub(crate) use super::android::SocketProtocol;
    pub(crate) mod egress {
        pub(crate) use super::super::android::egress::{
            Egress, RouteEpoch, RouteLease, canonical_socket_address, reconcile,
        };
    }
}

use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashSet},
    net::IpAddr,
};
use tokio::sync::watch;

mod discovery_source;
pub use discovery_source::PhysicalDiscovery;

pub const MAX_SNAPSHOT_BYTES: usize = 8192;
pub const MAX_SOURCE_ADDRESSES: usize = 64;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhysicalNetworkKind {
    #[default]
    None,
    Wifi,
    Ethernet,
    Cellular,
    Bluetooth,
    Other,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalNetworkSnapshot {
    pub generation: u64,
    pub kind: PhysicalNetworkKind,
    pub interface_name: Option<String>,
    pub network_handle: Option<u64>,
    pub addresses: BTreeSet<IpAddr>,
}

impl PhysicalNetworkSnapshot {
    pub fn parse(value: &str) -> Result<Self, String> {
        if value.len() > MAX_SNAPSHOT_BYTES {
            return Err("physical network snapshot exceeds byte limit".to_owned());
        }
        let snapshot: Self = serde_json::from_str(value)
            .map_err(|_| "invalid physical network snapshot".to_owned())?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.addresses.len() > MAX_SOURCE_ADDRESSES {
            return Err("physical network snapshot exceeds address limit".to_owned());
        }
        if self.kind == PhysicalNetworkKind::None {
            if self.interface_name.is_some()
                || self.network_handle.is_some()
                || !self.addresses.is_empty()
            {
                return Err("disconnected network contains interface data".to_owned());
            }
        } else if self.interface_name.as_ref().is_none_or(|name| {
            name.is_empty() || name.len() > 64 || name.chars().any(char::is_control)
        }) {
            return Err("physical network interface name is invalid".to_owned());
        }
        if self
            .addresses
            .iter()
            .any(|ip| ip.is_loopback() || ip.is_unspecified() || ip.is_multicast())
        {
            return Err("physical network contains an invalid source address".to_owned());
        }
        Ok(())
    }

    #[must_use]
    pub fn mdns_addresses(&self) -> HashSet<IpAddr> {
        if self.validate().is_err()
            || !matches!(
                self.kind,
                PhysicalNetworkKind::Wifi
                    | PhysicalNetworkKind::Ethernet
                    | PhysicalNetworkKind::Bluetooth
            )
        {
            return HashSet::new();
        }
        self.addresses.iter().copied().collect()
    }
}

/// One bounded latest-value channel can feed every VPN instance on the host.
pub struct PhysicalNetworkPublisher(watch::Sender<PhysicalNetworkSnapshot>);

impl Default for PhysicalNetworkPublisher {
    fn default() -> Self {
        Self(watch::channel(PhysicalNetworkSnapshot::default()).0)
    }
}

impl PhysicalNetworkPublisher {
    pub fn publish(&self, snapshot: PhysicalNetworkSnapshot) -> Result<bool, String> {
        snapshot.validate()?;
        Ok(self.0.send_if_modified(|current| {
            if snapshot.generation <= current.generation {
                return false;
            }
            *current = snapshot.clone();
            true
        }))
    }

    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<PhysicalNetworkSnapshot> {
        self.0.subscribe()
    }
}

/// Reconcile only on a selection update or a newly installed discovery behaviour.
pub(crate) struct DiscoveryPolicy {
    selection: PhysicalDiscovery,
    closed: bool,
    dirty: bool,
    presence: Option<(bool, bool)>,
}

impl DiscoveryPolicy {
    pub(crate) fn new(selection: impl Into<PhysicalDiscovery>) -> Self {
        Self {
            selection: selection.into(),
            closed: false,
            dirty: true,
            presence: None,
        }
    }

    pub(crate) fn is_open(&self) -> bool {
        !self.closed
    }

    pub(crate) async fn changed(&mut self) {
        if self.selection.changed().await.is_err() {
            self.closed = true;
        }
        self.dirty = true;
    }

    pub(crate) fn reconcile(
        &mut self,
        swarm: &mut libp2p::Swarm<super::p2p::Behaviour>,
    ) -> Option<(u64, usize, bool)> {
        let presence = (
            swarm.behaviour().mdns.is_enabled(),
            swarm.behaviour().pairing_mdns.is_enabled(),
        );
        self.dirty |= [
            swarm.behaviour().mdns.as_ref(),
            swarm.behaviour().pairing_mdns.as_ref(),
        ]
        .into_iter()
        .flatten()
        .any(|mdns| !mdns.has_interface_filter());
        let admission = self.admission(presence)?;
        let count = admission.allowed.len();
        if let Some(mdns) = swarm.behaviour_mut().mdns.as_mut() {
            admission.apply(mdns);
        }
        if let Some(mdns) = swarm.behaviour_mut().pairing_mdns.as_mut() {
            admission.apply(mdns);
        }
        Some((admission.generation, count, self.closed))
    }

    pub(crate) fn reconcile_bootstrap(&mut self, mdns: &mut libp2p::mdns::tokio::Behaviour) {
        self.dirty |= !mdns.has_interface_filter();
        if let Some(admission) = self.admission((true, false)) {
            admission.apply(mdns);
        }
    }

    fn admission(&mut self, presence: (bool, bool)) -> Option<discovery_source::Admission> {
        let changed = self.selection.has_changed();
        if changed.is_err() && !self.closed {
            self.closed = true;
            self.dirty = true;
        }
        if !self.dirty && self.presence == Some(presence) && !changed.unwrap_or(false) {
            return None;
        }
        let admission = self.selection.admission(self.closed);
        self.presence = Some(presence);
        self.dirty = false;
        Some(admission)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(generation: u64, kind: PhysicalNetworkKind) -> PhysicalNetworkSnapshot {
        PhysicalNetworkSnapshot {
            generation,
            kind,
            interface_name: Some("wlan0".into()),
            network_handle: Some(1),
            addresses: ["100.64.1.2".parse().unwrap(), "fe80::1".parse().unwrap()].into(),
        }
    }

    #[test]
    fn classification_uses_host_metadata_not_address_ranges() {
        assert_eq!(
            snapshot(1, PhysicalNetworkKind::Wifi)
                .mdns_addresses()
                .len(),
            2
        );
        for kind in [PhysicalNetworkKind::Cellular, PhysicalNetworkKind::Other] {
            assert!(snapshot(1, kind).mdns_addresses().is_empty());
        }
        assert!(
            PhysicalNetworkSnapshot::default()
                .mdns_addresses()
                .is_empty()
        );
    }

    #[test]
    fn snapshot_round_trip_and_input_bounds() {
        let value = snapshot(1, PhysicalNetworkKind::Ethernet);
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(PhysicalNetworkSnapshot::parse(&json).unwrap(), value);
        assert!(PhysicalNetworkSnapshot::parse(&" ".repeat(MAX_SNAPSHOT_BYTES + 1)).is_err());
        assert!(PhysicalNetworkSnapshot::parse(&json.replace("ethernet", "vpn")).is_err());
        assert!(PhysicalNetworkSnapshot::parse("{\"generation\":1}").is_err());
        let mut invalid = value;
        invalid.addresses = (1..=65)
            .map(|last| IpAddr::from([192, 0, 2, last]))
            .collect();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn malformed_snapshots_do_not_admit_discovery() {
        for ip in ["0.0.0.0", "127.0.0.1", "224.0.0.251", "::", "::1"] {
            let mut invalid = snapshot(1, PhysicalNetworkKind::Wifi);
            invalid.addresses = [ip.parse().unwrap()].into();
            assert!(invalid.validate().is_err());
            assert!(invalid.mdns_addresses().is_empty());
        }
        let mut invalid = snapshot(1, PhysicalNetworkKind::None);
        assert!(invalid.validate().is_err());
        invalid.kind = PhysicalNetworkKind::Wifi;
        invalid.interface_name = Some("bad\0name".into());
        assert!(invalid.validate().is_err());
    }

    #[tokio::test]
    async fn publication_is_monotonic_and_retains_latest_without_subscribers() {
        let publisher = PhysicalNetworkPublisher::default();
        assert!(
            publisher
                .publish(snapshot(2, PhysicalNetworkKind::Wifi))
                .unwrap()
        );
        let mut a = publisher.subscribe();
        let mut b = publisher.subscribe();
        assert_eq!(a.borrow().generation, 2);
        assert!(
            !publisher
                .publish(snapshot(1, PhysicalNetworkKind::Cellular))
                .unwrap()
        );
        assert!(
            !publisher
                .publish(snapshot(2, PhysicalNetworkKind::Cellular))
                .unwrap()
        );
        assert!(!a.has_changed().unwrap());
        assert!(
            publisher
                .publish(snapshot(3, PhysicalNetworkKind::Cellular))
                .unwrap()
        );
        a.changed().await.unwrap();
        b.changed().await.unwrap();
        assert_eq!(a.borrow().kind, PhysicalNetworkKind::Cellular);
        assert_eq!(b.borrow().generation, 3);
    }

    pub(super) fn node() -> super::super::p2p::P2pNode {
        use super::super::p2p::{HostConfig, build_node};
        use crate::{
            config::{DiscoveryConfig, RelayResourceConfig, ResourceConfig},
            identity::NodeIdentity,
        };
        build_node(&HostConfig {
            identity: NodeIdentity::generate_ed25519().unwrap(),
            network_name: "policy-test".into(),
            membership_tag: None,
            mtu: 1280,
            max_concurrent_control_streams: 16,
            max_concurrent_packet_streams: 16,
            listen_addresses: vec![],
            external_addresses: vec![],
            bootstrap_peers: vec![],
            known_peers: vec![],
            relay_reservations: vec![],
            relay_server: false,
            relay_resources: RelayResourceConfig::default(),
            resources: ResourceConfig::default(),
            discovery: DiscoveryConfig {
                mdns: true,
                ..DiscoveryConfig::default()
            },
        })
        .unwrap()
    }

    #[tokio::test]
    async fn discovery_consumes_selection_before_first_poll_and_tracks_pairing() {
        let publisher = PhysicalNetworkPublisher::default();
        let mut policy = DiscoveryPolicy::new(publisher.subscribe());
        let mut node = node();
        assert_eq!(policy.reconcile(&mut node.swarm), Some((0, 0, false)));
        assert_eq!(
            node.swarm
                .behaviour()
                .mdns
                .as_ref()
                .unwrap()
                .allowed_interfaces(),
            Some(HashSet::new())
        );
        assert!(policy.reconcile(&mut node.swarm).is_none());
        let wifi = snapshot(1, PhysicalNetworkKind::Wifi);
        let expected = wifi.mdns_addresses();
        publisher.publish(wifi).unwrap();
        policy.changed().await;
        policy.reconcile(&mut node.swarm);
        assert_eq!(
            node.swarm
                .behaviour()
                .mdns
                .as_ref()
                .unwrap()
                .allowed_interfaces(),
            Some(expected.clone())
        );
        node.swarm.behaviour_mut().pairing_mdns = Some(
            libp2p::mdns::tokio::Behaviour::new(
                libp2p::mdns::Config::default(),
                *node.swarm.local_peer_id(),
            )
            .unwrap(),
        )
        .into();
        assert!(policy.reconcile(&mut node.swarm).is_some());
        assert_eq!(
            node.swarm
                .behaviour()
                .pairing_mdns
                .as_ref()
                .unwrap()
                .allowed_interfaces(),
            Some(expected)
        );
        publisher
            .publish(snapshot(2, PhysicalNetworkKind::Cellular))
            .unwrap();
        policy.changed().await;
        policy.reconcile(&mut node.swarm);
        for mdns in [
            &node.swarm.behaviour().mdns,
            &node.swarm.behaviour().pairing_mdns,
        ] {
            assert_eq!(
                mdns.as_ref().unwrap().allowed_interfaces(),
                Some(HashSet::new())
            );
        }
    }

    #[tokio::test]
    async fn publisher_failure_disables_discovery_without_a_closed_channel_spin() {
        let publisher = PhysicalNetworkPublisher::default();
        publisher
            .publish(snapshot(1, PhysicalNetworkKind::Wifi))
            .unwrap();
        let mut policy = DiscoveryPolicy::new(publisher.subscribe());
        let mut node = node();
        policy.reconcile(&mut node.swarm);
        drop(publisher);
        assert_eq!(policy.reconcile(&mut node.swarm), Some((1, 0, true)));
        assert!(!policy.is_open());
        assert!(policy.reconcile(&mut node.swarm).is_none());
        assert_eq!(
            node.swarm
                .behaviour()
                .mdns
                .as_ref()
                .unwrap()
                .allowed_interfaces(),
            Some(HashSet::new())
        );
    }

    #[tokio::test]
    async fn profile_free_bootstrap_obeys_the_same_selection() {
        let publisher = PhysicalNetworkPublisher::default();
        let mut policy = DiscoveryPolicy::new(publisher.subscribe());
        let node = node();
        let mut mdns = libp2p::mdns::tokio::Behaviour::new(
            libp2p::mdns::Config::default(),
            *node.swarm.local_peer_id(),
        )
        .unwrap();
        policy.reconcile_bootstrap(&mut mdns);
        assert_eq!(mdns.allowed_interfaces(), Some(HashSet::new()));
        let wifi = snapshot(1, PhysicalNetworkKind::Wifi);
        let expected = wifi.mdns_addresses();
        publisher.publish(wifi).unwrap();
        policy.changed().await;
        policy.reconcile_bootstrap(&mut mdns);
        assert_eq!(mdns.allowed_interfaces(), Some(expected));
        publisher
            .publish(snapshot(2, PhysicalNetworkKind::Cellular))
            .unwrap();
        policy.changed().await;
        policy.reconcile_bootstrap(&mut mdns);
        assert_eq!(mdns.allowed_interfaces(), Some(HashSet::new()));
    }

    #[tokio::test]
    async fn replacement_behaviours_are_scoped_without_a_new_selection_or_presence_change() {
        let publisher = PhysicalNetworkPublisher::default();
        let selected = snapshot(1, PhysicalNetworkKind::Wifi);
        let expected = selected.mdns_addresses();
        publisher.publish(selected).unwrap();
        let mut policy = DiscoveryPolicy::new(publisher.subscribe());
        let mut node = node();
        policy.reconcile(&mut node.swarm).unwrap();
        let peer = *node.swarm.local_peer_id();
        node.swarm.behaviour_mut().mdns = Some(
            libp2p::mdns::tokio::Behaviour::new(libp2p::mdns::Config::default(), peer).unwrap(),
        )
        .into();
        assert!(
            !node
                .swarm
                .behaviour()
                .mdns
                .as_ref()
                .unwrap()
                .has_interface_filter()
        );
        policy
            .reconcile(&mut node.swarm)
            .expect("new behaviour at the same enabled presence must be scoped");
        assert_eq!(
            node.swarm
                .behaviour()
                .mdns
                .as_ref()
                .unwrap()
                .allowed_interfaces(),
            Some(expected.clone())
        );

        let mut bootstrap_policy = DiscoveryPolicy::new(publisher.subscribe());
        let mut bootstrap =
            libp2p::mdns::tokio::Behaviour::new(libp2p::mdns::Config::default(), peer).unwrap();
        bootstrap_policy.reconcile_bootstrap(&mut bootstrap);
        bootstrap =
            libp2p::mdns::tokio::Behaviour::new(libp2p::mdns::Config::default(), peer).unwrap();
        bootstrap_policy.reconcile_bootstrap(&mut bootstrap);
        assert_eq!(bootstrap.allowed_interfaces(), Some(expected));
    }
}
