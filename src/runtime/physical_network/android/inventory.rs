use super::super::{MAX_SOURCE_ADDRESSES, PhysicalNetworkKind};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::IpAddr};

pub const MAX_INVENTORY_BYTES: usize = 131_072;
pub const MAX_NETWORKS: usize = 16;
pub const MAX_ROUTES: usize = 128;
pub const MAX_DNS_SERVERS: usize = 8;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub revision: u64,
    pub preferred_network: Option<u64>,
    pub networks: Vec<NetworkRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRecord {
    pub network_handle: u64,
    pub incarnation: u64,
    pub revision: u64,
    pub kind: PhysicalNetworkKind,
    pub interface_name: String,
    pub interface_index: u32,
    pub validated: bool,
    pub addresses: BTreeSet<IpAddr>,
    pub routes: Vec<NetworkRoute>,
    #[serde(default)]
    pub dns_servers: Vec<IpAddr>,
    #[serde(default)]
    pub private_dns_active: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRoute {
    pub destination: IpAddr,
    pub prefix_length: u8,
    pub gateway: Option<IpAddr>,
}

impl NetworkRoute {
    pub(crate) fn matches(&self, destination: IpAddr) -> bool {
        match (self.destination, destination.to_canonical()) {
            (IpAddr::V4(prefix), IpAddr::V4(address)) if self.prefix_length <= 32 => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix_length))
                    .unwrap_or(0);
                u32::from(prefix) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(prefix), IpAddr::V6(address)) if self.prefix_length <= 128 => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix_length))
                    .unwrap_or(0);
                u128::from(prefix) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }

    fn valid(&self) -> bool {
        let canonical = match self.destination {
            IpAddr::V4(prefix) if self.prefix_length <= 32 => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix_length))
                    .unwrap_or(0);
                u32::from(prefix) & !mask == 0
            }
            IpAddr::V6(prefix)
                if self.prefix_length <= 128 && prefix.to_ipv4_mapped().is_none() =>
            {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix_length))
                    .unwrap_or(0);
                u128::from(prefix) & !mask == 0
            }
            _ => false,
        };
        canonical
            && self.gateway.is_none_or(|gateway| {
                gateway.is_ipv4() == self.destination.is_ipv4()
                    && !gateway.is_multicast()
                    && !gateway.is_unspecified()
                    && !gateway.is_loopback()
            })
    }
}

impl Inventory {
    /// Nominate Networks, not routes: only a Network-bound kernel lookup can
    /// establish family reachability when LinkProperties omits CLAT details.
    pub(crate) fn candidates(&self, destination: IpAddr) -> Vec<&NetworkRecord> {
        let mut candidates = self
            .networks
            .iter()
            .filter_map(|record| {
                let lan = record
                    .routes
                    .iter()
                    .filter(|route| {
                        route.matches(destination)
                            && route.prefix_length > 0
                            && route.gateway.is_none()
                            && matches!(
                                record.kind,
                                PhysicalNetworkKind::Wifi
                                    | PhysicalNetworkKind::Ethernet
                                    | PhysicalNetworkKind::Bluetooth
                            )
                    })
                    .map(|route| route.prefix_length)
                    .max();
                let rank = if let Some(prefix) = lan {
                    (0, std::cmp::Reverse(prefix))
                } else if self.preferred_network == Some(record.network_handle) {
                    (1, std::cmp::Reverse(0))
                } else if record.validated {
                    (2, std::cmp::Reverse(0))
                } else {
                    return None;
                };
                Some((rank, record))
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|(rank, record)| {
            (
                *rank,
                self.preferred_network != Some(record.network_handle),
                record.network_handle,
            )
        });
        candidates.into_iter().map(|(_, record)| record).collect()
    }

    pub fn parse(json: &str) -> Result<Self, String> {
        if json.len() > MAX_INVENTORY_BYTES {
            return Err("Android network inventory exceeds byte limit".to_owned());
        }
        let inventory: Self = serde_json::from_str(json)
            .map_err(|_| "invalid Android network inventory".to_owned())?;
        inventory.validate()?;
        Ok(inventory)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.revision == 0 || self.networks.len() > MAX_NETWORKS {
            return Err("invalid Android network inventory revision or count".to_owned());
        }
        let mut handles = BTreeSet::new();
        let mut incarnations = BTreeSet::new();
        for record in &self.networks {
            let mut dns_servers = BTreeSet::new();
            if record.network_handle == 0
                || record.incarnation == 0
                || record.revision == 0
                || !handles.insert(record.network_handle)
                || !incarnations.insert(record.incarnation)
                || record.kind == PhysicalNetworkKind::None
                || record.interface_index == 0
                || record.interface_index > i32::MAX as u32
                || record.interface_name.is_empty()
                || record.interface_name.len() > 64
                || record.interface_name.chars().any(char::is_control)
                || record.addresses.len() > MAX_SOURCE_ADDRESSES
                || record.addresses.iter().any(|address| {
                    address.is_unspecified()
                        || address.is_multicast()
                        || address.is_loopback()
                        || address.to_canonical() != *address
                })
                || record.routes.len() > MAX_ROUTES
                || record.routes.iter().any(|route| !route.valid())
                || record.dns_servers.len() > MAX_DNS_SERVERS
                || record.dns_servers.iter().any(|address| {
                    address.is_unspecified()
                        || address.is_multicast()
                        || address.is_loopback()
                        || address.to_canonical() != *address
                        || !dns_servers.insert(*address)
                })
            {
                return Err("invalid Android physical network record".to_owned());
            }
        }
        if self
            .preferred_network
            .is_some_and(|handle| !handles.contains(&handle))
        {
            return Err("Android preferred network is absent from inventory".to_owned());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn legacy_inventory() -> Value {
        json!({
            "revision": 1,
            "preferred_network": 10,
            "networks": [{
                "network_handle": 10,
                "incarnation": 1,
                "revision": 1,
                "kind": "wifi",
                "interface_name": "wlan0",
                "interface_index": 3,
                "validated": true,
                "addresses": ["192.0.2.1"],
                "routes": []
            }]
        })
    }

    fn with_dns(dns_servers: Value) -> String {
        let mut value = legacy_inventory();
        value["networks"][0]["dns_servers"] = dns_servers;
        value.to_string()
    }

    #[test]
    fn missing_dns_servers_defaults_to_empty_and_round_trips() {
        let legacy = Inventory::parse(&legacy_inventory().to_string()).unwrap();
        assert!(legacy.networks[0].dns_servers.is_empty());
        assert!(!legacy.networks[0].private_dns_active);
        assert_eq!(Inventory::parse(&with_dns(json!([]))).unwrap(), legacy);
        assert_eq!(
            Inventory::parse(&serde_json::to_string(&legacy).unwrap()).unwrap(),
            legacy
        );
    }

    #[test]
    fn private_dns_active_defaults_false_and_round_trips_true() {
        let legacy = Inventory::parse(&with_dns(json!(["192.0.2.53"]))).unwrap();
        assert!(!legacy.networks[0].private_dns_active);
        let mut value = serde_json::to_value(&legacy).unwrap();
        assert_eq!(value["networks"][0]["private_dns_active"], json!(false));
        assert_eq!(Inventory::parse(&value.to_string()).unwrap(), legacy);
        value["networks"][0]["private_dns_active"] = json!(true);
        let active = Inventory::parse(&value.to_string()).unwrap();
        assert!(active.networks[0].private_dns_active);
        assert_ne!(active.networks[0], legacy.networks[0]);
        assert_eq!(
            Inventory::parse(&serde_json::to_string(&active).unwrap()).unwrap(),
            active
        );
        for invalid in [json!(null), json!("true"), json!(1)] {
            value["networks"][0]["private_dns_active"] = invalid;
            assert!(Inventory::parse(&value.to_string()).is_err());
        }
    }

    #[test]
    fn dns_servers_preserve_os_order_including_unscoped_link_local() {
        let servers = ["198.51.100.53", "fe80::53", "192.0.2.53"];
        let parsed = Inventory::parse(&with_dns(json!(servers))).unwrap();
        assert_eq!(
            parsed.networks[0].dns_servers,
            servers
                .map(|server| server.parse::<IpAddr>().unwrap())
                .to_vec()
        );
        assert_eq!(
            Inventory::parse(&serde_json::to_string(&parsed).unwrap()).unwrap(),
            parsed
        );
    }

    #[test]
    fn dns_servers_are_bounded_without_truncation() {
        let mut servers = (1..=MAX_DNS_SERVERS)
            .map(|index| format!("192.0.2.{index}"))
            .collect::<Vec<_>>();
        let parsed = Inventory::parse(&with_dns(json!(servers))).unwrap();
        assert_eq!(parsed.networks[0].dns_servers.len(), MAX_DNS_SERVERS);
        servers.push("192.0.2.9".to_owned());
        assert!(Inventory::parse(&with_dns(json!(servers))).is_err());
    }

    #[test]
    fn dns_servers_reject_invalid_addresses_duplicates_and_wrong_types() {
        for server in [
            "0.0.0.0",
            "::",
            "127.0.0.1",
            "127.1.2.3",
            "::1",
            "224.0.0.53",
            "ff02::53",
            "::ffff:192.0.2.53",
            "::ffff:c000:235",
            "fe80::53%wlan0",
            "fe80::53%3",
            "192.000.2.53",
            "192.0.2.999",
            "192.0.2.53:53",
            "example.com",
            "",
        ] {
            assert!(
                Inventory::parse(&with_dns(json!([server]))).is_err(),
                "accepted DNS server {server}"
            );
        }
        for servers in [
            json!(["192.0.2.53", "192.0.2.53"]),
            json!(["fe80::53", "fe80:0:0:0:0:0:0:53"]),
            json!(null),
            json!("192.0.2.53"),
            json!([null]),
            json!([53]),
        ] {
            assert!(Inventory::parse(&with_dns(servers)).is_err());
        }
    }
}
