use super::super::{MAX_SOURCE_ADDRESSES, PhysicalNetworkKind};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::IpAddr};

pub const MAX_INVENTORY_BYTES: usize = 131_072;
pub const MAX_NETWORKS: usize = 16;
pub const MAX_ROUTES: usize = 128;

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
