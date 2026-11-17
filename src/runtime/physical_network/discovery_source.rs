use super::PhysicalNetworkSnapshot;
#[cfg(any(target_os = "android", all(test, target_os = "linux")))]
use super::android;
use libp2p::mdns::InterfaceSocketBinding;
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
};
use tokio::sync::watch;

/// Owns the platform's live LAN-discovery selection and its observation lifetime.
pub struct PhysicalDiscovery(Source);

enum Source {
    Snapshot(watch::Receiver<PhysicalNetworkSnapshot>),
    #[cfg(any(target_os = "android", all(test, target_os = "linux")))]
    Android(android::discovery::AndroidDiscovery),
}

impl From<watch::Receiver<PhysicalNetworkSnapshot>> for PhysicalDiscovery {
    fn from(receiver: watch::Receiver<PhysicalNetworkSnapshot>) -> Self {
        Self(Source::Snapshot(receiver))
    }
}

#[cfg(any(target_os = "android", all(test, target_os = "linux")))]
impl From<android::discovery::AndroidDiscovery> for PhysicalDiscovery {
    fn from(discovery: android::discovery::AndroidDiscovery) -> Self {
        Self(Source::Android(discovery))
    }
}

pub(super) struct Admission {
    pub generation: u64,
    pub allowed: HashSet<IpAddr>,
    pub bindings: Option<HashMap<IpAddr, Arc<dyn InterfaceSocketBinding>>>,
    pub ipv6: Option<bool>,
}

impl Admission {
    pub fn apply(&self, mdns: &mut libp2p::mdns::tokio::Behaviour) {
        // Withdraw old advertisements before any new socket task can run.
        if mdns.allowed_interfaces().as_ref() != Some(&self.allowed) {
            mdns.set_allowed_interfaces(Some(HashSet::new()));
        }
        mdns.set_interface_bindings(self.bindings.clone());
        if let Some(ipv6) = self.ipv6 {
            mdns.set_ipv6(ipv6);
        }
        mdns.set_allowed_interfaces(Some(self.allowed.clone()));
    }
}

impl PhysicalDiscovery {
    pub(super) fn has_changed(&self) -> Result<bool, watch::error::RecvError> {
        match &self.0 {
            Source::Snapshot(receiver) => receiver.has_changed(),
            #[cfg(any(target_os = "android", all(test, target_os = "linux")))]
            Source::Android(discovery) => discovery.has_changed(),
        }
    }

    pub(super) async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        match &mut self.0 {
            Source::Snapshot(receiver) => receiver.changed().await,
            #[cfg(any(target_os = "android", all(test, target_os = "linux")))]
            Source::Android(discovery) => discovery.changed().await,
        }
    }

    pub(super) fn admission(&mut self, closed: bool) -> Admission {
        match &mut self.0 {
            Source::Snapshot(receiver) => {
                let snapshot = receiver.borrow_and_update();
                Admission {
                    generation: snapshot.generation,
                    allowed: if closed {
                        HashSet::new()
                    } else {
                        snapshot.mdns_addresses()
                    },
                    bindings: None,
                    ipv6: None,
                }
            }
            #[cfg(any(target_os = "android", all(test, target_os = "linux")))]
            Source::Android(discovery) => discovery.admission(closed),
        }
    }
}
