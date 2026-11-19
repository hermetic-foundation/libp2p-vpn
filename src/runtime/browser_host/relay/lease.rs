//! Shared lease budget and registry for independently authorized circuits.

use std::{
    collections::{HashMap, hash_map::Entry},
    io,
    sync::{Arc, Mutex},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use libp2p::Multiaddr;
use rand_core::{OsRng, RngCore as _};
use serde::Serialize;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
};

use crate::runtime::{browser_relay_egress, physical_network::public_discovery::Scope};

const MAX_LIVE_LEASES: usize = 2;
const LEASE_ID_BYTES: usize = 24;

pub(in crate::runtime::browser_host) struct AuthorizedCircuit(Multiaddr);

impl AuthorizedCircuit {
    /// The resolver must authorize both the relay entrance and the target for
    /// its own operation before converting a route. This is not a validator.
    pub(in crate::runtime::browser_host) fn after_lookup(route: Multiaddr) -> Self {
        Self(route)
    }
}

pub(in crate::runtime::browser_host) struct LeaseManager {
    slots: Arc<Semaphore>,
    leases: Mutex<HashMap<String, LeaseTask>>,
}

struct LeaseTask(JoinHandle<()>);

impl Drop for LeaseTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Serialize)]
pub(in crate::runtime::browser_host) struct LeaseReply {
    pub(in crate::runtime::browser_host) relay_address: String,
    pub(in crate::runtime::browser_host) relay_lease_id: String,
}

pub(in crate::runtime::browser_host) struct PreparedLease<'a, F> {
    owner: &'a LeaseManager,
    scope: Scope,
    address: Multiaddr,
    pump: F,
    slot: OwnedSemaphorePermit,
}

impl<F: Future<Output = io::Result<()>> + Send + 'static> PreparedLease<'_, F> {
    /// Publish only after the enclosing lookup returns on its current scope.
    pub(in crate::runtime::browser_host) fn publish(self) -> io::Result<LeaseReply> {
        let Self {
            owner,
            scope,
            address,
            pump,
            slot,
        } = self;
        scope.with_current(|| {
            owner.register(address, async move {
                let _slot = slot;
                let _ = pump.await;
            })
        })
    }
}

impl LeaseManager {
    pub(super) fn new() -> Self {
        Self {
            slots: Arc::new(Semaphore::new(MAX_LIVE_LEASES)),
            leases: Mutex::new(HashMap::new()),
        }
    }

    fn reserve(&self) -> io::Result<OwnedSemaphorePermit> {
        Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "browser relay lease limit"))
    }

    /// Reserve a shared slot and bind the authorized circuit. A dropped
    /// prepared lease releases its slot and sockets without issuing a handle.
    pub(in crate::runtime::browser_host) async fn lease(
        &self,
        scope: Scope,
        circuit: AuthorizedCircuit,
    ) -> io::Result<PreparedLease<'_, impl Future<Output = io::Result<()>> + Send + use<>>> {
        let slot = self.reserve()?;
        let (address, pump) = browser_relay_egress::prepare(scope.clone(), &circuit.0).await?;
        Ok(PreparedLease {
            owner: self,
            scope,
            address,
            pump,
            slot,
        })
    }

    fn register(
        &self,
        address: Multiaddr,
        operation: impl Future<Output = ()> + Send + 'static,
    ) -> io::Result<LeaseReply> {
        let mut bytes = [0; LEASE_ID_BYTES];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let lease_id = URL_SAFE_NO_PAD.encode(bytes);
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| io::Error::other("relay lease owner poisoned"))?;
        leases.retain(|_, task| !task.0.is_finished());
        let Entry::Vacant(entry) = leases.entry(lease_id.clone()) else {
            return Err(io::Error::other("relay lease ID collision"));
        };
        entry.insert(LeaseTask(tokio::spawn(operation)));
        Ok(LeaseReply {
            relay_address: address.to_string(),
            relay_lease_id: lease_id,
        })
    }

    pub(in crate::runtime::browser_host) fn release(&self, lease_id: &str) -> io::Result<bool> {
        let lease = self
            .leases
            .lock()
            .map_err(|_| io::Error::other("relay lease owner poisoned"))?
            .remove(lease_id);
        Ok(lease.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::pending, time::Duration};

    #[tokio::test]
    async fn held_and_published_leases_share_capacity_and_release() {
        let manager = LeaseManager::new();
        let slot = manager.reserve().unwrap();
        let staged = manager.reserve().unwrap();
        assert_eq!(
            manager.reserve().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let reply = manager
            .register(Multiaddr::empty(), async move {
                let _slot = slot;
                pending::<()>().await;
            })
            .unwrap();
        assert_eq!(
            manager.reserve().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(manager.release(&reply.relay_lease_id).unwrap());
        assert!(!manager.release(&reply.relay_lease_id).unwrap());
        let granted = tokio::time::timeout(Duration::from_secs(1), manager.slots.acquire())
            .await
            .unwrap()
            .unwrap();
        drop((staged, granted));
        assert_eq!(manager.slots.available_permits(), MAX_LIVE_LEASES);
    }
}
