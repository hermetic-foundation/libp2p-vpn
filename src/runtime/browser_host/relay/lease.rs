//! Shared lease budget and registry for independently authorized circuits.

use std::{
    collections::{HashMap, hash_map::Entry},
    io,
    sync::{Arc, Mutex, MutexGuard},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use libp2p::Multiaddr;
use serde::Serialize;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
};

use crate::runtime::{
    browser_relay_egress::{LeaseControl, LeaseId, prepare_owned, prepare_reservation},
    physical_network::public_discovery::Scope,
};

const MAX_LIVE_LEASES: usize = 2;
const LEASE_ID_ENCODED_LEN: usize = 32;

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
    leases: Mutex<HashMap<LeaseId, LeaseTask>>,
}

struct LeaseTask {
    control: LeaseControl,
    pump: JoinHandle<()>,
    kind: Kind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Member,
    Pairing,
    Inviter,
}

impl Drop for LeaseTask {
    fn drop(&mut self) {
        self.pump.abort();
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
    control: LeaseControl,
    pump: F,
    kind: Kind,
}

impl<F: Future<Output = io::Result<()>> + Send + 'static> PreparedLease<'_, F> {
    /// Publish only after the enclosing lookup returns on its current scope.
    pub(in crate::runtime::browser_host) fn publish(self) -> io::Result<LeaseReply> {
        let Self {
            owner,
            scope,
            address,
            control,
            pump,
            kind,
        } = self;
        scope.with_current(|| {
            LeaseManager::register(&mut *owner.lock()?, address, control, pump, kind)
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

    pub(super) fn reserve(&self) -> io::Result<OwnedSemaphorePermit> {
        Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "browser relay lease limit"))
    }

    /// Pairing leases share the same slots and registry but stay pending-only.
    #[allow(dead_code, reason = "pairing lookup integration is separate")]
    pub(in crate::runtime::browser_host) async fn lease(
        &self,
        scope: Scope,
        circuit: AuthorizedCircuit,
    ) -> io::Result<PreparedLease<'_, impl Future<Output = io::Result<()>> + Send + use<>>> {
        self.prepare(scope, circuit, Kind::Pairing).await
    }

    pub(in crate::runtime::browser_host) async fn lease_member(
        &self,
        scope: Scope,
        circuit: AuthorizedCircuit,
    ) -> io::Result<PreparedLease<'_, impl Future<Output = io::Result<()>> + Send + use<>>> {
        self.prepare(scope, circuit, Kind::Member).await
    }

    async fn prepare(
        &self,
        scope: Scope,
        circuit: AuthorizedCircuit,
        kind: Kind,
    ) -> io::Result<PreparedLease<'_, impl Future<Output = io::Result<()>> + Send + use<>>> {
        let slot = self.reserve()?;
        let (address, control, pump) = prepare_owned(scope.clone(), &circuit.0, slot).await?;
        Ok(PreparedLease {
            owner: self,
            scope,
            address,
            control,
            pump,
            kind,
        })
    }

    pub(super) async fn prepare_inviter(
        &self,
        scope: Scope,
        entrance: &Multiaddr,
        slot: OwnedSemaphorePermit,
    ) -> io::Result<PreparedLease<'_, impl Future<Output = io::Result<()>> + Send + use<>>> {
        let (address, control, pump) = prepare_reservation(scope.clone(), entrance, slot).await?;
        Ok(PreparedLease {
            owner: self,
            scope,
            address,
            control,
            pump,
            kind: Kind::Inviter,
        })
    }

    fn register(
        leases: &mut HashMap<LeaseId, LeaseTask>,
        address: Multiaddr,
        control: LeaseControl,
        operation: impl Future<Output = io::Result<()>> + Send + 'static,
        kind: Kind,
    ) -> io::Result<LeaseReply> {
        let id = control.id();
        // A handoff can still hold this permit after the old pump has exited.
        leases.retain(|_, task| !task.pump.is_finished() || task.control.holds_slot());
        let Entry::Vacant(entry) = leases.entry(id) else {
            return Err(io::Error::other("relay lease ID collision"));
        };
        entry.insert(LeaseTask {
            control,
            pump: tokio::spawn(async move {
                let _ = operation.await;
            }),
            kind,
        });
        Ok(LeaseReply {
            relay_address: address.to_string(),
            relay_lease_id: URL_SAFE_NO_PAD.encode(id),
        })
    }

    pub(in crate::runtime::browser_host) fn activate_or_renew(
        &self,
        lease_id: &str,
        selected: &Multiaddr,
    ) -> io::Result<bool> {
        let id = parse_id(lease_id)?;
        // Publication locks the epoch before the registry, so drop the registry
        // lock before calling control, which locks that same epoch.
        let control = self
            .lock()?
            .get(&id)
            .filter(|lease| lease.kind == Kind::Member && !lease.pump.is_finished())
            .map(|lease| lease.control.clone());
        let Some(control) = control else {
            return Ok(false);
        };
        match control.activate_or_renew(id, selected) {
            Ok(()) => Ok(true),
            Err(error) if retired(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(in crate::runtime::browser_host) async fn handoff_pairing(
        &self,
        lease_id: &str,
        selected: &Multiaddr,
    ) -> io::Result<Option<LeaseReply>> {
        let id = parse_id(lease_id)?;
        let control = self
            .lock()?
            .get(&id)
            .filter(|lease| lease.kind == Kind::Pairing && !lease.pump.is_finished())
            .map(|lease| lease.control.clone());
        let Some(control) = control else {
            return Ok(None);
        };
        let (address, replacement, pump) = match control.handoff(id, selected).await {
            Ok(prepared) => prepared,
            Err(error) if retired(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        replacement
            .scope()
            .with_current(|| {
                let mut leases = self.lock()?;
                let Some(_retired) = leases.remove(&id) else {
                    // The owner released it while the new sockets were prepared.
                    return Ok(None);
                };
                Self::register(&mut leases, address, replacement, pump, Kind::Member).map(Some)
            })
            .or_else(|error| {
                if retired(&error) {
                    Ok(None)
                } else {
                    Err(error)
                }
            })
    }

    pub(in crate::runtime::browser_host) fn release(&self, lease_id: &str) -> io::Result<bool> {
        let Some(id) = decode_id(lease_id) else {
            return Ok(false);
        };
        let lease = self.lock()?.remove(&id);
        if let Some(lease) = lease {
            lease.control.cancel(id)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn lock(&self) -> io::Result<MutexGuard<'_, HashMap<LeaseId, LeaseTask>>> {
        self.leases
            .lock()
            .map_err(|_| io::Error::other("relay lease owner poisoned"))
    }
}

fn retired(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::Interrupted
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::TimedOut
    )
}

fn parse_id(encoded: &str) -> io::Result<LeaseId> {
    decode_id(encoded)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid relay lease ID"))
}

fn decode_id(encoded: &str) -> Option<LeaseId> {
    if encoded.len() != LEASE_ID_ENCODED_LEN {
        return None;
    }
    let mut id = LeaseId::default();
    (URL_SAFE_NO_PAD.decode_slice(encoded, &mut id).ok()? == id.len()).then_some(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staged_leases_already_occupy_shared_capacity() {
        let manager = LeaseManager::new();
        let slot = manager.reserve().unwrap();
        let staged = manager.reserve().unwrap();
        assert_eq!(
            manager.reserve().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(slot);
        let granted = manager.reserve().unwrap();
        drop((staged, granted));
        assert_eq!(manager.slots.available_permits(), MAX_LIVE_LEASES);
    }
}
