//! Shared lease budget and registry for independently authorized circuits.

use std::{
    collections::{HashMap, hash_map::Entry},
    io,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use libp2p::{Multiaddr, PeerId, StreamProtocol};
use serde::Serialize;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use super::{Publication, publication::LIFETIME};
use crate::runtime::{
    browser_relay_egress::{
        HandoffSource, LeaseControl, LeaseId, prepare_owned, prepare_reservation,
    },
    physical_network::public_discovery::Scope,
};

const MAX_LIVE_LEASES: usize = 2;
const LEASE_ID_ENCODED_LEN: usize = 32;
const MAX_PUBLICATION_CHILDREN: usize = 4;
const MAX_RETIRED_CHILDREN: usize = 8;
const CHILD_START_INTERVAL: Duration = Duration::from_secs(1);

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
    publication_started: bool,
    publication: Option<Arc<Publication>>,
    children: Children,
}

#[derive(Default)]
struct Children {
    used: Vec<LeaseId>,
    retired_before_start: Vec<LeaseId>,
    starts_closed: bool,
    last_start: Option<Instant>,
    active: Option<ChildPublication>,
}

struct ChildPublication {
    id: LeaseId,
    deadline: Instant,
    cancel: CancellationToken,
    publication: Option<Arc<Publication>>,
}

impl Children {
    fn retire(&mut self, id: LeaseId) {
        if self.active.as_ref().is_some_and(|active| active.id == id) {
            self.active = None;
        }
        if self.used.contains(&id) || self.retired_before_start.contains(&id) || self.starts_closed
        {
            return;
        }
        if self.retired_before_start.len() == MAX_RETIRED_CHILDREN {
            // Never evict a tombstone while a delayed request can still start.
            self.starts_closed = true;
        } else {
            self.retired_before_start.push(id);
        }
    }

    fn admit(
        &mut self,
        id: LeaseId,
        now: Instant,
        lease_deadline: Instant,
    ) -> io::Result<(Instant, CancellationToken)> {
        if self.starts_closed || self.used.contains(&id) || self.retired_before_start.contains(&id)
        {
            return Err(publication_unavailable());
        }
        if self
            .active
            .as_ref()
            .is_some_and(|active| now >= active.deadline)
        {
            self.active = None;
        }
        let deadline = lease_deadline.min(now + LIFETIME);
        if self.active.is_some()
            || self.used.len() == MAX_PUBLICATION_CHILDREN
            || now >= deadline
            || self
                .last_start
                .is_some_and(|last| now.duration_since(last) < CHILD_START_INTERVAL)
        {
            return Err(publication_unavailable());
        }
        let cancel = CancellationToken::new();
        self.used.push(id);
        self.last_start = Some(now);
        self.active = Some(ChildPublication {
            id,
            deadline,
            cancel: cancel.clone(),
            publication: None,
        });
        Ok((deadline, cancel))
    }
}

impl Drop for ChildPublication {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(publication) = &self.publication {
            publication.cancel();
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Member,
    Pairing,
    Inviter,
    CheckpointIngress,
}

impl Drop for LeaseTask {
    fn drop(&mut self) {
        if let Some(publication) = &self.publication {
            publication.cancel();
        }
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
    pub(super) fn for_checkpoint(mut self) -> Self {
        self.kind = Kind::CheckpointIngress;
        self
    }

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
            publication_started: false,
            publication: None,
            children: Children::default(),
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

    pub(in crate::runtime::browser_host) async fn handoff(
        &self,
        lease_id: &str,
        selected: &Multiaddr,
    ) -> io::Result<Option<LeaseReply>> {
        let id = parse_id(lease_id)?;
        let lease = self
            .lock()?
            .get(&id)
            .filter(|lease| !lease.pump.is_finished())
            .and_then(|lease| {
                let source = match lease.kind {
                    Kind::Pairing => HandoffSource::Pairing,
                    Kind::Member => HandoffSource::Member,
                    _ => return None,
                };
                Some((lease.control.clone(), source))
            });
        let Some((control, source)) = lease else {
            return Ok(None);
        };
        let (address, replacement, pump) = match control.handoff(id, selected, source).await {
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

    pub(in crate::runtime::browser_host) async fn begin_publication(
        &self,
        lease_id: &str,
        entrance: &Multiaddr,
        protocol: &StreamProtocol,
        bootstrap: &[(PeerId, Multiaddr)],
        key: Vec<u8>,
    ) -> io::Result<Arc<Publication>> {
        let id = parse_id(lease_id)?;
        let control = {
            let leases = self.lock()?;
            leases
                .get(&id)
                .filter(|task| {
                    task.kind == Kind::Inviter
                        && !task.pump.is_finished()
                        && !task.publication_started
                })
                .ok_or_else(publication_unavailable)?
                .control
                .clone()
        };
        control.check_publication_entrance(entrance)?;
        {
            let mut leases = self.lock()?;
            let lease = leases
                .get_mut(&id)
                .filter(|task| {
                    task.kind == Kind::Inviter
                        && !task.pump.is_finished()
                        && !task.publication_started
                })
                .ok_or_else(publication_unavailable)?;
            lease.publication_started = true;
        }
        let deadline = control
            .publication_deadline()?
            .min(Instant::now() + LIFETIME);
        let publication = Arc::new(
            Publication::discover(control.clone(), deadline, protocol, bootstrap, key).await?,
        );
        control.publication_deadline()?;
        let mut leases = self.lock()?;
        let lease = leases
            .get_mut(&id)
            .filter(|task| !task.pump.is_finished())
            .ok_or_else(publication_unavailable)?;
        lease.publication = Some(publication.clone());
        Ok(publication)
    }

    pub(in crate::runtime::browser_host) fn publication(
        &self,
        lease_id: &str,
    ) -> io::Result<Arc<Publication>> {
        let id = parse_id(lease_id)?;
        let leases = self.lock()?;
        leases
            .get(&id)
            .filter(|task| !task.pump.is_finished())
            .and_then(|task| task.publication.clone())
            .or_else(|| {
                leases
                    .values()
                    .filter(|task| !task.pump.is_finished())
                    .filter_map(|task| task.children.active.as_ref())
                    .find(|child| child.id == id && Instant::now() < child.deadline)
                    .and_then(|child| child.publication.clone())
            })
            .ok_or_else(publication_unavailable)
    }

    pub(in crate::runtime::browser_host) fn incoming_live(
        &self,
        lease_id: &str,
        entrance: &Multiaddr,
    ) -> io::Result<bool> {
        Ok(self
            .checkpoint_control(parse_id(lease_id)?)?
            .is_some_and(|control| control.check_incoming_entrance(entrance).is_ok()))
    }

    pub(in crate::runtime::browser_host) fn release_publication_child(
        &self,
        lease_id: &str,
        child_id: &str,
    ) -> io::Result<bool> {
        let (lease, child) = (parse_id(lease_id)?, parse_id(child_id)?);
        let mut leases = self.lock()?;
        let Some(task) = leases
            .get_mut(&lease)
            .filter(|task| task.kind == Kind::CheckpointIngress && !task.pump.is_finished())
        else {
            return Ok(false);
        };
        task.children.retire(child);
        Ok(true)
    }

    pub(in crate::runtime::browser_host) async fn begin_publication_child(
        &self,
        lease_id: &str,
        child_id: &str,
        entrance: &Multiaddr,
        protocol: &StreamProtocol,
        bootstrap: &[(PeerId, Multiaddr)],
        key: Vec<u8>,
    ) -> io::Result<Arc<Publication>> {
        let (id, child) = (parse_id(lease_id)?, parse_id(child_id)?);
        let control = self
            .checkpoint_control(id)?
            .ok_or_else(publication_unavailable)?;
        control.check_publication_entrance(entrance)?;
        let lease_deadline = control.publication_deadline()?;
        let (deadline, cancel) = {
            let mut leases = self.lock()?;
            if leases.contains_key(&child)
                || leases
                    .values()
                    .any(|task| task.children.used.contains(&child))
            {
                return Err(publication_unavailable());
            }
            let task = leases
                .get_mut(&id)
                .filter(|task| task.kind == Kind::CheckpointIngress && !task.pump.is_finished())
                .ok_or_else(publication_unavailable)?;
            task.children.admit(child, Instant::now(), lease_deadline)?
        };
        let discovered = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(publication_unavailable()),
            result = Publication::discover(control.clone(), deadline, protocol, bootstrap, key) => result,
        };
        let result = discovered.and_then(|publisher| {
            control.publication_deadline()?;
            Ok(Arc::new(publisher))
        });
        let mut leases = self.lock()?;
        let state = &mut leases
            .get_mut(&id)
            .ok_or_else(publication_unavailable)?
            .children;
        let active = state
            .active
            .as_mut()
            .filter(|active| active.id == child && Instant::now() < active.deadline)
            .ok_or_else(publication_unavailable)?;
        match result {
            Ok(publication) => {
                active.publication = Some(publication.clone());
                Ok(publication)
            }
            Err(error) => {
                state.active = None;
                Err(error)
            }
        }
    }

    fn checkpoint_control(&self, id: LeaseId) -> io::Result<Option<LeaseControl>> {
        Ok(self
            .lock()?
            .get(&id)
            .filter(|task| task.kind == Kind::CheckpointIngress && !task.pump.is_finished())
            .map(|task| task.control.clone()))
    }

    fn lock(&self) -> io::Result<MutexGuard<'_, HashMap<LeaseId, LeaseTask>>> {
        self.leases
            .lock()
            .map_err(|_| io::Error::other("relay lease owner poisoned"))
    }
}

fn publication_unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "locator publication lease unavailable",
    )
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
    fn release_before_delayed_start_spends_no_publication_budget() {
        let now = Instant::now();
        let lease_end = now + Duration::from_secs(60);
        let retired = [1; 24];
        let unrelated = [2; 24];
        let mut children = Children::default();

        children.retire(retired);
        children.retire(retired);
        assert_eq!(children.retired_before_start, [retired]);
        // Discovery and its stream capability are downstream of admit.
        assert!(children.admit(retired, now, lease_end).is_err());
        assert!(children.used.is_empty());
        assert!(children.last_start.is_none());
        assert!(children.active.is_none());

        let (_, cancel) = children.admit(unrelated, now, lease_end).unwrap();
        assert!(children.admit(retired, now + LIFETIME, lease_end).is_err());
        assert_eq!(children.used, [unrelated]);
        assert_eq!(children.last_start, Some(now));
        assert_eq!(children.active.as_ref().unwrap().id, unrelated);
        assert!(!cancel.is_cancelled());
    }

    #[test]
    fn retirement_overflow_refuses_new_starts_without_evicting_an_active_child() {
        let now = Instant::now();
        let lease_end = now + Duration::from_secs(60);
        let active = [0; 24];
        let mut children = Children::default();
        let (_, cancel) = children.admit(active, now, lease_end).unwrap();
        for value in 1..=(MAX_RETIRED_CHILDREN + 20) as u8 {
            children.retire([value; 24]);
        }
        assert_eq!(children.retired_before_start.len(), MAX_RETIRED_CHILDREN);
        assert_eq!(children.active.as_ref().unwrap().id, active);
        assert!(!cancel.is_cancelled());
        children.retire(active);
        assert!(cancel.is_cancelled());
        for value in [1, MAX_RETIRED_CHILDREN as u8 + 1, 250] {
            assert!(
                children
                    .admit([value; 24], now + CHILD_START_INTERVAL, lease_end)
                    .is_err()
            );
        }
        assert_eq!(children.used, [active]);
    }

    #[test]
    fn child_deadline_is_capped_by_the_lease_and_not_restarted_at_discovery() {
        let now = Instant::now();
        let mut children = Children::default();
        let lease_end = now + Duration::from_secs(5);
        let (deadline, cancel) = children.admit([1; 24], now, lease_end).unwrap();
        assert_eq!(deadline, lease_end);
        assert_eq!(children.active.as_ref().unwrap().deadline, deadline);
        assert!(children.admit([2; 24], deadline, lease_end).is_err());
        assert!(cancel.is_cancelled());
    }

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
