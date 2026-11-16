//! Exact authenticated control-connection ownership, independent of UDP tuples.

pub(crate) mod reconcile;

use super::egress::{LinuxEgress, RouteLease};
use libp2p::PeerId;
use libp2p::swarm::ConnectionId;
use std::{
    collections::BTreeMap,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
};

pub(crate) struct ControlRoutes {
    pub(crate) egress: Arc<LinuxEgress>,
    state: Mutex<State>,
    limit: usize,
}

#[derive(Default)]
struct State {
    next: u64,
    routes: BTreeMap<u64, Snapshot>,
}

#[derive(Clone, Debug)]
pub(crate) struct Snapshot {
    pub(crate) id: u64,
    pub(crate) peer: PeerId,
    pub(crate) lease: RouteLease,
    pub(crate) connection_id: Option<ConnectionId>,
    token: Arc<()>,
    inspection: Option<(u64, bool)>,
    status: Arc<AtomicU8>,
}

impl Snapshot {
    pub(crate) fn inspection_generation(&self) -> Option<u64> {
        self.refresh_required()?;
        self.inspection.map(|(generation, _)| generation)
    }

    pub(crate) fn is_live(&self) -> bool {
        self.status.load(Ordering::Acquire) != 2
    }
    pub(crate) fn is_adopted(&self) -> bool {
        self.status.load(Ordering::Acquire) == 1
    }

    pub(crate) fn refresh_required(&self) -> Option<bool> {
        let (generation, replace) = self.inspection?;
        (self.is_live() && self.is_adopted() && self.lease.generation_is_current(generation))
            .then_some(replace)
    }
}

pub(crate) struct Registration {
    owner: Arc<ControlRoutes>,
    id: u64,
    status: Arc<AtomicU8>,
}

impl ControlRoutes {
    pub(crate) fn new(limit: u32) -> Self {
        Self {
            egress: Arc::new(LinuxEgress::for_control()),
            state: Mutex::new(State::default()),
            limit: usize::try_from(limit).unwrap_or(usize::MAX),
        }
    }

    pub(crate) fn register(
        self: &Arc<Self>,
        peer: PeerId,
        lease: RouteLease,
    ) -> io::Result<Registration> {
        if !lease.is_current() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "control route changed during authentication",
            ));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("control route owner poisoned"))?;
        if state.routes.len() >= self.limit {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "control route connection limit",
            ));
        }
        let id = state
            .next
            .checked_add(1)
            .ok_or_else(|| io::Error::other("control route identifiers exhausted"))?;
        usize::try_from(id)
            .map_err(|_| io::Error::other("platform control route identifiers exhausted"))?;
        let status = Arc::new(AtomicU8::new(0));
        state.routes.insert(
            id,
            Snapshot {
                id,
                peer,
                lease,
                connection_id: None,
                token: Arc::new(()),
                inspection: None,
                status: Arc::clone(&status),
            },
        );
        state.next = id;
        drop(state);
        self.egress.paths_changed();
        Ok(Registration {
            owner: Arc::clone(self),
            id,
            status,
        })
    }

    pub(crate) fn snapshot(&self) -> Vec<Snapshot> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .routes
            .values()
            .filter(|route| route.is_live())
            .cloned()
            .collect()
    }

    pub(crate) fn log_connection(&self, peer: PeerId, connection_id: ConnectionId) {
        if let Some(route) = self.connection(peer, connection_id) {
            eprintln!(
                "level=info event=control_tcp_route_owned peer={} route={} connection_id={} generation={} interface={} source={} role={}",
                peer,
                route.id,
                connection_id,
                route.lease.route.generation,
                route.lease.route.interface_index,
                route.lease.local_addr,
                if route.lease.preferred_dial {
                    "dialer"
                } else {
                    "listener"
                },
            );
        }
    }

    pub(crate) fn connection(&self, peer: PeerId, connection_id: ConnectionId) -> Option<Snapshot> {
        self.bound_connection(peer, connection_id)
            .filter(Snapshot::is_adopted)
    }

    pub(crate) fn bound_connection(
        &self,
        peer: PeerId,
        connection_id: ConnectionId,
    ) -> Option<Snapshot> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .routes
            .values()
            .find(|route| {
                route.peer == peer && route.connection_id == Some(connection_id) && route.is_live()
            })
            .cloned()
    }
}

impl Registration {
    pub(crate) fn bind_connection(&self, connection_id: ConnectionId) -> io::Result<()> {
        let mut state = self
            .owner
            .state
            .lock()
            .map_err(|_| io::Error::other("control route owner poisoned"))?;
        let route = state
            .routes
            .get(&self.id)
            .ok_or_else(|| io::Error::other("retired control route"))?;
        if !route.is_live()
            || route
                .connection_id
                .is_some_and(|existing| existing != connection_id)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "control route cannot change swarm owner",
            ));
        }
        if state
            .routes
            .values()
            .any(|other| other.id != self.id && other.connection_id == Some(connection_id))
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "swarm connection already owns another control route",
            ));
        }
        if route.connection_id == Some(connection_id) {
            return Ok(());
        }
        state
            .routes
            .get_mut(&self.id)
            .expect("checked route owner")
            .connection_id = Some(connection_id);
        drop(state);
        self.owner.egress.paths_changed();
        Ok(())
    }

    pub(crate) fn adopt(&self) -> io::Result<()> {
        let state = self
            .owner
            .state
            .lock()
            .map_err(|_| io::Error::other("control route owner poisoned"))?;
        let route = state
            .routes
            .get(&self.id)
            .ok_or_else(|| io::Error::other("retired control route"))?;
        let connection_id = route.connection_id.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "control route has no swarm connection owner",
            )
        })?;
        if !route.lease.is_current() || !route.is_live() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "control route changed before swarm adoption",
            ));
        }
        self.status.store(1, Ordering::Release);
        let peer = route.peer;
        drop(state);
        self.owner.log_connection(peer, connection_id);
        self.owner.egress.paths_changed();
        Ok(())
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.status.store(2, Ordering::Release);
        self.owner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .routes
            .remove(&self.id);
        self.owner.egress.paths_changed();
    }
}

#[cfg(test)]
mod tests;
