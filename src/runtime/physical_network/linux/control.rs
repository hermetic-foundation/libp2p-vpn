//! Exact authenticated control-connection ownership, independent of UDP tuples.

use super::egress::{LinuxEgress, RouteLease};
use libp2p::PeerId;
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
    status: Arc<AtomicU8>,
}

impl Snapshot {
    pub(crate) fn is_live(&self) -> bool {
        self.status.load(Ordering::Acquire) != 2
    }
    pub(crate) fn is_adopted(&self) -> bool {
        self.status.load(Ordering::Acquire) == 1
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
        let status = Arc::new(AtomicU8::new(0));
        state.routes.insert(
            id,
            Snapshot {
                id,
                peer,
                lease,
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

    pub(crate) fn log_peer(&self, peer: PeerId) {
        for route in self
            .snapshot()
            .into_iter()
            .filter(|route| route.peer == peer && route.is_adopted())
        {
            eprintln!(
                "level=info event=control_tcp_route_owned peer={} route={} generation={} interface={} source={} role={}",
                peer,
                route.id,
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
}

impl Registration {
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
        if !route.lease.is_current() || !route.is_live() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "control route changed before swarm adoption",
            ));
        }
        self.status.store(1, Ordering::Release);
        let peer = route.peer;
        drop(state);
        self.owner.log_peer(peer);
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
