//! Exact authenticated control-connection ownership, independent of UDP tuples.

pub(crate) mod reconcile;

use super::platform::{
    SocketProtocol,
    egress::{Egress, RouteEpoch, RouteLease},
};
use libp2p::PeerId;
use libp2p::swarm::ConnectionId;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
};

pub(crate) struct ControlRoutes {
    pub(crate) egress: Arc<Egress>,
    state: Mutex<State>,
    limit: usize,
}

#[derive(Default)]
struct State {
    next: u64,
    routes: BTreeMap<u64, Snapshot>,
    network_fallback_peers: BTreeSet<PeerId>,
    preferred_validation: [BTreeSet<PeerId>; 2],
}

#[derive(Clone, Copy)]
pub(crate) enum PreferredValidation {
    Overlay,
    Infrastructure,
}

#[derive(Clone, Debug)]
pub(crate) struct Snapshot {
    pub(crate) id: u64,
    pub(crate) peer: PeerId,
    pub(crate) lease: RouteLease,
    pub(crate) connection_id: Option<ConnectionId>,
    token: Arc<()>,
    inspection: Option<(RouteEpoch, bool)>,
    status: Arc<AtomicU8>,
}

impl Snapshot {
    pub(crate) fn inspection_epoch(&self) -> Option<RouteEpoch> {
        self.refresh_required()?;
        self.inspection.as_ref().map(|(epoch, _)| epoch.clone())
    }

    pub(crate) fn is_live(&self) -> bool {
        self.status.load(Ordering::Acquire) != 2
    }
    pub(crate) fn is_adopted(&self) -> bool {
        self.status.load(Ordering::Acquire) == 1
    }

    pub(crate) fn refresh_required(&self) -> Option<bool> {
        let (epoch, replace) = self.inspection.as_ref()?;
        (self.is_live() && self.is_adopted() && epoch.is_current()).then_some(*replace)
    }
}

pub(crate) struct Registration {
    owner: Arc<ControlRoutes>,
    id: u64,
    status: Arc<AtomicU8>,
}

impl ControlRoutes {
    /// Runtime recovery intent, not a list of ordinary public routing peers.
    pub(crate) fn set_network_fallback_peers(&self, peers: impl IntoIterator<Item = PeerId>) {
        let peers = peers.into_iter().collect();
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .network_fallback_peers = peers;
    }

    pub(crate) fn network_fallback_allowed(&self, peer: Option<PeerId>) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        peer.is_some_and(|peer| {
            state.network_fallback_peers.contains(&peer)
                && state
                    .preferred_validation
                    .iter()
                    .all(|peers| !peers.contains(&peer))
        })
    }

    pub(crate) fn mark_preferred_validation(&self, scope: PreferredValidation, peer: PeerId) {
        let index = match scope {
            PreferredValidation::Overlay => 0,
            PreferredValidation::Infrastructure => 1,
        };
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .preferred_validation[index]
            .insert(peer);
    }

    pub(crate) fn set_preferred_validation(
        &self,
        scope: PreferredValidation,
        peers: impl IntoIterator<Item = PeerId>,
    ) {
        let index = match scope {
            PreferredValidation::Overlay => 0,
            PreferredValidation::Infrastructure => 1,
        };
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .preferred_validation[index] = peers.into_iter().collect();
    }

    pub(crate) fn allow_network_fallback_peer(&self, peer: PeerId) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .network_fallback_peers
            .insert(peer);
    }

    pub(crate) fn new(limit: u32) -> Self {
        Self {
            egress: Arc::new(Egress::for_control()),
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
            let event = match route.lease.context.protocol {
                SocketProtocol::Tcp => "control_tcp_route_owned",
                SocketProtocol::Udp => "control_quic_route_owned",
            };
            #[cfg(target_os = "android")]
            let network = {
                let [handle, incarnation, revision] = route.lease.network_identity();
                format!(
                    " network_handle={handle} network_incarnation={incarnation} network_revision={revision}"
                )
            };
            #[cfg(not(target_os = "android"))]
            let network = "";
            eprintln!(
                "level=info event={} peer={} route={} connection_id={} generation={} interface={} source={} role={}{}",
                event,
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
                network,
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

#[cfg(all(test, target_os = "linux"))]
mod tests;
