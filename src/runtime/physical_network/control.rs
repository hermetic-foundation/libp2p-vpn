//! Exact authenticated control-connection ownership, independent of UDP tuples.

pub(crate) mod reconcile;

use super::platform::{
    SocketProtocol,
    egress::{Egress, RouteEpoch, RouteLease},
};
use super::public_discovery::Scope;
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
    public_discovery_dials: BTreeMap<ConnectionId, Scope>,
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
    public_discovery: Option<Scope>,
}

impl Snapshot {
    pub(crate) fn has_public_discovery_scope(&self) -> bool {
        self.public_discovery.is_some()
    }

    /// This authenticated owner was created by a public dial and still belongs
    /// to its captured epoch. Callers needing an adopted muxer use `connection()`.
    pub(crate) fn is_public_discovery_current(&self) -> bool {
        self.is_live()
            && self
                .public_discovery
                .as_ref()
                .is_some_and(Scope::is_current)
    }

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
    /// Register before handing the dial to Swarm (including behaviour-generated dials).
    /// Failure must deny the dial. Clear the intent at the exact swarm terminal event.
    pub(crate) fn mark_public_discovery_dial(&self, id: ConnectionId) -> io::Result<()> {
        self.mark_public_discovery_dial_from(id, || Scope::new(Arc::clone(&self.egress)))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn mark_public_discovery_dial_in_scope(
        &self,
        id: ConnectionId,
        scope: &Scope,
    ) -> io::Result<()> {
        if !scope.uses_egress(&self.egress) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "public discovery scope has a different egress owner",
            ));
        }
        scope.check()?;
        self.mark_public_discovery_dial_from(id, || Ok(scope.clone()))
    }

    fn mark_public_discovery_dial_from(
        &self,
        id: ConnectionId,
        scope: impl FnOnce() -> io::Result<Scope>,
    ) -> io::Result<()> {
        use std::collections::btree_map::Entry;
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("control route owner poisoned"))?;
        let full = state.public_discovery_dials.len() >= self.limit;
        if let Entry::Vacant(entry) = state.public_discovery_dials.entry(id) {
            if full {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "public discovery dial limit",
                ));
            }
            entry.insert(scope()?);
        }
        Ok(())
    }

    pub(crate) fn finish_public_discovery_dial(&self, id: ConnectionId) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .public_discovery_dials
            .remove(&id);
    }

    pub(crate) fn public_discovery_dial(&self, id: ConnectionId) -> io::Result<Option<Scope>> {
        Ok(self
            .state
            .lock()
            .map_err(|_| io::Error::other("control route owner poisoned"))?
            .public_discovery_dials
            .get(&id)
            .cloned())
    }

    /// Swarm has bound an authenticated muxer before delivering ConnectionEstablished,
    /// even when the TCP muxer has not yet been polled for adoption.
    pub(crate) fn public_discovery_connection_available(
        &self,
        peer: PeerId,
        id: ConnectionId,
    ) -> bool {
        self.bound_connection(peer, id)
            .is_some_and(|route| route.is_public_discovery_current())
    }

    /// Runtime recovery intent, not a list of ordinary public routing peers.
    pub(crate) fn set_network_fallback_peers(&self, peers: impl IntoIterator<Item = PeerId>) {
        let peers = peers.into_iter().collect();
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .network_fallback_peers = peers;
    }

    #[cfg(any(target_os = "android", test))]
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

    pub(crate) fn new(limit: u32) -> Self {
        Self::with_egress(limit, Egress::for_control())
    }

    pub(crate) fn with_egress(limit: u32, egress: Egress) -> Self {
        Self {
            egress: Arc::new(egress),
            state: Mutex::new(State::default()),
            limit: usize::try_from(limit).unwrap_or(usize::MAX),
        }
    }

    #[cfg(test)]
    pub(crate) fn register(
        self: &Arc<Self>,
        peer: PeerId,
        lease: RouteLease,
    ) -> io::Result<Registration> {
        self.register_scoped(peer, lease, None)
    }

    pub(crate) fn register_scoped(
        self: &Arc<Self>,
        peer: PeerId,
        lease: RouteLease,
        public_discovery: Option<Scope>,
    ) -> io::Result<Registration> {
        if let Some(scope) = &public_discovery {
            scope.check()?;
            if lease.epoch() != *scope.epoch() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "public discovery route epoch mismatch",
                ));
            }
        }
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
                public_discovery,
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
        if !route.lease.is_current()
            || !route.is_live()
            || route
                .public_discovery
                .as_ref()
                .is_some_and(|scope| !scope.is_current())
        {
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
