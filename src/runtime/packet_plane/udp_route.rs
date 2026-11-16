//! Audit prepared UDP session owners without changing sockets or key sessions.

use super::*;

#[cfg(any(target_os = "linux", target_os = "android"))]
use super::super::physical_network::platform::egress::reconcile;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::collections::HashSet;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use reconcile::Event;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) enum Event {}

pub(crate) struct Reconciler {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    inner: reconcile::Reconciler,
}

impl Reconciler {
    pub(crate) fn new(runtime: &PacketPlaneRuntime) -> Option<Self> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        return runtime.udp_owner.as_ref().map(|owner| Self {
            inner: reconcile::Reconciler::new(Arc::clone(owner)),
        });
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = runtime;
            None
        }
    }

    pub(crate) async fn next(&mut self) -> Option<Event> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        return self.inner.next().await;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        std::future::pending().await
    }

    pub(crate) fn apply(&self, event: Event, runtime: &mut PacketPlaneRuntime) -> Vec<PeerId> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        match event {
            Event::Snapshot => {
                // Renewal changes the token even when the peer and endpoint
                // are unchanged. Old flags must not retain retired sessions.
                runtime.udp_route_refresh.retain(|(peer, listener), token| {
                    runtime.sessions.contains_key(peer)
                        && runtime.udp_routes.get(peer).is_some_and(|routes| {
                            Arc::ptr_eq(token, &routes.token)
                                && routes
                                    .sockets
                                    .get(*listener)
                                    .is_some_and(|slot| slot.path.get().is_some())
                        })
                });
                self.inner.submit(runtime.udp_route_targets());
                Vec::new()
            }
            Event::Checked(decisions) => {
                let mut changed = Vec::new();
                let mut notified = HashSet::new();
                for decision in decisions {
                    if !decision.is_current()
                        || !runtime.sessions.contains_key(&decision.peer)
                        || !runtime
                            .udp_routes
                            .get(&decision.peer)
                            .is_some_and(|routes| {
                                Arc::ptr_eq(&routes.token, &decision.token)
                                    && routes
                                        .sockets
                                        .get(decision.connection_id)
                                        .and_then(|slot| slot.path.get())
                                        .is_some_and(|path| {
                                            path.lease.context.destination == decision.destination
                                        })
                            })
                    {
                        continue;
                    }
                    let key = (decision.peer, decision.connection_id);
                    if decision.replace {
                        let previous = runtime
                            .udp_route_refresh
                            .insert(key, Arc::clone(&decision.token));
                        if !previous
                            .as_ref()
                            .is_some_and(|token| Arc::ptr_eq(token, &decision.token))
                            && notified.insert(decision.peer)
                        {
                            changed.push(decision.peer);
                        }
                    } else {
                        // A healthy sibling listener cannot clear this path's flag.
                        runtime.udp_route_refresh.remove(&key);
                    }
                }
                changed
            }
            Event::Unavailable => {
                eprintln!(
                    "level=warn event=packet_plane_udp_route_observer_unavailable action=retry_with_backoff"
                );
                Vec::new()
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = runtime;
            match event {}
        }
    }
}

impl PacketPlaneRuntime {
    pub(crate) fn recheck_physical_routes(&self) {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(owner) = &self.udp_owner {
            owner.paths_changed();
        }
    }

    pub(crate) fn route_refresh_needed(&self, peer: PeerId) -> bool {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        return self.sessions.contains_key(&peer)
            && self.udp_routes.get(&peer).is_some_and(|routes| {
                routes.sockets.iter().enumerate().any(|(listener, slot)| {
                    slot.path.get().is_some()
                        && self
                            .udp_route_refresh
                            .get(&(peer, listener))
                            .is_some_and(|token| Arc::ptr_eq(token, &routes.token))
                })
            });
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = peer;
            false
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn udp_route_targets(&self) -> Vec<reconcile::Target> {
        self.udp_routes
            .iter()
            .filter(|(peer, _)| self.sessions.contains_key(*peer))
            .flat_map(|(peer, routes)| {
                routes
                    .sockets
                    .iter()
                    .enumerate()
                    .filter_map(move |(listener, slot)| {
                        let path = slot.path.get()?;
                        Some(reconcile::Target {
                            peer: *peer,
                            connection_id: listener,
                            token: Arc::clone(&routes.token),
                            lease: path.lease.clone(),
                            destination: path.lease.context.destination,
                        })
                    })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
