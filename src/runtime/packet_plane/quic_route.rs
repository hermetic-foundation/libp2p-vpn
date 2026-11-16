//! Bridge kernel decisions into normal authenticated warm-path negotiation.

use super::*;

#[cfg(any(target_os = "linux", target_os = "android"))]
use super::super::physical_network::platform::egress::reconcile;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use reconcile::Event;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) enum Event {}

pub(crate) struct Reconciler {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    inner: reconcile::Reconciler,
}

impl Reconciler {
    pub(crate) fn new(runtime: &PacketPlaneQuicRuntime) -> Option<Self> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        return runtime.egress.as_ref().map(|owner| Self {
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

    pub(crate) fn apply(&self, event: Event, runtime: &mut PacketPlaneQuicRuntime) -> Vec<PeerId> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        match event {
            Event::Snapshot => {
                self.inner.submit(runtime.route_targets());
                Vec::new()
            }
            Event::Checked(decisions) => {
                let mut changed = Vec::new();
                for decision in decisions {
                    if !decision.is_current()
                        || !runtime
                            .connections
                            .get(&decision.peer)
                            .is_some_and(|connection| {
                                connection.stable_id() == decision.connection_id
                                    && Arc::ptr_eq(connection.route_token(), &decision.token)
                                    && connection.remote_address() == decision.destination
                            })
                    {
                        continue;
                    }
                    if decision.replace {
                        let previous = runtime
                            .route_refresh
                            .insert(decision.peer, Arc::clone(&decision.token));
                        if !previous
                            .as_ref()
                            .is_some_and(|token| Arc::ptr_eq(token, &decision.token))
                        {
                            changed.push(decision.peer);
                        }
                    } else {
                        runtime.route_refresh.remove(&decision.peer);
                    }
                }
                changed
            }
            Event::Unavailable => {
                eprintln!(
                    "level=warn event=packet_plane_quic_route_observer_unavailable action=retry_with_backoff"
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

impl PacketPlaneQuicRuntime {
    pub(crate) fn recheck_physical_routes(&self) {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(owner) = &self.egress {
            owner.paths_changed();
        }
    }

    pub(crate) fn route_refresh_needed(&self, peer: PeerId) -> bool {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        return self.route_refresh.get(&peer).is_some_and(|expected| {
            self.connections
                .get(&peer)
                .is_some_and(|connection| Arc::ptr_eq(connection.route_token(), expected))
        });
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = peer;
            false
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn route_targets(&self) -> Vec<reconcile::Target> {
        self.connections
            .iter()
            .filter_map(|(peer, connection)| {
                self.sessions.contains_key(peer).then_some(())?;
                Some(reconcile::Target {
                    peer: *peer,
                    connection_id: connection.stable_id(),
                    token: Arc::clone(connection.route_token()),
                    lease: connection.route_lease()?.clone(),
                    destination: connection.remote_address(),
                })
            })
            .collect()
    }
}
