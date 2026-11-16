//! Bridge kernel decisions into normal authenticated warm-path negotiation.

use super::*;

#[cfg(target_os = "linux")]
use super::super::physical_network::linux::egress::reconcile;

#[cfg(target_os = "linux")]
pub(crate) use reconcile::Event;
#[cfg(not(target_os = "linux"))]
pub(crate) enum Event {}

pub(crate) struct Reconciler {
    #[cfg(target_os = "linux")]
    inner: reconcile::Reconciler,
}

impl Reconciler {
    pub(crate) fn new(runtime: &PacketPlaneQuicRuntime) -> Option<Self> {
        #[cfg(target_os = "linux")]
        return runtime.egress.as_ref().map(|owner| Self {
            inner: reconcile::Reconciler::new(Arc::clone(owner)),
        });
        #[cfg(not(target_os = "linux"))]
        {
            let _ = runtime;
            None
        }
    }

    pub(crate) async fn next(&mut self) -> Option<Event> {
        #[cfg(target_os = "linux")]
        return self.inner.next().await;
        #[cfg(not(target_os = "linux"))]
        std::future::pending().await
    }

    pub(crate) fn apply(&self, event: Event, runtime: &mut PacketPlaneQuicRuntime) -> Vec<PeerId> {
        #[cfg(target_os = "linux")]
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
        #[cfg(not(target_os = "linux"))]
        {
            let _ = runtime;
            match event {}
        }
    }
}

impl PacketPlaneQuicRuntime {
    pub(crate) fn route_refresh_needed(&self, peer: PeerId) -> bool {
        #[cfg(target_os = "linux")]
        return self.route_refresh.get(&peer).is_some_and(|expected| {
            self.connections
                .get(&peer)
                .is_some_and(|connection| Arc::ptr_eq(connection.route_token(), expected))
        });
        #[cfg(not(target_os = "linux"))]
        {
            let _ = peer;
            false
        }
    }

    #[cfg(target_os = "linux")]
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
