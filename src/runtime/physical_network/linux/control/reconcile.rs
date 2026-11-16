//! Inspect exact adopted control owners on route events without dialing peers.

use super::{ControlRoutes, Snapshot};
use crate::runtime::physical_network::linux::egress::reconcile;
use std::{
    sync::Arc,
    task::{Context, Poll},
};

pub(crate) struct Reconciler {
    routes: Arc<ControlRoutes>,
    inner: reconcile::Reconciler,
    stopped: bool,
    unavailable: bool,
}

impl Reconciler {
    pub(crate) fn new(routes: Arc<ControlRoutes>) -> Self {
        Self {
            inner: reconcile::Reconciler::new(Arc::clone(&routes.egress)),
            routes,
            stopped: false,
            unavailable: false,
        }
    }

    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) {
        if self.stopped {
            return;
        }
        for _ in 0..4 {
            match self.inner.poll_next(cx) {
                Poll::Pending => return,
                Poll::Ready(None) => {
                    self.stopped = true;
                    eprintln!(
                        "level=warn event=control_tcp_route_observer_stopped action=preserve_connections"
                    );
                    return;
                }
                Poll::Ready(Some(reconcile::Event::Snapshot)) => self
                    .inner
                    .submit(self.routes.snapshot().iter().filter_map(target).collect()),
                Poll::Ready(Some(reconcile::Event::Checked(decisions))) => {
                    self.unavailable = false;
                    for decision in decisions {
                        self.apply(&decision);
                    }
                }
                Poll::Ready(Some(reconcile::Event::Unavailable)) => {
                    if !self.unavailable {
                        eprintln!(
                            "level=warn event=control_tcp_route_observer_unavailable action=retry_with_backoff"
                        );
                        self.unavailable = true;
                    }
                }
            }
        }
        // Drain a bounded batch; the next empty poll registers the channel waker.
        cx.waker().wake_by_ref();
    }

    fn apply(&self, decision: &reconcile::Decision) {
        let Ok(id) = u64::try_from(decision.connection_id) else {
            return;
        };
        let mut state = self
            .routes
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(route) = state.routes.get_mut(&id) else {
            return;
        };
        if !decision.is_current()
            || !route.is_adopted()
            || !route.is_live()
            || route.connection_id.is_none()
            || crate::PeerId::from_libp2p(route.peer) != decision.peer
            || !Arc::ptr_eq(&route.token, &decision.token)
            || route.lease.context.destination != decision.destination
        {
            return;
        }
        let previous = route.inspection.as_ref().map(|(_, replace)| *replace);
        route.inspection = Some((decision.epoch(), decision.replace));
        if route.refresh_required() != Some(decision.replace) {
            return;
        }
        if previous != Some(decision.replace) && (decision.replace || previous == Some(true)) {
            let event = match route.lease.context.protocol {
                crate::runtime::physical_network::linux::SocketProtocol::Tcp => {
                    "control_tcp_route_preference_changed"
                }
                crate::runtime::physical_network::linux::SocketProtocol::Udp => {
                    "control_quic_route_preference_changed"
                }
            };
            eprintln!(
                "level=info event={event} peer={} route={} connection_id={} generation={} replacement_required={} action=preserve_until_validated",
                route.peer,
                route.id,
                route.connection_id.expect("checked swarm connection"),
                decision.generation(),
                decision.replace
            );
        }
    }
}

fn target(route: &Snapshot) -> Option<reconcile::Target> {
    if !route.is_adopted() || !route.is_live() || route.connection_id.is_none() {
        return None;
    }
    Some(reconcile::Target {
        peer: crate::PeerId::from_libp2p(route.peer),
        connection_id: usize::try_from(route.id).ok()?,
        token: Arc::clone(&route.token),
        lease: route.lease.clone(),
        destination: route.lease.context.destination,
    })
}

#[cfg(test)]
mod tests;
