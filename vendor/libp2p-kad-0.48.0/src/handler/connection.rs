use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use super::HandlerQueueUsage;

/// Shared only by an existing connection record and its native handler.
#[derive(Clone, Default)]
pub(crate) struct ConnectionResources {
    state: Arc<Mutex<State>>,
    cleanup: Arc<AtomicBool>,
}

#[derive(Default)]
struct State {
    dropped: bool,
    dispatches: usize,
    notifications: usize,
    saturated: bool,
    usage: HandlerQueueUsage,
}

impl ConnectionResources {
    pub(crate) fn with_cleanup(cleanup: &Arc<AtomicBool>) -> Self {
        Self {
            state: Arc::default(),
            cleanup: Arc::clone(cleanup),
        }
    }

    pub(crate) fn tracker(&self) -> ConnectionTracker {
        ConnectionTracker {
            resources: self.clone(),
            previous: HandlerQueueUsage::default(),
        }
    }

    pub(crate) fn live(&self) -> bool {
        !self
            .state
            .lock()
            .expect("connection resources poisoned")
            .dropped
    }

    pub(crate) fn dispatched(&self) {
        let mut state = self.state.lock().expect("connection resources poisoned");
        match state.dispatches.checked_add(1) {
            Some(count) => state.dispatches = count,
            None => state.saturated = true,
        }
    }

    pub(crate) fn received_notification(&self) {
        let mut state = self.state.lock().expect("connection resources poisoned");
        state.notifications = state.notifications.saturating_sub(1);
    }

    pub(crate) fn busy(&self) -> bool {
        let state = self.state.lock().expect("connection resources poisoned");
        state.saturated
            || state.dispatches > 0
            || state.notifications > 0
            || state.usage.requests > 0
            || state.usage.pending_negotiations > 0
            || state.usage.active_outbound_streams > 0
            || state.usage.active_inbound_streams > 0
            || state.usage.queued_rejections > 0
    }
}

pub(crate) struct ConnectionTracker {
    resources: ConnectionResources,
    previous: HandlerQueueUsage,
}

impl ConnectionTracker {
    /// Publish transitions atomically so dispatch/notification handover never
    /// exposes an idle gap between queues owned by different pollers.
    pub(super) fn update(
        &mut self,
        usage: HandlerQueueUsage,
        received_dispatch: bool,
        emitted_notification: bool,
    ) {
        if !received_dispatch && !emitted_notification && usage == self.previous {
            return;
        }
        let mut state = self
            .resources
            .state
            .lock()
            .expect("connection resources poisoned");
        if received_dispatch {
            state.dispatches = state.dispatches.saturating_sub(1);
        }
        if emitted_notification {
            match state.notifications.checked_add(1) {
                Some(count) => state.notifications = count,
                None => state.saturated = true,
            }
        }
        state.usage = usage;
        self.previous = usage;
    }
}

impl Drop for ConnectionTracker {
    fn drop(&mut self) {
        let mut state = self
            .resources
            .state
            .lock()
            .expect("connection resources poisoned");
        state.dropped = true;
        state.usage = HandlerQueueUsage::default();
        drop(state);
        self.resources.cleanup.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_codec_and_notification_handover_remains_busy_until_delivery() {
        let resources = ConnectionResources::default();
        let mut tracker = resources.tracker();
        assert!(resources.live());
        assert!(!resources.busy());
        resources.dispatched();
        assert!(resources.busy());
        tracker.update(
            HandlerQueueUsage {
                requests: 1,
                ..Default::default()
            },
            true,
            false,
        );
        assert!(resources.busy());
        tracker.update(HandlerQueueUsage::default(), false, true);
        assert!(
            resources.busy(),
            "terminal notification is not delivered yet"
        );
        resources.received_notification();
        assert!(!resources.busy());
        drop(tracker);
        assert!(!resources.live());
    }

    #[test]
    fn siblings_are_independent_and_closed_handlers_release_codec_gauges() {
        let first = ConnectionResources::default();
        let second = ConnectionResources::default();
        let mut tracker = first.tracker();
        tracker.update(
            HandlerQueueUsage {
                active_inbound_streams: 1,
                ..Default::default()
            },
            false,
            false,
        );
        assert!(first.busy());
        assert!(!second.busy());
        drop(tracker);
        assert!(!first.live());
        assert!(!first.busy());
    }

    #[test]
    fn counter_exhaustion_fails_closed() {
        let resources = ConnectionResources::default();
        resources.state.lock().unwrap().dispatches = usize::MAX;
        resources.dispatched();
        resources.state.lock().unwrap().dispatches = 0;
        assert!(resources.busy());
    }

    #[test]
    fn handler_drop_requests_cleanup_and_later_drops_rearm_it() {
        let cleanup = Arc::new(AtomicBool::new(false));
        let first = ConnectionResources::with_cleanup(&cleanup);
        let tracker = first.tracker();
        assert!(!cleanup.load(Ordering::Acquire));
        drop(tracker);
        assert!(cleanup.swap(false, Ordering::AcqRel));
        let second = ConnectionResources::with_cleanup(&cleanup);
        let tracker = second.tracker();
        assert!(!cleanup.load(Ordering::Acquire));
        drop(tracker);
        assert!(cleanup.load(Ordering::Acquire));
    }
}
