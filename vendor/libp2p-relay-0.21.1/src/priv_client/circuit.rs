use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, Weak,
    },
    task::{Context, Poll},
};

use futures::task::AtomicWaker;
use libp2p_core::muxing::{StreamMuxer, StreamMuxerEvent};
use libp2p_identity::PeerId;
use libp2p_swarm::ConnectionId;

use super::{Dependencies, DependencyLease};

pub(super) type Registry = Arc<Mutex<RegistryState>>;

#[derive(Default)]
pub(super) struct RegistryState {
    pub(super) pins: HashMap<ConnectionId, Vec<Weak<Intent>>>,
    pub(super) admissions: HashMap<ConnectionId, Vec<Arc<Intent>>>,
    pub(super) connections: HashMap<ConnectionId, (PeerId, Weak<Owner>)>,
}

struct IntentStatus {
    cancelled: bool,
    constrained: bool,
    assigned: bool,
    outer: Option<ConnectionId>,
    dependencies: Option<Dependencies>,
    dependency: Option<DependencyLease>,
}

pub struct Intent {
    inner: ConnectionId,
    pub(super) peer: PeerId,
    pub(super) relay: PeerId,
    registry: Weak<Mutex<RegistryState>>,
    swarm_owned: bool,
    admitted: AtomicBool,
    status: Mutex<IntentStatus>,
    pub(super) waker: AtomicWaker,
}

impl Intent {
    pub(super) fn new(
        peer: PeerId,
        inner: ConnectionId,
        relay: PeerId,
        registry: &Registry,
        swarm_owned: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            peer,
            inner,
            relay,
            registry: Arc::downgrade(registry),
            swarm_owned,
            admitted: AtomicBool::new(false),
            status: Mutex::new(IntentStatus {
                cancelled: false,
                constrained: false,
                assigned: false,
                outer: None,
                dependencies: None,
                dependency: None,
            }),
            waker: AtomicWaker::new(),
        })
    }

    pub(super) fn cancelled(&self) -> bool {
        self.status.lock().expect("Circuit intent lock").cancelled
    }

    pub(super) fn constrained(&self) -> bool {
        self.status.lock().expect("Circuit intent lock").constrained
    }

    pub(super) fn cancel(&self) {
        self.cancel_pending(true);
    }

    // Registry callers apply constraints atomically, then wake after unlocking.
    pub(super) fn cancel_without_wake(&self) {
        self.set_cancelled(true);
    }

    fn cancel_pending(&self, constrain: bool) {
        self.set_cancelled(constrain);
        self.waker.wake();
    }

    fn set_cancelled(&self, constrain: bool) {
        let mut status = self.status.lock().expect("Circuit intent lock");
        if !self.admitted.load(Ordering::Relaxed) {
            status.cancelled = true;
            status.constrained |= constrain;
            status.dependency = None;
        }
    }

    pub(super) fn outer(&self) -> Option<ConnectionId> {
        self.status.lock().expect("Circuit intent lock").outer
    }

    pub(super) fn can_pin(&self) -> bool {
        let status = self.status.lock().expect("Circuit intent lock");
        !status.cancelled && !status.assigned && status.outer.is_none()
    }

    pub(super) fn pin(&self, outer: ConnectionId, dependencies: &Dependencies) {
        let mut status = self.status.lock().expect("Circuit intent lock");
        status.constrained = true;
        status.outer = Some(outer);
        status.dependencies = Some(dependencies.clone());
        status.dependency = Some(dependencies.lease());
    }

    pub(super) fn dispatch(&self) -> Result<Option<(ConnectionId, DependencyLease)>, ()> {
        let mut status = self.status.lock().expect("Circuit intent lock");
        status.assigned = true;
        if status.cancelled {
            status.dependency = None;
            return Err(());
        }
        Ok(status.outer.map(|outer| {
            let dependency = status.dependency.take().unwrap_or_else(|| {
                status
                    .dependencies
                    .as_ref()
                    .expect("Pinned request owner")
                    .lease()
            });
            (outer, dependency)
        }))
    }

    pub(super) fn finish_pending(&self) {
        // A branch may lose a concurrent dial race. Its sibling futures still
        // belong to the same real swarm attempt, whose outcome performs cleanup.
        if self.swarm_owned {
            return;
        }
        self.cancel_pending(false);
        self.status.lock().expect("Circuit intent lock").dependency = None;
        if let Some(registry) = self.registry.upgrade() {
            let mut registry = registry.lock().expect("Circuit registry lock");
            if let Some(records) = registry.pins.get_mut(&self.inner) {
                records.retain(|record| !std::ptr::eq(record.as_ptr(), self));
                if records.is_empty() {
                    registry.pins.remove(&self.inner);
                }
            }
        }
    }
}

impl Drop for Intent {
    fn drop(&mut self) {
        self.finish_pending();
    }
}

/// Intent guard for an existing ID-aware pending swarm circuit dial.
///
/// Create immediately after `Swarm::dial` succeeds, before polling the behaviour.
/// Drop cancels pending setup, not an admitted circuit. Only actual pending dial
/// futures own registry records; no unsubmitted-ID tombstones are retained.
pub struct CircuitDialPin(pub(super) Vec<Arc<Intent>>);

impl Drop for CircuitDialPin {
    fn drop(&mut self) {
        for intent in &self.0 {
            intent.cancel();
        }
    }
}

pub(super) struct DialLifetime {
    pub(super) intent: Arc<Intent>,
    pub(super) transferred: bool,
}

impl Drop for DialLifetime {
    fn drop(&mut self) {
        if !self.transferred {
            self.intent.finish_pending();
        }
    }
}

pub(super) struct Owner {
    pub(super) relay: PeerId,
    pub(super) outer: ConnectionId,
    pub(super) live: AtomicBool,
    registry: Weak<Mutex<RegistryState>>,
    inner: Mutex<Option<ConnectionId>>,
    intent: Option<Arc<Intent>>,
}

/// Ownership sidecar captured before Noise/Yamux consume the raw relay connection.
#[derive(Clone)]
pub struct CircuitBinding(Arc<Owner>);

impl CircuitBinding {
    pub(super) fn new(
        registry: &Registry,
        relay: PeerId,
        outer: ConnectionId,
        intent: Option<Arc<Intent>>,
    ) -> Self {
        Self(Arc::new(Owner {
            relay,
            outer,
            live: AtomicBool::new(true),
            registry: Arc::downgrade(registry),
            inner: Mutex::new(None),
            intent,
        }))
    }

    pub(super) fn check(&self, cx: &Context<'_>) -> io::Result<()> {
        if let Some(intent) = &self.0.intent {
            // Admission and cancellation serialize under status; once admitted,
            // cancellation can never change this circuit's state again.
            if intent.admitted.load(Ordering::Acquire) {
                return Ok(());
            }
            intent.waker.register(cx.waker());
            if intent.cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "circuit dial pin cancelled",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn close(&self) {
        self.0.live.store(false, Ordering::Release);
        let inner = *self.0.inner.lock().expect("Circuit association lock");
        if let (Some(inner), Some(registry)) = (inner, self.0.registry.upgrade()) {
            registry
                .lock()
                .expect("Circuit registry lock")
                .connections
                .remove(&inner);
        }
    }

    /// Wrap an authenticated muxer. Admission binds its exact local swarm CID.
    pub fn wrap_muxer<M: StreamMuxer>(self, peer: PeerId, muxer: M) -> CircuitMuxer<M> {
        CircuitMuxer {
            inner: Box::pin(muxer),
            binding: self,
            peer,
            invalid: false,
        }
    }

    fn bind(&self, peer: PeerId, inner: ConnectionId) -> bool {
        let Some(registry) = self.0.registry.upgrade() else {
            return false;
        };
        let mut registry = registry.lock().expect("Circuit registry lock");
        let mut associated = self.0.inner.lock().expect("Circuit association lock");
        if !self.0.live.load(Ordering::Acquire)
            || associated.is_some()
            || registry.connections.contains_key(&inner)
        {
            return false;
        }
        if let Some(intent) = &self.0.intent {
            let status = intent.status.lock().expect("Circuit intent lock");
            if status.cancelled || intent.peer != peer || intent.inner != inner {
                return false;
            }
            intent.admitted.store(true, Ordering::Release);
        }
        *associated = Some(inner);
        registry
            .connections
            .insert(inner, (peer, Arc::downgrade(&self.0)));
        true
    }
}

/// Multiplexer that binds authenticated circuit ownership through the swarm hook.
pub struct CircuitMuxer<M: StreamMuxer> {
    inner: Pin<Box<M>>,
    binding: CircuitBinding,
    peer: PeerId,
    invalid: bool,
}

impl<M: StreamMuxer> Drop for CircuitMuxer<M> {
    fn drop(&mut self) {
        self.binding.close();
    }
}

impl<M> StreamMuxer for CircuitMuxer<M>
where
    M: StreamMuxer,
    M::Error: Send + Sync + 'static,
{
    type Substream = M::Substream;
    type Error = io::Error;

    fn on_swarm_connection(self: Pin<&mut Self>, id: usize) {
        let this = self.get_mut();
        this.invalid = !this
            .binding
            .bind(this.peer, ConnectionId::new_unchecked(id));
        this.inner.as_mut().on_swarm_connection(id);
    }
    fn poll_inbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Self::Substream>> {
        let this = self.get_mut();
        if this.invalid {
            return Poll::Ready(Err(io::Error::other("invalid circuit association")));
        }
        this.inner
            .as_mut()
            .poll_inbound(cx)
            .map_err(io::Error::other)
    }
    fn poll_outbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Self::Substream>> {
        let this = self.get_mut();
        if this.invalid {
            return Poll::Ready(Err(io::Error::other("invalid circuit association")));
        }
        this.inner
            .as_mut()
            .poll_outbound(cx)
            .map_err(io::Error::other)
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .inner
            .as_mut()
            .poll_close(cx)
            .map_err(io::Error::other)
    }
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<StreamMuxerEvent>> {
        let this = self.get_mut();
        if this.invalid {
            return Poll::Ready(Err(io::Error::other("invalid circuit association")));
        }
        this.inner.as_mut().poll(cx).map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::task::{waker, ArcWake};

    struct WakeProbe;

    impl ArcWake for WakeProbe {
        fn wake_by_ref(_: &Arc<Self>) {}
    }

    #[test]
    fn admitted_io_neither_locks_pending_status_nor_replaces_its_waker() {
        let registry = Registry::default();
        let peer = PeerId::random();
        let relay = PeerId::random();
        let inner = ConnectionId::new_unchecked(1);
        let intent = Intent::new(peer, inner, relay, &registry, false);
        let binding = CircuitBinding::new(
            &registry,
            relay,
            ConnectionId::new_unchecked(2),
            Some(intent.clone()),
        );
        let pending_waker = waker(Arc::new(WakeProbe));
        binding.check(&Context::from_waker(&pending_waker)).unwrap();
        assert!(binding.bind(peer, inner));
        let established_waker = waker(Arc::new(WakeProbe));
        let status = intent.status.lock().unwrap();
        binding
            .check(&Context::from_waker(&established_waker))
            .unwrap();
        assert!(intent.waker.take().unwrap().will_wake(&pending_waker));
        drop(status);
        intent.cancel();
        assert!(!intent.cancelled(), "admitted circuits cannot be cancelled");
        binding.close();
    }
}
