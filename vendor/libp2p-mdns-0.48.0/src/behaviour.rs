// Copyright 2018 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

mod iface;
#[cfg(all(test, feature = "tokio"))]
mod policy_tests;
mod socket;
mod timer;

use std::{
    cmp,
    collections::{
        hash_map::{Entry, HashMap},
        HashSet, VecDeque,
    },
    convert::Infallible,
    fmt,
    future::Future,
    io,
    net::IpAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock,
    },
    task::{Context, Poll},
    time::Instant,
};

use futures::{channel::mpsc, task::AtomicWaker, Stream, StreamExt};
use if_watch::IfEvent;
use libp2p_core::{transport::PortUse, Endpoint, Multiaddr};
use libp2p_identity::PeerId;
use libp2p_swarm::{
    behaviour::FromSwarm, dummy, ConnectionDenied, ConnectionId, ListenAddresses, NetworkBehaviour,
    THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use smallvec::SmallVec;

use self::iface::InterfaceState;
type InterfaceFilter = Arc<RwLock<Option<HashSet<IpAddr>>>>;
use crate::{
    behaviour::{socket::AsyncSocket, timer::Builder},
    Config,
};

/// Ownership of mDNS sockets on one interface. Implementations must constrain
/// both incoming and outgoing traffic to that interface in `bind`.
///
/// The identity and interface index must remain stable for the lifetime of a
/// binding. A replacement interface or ownership generation needs a new identity.
/// Revocation must make `is_current` return false; it is checked before socket
/// setup and each task poll and send. `bind` receives an unbound UDP socket.
pub trait InterfaceSocketBinding: fmt::Debug + Send + Sync + 'static {
    fn identity(&self) -> [u64; 3];
    fn interface_index(&self) -> std::num::NonZeroU32;
    fn bind(&self, socket: &std::net::UdpSocket) -> io::Result<()>;
    fn is_current(&self) -> bool;

    /// Prepare both unbound sockets before multicast setup. Override this when
    /// binding can block: offload it with bounded capacity and stale fencing.
    /// Cancellation must not release capacity while backend work is still live.
    fn prepare_sockets(self: Arc<Self>, source: IpAddr) -> SocketPreparation {
        Box::pin(async move {
            let (recv, send) = iface::socket_pair(source)?;
            for socket in [&recv, &send] {
                if !self.is_current() {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                self.bind(socket)?;
            }
            if !self.is_current() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            Ok((recv, send))
        })
    }
}

/// An owned preparation; dropping it must leave no usable partially bound task.
pub type SocketPreparation =
    Pin<Box<dyn Future<Output = io::Result<(std::net::UdpSocket, std::net::UdpSocket)>> + Send>>;

type InterfaceBindings = Option<HashMap<IpAddr, Arc<dyn InterfaceSocketBinding>>>;
type BindingIdentity = ([u64; 3], std::num::NonZeroU32);
type OwnedDiscovery = ((PeerId, Multiaddr, Instant), Arc<InterfaceTaskState>);

#[derive(Debug)]
struct CachedDiscovery {
    peer: PeerId,
    addr: Multiaddr,
    observations: SmallVec<[(Instant, Arc<InterfaceTaskState>); 1]>,
    generation: Arc<()>,
}

#[derive(Debug, Clone)]
struct PendingDiscovery {
    discovery: OwnedDiscovery,
    generation: Arc<()>,
}

#[derive(Debug)]
enum PendingEvent {
    Discovered(Vec<PendingDiscovery>),
    Announce(PendingDiscovery),
    Expired(Vec<(PeerId, Multiaddr)>),
}

#[derive(Debug)]
struct InterfaceTaskState {
    source: Option<IpAddr>,
    binding: Option<Arc<dyn InterfaceSocketBinding>>,
    identity: Option<BindingIdentity>,
    revoked: AtomicBool,
    finished: AtomicBool,
    installed: AtomicBool,
    preparation: Mutex<Preparation>,
    waker: Arc<AtomicWaker>,
}

#[derive(Debug, Default)]
struct Preparation {
    opportunity: u64,
    exhausted: bool,
}

impl InterfaceTaskState {
    fn new(binding: Option<Arc<dyn InterfaceSocketBinding>>, waker: Arc<AtomicWaker>) -> Self {
        let identity = binding
            .as_ref()
            .map(|b| (b.identity(), b.interface_index()));
        Self {
            source: None,
            binding,
            identity,
            revoked: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            installed: AtomicBool::new(false),
            preparation: Mutex::new(Preparation::default()),
            waker,
        }
    }

    fn is_current(&self) -> bool {
        !self.revoked.load(Ordering::Acquire)
            && self.binding.as_ref().is_none_or(|binding| {
                binding.is_current()
                    && self.identity == Some((binding.identity(), binding.interface_index()))
            })
    }

    fn matches_binding(&self, binding: Option<&Arc<dyn InterfaceSocketBinding>>) -> bool {
        self.identity == binding.map(|b| (b.identity(), b.interface_index()))
    }
}

#[derive(Debug)]
struct InterfaceTask<H> {
    handle: H,
    state: Arc<InterfaceTaskState>,
}

impl<H: Abort> InterfaceTask<H> {
    fn abort(self) {
        // Fence a task even if its runtime has not processed the abort yet.
        self.state.revoked.store(true, Ordering::Release);
        self.handle.abort();
    }
}

struct TaskFinished(Arc<InterfaceTaskState>);

impl Drop for TaskFinished {
    fn drop(&mut self) {
        self.0.finished.store(true, Ordering::Release);
        self.0.waker.wake();
    }
}

/// An abstraction to allow for compatibility with various async runtimes.
pub trait Provider: 'static {
    /// The Async Socket type.
    type Socket: AsyncSocket;
    /// The Async Timer type.
    type Timer: Builder + Stream;
    /// The IfWatcher type.
    type Watcher: Stream<Item = std::io::Result<IfEvent>> + fmt::Debug + Unpin;

    type TaskHandle: Abort;

    /// Create a new instance of the `IfWatcher` type.
    fn new_watcher() -> Result<Self::Watcher, std::io::Error>;

    #[track_caller]
    fn spawn(task: impl Future<Output = ()> + Send + 'static) -> Self::TaskHandle;
}

#[allow(unreachable_pub)] // Not re-exported.
pub trait Abort {
    fn abort(self);
}

/// The type of a [`Behaviour`] using the `tokio` implementation.
#[cfg(feature = "tokio")]
pub mod tokio {
    use std::future::Future;

    use if_watch::tokio::IfWatcher;
    use tokio::task::JoinHandle;

    use super::Provider;
    use crate::behaviour::{socket::tokio::TokioUdpSocket, timer::tokio::TokioTimer, Abort};

    #[doc(hidden)]
    pub enum Tokio {}

    impl Provider for Tokio {
        type Socket = TokioUdpSocket;
        type Timer = TokioTimer;
        type Watcher = IfWatcher;
        type TaskHandle = JoinHandle<()>;

        fn new_watcher() -> Result<Self::Watcher, std::io::Error> {
            IfWatcher::new()
        }

        fn spawn(task: impl Future<Output = ()> + Send + 'static) -> Self::TaskHandle {
            tokio::spawn(task)
        }
    }

    impl Abort for JoinHandle<()> {
        fn abort(self) {
            JoinHandle::abort(&self)
        }
    }

    pub type Behaviour = super::Behaviour<Tokio>;
}

/// A `NetworkBehaviour` for mDNS. Automatically discovers peers on the local network and adds
/// them to the topology.
#[derive(Debug)]
pub struct Behaviour<P>
where
    P: Provider,
{
    /// InterfaceState config.
    config: Config,

    /// Iface watcher.
    if_watch: P::Watcher,

    /// Handles to tasks running the mDNS queries.
    if_tasks: HashMap<IpAddr, InterfaceTask<P::TaskHandle>>,
    available_interfaces: HashSet<IpAddr>,
    allowed_interfaces: InterfaceFilter,
    interface_bindings: InterfaceBindings,
    task_waker: Arc<AtomicWaker>,

    query_response_receiver: mpsc::Receiver<OwnedDiscovery>,
    query_response_sender: mpsc::Sender<OwnedDiscovery>,

    /// List of nodes that we have discovered, the address, and when their TTL expires.
    ///
    /// Each combination of `PeerId` and `Multiaddr` can only appear once, but the same `PeerId`
    /// can appear multiple times. Sources retain independent observation TTLs.
    discovered_nodes: SmallVec<[CachedDiscovery; 8]>,

    /// Future that fires when the TTL of at least one node in `discovered_nodes` expires.
    ///
    /// `None` if `discovered_nodes` is empty.
    closest_expiration: Option<P::Timer>,

    /// The current set of listen addresses.
    ///
    /// This is shared across all interface tasks using an [`RwLock`].
    /// The [`Behaviour`] updates this upon new [`FromSwarm`]
    /// events where as [`InterfaceState`]s read from it to answer inbound mDNS queries.
    listen_addresses: Arc<RwLock<ListenAddresses>>,

    local_peer_id: PeerId,

    /// Pending behaviour events to be emitted.
    pending_events: VecDeque<PendingEvent>,
}

impl<P: Provider> Drop for Behaviour<P> {
    fn drop(&mut self) {
        for (_, task) in self.if_tasks.drain() {
            task.abort();
        }
    }
}

impl<P> Behaviour<P>
where
    P: Provider,
{
    /// Builds a new `Mdns` behaviour.
    pub fn new(config: Config, local_peer_id: PeerId) -> io::Result<Self> {
        let (tx, rx) = mpsc::channel(10); // Chosen arbitrarily.

        Ok(Self {
            config,
            if_watch: P::new_watcher()?,
            if_tasks: Default::default(),
            available_interfaces: Default::default(),
            allowed_interfaces: Arc::new(RwLock::new(None)),
            interface_bindings: None,
            task_waker: Arc::new(AtomicWaker::new()),
            query_response_receiver: rx,
            query_response_sender: tx,
            discovered_nodes: Default::default(),
            closest_expiration: Default::default(),
            listen_addresses: Default::default(),
            local_peer_id,
            pending_events: Default::default(),
        })
    }

    /// Restrict discovery sockets to these source addresses. `None` preserves
    /// upstream address admission; an empty set disables interface tasks without dropping
    /// the behaviour or its interface watcher.
    pub fn set_allowed_interfaces(&mut self, allowed: Option<HashSet<IpAddr>>) {
        let mode_changed = {
            let mut current = self
                .allowed_interfaces
                .write()
                .unwrap_or_else(|error| error.into_inner());
            let changed = current.is_some() != allowed.is_some();
            *current = allowed;
            changed
        };
        // Owned sockets already use restricted multicast options regardless
        // of advertisement filtering. Only legacy sockets need a mode restart.
        self.reconcile_interfaces(mode_changed && self.interface_bindings.is_none());
    }

    /// Set per-address socket ownership independently of advertisement filtering.
    /// `None` preserves legacy sockets; `Some(empty)` disables discovery sockets.
    /// Only tasks whose binding identity/index changed or was revoked are retired.
    /// Binding keys are authoritative source inventory, independent of IfWatch;
    /// each binding provider must prove that its source address is available.
    pub fn set_interface_bindings(
        &mut self,
        bindings: Option<HashMap<IpAddr, Arc<dyn InterfaceSocketBinding>>>,
    ) {
        for (source, task) in &self.if_tasks {
            if !task.state.installed.load(Ordering::Acquire)
                && task
                    .state
                    .matches_binding(bindings.as_ref().and_then(|b| b.get(source)))
            {
                let mut preparation = task
                    .state
                    .preparation
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                preparation.opportunity = preparation.opportunity.saturating_add(1);
            }
        }
        self.interface_bindings = bindings;
        self.reconcile_interfaces(false);
    }

    /// Select IPv6 instead of IPv4 without losing interface inventory or policy.
    /// Repeating the current selection leaves healthy tasks running.
    pub fn set_ipv6(&mut self, enabled: bool) {
        self.config.enable_ipv6 = enabled;
        self.reconcile_interfaces(false);
    }

    fn reap_interfaces(&mut self, restart_all: bool) {
        let retired: Vec<_> = self
            .if_tasks
            .iter()
            .filter_map(|(addr, task)| {
                let revoked = restart_all
                    || task
                        .state
                        .preparation
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .exhausted
                    || !task.state.is_current()
                    || !self.interface_allowed(*addr)
                    || !task.state.matches_binding(
                        self.interface_bindings.as_ref().and_then(|b| b.get(addr)),
                    );
                (revoked || task.state.finished.load(Ordering::Acquire)).then_some((*addr, revoked))
            })
            .collect();
        for (addr, revoked) in retired {
            if let Some(task) = self.if_tasks.remove(&addr) {
                // Completion alone does not revoke already received data.
                // Its owner is still checked against current policy at dispatch.
                if revoked {
                    task.abort();
                }
            }
        }
    }

    fn interface_candidates(&self) -> Vec<IpAddr> {
        match &self.interface_bindings {
            Some(bindings) => bindings.keys().copied().collect(),
            None => self.available_interfaces.iter().copied().collect(),
        }
    }

    fn reconcile_interfaces(&mut self, restart_all: bool) {
        self.reap_interfaces(restart_all);
        for addr in self.interface_candidates() {
            self.start_interface(addr);
        }
    }

    fn on_interface_event(&mut self, event: IfEvent) {
        match event {
            IfEvent::Up(inet) => {
                let addr = inet.addr();
                self.available_interfaces.insert(addr);
                self.start_interface(addr);
            }
            IfEvent::Down(inet) => {
                let addr = inet.addr();
                self.available_interfaces.remove(&addr);
                // IfWatch has no link identity. A selected, current binding is
                // authoritative even if another link loses the same address.
                let selected = self.interface_bindings.as_ref().is_some_and(|bindings| {
                    bindings
                        .get(&addr)
                        .is_some_and(|binding| binding.is_current())
                });
                if !selected {
                    if let Some(task) = self.if_tasks.remove(&addr) {
                        tracing::info!(instance=%addr, "dropping instance");
                        task.abort();
                    }
                }
            }
        }
    }

    fn interface_task_state(&self, addr: IpAddr) -> Arc<InterfaceTaskState> {
        let mut state = InterfaceTaskState::new(
            self.interface_bindings
                .as_ref()
                .and_then(|b| b.get(&addr))
                .cloned(),
            self.task_waker.clone(),
        );
        state.source = Some(addr);
        Arc::new(state)
    }

    fn discovery_owner_current(&self, owner: &Arc<InterfaceTaskState>) -> bool {
        let Some(source) = owner.source else {
            return false;
        };
        owner.is_current()
            && self.interface_allowed(source)
            && owner.matches_binding(
                self.interface_bindings
                    .as_ref()
                    .and_then(|b| b.get(&source)),
            )
            && (self.interface_bindings.is_some() || self.available_interfaces.contains(&source))
            && self
                .if_tasks
                .get(&source)
                .is_none_or(|task| Arc::ptr_eq(&task.state, owner))
    }

    fn cached_discovery_current(&self, cached: &CachedDiscovery, now: Instant) -> bool {
        cached
            .observations
            .iter()
            .any(|(expires, owner)| *expires > now && self.discovery_owner_current(owner))
    }

    fn announcement_current(&self, pending: &PendingDiscovery) -> bool {
        let ((peer, addr, _), _) = &pending.discovery;
        self.discovered_nodes.iter().any(|cached| {
            cached.peer == *peer
                && cached.addr == *addr
                && Arc::ptr_eq(&cached.generation, &pending.generation)
                && self.cached_discovery_current(cached, Instant::now())
        })
    }

    fn prune_discoveries(&mut self, now: Instant) -> Option<Instant> {
        let mut closest_expiration: Option<Instant> = None;
        let mut expired = Vec::new();
        let mut nodes = std::mem::take(&mut self.discovered_nodes);
        nodes.retain(|cached| {
            cached
                .observations
                .retain(|(expires, owner)| *expires > now && self.discovery_owner_current(owner));
            if cached.observations.is_empty() {
                tracing::info!(peer=%cached.peer, address=%cached.addr, "expired peer on address");
                expired.push((cached.peer, cached.addr.clone()));
                return false;
            }
            for (expires, _) in &cached.observations {
                closest_expiration = Some(closest_expiration.unwrap_or(*expires).min(*expires));
            }
            true
        });
        self.discovered_nodes = nodes;
        if !expired.is_empty() {
            self.pending_events
                .push_back(PendingEvent::Expired(expired));
        }
        closest_expiration
    }

    fn accept_discovery(&mut self, discovery: OwnedDiscovery) -> Option<PendingDiscovery> {
        let now = Instant::now();
        if !self.discovery_owner_current(&discovery.1) {
            return None;
        }
        self.prune_discoveries(now);
        let ((peer, addr, expiration), owner) = discovery;
        if expiration <= now {
            return None;
        }
        if let Some(cached) = self
            .discovered_nodes
            .iter_mut()
            .find(|cached| cached.peer == peer && cached.addr == addr)
        {
            if let Some((expires, _)) = cached
                .observations
                .iter_mut()
                .find(|(_, current)| Arc::ptr_eq(current, &owner))
            {
                *expires = cmp::max(*expires, expiration);
            } else if let Some(observation) = cached
                .observations
                .iter_mut()
                .find(|(_, current)| current.source == owner.source)
            {
                // Completed tasks may no longer be in if_tasks. Keep only the
                // latest observation of a source, not a history of task owners.
                *observation = (expiration, owner);
            } else {
                cached.observations.push((expiration, owner));
            }
            return None;
        }
        tracing::info!(%peer, address=%addr, "discovered peer on address");
        // Pending events can follow surviving observations of this entry, but
        // cannot attach themselves to a later incarnation of the same tuple.
        let generation = Arc::new(());
        let pending = PendingDiscovery {
            discovery: ((peer, addr.clone(), expiration), owner.clone()),
            generation: generation.clone(),
        };
        self.discovered_nodes.push(CachedDiscovery {
            peer,
            addr,
            observations: SmallVec::from_buf([(expiration, owner)]),
            generation,
        });
        Some(pending)
    }

    fn next_pending_event(&mut self) -> Option<ToSwarm<Event, Infallible>> {
        while let Some(event) = self.pending_events.pop_front() {
            match event {
                PendingEvent::Discovered(discoveries) => {
                    let addresses: Vec<_> = discoveries
                        .into_iter()
                        .filter(|d| self.announcement_current(d))
                        .map(|pending| {
                            let ((peer, addr, _), _) = pending.discovery;
                            (peer, addr)
                        })
                        .collect();
                    if !addresses.is_empty() {
                        return Some(ToSwarm::GenerateEvent(Event::Discovered(addresses)));
                    }
                }
                PendingEvent::Announce(discovery) => {
                    if self.announcement_current(&discovery) {
                        let ((peer_id, address, _), _) = discovery.discovery;
                        return Some(ToSwarm::NewExternalAddrOfPeer { peer_id, address });
                    }
                }
                PendingEvent::Expired(addresses) => {
                    let addresses: Vec<_> = addresses
                        .into_iter()
                        .filter(|(peer, addr)| {
                            !self.discovered_nodes.iter().any(|cached| {
                                cached.peer == *peer
                                    && cached.addr == *addr
                                    && self.cached_discovery_current(cached, Instant::now())
                            })
                        })
                        .collect();
                    if !addresses.is_empty() {
                        return Some(ToSwarm::GenerateEvent(Event::Expired(addresses)));
                    }
                }
            }
        }
        None
    }

    /// Source addresses of currently installed discovery tasks.
    pub fn active_interfaces(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.if_tasks
            .iter()
            .filter(|(_, task)| {
                task.state.installed.load(Ordering::Acquire)
                    && !task.state.finished.load(Ordering::Acquire)
                    && task.state.is_current()
            })
            .map(|(addr, _)| *addr)
    }

    /// Whether a source-address admission filter is installed, including an empty filter.
    pub fn has_interface_filter(&self) -> bool {
        self.allowed_interfaces
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .is_some()
    }

    /// Current source-address admission policy, for local diagnostics.
    pub fn allowed_interfaces(&self) -> Option<HashSet<IpAddr>> {
        self.allowed_interfaces
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    fn interface_allowed(&self, addr: IpAddr) -> bool {
        !addr.is_loopback()
            && !addr.is_unspecified()
            && !addr.is_multicast()
            && addr.is_ipv6() == self.config.enable_ipv6
            && self
                .allowed_interfaces
                .read()
                .unwrap_or_else(|error| error.into_inner())
                .as_ref()
                .is_none_or(|allowed| allowed.contains(&addr))
            && self.interface_bindings.as_ref().is_none_or(|bindings| {
                bindings
                    .get(&addr)
                    .is_some_and(|binding| binding.is_current())
            })
    }

    fn start_interface(&mut self, addr: IpAddr) {
        if !self.interface_allowed(addr) || self.if_tasks.contains_key(&addr) {
            return;
        }
        let task_state = self.interface_task_state(addr);
        if let Entry::Vacant(entry) = self.if_tasks.entry(addr) {
            if let Some(binding) = task_state.binding.clone() {
                let config = self.config.clone();
                let local_peer = self.local_peer_id;
                let listen_addresses = self.listen_addresses.clone();
                let sender = self.query_response_sender.clone();
                let allowed = self.allowed_interfaces.clone();
                let state = task_state.clone();
                let finished = TaskFinished(state.clone());
                let handle = P::spawn(async move {
                    let _finished = finished;
                    let mut opportunity = None;
                    let mut attempt = 0_u64;
                    loop {
                        {
                            let preparation =
                                state.preparation.lock().unwrap_or_else(|e| e.into_inner());
                            if opportunity != Some(preparation.opportunity) {
                                opportunity = Some(preparation.opportunity);
                                attempt = 0;
                            }
                        }
                        attempt += 1;
                        if !state.is_current() || !iface::source_allowed(addr, &allowed) {
                            return;
                        }
                        let prepared = binding.clone().prepare_sockets(addr).await;
                        let result = prepared.and_then(|sockets| {
                            InterfaceState::<P::Socket, P::Timer>::new(
                                addr,
                                config.clone(),
                                local_peer,
                                listen_addresses.clone(),
                                sender.clone(),
                                allowed.clone(),
                                state.clone(),
                                Some(sockets),
                            )
                        });
                        match result {
                            Ok(interface) => {
                                interface.await;
                                return;
                            }
                            Err(error) => {
                                let retryable = matches!(
                                    error.kind(),
                                    io::ErrorKind::WouldBlock
                                        | io::ErrorKind::TimedOut
                                        | io::ErrorKind::AddrNotAvailable
                                        | io::ErrorKind::AddrInUse
                                        | io::ErrorKind::NetworkUnreachable
                                        | io::ErrorKind::HostUnreachable
                                        | io::ErrorKind::ConnectionAborted
                                        | io::ErrorKind::ConnectionReset
                                        | io::ErrorKind::Interrupted
                                        | io::ErrorKind::Other
                                );
                                let failed_attempt = attempt;
                                let retry = {
                                    // Serialize terminal exhaustion with fresh opportunities.
                                    // Reconciliation can reap an exhausted task even before
                                    // TaskFinished runs, so no final event falls through a gap.
                                    let mut preparation =
                                        state.preparation.lock().unwrap_or_else(|e| e.into_inner());
                                    let fresh = opportunity != Some(preparation.opportunity);
                                    if fresh {
                                        opportunity = Some(preparation.opportunity);
                                        attempt = 0;
                                    }
                                    let retry = fresh || (retryable && attempt < 3);
                                    preparation.exhausted = !retry;
                                    retry
                                };
                                tracing::warn!(%addr, attempt=failed_attempt, retry, %error, "mDNS socket preparation failed");
                                if !retry || !state.is_current() {
                                    return;
                                }
                                P::Timer::interval(std::time::Duration::from_secs(attempt.max(1)))
                                    .next()
                                    .await;
                            }
                        }
                    }
                });
                entry.insert(InterfaceTask {
                    handle,
                    state: task_state,
                });
                return;
            }
            match InterfaceState::<P::Socket, P::Timer>::new(
                addr,
                self.config.clone(),
                self.local_peer_id,
                self.listen_addresses.clone(),
                self.query_response_sender.clone(),
                self.allowed_interfaces.clone(),
                task_state.clone(),
                None,
            ) {
                Ok(state) => {
                    let finished = TaskFinished(task_state.clone());
                    let handle = P::spawn(async move {
                        let _finished = finished;
                        state.await;
                    });
                    entry.insert(InterfaceTask {
                        handle,
                        state: task_state,
                    });
                }
                Err(error) => {
                    tracing::error!(%addr, %error, "failed to create mDNS interface task")
                }
            }
        }
    }

    /// Returns true if the given `PeerId` is in the list of nodes discovered through mDNS.
    #[deprecated(note = "Use `discovered_nodes` iterator instead.")]
    pub fn has_node(&self, peer_id: &PeerId) -> bool {
        self.discovered_nodes().any(|p| p == peer_id)
    }

    /// Returns the list of nodes that we have discovered through mDNS and that are not expired.
    pub fn discovered_nodes(&self) -> impl ExactSizeIterator<Item = &PeerId> {
        self.discovered_nodes.iter().map(|cached| &cached.peer)
    }

    /// Expires a node before the ttl.
    #[deprecated(note = "Unused API. Will be removed in the next release.")]
    pub fn expire_node(&mut self, peer_id: &PeerId) {
        let now = Instant::now();
        for cached in &mut self.discovered_nodes {
            if &cached.peer == peer_id {
                for (expires, _) in &mut cached.observations {
                    *expires = now;
                }
            }
        }
        self.closest_expiration = Some(P::Timer::at(now));
    }
}

impl<P> NetworkBehaviour for Behaviour<P>
where
    P: Provider,
{
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        _addresses: &[Multiaddr],
        _effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        let Some(peer_id) = maybe_peer else {
            return Ok(vec![]);
        };

        let now = Instant::now();
        Ok(self
            .discovered_nodes
            .iter()
            .filter(|cached| cached.peer == peer_id && self.cached_discovery_current(cached, now))
            .map(|cached| cached.addr.clone())
            .collect())
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        ev: THandlerOutEvent<Self>,
    ) {
        libp2p_core::util::unreachable(ev)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        self.listen_addresses
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .on_swarm_event(&event);
    }

    #[tracing::instrument(level = "trace", name = "NetworkBehaviour::poll", skip(self, cx))]
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.task_waker.register(cx.waker());
        // Reap without retrying failed socket setup on every swarm poll. Policy
        // reconciliation or an interface event can subsequently recreate tasks.
        self.reap_interfaces(false);
        self.prune_discoveries(Instant::now());
        loop {
            // Poll ifwatch.
            while let Poll::Ready(Some(event)) = Pin::new(&mut self.if_watch).poll_next(cx) {
                match event {
                    Ok(event) => self.on_interface_event(event),
                    Err(err) => tracing::error!("if watch returned an error: {}", err),
                }
            }
            // Emit discovered event.
            let mut discovered = Vec::new();

            while let Poll::Ready(Some(discovery)) =
                self.query_response_receiver.poll_next_unpin(cx)
            {
                if let Some(pending) = self.accept_discovery(discovery) {
                    discovered.push(pending.clone());
                    self.pending_events
                        .push_back(PendingEvent::Announce(pending));
                }
            }

            if !discovered.is_empty() {
                // Push to the front of the queue so that the behavior event is reported before
                // the individual discovered addresses.
                self.pending_events
                    .push_front(PendingEvent::Discovered(discovered));
            }
            // Reconcile queued observations before dispatch, so a fresh owner
            // can supersede an old entry without a spurious expiration event.
            if let Some(event) = self.next_pending_event() {
                return Poll::Ready(event);
            }
            // Emit expired event.
            let closest_expiration = self.prune_discoveries(Instant::now());
            if !self.pending_events.is_empty() {
                continue;
            }
            if let Some(closest_expiration) = closest_expiration {
                let mut timer = P::Timer::at(closest_expiration);
                let _ = Pin::new(&mut timer).poll_next(cx);

                self.closest_expiration = Some(timer);
            } else {
                self.closest_expiration = None;
            }

            return Poll::Pending;
        }
    }
}

/// Event that can be produced by the `Mdns` behaviour.
#[derive(Debug, Clone)]
pub enum Event {
    /// Discovered nodes through mDNS.
    Discovered(Vec<(PeerId, Multiaddr)>),

    /// The given combinations of `PeerId` and `Multiaddr` have expired.
    ///
    /// Each discovered record has a time-to-live. When this TTL expires and the address hasn't
    /// been refreshed, we remove it from the list and emit it as an `Expired` event.
    Expired(Vec<(PeerId, Multiaddr)>),
}
