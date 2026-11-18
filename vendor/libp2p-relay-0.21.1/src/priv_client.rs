// Copyright 2021 Protocol Labs.
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

//! [`NetworkBehaviour`] to act as a circuit relay v2 **client**.

pub(crate) mod circuit;
pub(crate) mod handler;
pub(crate) mod transport;

use std::{
    collections::{hash_map, HashMap, VecDeque},
    convert::Infallible,
    io::{Error, IoSlice},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll, Waker},
};

use bytes::Bytes;
pub use circuit::{CircuitBinding, CircuitDialPin, CircuitMuxer};
use either::Either;
use futures::{
    channel::mpsc::Receiver,
    future::{BoxFuture, FutureExt},
    io::{AsyncRead, AsyncWrite},
    ready,
    stream::StreamExt,
};
use libp2p_core::{
    multiaddr::Protocol,
    transport::{ListenerId, PortUse},
    Endpoint, Multiaddr,
};
use libp2p_identity::PeerId;
use libp2p_swarm::{
    behaviour::{ConnectionClosed, ConnectionEstablished, FromSwarm},
    dial_opts::{DialOpts, PeerCondition},
    dummy, ConnectionDenied, ConnectionHandler, ConnectionId, DialFailure, NetworkBehaviour,
    NotifyHandler, Stream, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use transport::Transport;

use crate::{
    multiaddr_ext::MultiaddrExt,
    priv_client::handler::Handler,
    protocol::{self, inbound_stop},
};

/// The events produced by the client `Behaviour`.
#[derive(Debug)]
pub enum Event {
    /// An outbound reservation has been accepted.
    ReservationReqAccepted {
        relay_peer_id: PeerId,
        /// Indicates whether the request replaces an existing reservation.
        renewal: bool,
        limit: Option<protocol::Limit>,
    },
    OutboundCircuitEstablished {
        relay_peer_id: PeerId,
        limit: Option<protocol::Limit>,
    },
    /// An inbound circuit has been established.
    InboundCircuitEstablished {
        src_peer_id: PeerId,
        limit: Option<protocol::Limit>,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ReservationStatus {
    Pending,
    Confirmed,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Dependencies(Arc<AtomicUsize>, Arc<AtomicBool>);

impl Dependencies {
    fn lease(&self) -> DependencyLease {
        // Saturation pins the owner until removal rather than wrapping to idle.
        let _ = self
            .0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                count.checked_add(1)
            });
        DependencyLease {
            dependencies: self.clone(),
        }
    }

    fn is_in_use(&self) -> bool {
        self.0.load(Ordering::Relaxed) != 0
    }

    fn is_reservation_draining(&self) -> bool {
        self.1.load(Ordering::Relaxed)
    }

    fn set_reservation_draining(&self, draining: bool) {
        self.1.store(draining, Ordering::Relaxed);
    }
}

/// Keeps a physical relay owner required while native work or a stream exists.
#[derive(Debug)]
pub struct DependencyLease {
    dependencies: Dependencies,
}

impl Drop for DependencyLease {
    fn drop(&mut self) {
        let _ = self
            .dependencies
            .0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count != usize::MAX).then(|| count.saturating_sub(1))
            });
    }
}

struct ConnectionDependencies {
    peer: PeerId,
    dependencies: Dependencies,
    pending_reservation_drain: Option<DependencyLease>,
    reservation_listener: Option<ListenerId>,
}

/// Optional transport ownership policy for outgoing circuit entrances.
pub trait CircuitEntrancePolicy: Send + Sync {
    /// Whether this circuit needs an outer connection scoped to the default network.
    fn requires_scope(&self, relay: PeerId, entrance: &Multiaddr, destination: PeerId) -> bool;
    /// Record the new outer dial before it reaches the physical transport.
    fn start_dial(&self, connection: ConnectionId) -> bool;
    /// Release the exact outer dial's registration on a terminal swarm event.
    fn finish_dial(&self, connection: ConnectionId);
    /// Check that an authenticated outer connection still owns its scoped route.
    fn allows_connection(&self, relay: PeerId, connection: ConnectionId) -> bool;
}

/// [`NetworkBehaviour`] implementation of the relay client
/// functionality of the circuit relay v2 protocol.
pub struct Behaviour {
    local_peer_id: PeerId,

    from_transport: Receiver<transport::TransportToBehaviourMsg>,
    /// Set of directly connected peers, i.e. not connected via a relayed
    /// connection.
    directly_connected_peers: HashMap<PeerId, Vec<ConnectionId>>,

    /// Stores the address of a pending or confirmed reservation.
    ///
    /// This is indexed by the [`ConnectionId`] to a relay server and the address is the
    /// `/p2p-circuit` address we reserved on it.
    reservation_addresses: HashMap<ConnectionId, (Multiaddr, ReservationStatus)>,

    /// Queue of actions to return when polled.
    queued_actions: VecDeque<ToSwarm<Event, Either<handler::In, Infallible>>>,

    pending_handler_commands: HashMap<ConnectionId, handler::In>,

    connection_dependencies: HashMap<ConnectionId, ConnectionDependencies>,
    listener_bindings: transport::ListenerBindings,
    circuits: circuit::Registry,
    waker: Option<Waker>,
    entrance_policy: Option<Arc<dyn CircuitEntrancePolicy>>,
}

/// Create a new client relay [`Behaviour`] with it's corresponding [`Transport`].
pub fn new(local_peer_id: PeerId) -> (Transport, Behaviour) {
    let circuits = circuit::Registry::default();
    let (transport, from_transport, listener_bindings) = Transport::new(circuits.clone());
    let behaviour = Behaviour {
        local_peer_id,
        from_transport,
        directly_connected_peers: Default::default(),
        reservation_addresses: Default::default(),
        queued_actions: Default::default(),
        pending_handler_commands: Default::default(),
        connection_dependencies: Default::default(),
        listener_bindings,
        circuits,
        waker: None,
        entrance_policy: None,
    };
    (transport, behaviour)
}

impl Behaviour {
    /// Set the application-specific scope for circuit entrance dials.
    pub fn set_circuit_entrance_policy(&mut self, policy: Arc<dyn CircuitEntrancePolicy>) {
        self.entrance_policy = Some(policy);
    }

    /// Pin an existing ID-aware pending relay dial immediately after `Swarm::dial`
    /// succeeds and before polling again. Unknown or wrong-peer inner IDs allocate
    /// nothing. Invalid targets for a matching pending peer/ID cancel that request.
    /// Selects the matching offered relay and cancels the other relay alternatives.
    /// Drop the returned guard to cancel pending setup, not an admitted circuit.
    pub fn pin_circuit_dial(
        &mut self,
        peer: PeerId,
        inner: ConnectionId,
        relay_peer: PeerId,
        outer: ConnectionId,
    ) -> Option<CircuitDialPin> {
        let valid = inner != outer
            && self
                .directly_connected_peers
                .get(&relay_peer)
                .is_some_and(|ids| ids.contains(&outer));
        let owner = self
            .connection_dependencies
            .get(&outer)
            .filter(|owner| owner.peer == relay_peer);
        // Upgraded references must outlive the lock, including wrong-peer ones:
        // their last drop may clean a standalone dial out of this registry.
        let intents;
        let registry = self.circuits.lock().expect("Circuit registry lock");
        intents = registry
            .pins
            .get(&inner)?
            .iter()
            .filter_map(|record| record.upgrade())
            .collect::<Vec<_>>();
        if !intents.iter().any(|intent| intent.peer == peer) {
            return None;
        }
        if !valid
            || owner.is_none()
            || !intents
                .iter()
                .any(|intent| intent.peer == peer && intent.relay == relay_peer)
            || intents
                .iter()
                .any(|intent| intent.peer == peer && !intent.can_pin())
        {
            for intent in intents.iter().filter(|intent| intent.peer == peer) {
                intent.cancel_without_wake();
            }
            drop(registry);
            for intent in intents.iter().filter(|intent| intent.peer == peer) {
                intent.waker.wake();
            }
            return None;
        }
        for intent in intents.iter().filter(|intent| intent.peer == peer) {
            if intent.relay == relay_peer {
                intent.pin(outer, &owner.expect("Validated owner").dependencies);
            } else {
                intent.cancel_without_wake();
            }
        }
        drop(registry);
        for intent in intents
            .iter()
            .filter(|intent| intent.peer == peer && intent.relay != relay_peer)
        {
            intent.waker.wake();
        }
        Some(CircuitDialPin(
            intents
                .into_iter()
                .filter(|intent| intent.peer == peer)
                .collect(),
        ))
    }

    /// Exact local relay owner of a live authenticated inner circuit connection.
    /// Direct, unknown, closed, and mismatched inner peer/connection pairs return
    /// `None`. Ownership is immutable and available at `ConnectionEstablished`
    /// when the transport installs the ownership-tagged muxer.
    pub fn circuit_connection_owner(
        &self,
        peer: PeerId,
        inner: ConnectionId,
    ) -> Option<(PeerId, ConnectionId)> {
        let owner = {
            let registry = self.circuits.lock().expect("Circuit registry lock");
            let (authenticated, owner) = registry.connections.get(&inner)?;
            if *authenticated != peer {
                return None;
            }
            owner.upgrade()?
        };
        if !owner.live.load(Ordering::Acquire)
            || !self
                .connection_dependencies
                .get(&owner.outer)
                .is_some_and(|physical| physical.peer == owner.relay)
        {
            return None;
        }
        Some((owner.relay, owner.outer))
    }

    /// Pin a live, unassigned transport listener to an established direct owner.
    ///
    /// The listener and connection must both belong to `peer`. The pin is used
    /// when the queued listen request is consumed, regardless of connection
    /// preferences then. If that owner disappears, the listener fails rather than
    /// falling back. After assignment only the same binding succeeds idempotently.
    /// Unknown or closed listeners and connections do not allocate state.
    pub fn pin_reservation_listener(
        &mut self,
        peer: PeerId,
        listener: ListenerId,
        connection: ConnectionId,
    ) -> bool {
        if !self
            .directly_connected_peers
            .get(&peer)
            .is_some_and(|cs| cs.contains(&connection))
            || !self
                .connection_dependencies
                .get(&connection)
                .is_some_and(|owner| owner.peer == peer)
        {
            return false;
        }
        let mut bindings = self
            .listener_bindings
            .lock()
            .expect("Listener bindings lock");
        let Some(binding) = bindings
            .get_mut(&listener)
            .filter(|binding| binding.peer == peer)
        else {
            return false;
        };
        if binding.assigned {
            return binding.connection == Some(connection);
        }
        binding.connection = Some(connection);
        true
    }

    /// The exact assigned owner of a live reservation listener, including a
    /// pending physical dial. A pin alone is not an assignment. Wrong peers,
    /// closed listeners, failed or closed owners, and unknown IDs return `None`.
    pub fn reservation_listener_connection(
        &self,
        peer: PeerId,
        listener: ListenerId,
    ) -> Option<ConnectionId> {
        let bindings = self
            .listener_bindings
            .lock()
            .expect("Listener bindings lock");
        let binding = bindings.get(&listener)?;
        if binding.peer != peer || !binding.assigned {
            return None;
        }
        let id = binding.connection?;
        self.connection_dependencies
            .get(&id)
            .filter(|owner| owner.peer == peer)
            .map(|_| id)
    }

    /// Whether native relay work or streams still require this physical connection.
    ///
    /// Includes assigned but undispatched commands, pending/confirmed reservations,
    /// stream negotiation and codec work, and handed-off relayed connections until
    /// dropped. Closing a relayed stream alone does not release its ownership.
    /// Unknown, closed, relayed, and mismatched peer/connection pairs return `false`.
    /// Unassigned transport requests cannot yet depend on a particular connection.
    /// Inbound multistream negotiation is conservatively included before the
    /// negotiated protocol is known, once surfaced by the swarm to this handler.
    /// This is a read-only, allocation-free observation, not a keep-alive policy.
    pub fn has_connection_dependencies(&self, peer: PeerId, id: ConnectionId) -> bool {
        self.connection_dependencies
            .get(&id)
            .is_some_and(|owner| owner.peer == peer && owner.dependencies.is_in_use())
    }

    fn dependencies(&mut self, peer: PeerId, id: ConnectionId) -> Dependencies {
        let owner =
            self.connection_dependencies
                .entry(id)
                .or_insert_with(|| ConnectionDependencies {
                    peer,
                    dependencies: Dependencies::default(),
                    pending_reservation_drain: None,
                    reservation_listener: None,
                });
        assert_eq!(owner.peer, peer, "Relay owner peer must match connection");
        owner.dependencies.clone()
    }

    /// Confirmed reservation owners among the current direct connections to `peer`.
    ///
    /// An advertised circuit address does not identify the owning transport: a
    /// reservation may reuse an already established connection to the relay.
    /// Pending, drain-requested reservations and closed connections are not returned.
    pub fn confirmed_reservation_connections(
        &self,
        peer: PeerId,
    ) -> impl Iterator<Item = ConnectionId> + '_ {
        self.directly_connected_peers
            .get(&peer)
            .into_iter()
            .flatten()
            .copied()
            .filter(move |connection| {
                !self.is_reservation_draining(peer, *connection)
                    && matches!(
                        self.reservation_addresses.get(connection),
                        Some((_, ReservationStatus::Confirmed))
                    )
            })
    }

    /// Stop renewing an old reservation after its replacement is confirmed.
    ///
    /// Both connections must be distinct, direct connections to `peer`. The old
    /// reservation may be pending or confirmed; the replacement must be confirmed
    /// and must not be draining. This also quiesces uncertain old setup work.
    /// Repeated valid requests succeed without queuing additional work. Unknown
    /// or invalid pairs return `false` without allocating ownership records.
    /// This does not close connections, listeners or circuits. Existing codec
    /// work may finish, but cannot restart renewals on the draining owner.
    /// A normal reservation request on the old connection clears this policy.
    pub fn begin_reservation_drain(
        &mut self,
        peer: PeerId,
        old: ConnectionId,
        replacement: ConnectionId,
    ) -> bool {
        if old == replacement {
            return false;
        }
        let Some(connections) = self.directly_connected_peers.get(&peer) else {
            return false;
        };
        for id in [old, replacement] {
            if !connections.contains(&id)
                || !self
                    .connection_dependencies
                    .get(&id)
                    .is_some_and(|owner| owner.peer == peer)
                || !self.reservation_addresses.contains_key(&id)
            {
                return false;
            }
        }
        if self.is_reservation_draining(peer, replacement)
            || !matches!(
                self.reservation_addresses.get(&replacement),
                Some((_, ReservationStatus::Confirmed))
            )
        {
            return false;
        }
        let owner = self
            .connection_dependencies
            .get_mut(&old)
            .expect("Known owner");
        if !owner.dependencies.is_reservation_draining() {
            owner.dependencies.set_reservation_draining(true);
            owner.pending_reservation_drain = Some(owner.dependencies.lease());
            if let Some(waker) = &self.waker {
                waker.wake_by_ref();
            }
        }
        true
    }

    /// Whether reservation draining has been requested for this native owner.
    ///
    /// Includes policy awaiting handler delivery. Unknown, closed, relayed and
    /// mismatched peer/connection pairs return `false` without allocating state.
    pub fn is_reservation_draining(&self, peer: PeerId, id: ConnectionId) -> bool {
        self.connection_dependencies
            .get(&id)
            .is_some_and(|owner| owner.peer == peer && owner.dependencies.is_reservation_draining())
    }

    /// Prefer a current direct connection for future reservations and circuits.
    ///
    /// Returns `false` if `connection` is not a direct connection to `peer`.
    /// Existing reservations, circuits and renewals keep their original owner.
    /// The caller must determine the connection's transport and suitability.
    /// Without a preference, the original first-established selection is retained.
    pub fn prefer_relay_connection(&mut self, peer: PeerId, connection: ConnectionId) -> bool {
        let Some(connections) = self.directly_connected_peers.get_mut(&peer) else {
            return false;
        };
        let Some(index) = connections
            .iter()
            .position(|candidate| *candidate == connection)
        else {
            return false;
        };
        connections.swap(0, index);
        true
    }

    fn on_connection_closed(
        &mut self,
        ConnectionClosed {
            peer_id,
            connection_id,
            endpoint,
            ..
        }: ConnectionClosed,
    ) {
        let pending = {
            let mut registry = self.circuits.lock().expect("Circuit registry lock");
            registry.connections.remove(&connection_id);
            if !endpoint.is_relayed() {
                registry
                    .pins
                    .values()
                    .flatten()
                    .filter_map(|record| record.upgrade())
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        };
        for intent in pending
            .into_iter()
            .filter(|intent| intent.relay == peer_id && intent.outer() == Some(connection_id))
        {
            intent.cancel();
        }
        if !endpoint.is_relayed() {
            self.connection_dependencies.remove(&connection_id);
            self.pending_handler_commands.remove(&connection_id);
            match self.directly_connected_peers.entry(peer_id) {
                hash_map::Entry::Occupied(mut connections) => {
                    let position = connections
                        .get()
                        .iter()
                        .position(|c| c == &connection_id)
                        .expect("Connection to be known.");
                    connections.get_mut().remove(position);

                    if connections.get().is_empty() {
                        connections.remove();
                    }
                }
                hash_map::Entry::Vacant(_) => {
                    unreachable!("`on_connection_closed` for unconnected peer.")
                }
            };
            if let Some((addr, ReservationStatus::Confirmed)) =
                self.reservation_addresses.remove(&connection_id)
            {
                let retained =
                    self.reservation_addresses
                        .iter()
                        .any(|(id, (other, status))| {
                            *status == ReservationStatus::Confirmed
                                && *other == addr
                                && self.connection_dependencies.get(id).is_some_and(|owner| {
                                    !owner.dependencies.is_reservation_draining()
                                })
                        });
                if !retained {
                    self.queued_actions
                        .push_back(ToSwarm::ExternalAddrExpired(addr));
                }
            }
        }
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Either<Handler, dummy::ConnectionHandler>;
    type ToSwarm = Event;

    fn handle_pending_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: Option<PeerId>,
        addresses: &[Multiaddr],
        _: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        if let Some(peer) = peer {
            let mut registry = self.circuits.lock().expect("Circuit registry lock");
            if !registry.admissions.contains_key(&id) {
                let mut intents = Vec::new();
                for relay in addresses
                    .iter()
                    .filter_map(|address| transport::relay_peer_for_dial(address, peer))
                {
                    if intents
                        .iter()
                        .any(|intent: &Arc<circuit::Intent>| intent.relay == relay)
                    {
                        continue;
                    }
                    intents.push(circuit::Intent::new(peer, id, relay, &self.circuits, true));
                }
                if !intents.is_empty() {
                    registry
                        .pins
                        .insert(id, intents.iter().map(Arc::downgrade).collect());
                    registry.admissions.insert(id, intents);
                }
            }
        }
        Ok(Vec::new())
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        let pending_handler_command = self.pending_handler_commands.remove(&connection_id);

        if local_addr.is_relayed() {
            return Ok(Either::Right(dummy::ConnectionHandler));
        }
        let dependencies = self.dependencies(peer, connection_id);
        let mut handler = Handler::new(self.local_peer_id, peer, remote_addr.clone(), dependencies)
            .with_circuit_owner(connection_id, self.circuits.clone());

        if let Some(event) = pending_handler_command {
            handler.on_behaviour_event(event)
        }

        Ok(Either::Left(handler))
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        let pending_handler_command = self.pending_handler_commands.remove(&connection_id);

        if addr.is_relayed() {
            return Ok(Either::Right(dummy::ConnectionHandler));
        }

        let dependencies = self.dependencies(peer, connection_id);
        let mut handler = Handler::new(self.local_peer_id, peer, addr.clone(), dependencies)
            .with_circuit_owner(connection_id, self.circuits.clone());

        if let Some(event) = pending_handler_command {
            handler.on_behaviour_event(event)
        }

        Ok(Either::Left(handler))
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        if let Some(policy) = &self.entrance_policy {
            match event {
                FromSwarm::ConnectionEstablished(ConnectionEstablished { connection_id, .. })
                | FromSwarm::DialFailure(DialFailure { connection_id, .. }) => {
                    policy.finish_dial(connection_id);
                }
                _ => {}
            }
        }
        if let FromSwarm::ConnectionEstablished(ConnectionEstablished { connection_id, .. }) =
            &event
        {
            let admissions = {
                let mut registry = self.circuits.lock().expect("Circuit registry lock");
                registry.pins.remove(connection_id);
                registry.admissions.remove(connection_id)
            };
            drop(admissions);
        }
        match event {
            FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            }) if !endpoint.is_relayed() => {
                self.directly_connected_peers
                    .entry(peer_id)
                    .or_default()
                    .push(connection_id);
            }
            FromSwarm::ConnectionEstablished(ConnectionEstablished { connection_id, .. }) => {
                self.circuits
                    .lock()
                    .expect("Circuit registry lock")
                    .pins
                    .remove(&connection_id);
            }
            FromSwarm::ConnectionClosed(connection_closed) => {
                self.on_connection_closed(connection_closed)
            }
            FromSwarm::DialFailure(DialFailure { connection_id, .. }) => {
                let (records, admissions) = {
                    let mut registry = self.circuits.lock().expect("Circuit registry lock");
                    (
                        registry.pins.remove(&connection_id).unwrap_or_default(),
                        registry
                            .admissions
                            .remove(&connection_id)
                            .unwrap_or_default(),
                    )
                };
                for intent in admissions
                    .into_iter()
                    .chain(records.into_iter().filter_map(|record| record.upgrade()))
                {
                    intent.cancel();
                }
                self.connection_dependencies.remove(&connection_id);
                self.reservation_addresses.remove(&connection_id);
                self.pending_handler_commands.remove(&connection_id);
            }
            FromSwarm::ListenFailure(failure) => {
                self.connection_dependencies.remove(&failure.connection_id);
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        event_source: PeerId,
        connection: ConnectionId,
        handler_event: THandlerOutEvent<Self>,
    ) {
        let handler_event = match handler_event {
            Either::Left(e) => e,
            Either::Right(v) => libp2p_core::util::unreachable(v),
        };

        let event = match handler_event {
            handler::Event::ReservationListenerConfirmed { listener_id } => {
                // A reply for an older logical listener must not confirm a newer
                // request assigned to the same physical connection.
                if !self
                    .connection_dependencies
                    .get(&connection)
                    .is_some_and(|owner| {
                        owner.peer == event_source
                            && owner.reservation_listener == Some(listener_id)
                    })
                    || self.reservation_listener_connection(event_source, listener_id)
                        != Some(connection)
                {
                    return;
                }
                let draining = self.is_reservation_draining(event_source, connection);
                let (addr, status) = self
                    .reservation_addresses
                    .get_mut(&connection)
                    .expect("Relay connection exist");

                if *status == ReservationStatus::Pending {
                    *status = ReservationStatus::Confirmed;
                    if !draining {
                        self.queued_actions
                            .push_back(ToSwarm::ExternalAddrConfirmed(addr.clone()));
                    }
                }
                return;
            }
            handler::Event::ReservationReqAccepted { renewal, limit } => {
                Event::ReservationReqAccepted {
                    relay_peer_id: event_source,
                    renewal,
                    limit,
                }
            }
            handler::Event::OutboundCircuitEstablished { limit } => {
                Event::OutboundCircuitEstablished {
                    relay_peer_id: event_source,
                    limit,
                }
            }
            handler::Event::InboundCircuitEstablished { src_peer_id, limit } => {
                Event::InboundCircuitEstablished { src_peer_id, limit }
            }
        };

        self.queued_actions.push_back(ToSwarm::GenerateEvent(event));
    }

    #[tracing::instrument(level = "trace", name = "NetworkBehaviour::poll", skip(self, cx))]
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if !self.waker.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
            self.waker = Some(cx.waker().clone());
        }
        // Coalesced policy is bounded by native owners, not by API call count.
        for (id, owner) in &mut self.connection_dependencies {
            if let Some(dependency) = owner.pending_reservation_drain.take() {
                return Poll::Ready(ToSwarm::NotifyHandler {
                    peer_id: owner.peer,
                    handler: NotifyHandler::One(*id),
                    event: Either::Left(handler::In::DrainReservation { dependency }),
                });
            }
        }
        if let Some(action) = self.queued_actions.pop_front() {
            return Poll::Ready(action);
        }

        loop {
            let action = match ready!(self.from_transport.poll_next_unpin(cx)) {
                Some(transport::TransportToBehaviourMsg::ListenReq {
                    listener_id,
                    relay_peer_id,
                    relay_addr,
                    mut to_listener,
                }) => {
                    // Assignment and pinning share the live listener's registry lock.
                    let registry = self.listener_bindings.clone();
                    let mut bindings = registry.lock().expect("Listener bindings lock");
                    let Some(binding) = bindings
                        .get_mut(&listener_id)
                        .filter(|b| b.peer == relay_peer_id)
                    else {
                        continue;
                    };
                    let connection = if let Some(pinned) = binding.connection {
                        if !self
                            .directly_connected_peers
                            .get(&relay_peer_id)
                            .is_some_and(|cs| cs.contains(&pinned))
                            || !self
                                .connection_dependencies
                                .get(&pinned)
                                .is_some_and(|owner| owner.peer == relay_peer_id)
                        {
                            binding.assigned = true;
                            binding.connection = None;
                            let _ = to_listener.try_send(transport::ToListenerMsg::Reservation(
                                Err(protocol::outbound_hop::ReserveError::Io(
                                    std::io::ErrorKind::NotConnected.into(),
                                )),
                            ));
                            continue;
                        }
                        Some(pinned)
                    } else {
                        self.directly_connected_peers
                            .get(&relay_peer_id)
                            .and_then(|cs| cs.first())
                            .copied()
                    };
                    binding.assigned = true;
                    match connection {
                        Some(connection_id) => {
                            binding.connection = Some(connection_id);
                            let dependency =
                                self.dependencies(relay_peer_id, connection_id).lease();
                            let owner = self
                                .connection_dependencies
                                .get_mut(&connection_id)
                                .expect("Known owner");
                            owner.dependencies.set_reservation_draining(false);
                            owner.pending_reservation_drain = None;
                            owner.reservation_listener = Some(listener_id);
                            self.reservation_addresses.insert(
                                connection_id,
                                (
                                    relay_addr
                                        .with(Protocol::P2p(relay_peer_id))
                                        .with(Protocol::P2pCircuit)
                                        .with(Protocol::P2p(self.local_peer_id)),
                                    ReservationStatus::Pending,
                                ),
                            );

                            ToSwarm::NotifyHandler {
                                peer_id: relay_peer_id,
                                handler: NotifyHandler::One(connection_id),
                                event: Either::Left(handler::In::Reserve {
                                    listener_id,
                                    to_listener,
                                    dependency,
                                }),
                            }
                        }
                        None => {
                            let opts = DialOpts::peer_id(relay_peer_id)
                                .addresses(vec![relay_addr.clone()])
                                .extend_addresses_through_behaviour()
                                .build();
                            let relayed_connection_id = opts.connection_id();
                            binding.connection = Some(relayed_connection_id);

                            self.reservation_addresses.insert(
                                relayed_connection_id,
                                (
                                    relay_addr
                                        .with(Protocol::P2p(relay_peer_id))
                                        .with(Protocol::P2pCircuit)
                                        .with(Protocol::P2p(self.local_peer_id)),
                                    ReservationStatus::Pending,
                                ),
                            );

                            let dependency = self
                                .dependencies(relay_peer_id, relayed_connection_id)
                                .lease();
                            self.connection_dependencies
                                .get_mut(&relayed_connection_id)
                                .expect("Known owner")
                                .reservation_listener = Some(listener_id);
                            self.pending_handler_commands.insert(
                                relayed_connection_id,
                                handler::In::Reserve {
                                    listener_id,
                                    to_listener,
                                    dependency,
                                },
                            );
                            ToSwarm::Dial { opts }
                        }
                    }
                }
                Some(transport::TransportToBehaviourMsg::DialReq {
                    relay_addr,
                    relay_peer_id,
                    dst_peer_id,
                    send_back,
                    pin,
                    ..
                }) => {
                    if send_back.is_canceled() {
                        continue;
                    }
                    let policy = self.entrance_policy.as_ref().filter(|policy| {
                        policy.requires_scope(relay_peer_id, &relay_addr, dst_peer_id)
                    });
                    let can_reuse = |id| {
                        policy.is_none_or(|policy| policy.allows_connection(relay_peer_id, id))
                    };
                    let directed = pin.as_ref().map(|pin| pin.dispatch()).transpose();
                    let Ok(directed) = directed else {
                        let _ = send_back.send(Err(protocol::outbound_hop::ConnectError::Io(
                            std::io::ErrorKind::Interrupted.into(),
                        )));
                        continue;
                    };
                    if let Some(Some((outer, dependency))) = directed {
                        if send_back.is_canceled()
                            || !can_reuse(outer)
                            || !self
                                .directly_connected_peers
                                .get(&relay_peer_id)
                                .is_some_and(|ids| ids.contains(&outer))
                            || !self
                                .connection_dependencies
                                .get(&outer)
                                .is_some_and(|owner| owner.peer == relay_peer_id)
                        {
                            let _ = send_back.send(Err(protocol::outbound_hop::ConnectError::Io(
                                std::io::ErrorKind::Interrupted.into(),
                            )));
                            continue;
                        }
                        return Poll::Ready(ToSwarm::NotifyHandler {
                            peer_id: relay_peer_id,
                            handler: NotifyHandler::One(outer),
                            event: Either::Left(handler::In::EstablishCircuit {
                                dst_peer_id,
                                to_dial: send_back,
                                dependency,
                                pin,
                            }),
                        });
                    }
                    match self
                        .directly_connected_peers
                        .get(&relay_peer_id)
                        .and_then(|cs| cs.iter().find(|id| can_reuse(**id)))
                        .copied()
                    {
                        Some(connection_id) => ToSwarm::NotifyHandler {
                            peer_id: relay_peer_id,
                            handler: NotifyHandler::One(connection_id),
                            event: Either::Left(handler::In::EstablishCircuit {
                                pin,
                                to_dial: send_back,
                                dst_peer_id,
                                dependency: self.dependencies(relay_peer_id, connection_id).lease(),
                            }),
                        },
                        None => {
                            let opts = if policy.is_some() {
                                DialOpts::peer_id(relay_peer_id)
                                    .condition(PeerCondition::Always)
                                    .addresses(vec![relay_addr])
                                    .build()
                            } else {
                                DialOpts::peer_id(relay_peer_id)
                                    .addresses(vec![relay_addr])
                                    .extend_addresses_through_behaviour()
                                    .build()
                            };
                            let connection_id = opts.connection_id();
                            if policy.is_some_and(|policy| !policy.start_dial(connection_id)) {
                                let _ = send_back.send(Err(protocol::outbound_hop::ConnectError::Io(
                                    std::io::ErrorKind::PermissionDenied.into(),
                                )));
                                continue;
                            }
                            let dependency =
                                self.dependencies(relay_peer_id, connection_id).lease();

                            self.pending_handler_commands.insert(
                                connection_id,
                                handler::In::EstablishCircuit {
                                    pin,
                                    to_dial: send_back,
                                    dst_peer_id,
                                    dependency,
                                },
                            );

                            ToSwarm::Dial { opts }
                        }
                    }
                }
                None => unreachable!(
                    "`relay::Behaviour` polled after channel from \
                     `Transport` has been closed. Unreachable under \
                     the assumption that the `client::Behaviour` is never polled after \
                     `client::Transport` is dropped.",
                ),
            };

            return Poll::Ready(action);
        }
    }
}

/// Represents a connection to another peer via a relay.
///
/// Internally, this uses a stream to the relay.
pub struct Connection {
    pub(crate) state: ConnectionState,
    pub(crate) _dependency: DependencyLease,
    pub(crate) binding: CircuitBinding,
}

impl Connection {
    /// Capture ownership before upgrading the stream; wrap the authenticated muxer
    /// with this sidecar to register its exact inner swarm connection identity.
    pub fn circuit_binding(&self) -> CircuitBinding {
        self.binding.clone()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.binding.close();
    }
}

pub(crate) enum ConnectionState {
    InboundAccepting {
        accept: BoxFuture<'static, Result<ConnectionState, Error>>,
    },
    Operational {
        read_buffer: Bytes,
        substream: Stream,
    },
}

impl Unpin for ConnectionState {}

impl ConnectionState {
    pub(crate) fn new_inbound(circuit: inbound_stop::Circuit) -> Self {
        ConnectionState::InboundAccepting {
            accept: async {
                let (substream, read_buffer) = circuit.accept().await.map_err(Error::other)?;
                Ok(ConnectionState::Operational {
                    read_buffer,
                    substream,
                })
            }
            .boxed(),
        }
    }

    pub(crate) fn new_outbound(substream: Stream, read_buffer: Bytes) -> Self {
        ConnectionState::Operational {
            substream,
            read_buffer,
        }
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        self.binding.check(cx)?;
        loop {
            match &mut self.state {
                ConnectionState::InboundAccepting { accept } => {
                    self.state = ready!(accept.poll_unpin(cx))?;
                }
                ConnectionState::Operational { substream, .. } => {
                    return Pin::new(substream).poll_write(cx, buf);
                }
            }
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        self.binding.check(cx)?;
        loop {
            match &mut self.state {
                ConnectionState::InboundAccepting { accept } => {
                    self.state = ready!(accept.poll_unpin(cx))?;
                }
                ConnectionState::Operational { substream, .. } => {
                    return Pin::new(substream).poll_flush(cx);
                }
            }
        }
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        loop {
            match &mut self.state {
                ConnectionState::InboundAccepting { accept } => {
                    self.state = ready!(accept.poll_unpin(cx))?;
                }
                ConnectionState::Operational { substream, .. } => {
                    return Pin::new(substream).poll_close(cx);
                }
            }
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        bufs: &[IoSlice],
    ) -> Poll<Result<usize, Error>> {
        self.binding.check(cx)?;
        loop {
            match &mut self.state {
                ConnectionState::InboundAccepting { accept } => {
                    self.state = ready!(accept.poll_unpin(cx))?;
                }
                ConnectionState::Operational { substream, .. } => {
                    return Pin::new(substream).poll_write_vectored(cx, bufs);
                }
            }
        }
    }
}

impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        self.binding.check(cx)?;
        loop {
            match &mut self.state {
                ConnectionState::InboundAccepting { accept } => {
                    self.state = ready!(accept.poll_unpin(cx))?;
                }
                ConnectionState::Operational {
                    read_buffer,
                    substream,
                    ..
                } => {
                    if !read_buffer.is_empty() {
                        let n = std::cmp::min(read_buffer.len(), buf.len());
                        let data = read_buffer.split_to(n);
                        buf[0..n].copy_from_slice(&data[..]);
                        return Poll::Ready(Ok(n));
                    }

                    return Pin::new(substream).poll_read(cx, buf);
                }
            }
        }
    }
}

#[cfg(test)]
mod drain_tests {
    use super::*;
    use futures::task::{waker, ArcWake};
    use libp2p_core::Transport as _;

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl ArcWake for WakeCount {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn drain_is_coalesced_wakes_and_pins_until_handler_delivery() {
        let (_transport, mut client) = new(PeerId::random());
        let peer = PeerId::random();
        let old = ConnectionId::new_unchecked(1);
        let replacement = ConnectionId::new_unchecked(2);
        let dependencies = client.dependencies(peer, old);
        client.dependencies(peer, replacement);
        client
            .directly_connected_peers
            .insert(peer, vec![old, replacement]);
        for id in [old, replacement] {
            client
                .reservation_addresses
                .insert(id, (Multiaddr::empty(), ReservationStatus::Confirmed));
        }
        let count = Arc::new(WakeCount::default());
        let waker = waker(count.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(client.poll(&mut cx).is_pending());
        for _ in 0..1000 {
            assert!(client.begin_reservation_drain(peer, old, replacement));
        }
        assert_eq!(count.0.load(Ordering::Relaxed), 1);
        assert_eq!(dependencies.0.load(Ordering::Relaxed), 1);
        assert_eq!(
            client
                .confirmed_reservation_connections(peer)
                .collect::<Vec<_>>(),
            vec![replacement]
        );
        assert!(!client.begin_reservation_drain(peer, replacement, old));
        assert!(!client.is_reservation_draining(PeerId::random(), old));
        let Poll::Ready(ToSwarm::NotifyHandler {
            peer_id,
            handler: NotifyHandler::One(id),
            event,
        }) = client.poll(&mut cx)
        else {
            panic!("missing drain command")
        };
        assert_eq!(peer_id, peer);
        assert_eq!(id, old);
        assert!(matches!(
            &event,
            Either::Left(handler::In::DrainReservation { .. })
        ));
        assert!(client.has_connection_dependencies(peer, old));
        assert!(client.poll(&mut cx).is_pending());
        assert!(client.begin_reservation_drain(peer, old, replacement));
        assert!(client.poll(&mut cx).is_pending());
        let mut handler = Handler::new(PeerId::random(), peer, Multiaddr::empty(), dependencies);
        let Either::Left(command) = event else {
            panic!("direct handler")
        };
        handler.on_behaviour_event(command);
        assert!(!client.has_connection_dependencies(peer, old));
        assert!(!handler.connection_keep_alive());
    }

    #[test]
    fn late_renewal_retains_address_and_close_expires_only_the_last_normal_owner() {
        let (_transport, mut client) = new(PeerId::random());
        let peer = PeerId::random();
        let old = ConnectionId::new_unchecked(10);
        let replacement = ConnectionId::new_unchecked(11);
        let address: Multiaddr = "/ip4/127.0.0.1/tcp/12345".parse().unwrap();
        client
            .directly_connected_peers
            .insert(peer, vec![old, replacement]);
        for id in [old, replacement] {
            client.dependencies(peer, id);
            client
                .reservation_addresses
                .insert(id, (address.clone(), ReservationStatus::Confirmed));
        }
        assert!(client.begin_reservation_drain(peer, old, replacement));
        client.on_connection_handler_event(
            peer,
            old,
            Either::Left(handler::Event::ReservationReqAccepted {
                renewal: true,
                limit: None,
            }),
        );
        assert!(client.reservation_addresses.contains_key(&old));
        assert!(client.is_reservation_draining(peer, old));
        client.queued_actions.clear();
        let endpoint = libp2p_core::ConnectedPoint::Dialer {
            address: address.clone(),
            role_override: Endpoint::Dialer,
            port_use: PortUse::Reuse,
        };
        for id in [old, replacement] {
            client.on_connection_closed(ConnectionClosed {
                peer_id: peer,
                connection_id: id,
                endpoint: &endpoint,
                cause: None,
                remaining_established: usize::from(id == old),
            });
            assert!(!client.is_reservation_draining(peer, id));
            if id == old {
                assert!(client.queued_actions.is_empty());
            } else {
                assert!(
                    matches!(client.queued_actions.pop_front(), Some(ToSwarm::ExternalAddrExpired(a)) if a == address)
                );
            }
        }
    }

    #[test]
    fn pending_source_can_drain_but_stale_listener_cannot_confirm_a_new_request() {
        let (mut transport, mut client) = new(PeerId::random());
        let peer = PeerId::random();
        let old = ConnectionId::new_unchecked(20);
        let replacement = ConnectionId::new_unchecked(21);
        client
            .directly_connected_peers
            .insert(peer, vec![old, replacement]);
        client.dependencies(peer, old);
        client.dependencies(peer, replacement);
        client.reservation_addresses.insert(
            replacement,
            (Multiaddr::empty(), ReservationStatus::Confirmed),
        );
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let address = Multiaddr::empty()
            .with(Protocol::Memory(42))
            .with(Protocol::P2p(peer))
            .with(Protocol::P2pCircuit);
        let first = ListenerId::next();
        transport.listen_on(first, address.clone()).unwrap();
        assert!(Pin::new(&mut transport).poll(&mut cx).is_pending());
        let Poll::Ready(command) = client.poll(&mut cx) else {
            panic!("missing first listen")
        };
        assert!(client.begin_reservation_drain(peer, old, replacement));
        assert!(client.has_connection_dependencies(peer, old));
        assert_eq!(
            client.reservation_addresses.get(&old).unwrap().1,
            ReservationStatus::Pending
        );
        // Delivering the drain cannot release the already assigned reserve command.
        let Poll::Ready(ToSwarm::NotifyHandler {
            event: Either::Left(drain),
            ..
        }) = client.poll(&mut cx)
        else {
            panic!("missing drain")
        };
        let mut handler = Handler::new(
            PeerId::random(),
            peer,
            Multiaddr::empty(),
            client.dependencies(peer, old),
        );
        handler.on_behaviour_event(drain);
        assert!(client.has_connection_dependencies(peer, old));
        assert!(client.is_reservation_draining(peer, old));

        let second = ListenerId::next();
        transport.listen_on(second, address).unwrap();
        assert!(Pin::new(&mut transport).poll(&mut cx).is_pending());
        let Poll::Ready(new_command) = client.poll(&mut cx) else {
            panic!("missing second listen")
        };
        assert!(!client.is_reservation_draining(peer, old));
        client.on_connection_handler_event(
            peer,
            old,
            Either::Left(handler::Event::ReservationListenerConfirmed { listener_id: first }),
        );
        client.on_connection_handler_event(
            peer,
            old,
            Either::Left(handler::Event::ReservationReqAccepted {
                renewal: false,
                limit: None,
            }),
        );
        assert_eq!(
            client.reservation_addresses.get(&old).unwrap().1,
            ReservationStatus::Pending
        );
        client.on_connection_handler_event(
            peer,
            old,
            Either::Left(handler::Event::ReservationListenerConfirmed {
                listener_id: second,
            }),
        );
        assert_eq!(
            client.reservation_addresses.get(&old).unwrap().1,
            ReservationStatus::Confirmed
        );
        drop(command);
        drop(new_command);
    }
}
