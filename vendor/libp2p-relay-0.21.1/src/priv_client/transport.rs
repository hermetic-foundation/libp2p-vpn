// Copyright 2020 Parity Technologies (UK) Ltd.
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

use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use futures::{
    channel::{mpsc, oneshot},
    future::{ready, BoxFuture, FutureExt, Ready},
    sink::SinkExt,
    stream::{SelectAll, Stream, StreamExt},
};
use libp2p_core::{
    multiaddr::{Multiaddr, Protocol},
    transport::{DialOpts, ListenerId, TransportError, TransportEvent},
};
use libp2p_identity::PeerId;
use libp2p_swarm::ConnectionId;
use thiserror::Error;

use crate::{
    multiaddr_ext::MultiaddrExt,
    priv_client::{circuit, Connection},
    protocol::{
        outbound_hop,
        outbound_hop::{ConnectError, ReserveError},
    },
    RequestId,
};

/// A [`Transport`] enabling client relay capabilities.
///
/// Note: The transport only handles listening and dialing on relayed [`Multiaddr`], and depends on
/// an other transport to do the actual transmission of data. They should be combined through the
/// [`OrTransport`](libp2p_core::transport::choice::OrTransport).
///
/// Allows the local node to:
///
/// 1. Establish relayed connections by dialing `/p2p-circuit` addresses.
///
///    ```
///    # use libp2p_core::{Multiaddr, multiaddr::{Protocol}, Transport,
///    # transport::{DialOpts, PortUse}, connection::Endpoint};
///    # use libp2p_core::transport::memory::MemoryTransport;
///    # use libp2p_core::transport::choice::OrTransport;
///    # use libp2p_relay as relay;
///    # use libp2p_identity::PeerId;
///    let actual_transport = MemoryTransport::default();
///    let (relay_transport, behaviour) = relay::client::new(
///        PeerId::random()
///    );
///    let mut transport = OrTransport::new(relay_transport, actual_transport);
///    # let relay_id = PeerId::random();
///    # let destination_id = PeerId::random();
///    let dst_addr_via_relay = Multiaddr::empty()
///        .with(Protocol::Memory(40)) // Relay address.
///        .with(Protocol::P2p(relay_id.into())) // Relay peer id.
///        .with(Protocol::P2pCircuit) // Signal to connect via relay and not directly.
///        .with(Protocol::P2p(destination_id.into())); // Destination peer id.
///    transport.dial(dst_addr_via_relay, DialOpts {
///         port_use: PortUse::Reuse,
///         role: Endpoint::Dialer,
///    }).unwrap();
///    ```
///
/// 3. Listen for incoming relayed connections via specific relay.
///
///    ```
///    # use libp2p_core::{Multiaddr, multiaddr::{Protocol}, transport::ListenerId, Transport};
///    # use libp2p_core::transport::memory::MemoryTransport;
///    # use libp2p_core::transport::choice::OrTransport;
///    # use libp2p_relay as relay;
///    # use libp2p_identity::PeerId;
///    # let relay_id = PeerId::random();
///    # let local_peer_id = PeerId::random();
///    let actual_transport = MemoryTransport::default();
///    let (relay_transport, behaviour) = relay::client::new(
///       local_peer_id
///    );
///    let mut transport = OrTransport::new(relay_transport, actual_transport);
///    let relay_addr = Multiaddr::empty()
///        .with(Protocol::Memory(40)) // Relay address.
///        .with(Protocol::P2p(relay_id.into())) // Relay peer id.
///        .with(Protocol::P2pCircuit); // Signal to listen via remote relay node.
///    transport.listen_on(ListenerId::next(), relay_addr).unwrap();
///    ```
pub struct Transport {
    to_behaviour: mpsc::Sender<TransportToBehaviourMsg>,
    pending_to_behaviour: VecDeque<TransportToBehaviourMsg>,
    listeners: SelectAll<Listener>,
    listener_bindings: ListenerBindings,
    circuits: circuit::Registry,
}

pub(super) type ListenerBindings = Arc<Mutex<HashMap<ListenerId, ListenerBinding>>>;

pub(super) struct ListenerBinding {
    pub(super) peer: PeerId,
    /// Desired connection before assignment, actual connection afterwards.
    pub(super) connection: Option<ConnectionId>,
    pub(super) assigned: bool,
}

impl Transport {
    pub(super) fn new(
        circuits: circuit::Registry,
    ) -> (
        Self,
        mpsc::Receiver<TransportToBehaviourMsg>,
        ListenerBindings,
    ) {
        let (to_behaviour, from_transport) = mpsc::channel(1000);
        let listener_bindings = ListenerBindings::default();
        let transport = Transport {
            to_behaviour,
            pending_to_behaviour: VecDeque::new(),
            listeners: SelectAll::new(),
            listener_bindings: listener_bindings.clone(),
            circuits,
        };
        (transport, from_transport, listener_bindings)
    }

    fn dial_inner(
        &mut self,
        addr: Multiaddr,
        dial_opts: DialOpts,
        inner: Option<ConnectionId>,
    ) -> Result<<Self as libp2p_core::Transport>::Dial, TransportError<Error>> {
        if dial_opts.role.is_listener() {
            return Err(TransportError::MultiaddrNotSupported(addr));
        }
        let RelayedMultiaddr {
            relay_peer_id,
            relay_addr,
            dst_peer_id,
            dst_addr,
        } = parse_relayed_multiaddr(addr)?;
        let relay_peer_id = relay_peer_id.ok_or(Error::MissingRelayPeerId)?;
        let relay_addr = relay_addr.ok_or(Error::MissingRelayAddr)?;
        let dst_peer_id = dst_peer_id.ok_or(Error::MissingDstPeerId)?;
        let pin = if let Some(inner) = inner {
            // Registration and pin selection must be atomic: deferred dial
            // futures may run on the executor concurrently with the caller.
            // Keep every upgraded reference until after the registry unlocks.
            let retained;
            let mut registry = self.circuits.lock().expect("Circuit registry lock");
            retained = registry
                .pins
                .get(&inner)
                .map(|records| {
                    records
                        .iter()
                        .filter_map(|record| record.upgrade())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let admitted = registry.admissions.get(&inner).and_then(|records| {
                records
                    .iter()
                    .find(|intent| intent.peer == dst_peer_id && intent.relay == relay_peer_id)
                    .cloned()
            });
            // The real CID's selection also governs branches whose raw dial
            // is created later by DNS or behaviour-supplied alternatives.
            let constrained = retained.iter().any(|intent| intent.constrained());
            if let Some(intent) = admitted {
                Some(intent)
            } else if constrained {
                return Err(Error::CircuitPin(
                    "relay alternative violates the circuit dial constraint",
                )
                .into());
            } else {
                let intent =
                    circuit::Intent::new(dst_peer_id, inner, relay_peer_id, &self.circuits, false);
                registry
                    .pins
                    .entry(inner)
                    .or_default()
                    .push(Arc::downgrade(&intent));
                Some(intent)
            }
        } else {
            None
        };
        let mut lifetime = pin.as_ref().map(|intent| circuit::DialLifetime {
            intent: intent.clone(),
            transferred: false,
        });
        let requested_pin = pin.clone();
        let mut to_behaviour = self.to_behaviour.clone();
        let mut request = Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            to_behaviour
                .send(TransportToBehaviourMsg::DialReq {
                    request_id: RequestId::new(),
                    relay_addr,
                    relay_peer_id,
                    dst_addr,
                    dst_peer_id,
                    send_back: tx,
                    pin: requested_pin,
                })
                .await?;
            Ok(rx.await??)
        });
        Ok(futures::future::poll_fn(move |cx| {
            if let Some(pin) = &pin {
                pin.waker.register(cx.waker());
                if pin.cancelled() {
                    pin.finish_pending();
                    return Poll::Ready(Err(Error::CircuitPin("circuit pin cancelled")));
                }
            }
            let result = request.poll_unpin(cx);
            if let Poll::Ready(result) = &result {
                if let Some(lifetime) = &mut lifetime {
                    lifetime.transferred = result.is_ok();
                    if result.is_err() {
                        lifetime.intent.finish_pending();
                    }
                }
            }
            result
        })
        .boxed())
    }
}

impl libp2p_core::Transport for Transport {
    type Output = Connection;
    type Error = Error;
    type ListenerUpgrade = Ready<Result<Self::Output, Self::Error>>;
    type Dial = BoxFuture<'static, Result<Connection, Error>>;

    fn listen_on(
        &mut self,
        listener_id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        let (relay_peer_id, relay_addr) = match parse_relayed_multiaddr(addr)? {
            RelayedMultiaddr {
                relay_peer_id: None,
                relay_addr: _,
                ..
            } => return Err(Error::MissingDstPeerId.into()),
            RelayedMultiaddr {
                relay_peer_id: _,
                relay_addr: None,
                ..
            } => return Err(Error::MissingRelayAddr.into()),
            RelayedMultiaddr {
                relay_peer_id: Some(peer_id),
                relay_addr: Some(addr),
                ..
            } => (peer_id, addr),
        };

        let (to_listener, from_behaviour) = mpsc::channel(0);
        self.listener_bindings
            .lock()
            .expect("Listener bindings lock")
            .insert(
                listener_id,
                ListenerBinding {
                    peer: relay_peer_id,
                    connection: None,
                    assigned: false,
                },
            );
        self.pending_to_behaviour
            .push_back(TransportToBehaviourMsg::ListenReq {
                listener_id,
                relay_peer_id,
                relay_addr,
                to_listener,
            });

        let listener = Listener {
            listener_id,
            queued_events: Default::default(),
            advertised_addresses: Vec::new(),
            from_behaviour,
            is_closed: false,
            waker: None,
            listener_bindings: self.listener_bindings.clone(),
        };
        self.listeners.push(listener);
        Ok(())
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        if let Some(listener) = self.listeners.iter_mut().find(|l| l.listener_id == id) {
            listener.close(Ok(()));
            true
        } else {
            false
        }
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        dial_opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        self.dial_inner(
            addr,
            dial_opts,
            libp2p_core::transport::dial_connection_id().map(ConnectionId::new_unchecked),
        )
    }

    fn dial_with_connection_id(
        &mut self,
        addr: Multiaddr,
        opts: DialOpts,
        id: usize,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        self.dial_inner(addr, opts, Some(ConnectionId::new_unchecked(id)))
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>>
    where
        Self: Sized,
    {
        loop {
            if !self.pending_to_behaviour.is_empty() {
                match self.to_behaviour.poll_ready(cx) {
                    Poll::Ready(Ok(())) => {
                        let msg = self
                            .pending_to_behaviour
                            .pop_front()
                            .expect("Called !is_empty().");
                        let _ = self.to_behaviour.start_send(msg);
                        continue;
                    }
                    Poll::Ready(Err(_)) => unreachable!("Receiver is never dropped."),
                    Poll::Pending => {}
                }
            }
            match self.listeners.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => return Poll::Ready(event),
                _ => return Poll::Pending,
            }
        }
    }
}

#[derive(Default)]
struct RelayedMultiaddr {
    relay_peer_id: Option<PeerId>,
    relay_addr: Option<Multiaddr>,
    dst_peer_id: Option<PeerId>,
    dst_addr: Option<Multiaddr>,
}

pub(super) fn relay_peer_for_dial(address: &Multiaddr, peer: PeerId) -> Option<PeerId> {
    let parsed = parse_relayed_multiaddr(address.clone()).ok()?;
    if parsed.relay_addr.is_none()
        || parsed
            .dst_peer_id
            .is_some_and(|destination| destination != peer)
    {
        return None;
    }
    parsed.relay_peer_id
}

/// Parse a [`Multiaddr`] containing a [`Protocol::P2pCircuit`].
fn parse_relayed_multiaddr(addr: Multiaddr) -> Result<RelayedMultiaddr, TransportError<Error>> {
    if !addr.is_relayed() {
        return Err(TransportError::MultiaddrNotSupported(addr));
    }

    let mut relayed_multiaddr = RelayedMultiaddr::default();

    let mut before_circuit = true;
    for protocol in addr.into_iter() {
        match protocol {
            Protocol::P2pCircuit => {
                if before_circuit {
                    before_circuit = false;
                } else {
                    return Err(Error::MultipleCircuitRelayProtocolsUnsupported.into());
                }
            }
            Protocol::P2p(peer_id) => {
                if before_circuit {
                    if relayed_multiaddr.relay_peer_id.is_some() {
                        return Err(Error::MalformedMultiaddr.into());
                    }
                    relayed_multiaddr.relay_peer_id = Some(peer_id)
                } else {
                    if relayed_multiaddr.dst_peer_id.is_some() {
                        return Err(Error::MalformedMultiaddr.into());
                    }
                    relayed_multiaddr.dst_peer_id = Some(peer_id)
                }
            }
            p => {
                if before_circuit {
                    relayed_multiaddr
                        .relay_addr
                        .get_or_insert_with(Multiaddr::empty)
                        .push(p);
                } else {
                    relayed_multiaddr
                        .dst_addr
                        .get_or_insert_with(Multiaddr::empty)
                        .push(p);
                }
            }
        }
    }

    Ok(relayed_multiaddr)
}

pub(crate) struct Listener {
    listener_id: ListenerId,
    /// Queue of events to report when polled.
    queued_events: VecDeque<<Self as Stream>::Item>,
    advertised_addresses: Vec<Multiaddr>,
    /// Channel for messages from the behaviour [`Handler`][super::handler::Handler].
    from_behaviour: mpsc::Receiver<ToListenerMsg>,
    /// The listener can be closed either manually with
    /// [`Transport::remove_listener`](libp2p_core::Transport) or if the sender side of the
    /// `from_behaviour` channel is dropped.
    is_closed: bool,
    waker: Option<Waker>,
    listener_bindings: ListenerBindings,
}

impl Listener {
    /// Close the listener.
    ///
    /// This will create a [`TransportEvent::ListenerClosed`] event
    /// and terminate the stream once all remaining events in queue have
    /// been reported.
    fn close(&mut self, reason: Result<(), Error>) {
        self.listener_bindings
            .lock()
            .expect("Listener bindings lock")
            .remove(&self.listener_id);
        self.queued_events
            .push_back(TransportEvent::ListenerClosed {
                listener_id: self.listener_id,
                reason,
            });
        self.is_closed = true;

        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.listener_bindings
            .lock()
            .expect("Listener bindings lock")
            .remove(&self.listener_id);
    }
}

impl Stream for Listener {
    type Item = TransportEvent<<Transport as libp2p_core::Transport>::ListenerUpgrade, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(event) = self.queued_events.pop_front() {
                self.waker = None;
                return Poll::Ready(Some(event));
            }

            if self.is_closed {
                // Terminate the stream if the listener closed and
                // all remaining events have been reported.
                self.waker = None;
                return Poll::Ready(None);
            }

            let msg = match self.from_behaviour.poll_next_unpin(cx) {
                Poll::Ready(Some(msg)) => msg,
                Poll::Ready(None) => {
                    // Sender of `from_behaviour` has been dropped, signaling listener to close.
                    self.close(Ok(()));
                    continue;
                }
                Poll::Pending => {
                    self.waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            };

            match msg {
                ToListenerMsg::Reservation(Ok(Reservation { addrs })) => {
                    debug_assert!(
                        self.queued_events.is_empty(),
                        "Assert empty due to previous `pop_front` attempt."
                    );
                    let old = std::mem::replace(&mut self.advertised_addresses, addrs);
                    let listener_id = self.listener_id;
                    // Report renewals even for unchanged entrances. Emit them
                    // before removals so a changed reservation remains ready.
                    let removed = old
                        .iter()
                        .filter(|addr| !self.advertised_addresses.contains(addr));
                    self.queued_events =
                        self.advertised_addresses
                            .iter()
                            .cloned()
                            .map(|listen_addr| TransportEvent::NewAddress {
                                listener_id,
                                listen_addr,
                            })
                            .chain(removed.cloned().map(|listen_addr| {
                                TransportEvent::AddressExpired {
                                    listener_id,
                                    listen_addr,
                                }
                            }))
                            .collect();
                }
                ToListenerMsg::IncomingRelayedConnection {
                    stream,
                    src_peer_id,
                    relay_addr,
                    relay_peer_id: _,
                } => {
                    let listener_id = self.listener_id;

                    self.queued_events.push_back(TransportEvent::Incoming {
                        upgrade: ready(Ok(stream)),
                        listener_id,
                        local_addr: relay_addr.with(Protocol::P2pCircuit),
                        send_back_addr: Protocol::P2p(src_peer_id).into(),
                    })
                }
                ToListenerMsg::Reservation(Err(e)) => self.close(Err(Error::Reservation(e))),
            };
        }
    }
}

/// Error that occurred during relay connection setup.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Directed circuit dial failed: {0}")]
    CircuitPin(&'static str),
    #[error("Missing relay peer id.")]
    MissingRelayPeerId,
    #[error("Missing relay address.")]
    MissingRelayAddr,
    #[error("Missing destination peer id.")]
    MissingDstPeerId,
    #[error("Invalid peer id hash.")]
    InvalidHash,
    #[error("Failed to send message to relay behaviour: {0:?}")]
    SendingMessageToBehaviour(#[from] mpsc::SendError),
    #[error("Response from behaviour was canceled")]
    ResponseFromBehaviourCanceled(#[from] oneshot::Canceled),
    #[error(
        "Address contains multiple circuit relay protocols (`p2p-circuit`) which is not supported."
    )]
    MultipleCircuitRelayProtocolsUnsupported,
    #[error("One of the provided multiaddresses is malformed.")]
    MalformedMultiaddr,
    #[error("Failed to get Reservation.")]
    Reservation(#[from] ReserveError),
    #[error("Failed to connect to destination.")]
    Connect(#[from] ConnectError),
}

impl From<Error> for TransportError<Error> {
    fn from(error: Error) -> Self {
        TransportError::Other(error)
    }
}

/// Message from the [`Transport`] to the [`Behaviour`](crate::Behaviour)
/// [`NetworkBehaviour`](libp2p_swarm::NetworkBehaviour).
pub(crate) enum TransportToBehaviourMsg {
    /// Dial destination node via relay node.
    #[allow(dead_code)]
    DialReq {
        request_id: RequestId,
        relay_addr: Multiaddr,
        relay_peer_id: PeerId,
        dst_addr: Option<Multiaddr>,
        dst_peer_id: PeerId,
        send_back: oneshot::Sender<Result<Connection, outbound_hop::ConnectError>>,
        pin: Option<Arc<circuit::Intent>>,
    },
    /// Listen for incoming relayed connections via relay node.
    ListenReq {
        listener_id: ListenerId,
        relay_peer_id: PeerId,
        relay_addr: Multiaddr,
        to_listener: mpsc::Sender<ToListenerMsg>,
    },
}

#[allow(clippy::large_enum_variant)]
pub enum ToListenerMsg {
    Reservation(Result<Reservation, ReserveError>),
    IncomingRelayedConnection {
        stream: Connection,
        src_peer_id: PeerId,
        relay_peer_id: PeerId,
        relay_addr: Multiaddr,
    },
}

pub struct Reservation {
    pub(crate) addrs: Vec<Multiaddr>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_adds_new_entrance_before_expiring_removed_entrance() {
        let (mut to_listener, from_behaviour) = mpsc::channel(2);
        let listener_id = ListenerId::next();
        let mut listener = Listener {
            listener_id,
            queued_events: VecDeque::new(),
            advertised_addresses: Vec::new(),
            from_behaviour,
            is_closed: false,
            waker: None,
            listener_bindings: ListenerBindings::default(),
        };
        let mut context = Context::from_waker(futures::task::noop_waker_ref());
        let v4: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        let v6: Multiaddr = "/ip6/::1/tcp/4002".parse().unwrap();
        let extra: Multiaddr = "/ip4/127.0.0.1/tcp/4003".parse().unwrap();

        let send = |tx: &mut mpsc::Sender<ToListenerMsg>, addrs| {
            assert!(tx
                .try_send(ToListenerMsg::Reservation(Ok(Reservation { addrs })))
                .is_ok());
        };
        send(&mut to_listener, vec![v4.clone(), v6.clone()]);
        let mut next = || Pin::new(&mut listener).poll_next(&mut context);
        for expected in [&v4, &v6] {
            assert!(
                matches!(next(), Poll::Ready(Some(TransportEvent::NewAddress {
                listener_id: owner, listen_addr,
            })) if owner == listener_id && &listen_addr == expected)
            );
        }
        send(&mut to_listener, vec![extra.clone(), v4.clone()]);
        for expected in [&extra, &v4] {
            assert!(
                matches!(next(), Poll::Ready(Some(TransportEvent::NewAddress {
                    listener_id: owner, listen_addr,
                })) if owner == listener_id && &listen_addr == expected)
            );
        }
        assert!(
            matches!(next(), Poll::Ready(Some(TransportEvent::AddressExpired {
            listener_id: owner, listen_addr,
        })) if owner == listener_id && listen_addr == v6)
        );
        assert!(next().is_pending());
    }
}
