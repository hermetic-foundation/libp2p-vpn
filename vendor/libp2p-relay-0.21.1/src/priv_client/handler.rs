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
    collections::VecDeque,
    convert::Infallible,
    fmt, io,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use futures::{
    channel::{mpsc, mpsc::Sender, oneshot},
    future::FutureExt,
};
use futures_timer::Delay;
use libp2p_core::{multiaddr::Protocol, transport::ListenerId, upgrade::ReadyUpgrade, Multiaddr};
use libp2p_identity::PeerId;
use libp2p_swarm::{
    handler::{ConnectionEvent, FullyNegotiatedInbound},
    ConnectionHandler, ConnectionHandlerEvent, Stream, StreamProtocol, StreamUpgradeError,
    SubstreamProtocol,
};

use crate::{
    client::Connection,
    priv_client,
    priv_client::{transport, transport::ToListenerMsg, Dependencies, DependencyLease},
    proto,
    protocol::{self, inbound_stop, outbound_hop},
    HOP_PROTOCOL_NAME, STOP_PROTOCOL_NAME,
};

/// The maximum number of circuits being denied concurrently.
///
/// Circuits to be denied exceeding the limit are dropped.
const MAX_NUMBER_DENYING_CIRCUIT: usize = 8;
const DENYING_CIRCUIT_TIMEOUT: Duration = Duration::from_secs(60);

const MAX_CONCURRENT_STREAMS_PER_CONNECTION: usize = 10;
const STREAM_TIMEOUT: Duration = Duration::from_secs(60);

pub enum In {
    DrainReservation {
        dependency: DependencyLease,
    },
    Reserve {
        listener_id: ListenerId,
        to_listener: mpsc::Sender<transport::ToListenerMsg>,
        dependency: DependencyLease,
    },
    EstablishCircuit {
        dst_peer_id: PeerId,
        to_dial: oneshot::Sender<Result<priv_client::Connection, outbound_hop::ConnectError>>,
        dependency: DependencyLease,
    },
}

impl fmt::Debug for In {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            In::DrainReservation { .. } => f.debug_struct("In::DrainReservation").finish(),
            In::Reserve { .. } => f.debug_struct("In::Reserve").finish(),
            In::EstablishCircuit {
                dst_peer_id,
                to_dial: _,
                ..
            } => f
                .debug_struct("In::EstablishCircuit")
                .field("dst_peer_id", dst_peer_id)
                .finish(),
        }
    }
}

#[derive(Debug)]
pub enum Event {
    /// Private confirmation tied to the exact logical listener, before emitting
    /// the unchanged user-facing acceptance event.
    ReservationListenerConfirmed { listener_id: ListenerId },
    ReservationReqAccepted {
        /// Indicates whether the request replaces an existing reservation.
        renewal: bool,
        limit: Option<protocol::Limit>,
    },
    /// An outbound circuit has been established.
    OutboundCircuitEstablished { limit: Option<protocol::Limit> },
    /// An inbound circuit has been established.
    InboundCircuitEstablished {
        src_peer_id: PeerId,
        limit: Option<protocol::Limit>,
    },
}

pub struct Handler {
    local_peer_id: PeerId,
    remote_peer_id: PeerId,
    remote_addr: Multiaddr,
    dependencies: Dependencies,

    /// Queue of events to return when polled.
    queued_events: VecDeque<
        ConnectionHandlerEvent<
            <Handler as ConnectionHandler>::OutboundProtocol,
            DependencyLease,
            <Handler as ConnectionHandler>::ToBehaviour,
        >,
    >,

    pending_streams: VecDeque<oneshot::Sender<Result<Stream, StreamUpgradeError<Infallible>>>>,

    inflight_reserve_requests: futures_bounded::FuturesTupleSet<
        Result<outbound_hop::Reservation, outbound_hop::ReserveError>,
        (
            mpsc::Sender<transport::ToListenerMsg>,
            DependencyLease,
            Arc<()>,
        ),
    >,

    inflight_outbound_connect_requests: futures_bounded::FuturesTupleSet<
        Result<outbound_hop::Circuit, outbound_hop::ConnectError>,
        (
            oneshot::Sender<Result<priv_client::Connection, outbound_hop::ConnectError>>,
            DependencyLease,
        ),
    >,

    inflight_inbound_circuit_requests: futures_bounded::FuturesTupleSet<
        Result<inbound_stop::Circuit, inbound_stop::Error>,
        DependencyLease,
    >,

    inflight_outbound_circuit_deny_requests:
        futures_bounded::FuturesSet<Result<(), inbound_stop::Error>>,

    reservation: Reservation,
    reservation_draining: bool,
    /// Identifies the logical listener without retaining obsolete listener senders.
    reservation_generation: Arc<()>,
    reservation_listener: Option<ListenerId>,
}

impl Handler {
    pub(crate) fn new(
        local_peer_id: PeerId,
        remote_peer_id: PeerId,
        remote_addr: Multiaddr,
        dependencies: Dependencies,
    ) -> Self {
        Self {
            local_peer_id,
            remote_peer_id,
            remote_addr,
            dependencies,
            queued_events: Default::default(),
            pending_streams: Default::default(),
            inflight_reserve_requests: futures_bounded::FuturesTupleSet::new(
                STREAM_TIMEOUT,
                MAX_CONCURRENT_STREAMS_PER_CONNECTION,
            ),
            inflight_inbound_circuit_requests: futures_bounded::FuturesTupleSet::new(
                STREAM_TIMEOUT,
                MAX_CONCURRENT_STREAMS_PER_CONNECTION,
            ),
            inflight_outbound_connect_requests: futures_bounded::FuturesTupleSet::new(
                STREAM_TIMEOUT,
                MAX_CONCURRENT_STREAMS_PER_CONNECTION,
            ),
            inflight_outbound_circuit_deny_requests: futures_bounded::FuturesSet::new(
                DENYING_CIRCUIT_TIMEOUT,
                MAX_NUMBER_DENYING_CIRCUIT,
            ),
            reservation: Reservation::None,
            reservation_draining: false,
            reservation_generation: Arc::new(()),
            reservation_listener: None,
        }
    }

    fn apply_reservation_drain(&mut self) {
        // A newer normal listen may have superseded a queued drain command.
        if self.dependencies.is_reservation_draining() {
            self.reservation_draining = true;
            self.reservation.drain();
        }
    }

    fn insert_to_deny_futs(&mut self, circuit: inbound_stop::Circuit, dependency: DependencyLease) {
        let src_peer_id = circuit.src_peer_id();

        if self
            .inflight_outbound_circuit_deny_requests
            .try_push(async move {
                let _dependency = dependency;
                circuit.deny(proto::Status::NO_RESERVATION).await
            })
            .is_err()
        {
            tracing::warn!(
                peer=%src_peer_id,
                "Dropping existing inbound circuit request to be denied from peer in favor of new one"
            )
        }
    }

    fn make_new_reservation(
        &mut self,
        to_listener: Sender<ToListenerMsg>,
        dependency: DependencyLease,
    ) {
        let (sender, receiver) = oneshot::channel();

        self.pending_streams.push_back(sender);
        self.queued_events
            .push_back(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(
                    ReadyUpgrade::new(HOP_PROTOCOL_NAME),
                    self.dependencies.lease(),
                ),
            });
        let result = self.inflight_reserve_requests.try_push(
            async move {
                let stream = receiver
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?
                    .map_err(into_reserve_error)?;

                let reservation = outbound_hop::make_reservation(stream).await?;

                Ok(reservation)
            },
            (to_listener, dependency, self.reservation_generation.clone()),
        );

        if result.is_err() {
            tracing::warn!("Dropping in-flight reservation request because we are at capacity");
        }
    }

    fn establish_new_circuit(
        &mut self,
        to_dial: oneshot::Sender<Result<Connection, outbound_hop::ConnectError>>,
        dst_peer_id: PeerId,
        dependency: DependencyLease,
    ) {
        let (sender, receiver) = oneshot::channel();

        self.pending_streams.push_back(sender);
        self.queued_events
            .push_back(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(
                    ReadyUpgrade::new(HOP_PROTOCOL_NAME),
                    self.dependencies.lease(),
                ),
            });
        let result = self.inflight_outbound_connect_requests.try_push(
            async move {
                let stream = receiver
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?
                    .map_err(into_connect_error)?;

                outbound_hop::open_circuit(stream, dst_peer_id).await
            },
            (to_dial, dependency),
        );

        if result.is_err() {
            tracing::warn!("Dropping in-flight connect request because we are at capacity")
        }
    }
}

impl ConnectionHandler for Handler {
    type FromBehaviour = In;
    type ToBehaviour = Event;
    type InboundProtocol = ReadyUpgrade<StreamProtocol>;
    type InboundOpenInfo = DependencyLease;
    type OutboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundOpenInfo = DependencyLease;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        // The swarm retains open info even while multistream negotiation is pending.
        SubstreamProtocol::new(
            ReadyUpgrade::new(STOP_PROTOCOL_NAME),
            self.dependencies.lease(),
        )
    }

    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        match event {
            In::DrainReservation { dependency } => {
                self.apply_reservation_drain();
                // The command pins the owner until the policy has been applied.
                drop(dependency);
            }
            In::Reserve {
                listener_id,
                to_listener,
                dependency,
            } => {
                // Do not undo a drain requested after this command was assigned.
                self.reservation_draining = self.dependencies.is_reservation_draining();
                self.reservation_generation = Arc::new(());
                self.reservation_listener = Some(listener_id);
                self.reservation = Reservation::Pending {
                    _to_listener: to_listener.clone(),
                };
                self.make_new_reservation(to_listener, dependency);
            }
            In::EstablishCircuit {
                to_dial,
                dst_peer_id,
                dependency,
            } => {
                self.establish_new_circuit(to_dial, dst_peer_id, dependency);
            }
        }
    }

    fn connection_keep_alive(&self) -> bool {
        !self.reservation_draining && self.reservation.is_some()
    }

    #[tracing::instrument(level = "trace", name = "ConnectionHandler::poll", skip(self, cx))]
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        // Codec completion can race delivery of the policy command. That command
        // retains its lease even if the requested policy is observed here first.
        self.apply_reservation_drain();
        loop {
            // Reservations
            match self.inflight_reserve_requests.poll_unpin(cx) {
                Poll::Ready((_, (_, _, generation)))
                    if !Arc::ptr_eq(&generation, &self.reservation_generation) =>
                {
                    // A fresh listener superseded this codec, but let it finish first.
                    continue;
                }
                Poll::Ready((
                    Ok(Ok(outbound_hop::Reservation {
                        renewal_timeout,
                        addrs,
                        limit,
                    })),
                    (to_listener, dependency, _generation),
                )) => {
                    let event = self.reservation.accepted(
                        (!self.reservation_draining).then_some(renewal_timeout),
                        addrs,
                        to_listener,
                        self.local_peer_id,
                        limit,
                        (!self.reservation_draining).then_some(dependency),
                    );
                    if matches!(event, Event::ReservationReqAccepted { renewal: false, .. }) {
                        if let Some(listener_id) = self.reservation_listener {
                            self.queued_events
                                .push_front(ConnectionHandlerEvent::NotifyBehaviour(event));
                            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                                Event::ReservationListenerConfirmed { listener_id },
                            ));
                        }
                    }
                    return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(event));
                }
                Poll::Ready((Ok(Err(error)), (mut to_listener, _dependency, _generation))) => {
                    if self.reservation_draining {
                        continue;
                    }
                    if let Err(e) =
                        to_listener.try_send(transport::ToListenerMsg::Reservation(Err(error)))
                    {
                        tracing::debug!("Unable to send error to listener: {}", e.into_send_error())
                    }
                    self.reservation.failed();
                    continue;
                }
                Poll::Ready((
                    Err(futures_bounded::Timeout { .. }),
                    (mut to_listener, _dependency, _generation),
                )) => {
                    if self.reservation_draining {
                        continue;
                    }
                    if let Err(e) =
                        to_listener.try_send(transport::ToListenerMsg::Reservation(Err(
                            outbound_hop::ReserveError::Io(io::ErrorKind::TimedOut.into()),
                        )))
                    {
                        tracing::debug!("Unable to send error to listener: {}", e.into_send_error())
                    }
                    self.reservation.failed();
                    continue;
                }
                Poll::Pending => {}
            }

            // Circuits
            match self.inflight_outbound_connect_requests.poll_unpin(cx) {
                Poll::Ready((
                    Ok(Ok(outbound_hop::Circuit {
                        limit,
                        read_buffer,
                        stream,
                    })),
                    (to_dialer, dependency),
                )) => {
                    if to_dialer
                        .send(Ok(priv_client::Connection {
                            state: priv_client::ConnectionState::new_outbound(stream, read_buffer),
                            _dependency: dependency,
                        }))
                        .is_err()
                    {
                        tracing::debug!(
                            "Dropping newly established circuit because the listener is gone"
                        );
                        continue;
                    }

                    return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                        Event::OutboundCircuitEstablished { limit },
                    ));
                }
                Poll::Ready((Ok(Err(error)), (to_dialer, _dependency))) => {
                    let _ = to_dialer.send(Err(error));
                    continue;
                }
                Poll::Ready((Err(futures_bounded::Timeout { .. }), (to_dialer, _dependency))) => {
                    if to_dialer
                        .send(Err(outbound_hop::ConnectError::Io(
                            io::ErrorKind::TimedOut.into(),
                        )))
                        .is_err()
                    {
                        tracing::debug!("Unable to send error to dialer")
                    }
                    if !self.reservation_draining {
                        self.reservation.failed();
                    }
                    continue;
                }
                Poll::Pending => {}
            }

            // Return queued events.
            if let Some(event) = self.queued_events.pop_front() {
                return Poll::Ready(event);
            }

            match self.inflight_inbound_circuit_requests.poll_unpin(cx) {
                Poll::Ready((Ok(Ok(circuit)), dependency)) => match &mut self.reservation {
                    Reservation::Accepted { pending_msgs, .. }
                    | Reservation::Renewing { pending_msgs, .. } => {
                        let src_peer_id = circuit.src_peer_id();
                        let limit = circuit.limit();

                        let connection = super::ConnectionState::new_inbound(circuit);

                        pending_msgs.push_back(
                            transport::ToListenerMsg::IncomingRelayedConnection {
                                stream: super::Connection {
                                    state: connection,
                                    _dependency: dependency,
                                },
                                src_peer_id,
                                relay_peer_id: self.remote_peer_id,
                                relay_addr: self.remote_addr.clone(),
                            },
                        );
                        return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                            Event::InboundCircuitEstablished { src_peer_id, limit },
                        ));
                    }
                    Reservation::None | Reservation::Pending { .. } => {
                        self.insert_to_deny_futs(circuit, dependency);
                        continue;
                    }
                },
                Poll::Ready((Ok(Err(e)), _dependency)) => {
                    tracing::debug!("An inbound circuit request failed: {e}");
                    continue;
                }
                Poll::Ready((Err(e), _dependency)) => {
                    tracing::debug!("An inbound circuit request timed out: {e}");
                    continue;
                }
                Poll::Pending => {}
            }

            if let Poll::Ready(Some(to_listener)) = self.reservation.poll(cx) {
                self.make_new_reservation(to_listener, self.dependencies.lease());
                continue;
            }

            // Deny incoming circuit requests.
            match self.inflight_outbound_circuit_deny_requests.poll_unpin(cx) {
                Poll::Ready(Ok(Ok(()))) => continue,
                Poll::Ready(Ok(Err(error))) => {
                    tracing::debug!("Denying inbound circuit failed: {error}");
                    continue;
                }
                Poll::Ready(Err(futures_bounded::Timeout { .. })) => {
                    tracing::debug!("Denying inbound circuit timed out");
                    continue;
                }
                Poll::Pending => {}
            }

            return Poll::Pending;
        }
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<
            Self::InboundProtocol,
            Self::OutboundProtocol,
            Self::InboundOpenInfo,
            Self::OutboundOpenInfo,
        >,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                protocol: stream,
                info: dependency,
                ..
            }) => {
                if self
                    .inflight_inbound_circuit_requests
                    .try_push(inbound_stop::handle_open_circuit(stream), dependency)
                    .is_err()
                {
                    tracing::warn!("Dropping inbound stream because we are at capacity")
                }
            }
            ConnectionEvent::FullyNegotiatedOutbound(ev) => {
                if let Some(next) = self.pending_streams.pop_front() {
                    let _ = next.send(Ok(ev.protocol));
                }
            }
            ConnectionEvent::ListenUpgradeError(ev) => libp2p_core::util::unreachable(ev.error),
            ConnectionEvent::DialUpgradeError(ev) => {
                if let Some(next) = self.pending_streams.pop_front() {
                    let _ = next.send(Err(ev.error));
                }
            }
            _ => {}
        }
    }
}

enum Reservation {
    /// Retain the listener while its first codec completes, even if drained.
    Pending {
        _to_listener: mpsc::Sender<transport::ToListenerMsg>,
    },
    /// The Reservation is accepted by the relay.
    Accepted {
        _dependency: Option<DependencyLease>,
        renewal_timeout: Option<Delay>,
        /// Buffer of messages to be send to the transport listener.
        pending_msgs: VecDeque<transport::ToListenerMsg>,
        to_listener: mpsc::Sender<transport::ToListenerMsg>,
    },
    /// The reservation is being renewed with the relay.
    Renewing {
        _dependency: Option<DependencyLease>,
        /// Buffer of messages to be send to the transport listener.
        pending_msgs: VecDeque<transport::ToListenerMsg>,
        to_listener: mpsc::Sender<transport::ToListenerMsg>,
    },
    None,
}

impl Reservation {
    fn accepted(
        &mut self,
        renewal_timeout: Option<Delay>,
        addrs: Vec<Multiaddr>,
        to_listener: mpsc::Sender<transport::ToListenerMsg>,
        local_peer_id: PeerId,
        limit: Option<protocol::Limit>,
        dependency: Option<DependencyLease>,
    ) -> Event {
        let (renewal, mut pending_msgs) = match std::mem::replace(self, Self::None) {
            Reservation::Accepted { pending_msgs, .. }
            | Reservation::Renewing { pending_msgs, .. } => (true, pending_msgs),
            Reservation::None | Reservation::Pending { .. } => (false, VecDeque::new()),
        };

        pending_msgs.push_back(transport::ToListenerMsg::Reservation(Ok(
            transport::Reservation {
                addrs: addrs
                    .into_iter()
                    .map(|a| {
                        a.with(Protocol::P2pCircuit)
                            .with(Protocol::P2p(local_peer_id))
                    })
                    .collect(),
            },
        )));

        *self = Reservation::Accepted {
            _dependency: dependency,
            renewal_timeout,
            pending_msgs,
            to_listener,
        };

        Event::ReservationReqAccepted { renewal, limit }
    }

    fn is_some(&self) -> bool {
        matches!(self, Self::Accepted { .. } | Self::Renewing { .. })
    }

    fn drain(&mut self) {
        match self {
            Self::Accepted {
                _dependency,
                renewal_timeout,
                ..
            } => {
                *_dependency = None;
                *renewal_timeout = None;
            }
            Self::Renewing { _dependency, .. } => *_dependency = None,
            Self::None | Self::Pending { .. } => {}
        }
    }

    /// Marks the current reservation as failed.
    fn failed(&mut self) {
        *self = Reservation::None;
    }

    fn forward_messages_to_transport_listener(&mut self, cx: &mut Context<'_>) {
        if let Reservation::Accepted {
            pending_msgs,
            to_listener,
            ..
        }
        | Reservation::Renewing {
            pending_msgs,
            to_listener,
            ..
        } = self
        {
            if !pending_msgs.is_empty() {
                match to_listener.poll_ready(cx) {
                    Poll::Ready(Ok(())) => {
                        if let Err(e) = to_listener
                            .start_send(pending_msgs.pop_front().expect("Called !is_empty()."))
                        {
                            tracing::debug!("Failed to sent pending message to listener: {:?}", e);
                            *self = Reservation::None;
                        } else if !pending_msgs.is_empty() {
                            cx.waker().wake_by_ref();
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        tracing::debug!("Channel to listener failed: {:?}", e);
                        *self = Reservation::None;
                    }
                    Poll::Pending => {}
                }
            }
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<mpsc::Sender<transport::ToListenerMsg>>> {
        self.forward_messages_to_transport_listener(cx);

        // Check renewal timeout if any.
        let (next_reservation, poll_val) = match std::mem::replace(self, Reservation::None) {
            Reservation::Accepted {
                _dependency,
                mut renewal_timeout,
                pending_msgs,
                to_listener,
            } => match renewal_timeout.as_mut().map(|timer| timer.poll_unpin(cx)) {
                Some(Poll::Ready(())) => (
                    Reservation::Renewing {
                        pending_msgs,
                        _dependency,
                        to_listener: to_listener.clone(),
                    },
                    Poll::Ready(Some(to_listener)),
                ),
                _ => (
                    Reservation::Accepted {
                        _dependency,
                        renewal_timeout,
                        pending_msgs,
                        to_listener,
                    },
                    Poll::Pending,
                ),
            },
            r => (r, Poll::Pending),
        };
        *self = next_reservation;

        poll_val
    }
}

fn into_reserve_error(e: StreamUpgradeError<Infallible>) -> outbound_hop::ReserveError {
    match e {
        StreamUpgradeError::Timeout => {
            outbound_hop::ReserveError::Io(io::ErrorKind::TimedOut.into())
        }
        StreamUpgradeError::Apply(never) => libp2p_core::util::unreachable(never),
        StreamUpgradeError::NegotiationFailed => outbound_hop::ReserveError::Unsupported,
        StreamUpgradeError::Io(e) => outbound_hop::ReserveError::Io(e),
    }
}

fn into_connect_error(e: StreamUpgradeError<Infallible>) -> outbound_hop::ConnectError {
    match e {
        StreamUpgradeError::Timeout => {
            outbound_hop::ConnectError::Io(io::ErrorKind::TimedOut.into())
        }
        StreamUpgradeError::Apply(never) => libp2p_core::util::unreachable(never),
        StreamUpgradeError::NegotiationFailed => outbound_hop::ConnectError::Unsupported,
        StreamUpgradeError::Io(e) => outbound_hop::ConnectError::Io(e),
    }
}

#[cfg(test)]
mod drain_tests {
    use super::*;
    use futures::{task::noop_waker_ref, StreamExt};

    #[test]
    fn draining_inflight_renewal_preserves_listener_and_other_leases() {
        for success in [true, false] {
            let dependencies = Dependencies::default();
            let mut handler = Handler::new(
                PeerId::random(),
                PeerId::random(),
                Multiaddr::empty(),
                dependencies.clone(),
            );
            let (to_listener, mut listener) = mpsc::channel(0);
            handler.reservation = Reservation::Renewing {
                _dependency: Some(dependencies.lease()),
                pending_msgs: VecDeque::from([ToListenerMsg::Reservation(Ok(
                    transport::Reservation { addrs: vec![] },
                ))]),
                to_listener: to_listener.clone(),
            };
            let (send, receive) = oneshot::channel();
            assert!(handler
                .inflight_reserve_requests
                .try_push(
                    async move { receive.await.unwrap() },
                    (
                        to_listener,
                        dependencies.lease(),
                        handler.reservation_generation.clone()
                    ),
                )
                .is_ok());
            let circuit = dependencies.lease();
            let mut cx = Context::from_waker(noop_waker_ref());
            assert!(handler.connection_keep_alive());
            dependencies.set_reservation_draining(true);
            handler.on_behaviour_event(In::DrainReservation {
                dependency: dependencies.lease(),
            });
            assert!(!handler.connection_keep_alive());
            assert!(handler.poll(&mut cx).is_pending());
            assert!(matches!(
                listener.poll_next_unpin(&mut cx),
                Poll::Ready(Some(ToListenerMsg::Reservation(Ok(_))))
            ));
            // Reservation-only ownership is gone, but codec and circuit remain.
            assert_eq!(dependencies.0.load(std::sync::atomic::Ordering::Relaxed), 2);
            let result = if success {
                Ok(outbound_hop::Reservation {
                    renewal_timeout: Delay::new(Duration::ZERO),
                    addrs: vec![],
                    limit: None,
                })
            } else {
                Err(outbound_hop::ReserveError::Refused)
            };
            assert!(send.send(result).is_ok());
            if success {
                assert!(matches!(
                    handler.poll(&mut cx),
                    Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                        Event::ReservationReqAccepted { renewal: true, .. }
                    ))
                ));
                assert!(matches!(
                    &handler.reservation,
                    Reservation::Accepted {
                        _dependency: None,
                        renewal_timeout: None,
                        ..
                    }
                ));
            } else {
                assert!(handler.poll(&mut cx).is_pending());
                assert!(matches!(
                    &handler.reservation,
                    Reservation::Renewing {
                        _dependency: None,
                        ..
                    }
                ));
            }
            assert!(!handler.connection_keep_alive());
            assert!(handler.poll(&mut cx).is_pending());
            assert!(handler.reservation.is_some());
            assert_eq!(dependencies.0.load(std::sync::atomic::Ordering::Relaxed), 1);
            drop(circuit);
            assert!(!dependencies.is_in_use());
            // Even after the codec completes the old listener is still open.
            if success {
                assert!(matches!(
                    listener.poll_next_unpin(&mut cx),
                    Poll::Ready(Some(_))
                ));
            }
            assert!(listener.poll_next_unpin(&mut cx).is_pending());
        }
    }

    #[test]
    fn fresh_reserve_ignores_a_superseded_codec_and_requires_new_confirmation() {
        let dependencies = Dependencies::default();
        let mut handler = Handler::new(
            PeerId::random(),
            PeerId::random(),
            Multiaddr::empty(),
            dependencies.clone(),
        );
        let (old_listener, _old_receive) = mpsc::channel(0);
        assert!(handler
            .inflight_reserve_requests
            .try_push(
                async {
                    Ok(outbound_hop::Reservation {
                        renewal_timeout: Delay::new(Duration::ZERO),
                        addrs: vec![],
                        limit: None,
                    })
                },
                (
                    old_listener,
                    dependencies.lease(),
                    handler.reservation_generation.clone()
                ),
            )
            .is_ok());
        dependencies.set_reservation_draining(true);
        handler.on_behaviour_event(In::DrainReservation {
            dependency: dependencies.lease(),
        });
        let (to_listener, _listener) = mpsc::channel(0);
        dependencies.set_reservation_draining(false);
        handler.on_behaviour_event(In::Reserve {
            listener_id: ListenerId::next(),
            to_listener,
            dependency: dependencies.lease(),
        });
        let mut cx = Context::from_waker(noop_waker_ref());
        assert!(!handler.reservation_draining);
        assert!(matches!(
            handler.poll(&mut cx),
            Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest { .. })
        ));
        assert!(!handler.reservation.is_some());
        assert!(!handler.connection_keep_alive());
        assert!(handler.poll(&mut cx).is_pending());
    }

    #[test]
    fn drain_requested_before_command_delivery_preserves_a_failed_pending_listener() {
        let dependencies = Dependencies::default();
        let mut handler = Handler::new(
            PeerId::random(),
            PeerId::random(),
            Multiaddr::empty(),
            dependencies.clone(),
        );
        let (to_listener, mut listener) = mpsc::channel(0);
        handler.on_behaviour_event(In::Reserve {
            listener_id: ListenerId::next(),
            to_listener,
            dependency: dependencies.lease(),
        });
        let mut cx = Context::from_waker(noop_waker_ref());
        let Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest { protocol }) =
            handler.poll(&mut cx)
        else {
            panic!("missing reserve negotiation")
        };
        let (_, info) = protocol.into_upgrade();
        // Policy is requested before the handler gets its command. Simulate the
        // reserve codec failing in that interval, without cancelling the listener.
        let drain = In::DrainReservation {
            dependency: dependencies.lease(),
        };
        dependencies.set_reservation_draining(true);
        handler.on_connection_event(ConnectionEvent::DialUpgradeError(
            libp2p_swarm::handler::DialUpgradeError {
                info,
                error: StreamUpgradeError::NegotiationFailed,
            },
        ));
        assert!(handler.poll(&mut cx).is_pending());
        assert!(listener.poll_next_unpin(&mut cx).is_pending());
        assert!(matches!(handler.reservation, Reservation::Pending { .. }));
        assert!(
            dependencies.is_in_use(),
            "undelivered policy must still pin the owner"
        );
        handler.on_behaviour_event(drain);
        assert!(!dependencies.is_in_use());
        assert!(!handler.connection_keep_alive());
        assert!(listener.poll_next_unpin(&mut cx).is_pending());
    }
}
