//! Only explicit bootstrap circuit attempts may reach the relay transport.

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use libp2p::{
    Multiaddr, PeerId, Transport,
    core::{
        muxing::StreamMuxerBox,
        transport::{
            Boxed, DialOpts, ListenerId, TransportError, TransportEvent, dial_connection_id,
        },
        upgrade::{Version, apply},
    },
    identity::Keypair,
    multiaddr::Protocol,
    noise, relay,
    swarm::{ConnectionId, SwarmEvent},
    yamux,
};

use crate::runtime::{
    physical_network::{control::ControlRoutes, public_discovery::Scope},
    runner::public_discovery_transport_is_publicly_dialable,
};

const HINT_TTL: Duration = Duration::from_secs(10);
const CONNECT_BUDGET: Duration = Duration::from_secs(8);
type Circuit = (PeerId, StreamMuxerBox);

pub(super) struct Hint {
    pub(super) address: Multiaddr,
    scope: Scope,
    expires: Instant,
}

impl Hint {
    pub(super) fn new(
        address: Multiaddr,
        provider: PeerId,
        scope: &Scope,
        now: Instant,
    ) -> Option<Self> {
        if !scope.is_current() || !eligible(&address, provider) {
            return None;
        }
        Some(Self {
            address,
            scope: scope.clone(),
            expires: now + HINT_TTL,
        })
    }

    fn current(&self, now: Instant) -> bool {
        now < self.expires && self.scope.is_current()
    }
}

fn eligible(address: &Multiaddr, provider: PeerId) -> bool {
    let mut parts = address.iter();
    if !matches!(parts.next(), Some(Protocol::Ip4(_) | Protocol::Ip6(_)))
        || !public_discovery_transport_is_publicly_dialable(address)
    {
        return false;
    }
    match parts.next() {
        Some(Protocol::Tcp(port)) if port != 0 => {}
        Some(Protocol::Udp(port)) if port != 0 && parts.next() == Some(Protocol::QuicV1) => {}
        _ => return false,
    }
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(Protocol::P2p(relay)), Some(Protocol::P2pCircuit), Some(Protocol::P2p(peer)), None)
            if relay != peer && peer == provider
    )
}

pub(super) struct Gate {
    routes: Arc<ControlRoutes>,
    pending: Mutex<Option<Attempt>>,
}

struct Attempt {
    id: ConnectionId,
    peer: PeerId,
    hint: Hint,
}

impl Gate {
    pub(super) fn scope(&self) -> io::Result<Scope> {
        Scope::new(Arc::clone(&self.routes.egress))
    }

    pub(super) fn reserve(&self, id: ConnectionId, peer: PeerId, hint: Hint, now: Instant) -> bool {
        let Ok(mut pending) = self.pending.lock() else {
            return false;
        };
        if pending.is_some() || !hint.current(now) {
            return false;
        }
        *pending = Some(Attempt { id, peer, hint });
        true
    }

    pub(super) fn busy(&self) -> bool {
        self.pending
            .lock()
            .map_or(true, |pending| pending.is_some())
    }

    pub(super) fn finish(&self, id: ConnectionId) -> Option<(PeerId, Scope)> {
        let mut pending = self.pending.lock().ok()?;
        if pending.as_ref()?.id != id {
            return None;
        }
        pending
            .take()
            .map(|attempt| (attempt.peer, attempt.hint.scope))
    }

    pub(super) fn observe<T>(
        &self,
        event: &SwarmEvent<T>,
    ) -> Option<(PeerId, ConnectionId, Option<Scope>)> {
        match event {
            SwarmEvent::ConnectionEstablished {
                connection_id,
                peer_id,
                endpoint,
                ..
            } => {
                let (expected, scope) = self.finish(*connection_id)?;
                let accepted = expected == *peer_id && endpoint.is_relayed() && scope.is_current();
                Some((expected, *connection_id, accepted.then_some(scope)))
            }
            SwarmEvent::OutgoingConnectionError { connection_id, .. } => {
                let (expected, _) = self.finish(*connection_id)?;
                Some((expected, *connection_id, None))
            }
            _ => None,
        }
    }
}

impl relay::client::CircuitEntrancePolicy for Gate {
    fn requires_scope(&self, _: PeerId, _: &Multiaddr, _: PeerId) -> bool {
        true
    }

    fn start_dial(&self, connection: ConnectionId) -> bool {
        self.pending.lock().is_ok_and(|pending| {
            pending.as_ref().is_some_and(|attempt| {
                attempt.hint.current(Instant::now())
                    && self
                        .routes
                        .mark_public_discovery_dial_in_scope(connection, &attempt.hint.scope)
                        .is_ok()
            })
        })
    }

    fn finish_dial(&self, connection: ConnectionId) {
        self.routes.finish_public_discovery_dial(connection);
    }

    fn allows_connection(&self, _: PeerId, _: ConnectionId) -> bool {
        // Never use another connection to the relay outside the exact scoped dial.
        false
    }
}

pub(super) fn transport(
    keypair: &Keypair,
    routes: Arc<ControlRoutes>,
) -> Result<(Boxed<Circuit>, relay::client::Behaviour, Arc<Gate>), noise::Error> {
    let gate = Arc::new(Gate {
        routes,
        pending: Mutex::new(None),
    });
    let (transport, mut client) = relay::client::new(keypair.public().to_peer_id());
    client.set_circuit_entrance_policy(gate.clone());
    let noise = noise::Config::new(keypair)?;
    let transport = transport.and_then(move |circuit, endpoint| {
        let noise = noise.clone();
        async move {
            let (peer, secured) = apply(circuit, noise, endpoint.clone(), Version::V1Lazy)
                .await
                .map_err(io::Error::other)?;
            let muxer = apply(secured, yamux::Config::default(), endpoint, Version::V1Lazy)
                .await
                .map_err(io::Error::other)?;
            Ok::<_, io::Error>((peer, StreamMuxerBox::new(muxer)))
        }
    });
    Ok((
        TransportGate {
            inner: libp2p::core::transport::timeout::TransportTimeout::new(
                transport,
                CONNECT_BUDGET,
            )
            .boxed(),
            gate: gate.clone(),
        }
        .boxed(),
        client,
        gate,
    ))
}

struct TransportGate {
    inner: Boxed<Circuit>,
    gate: Arc<Gate>,
}

impl Transport for TransportGate {
    type Output = Circuit;
    type Error = io::Error;
    type ListenerUpgrade = <Boxed<Circuit> as Transport>::ListenerUpgrade;
    type Dial = <Boxed<Circuit> as Transport>::Dial;

    fn dial(
        &mut self,
        address: Multiaddr,
        options: DialOpts,
    ) -> Result<Self::Dial, TransportError<io::Error>> {
        let dial_id = dial_connection_id();
        let id = dial_id.map(ConnectionId::new_unchecked);
        if !self.gate.pending.lock().is_ok_and(|pending| {
            pending.as_ref().is_some_and(|attempt| {
                Some(attempt.id) == id
                    && attempt.hint.address == address
                    && attempt.hint.current(Instant::now())
            })
        }) {
            return Err(TransportError::MultiaddrNotSupported(address));
        }
        self.inner
            .dial_with_connection_id(address, options, dial_id.expect("admitted dial"))
    }

    fn listen_on(
        &mut self,
        _: ListenerId,
        address: Multiaddr,
    ) -> Result<(), TransportError<io::Error>> {
        Err(TransportError::MultiaddrNotSupported(address))
    }

    fn remove_listener(&mut self, _: ListenerId) -> bool {
        false
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, io::Error>> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

#[cfg(test)]
mod tests;
