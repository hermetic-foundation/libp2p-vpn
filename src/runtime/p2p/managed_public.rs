//! Carry exact discovery intent through DNS indirection and transport selection.

use crate::runtime::physical_network::{
    control::ControlRoutes,
    public_discovery::{self, DIAL},
};
use futures::{FutureExt as _, future::BoxFuture};
use libp2p::{
    Multiaddr, PeerId, Transport,
    core::{
        muxing::StreamMuxerBox,
        transport::{
            Boxed, DialOpts, ListenerId, PortUse, TransportError, TransportEvent,
            dial_connection_id,
        },
    },
    multiaddr::Protocol,
    swarm::ConnectionId,
};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

type Output = (PeerId, StreamMuxerBox);
type Upgrade = BoxFuture<'static, io::Result<Output>>;

impl libp2p::kad::OutboundDiscoveryPolicy for ControlRoutes {
    fn start_dial(&self, connection: ConnectionId) -> bool {
        self.mark_public_discovery_dial(connection).is_ok()
    }

    fn finish_dial(&self, connection: ConnectionId) {
        self.finish_public_discovery_dial(connection);
    }

    fn allows_connection(&self, peer: PeerId, connection: ConnectionId) -> bool {
        self.public_discovery_connection_available(peer, connection)
    }
}

pub(super) struct CircuitEntrancePolicy {
    routes: Arc<ControlRoutes>,
    // None is an explicit relay reservation; Some is a configured member's
    // explicit entrance. Learning another address for either does not exempt it.
    explicit: Vec<(PeerId, Multiaddr, Option<PeerId>)>,
}

impl CircuitEntrancePolicy {
    pub(super) fn new(routes: Arc<ControlRoutes>, config: &super::HostConfig) -> Self {
        let explicit = config
            .relay_reservations
            .iter()
            .map(|addr| (addr, None))
            .chain(
                config
                    .known_peers
                    .iter()
                    .filter(|(_, addr)| super::is_relayed_address(addr))
                    .map(|(member, addr)| (addr, Some(*member))),
            )
            .filter_map(|(addr, destination)| {
                let (relay, mut entrance) = super::relay_peer_address_from_reservation(addr)?;
                if entrance.pop() != Some(Protocol::P2p(relay)) {
                    return None;
                }
                Some((relay, entrance, destination))
            })
            .collect();
        Self { routes, explicit }
    }
}

impl libp2p::relay::client::CircuitEntrancePolicy for CircuitEntrancePolicy {
    fn requires_scope(&self, relay: PeerId, entrance: &Multiaddr, destination: PeerId) -> bool {
        super::super::runner::relay_transport_is_publicly_dialable(entrance)
            && !self.explicit.iter().any(|(owner, address, member)| {
                *owner == relay
                    && address == entrance
                    && member.is_none_or(|member| member == destination)
            })
    }

    fn start_dial(&self, connection: ConnectionId) -> bool {
        self.routes.mark_public_discovery_dial(connection).is_ok()
    }

    fn finish_dial(&self, connection: ConnectionId) {
        self.routes.finish_public_discovery_dial(connection);
    }

    fn allows_connection(&self, relay: PeerId, connection: ConnectionId) -> bool {
        self.routes
            .public_discovery_connection_available(relay, connection)
    }
}

pub(in crate::runtime) fn transport(
    physical_and_relay: Boxed<Output>,
    routes: Arc<ControlRoutes>,
) -> Boxed<Output> {
    scoped_transport(physical_and_relay, routes, false)
}

#[cfg(target_os = "linux")]
pub(crate) fn discovery_only_transport(
    physical: Boxed<Output>,
    routes: Arc<ControlRoutes>,
) -> Boxed<Output> {
    scoped_transport(physical, routes, true)
}

fn scoped_transport(
    physical_and_relay: Boxed<Output>,
    routes: Arc<ControlRoutes>,
    discovery_only: bool,
) -> Boxed<Output> {
    // Check again after DNS TXT expansion. It must never turn a scoped dial
    // into an unowned relay circuit or other non-physical transport.
    let resolved = ScopedTransport::new(physical_and_relay, None, discovery_only);
    #[cfg(target_os = "linux")]
    let resolver =
        crate::runtime::physical_network::linux::egress::public_discovery::dns::Resolver::new();
    #[cfg(target_os = "android")]
    let resolver = crate::runtime::physical_network::android::dns::NetworkResolver::new();
    let dns = libp2p::dns::Transport::with_resolver(resolved, resolver);
    ScopedTransport::new(dns.boxed(), Some(routes), discovery_only).boxed()
}

struct ScopedTransport {
    inner: Arc<Mutex<Boxed<Output>>>,
    routes: Option<Arc<ControlRoutes>>,
    discovery_only: bool,
}

impl ScopedTransport {
    fn new(inner: Boxed<Output>, routes: Option<Arc<ControlRoutes>>, discovery_only: bool) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
            routes,
            discovery_only,
        }
    }
}

impl Transport for ScopedTransport {
    type Output = Output;
    type Error = io::Error;
    type Dial = Upgrade;
    type ListenerUpgrade = Upgrade;

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        if self.discovery_only {
            return Err(blocked());
        }
        self.inner
            .lock()
            .expect("managed transport")
            .listen_on(id, addr)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.inner
            .lock()
            .expect("managed transport")
            .remove_listener(id)
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        mut opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        let id = dial_connection_id();
        if self.routes.is_none() {
            let scoped = public_discovery::current().is_some();
            if (scoped && !is_direct(&addr))
                || (self.discovery_only
                    && (!scoped
                        || !super::super::runner::public_discovery_transport_is_publicly_dialable(
                            &addr,
                        )))
            {
                return Err(blocked());
            }
        }
        let scope = if let (Some(routes), Some(id)) = (&self.routes, id) {
            routes
                .public_discovery_dial(ConnectionId::new_unchecked(id))
                .map_err(TransportError::Other)?
        } else {
            None
        };
        let Some(scope) = scope else {
            if self.discovery_only && self.routes.is_some() {
                return Err(blocked());
            }
            return dial_inner(&self.inner, addr, opts, id);
        };
        if !opts.role.is_dialer() {
            return Err(blocked());
        }
        if addr.iter().any(|protocol| protocol == Protocol::P2pCircuit) {
            return Err(TransportError::Other(io::Error::new(
                io::ErrorKind::PermissionDenied,
                ScopedCircuitDenied(CircuitDeniedBeforeDial),
            )));
        }
        opts.port_use = PortUse::New;
        let inner = Arc::clone(&self.inner);
        Ok(async move {
            let dial = async {
                scope.check()?;
                let attempt = dial_inner(&inner, addr, opts, id).map_err(|error| match error {
                    TransportError::Other(error) => error,
                    TransportError::MultiaddrNotSupported(_) => io::ErrorKind::Unsupported.into(),
                })?;
                let connected = attempt.await?;
                scope.check()?;
                Ok(connected)
            };
            tokio::select! {
                biased;
                () = scope.invalidated() => {
                    scope.check()?;
                    Err(io::ErrorKind::Interrupted.into())
                }
                result = DIAL.scope(scope.clone(), dial) => result,
            }
        }
        .boxed())
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Pin::new(&mut *self.inner.lock().expect("managed transport")).poll(cx)
    }
}

fn dial_inner(
    inner: &Mutex<Boxed<Output>>,
    addr: Multiaddr,
    opts: DialOpts,
    id: Option<usize>,
) -> Result<Upgrade, TransportError<io::Error>> {
    let mut inner = inner.lock().expect("managed transport");
    match id {
        Some(id) => inner.dial_with_connection_id(addr, opts, id),
        None => inner.dial(addr, opts),
    }
}

const DISCOVERY_DENIED: &str = "public discovery requires a direct physical TCP or QUIC dial";

#[derive(Debug)]
struct CircuitDeniedBeforeDial;

impl std::fmt::Display for CircuitDeniedBeforeDial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(DISCOVERY_DENIED)
    }
}

impl std::error::Error for CircuitDeniedBeforeDial {}

#[derive(Debug)]
struct ScopedCircuitDenied(CircuitDeniedBeforeDial);

impl std::fmt::Display for ScopedCircuitDenied {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for ScopedCircuitDenied {
    // The swarm's Either and io::Error wrappers forward source() without
    // yielding their immediate payload. Keep the marker in that chain.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

pub(in crate::runtime) fn is_circuit_denied_before_dial(error: &io::Error) -> bool {
    let mut cause = std::error::Error::source(error);
    while let Some(error) = cause {
        if error.is::<CircuitDeniedBeforeDial>() {
            return true;
        }
        cause = error.source();
    }
    false
}

fn blocked() -> TransportError<io::Error> {
    TransportError::Other(io::Error::new(
        io::ErrorKind::PermissionDenied,
        DISCOVERY_DENIED,
    ))
}

fn is_direct(addr: &Multiaddr) -> bool {
    let mut protocols = addr.iter();
    let ip = match protocols.next() {
        Some(Protocol::Ip4(ip)) => ip.into(),
        Some(Protocol::Ip6(ip)) => ip.into(),
        _ => return false,
    };
    let port = match protocols.next() {
        Some(Protocol::Tcp(port)) => port,
        Some(Protocol::Udp(port)) if protocols.next() == Some(Protocol::QuicV1) => port,
        _ => return false,
    };
    public_discovery::valid_destination(SocketAddr::new(ip, port))
        && match protocols.next() {
            None => true,
            Some(Protocol::P2p(_)) => protocols.next().is_none(),
            _ => false,
        }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
