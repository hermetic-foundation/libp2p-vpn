//! Route-owned TCP with the existing libp2p multistream, Noise and Yamux engines.

use crate::runtime::physical_network::{
    control::{ControlRoutes, Registration},
    platform::{SocketProtocol, egress::RouteLease},
    public_discovery::{self, GuardedIo, Scope},
};
use futures::{AsyncRead, AsyncWrite, FutureExt, future::BoxFuture};
use libp2p::{
    Multiaddr, PeerId,
    core::{
        Negotiated,
        muxing::{StreamMuxer, StreamMuxerEvent},
        transport::{DialOpts, ListenerId, PortUse, TransportError, TransportEvent},
        upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade, UpgradeInfo},
    },
    identity::Keypair,
    multiaddr::Protocol,
    noise, tcp, yamux,
};
use std::{
    collections::HashSet,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

type Stream = tcp::tokio::TcpStream;
type Secured = noise::Output<Negotiated<GuardedIo<Stream>>>;
type InnerMuxer = yamux::Muxer<Negotiated<Secured>>;
type Upgrade = BoxFuture<'static, io::Result<(PeerId, OwnedMuxer)>>;
const MAX_REUSE_ADDRESSES: usize = 256;
const MAX_ACCEPTING: usize = 16;

pub(crate) struct Transport {
    inner: tcp::tokio::Transport,
    routes: Arc<ControlRoutes>,
    noise: noise::Config,
    listeners: HashSet<(ListenerId, SocketAddr)>,
    accepting: Arc<tokio::sync::Semaphore>,
}

impl Transport {
    pub(crate) fn new(key: &Keypair, routes: Arc<ControlRoutes>) -> Result<Self, noise::Error> {
        Ok(Self {
            inner: tcp::tokio::Transport::new(tcp::Config::default()),
            routes,
            noise: noise::Config::new(key)?,
            listeners: HashSet::new(),
            accepting: Arc::new(tokio::sync::Semaphore::new(MAX_ACCEPTING)),
        })
    }
}

impl libp2p::core::Transport for Transport {
    type Output = (PeerId, OwnedMuxer);
    type Error = io::Error;
    type Dial = Upgrade;
    type ListenerUpgrade = Upgrade;

    fn listen_on(
        &mut self,
        id: ListenerId,
        address: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        self.inner.listen_on(id, address)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        let removed = self.inner.remove_listener(id);
        if removed {
            self.listeners.retain(|(listener, _)| *listener != id);
        }
        removed
    }

    fn dial(
        &mut self,
        address: Multiaddr,
        options: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        let destination = socket_address(&address)
            .filter(|address| !address.ip().is_unspecified() && address.port() != 0)
            .ok_or_else(|| TransportError::MultiaddrNotSupported(address.clone()))?;
        let listeners = self
            .listeners
            .iter()
            .map(|(_, address)| *address)
            .collect::<Vec<_>>();
        let routes = Arc::clone(&self.routes);
        let noise = self.noise.clone();
        let public_discovery = public_discovery::current();
        #[cfg(target_os = "android")]
        let peer = address.iter().last().and_then(|protocol| match protocol {
            Protocol::P2p(peer) => Some(peer),
            _ => None,
        });
        Ok(async move {
            let _permit = routes.egress.connect_permit()?;
            if let Some(scope) = public_discovery {
                let stream = connect_public(&scope, destination).await?;
                return authenticate(
                    stream.0,
                    stream.1,
                    Arc::clone(&routes),
                    noise,
                    true,
                    Some(scope),
                )
                .await;
            }
            let reuse = options.port_use == PortUse::Reuse;
            #[cfg(target_os = "android")]
            return dial_android(
                Arc::clone(&routes),
                noise,
                destination,
                reuse,
                listeners,
                options.role.is_dialer(),
                peer,
            )
            .await;
            #[cfg(target_os = "linux")]
            {
                let result = connect(&routes, destination, reuse, &listeners).await;
                let (stream, lease) = match result {
                    Err(error)
                        if reuse
                            && matches!(
                                error.kind(),
                                io::ErrorKind::AddrNotAvailable | io::ErrorKind::AddrInUse
                            ) =>
                    {
                        // Best-effort reuse may collide with an existing four-tuple.
                        // The new-port attempt must select and bind its own route.
                        connect(&routes, destination, false, &[]).await?
                    }
                    result => result?,
                };
                authenticate(
                    GuardedIo::unrestricted(stream),
                    lease,
                    routes.clone(),
                    noise,
                    options.role.is_dialer(),
                    None,
                )
                .await
            }
        }
        .boxed())
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        let event = futures::ready!(Pin::new(&mut self.inner).poll(cx));
        match &event {
            TransportEvent::NewAddress {
                listener_id,
                listen_addr,
            } => {
                if self.listeners.len() < MAX_REUSE_ADDRESSES
                    && let Some(address) = socket_address(listen_addr)
                {
                    self.listeners.insert((*listener_id, address));
                }
            }
            TransportEvent::AddressExpired {
                listener_id,
                listen_addr,
            } => {
                if let Some(address) = socket_address(listen_addr) {
                    self.listeners.remove(&(*listener_id, address));
                }
            }
            TransportEvent::ListenerClosed { listener_id, .. } => {
                self.listeners.retain(|(id, _)| id != listener_id);
            }
            _ => {}
        }
        let routes = Arc::clone(&self.routes);
        let noise = self.noise.clone();
        let accepting = Arc::clone(&self.accepting);
        Poll::Ready(event.map_upgrade(move |incoming| -> Upgrade {
            async move {
                let stream = incoming.await?;
                let _permit = accepting.try_acquire_owned().map_err(|_| {
                    io::Error::new(io::ErrorKind::WouldBlock, "incoming TCP handshake limit")
                })?;
                let lease = routes.egress.prepare_tcp_stream(&stream.0).await?;
                authenticate(
                    GuardedIo::unrestricted(stream),
                    lease,
                    routes,
                    noise,
                    false,
                    None,
                )
                .await
            }
            .boxed()
        }))
    }
}

async fn connect_public(
    scope: &Scope,
    destination: SocketAddr,
) -> io::Result<(GuardedIo<Stream>, RouteLease)> {
    let (socket, lease) = scope
        .prepare_socket(destination, SocketProtocol::Tcp)
        .await?;
    let stream = public_discovery::connect_tcp(socket, lease.context.destination, scope).await?;
    let shutdown = socket2::SockRef::from(&stream).try_clone()?;
    let stream = GuardedIo::new(tcp::tokio::TcpStream(stream), scope.clone(), shutdown)?;
    Ok((stream, lease))
}

#[cfg(target_os = "linux")]
async fn connect(
    routes: &ControlRoutes,
    destination: SocketAddr,
    reuse: bool,
    listeners: &[SocketAddr],
) -> io::Result<(Stream, RouteLease)> {
    let (socket, lease) = routes
        .egress
        .prepare_tcp(destination, reuse, listeners)
        .await?;
    connect_prepared(socket, lease).await
}

async fn connect_prepared(
    socket: socket2::Socket,
    lease: RouteLease,
) -> io::Result<(Stream, RouteLease)> {
    if !lease.is_current() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "TCP route changed before connect",
        ));
    }
    let destination = lease.context.destination;
    let stream = tokio::net::TcpSocket::from_std_stream(socket.into())
        .connect(destination)
        .await?;
    let stream = tcp::tokio::TcpStream(stream);
    if !lease.is_current() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "TCP route changed while connecting",
        ));
    }
    Ok((stream, lease))
}

#[cfg(target_os = "android")]
async fn dial_android(
    routes: Arc<ControlRoutes>,
    noise: noise::Config,
    destination: SocketAddr,
    reuse: bool,
    listeners: Vec<SocketAddr>,
    outbound: bool,
    peer: Option<PeerId>,
) -> io::Result<(PeerId, OwnedMuxer)> {
    use crate::runtime::physical_network::android::{SocketProtocol, egress::Egress};
    let local = if destination.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0_u16; 8], 0))
    };
    let operation_routes = Arc::clone(&routes);
    let permission_routes = Arc::clone(&routes);
    let listeners = Arc::new(listeners);
    routes
        .egress
        .attempt_networks_if(
            local,
            destination,
            SocketProtocol::Tcp,
            0,
            move |lease| {
                let routes = Arc::clone(&operation_routes);
                let noise = noise.clone();
                let listeners = Arc::clone(&listeners);
                async move {
                    let saved = lease.clone();
                    let connect = |lease, reuse| {
                        let listeners = Arc::clone(&listeners);
                        async move {
                            let (socket, lease) = Egress::tcp_socket(lease, reuse, &listeners)?;
                            connect_prepared(socket, lease).await
                        }
                    };
                    let (stream, lease) = match connect(lease, reuse).await {
                        Err(error)
                            if reuse
                                && matches!(
                                    error.kind(),
                                    io::ErrorKind::AddrNotAvailable | io::ErrorKind::AddrInUse
                                ) =>
                        {
                            // Port reuse collision is not evidence against this Network.
                            connect(saved, false).await?
                        }
                        result => result?,
                    };
                    authenticate(
                        GuardedIo::unrestricted(stream),
                        lease,
                        routes,
                        noise,
                        outbound,
                        None,
                    )
                    .await
                }
            },
            move || permission_routes.network_fallback_allowed(peer),
        )
        .await
}

async fn select<S, I>(
    stream: S,
    protocols: I,
    outbound: bool,
) -> io::Result<(I::Item, Negotiated<S>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
    I: IntoIterator,
    I::Item: AsRef<str> + Clone,
{
    if outbound {
        multistream_select::dialer_select_proto(
            stream,
            protocols,
            multistream_select::Version::V1Lazy,
        )
        .await
        .map_err(negotiation_error)
    } else {
        multistream_select::listener_select_proto(stream, protocols)
            .await
            .map_err(negotiation_error)
    }
}

fn negotiation_error(error: multistream_select::NegotiationError) -> io::Error {
    match error {
        multistream_select::NegotiationError::ProtocolError(
            multistream_select::ProtocolError::IoError(error),
        ) => upgrade_io_error(error),
        error => io::Error::new(io::ErrorKind::InvalidData, error),
    }
}

fn noise_error(error: noise::Error) -> io::Error {
    match error {
        noise::Error::Io(error) => upgrade_io_error(error),
        error => io::Error::new(io::ErrorKind::InvalidData, error),
    }
}

fn upgrade_io_error(error: io::Error) -> io::Error {
    // V1Lazy can surface negotiation rejection through Noise's I/O variant.
    // Unwrap only known typed wrappers; ordinary I/O retains its errno/source.
    let Some(source) = error.get_ref() else {
        return error;
    };
    if source.is::<multistream_select::NegotiationError>() {
        let source = error.into_inner().expect("typed negotiation error");
        return negotiation_error(*source.downcast().expect("checked negotiation error type"));
    }
    if source.is::<multistream_select::ProtocolError>() {
        let source = error.into_inner().expect("typed protocol error");
        let protocol = *source
            .downcast::<multistream_select::ProtocolError>()
            .expect("checked protocol error type");
        return negotiation_error(protocol.into());
    }
    if source.is::<noise::Error>() {
        let source = error.into_inner().expect("typed Noise error");
        return noise_error(*source.downcast().expect("checked Noise error type"));
    }
    if source.is::<io::Error>() {
        let source = error.into_inner().expect("nested I/O error");
        return upgrade_io_error(*source.downcast().expect("checked I/O error type"));
    }
    error
}

async fn authenticate(
    stream: GuardedIo<Stream>,
    lease: RouteLease,
    routes: Arc<ControlRoutes>,
    noise: noise::Config,
    outbound: bool,
    public_discovery: Option<Scope>,
) -> io::Result<(PeerId, OwnedMuxer)> {
    let (protocol, negotiated) = select(stream, noise.protocol_info(), outbound).await?;
    let (peer, secured) = if outbound {
        noise.upgrade_outbound(negotiated, protocol).await
    } else {
        noise.upgrade_inbound(negotiated, protocol).await
    }
    .map_err(noise_error)?;
    let yamux = yamux::Config::default();
    let (protocol, negotiated) = select(secured, yamux.protocol_info(), outbound).await?;
    let inner = if outbound {
        yamux.upgrade_outbound(negotiated, protocol).await
    } else {
        yamux.upgrade_inbound(negotiated, protocol).await
    }?;
    let registration = routes.register_scoped(peer, lease, public_discovery)?;
    Ok((
        peer,
        OwnedMuxer {
            inner,
            registration,
            adopted: false,
            association_failed: false,
        },
    ))
}

pub(crate) struct OwnedMuxer {
    inner: InnerMuxer,
    registration: Registration,
    adopted: bool,
    association_failed: bool,
}

impl OwnedMuxer {
    fn adopt(&mut self) -> io::Result<()> {
        if self.association_failed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid TCP swarm connection association",
            ));
        }
        if !self.adopted {
            self.registration.adopt()?;
            self.adopted = true;
        }
        Ok(())
    }
}

impl StreamMuxer for OwnedMuxer {
    type Substream = yamux::Stream;
    type Error = io::Error;
    fn on_swarm_connection(mut self: Pin<&mut Self>, connection_id: usize) {
        if self
            .registration
            .bind_connection(libp2p::swarm::ConnectionId::new_unchecked(connection_id))
            .is_err()
        {
            self.association_failed = true;
        }
    }
    fn poll_inbound(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        self.adopt()?;
        Pin::new(&mut self.inner)
            .poll_inbound(cx)
            .map_err(io::Error::other)
    }
    fn poll_outbound(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        self.adopt()?;
        Pin::new(&mut self.inner)
            .poll_outbound(cx)
            .map_err(io::Error::other)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_close(cx)
            .map_err(io::Error::other)
    }
    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<StreamMuxerEvent, Self::Error>> {
        self.adopt()?;
        Pin::new(&mut self.inner).poll(cx).map_err(io::Error::other)
    }
}

fn socket_address(address: &Multiaddr) -> Option<SocketAddr> {
    let mut address = address.clone();
    let mut port = None;
    while let Some(protocol) = address.pop() {
        match protocol {
            Protocol::Tcp(value) if port.is_none() => port = Some(value),
            Protocol::Ip4(ip) => return port.map(|port| SocketAddr::new(ip.into(), port)),
            Protocol::Ip6(ip) => return port.map(|port| SocketAddr::new(ip.into(), port)),
            Protocol::P2p(_) => {}
            _ => return None,
        }
    }
    None
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
