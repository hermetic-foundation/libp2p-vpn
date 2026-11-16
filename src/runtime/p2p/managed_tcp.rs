//! Route-owned TCP with the existing libp2p multistream, Noise and Yamux engines.

use crate::runtime::physical_network::linux::{
    control::{ControlRoutes, Registration},
    egress::RouteLease,
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
type Secured = noise::Output<Negotiated<Stream>>;
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
        Ok(async move {
            let _permit = routes.egress.connect_permit()?;
            let reuse = options.port_use == PortUse::Reuse;
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
                stream,
                lease,
                routes.clone(),
                noise,
                options.role.is_dialer(),
            )
            .await
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
                authenticate(stream, lease, routes.clone(), noise, false).await
            }
            .boxed()
        }))
    }
}

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
        .map_err(io::Error::other)
    } else {
        multistream_select::listener_select_proto(stream, protocols)
            .await
            .map_err(io::Error::other)
    }
}

async fn authenticate(
    stream: Stream,
    lease: RouteLease,
    routes: Arc<ControlRoutes>,
    noise: noise::Config,
    outbound: bool,
) -> io::Result<(PeerId, OwnedMuxer)> {
    let (protocol, negotiated) = select(stream, noise.protocol_info(), outbound).await?;
    let (peer, secured) = if outbound {
        noise.upgrade_outbound(negotiated, protocol).await
    } else {
        noise.upgrade_inbound(negotiated, protocol).await
    }
    .map_err(io::Error::other)?;
    let yamux = yamux::Config::default();
    let (protocol, negotiated) = select(secured, yamux.protocol_info(), outbound).await?;
    let inner = if outbound {
        yamux.upgrade_outbound(negotiated, protocol).await
    } else {
        yamux.upgrade_inbound(negotiated, protocol).await
    }?;
    let registration = routes.register(peer, lease)?;
    Ok((
        peer,
        OwnedMuxer {
            inner,
            registration,
            adopted: false,
        },
    ))
}

pub(crate) struct OwnedMuxer {
    inner: InnerMuxer,
    registration: Registration,
    adopted: bool,
}

impl OwnedMuxer {
    fn adopt(&mut self) -> io::Result<()> {
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

#[cfg(test)]
mod tests;
