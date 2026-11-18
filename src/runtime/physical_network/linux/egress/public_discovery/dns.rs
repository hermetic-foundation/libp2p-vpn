//! Existing libp2p DNS configuration, with a separate resolver for each scoped dial.

use crate::runtime::physical_network::{
    platform::SocketProtocol,
    public_discovery::{self, GuardedIo, Scope},
};
use futures::{FutureExt as _, future::BoxFuture};
use hickory_proto::{
    runtime::{RuntimeProvider, TokioHandle, TokioTime, iocompat::AsyncIoTokioAsStd},
    tcp::DnsTcpStream,
    udp::DnsUdpSocket,
};
use hickory_resolver::{
    ResolveError, Resolver as HickoryResolver, TokioResolver,
    config::{ResolverConfig, ResolverOpts},
    lookup::{Ipv4Lookup, Ipv6Lookup, TxtLookup},
    lookup_ip::LookupIp,
    name_server::{GenericConnector, TokioConnectionProvider},
};
use std::{
    io,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

const QUERY_TIMEOUT: Duration = Duration::from_secs(6);

#[derive(Clone)]
pub(crate) struct Resolver(TokioResolver, Arc<tokio::sync::Semaphore>);

impl Resolver {
    pub(crate) fn new() -> Self {
        Self(
            TokioResolver::builder_with_config(
                ResolverConfig::default(),
                TokioConnectionProvider::default(),
            )
            .build(),
            Arc::new(tokio::sync::Semaphore::new(4)),
        )
    }
}

#[async_trait::async_trait]
impl libp2p::dns::Resolver for Resolver {
    async fn lookup_ip(&self, name: String) -> Result<LookupIp, ResolveError> {
        match public_discovery::current() {
            Some(scope) => {
                self.lookup(&scope, |resolver| resolver.lookup_ip(name).boxed())
                    .await
            }
            None => self.0.lookup_ip(name).await,
        }
    }

    async fn ipv4_lookup(&self, name: String) -> Result<Ipv4Lookup, ResolveError> {
        match public_discovery::current() {
            Some(scope) => {
                self.lookup(&scope, |resolver| resolver.ipv4_lookup(name).boxed())
                    .await
            }
            None => self.0.ipv4_lookup(name).await,
        }
    }

    async fn ipv6_lookup(&self, name: String) -> Result<Ipv6Lookup, ResolveError> {
        match public_discovery::current() {
            Some(scope) => {
                self.lookup(&scope, |resolver| resolver.ipv6_lookup(name).boxed())
                    .await
            }
            None => self.0.ipv6_lookup(name).await,
        }
    }

    async fn txt_lookup(&self, name: String) -> Result<TxtLookup, ResolveError> {
        match public_discovery::current() {
            Some(scope) => {
                self.lookup(&scope, |resolver| resolver.txt_lookup(name).boxed())
                    .await
            }
            None => self.0.txt_lookup(name).await,
        }
    }
}

type ScopedResolver = HickoryResolver<GenericConnector<Runtime>>;

impl<T: DnsTcpStream> DnsTcpStream for GuardedIo<T> {
    type Time = T::Time;
}

impl Resolver {
    async fn lookup<T>(
        &self,
        scope: &Scope,
        query: impl for<'a> FnOnce(&'a ScopedResolver) -> BoxFuture<'a, Result<T, ResolveError>>,
    ) -> Result<T, ResolveError> {
        let _permit = self
            .1
            .try_acquire()
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "public DNS query limit"))?;
        scope.check()?;
        let mut opts = ResolverOpts::default();
        opts.use_hosts_file = hickory_resolver::config::ResolveHosts::Never;
        opts.cache_size = 0;
        let resolver = HickoryResolver::builder_with_config(
            ResolverConfig::default(),
            GenericConnector::new(Runtime {
                scope: scope.clone(),
                handle: TokioHandle::default(),
            }),
        )
        .with_options(opts)
        .build();
        let answer = tokio::time::timeout(QUERY_TIMEOUT, query(&resolver))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "public DNS query deadline"))?;
        scope.check()?;
        answer
    }
}

#[derive(Clone)]
struct Runtime {
    scope: Scope,
    handle: TokioHandle,
}

struct ScopedUdp {
    socket: tokio::net::UdpSocket,
    scope: Scope,
    server: SocketAddr,
}

#[async_trait::async_trait]
impl DnsUdpSocket for ScopedUdp {
    type Time = TokioTime;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        self.scope
            .with_current(|| Ok(DnsUdpSocket::poll_recv_from(&self.socket, cx, buf)))
            .unwrap_or_else(|error| Poll::Ready(Err(error)))
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        server: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        if server != self.server {
            return Poll::Ready(Err(io::ErrorKind::PermissionDenied.into()));
        }
        self.scope
            .with_current(|| Ok(self.socket.poll_send_to(cx, buf, server)))
            .unwrap_or_else(|error| Poll::Ready(Err(error)))
    }
}

impl RuntimeProvider for Runtime {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = ScopedUdp;
    type Tcp = GuardedIo<AsyncIoTokioAsStd<tokio::net::TcpStream>>;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn bind_udp(
        &self,
        local: SocketAddr,
        server: SocketAddr,
    ) -> BoxFuture<'static, io::Result<Self::Udp>> {
        let scope = self.scope.clone();
        async move {
            if !local.ip().is_unspecified() || local.is_ipv4() != server.is_ipv4() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let (socket, _) = scope.prepare_socket(server, SocketProtocol::Udp).await?;
            let socket = tokio::net::UdpSocket::from_std(socket.into())?;
            Ok(ScopedUdp {
                socket,
                scope,
                server,
            })
        }
        .boxed()
    }

    fn connect_tcp(
        &self,
        server: SocketAddr,
        local: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> BoxFuture<'static, io::Result<Self::Tcp>> {
        let scope = self.scope.clone();
        async move {
            if local.is_some_and(|local| {
                !local.ip().is_unspecified() || local.is_ipv4() != server.is_ipv4()
            }) {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let (socket, lease) = scope.prepare_socket(server, SocketProtocol::Tcp).await?;
            let stream = tokio::time::timeout(
                timeout.unwrap_or(QUERY_TIMEOUT).min(QUERY_TIMEOUT),
                public_discovery::connect_tcp(socket, lease.context.destination, &scope),
            )
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
            let shutdown = socket2::SockRef::from(&stream).try_clone()?;
            GuardedIo::new(AsyncIoTokioAsStd(stream), scope, shutdown)
        }
        .boxed()
    }
}
