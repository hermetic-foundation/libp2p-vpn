//! DNS follows an immutable physical Network; never the process-wide resolver.

use super::{NetworkRecord, Networks, egress::RouteEpoch, networks};
use futures::{FutureExt as _, future::BoxFuture};
use hickory_proto::{
    ProtoErrorKind,
    runtime::{RuntimeProvider, TokioHandle, TokioTime, iocompat::AsyncIoTokioAsStd},
    udp::DnsUdpSocket,
    xfer::Protocol,
};
use hickory_resolver::{
    ResolveError, Resolver,
    config::{NameServerConfig, ResolverConfig, ResolverOpts, ServerOrderingStrategy},
    lookup::{Ipv4Lookup, Ipv6Lookup, TxtLookup},
    lookup_ip::LookupIp,
};
use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    io,
    net::{SocketAddr, SocketAddrV6},
    os::fd::AsFd,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{io::ReadBuf, sync::Semaphore};

mod endpoints;
mod platform;
#[cfg(all(test, target_os = "linux"))]
pub(crate) use endpoints::fixture;
#[cfg(any(target_os = "android", all(test, target_os = "linux")))]
pub(crate) use endpoints::{Snapshot, capture_snapshot, delivery_scope};
#[cfg(target_os = "android")]
pub(crate) use endpoints::{endpoint_candidates, endpoint_pending, subscribe_endpoints};
use platform::NetworkProvider;

const MAX_QUERIES: usize = 4;
const MAX_NETWORK_ATTEMPTS: usize = 3;
const QUERY_TIMEOUT: Duration = Duration::from_secs(6);
const SERVER_TIMEOUT: Duration = Duration::from_secs(2);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(1);

type InnerResolver = Resolver<NetworkProvider>;

#[derive(Clone)]
struct Scope {
    epoch: RouteEpoch,
    network: u64,
    incarnation: u64,
    servers: Vec<SocketAddr>,
    preparations: Arc<Semaphore>,
    platform_dns: bool,
}

impl Scope {
    fn with_current<T>(&self, action: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        let state = self
            .epoch_networks()
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.inventory.revision != self.epoch.generation()
            || !state.inventory.networks.iter().any(|record| {
                record.network_handle == self.network && record.incarnation == self.incarnation
            })
        {
            return Err(stale());
        }
        action()
    }

    fn epoch_networks(&self) -> &Arc<Networks> {
        self.epoch.networks()
    }

    fn check(&self) -> io::Result<()> {
        self.with_current(|| Ok(()))
    }

    async fn socket(&self, local: SocketAddr, server: SocketAddr, tcp: bool) -> io::Result<Socket> {
        if !local.ip().is_unspecified()
            || local.is_ipv4() != server.is_ipv4()
            || !self.servers.contains(&server)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS socket does not match the selected Network's server",
            ));
        }
        self.check()?;
        let permit = Arc::clone(&self.preparations)
            .try_acquire_owned()
            .map_err(|_| busy())?;
        let scope = self.clone();
        let binding = tokio::task::spawn_blocking(move || {
            // Cancellation must not release capacity while netd still owns work.
            let _permit = permit;
            let binder = scope.epoch_networks().binder.get().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "Android DNS binder unavailable",
                )
            })?;
            scope.check()?;
            let socket = Socket::new(
                if server.is_ipv4() {
                    Domain::IPV4
                } else {
                    Domain::IPV6
                },
                if tcp { Type::STREAM } else { Type::DGRAM },
                Some(if tcp {
                    socket2::Protocol::TCP
                } else {
                    socket2::Protocol::UDP
                }),
            )?;
            socket.set_nonblocking(true)?;
            if server.is_ipv6() {
                socket.set_only_v6(true)?;
            }
            binder.bind(scope.network, socket.as_fd())?;
            socket.bind(&SockAddr::from(local))?;
            scope.check()?;
            Ok::<_, io::Error>(socket)
        });
        let socket = tokio::time::timeout(SERVER_TIMEOUT, binding)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Android DNS socket deadline"))?
            .map_err(|_| io::Error::other("Android DNS binding worker failed"))??;
        self.check()?;
        Ok(socket)
    }
}

#[derive(Clone)]
struct NetworkRuntime {
    scope: Scope,
    handle: TokioHandle,
}

struct ScopedUdp {
    scope: Scope,
    socket: tokio::net::UdpSocket,
}

#[async_trait::async_trait]
impl DnsUdpSocket for ScopedUdp {
    type Time = TokioTime;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        self.scope
            .with_current(|| Ok(DnsUdpSocket::poll_recv_from(&self.socket, cx, bytes)))
            .unwrap_or_else(|error| Poll::Ready(Err(error)))
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        bytes: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        if !self.scope.servers.contains(&target) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Unexpected DNS server",
            )));
        }
        self.scope
            .with_current(|| Ok(self.socket.poll_send_to(cx, bytes, target)))
            .unwrap_or_else(|error| Poll::Ready(Err(error)))
    }
}

struct ScopedTcp {
    scope: Scope,
    socket: tokio::net::TcpStream,
}

impl tokio::io::AsyncRead for ScopedTcp {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.scope
            .with_current(|| Ok(Pin::new(&mut this.socket).poll_read(cx, bytes)))
            .unwrap_or_else(|error| Poll::Ready(Err(error)))
    }
}

impl tokio::io::AsyncWrite for ScopedTcp {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.scope
            .with_current(|| Ok(Pin::new(&mut this.socket).poll_write(cx, bytes)))
            .unwrap_or_else(|error| Poll::Ready(Err(error)))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.scope
            .with_current(|| Ok(Pin::new(&mut this.socket).poll_flush(cx)))
            .unwrap_or_else(|error| Poll::Ready(Err(error)))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.scope
            .with_current(|| Ok(Pin::new(&mut this.socket).poll_shutdown(cx)))
            .unwrap_or_else(|error| Poll::Ready(Err(error)))
    }
}

impl RuntimeProvider for NetworkRuntime {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = ScopedUdp;
    type Tcp = AsyncIoTokioAsStd<ScopedTcp>;

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
            let socket =
                tokio::net::UdpSocket::from_std(scope.socket(local, server, false).await?.into())?;
            scope.check()?;
            Ok(ScopedUdp { scope, socket })
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
            let local = local.unwrap_or_else(|| {
                SocketAddr::new(
                    if server.is_ipv4() {
                        std::net::Ipv4Addr::UNSPECIFIED.into()
                    } else {
                        std::net::Ipv6Addr::UNSPECIFIED.into()
                    },
                    0,
                )
            });
            let socket = scope.socket(local, server, true).await?;
            let socket = tokio::net::TcpSocket::from_std_stream(socket.into());
            let connection = socket.connect(server);
            tokio::pin!(connection);
            let guarded = futures::future::poll_fn(|cx| {
                scope
                    .with_current(|| Ok(connection.as_mut().poll(cx)))
                    .unwrap_or_else(|error| Poll::Ready(Err(error)))
            });
            let socket = tokio::time::timeout(
                timeout.unwrap_or(SERVER_TIMEOUT).min(SERVER_TIMEOUT),
                guarded,
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Android DNS TCP deadline"))??;
            scope.check()?;
            Ok(AsyncIoTokioAsStd(ScopedTcp { scope, socket }))
        }
        .boxed()
    }
}

#[derive(Clone)]
struct ScopedResolver {
    scope: Scope,
    resolver: InnerResolver,
}

struct Cached {
    epoch: RouteEpoch,
    resolvers: Vec<ScopedResolver>,
}

struct Shared {
    networks: Arc<Networks>,
    cached: Mutex<Option<Cached>>,
    queries: Semaphore,
    preparations: Arc<Semaphore>,
}

#[derive(Clone)]
pub(crate) struct NetworkResolver(Arc<Shared>);

impl std::fmt::Debug for NetworkResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AndroidNetworkResolver")
            .finish_non_exhaustive()
    }
}

impl NetworkResolver {
    pub(crate) fn new() -> Self {
        Self::with_networks(networks())
    }

    fn with_networks(networks: Arc<Networks>) -> Self {
        Self(Arc::new(Shared {
            networks,
            cached: Mutex::new(None),
            queries: Semaphore::new(MAX_QUERIES),
            preparations: Arc::new(Semaphore::new(MAX_QUERIES)),
        }))
    }

    fn resolvers(&self) -> io::Result<Vec<ScopedResolver>> {
        let mut cached = self
            .0
            .cached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(cached) = cached.as_ref().filter(|cached| cached.epoch.is_current()) {
            return Ok(cached.resolvers.clone());
        }
        let state = self
            .0
            .networks
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let platform_dns = self
            .0
            .networks
            .binder
            .get()
            .is_some_and(|binder| binder.supports_platform_dns());
        if !platform_dns
            && state.inventory.networks.iter().any(|record| {
                state.inventory.preferred_network == Some(record.network_handle)
                    && record.private_dns_active
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Android Private DNS requires the platform resolver adapter",
            ));
        }
        let epoch = RouteEpoch::new(Arc::clone(&self.0.networks), state.inventory.revision);
        // The name has no destination IP yet. Use the Internet default, not a
        // fabricated IP which might match an unrelated destination-specific LAN route.
        let mut records = state
            .inventory
            .networks
            .iter()
            .filter(|record| {
                state.inventory.preferred_network == Some(record.network_handle) || record.validated
            })
            .collect::<Vec<_>>();
        records.sort_by_key(|record| {
            (
                state.inventory.preferred_network != Some(record.network_handle),
                record.network_handle,
            )
        });
        let resolvers = records
            .into_iter()
            .filter(|record| {
                platform_dns || (!record.dns_servers.is_empty() && !record.private_dns_active)
            })
            .take(MAX_NETWORK_ATTEMPTS)
            .map(|record| {
                let servers = server_addresses(record);
                let scope = Scope {
                    epoch: epoch.clone(),
                    network: record.network_handle,
                    incarnation: record.incarnation,
                    servers,
                    preparations: Arc::clone(&self.0.preparations),
                    platform_dns,
                };
                scoped_resolver(scope)
            })
            .collect::<Vec<_>>();
        if resolvers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "No eligible physical Network DNS servers",
            ));
        }
        drop(state);
        if !epoch.is_current() {
            return Err(stale());
        }
        *cached = Some(Cached {
            epoch,
            resolvers: resolvers.clone(),
        });
        Ok(resolvers)
    }

    async fn query<T: Send, F>(&self, mut operation: F) -> Result<T, ResolveError>
    where
        F: for<'a> FnMut(&'a InnerResolver) -> BoxFuture<'a, Result<T, ResolveError>> + Send,
    {
        let _permit = self.0.queries.try_acquire().map_err(|_| busy())?;
        #[cfg(target_os = "android")]
        if let Some(scope) = crate::runtime::physical_network::public_discovery::current() {
            return self.query_default(scope.epoch(), operation).await;
        }
        let resolvers = self.resolvers()?;
        tokio::time::timeout(QUERY_TIMEOUT, async {
            let mut failure = None;
            for selected in resolvers {
                selected.scope.check()?;
                let answer = tokio::time::timeout(SERVER_TIMEOUT, operation(&selected.resolver))
                    .await
                    .unwrap_or_else(|_| {
                        Err(
                            io::Error::new(io::ErrorKind::TimedOut, "Android DNS Network deadline")
                                .into(),
                        )
                    });
                selected.scope.check()?;
                match answer {
                    Err(error) if connectivity_failure(&error) => failure = Some(error),
                    answer => return answer,
                }
            }
            Err(failure.unwrap_or_else(|| ResolveError::from("No physical DNS result")))
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Android DNS query deadline"))?
    }

    fn default_resolver(&self, epoch: &RouteEpoch) -> io::Result<ScopedResolver> {
        let preferred = {
            let state = self
                .0
                .networks
                .state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !Arc::ptr_eq(epoch.networks(), &self.0.networks)
                || state.inventory.revision != epoch.generation()
            {
                return Err(stale());
            }
            state.inventory.preferred_network.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "default Android DNS Network is absent",
                )
            })?
        };
        self.resolvers()?
            .into_iter()
            .find(|resolver| resolver.scope.network == preferred && resolver.scope.epoch == *epoch)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "default Android DNS Network unavailable",
                )
            })
    }

    async fn query_default<T: Send, F>(
        &self,
        epoch: &RouteEpoch,
        mut operation: F,
    ) -> Result<T, ResolveError>
    where
        F: for<'a> FnMut(&'a InnerResolver) -> BoxFuture<'a, Result<T, ResolveError>> + Send,
    {
        let selected = self.default_resolver(epoch)?;
        selected.scope.check()?;
        let answer = tokio::time::timeout(SERVER_TIMEOUT, operation(&selected.resolver)).await;
        selected.scope.check()?;
        answer.map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "default Android DNS Network deadline",
            )
        })?
    }
}

fn server_addresses(record: &NetworkRecord) -> Vec<SocketAddr> {
    record
        .dns_servers
        .iter()
        .map(|address| match address {
            std::net::IpAddr::V6(address) if address.is_unicast_link_local() => {
                SocketAddr::V6(SocketAddrV6::new(*address, 53, 0, record.interface_index))
            }
            address => SocketAddr::new(*address, 53),
        })
        .collect()
}

fn scoped_resolver(scope: Scope) -> ScopedResolver {
    let mut config = ResolverConfig::new();
    if scope.platform_dns {
        // This is a connector dispatch key, never a network destination. netd
        // chooses the actual DNS servers and Private DNS policy for the handle.
        config.add_name_server(NameServerConfig::new(
            "0.0.0.0:0".parse().expect("dispatch key"),
            Protocol::Udp,
        ));
    } else {
        for server in &scope.servers {
            config.add_name_server(NameServerConfig::new(*server, Protocol::Udp));
            config.add_name_server(NameServerConfig::new(*server, Protocol::Tcp));
        }
    }
    let mut options = ResolverOpts::default();
    options.timeout = REQUEST_TIMEOUT;
    // Hickory interprets attempts as retries after the initial request. netd
    // already owns native request retry policy, so do not add another layer.
    options.attempts = usize::from(!scope.platform_dns);
    options.cache_size = 64;
    options.num_concurrent_reqs = 1;
    options.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
    options.positive_max_ttl = Some(Duration::from_secs(300));
    options.negative_max_ttl = Some(Duration::from_secs(30));
    let runtime = NetworkRuntime {
        scope: scope.clone(),
        handle: TokioHandle::default(),
    };
    let resolver = Resolver::builder_with_config(config, NetworkProvider::new(runtime))
        .with_options(options)
        .build();
    ScopedResolver { scope, resolver }
}

fn connectivity_failure(error: &ResolveError) -> bool {
    error
        .proto()
        .is_some_and(|error| match error.kind.as_ref() {
            ProtoErrorKind::Timeout | ProtoErrorKind::NoConnections => true,
            ProtoErrorKind::Io(error) => matches!(
                error.kind(),
                io::ErrorKind::TimedOut
                    | io::ErrorKind::NetworkUnreachable
                    | io::ErrorKind::HostUnreachable
                    | io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::NotConnected
            ),
            _ => false,
        })
}

fn stale() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "Android DNS Network epoch changed",
    )
}

fn busy() -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        "Android DNS preparation/query capacity",
    )
}

#[async_trait::async_trait]
impl libp2p::dns::Resolver for NetworkResolver {
    async fn lookup_ip(&self, name: String) -> Result<LookupIp, ResolveError> {
        self.query(|resolver| resolver.lookup_ip(name.clone()).boxed())
            .await
    }
    async fn ipv4_lookup(&self, name: String) -> Result<Ipv4Lookup, ResolveError> {
        self.query(|resolver| resolver.ipv4_lookup(name.clone()).boxed())
            .await
    }
    async fn ipv6_lookup(&self, name: String) -> Result<Ipv6Lookup, ResolveError> {
        self.query(|resolver| resolver.ipv6_lookup(name.clone()).boxed())
            .await
    }
    async fn txt_lookup(&self, name: String) -> Result<TxtLookup, ResolveError> {
        self.query(|resolver| resolver.txt_lookup(name.clone()).boxed())
            .await
    }
}

#[cfg(test)]
mod tests;
