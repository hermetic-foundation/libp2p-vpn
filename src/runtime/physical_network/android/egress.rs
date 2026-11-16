//! Per-socket Network binding; preparation never sends a packet.

pub(crate) mod reconcile;
use super::{
    Inventory, NetworkRecord, Networks, ResolvedRoute, SocketProtocol, SocketRouteContext, networks,
};
use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, Type};
use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket},
    os::fd::AsFd,
    sync::Arc,
};
use tokio::sync::{Semaphore, watch};

pub(crate) const MAX_PREPARATIONS: usize = 4;
const LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

pub(crate) struct Egress {
    pub(super) networks: Arc<Networks>,
    preparations: Arc<Semaphore>,
    connecting: Semaphore,
    pub(super) path_changes: watch::Sender<()>,
}

impl fmt::Debug for Egress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AndroidEgress")
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(crate) struct RouteEpoch {
    networks: Arc<Networks>,
    generation: u64,
}

impl RouteEpoch {
    pub(super) fn new(networks: Arc<Networks>, generation: u64) -> Self {
        Self {
            networks,
            generation,
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn is_current(&self) -> bool {
        self.networks.revision() == self.generation
    }
}

impl PartialEq for RouteEpoch {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.networks, &other.networks) && self.generation == other.generation
    }
}
impl Eq for RouteEpoch {}

impl fmt::Debug for RouteEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AndroidRouteEpoch")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(crate) struct RouteLease {
    networks: Arc<Networks>,
    pub(crate) route: ResolvedRoute,
    pub(crate) context: SocketRouteContext,
    pub(crate) local_addr: SocketAddr,
    pub(crate) preferred_dial: bool,
    pub(crate) source_fixed: bool,
    pub(super) network_handle: u64,
    pub(super) incarnation: u64,
    record_revision: u64,
    kernel_source: bool,
}

impl fmt::Debug for RouteLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AndroidRouteLease")
            .field("network_handle", &self.network_handle)
            .field("incarnation", &self.incarnation)
            .field("record_revision", &self.record_revision)
            .field("route", &self.route)
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl RouteLease {
    pub(crate) fn is_available(&self) -> bool {
        let state = self
            .networks
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.available_in(&state.inventory)
    }

    pub(crate) fn is_current(&self) -> bool {
        let state = self
            .networks
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.inventory.revision == self.route.generation
            && self.available_in(&state.inventory)
            && state
                .inventory
                .networks
                .iter()
                .any(|network| self.matches(network) && network.revision == self.record_revision)
    }

    pub(crate) fn epoch(&self) -> RouteEpoch {
        RouteEpoch::new(Arc::clone(&self.networks), self.route.generation)
    }

    pub(super) fn matches(&self, network: &NetworkRecord) -> bool {
        network.network_handle == self.network_handle && network.incarnation == self.incarnation
    }

    pub(super) fn available_in(&self, inventory: &super::Inventory) -> bool {
        inventory.networks.iter().any(|network| {
            self.matches(network)
                && network.interface_index == self.route.interface_index
                && if self.kernel_source {
                    network.revision == self.record_revision
                } else {
                    network.addresses.contains(&self.local_addr.ip())
                }
        })
    }

    fn bind(&self, socket: &Socket) -> io::Result<()> {
        if !self.is_current() {
            return Err(stale());
        }
        let binder = self.networks.binder.get().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "Android socket binder is not installed",
            )
        })?;
        binder.bind(self.network_handle, socket.as_fd())?;
        if !self.is_current() {
            return Err(stale());
        }
        Ok(())
    }

    pub(crate) fn socket_binding(&self) -> Arc<dyn quinn::UdpSocketBinding> {
        Arc::new(self.clone())
    }

    pub(crate) fn network_identity(&self) -> [u64; 3] {
        [self.network_handle, self.incarnation, self.record_revision]
    }
}

impl quinn::UdpSocketBinding for RouteLease {
    fn identity(&self) -> [u64; 3] {
        self.network_identity()
    }

    fn bind(&self, socket: &UdpSocket) -> io::Result<()> {
        self.bind(&SockRef::from(socket))
    }

    fn uses_platform_routing(&self) -> bool {
        true
    }

    fn ipv6_scope_id(&self) -> Option<std::num::NonZeroU32> {
        match self.local_addr {
            SocketAddr::V6(address) if address.ip().is_unicast_link_local() => {
                std::num::NonZeroU32::new(address.scope_id())
            }
            _ => None,
        }
    }
}

impl Egress {
    pub(crate) fn new(_owned_interface: String) -> Self {
        // Java inventories only NOT_VPN Networks; this UID is VPN-excluded.
        Self::for_control()
    }

    pub(crate) fn for_control() -> Self {
        Self::with_networks(networks())
    }

    pub(super) fn with_networks(networks: Arc<Networks>) -> Self {
        Self {
            networks,
            preparations: Arc::new(Semaphore::new(MAX_PREPARATIONS)),
            connecting: Semaphore::new(16),
            path_changes: watch::channel(()).0,
        }
    }

    pub(crate) fn connect_permit(&self) -> io::Result<tokio::sync::SemaphorePermit<'_>> {
        self.connecting.try_acquire().map_err(|_| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "Android connection preparation limit",
            )
        })
    }

    pub(crate) fn paths_changed(&self) {
        self.path_changes.send_replace(());
    }

    pub(super) fn lease(
        &self,
        local: SocketAddr,
        destination: SocketAddr,
        protocol: SocketProtocol,
        mark: u32,
        incoming: bool,
    ) -> io::Result<RouteLease> {
        let local = canonical_socket_address(local);
        let destination = canonical_socket_address(destination);
        if destination.port() == 0
            || destination.ip().is_unspecified()
            || destination.ip().is_multicast()
            || destination.ip().is_loopback()
            || destination.is_ipv4() != local.is_ipv4()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Android physical destination",
            ));
        }
        let inventory = {
            let state = self
                .networks
                .state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.inventory.clone()
        };
        // Never hold the inventory lock across netd/kernel calls. Publication
        // can race any lookup; the resulting lease is checked again below.
        let (record, source) = self.select(&inventory, local, destination, incoming)?;
        if let SocketAddr::V6(source) = local
            && source.scope_id() != 0
            && source.scope_id() != record.interface_index
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Android local scope conflicts with Network",
            ));
        }
        if let SocketAddr::V6(remote) = destination
            && remote.ip().is_unicast_link_local()
            && remote.scope_id() != 0
            && remote.scope_id() != record.interface_index
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Android IPv6 scope conflicts with Network",
            ));
        }
        let source_fixed = !local.ip().is_unspecified();
        let route = record
            .routes
            .iter()
            .filter(|route| route.matches(destination.ip()))
            .max_by_key(|route| route.prefix_length);
        let lease = RouteLease {
            networks: Arc::clone(&self.networks),
            route: ResolvedRoute {
                generation: inventory.revision,
                destination: destination.ip(),
                interface_index: record.interface_index,
                preferred_source: Some(source.ip()),
                gateway: route.and_then(|route| route.gateway),
                table: 0,
            },
            context: SocketRouteContext {
                source,
                destination: scoped(destination, record.interface_index),
                protocol,
                mark,
                interface_index: Some(record.interface_index),
            },
            local_addr: scoped(source, record.interface_index),
            preferred_dial: !incoming,
            source_fixed,
            network_handle: record.network_handle,
            incarnation: record.incarnation,
            record_revision: record.revision,
            kernel_source: !record.addresses.contains(&source.ip()),
        };
        if !lease.is_current() {
            return Err(stale());
        }
        Ok(lease)
    }

    fn select<'a>(
        &self,
        inventory: &'a Inventory,
        local: SocketAddr,
        destination: SocketAddr,
        incoming: bool,
    ) -> io::Result<(&'a NetworkRecord, SocketAddr)> {
        let scope_matches = |record: &&NetworkRecord| match local {
            SocketAddr::V6(address) if address.scope_id() != 0 => {
                address.scope_id() == record.interface_index
            }
            _ => true,
        };
        let fixed = !local.ip().is_unspecified();
        let known = inventory
            .networks
            .iter()
            .filter(scope_matches)
            .filter(|network| fixed && network.addresses.contains(&local.ip()))
            .collect::<Vec<_>>();
        if incoming && known.len() > 1 {
            return Err(ambiguous());
        }
        let binder = self.networks.binder.get().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "Android socket binder is not installed",
            )
        })?;
        let mut found = incoming
            .then(|| known.first().copied().map(|record| (record, local)))
            .flatten();
        // Incoming attribution must examine all eligible Networks, including
        // non-default ones. Identical CLAT source addresses are not identity.
        let candidates = if incoming {
            inventory.networks.iter().collect()
        } else {
            inventory.candidates(destination.ip())
        };
        for network in candidates.into_iter().filter(scope_matches) {
            if fixed && !known.is_empty() {
                let known_source = known
                    .iter()
                    .any(|record| record.network_handle == network.network_handle);
                if incoming {
                    if known_source {
                        continue;
                    }
                } else {
                    if known_source {
                        return Ok((network, local));
                    }
                    continue;
                }
            }
            if let SocketAddr::V6(remote) = destination
                && remote.ip().is_unicast_link_local()
                && remote.scope_id() != 0
                && remote.scope_id() != network.interface_index
            {
                continue;
            }
            let mut source = match binder.source_for(
                network.network_handle,
                scoped(destination, network.interface_index),
            ) {
                Ok(source) => source,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NetworkUnreachable
                            | io::ErrorKind::HostUnreachable
                            | io::ErrorKind::AddrNotAvailable
                    ) =>
                {
                    continue;
                }
                // An inconclusive lookup is not proof that another Network
                // cannot own an overlapping source, especially with CLAT.
                Err(error) => return Err(error),
            };
            source = canonical_socket_address(source);
            if source.is_ipv4() != destination.is_ipv4()
                || source.ip().is_unspecified()
                || source.ip().is_loopback()
                || source.ip().is_multicast()
                || (fixed && source.ip() != local.ip())
            {
                continue;
            }
            source.set_port(local.port());
            if !incoming {
                return Ok((network, source));
            }
            if found.is_some() {
                return Err(ambiguous());
            }
            found = Some((network, source));
        }
        found.ok_or_else(no_route)
    }

    pub(super) async fn prepare_lease(
        &self,
        local: SocketAddr,
        destination: SocketAddr,
        protocol: SocketProtocol,
        mark: u32,
        incoming: bool,
    ) -> io::Result<RouteLease> {
        let permit = Arc::clone(&self.preparations)
            .try_acquire_owned()
            .map_err(|_| busy())?;
        let networks = Arc::clone(&self.networks);
        let lookup = tokio::task::spawn_blocking(move || {
            // Cancellation cannot free capacity while a netd call is running.
            let _permit = permit;
            Self::with_networks(networks).lease(local, destination, protocol, mark, incoming)
        });
        tokio::time::timeout(LOOKUP_TIMEOUT, lookup)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Android route lookup deadline"))?
            .map_err(|_| io::Error::other("Android route lookup task failed"))?
    }

    pub(crate) async fn prepare_shared_datagram(
        &self,
        local: SocketAddr,
        destination: SocketAddr,
        mark: u32,
    ) -> io::Result<RouteLease> {
        if local.port() == 0 {
            return Err(no_route());
        }
        self.prepare_lease(local, destination, SocketProtocol::Udp, mark, false)
            .await
    }

    pub(crate) async fn prepare_incoming(
        &self,
        local: SocketAddr,
        destination: SocketAddr,
        mark: u32,
    ) -> io::Result<RouteLease> {
        self.prepare_lease(local, destination, SocketProtocol::Udp, mark, true)
            .await
    }

    pub(crate) async fn prepare_tcp(
        &self,
        destination: SocketAddr,
        reuse: bool,
        listeners: &[SocketAddr],
    ) -> io::Result<(Socket, RouteLease)> {
        let destination = canonical_socket_address(destination);
        let mut lease = self
            .prepare_lease(
                wildcard(destination.is_ipv4(), 0),
                destination,
                SocketProtocol::Tcp,
                0,
                false,
            )
            .await?;
        let socket = Socket::new(
            if destination.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            },
            Type::STREAM,
            Some(Protocol::TCP),
        )?;
        socket.set_nonblocking(true)?;
        socket.set_tcp_nodelay(true)?;
        socket.set_reuse_address(true)?;
        if !destination.is_ipv4() {
            socket.set_only_v6(true)?;
        }
        if reuse {
            socket.set_reuse_port(true)?;
        }
        lease.bind(&socket)?;
        let mut source = lease.local_addr;
        if reuse {
            source.set_port(
                listeners
                    .iter()
                    .copied()
                    .map(canonical_socket_address)
                    .filter(|listen| {
                        listen.port() != 0
                            && listen.is_ipv4() == source.is_ipv4()
                            && (listen.ip().is_unspecified() || listen.ip() == source.ip())
                    })
                    .map(|listen| listen.port())
                    .min()
                    .unwrap_or(0),
            );
        }
        socket.bind(&SockAddr::from(source))?;
        lease.local_addr = socket.local_addr()?.as_socket().ok_or_else(no_route)?;
        lease.context.source = lease.local_addr;
        lease.context.mark = socket.mark()?;
        if !lease.is_current() {
            return Err(stale());
        }
        Ok((socket, lease))
    }

    pub(crate) async fn prepare_tcp_stream(
        &self,
        stream: &tokio::net::TcpStream,
    ) -> io::Result<RouteLease> {
        let socket = SockRef::from(stream);
        let lease = self
            .prepare_lease(
                stream.local_addr()?,
                stream.peer_addr()?,
                SocketProtocol::Tcp,
                socket.mark()?,
                true,
            )
            .await?;
        lease.bind(&socket)?;
        Ok(lease)
    }

    pub(crate) async fn prepare(
        &self,
        destination: SocketAddr,
    ) -> io::Result<(UdpSocket, RouteLease)> {
        let destination = canonical_socket_address(destination);
        let mut lease = self
            .prepare_lease(
                wildcard(destination.is_ipv4(), 0),
                destination,
                SocketProtocol::Udp,
                0,
                false,
            )
            .await?;
        let socket = udp_socket(destination.is_ipv4())?;
        lease.bind(&socket)?;
        socket.bind(&SockAddr::from(lease.local_addr))?;
        lease.local_addr = socket.local_addr()?.as_socket().ok_or_else(no_route)?;
        lease.context.source = lease.local_addr;
        lease.context.mark = socket.mark()?;
        if !lease.is_current() {
            return Err(stale());
        }
        Ok((socket.into(), lease))
    }
}

pub(crate) fn canonical_socket_address(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(address) if address.ip().to_ipv4_mapped().is_some() => {
            SocketAddr::new(address.ip().to_canonical(), address.port())
        }
        address => address,
    }
}

fn scoped(address: SocketAddr, interface: u32) -> SocketAddr {
    match address {
        SocketAddr::V6(address) if address.ip().is_unicast_link_local() => SocketAddr::V6(
            SocketAddrV6::new(*address.ip(), address.port(), 0, interface),
        ),
        address => address,
    }
}

fn wildcard(ipv4: bool, port: u16) -> SocketAddr {
    SocketAddr::new(
        if ipv4 {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        },
        port,
    )
}

fn udp_socket(ipv4: bool) -> io::Result<Socket> {
    let socket = Socket::new(
        if ipv4 { Domain::IPV4 } else { Domain::IPV6 },
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if !ipv4 {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.set_reuse_port(true)?;
    Ok(socket)
}

pub(super) fn source_for<B: super::SocketBinder + ?Sized>(
    binder: &B,
    network: u64,
    destination: SocketAddr,
) -> io::Result<SocketAddr> {
    let socket = udp_socket(destination.is_ipv4())?;
    binder.bind(network, socket.as_fd())?;
    socket.bind(&SockAddr::from(wildcard(destination.is_ipv4(), 0)))?;
    socket.connect(&SockAddr::from(destination))?;
    socket.local_addr()?.as_socket().ok_or_else(no_route)
}

fn ambiguous() -> io::Error {
    io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "ambiguous Android incoming Network",
    )
}

fn no_route() -> io::Error {
    io::Error::new(
        io::ErrorKind::NetworkUnreachable,
        "no eligible Android Network route",
    )
}
fn stale() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "Android Network selection changed",
    )
}
fn busy() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "Android route preparation limit")
}
