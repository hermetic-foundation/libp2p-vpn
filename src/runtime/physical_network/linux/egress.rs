//! Prepare an interface/source-bound socket without emitting probe traffic.

pub(crate) mod reconcile;
mod tcp;

use super::{
    LOOKUP_TIMEOUT, LinuxRouteMonitor, PendingLookup, ResolvedRoute, RouteLookupError,
    SocketProtocol, SocketRouteContext,
};
use futures::TryStreamExt;
use netlink_packet_route::address::AddressAttribute;
use netlink_packet_route::link::{LinkAttribute, LinkMessage};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    collections::HashSet,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    num::NonZeroU32,
    sync::{Arc, Mutex},
};
use tokio::{
    sync::{Semaphore, watch},
    time::timeout,
};

const MAX_PREPARATIONS: usize = 4;
const MAX_CONNECTING: usize = 16;

pub(crate) fn canonical_socket_address(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_some() => SocketAddr::new(
            IpAddr::V4(v6.ip().to_ipv4_mapped().expect("mapped IPv4")),
            v6.port(),
        ),
        address => address,
    }
}

pub(crate) struct LinuxEgress {
    owned_interface: Option<String>,
    monitor: Mutex<Option<Arc<LinuxRouteMonitor>>>,
    preparations: Semaphore,
    connecting: Semaphore,
    path_changes: watch::Sender<()>,
}

impl fmt::Debug for LinuxEgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxEgress")
            .field("owned_interface", &self.owned_interface)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(crate) struct RouteEpoch {
    monitor: Arc<LinuxRouteMonitor>,
    generation: u64,
}

impl RouteEpoch {
    fn new(monitor: Arc<LinuxRouteMonitor>, generation: u64) -> Self {
        Self {
            monitor,
            generation,
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn is_current(&self) -> bool {
        self.monitor.generation() == Ok(self.generation)
    }
}

impl PartialEq for RouteEpoch {
    fn eq(&self, other: &Self) -> bool {
        self.generation == other.generation && Arc::ptr_eq(&self.monitor, &other.monitor)
    }
}

impl Eq for RouteEpoch {}

impl fmt::Debug for RouteEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteEpoch")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(crate) struct RouteLease {
    monitor: Arc<LinuxRouteMonitor>,
    pub(crate) route: ResolvedRoute,
    pub(crate) context: SocketRouteContext,
    pub(crate) local_addr: SocketAddr,
    pub(crate) preferred_dial: bool,
}

impl fmt::Debug for RouteLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteLease")
            .field("route", &self.route)
            .field("context", &self.context)
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl RouteLease {
    pub(crate) fn is_current(&self) -> bool {
        self.monitor.generation() == Ok(self.route.generation)
    }

    pub(crate) fn epoch(&self) -> RouteEpoch {
        RouteEpoch::new(Arc::clone(&self.monitor), self.route.generation)
    }
}

impl LinuxEgress {
    #[cfg(test)]
    pub(crate) fn retire_observer_for_test(&self) {
        let current = self.monitor.lock().unwrap();
        let monitor = current.as_ref().expect("initialized route observer");
        // Exercise the same cleanup as a cancelled lookup, without injecting
        // syscall failures or changing a real physical interface.
        drop(PendingLookup {
            monitor,
            complete: false,
        });
    }

    pub(crate) fn new(owned_interface: String) -> Self {
        Self::with_owned_interface(Some(owned_interface))
    }

    pub(crate) fn for_control() -> Self {
        Self::with_owned_interface(None)
    }

    fn with_owned_interface(owned_interface: Option<String>) -> Self {
        Self {
            owned_interface,
            monitor: Mutex::new(None),
            preparations: Semaphore::new(MAX_PREPARATIONS),
            connecting: Semaphore::new(MAX_CONNECTING),
            path_changes: watch::channel(()).0,
        }
    }

    pub(crate) fn connect_permit(&self) -> io::Result<tokio::sync::SemaphorePermit<'_>> {
        self.connecting.try_acquire().map_err(|_| {
            io::Error::new(io::ErrorKind::WouldBlock, "physical route connection limit")
        })
    }

    pub(crate) fn paths_changed(&self) {
        self.path_changes.send_replace(());
    }

    async fn configured_exclusions(
        &self,
        monitor: &LinuxRouteMonitor,
    ) -> Result<HashSet<u32>, RouteLookupError> {
        let Some(name) = &self.owned_interface else {
            return Ok(HashSet::new());
        };
        Ok(link(monitor, None, Some(name.clone()))
            .await
            .map_err(|error| match error.kind() {
                io::ErrorKind::WouldBlock => RouteLookupError::Busy,
                io::ErrorKind::TimedOut => RouteLookupError::Timeout,
                _ => RouteLookupError::MonitorUnavailable,
            })?
            .map(|link| link.header.index)
            .into_iter()
            .collect())
    }

    pub(crate) async fn source_is_assigned(
        &self,
        monitor: &LinuxRouteMonitor,
        source: IpAddr,
    ) -> Result<bool, RouteLookupError> {
        let mut excluded = super::ownership::indices(monitor).await?;
        excluded.extend(self.configured_exclusions(monitor).await?);
        let _dump = monitor.dump_permit().await?;
        let _permit = monitor
            .lookups
            .try_acquire()
            .map_err(|_| RouteLookupError::Busy)?;
        let mut addresses = monitor.handle.address().get().execute();
        let mut pending = PendingLookup {
            monitor,
            complete: false,
        };
        timeout(LOOKUP_TIMEOUT, async {
            let mut found = false;
            let mut count = 0;
            while let Some(address) = addresses
                .try_next()
                .await
                .map_err(|error| pending.response_error(error))?
            {
                count += 1;
                if count > 4096 {
                    return Err(RouteLookupError::UnsupportedRoute);
                }
                if excluded.contains(&address.header.index) {
                    continue;
                }
                let local = address
                    .attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        AddressAttribute::Local(ip) => Some(*ip),
                        _ => None,
                    })
                    .or_else(|| {
                        address
                            .attributes
                            .iter()
                            .find_map(|attribute| match attribute {
                                AddressAttribute::Address(ip) => Some(*ip),
                                _ => None,
                            })
                    });
                let loopback_prefix = match (local, source) {
                    (Some(IpAddr::V4(local)), IpAddr::V4(source))
                        if local.is_loopback()
                            && source.is_loopback()
                            && address.header.prefix_len <= 32 =>
                    {
                        let mask = u32::MAX
                            .checked_shl(32 - u32::from(address.header.prefix_len))
                            .unwrap_or(0);
                        u32::from(local) & mask == u32::from(source) & mask
                    }
                    _ => false,
                };
                found |= local == Some(source) || loopback_prefix;
            }
            pending.complete = true;
            Ok(found)
        })
        .await
        .map_err(|_| RouteLookupError::Timeout)?
    }

    pub(crate) async fn prepare_incoming(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        mark: u32,
    ) -> io::Result<RouteLease> {
        let _permit = timeout(LOOKUP_TIMEOUT, self.preparations.acquire())
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "incoming route preparation timeout",
                )
            })?
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "route owner closed"))?;
        let monitor = self.monitor()?;
        let owned = self
            .configured_exclusions(&monitor)
            .await
            .map_err(route_error)?;
        let mut context = SocketRouteContext {
            source: local,
            destination: remote,
            protocol: SocketProtocol::Udp,
            mark,
            interface_index: None,
        };
        let selected = monitor
            .route_for_socket(context, &owned)
            .await
            .map_err(route_error)?;
        context.interface_index = Some(selected.interface_index);
        let route = monitor
            .route_for_socket(context, &owned)
            .await
            .map_err(route_error)?;
        if route.generation != selected.generation
            || route.interface_index != selected.interface_index
        {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "incoming route changed during selection",
            ));
        }
        monitor.validate_generation(&route).map_err(route_error)?;
        self.require_underlay_source(&monitor, local.ip()).await?;
        monitor.validate_generation(&route).map_err(route_error)?;
        Ok(RouteLease {
            monitor,
            route,
            context,
            local_addr: local,
            preferred_dial: false,
        })
    }

    async fn require_underlay_source(
        &self,
        monitor: &LinuxRouteMonitor,
        source: IpAddr,
    ) -> io::Result<()> {
        if self
            .source_is_assigned(monitor, source)
            .await
            .map_err(route_error)?
        {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "QUIC source is not assigned to an eligible underlay",
            ))
        }
    }

    fn monitor(&self) -> io::Result<Arc<LinuxRouteMonitor>> {
        let mut current = self
            .monitor
            .lock()
            .map_err(|_| io::Error::other("route owner poisoned"))?;
        if let Some(monitor) = current
            .as_ref()
            .filter(|monitor| monitor.generation().is_ok())
        {
            return Ok(Arc::clone(monitor));
        }
        let monitor = Arc::new(LinuxRouteMonitor::new()?);
        *current = Some(Arc::clone(&monitor));
        Ok(monitor)
    }

    pub(crate) async fn prepare(
        &self,
        destination: SocketAddr,
    ) -> io::Result<(UdpSocket, RouteLease)> {
        let destination = canonical_socket_address(destination);
        let _permit = timeout(LOOKUP_TIMEOUT, self.preparations.acquire())
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "QUIC socket preparation queue timeout",
                )
            })?
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "QUIC socket preparation closed")
            })?;
        let monitor = self.monitor()?;
        let owned = self
            .configured_exclusions(&monitor)
            .await
            .map_err(route_error)?;

        // Reserve the actual source port. UDP connect chooses a source without
        // sending traffic. The reservation is dropped before QUIC can transmit.
        let reservation = socket(destination.is_ipv4())?;
        reservation.bind(&SockAddr::from(SocketAddr::new(
            if destination.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            },
            0,
        )))?;
        reservation.connect(&SockAddr::from(destination))?;
        let local = reservation
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::other("missing UDP source address"))?;
        let context = SocketRouteContext {
            source: local,
            destination,
            protocol: SocketProtocol::Udp,
            mark: reservation.mark()?,
            interface_index: None,
        };
        let route = monitor
            .route_for_socket(context, &owned)
            .await
            .map_err(route_error)?;
        self.require_underlay_source(&monitor, local.ip()).await?;
        let interface = link(&monitor, Some(route.interface_index), None)
            .await?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "selected network disappeared")
            })?;

        let selected = socket(destination.is_ipv4())?;
        if selected.mark()? != context.mark {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "socket routing marks differ",
            ));
        }
        // Bind before setting up Quinn. No packet can escape through another
        // interface, even if the default route changes during authentication.
        bind_interface(&selected, destination.is_ipv4(), &interface)?;
        selected.bind(&SockAddr::from(local))?;
        if selected.mark()? != context.mark {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "socket routing mark changed during binding",
            ));
        }
        let bound_context = SocketRouteContext {
            interface_index: Some(route.interface_index),
            ..context
        };
        let confirmed = monitor
            .route_for_socket(bound_context, &owned)
            .await
            .map_err(route_error)?;
        let preferred = monitor
            .route_for_socket(context, &owned)
            .await
            .map_err(route_error)?;
        if confirmed.interface_index != route.interface_index || route != preferred {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "egress selection changed during socket preparation",
            ));
        }
        monitor.validate_generation(&route).map_err(route_error)?;
        drop(reservation);
        Ok((
            selected.into(),
            RouteLease {
                monitor,
                route: confirmed,
                context: bound_context,
                local_addr: local,
                preferred_dial: true,
            },
        ))
    }
}

fn bind_interface(selected: &Socket, ipv4: bool, interface: &LinkMessage) -> io::Result<()> {
    let index = NonZeroU32::new(interface.header.index)
        .ok_or_else(|| io::Error::other("zero egress index"))?;
    let bound = if ipv4 {
        selected.bind_device_by_index_v4(Some(index))
    } else {
        selected.bind_device_by_index_v6(Some(index))
    };
    match bound {
        Ok(()) => Ok(()),
        // Keep older kernels supported, without falling back to an unbound socket.
        Err(error) if error.raw_os_error() == Some(92) => {
            let name = interface
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    LinkAttribute::IfName(name) => Some(name),
                    _ => None,
                })
                .ok_or_else(|| io::Error::other("missing egress interface name"))?;
            selected.bind_device(Some(name.as_bytes()))
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests;

fn socket(ipv4: bool) -> io::Result<Socket> {
    let socket = Socket::new(
        if ipv4 { Domain::IPV4 } else { Domain::IPV6 },
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if !ipv4 {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    // Only same-UID SO_REUSEPORT sharing is needed for the short reservation.
    // SO_REUSEADDR would unnecessarily permit less restrictive UDP sharing.
    socket.set_reuse_port(true)?;
    Ok(socket)
}

fn route_error(error: RouteLookupError) -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, error)
}

async fn link(
    monitor: &LinuxRouteMonitor,
    index: Option<u32>,
    name: Option<String>,
) -> io::Result<Option<LinkMessage>> {
    let _dump = if index.is_none() && name.is_none() {
        Some(monitor.dump_permit().await.map_err(route_error)?)
    } else {
        None
    };
    let _permit = monitor
        .lookups
        .try_acquire()
        .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "interface lookup limit"))?;
    let mut request = monitor.handle.link().get();
    if let Some(index) = index {
        request = request.match_index(index);
    }
    if let Some(name) = name {
        request = request.match_name(name);
    }
    let mut links = request.execute();
    let mut pending = PendingLookup {
        monitor,
        complete: false,
    };
    let result = timeout(LOOKUP_TIMEOUT, async {
        let first = match links.try_next().await {
            Ok(first) => first,
            Err(rtnetlink::Error::NetlinkError(error))
                if error.code.is_some_and(|code| code.get() == -19) =>
            {
                pending.complete = true;
                return Ok(None);
            }
            Err(error) => return Err(route_error(pending.response_error(error))),
        };
        if links
            .try_next()
            .await
            .map_err(|error| route_error(pending.response_error(error)))?
            .is_some()
        {
            return Err(io::Error::other("ambiguous egress interface"));
        }
        pending.complete = true;
        Ok(first)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "interface lookup timed out"))?;
    monitor.generation().map_err(route_error)?;
    result
}
