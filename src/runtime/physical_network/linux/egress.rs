//! Prepare an interface/source-bound socket without emitting probe traffic.

use super::{
    LOOKUP_TIMEOUT, LinuxRouteMonitor, PendingLookup, ResolvedRoute, RouteLookupError,
    SocketProtocol, SocketRouteContext,
};
use futures::TryStreamExt;
use netlink_packet_route::link::{LinkAttribute, LinkMessage};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    collections::HashSet,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    num::NonZeroU32,
    sync::{Arc, Mutex},
};
use tokio::{sync::Semaphore, time::timeout};

const MAX_PREPARATIONS: usize = 4;
const MAX_CONNECTING: usize = 16;

pub(crate) struct LinuxEgress {
    owned_interface: String,
    monitor: Mutex<Option<Arc<LinuxRouteMonitor>>>,
    preparations: Semaphore,
    connecting: Semaphore,
}

impl fmt::Debug for LinuxEgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxEgress")
            .field("owned_interface", &self.owned_interface)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(crate) struct RouteLease {
    monitor: Arc<LinuxRouteMonitor>,
    pub(crate) route: ResolvedRoute,
    pub(crate) context: SocketRouteContext,
    pub(crate) local_addr: SocketAddr,
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
        self.monitor.validate_generation(&self.route).is_ok()
    }
}

impl LinuxEgress {
    pub(crate) fn new(owned_interface: String) -> Self {
        Self {
            owned_interface,
            monitor: Mutex::new(None),
            preparations: Semaphore::new(MAX_PREPARATIONS),
            connecting: Semaphore::new(MAX_CONNECTING),
        }
    }

    pub(crate) fn connect_permit(&self) -> io::Result<tokio::sync::SemaphorePermit<'_>> {
        self.connecting
            .try_acquire()
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "QUIC route connection limit"))
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
        let owned = link(&monitor, None, Some(self.owned_interface.clone()))
            .await?
            .map(|link| link.header.index)
            .into_iter()
            .collect::<HashSet<_>>();

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
