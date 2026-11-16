//! TCP preparation never connects: the caller owns the first SYN.

use super::{
    LOOKUP_TIMEOUT, LinuxEgress, LinuxRouteMonitor, ResolvedRoute, RouteLease, SocketProtocol,
    SocketRouteContext, canonical_socket_address, route_error,
};
use socket2::SockRef;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    collections::HashSet,
    io,
    net::{IpAddr, SocketAddr, SocketAddrV6},
    sync::Arc,
};
use tokio::time::timeout;

impl LinuxEgress {
    pub(crate) async fn prepare_tcp(
        &self,
        destination: SocketAddr,
        reuse: bool,
        listeners: &[SocketAddr],
    ) -> io::Result<(Socket, RouteLease)> {
        let _permit = timeout(LOOKUP_TIMEOUT, self.preparations.acquire())
            .await
            .map_err(|_| tcp_timeout("TCP preparation queue timed out"))?
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "route owner closed"))?;
        timeout(LOOKUP_TIMEOUT, async {
            let destination = canonical_socket_address(destination);
            let monitor = self.monitor()?;
            let owned = self
                .configured_exclusions(&monitor)
                .await
                .map_err(route_error)?;
            let selected = tcp_socket(destination.is_ipv4(), reuse)?;
            let wildcard = selected
                .local_addr()?
                .as_socket()
                .ok_or_else(|| io::Error::other("missing TCP wildcard address"))?;
            let context = SocketRouteContext {
                source: wildcard,
                destination,
                protocol: SocketProtocol::Tcp,
                mark: selected.mark()?,
                interface_index: None,
            };
            let initial = monitor
                .route_for_socket(context, &owned)
                .await
                .map_err(route_error)?;
            let mut source = tcp_source(&initial, destination)?;
            self.require_underlay_source(&monitor, source.ip()).await?;
            if reuse {
                source.set_port(tcp_listener_port(source, listeners));
            }
            selected.bind(&SockAddr::from(source))?;
            let local = selected
                .local_addr()?
                .as_socket()
                .ok_or_else(|| io::Error::other("missing bound TCP source address"))?;
            if local.ip() != source.ip() || local.port() == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "TCP source binding did not select a concrete tuple",
                ));
            }
            monitor.validate_generation(&initial).map_err(route_error)?;
            // Source/port rules may select a different device from the wildcard
            // lookup. Only the concrete, still-unbound tuple chooses the device.
            let mut lease = self
                .tcp_route(
                    &selected,
                    Arc::clone(&monitor),
                    SocketRouteContext {
                        source: local,
                        ..context
                    },
                    &owned,
                )
                .await?;
            monitor.validate_generation(&initial).map_err(route_error)?;
            lease.preferred_dial = true;
            Ok((selected, lease))
        })
        .await
        .map_err(|_| tcp_timeout("TCP socket preparation timed out"))?
    }

    /// Preserve receive-side routing of accepted streams. Device binding also
    /// filters incoming packets and would break valid asymmetric physical paths.
    pub(crate) async fn prepare_tcp_stream(
        &self,
        stream: &tokio::net::TcpStream,
    ) -> io::Result<RouteLease> {
        let _permit = timeout(LOOKUP_TIMEOUT, self.preparations.acquire())
            .await
            .map_err(|_| tcp_timeout("accepted TCP preparation queue timed out"))?
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "route owner closed"))?;
        timeout(LOOKUP_TIMEOUT, async {
            let socket = SockRef::from(stream);
            let local = socket
                .local_addr()?
                .as_socket()
                .map(canonical_socket_address)
                .ok_or_else(|| io::Error::other("missing accepted TCP source address"))?;
            let destination = socket
                .peer_addr()?
                .as_socket()
                .map(canonical_socket_address)
                .ok_or_else(|| io::Error::other("missing accepted TCP peer address"))?;
            let context = SocketRouteContext {
                source: local,
                destination,
                protocol: SocketProtocol::Tcp,
                mark: socket.mark()?,
                interface_index: None,
            };
            let monitor = self.monitor()?;
            let owned = self
                .configured_exclusions(&monitor)
                .await
                .map_err(route_error)?;
            self.tcp_route(&socket, monitor, context, &owned).await
        })
        .await
        .map_err(|_| tcp_timeout("accepted TCP preparation timed out"))?
    }

    async fn tcp_route(
        &self,
        socket: &Socket,
        monitor: Arc<LinuxRouteMonitor>,
        context: SocketRouteContext,
        owned: &HashSet<u32>,
    ) -> io::Result<RouteLease> {
        let selected = monitor
            .route_for_socket(context, owned)
            .await
            .map_err(route_error)?;
        self.require_underlay_source(&monitor, context.source.ip())
            .await?;
        let confirmed = monitor
            .route_for_socket(context, owned)
            .await
            .map_err(route_error)?;
        let preferred = monitor
            .route_for_socket(context, owned)
            .await
            .map_err(route_error)?;
        if confirmed.generation != selected.generation
            || confirmed.interface_index != selected.interface_index
            || preferred != selected
            || socket.mark()? != context.mark
            || socket
                .local_addr()?
                .as_socket()
                .map(canonical_socket_address)
                != Some(context.source)
        {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "TCP egress selection changed during socket preparation",
            ));
        }
        monitor
            .validate_generation(&selected)
            .map_err(route_error)?;
        Ok(RouteLease {
            monitor,
            route: confirmed,
            context,
            local_addr: context.source,
            preferred_dial: false,
        })
    }
}

fn tcp_socket(ipv4: bool, reuse: bool) -> io::Result<Socket> {
    let socket = Socket::new(
        if ipv4 { Domain::IPV4 } else { Domain::IPV6 },
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    socket.set_nonblocking(true)?;
    socket.set_tcp_nodelay(true)?;
    socket.set_reuse_address(true)?;
    if !ipv4 {
        socket.set_only_v6(true)?;
    }
    if reuse {
        socket.set_reuse_port(true)?;
    }
    Ok(socket)
}

fn tcp_source(route: &ResolvedRoute, destination: SocketAddr) -> io::Result<SocketAddr> {
    match route.preferred_source {
        Some(source)
            if !source.is_unspecified()
                && !source.is_multicast()
                && source.is_ipv4() == destination.is_ipv4() =>
        {
            Ok(match source {
                IpAddr::V6(ip) if ip.is_unicast_link_local() => {
                    SocketAddr::V6(SocketAddrV6::new(ip, 0, 0, route.interface_index))
                }
                source => SocketAddr::new(source, 0),
            })
        }
        _ => Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "TCP route has no concrete preferred source in the destination family",
        )),
    }
}

fn tcp_listener_port(source: SocketAddr, listeners: &[SocketAddr]) -> u16 {
    listeners
        .iter()
        .copied()
        .map(canonical_socket_address)
        .filter(|listener| {
            listener.is_ipv4() == source.is_ipv4()
                && listener.ip().is_loopback() == source.ip().is_loopback()
                && listener.port() != 0
                && match (source, *listener) {
                    (SocketAddr::V6(source), SocketAddr::V6(listener))
                        if source.ip().is_unicast_link_local() =>
                    {
                        source.scope_id() == listener.scope_id()
                    }
                    _ => true,
                }
        })
        .min_by_key(|listener| (listener.ip() != source.ip(), listener.port()))
        .map_or(0, |listener| listener.port())
}

fn tcp_timeout(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
}

#[cfg(test)]
mod tests;
