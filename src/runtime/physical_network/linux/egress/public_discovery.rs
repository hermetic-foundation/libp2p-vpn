use super::*;
use crate::runtime::physical_network::public_discovery::{Scope, stale};
use netlink_packet_route::link::{InfoKind, LinkFlags, LinkInfo, LinkLayerType};

pub(crate) mod dns;

#[derive(Debug)]
pub(crate) struct DefaultLink {
    index: u32,
}

impl DefaultLink {
    fn from_kernel(link: LinkMessage) -> io::Result<Self> {
        if !link.header.flags.contains(LinkFlags::Up)
            || link.header.flags.contains(LinkFlags::Loopback)
            || !matches!(
                link.header.link_layer_type,
                LinkLayerType::Ether | LinkLayerType::Rawip | LinkLayerType::Ppp
            ) || link.attributes.iter().any(|attr| {
            matches!(attr, LinkAttribute::LinkInfo(info) if info.iter().any(|entry| {
                matches!(entry, LinkInfo::Kind(kind) if !matches!(kind,
                    InfoKind::Bridge | InfoKind::Veth | InfoKind::Vlan | InfoKind::Bond
                    | InfoKind::MacVlan | InfoKind::MacVtap | InfoKind::IpVlan | InfoKind::IpVtap)
                    && !matches!(kind, InfoKind::Other(name) if name == "wwan"))
            }))
        }) {
            return Err(no_default());
        }
        Ok(Self {
            index: link.header.index,
        })
    }

    fn bind(&self, socket: &Socket) -> io::Result<()> {
        // A source bind or packet-info hint alone does not isolate retries,
        // retransmits, or a route update between validation and transmission.
        let index = NonZeroU32::new(self.index).ok_or_else(no_default)?;
        socket.bind_device_by_index_v4(Some(index))?;
        if socket.device_index_v4()? != Some(index) {
            return Err(stale());
        }
        Ok(())
    }
}

fn no_default() -> io::Error {
    io::Error::new(
        io::ErrorKind::NetworkUnreachable,
        "no unambiguous default physical network",
    )
}

impl LinuxEgress {
    pub(crate) async fn public_default_link(&self, epoch: &RouteEpoch) -> io::Result<DefaultLink> {
        let monitor = &epoch.monitor;
        let owned = self
            .configured_exclusions(monitor)
            .await
            .map_err(route_error)?;
        // Ask the kernel's routing policy, not the mDNS selection or the
        // discovery destination. FIB_MATCH rejects a probe covered by a host,
        // LAN, split-default or VPN route instead of treating it as a default.
        // Linux policy is per family. Do not choose a family arbitrarily if
        // their kernel defaults disagree about the physical network.
        let v4 = default_interface(epoch, &owned, &["198.51.100.1", "203.0.113.1"]).await?;
        let v6 = default_interface(epoch, &owned, &["2001:db8::1", "2001:db8:ffff::1"]).await?;
        let index = match (v4, v6) {
            (Some(a), Some(b)) if a != b => return Err(no_default()),
            (Some(index), _) | (_, Some(index)) => index,
            (None, None) => return Err(no_default()),
        };
        let selected = link(monitor, Some(index), None)
            .await?
            .ok_or_else(no_default)?;
        let selected = DefaultLink::from_kernel(selected)?;
        epoch.with_current(|| {
            if selected.index != index {
                return Err(stale());
            }
            Ok(selected)
        })
    }

    async fn prepare_public_route(
        &self,
        scope: &Scope,
        local: SocketAddr,
        destination: SocketAddr,
        protocol: SocketProtocol,
        mark: u32,
    ) -> io::Result<RouteLease> {
        let local = canonical_socket_address(local);
        let destination = canonical_socket_address(destination);
        if !local.ip().is_unspecified()
            || local.is_ipv4() != destination.is_ipv4()
            || !crate::runtime::physical_network::public_discovery::valid_destination(destination)
            || mark != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid public discovery route context",
            ));
        }
        let selected = scope.link().await?;
        let epoch = scope.epoch();
        let monitor = &epoch.monitor;
        let owned = self
            .configured_exclusions(monitor)
            .await
            .map_err(route_error)?;
        let mut context = SocketRouteContext {
            source: local,
            destination,
            protocol,
            mark,
            interface_index: Some(selected.index),
        };
        let initial = monitor
            .route_for_socket(context, &owned)
            .await
            .map_err(route_error)?;
        let source = initial
            .preferred_source
            .filter(|ip| {
                ip.is_ipv4() == local.is_ipv4()
                    && !ip.is_unspecified()
                    && !ip.is_loopback()
                    && !ip.is_multicast()
            })
            .ok_or_else(no_default)?;
        context.source.set_ip(source);
        if let SocketAddr::V6(address) = &mut context.source
            && address.ip().is_unicast_link_local()
        {
            address.set_scope_id(selected.index);
        }
        if initial.interface_index != selected.index
            || !self
                .source_is_assigned_on(monitor, source, Some(selected.index))
                .await
                .map_err(route_error)?
        {
            return Err(no_default());
        }
        let route = monitor
            .route_for_socket(context, &owned)
            .await
            .map_err(route_error)?;
        if route.interface_index != selected.index || route.generation != epoch.generation {
            return Err(stale());
        }
        scope.check()?;
        Ok(RouteLease {
            monitor: Arc::clone(monitor),
            route,
            context,
            local_addr: context.source,
            preferred_dial: true,
            source_fixed: false,
        })
    }

    pub(crate) async fn prepare_public_socket(
        self: &Arc<Self>,
        scope: &Scope,
        destination: SocketAddr,
        protocol: SocketProtocol,
    ) -> io::Result<(Socket, RouteLease)> {
        let owner = Arc::clone(self);
        let scope = scope.clone();
        self.run_public_preparation(async move {
            owner
                .prepare_public_socket_inner(&scope, destination, protocol)
                .await
        })
        .await
    }

    pub(super) async fn run_public_preparation<T: Send + 'static>(
        &self,
        prepare: impl Future<Output = io::Result<T>> + Send + 'static,
    ) -> io::Result<T> {
        let permit = timeout(
            LOOKUP_TIMEOUT,
            Arc::clone(&self.preparations).acquire_owned(),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "public socket preparation queue timed out",
            )
        })?
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "route owner closed"))?;
        // Dial races may drop the caller. Drain admitted Netlink work under the
        // same bound to avoid cancelling other queries on the request socket.
        tokio::spawn(async move {
            let _permit = permit;
            prepare.await
        })
        .await
        .map_err(io::Error::other)?
    }

    async fn prepare_public_socket_inner(
        &self,
        scope: &Scope,
        destination: SocketAddr,
        protocol: SocketProtocol,
    ) -> io::Result<(Socket, RouteLease)> {
        scope.check()?;
        let destination = canonical_socket_address(destination);
        let ipv4 = destination.is_ipv4();
        let local = if ipv4 {
            Ipv4Addr::UNSPECIFIED.into()
        } else {
            Ipv6Addr::UNSPECIFIED.into()
        };
        let mut lease = self
            .prepare_public_route(scope, SocketAddr::new(local, 0), destination, protocol, 0)
            .await?;
        let socket = match protocol {
            SocketProtocol::Tcp => super::tcp::tcp_socket(ipv4, false)?,
            SocketProtocol::Udp => {
                let sock = Socket::new(
                    if ipv4 { Domain::IPV4 } else { Domain::IPV6 },
                    Type::DGRAM,
                    Some(Protocol::UDP),
                )?;
                if !ipv4 {
                    sock.set_only_v6(true)?;
                }
                sock.set_nonblocking(true)?;
                sock
            }
        };
        if socket.mark()? != 0 {
            return Err(stale());
        }
        scope.link().await?.bind(&socket)?;
        socket.bind(&SockAddr::from(lease.local_addr))?;
        lease.local_addr = socket.local_addr()?.as_socket().ok_or_else(no_default)?;
        lease.context.source = lease.local_addr;
        let owned = self
            .configured_exclusions(&lease.monitor)
            .await
            .map_err(route_error)?;
        let route = lease
            .monitor
            .route_for_socket(lease.context, &owned)
            .await
            .map_err(route_error)?;
        if route.generation != lease.route.generation
            || route.interface_index != lease.route.interface_index
        {
            return Err(stale());
        }
        scope.check()?;
        lease.route = route;
        Ok((socket, lease))
    }
}

async fn default_interface(
    epoch: &RouteEpoch,
    owned: &HashSet<u32>,
    probes: &[&str],
) -> io::Result<Option<u32>> {
    for probe in probes {
        let result = epoch
            .monitor
            .default_route(probe.parse().expect("FIB probe"), owned)
            .await;
        match result {
            Ok(route) if epoch.generation == route.generation => {
                return Ok(Some(route.interface_index));
            }
            Ok(_) => return Err(stale()),
            Err(
                RouteLookupError::UnsupportedRoute
                | RouteLookupError::OwnOverlay
                | RouteLookupError::Kernel(Some(-101 | -113 | -97 | -19 | -2)),
            ) => {}
            Err(error) => return Err(route_error(error)),
        }
    }
    Ok(None)
}

#[derive(Debug)]
pub(crate) struct QuicBinding {
    pub(crate) scope: Scope,
    pub(crate) lease: RouteLease,
}

impl quinn::UdpSocketBinding for QuicBinding {
    fn identity(&self) -> [u64; 3] {
        [
            u64::from(self.lease.route.interface_index),
            0,
            self.lease.route.generation,
        ]
    }

    fn bind(&self, socket: &UdpSocket) -> io::Result<()> {
        let link = self.scope.initialized_link()?;
        self.scope.with_current(|| {
            let socket = socket2::SockRef::from(socket);
            if socket.mark()? != 0 {
                return Err(stale());
            }
            link.bind(&socket)
        })
    }

    fn uses_platform_routing(&self) -> bool {
        true
    }

    fn send_if_current(&self, send: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        self.scope.with_current(send)
    }
}
