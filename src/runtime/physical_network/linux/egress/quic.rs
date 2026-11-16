//! Select per-connection UDP egress without rebinding the shared endpoint.

use super::*;

impl LinuxEgress {
    pub(crate) async fn prepare_shared_datagram(
        &self,
        local: SocketAddr,
        destination: SocketAddr,
        mark: u32,
    ) -> io::Result<RouteLease> {
        let _permit = timeout(LOOKUP_TIMEOUT, self.preparations.acquire())
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "shared QUIC preparation queue timeout",
                )
            })?
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "route owner closed"))?;
        timeout(LOOKUP_TIMEOUT, async {
            let local = canonical_socket_address(local);
            let destination = canonical_socket_address(destination);
            if local.port() == 0
                || destination.port() == 0
                || local.is_ipv4() != destination.is_ipv4()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "QUIC shared socket requires a matching concrete port and family",
                ));
            }
            let monitor = self.monitor()?;
            let owned = self
                .configured_exclusions(&monitor)
                .await
                .map_err(route_error)?;
            let mut context = SocketRouteContext {
                source: local,
                destination,
                protocol: SocketProtocol::Udp,
                mark,
                interface_index: None,
            };
            let initial = monitor
                .route_for_socket(context, &owned)
                .await
                .map_err(route_error)?;
            let source_fixed = !local.ip().is_unspecified();
            if !source_fixed {
                let source = initial
                    .preferred_source
                    .filter(|source| {
                        !source.is_unspecified()
                            && !source.is_multicast()
                            && source.is_ipv4() == local.is_ipv4()
                    })
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::AddrNotAvailable,
                            "QUIC route has no eligible source",
                        )
                    })?;
                context.source.set_ip(source);
                if let SocketAddr::V6(address) = &mut context.source {
                    address.set_scope_id(if address.ip().is_unicast_link_local() {
                        initial.interface_index
                    } else {
                        0
                    });
                }
            }
            self.require_underlay_source(&monitor, context.source.ip())
                .await?;
            let selected = monitor
                .route_for_socket(context, &owned)
                .await
                .map_err(route_error)?;
            context.interface_index = Some(selected.interface_index);
            let bound = monitor
                .route_for_socket(context, &owned)
                .await
                .map_err(route_error)?;
            let preferred = monitor
                .route_for_socket(
                    SocketRouteContext {
                        interface_index: None,
                        ..context
                    },
                    &owned,
                )
                .await
                .map_err(route_error)?;
            if initial.generation != selected.generation
                || selected != preferred
                || bound.interface_index != selected.interface_index
            {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "QUIC route changed during shared socket preparation",
                ));
            }
            monitor.validate_generation(&bound).map_err(route_error)?;
            Ok(RouteLease {
                monitor,
                route: bound,
                local_addr: context.source,
                context,
                preferred_dial: true,
                source_fixed,
            })
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "QUIC shared socket preparation timeout",
            )
        })?
    }
}
