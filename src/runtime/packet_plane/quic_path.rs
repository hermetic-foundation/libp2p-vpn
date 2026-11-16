//! Socket ownership travels with a connection through staging, drain and rollback.

use super::*;

#[derive(Clone, Debug)]
pub(super) struct QuicPath {
    inner: Connection,
    #[cfg(target_os = "linux")]
    lease: Option<super::super::physical_network::linux::egress::RouteLease>,
    #[cfg(target_os = "linux")]
    route_token: Arc<()>,
}

impl From<Connection> for QuicPath {
    fn from(inner: Connection) -> Self {
        Self {
            inner,
            #[cfg(target_os = "linux")]
            lease: None,
            #[cfg(target_os = "linux")]
            route_token: Arc::new(()),
        }
    }
}

impl std::ops::Deref for QuicPath {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.inner
    }
}

impl QuicPath {
    // A queued decision must not match a recycled Quinn stable_id. This token
    // retains no connection/socket resources through retirement.
    #[cfg(target_os = "linux")]
    pub(super) fn route_token(&self) -> &Arc<()> {
        &self.route_token
    }
    #[cfg(target_os = "linux")]
    pub(super) fn route_lease(
        &self,
    ) -> Option<&super::super::physical_network::linux::egress::RouteLease> {
        self.lease.as_ref()
    }

    pub(super) fn route_is_current(&self) -> bool {
        #[cfg(target_os = "linux")]
        if let Some(lease) = &self.lease {
            return lease.is_current();
        }
        true
    }

    pub(super) fn local_socket_addr(&self, listener: SocketAddr) -> SocketAddr {
        #[cfg(target_os = "linux")]
        if let Some(lease) = &self.lease {
            return lease.local_addr;
        }
        listener
    }
}

impl PacketPlaneQuicRuntime {
    #[cfg(target_os = "linux")]
    pub(crate) fn follow_linux_routes(&mut self, owned_interface: String) {
        // Explicit addresses and fixed ports retain their source overrides.
        if self.automatic_egress {
            self.egress = Some(Arc::new(
                super::super::physical_network::linux::egress::LinuxEgress::new(owned_interface),
            ));
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn automatic_egress_allowed(listener: SocketAddr) -> bool {
    listener.ip().is_unspecified() && listener.port() == 0
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    fn explicit_sources_and_fixed_ports_retain_the_existing_dial_socket() {
        for (listener, allowed) in [
            ("0.0.0.0:0", true),
            ("[::]:0", true),
            ("0.0.0.0:4001", false),
            ("[::]:4001", false),
            ("127.0.0.1:0", false),
            ("192.0.2.1:0", false),
        ] {
            assert_eq!(
                automatic_egress_allowed(listener.parse().unwrap()),
                allowed,
                "{listener}"
            );
        }
    }
}

impl PacketPlaneQuicConnector {
    #[cfg(target_os = "linux")]
    pub(super) async fn connect_routed(
        &self,
        destination: SocketAddr,
        trusted_certificate: CertificateDer<'static>,
    ) -> Result<PacketPlaneQuicConnection, PacketPlaneQuicError> {
        let owner = self.egress.as_ref().expect("route owner present");
        let _permit = owner.connect_permit()?;
        let (socket, lease) = owner.prepare(destination).await?;
        if !lease.is_current() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "QUIC egress changed before connection",
            )
            .into());
        }
        let endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        let connection = endpoint
            .connect_with(
                quic_client_config(trusted_certificate)?,
                destination,
                "p2p-vpn-packet-plane",
            )?
            .await?;
        if !lease.is_current() {
            connection.close(0_u32.into(), b"stale QUIC egress selection");
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "QUIC egress changed during connection",
            )
            .into());
        }
        eprintln!(
            "level=info event=packet_plane_quic_source_bound generation={} interface={}",
            lease.route.generation, lease.route.interface_index
        );
        // Quinn's driver retains the socket while its connections are live,
        // even after the public Endpoint handle is dropped.
        Ok(PacketPlaneQuicConnection {
            connection: QuicPath {
                inner: connection,
                lease: Some(lease),
                route_token: Arc::new(()),
            },
        })
    }
}
