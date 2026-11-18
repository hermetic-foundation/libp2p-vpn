//! Network retry is an authenticated negotiation's intent, not a socket default.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketPlaneQuicDialPolicy {
    SelectedRoute,
    NetworkRecovery,
}

#[cfg(any(target_os = "android", test))]
fn attempt_timeout(budget: Duration) -> io::Result<Duration> {
    let timeout = (budget / 3).min(Duration::from_secs(6));
    if timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC Network retry budget is too small",
        ));
    }
    Ok(timeout)
}

#[cfg(target_os = "android")]
impl PacketPlaneQuicConnector {
    pub(super) async fn connect_routed_recovering(
        &self,
        destination: SocketAddr,
        certificate: CertificateDer<'static>,
        budget: Duration,
    ) -> Result<PacketPlaneQuicConnection, PacketPlaneQuicError> {
        use super::super::physical_network::android::{
            SocketProtocol,
            egress::{Egress, canonical_socket_address},
        };
        let owner = self.egress.as_ref().expect("route owner present");
        let destination = canonical_socket_address(destination);
        let _permit = owner.connect_permit()?;
        let config = quic_client_config(certificate)?;
        let local = if destination.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()
        .expect("wildcard address");
        owner
            .attempt_networks_if_with_timeout(
                local,
                destination,
                SocketProtocol::Udp,
                0,
                attempt_timeout(budget)?,
                move |lease| {
                    let prepared = Egress::udp_socket(lease);
                    let config = config.clone();
                    async move {
                        let (socket, lease) = prepared?;
                        connect_prepared(socket, lease, config).await
                    }
                },
                || true,
            )
            .await
            .map_err(restore_error)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) async fn connect_prepared(
    socket: std::net::UdpSocket,
    lease: super::super::physical_network::platform::egress::RouteLease,
    config: ClientConfig,
) -> io::Result<PacketPlaneQuicConnection> {
    if !lease.is_current() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "QUIC egress changed before connection",
        ));
    }
    let endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    let connection = endpoint
        .connect_with(config, lease.context.destination, "p2p-vpn-packet-plane")
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
        .await
        .map_err(connection_error)?;
    if !lease.is_current() {
        connection.close(0_u32.into(), b"stale QUIC egress selection");
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "QUIC egress changed during connection",
        ));
    }
    eprintln!(
        "level=info event=packet_plane_quic_source_bound generation={} interface={}",
        lease.route.generation, lease.route.interface_index
    );
    // Quinn's driver retains the socket while its connection is live.
    Ok(PacketPlaneQuicConnection {
        connection: QuicPath::owned(connection, lease),
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn connection_error(error: quinn::ConnectionError) -> io::Error {
    let kind = match &error {
        quinn::ConnectionError::TimedOut => io::ErrorKind::TimedOut,
        quinn::ConnectionError::Reset => io::ErrorKind::ConnectionReset,
        quinn::ConnectionError::LocallyClosed => io::ErrorKind::Interrupted,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, error)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn restore_error(error: io::Error) -> PacketPlaneQuicError {
    if !error.get_ref().is_some_and(|source| {
        source.is::<quinn::ConnectionError>() || source.is::<quinn::ConnectError>()
    }) {
        return PacketPlaneQuicError::Io(error);
    }
    let kind = error.kind();
    match error.into_inner() {
        Some(source) => match source.downcast::<quinn::ConnectionError>() {
            Ok(error) => PacketPlaneQuicError::Connection(*error),
            Err(source) => match source.downcast::<quinn::ConnectError>() {
                Ok(error) => PacketPlaneQuicError::Connect(*error),
                Err(source) => PacketPlaneQuicError::Io(io::Error::new(kind, source)),
            },
        },
        None => PacketPlaneQuicError::Io(kind.into()),
    }
}

#[cfg(test)]
mod tests;
