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
    pub(super) fn route_paths_changed(&self) {
        #[cfg(target_os = "linux")]
        if let Some(owner) = &self.egress {
            owner.paths_changed();
        }
    }
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

#[derive(Clone, Default)]
pub(super) struct AcceptedRoutes {
    #[cfg(target_os = "linux")]
    owner: Option<Arc<super::super::physical_network::linux::egress::LinuxEgress>>,
    #[cfg(target_os = "linux")]
    mark: u32,
    #[cfg(target_os = "linux")]
    listener: Option<SocketAddr>,
}

#[cfg(target_os = "linux")]
struct SelectedIncoming(Option<quinn::Incoming>, bool);

#[cfg(target_os = "linux")]
impl Drop for SelectedIncoming {
    fn drop(&mut self) {
        if let Some(incoming) = self.0.take()
            && self.1
        {
            incoming.ignore();
        }
    }
}

impl AcceptedRoutes {
    pub(super) fn accept(
        self,
        incoming: quinn::Incoming,
    ) -> impl std::future::Future<Output = Result<QuicPath, PacketPlaneQuicError>> + Send {
        // Install cancellation ownership before returning even an unpolled future.
        #[cfg(target_os = "linux")]
        let mut incoming = SelectedIncoming(Some(incoming), self.owner.is_some());
        async move {
            #[cfg(target_os = "linux")]
            if let Some(owner) = &self.owner {
                let prepared = async {
                    let incoming = incoming.0.as_ref().expect("selected incoming exists");
                    let listener = self.listener.expect("managed listener exists");
                    let remote =
                        super::super::physical_network::linux::egress::canonical_socket_address(
                            incoming.remote_address(),
                        );
                    let mut ip = incoming
                        .local_ip()
                        .ok_or_else(|| io::Error::other("missing incoming destination IP"))?;
                    if remote.is_ipv4()
                        && let std::net::IpAddr::V6(v6) = ip
                    {
                        ip = v6.to_ipv4_mapped().map_or(ip, std::net::IpAddr::V4);
                    }
                    let mut local = SocketAddr::new(ip, listener.port());
                    if let (SocketAddr::V6(local), SocketAddr::V6(remote)) = (&mut local, remote)
                        && local.ip().is_unicast_link_local()
                    {
                        local.set_scope_id(remote.scope_id());
                    }
                    owner.prepare_incoming(local, remote, self.mark).await
                }
                .await;
                let lease = match prepared {
                    Ok(lease) => lease,
                    Err(error) => {
                        drop(incoming);
                        eprintln!(
                            "level=warn event=packet_plane_quic_incoming_route_rejected reason={error:?}"
                        );
                        return Err(error.into());
                    }
                };
                let Some(index) = std::num::NonZeroU32::new(lease.route.interface_index) else {
                    drop(incoming);
                    return Err(io::Error::other("zero incoming interface").into());
                };
                if !lease.is_current() {
                    drop(incoming);
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "incoming route changed before TLS",
                    )
                    .into());
                }
                let connection = incoming
                    .0
                    .take()
                    .expect("selected incoming exists")
                    .accept_on_interface(index)?
                    .await?;
                if !lease.is_current() {
                    connection.close(0_u32.into(), b"stale incoming QUIC route");
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "incoming route changed during TLS",
                    )
                    .into());
                }
                eprintln!(
                    "level=info event=packet_plane_quic_incoming_source_bound generation={} interface={}",
                    lease.route.generation, lease.route.interface_index
                );
                return Ok(QuicPath {
                    inner: connection,
                    lease: Some(lease),
                    route_token: Arc::new(()),
                });
            }
            #[cfg(target_os = "linux")]
            let incoming = incoming.0.take().expect("unmanaged incoming exists");
            Ok(incoming.await?.into())
        }
    }
}

impl PacketPlaneQuicConnector {
    pub(super) fn accepted_routes(&self) -> AcceptedRoutes {
        AcceptedRoutes {
            #[cfg(target_os = "linux")]
            owner: self.egress.clone(),
            #[cfg(target_os = "linux")]
            mark: self.listener_mark,
            #[cfg(target_os = "linux")]
            listener: self.endpoint.local_addr().ok(),
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn bind_listener(
    config: ServerConfig,
    address: SocketAddr,
) -> io::Result<(Endpoint, u32)> {
    let socket = std::net::UdpSocket::bind(address)?;
    let wrapped = quinn::Runtime::wrap_udp_socket(&quinn::TokioRuntime, socket.try_clone()?)?;
    let mark = socket2::SockRef::from(&socket).mark()?;
    let endpoint = Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(config),
        wrapped,
        Arc::new(quinn::TokioRuntime),
    )?;
    Ok((endpoint, mark))
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

    #[tokio::test]
    async fn accepted_connections_pin_egress_without_rebinding_or_closing_shared_listener() {
        for (listen, client, destination) in [
            ("0.0.0.0:0", "127.0.0.1:0", "127.0.0.1"),
            ("[::]:0", "[::1]:0", "::1"),
            ("[::]:0", "127.0.0.1:0", "127.0.0.1"),
        ] {
            let mut server = PacketPlaneQuicRuntime::bind(listen.parse().unwrap()).unwrap();
            server.follow_linux_routes("absent-pv".into());
            let client_a = PacketPlaneQuicRuntime::bind(client.parse().unwrap()).unwrap();
            let client_b = PacketPlaneQuicRuntime::bind(client.parse().unwrap()).unwrap();
            let endpoint =
                SocketAddr::new(destination.parse().unwrap(), server.local_addr().port());
            let connector = server.connector();
            let mut connections = Vec::new();
            for client in [&client_a, &client_b] {
                let client = client.connector();
                let (accepted, dialed) = tokio::time::timeout(Duration::from_secs(2), async {
                    tokio::join!(
                        connector.accept(),
                        client.connect(endpoint, server.server_certificate())
                    )
                })
                .await
                .unwrap();
                let accepted = accepted.unwrap();
                let lease = accepted.connection.route_lease().unwrap();
                assert!(!lease.preferred_dial);
                assert!(lease.is_current());
                assert_eq!(lease.local_addr, endpoint);
                assert_eq!(lease.context.mark, server.listener_mark);
                assert_eq!(
                    accepted.connection.egress_interface().unwrap().get(),
                    lease.route.interface_index
                );
                connections.push((accepted, dialed.unwrap()));
            }
            connections[0]
                .0
                .connection
                .close(0_u32.into(), b"retire first accepted path");
            connections[1]
                .1
                .connection
                .send_datagram(b"second-peer-still-reachable".as_slice().into())
                .unwrap();
            let received = tokio::time::timeout(
                Duration::from_secs(1),
                connections[1].0.connection.read_datagram(),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(received.as_ref(), b"second-peer-still-reachable");
            assert_eq!(server.local_addr().port(), endpoint.port());
            assert!(connector.endpoint.local_addr().is_ok());
        }
    }

    #[tokio::test]
    async fn cancelled_incoming_selection_ignores_instead_of_refusing_on_an_unselected_route() {
        let mut server = PacketPlaneQuicRuntime::bind("0.0.0.0:0".parse().unwrap()).unwrap();
        server.follow_linux_routes("absent-pv".into());
        let client = PacketPlaneQuicRuntime::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = SocketAddr::new("127.0.0.1".parse().unwrap(), server.local_addr().port());
        let certificate = server.server_certificate();
        let dialer = client.connector();
        let task = tokio::spawn(async move { dialer.connect(address, certificate).await });
        let incoming = tokio::time::timeout(Duration::from_secs(1), server.endpoint.accept())
            .await
            .unwrap()
            .unwrap();
        let routes = server.connector().accepted_routes();
        let mut selection = Box::pin(routes.accept(incoming));
        // Stop at the first route-lookup suspension, before the runtime can
        // deliver a response and advance to the TLS handshake.
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(std::future::Future::poll(selection.as_mut(), &mut context).is_pending());
        drop(selection);
        assert_eq!(server.endpoint.stats().refused_handshakes, 0);
        assert_eq!(server.endpoint.stats().ignored_handshakes, 1);
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn unpolled_incoming_selection_is_ignored_before_handshake_task_starts() {
        let mut server = PacketPlaneQuicRuntime::bind("0.0.0.0:0".parse().unwrap()).unwrap();
        server.follow_linux_routes("absent-pv".into());
        let client = PacketPlaneQuicRuntime::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = SocketAddr::new("127.0.0.1".parse().unwrap(), server.local_addr().port());
        let certificate = server.server_certificate();
        let dialer = client.connector();
        let task = tokio::spawn(async move { dialer.connect(address, certificate).await });
        let incoming = tokio::time::timeout(Duration::from_secs(1), server.endpoint.accept())
            .await
            .unwrap()
            .unwrap();
        let accepting = server.connector().accepted_routes().accept(incoming);
        drop(accepting);
        assert_eq!(server.endpoint.stats().refused_handshakes, 0);
        assert_eq!(server.endpoint.stats().ignored_handshakes, 1);
        task.abort();
        let _ = task.await;
    }

    #[derive(Debug)]
    struct UnsupportedSocket(Arc<dyn quinn::AsyncUdpSocket>);

    impl quinn::AsyncUdpSocket for UnsupportedSocket {
        fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
            self.0.clone().create_io_poller()
        }
        fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
            self.0.try_send(transmit)
        }
        fn poll_recv(
            &self,
            cx: &mut std::task::Context<'_>,
            bufs: &mut [io::IoSliceMut<'_>],
            meta: &mut [quinn::udp::RecvMeta],
        ) -> std::task::Poll<io::Result<usize>> {
            self.0.poll_recv(cx, bufs, meta)
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.0.local_addr()
        }
        fn max_transmit_segments(&self) -> usize {
            self.0.max_transmit_segments()
        }
        fn max_receive_segments(&self) -> usize {
            self.0.max_receive_segments()
        }
        fn may_fragment(&self) -> bool {
            self.0.may_fragment()
        }
    }

    #[tokio::test]
    async fn unsupported_backend_and_invalid_index_fail_without_an_unselected_refusal() {
        for unsupported in [true, false] {
            let (config, certificate) = quic_server_config().unwrap();
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let socket = quinn::Runtime::wrap_udp_socket(&quinn::TokioRuntime, socket).unwrap();
            let socket: Arc<dyn quinn::AsyncUdpSocket> = if unsupported {
                Arc::new(UnsupportedSocket(socket))
            } else {
                socket
            };
            let server = Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                Some(config),
                socket,
                Arc::new(quinn::TokioRuntime),
            )
            .unwrap();
            let client = PacketPlaneQuicRuntime::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let address = server.local_addr().unwrap();
            let dialer = client.connector();
            let task = tokio::spawn(async move { dialer.connect(address, certificate).await });
            let incoming = tokio::time::timeout(Duration::from_secs(1), server.accept())
                .await
                .unwrap()
                .unwrap();
            let index = std::num::NonZeroU32::new(if unsupported { 1 } else { u32::MAX }).unwrap();
            let error = incoming.accept_on_interface(index).unwrap_err();
            assert_eq!(
                error.kind(),
                if unsupported {
                    io::ErrorKind::Unsupported
                } else {
                    io::ErrorKind::InvalidInput
                }
            );
            assert_eq!(server.stats().refused_handshakes, 0);
            assert_eq!(server.stats().ignored_handshakes, 1);
            task.abort();
            let _ = task.await;
        }
    }

    #[test]
    fn selected_datagrams_reject_missing_unspecified_and_mismatched_source_families() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp = quinn::udp::UdpSocketState::new((&socket).into()).unwrap();
        for (source, destination, index) in [
            (None, "127.0.0.1:9", 1),
            (Some("0.0.0.0"), "127.0.0.1:9", 1),
            (Some("127.0.0.1"), "[::1]:9", 1),
            (Some("::1"), "127.0.0.1:9", 1),
            (Some("::ffff:127.0.0.1"), "[::1]:9", 1),
            (Some("127.0.0.1"), "127.0.0.1:9", u32::MAX),
        ] {
            let transmit = quinn::udp::Transmit {
                destination: destination.parse().unwrap(),
                src_ip: source.map(|source| source.parse().unwrap()),
                ecn: None,
                segment_size: None,
                contents: b"must-not-be-sent",
            };
            assert_eq!(
                udp.send_on_interface(
                    (&socket).into(),
                    &transmit,
                    std::num::NonZeroU32::new(index).unwrap()
                )
                .unwrap_err()
                .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(socket2::SockRef::from(&socket).device().unwrap(), None);
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
        let destination =
            super::super::physical_network::linux::egress::canonical_socket_address(destination);
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
