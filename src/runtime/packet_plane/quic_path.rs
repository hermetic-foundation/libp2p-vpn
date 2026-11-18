//! Socket ownership travels with a connection through staging, drain and rollback.

use super::*;

#[cfg(any(target_os = "linux", target_os = "android"))]
use super::super::physical_network::platform::egress::{
    Egress, RouteLease, canonical_socket_address,
};

#[derive(Clone, Debug)]
pub(super) struct QuicPath {
    inner: Connection,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    lease: Option<RouteLease>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    route_token: Arc<()>,
}

impl From<Connection> for QuicPath {
    fn from(inner: Connection) -> Self {
        Self {
            inner,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            lease: None,
            #[cfg(any(target_os = "linux", target_os = "android"))]
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
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(super) fn owned(inner: Connection, lease: RouteLease) -> Self {
        Self {
            inner,
            lease: Some(lease),
            route_token: Arc::new(()),
        }
    }

    // A queued decision must not match a recycled Quinn stable_id. This token
    // retains no connection/socket resources through retirement.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(super) fn route_token(&self) -> &Arc<()> {
        &self.route_token
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(super) fn route_lease(&self) -> Option<&RouteLease> {
        self.lease.as_ref()
    }

    pub(super) fn route_is_current(&self) -> bool {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(lease) = &self.lease {
            return lease.is_current();
        }
        true
    }

    pub(super) fn route_is_available(&self) -> bool {
        #[cfg(target_os = "android")]
        if let Some(lease) = &self.lease {
            return lease.is_available();
        }
        // Linux availability requires an asynchronous audit. Preserve its
        // existing rollback behavior rather than treating preference as loss.
        true
    }

    pub(super) fn local_socket_addr(&self, listener: SocketAddr) -> SocketAddr {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(lease) = &self.lease {
            return lease.local_addr;
        }
        listener
    }
}

impl PacketPlaneQuicRuntime {
    pub(crate) fn retained_source_aliases(&self) -> Vec<SocketAddr> {
        self.connections
            .iter()
            .filter_map(|(peer, connection)| {
                if !self.sessions.contains_key(peer)
                    || connection.close_reason().is_some()
                    || !connection.route_is_available()
                {
                    return None;
                }
                let source = connection.local_socket_addr(self.local_addr);
                (!source.ip().is_unspecified())
                    .then_some(SocketAddr::new(source.ip(), self.local_addr.port()))
            })
            .collect()
    }

    pub(super) fn route_paths_changed(&self) {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(owner) = &self.egress {
            owner.paths_changed();
        }
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(crate) fn follow_physical_routes(&mut self, owned_interface: String) {
        // Explicit addresses and fixed ports retain their source overrides.
        if self.automatic_egress {
            self.egress = Some(Arc::new(Egress::new(owned_interface)));
        }
    }

    #[cfg(target_os = "linux")]
    #[allow(dead_code)] // Compatibility entry point for Linux callers.
    pub(crate) fn follow_linux_routes(&mut self, owned_interface: String) {
        self.follow_physical_routes(owned_interface);
    }
}

#[derive(Clone, Default)]
pub(super) struct AcceptedRoutes {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    owner: Option<Arc<Egress>>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    mark: u32,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    listener: Option<SocketAddr>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
struct SelectedIncoming(Option<quinn::Incoming>, bool);

#[cfg(any(target_os = "linux", target_os = "android"))]
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
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let mut incoming = SelectedIncoming(Some(incoming), self.owner.is_some());
        async move {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            if let Some(owner) = &self.owner {
                let prepared = async {
                    let incoming = incoming.0.as_ref().expect("selected incoming exists");
                    let listener = self.listener.expect("managed listener exists");
                    let remote = canonical_socket_address(incoming.remote_address());
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
                #[cfg(target_os = "android")]
                let binding = Some(lease.socket_binding());
                #[cfg(target_os = "linux")]
                let binding = None;
                let connection = incoming
                    .0
                    .take()
                    .expect("selected incoming exists")
                    .accept_on_interface_and_binding(index, binding)?
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
            #[cfg(any(target_os = "linux", target_os = "android"))]
            let incoming = incoming.0.take().expect("unmanaged incoming exists");
            Ok(incoming.await?.into())
        }
    }
}

impl PacketPlaneQuicConnector {
    pub(super) fn accepted_routes(&self) -> AcceptedRoutes {
        AcceptedRoutes {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            owner: self.egress.clone(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            mark: self.listener_mark,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            listener: self.endpoint.local_addr().ok(),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
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

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn automatic_egress_allowed(listener: SocketAddr) -> bool {
    listener.ip().is_unspecified() && listener.port() == 0
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod policy_tests {
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
            ("[::1]:0", false),
            ("[2001:db8::1]:0", false),
        ] {
            assert_eq!(
                automatic_egress_allowed(listener.parse().unwrap()),
                allowed,
                "{listener}"
            );
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn active_payload_retains_listener_alias_not_client_only_port() {
        for (listen, remote) in [("0.0.0.0:0", "127.0.0.1:0"), ("[::]:0", "[::1]:0")] {
            let mut client = PacketPlaneQuicRuntime::bind(listen.parse().unwrap()).unwrap();
            client.follow_physical_routes("absent-pv".into());
            let server = PacketPlaneQuicRuntime::bind(remote.parse().unwrap()).unwrap();
            let connector = client.connector();
            let acceptor = server.connector();
            let (outgoing, incoming) = tokio::time::timeout(Duration::from_secs(2), async {
                tokio::join!(
                    connector.connect(server.local_addr(), server.server_certificate()),
                    acceptor.accept()
                )
            })
            .await
            .unwrap();
            let outgoing = outgoing.unwrap();
            let _incoming = incoming.unwrap();
            let source = outgoing.connection.route_lease().unwrap().local_addr;
            let listener_alias = SocketAddr::new(source.ip(), client.local_addr().port());
            let (secret, _, hello, accept) =
                super::super::tests::verified_session_pair_with_endpoints(
                    listener_alias,
                    server.local_addr(),
                    1200,
                );
            client.install_connection(accept.peer, outgoing);
            assert!(
                client.retained_source_aliases().is_empty(),
                "an unbound connection is not a payload owner"
            );
            client
                .establish_session(PacketPlaneSessionRole::Initiator, &secret, &hello, &accept)
                .unwrap();
            assert_eq!(client.retained_source_aliases(), [listener_alias]);
            if source.port() != listener_alias.port() {
                assert!(
                    !client.retained_source_aliases().contains(&source),
                    "the outgoing-only socket is not an advertised server"
                );
            }
            assert!(client.close_connection(accept.peer));
            assert!(client.has_session(accept.peer));
            assert!(
                client.retained_source_aliases().is_empty(),
                "retained keys cannot advertise a closed path"
            );
        }
    }

    #[tokio::test]
    async fn platform_and_linux_entry_points_share_route_ownership_policy() {
        for legacy in [false, true] {
            for (listen, managed) in [("0.0.0.0:0", true), ("127.0.0.1:0", false)] {
                let mut runtime = PacketPlaneQuicRuntime::bind(listen.parse().unwrap()).unwrap();
                let listener = runtime.local_addr();
                if legacy {
                    runtime.follow_linux_routes("absent-pv".into());
                } else {
                    runtime.follow_physical_routes("absent-pv".into());
                }
                assert_eq!(runtime.egress.is_some(), managed);
                let connector = runtime.connector();
                let accepted = connector.accepted_routes();
                assert_eq!(runtime.local_addr(), listener);
                if managed {
                    let owner = runtime.egress.as_ref().unwrap();
                    assert!(Arc::ptr_eq(owner, connector.egress.as_ref().unwrap()));
                    assert!(Arc::ptr_eq(owner, accepted.owner.as_ref().unwrap()));
                    assert_eq!(accepted.listener, Some(listener));
                    assert_eq!(accepted.mark, runtime.listener_mark);
                } else {
                    assert!(connector.egress.is_none());
                    assert!(accepted.owner.is_none());
                }
            }
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
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(super) async fn connect_routed(
        &self,
        destination: SocketAddr,
        trusted_certificate: CertificateDer<'static>,
    ) -> Result<PacketPlaneQuicConnection, PacketPlaneQuicError> {
        let owner = self.egress.as_ref().expect("route owner present");
        let destination = canonical_socket_address(destination);
        let _permit = owner.connect_permit()?;
        let (socket, lease) = owner.prepare(destination).await?;
        quic_retry::connect_prepared(socket, lease, quic_client_config(trusted_certificate)?)
            .await
            .map_err(quic_retry::restore_error)
    }
}
