use super::*;

#[tokio::test]
async fn binding_capacity_is_shared_and_cancelled_writes_release_every_slot() {
    tokio::time::timeout(Duration::from_secs(4), async {
        let (mut config, certificate) = quic_server_config().unwrap();
        let mut transport = packet_plane_quic_transport_config();
        transport.max_concurrent_uni_streams(0_u8.into());
        config.transport_config(Arc::new(transport));
        let server = Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let runtime = PacketPlaneQuicRuntime::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let connector = runtime.connector();
        let clone = connector.clone();
        let (outgoing, incoming) = tokio::join!(
            connector.connect(server.local_addr().unwrap(), certificate),
            async { server.accept().await.unwrap().await.unwrap() },
        );
        let outgoing = outgoing.unwrap();
        let mut pending = Vec::new();
        for _ in 0..QUIC_BINDING_MAX_OUTBOUND {
            let copy = PacketPlaneQuicConnection { connection: outgoing.connection.clone() };
            let mut binding = Box::pin(connector.bind_selected_connection(copy, PacketPlaneQuicBinding::from_bytes([23; 32])));
            assert!(futures::poll!(&mut binding).is_pending(), "remote has no unidirectional-stream credit");
            pending.push(binding);
        }
        assert_eq!(connector.accept_router.outbound_bindings.available_permits(), 0);
        let copy = PacketPlaneQuicConnection { connection: outgoing.connection.clone() };
        let error = clone.bind_selected_connection(copy, PacketPlaneQuicBinding::from_bytes([24; 32])).await.unwrap_err();
        assert!(matches!(error, PacketPlaneQuicError::Io(ref error) if error.kind() == io::ErrorKind::WouldBlock));
        drop(pending);
        assert_eq!(clone.accept_router.outbound_bindings.available_permits(), QUIC_BINDING_MAX_OUTBOUND);
        drop((incoming, outgoing));
    }).await.expect("bounded real TLS with withheld stream credit, shared binding cap and cancellation");
}

#[tokio::test]
async fn request_dial_returns_unbound_tls_and_binding_is_sent_once_after_selection() {
    tokio::time::timeout(Duration::from_secs(4), async {
        for policy in [
            PacketPlaneQuicDialPolicy::SelectedRoute,
            PacketPlaneQuicDialPolicy::NetworkRecovery,
        ] {
            let server = PacketPlaneQuicRuntime::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let client = PacketPlaneQuicRuntime::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let connector = client.connector();
            let acceptor = server.connector();
            let (outgoing, incoming) = tokio::join!(
                connector.connect_for_dial(
                    server.local_addr(),
                    server.server_certificate(),
                    policy,
                    Duration::from_secs(1)
                ),
                acceptor.accept(),
            );
            let outgoing = outgoing.unwrap();
            let incoming = incoming.unwrap();
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(20),
                    receive_quic_binding(&incoming.connection)
                )
                .await
                .is_err(),
                "TLS candidates cannot consume a binding before selection"
            );
            let binding = PacketPlaneQuicBinding::from_bytes([19; 32]);
            let _outgoing = bind_quic_connection(outgoing, binding).await.unwrap();
            assert_eq!(
                receive_quic_binding(&incoming.connection).await.unwrap(),
                binding
            );
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(20),
                    receive_quic_binding(&incoming.connection)
                )
                .await
                .is_err(),
                "selected connection receives exactly one binding stream"
            );
        }
    })
    .await
    .expect("bounded real TLS then single selected binding");
}

#[test]
fn retry_timeout_divides_the_existing_endpoint_budget_without_extending_it() {
    for budget in [
        Duration::from_secs(1),
        Duration::from_secs(5),
        Duration::from_secs(10),
        Duration::from_secs(100),
    ] {
        let per_attempt = attempt_timeout(budget).unwrap();
        assert!(!per_attempt.is_zero());
        assert!(per_attempt <= Duration::from_secs(6));
        assert!(per_attempt * 3 <= budget);
    }
    for budget in [Duration::ZERO, Duration::from_nanos(2)] {
        assert_eq!(
            attempt_timeout(budget).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn retry_error_round_trip_preserves_types_and_rejects_peer_refusal() {
    let original = io::Error::from_raw_os_error(24);
    let message = original.to_string();
    assert!(
        matches!(restore_error(original), PacketPlaneQuicError::Io(ref error)
        if error.raw_os_error() == Some(24) && error.to_string() == message)
    );
    for (error, kind) in [
        (quinn::ConnectionError::TimedOut, io::ErrorKind::TimedOut),
        (
            quinn::ConnectionError::Reset,
            io::ErrorKind::ConnectionReset,
        ),
        (
            quinn::ConnectionError::LocallyClosed,
            io::ErrorKind::Interrupted,
        ),
        (
            quinn::ConnectionError::VersionMismatch,
            io::ErrorKind::InvalidData,
        ),
        (
            quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code: 1_u32.into(),
                reason: Default::default(),
            }),
            io::ErrorKind::InvalidData,
        ),
        (
            quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
                error_code: quinn::TransportErrorCode::PROTOCOL_VIOLATION,
                frame_type: None,
                reason: Default::default(),
            }),
            io::ErrorKind::InvalidData,
        ),
    ] {
        let expected = error.to_string();
        let io = connection_error(error);
        assert_eq!(io.kind(), kind);
        let PacketPlaneQuicError::Connection(restored) = restore_error(io) else {
            panic!("native QUIC error must retain its variant");
        };
        assert_eq!(restored.to_string(), expected);
    }
    let error = io::Error::new(
        io::ErrorKind::InvalidInput,
        quinn::ConnectError::EndpointStopping,
    );
    assert!(matches!(
        restore_error(error),
        PacketPlaneQuicError::Connect(quinn::ConnectError::EndpointStopping)
    ));
    let error = io::Error::new(io::ErrorKind::PermissionDenied, "Network bind denied");
    assert!(
        matches!(restore_error(error), PacketPlaneQuicError::Io(ref error)
        if error.kind() == io::ErrorKind::PermissionDenied && error.to_string() == "Network bind denied")
    );
    assert!(
        matches!(restore_error(io::ErrorKind::TimedOut.into()), PacketPlaneQuicError::Io(ref error)
        if error.kind() == io::ErrorKind::TimedOut)
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn stale_route_after_tls_is_rejected_before_binding() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let server = PacketPlaneQuicRuntime::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut client = PacketPlaneQuicRuntime::bind("0.0.0.0:0".parse().unwrap()).unwrap();
        client.follow_linux_routes("absent-pv".into());
        let connector = client.connector();
        let acceptor = server.connector();
        let (outgoing, incoming) = tokio::join!(
            connector.connect(server.local_addr(), server.server_certificate()),
            acceptor.accept(),
        );
        let outgoing = outgoing.unwrap();
        let incoming = incoming.unwrap();
        assert!(outgoing.connection.route_is_current());
        connector.egress.as_ref().unwrap().retire_observer_for_test();
        let error = bind_quic_connection(outgoing, PacketPlaneQuicBinding::from_bytes([7; 32])).await.unwrap_err();
        assert!(matches!(error, PacketPlaneQuicError::Io(ref error)
            if error.kind() == io::ErrorKind::Interrupted && error.to_string() == "QUIC egress changed before binding"));
        assert!(incoming.connection.accept_uni().await.is_err(), "stale selection cannot transmit a binding stream");
    }).await.expect("bounded real TLS and stale-before-binding rejection");
}
