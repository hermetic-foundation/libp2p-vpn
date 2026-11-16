use super::*;
use libp2p::{
    Multiaddr, Transport,
    core::{
        Endpoint,
        transport::{DialOpts as TransportDialOpts, ListenerId, PortUse, TransportEvent},
    },
    multiaddr::Protocol,
};
use std::{future::poll_fn, net::SocketAddr, pin::Pin};

type NativeTransport = libp2p::quic::tokio::Transport;

#[tokio::test]
async fn ipv4_hole_punch_releases_only_preparation_slot_before_incoming_tls() {
    hole_punch("/ip4/127.0.0.1/udp/0/quic-v1").await;
}

#[tokio::test]
async fn ipv6_hole_punch_releases_only_preparation_slot_before_incoming_tls() {
    hole_punch("/ip6/::1/udp/0/quic-v1").await;
}

async fn hole_punch(listen: &str) {
    tokio::time::timeout(Duration::from_secs(15), async {
        let routes = Arc::new(ControlRoutes::new(4));
        let preparing = Arc::new(tokio::sync::Semaphore::new(1));
        let policy = Arc::new(Policy {
            routes: Arc::clone(&routes),
            preparing: Arc::clone(&preparing),
        });
        let server_key = Keypair::generate_ed25519();
        let client_key = Keypair::generate_ed25519();
        let server_id = server_key.public().to_peer_id();
        let client_id = client_key.public().to_peer_id();
        let mut server = NativeTransport::new(
            libp2p::quic::Config::new(&server_key).with_socket_policy(policy),
        );
        let mut client = NativeTransport::new(libp2p::quic::Config::new(&client_key));
        let server_address = listen_address(&mut server, listen).await;
        let client_address = listen_address(&mut client, listen).await;
        let server_socket = socket_address(&server_address);
        let client_socket = socket_address(&client_address);

        // Listener + New selects hole punching on the existing listener socket;
        // Listener + Reuse instead selects an ordinary outbound TLS dial.
        let punch = server.dial(
            client_address.with(Protocol::P2p(client_id)),
            TransportDialOpts { role: Endpoint::Listener, port_use: PortUse::New },
        ).unwrap();
        // JoinSet owns each dial and aborts unfinished tasks if an assertion or
        // the outer deadline unwinds this test. No borrowed pinned future survives.
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move { ("server", punch.await) });
        while preparing.available_permits() != 0 {
            tokio::select! {
                event = next_event(&mut server) => unexpected_event(event),
                event = next_event(&mut client) => unexpected_event(event),
                completed = tasks.join_next() => {
                    let (_, result) = completed.expect("pending hole punch").expect("hole-punch task");
                    panic!("hole punch ended before owning the preparation slot: {:?}", result.err());
                },
                _ = tokio::time::sleep(Duration::from_millis(1)) => {},
            }
        }
        assert!(routes.snapshot().is_empty(), "preparation is not authentication");
        let dial = client.dial(
            server_address.with(Protocol::P2p(server_id)),
            TransportDialOpts { role: Endpoint::Dialer, port_use: PortUse::Reuse },
        ).unwrap();
        tasks.spawn(async move { ("client", dial.await) });
        let mut connections = Vec::new();
        let mut completed_roles = std::collections::HashSet::new();
        while completed_roles.len() != 2 {
            tokio::select! {
                // Transport::poll forwards the matching incoming upgrade to the
                // punch future's oneshot; it must not emerge as an ordinary accept.
                event = next_event(&mut server) => unexpected_event(event),
                event = next_event(&mut client) => unexpected_event(event),
                completed = tasks.join_next() => {
                    let (role, result) = completed.expect("outstanding native TLS dial").expect("native TLS task");
                    let (peer, connection) = result.unwrap_or_else(|error| panic!("{role} native TLS failed: {error}"));
                    assert_eq!(peer, if role == "server" { client_id } else { server_id });
                    assert!(completed_roles.insert(role), "duplicate dial completion");
                    connections.push(connection);
                },
            }
        }
        assert_eq!(preparing.available_permits(), 1);
        let owners = routes.snapshot();
        assert_eq!(owners.len(), 1, "exactly the authenticated incoming owner remains");
        assert_eq!(owners[0].peer, client_id);
        assert_eq!(owners[0].lease.local_addr, server_socket);
        assert_eq!(owners[0].lease.context.destination, client_socket,
            "outgoing client must reuse the port matched by the hole-punch attempt");
        assert!(!owners[0].lease.preferred_dial, "owner belongs to the incoming TLS connection");
        assert!(!owners[0].is_adopted(), "raw transports have no Swarm CID admission");
        drop(owners);
        drop((connections, tasks, server, client));
        while !routes.snapshot().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(preparing.available_permits(), 1);
    }).await.expect("bounded one-slot native QUIC hole-punch handshake and cleanup");
}

async fn next_event(
    transport: &mut NativeTransport,
) -> TransportEvent<libp2p::quic::Connecting, libp2p::quic::Error> {
    poll_fn(|cx| Pin::new(&mut *transport).poll(cx)).await
}

async fn listen_address(transport: &mut NativeTransport, listen: &str) -> Multiaddr {
    transport
        .listen_on(ListenerId::next(), listen.parse().unwrap())
        .unwrap();
    loop {
        match next_event(transport).await {
            TransportEvent::NewAddress { listen_addr, .. } => return listen_addr,
            event => unexpected_event(event),
        }
    }
}

fn unexpected_event(event: TransportEvent<libp2p::quic::Connecting, libp2p::quic::Error>) {
    panic!("unexpected raw native QUIC transport event: {event:?}");
}

fn socket_address(address: &Multiaddr) -> SocketAddr {
    let mut parts = address.iter();
    let ip = match parts.next().unwrap() {
        Protocol::Ip4(ip) => ip.into(),
        Protocol::Ip6(ip) => ip.into(),
        other => panic!("expected loopback IP, got {other:?}"),
    };
    let Some(Protocol::Udp(port)) = parts.next() else {
        panic!("expected UDP listener port");
    };
    assert_ne!(port, 0);
    assert_eq!(parts.next(), Some(Protocol::QuicV1));
    assert!(parts.next().is_none());
    SocketAddr::new(ip, port)
}
