use super::*;
use futures::StreamExt;
use libp2p::{Swarm, SwarmBuilder, ping, swarm::SwarmEvent};
use std::time::Duration;

fn stock(key: Keypair) -> Swarm<ping::Behaviour> {
    SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|_| ping::Behaviour::default())
        .unwrap()
        .build()
}

fn managed(key: Keypair) -> (Swarm<ping::Behaviour>, Arc<ControlRoutes>) {
    let routes = Arc::new(ControlRoutes::new(8));
    let transport = Transport::new(&key, Arc::clone(&routes)).unwrap();
    let swarm = SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_other_transport(|_| transport)
        .unwrap_or_else(|never| match never {})
        .with_behaviour(|_| ping::Behaviour::default())
        .unwrap()
        .build();
    (swarm, routes)
}

#[test]
fn address_parsing_matches_tcp_structure_and_peer_suffixes() {
    for (multiaddr, socket) in [
        ("/ip4/127.0.0.1/tcp/4001", "127.0.0.1:4001"),
        ("/ip6/::1/tcp/4001", "[::1]:4001"),
    ] {
        let address: Multiaddr = multiaddr.parse().unwrap();
        assert_eq!(socket_address(&address), Some(socket.parse().unwrap()));
        assert_eq!(
            socket_address(&address.with(Protocol::P2p(PeerId::random()))),
            Some(socket.parse().unwrap())
        );
    }
    for address in [
        "/ip4/127.0.0.1/udp/4001",
        "/ip4/127.0.0.1/tcp/4001/ws",
        "/ip4/127.0.0.1/tcp/4001/tcp/4002",
    ] {
        assert!(socket_address(&address.parse().unwrap()).is_none());
    }
}

#[tokio::test]
async fn stock_noise_yamux_interoperates_in_both_directions_and_families() {
    for listen in ["/ip4/127.0.0.1/tcp/0", "/ip6/::1/tcp/0"] {
        for managed_dials in [false, true] {
            let (mut owned, routes) = managed(Keypair::generate_ed25519());
            let mut legacy = stock(Keypair::generate_ed25519());
            let remote = *legacy.local_peer_id();
            tokio::time::timeout(Duration::from_secs(10), async {
                let (listener, dialer) = if managed_dials { (&mut legacy, &mut owned) } else { (&mut owned, &mut legacy) };
                listener.listen_on(listen.parse().unwrap()).unwrap();
                let address = loop {
                    if let SwarmEvent::NewListenAddr { address, .. } = listener.select_next_some().await { break address; }
                };
                dialer.dial(address).unwrap();
                let mut pings = [false; 2];
                while !pings.into_iter().all(|success| success) {
                    tokio::select! {
                        event = owned.select_next_some() => if let SwarmEvent::Behaviour(event) = event {
                            assert!(event.result.is_ok(), "managed ping failed: {event:?}");
                            pings[0] = true;
                        },
                        event = legacy.select_next_some() => if let SwarmEvent::Behaviour(event) = event {
                            assert!(event.result.is_ok(), "stock ping failed: {event:?}");
                            pings[1] = true;
                        },
                    }
                }
                let snapshot = routes.snapshot();
                assert_eq!(snapshot.len(), 1);
                assert_eq!(snapshot[0].peer, remote);
                assert_eq!(snapshot[0].lease.context.protocol, crate::runtime::physical_network::linux::SocketProtocol::Tcp);
                assert_eq!(snapshot[0].lease.preferred_dial, managed_dials);
                assert!(snapshot[0].lease.is_current());
                assert!(snapshot[0].is_live());
                assert!(snapshot[0].is_adopted());
            }).await.expect("bounded stock/managed interoperability");
            drop(owned);
            tokio::time::timeout(Duration::from_secs(2), async {
                while !routes.snapshot().is_empty() {
                    let _ =
                        tokio::time::timeout(Duration::from_millis(10), legacy.select_next_some())
                            .await;
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("dropping the swarm retires exact route ownership");
        }
    }
}

#[tokio::test]
async fn wrong_peer_identity_never_becomes_an_adopted_route() {
    let (mut owned, routes) = managed(Keypair::generate_ed25519());
    let mut legacy = stock(Keypair::generate_ed25519());
    legacy
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        let address = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = legacy.select_next_some().await {
                break address;
            }
        };
        let expected = PeerId::random();
        owned.dial(address.with(Protocol::P2p(expected))).unwrap();
        loop {
            tokio::select! {
                event = owned.select_next_some() => match event {
                    SwarmEvent::OutgoingConnectionError { error, .. } => {
                        assert!(matches!(error, libp2p::swarm::DialError::WrongPeerId { .. }), "unexpected dial failure: {error:?}");
                        break;
                    }
                    SwarmEvent::ConnectionEstablished { .. } => panic!("unexpected identity accepted"),
                    _ => {}
                },
                _ = legacy.select_next_some() => {},
            }
            assert!(!routes.snapshot().iter().any(|route| route.is_adopted()));
        }
        while !routes.snapshot().is_empty() {
            assert!(!routes.snapshot().iter().any(|route| route.is_adopted()));
            tokio::select! {
                _ = owned.select_next_some() => {},
                _ = legacy.select_next_some() => {},
                _ = tokio::time::sleep(Duration::from_millis(10)) => {},
            }
        }
    }).await.expect("identity rejection and route retirement are bounded");
}

#[tokio::test]
async fn cancelled_handshake_closes_the_socket_and_releases_the_connection_budget() {
    use libp2p::core::{Endpoint, Transport as _};
    use tokio::io::AsyncReadExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let routes = Arc::new(ControlRoutes::new(8));
    let mut transport = Transport::new(&Keypair::generate_ed25519(), Arc::clone(&routes)).unwrap();
    let address: Multiaddr = format!(
        "/ip4/127.0.0.1/tcp/{}",
        listener.local_addr().unwrap().port()
    )
    .parse()
    .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        // More attempts than the owner permits concurrently exposes leaked permits.
        for _ in 0..20 {
            let mut dial = transport
                .dial(
                    address.clone(),
                    DialOpts {
                        role: Endpoint::Dialer,
                        port_use: PortUse::New,
                    },
                )
                .unwrap();
            assert!(routes.snapshot().is_empty());
            assert!(
                tokio::time::timeout(Duration::from_millis(5), listener.accept())
                    .await
                    .is_err(),
                "unpolled dial sent traffic"
            );
            let (mut server, _) = tokio::select! {
                result = listener.accept() => result.unwrap(),
                result = &mut dial => panic!("incomplete handshake completed: {:?}", result.err()),
            };
            assert!(routes.snapshot().is_empty());
            drop(dial);
            let mut bytes = Vec::new();
            server.read_to_end(&mut bytes).await.unwrap();
            assert!(routes.snapshot().is_empty());
        }
    })
    .await
    .expect("cancelled setup releases sockets and permits");
}

#[tokio::test]
async fn silent_inbound_handshakes_cannot_starve_outbound_tcp() {
    let (mut owned, routes) = managed(Keypair::generate_ed25519());
    let mut legacy = stock(Keypair::generate_ed25519());
    tokio::time::timeout(Duration::from_secs(10), async {
        owned.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
        legacy.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
        let incoming = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = owned.select_next_some().await { break socket_address(&address).unwrap(); }
        };
        let target = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = legacy.select_next_some().await { break address; }
        };
        let mut silent = Vec::new();
        for _ in 0..MAX_ACCEPTING {
            silent.push(tokio::net::TcpStream::connect(incoming).await.unwrap());
            loop {
                if let SwarmEvent::IncomingConnection { .. } = owned.select_next_some().await { break; }
            }
        }
        // Poll the final accepted upgrade without providing a Noise response.
        let _ = tokio::time::timeout(Duration::from_millis(20), owned.select_next_some()).await;
        assert!(routes.snapshot().is_empty());
        owned.dial(target).unwrap();
        loop {
            tokio::select! {
                event = owned.select_next_some() => match event {
                    SwarmEvent::Behaviour(event) => { assert!(event.result.is_ok()); break; }
                    SwarmEvent::OutgoingConnectionError { error, .. } => panic!("outbound starved: {error:?}"),
                    _ => {}
                },
                _ = legacy.select_next_some() => {},
            }
        }
        assert_eq!(routes.snapshot().len(), 1);
        assert!(routes.snapshot()[0].is_adopted());
        drop(silent);
    }).await.expect("outbound traffic survives a full silent inbound handshake budget");
}
