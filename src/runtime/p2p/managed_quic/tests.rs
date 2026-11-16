use super::*;
use futures::StreamExt;
use libp2p::{
    Swarm, SwarmBuilder,
    identity::Keypair,
    ping,
    swarm::{
        SwarmEvent,
        dial_opts::{DialOpts, PeerCondition},
    },
};
use std::{net::UdpSocket, time::Duration};

#[derive(Debug)]
struct PendingPolicy(Arc<std::sync::atomic::AtomicUsize>);

#[derive(Debug)]
struct RetireBeforeTls(Policy);

impl SocketPolicy for RetireBeforeTls {
    fn prepare(&self, context: SocketContext) -> BoxFuture<'static, io::Result<Selection>> {
        let prepared = self.0.prepare(context);
        let routes = Arc::clone(&self.0.routes);
        async move {
            let selection = prepared.await?;
            routes.egress.retire_observer_for_test();
            Ok(selection)
        }
        .boxed()
    }
}

#[tokio::test]
async fn stale_native_selection_sends_no_initial_and_cannot_be_adopted() {
    use libp2p::{
        Transport,
        core::{
            Endpoint,
            transport::{DialOpts as TransportDialOpts, PortUse},
        },
    };
    let routes = Arc::new(ControlRoutes::new(4));
    let policy = Arc::new(RetireBeforeTls(Policy::new(Arc::clone(&routes))));
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver.set_nonblocking(true).unwrap();
    let port = receiver.local_addr().unwrap().port();
    let mut transport = libp2p::quic::tokio::Transport::new(
        libp2p::quic::Config::new(&Keypair::generate_ed25519()).with_socket_policy(policy),
    );
    let result = transport
        .dial(
            format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
                .parse()
                .unwrap(),
            TransportDialOpts {
                role: Endpoint::Dialer,
                port_use: PortUse::New,
            },
        )
        .unwrap()
        .await;
    assert!(
        matches!(result, Err(libp2p::quic::Error::Io(error)) if error.kind() == io::ErrorKind::Interrupted)
    );
    assert_eq!(
        receiver.recv_from(&mut [0_u8; 2048]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(routes.snapshot().is_empty());

    let policy = Policy::new(Arc::clone(&routes));
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    let context = SocketContext {
        local: socket.local_addr().unwrap(),
        remote: receiver.local_addr().unwrap(),
        role: Endpoint::Dialer,
        mark: 0,
    };
    let mut selection = policy.prepare(context).await.unwrap();
    selection.owner.authenticated(PeerId::random()).unwrap();
    routes.egress.retire_observer_for_test();
    assert!(selection.owner.admitted(44).is_err());
    assert!(!routes.snapshot().iter().any(|route| route.is_adopted()));
    drop(selection);
    assert!(routes.snapshot().is_empty());
}

impl SocketPolicy for PendingPolicy {
    fn prepare(&self, _: SocketContext) -> BoxFuture<'static, io::Result<Selection>> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        futures::future::pending().boxed()
    }
}

#[tokio::test]
async fn cancelled_and_unpolled_native_accepts_do_not_refuse_before_selection() {
    use libp2p::{
        Transport,
        core::{
            Endpoint,
            transport::{DialOpts as TransportDialOpts, ListenerId, PortUse, TransportEvent},
        },
    };
    use std::{
        pin::Pin,
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Waker},
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        for polled in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let mut server = libp2p::quic::tokio::Transport::new(
                libp2p::quic::Config::new(&Keypair::generate_ed25519())
                    .with_socket_policy(Arc::new(PendingPolicy(Arc::clone(&calls)))),
            );
            server
                .listen_on(
                    ListenerId::next(),
                    "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
                )
                .unwrap();
            let address = loop {
                if let TransportEvent::NewAddress { listen_addr, .. } =
                    futures::future::poll_fn(|cx| Pin::new(&mut server).poll(cx)).await
                {
                    break listen_addr;
                }
            };
            let mut config = libp2p::quic::Config::new(&Keypair::generate_ed25519());
            config.handshake_timeout = Duration::from_millis(400);
            let mut client = libp2p::quic::tokio::Transport::new(config);
            let dial = client
                .dial(
                    address,
                    TransportDialOpts {
                        role: Endpoint::Dialer,
                        port_use: PortUse::New,
                    },
                )
                .unwrap();
            let task = tokio::spawn(dial);
            let mut upgrade = loop {
                if let TransportEvent::Incoming { upgrade, .. } =
                    futures::future::poll_fn(|cx| Pin::new(&mut server).poll(cx)).await
                {
                    break upgrade;
                }
            };
            if polled {
                assert!(
                    std::future::Future::poll(
                        Pin::new(&mut upgrade),
                        &mut Context::from_waker(Waker::noop())
                    )
                    .is_pending()
                );
            }
            drop(upgrade);
            assert_eq!(calls.load(Ordering::Relaxed), usize::from(polled));
            assert!(
                matches!(
                    task.await.unwrap(),
                    Err(libp2p::quic::Error::HandshakeTimedOut)
                ),
                "discarded selection must not emit a refusal to the client"
            );
        }
    })
    .await
    .expect("bounded native incoming cancellation check");
}

fn node() -> (Swarm<ping::Behaviour>, Arc<ControlRoutes>) {
    let routes = Arc::new(ControlRoutes::new(16));
    let policy = Arc::new(Policy::new(Arc::clone(&routes)));
    let swarm = SwarmBuilder::with_existing_identity(Keypair::generate_ed25519())
        .with_tokio()
        .with_other_transport(move |key: &Keypair| {
            libp2p::quic::tokio::Transport::new(
                libp2p::quic::Config::new(key).with_socket_policy(policy),
            )
        })
        .unwrap()
        .with_behaviour(|_| {
            ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_millis(50)))
        })
        .unwrap()
        .build();
    (swarm, routes)
}

#[tokio::test]
async fn shared_native_quic_tuple_has_independent_authenticated_swarm_owners() {
    shared_tuple("/ip4/127.0.0.1/udp/0/quic-v1", true).await;
}

#[tokio::test]
async fn wildcard_native_quic_preserves_shared_ipv4_listener() {
    shared_tuple("/ip4/0.0.0.0/udp/0/quic-v1", false).await;
}

#[tokio::test]
async fn fixed_ipv6_native_quic_preserves_shared_listener() {
    shared_tuple("/ip6/::1/udp/0/quic-v1", true).await;
}

#[tokio::test]
async fn wildcard_ipv6_native_quic_preserves_shared_listener() {
    shared_tuple("/ip6/::/udp/0/quic-v1", false).await;
}

async fn shared_tuple(listen: &str, fixed: bool) {
    tokio::time::timeout(Duration::from_secs(12), async {
        let (mut a, routes_a) = node();
        let (mut b, routes_b) = node();
        a.listen_on(listen.parse().unwrap()).unwrap();
        b.listen_on(listen.parse().unwrap()).unwrap();
        let mut ready = [None, None];
        while ready.iter().any(Option::is_none) {
            tokio::select! {
                event = a.select_next_some() => if let SwarmEvent::NewListenAddr {address, ..} = event { if loopback(&address) { ready[0] = Some(address); } },
                event = b.select_next_some() => if let SwarmEvent::NewListenAddr {address, ..} = event { if loopback(&address) { ready[1] = Some(address); } },
            }
        }
        let peer_a = *a.local_peer_id();
        let peer_b = *b.local_peer_id();
        let mut ids = Vec::new();
        for _ in 0..2 {
            let options = DialOpts::peer_id(peer_b).condition(PeerCondition::Always).addresses(vec![ready[1].clone().unwrap()]).build();
            ids.push(options.connection_id());
            a.dial(options).unwrap();
            while routes_a.snapshot().len() < ids.len() || routes_b.snapshot().len() < ids.len()
                || !routes_a.snapshot().iter().all(|route| route.is_adopted())
                || !routes_b.snapshot().iter().all(|route| route.is_adopted()) {
                tokio::select! {
                    event = a.select_next_some() => if let SwarmEvent::OutgoingConnectionError {error, ..} = event { panic!("native QUIC dial failed: {error}"); },
                    _ = b.select_next_some() => {},
                }
            }
        }
        assert_ne!(ids[0], ids[1]);
        let owners = ids.iter().map(|id| routes_a.connection(peer_b, *id).unwrap()).collect::<Vec<_>>();
        assert_eq!(owners[0].lease.local_addr, owners[1].lease.local_addr, "shared endpoint source/port must be retained");
        assert_ne!(owners[0].id, owners[1].id);
        for owner in &owners {
            assert!(owner.lease.preferred_dial);
            assert_eq!(owner.lease.source_fixed, fixed);
            assert_eq!(owner.lease.context.protocol, crate::runtime::physical_network::linux::SocketProtocol::Udp);
            assert!(owner.lease.is_current());
            assert!(routes_a.connection(peer_a, owner.connection_id.unwrap()).is_none());
        }
        for incoming in routes_b.snapshot() {
            assert_eq!(incoming.peer, peer_a);
            assert!(!incoming.lease.preferred_dial);
            assert!(incoming.is_adopted());
        }
        assert!(a.close_connection(ids[0]));
        while routes_a.connection(peer_b, ids[0]).is_some() || routes_b.snapshot().len() != 1 {
            tokio::select! { _ = a.select_next_some() => {}, _ = b.select_next_some() => {} }
        }
        assert!(!owners[0].is_live());
        assert!(routes_a.connection(peer_b, ids[1]).is_some());
        loop {
            tokio::select! {
                event = a.select_next_some() => if let SwarmEvent::Behaviour(ping::Event {connection, result: Ok(_), ..}) = event {
                    if connection == ids[1] { break; }
                },
                _ = b.select_next_some() => {},
            }
        }
        drop((a, b));
        while !routes_a.snapshot().is_empty() || !routes_b.snapshot().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("bounded shared native QUIC ownership test");
}

fn loopback(address: &libp2p::Multiaddr) -> bool {
    address.iter().any(|protocol| match protocol {
        libp2p::multiaddr::Protocol::Ip4(ip) => ip.is_loopback(),
        libp2p::multiaddr::Protocol::Ip6(ip) => ip.is_loopback(),
        _ => false,
    })
}

#[tokio::test]
async fn native_policy_bounds_pre_authentication_and_releases_exact_registrations() {
    let routes = Arc::new(ControlRoutes::new(16));
    let policy = Policy::new(Arc::clone(&routes));
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    let context = SocketContext {
        local: socket.local_addr().unwrap(),
        remote: "127.0.0.1:4001".parse().unwrap(),
        role: libp2p::core::Endpoint::Dialer,
        mark: 0,
    };
    let mut selections = Vec::new();
    for _ in 0..16 {
        selections.push(policy.prepare(context).await.unwrap());
    }
    assert_eq!(
        policy.prepare(context).await.unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(routes.snapshot().is_empty());
    let mut selection = selections.pop().unwrap();
    assert!(selection.owner.admitted(10).is_err());
    let peer = PeerId::random();
    selection.owner.authenticated(peer).unwrap();
    assert_eq!(routes.snapshot().len(), 1);
    assert!(!routes.snapshot()[0].is_adopted());
    assert!(selection.owner.authenticated(peer).is_err());
    selection.owner.admitted(10).unwrap();
    assert!(
        routes
            .connection(peer, ConnectionId::new_unchecked(10))
            .is_some()
    );
    assert!(selection.owner.admitted(11).is_err());
    let replacement = policy.prepare(context).await.unwrap();
    drop((selection, selections, replacement));
    assert!(routes.snapshot().is_empty());
    assert_eq!(policy.preparing.available_permits(), 16);
}
