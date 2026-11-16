//! Native per-connection selection and dispatcher/handler ownership.

use std::{
    io,
    task::{Context, Poll},
    time::Duration,
};

use futures::{StreamExt as _, future::poll_fn, task::noop_waker};
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder,
    core::{ConnectedPoint, Endpoint, transport::PortUse},
    kad::{self, HandlerQueueUsage, store::MemoryStore},
    noise,
    swarm::{
        ConnectionHandler, ConnectionHandlerEvent, ConnectionId, FromSwarm, NetworkBehaviour,
        NotifyHandler, StreamUpgradeError, SwarmEvent, ToSwarm,
        behaviour::ConnectionEstablished,
        dial_opts::{DialOpts, PeerCondition},
        handler::{ConnectionEvent, DialUpgradeError},
    },
    tcp, yamux,
};

// Exercise the same private ownership source without the excluded crate's
// unrelated upstream test dependencies.
#[rustfmt::skip]
#[path = "../vendor/libp2p-kad-0.48.0/src/handler/connection.rs"]
mod connection;

type Kad = kad::Behaviour<MemoryStore>;
type Handler = <Kad as NetworkBehaviour>::ConnectionHandler;

fn native(local: PeerId) -> Kad {
    let mut config = kad::Config::new(kad::PROTOCOL_NAME);
    config.set_query_timeout(Duration::from_secs(5));
    let mut native = Kad::with_config(local, MemoryStore::new(local), config);
    native.set_mode(Some(kad::Mode::Server));
    native.set_background_jobs_paused(true);
    native
}

fn address() -> Multiaddr {
    "/ip4/127.0.0.1/tcp/4001".parse().unwrap()
}

fn attach(native: &mut Kad, peer: PeerId, id: ConnectionId, other: usize) -> Handler {
    let address = address();
    let handler = native
        .handle_established_outbound_connection(id, peer, &address, Endpoint::Dialer, PortUse::New)
        .unwrap();
    let endpoint = ConnectedPoint::Dialer {
        address,
        role_override: Endpoint::Dialer,
        port_use: PortUse::New,
    };
    native.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
        peer_id: peer,
        connection_id: id,
        endpoint: &endpoint,
        failed_addresses: &[],
        other_established: other,
    }));
    handler
}

#[test]
fn unknown_and_mismatched_selection_does_not_create_work() {
    let local = PeerId::random();
    let peer = PeerId::random();
    let mut native = native(local);
    let id = ConnectionId::new_unchecked(101);
    for _ in 0..1000 {
        assert!(!native.set_connection_outbound_enabled(&peer, id, false));
        assert!(!native.has_pending_requests_on_connection(&peer, id));
        assert_eq!(native.handler_resource_usage().handlers, 0);
    }
    let handler = attach(&mut native, peer, id, 0);
    assert!(!native.set_connection_outbound_enabled(&local, id, false));
    assert!(!native.has_pending_requests_on_connection(&local, id));
    assert!(native.set_connection_outbound_enabled(&peer, id, false));
    assert!(!native.has_pending_requests_on_connection(&peer, id));
    drop(handler);
    assert!(!native.set_connection_outbound_enabled(&peer, id, true));
}

#[tokio::test]
async fn defaults_and_reenable_select_only_future_rpcs_without_moving_owned_work() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let peer = PeerId::random();
        let mut native = native(PeerId::random());
        native.add_address(&peer, address());
        let first = ConnectionId::new_unchecked(101);
        let second = ConnectionId::new_unchecked(102);
        let _first = attach(&mut native, peer, first, 0);
        let _second = attach(&mut native, peer, second, 1);
        for (key, expected) in [(1, first), (2, second), (3, first)] {
            native.get_closest_peers(vec![key]);
            loop {
                match poll_fn(|cx| native.poll(cx)).await {
                    ToSwarm::NotifyHandler {
                        peer_id,
                        handler: NotifyHandler::One(owner),
                        ..
                    } => {
                        assert_eq!(peer_id, peer);
                        assert_eq!(owner, expected);
                        break;
                    }
                    ToSwarm::Dial { .. } => panic!("existing connections are available"),
                    _ => {}
                }
            }
            assert!(native.has_pending_requests_on_connection(&peer, expected));
            assert!(native.set_connection_outbound_enabled(&peer, first, key != 1));
            if key > 1 {
                assert!(native.has_pending_requests_on_connection(&peer, first));
                assert!(native.has_pending_requests_on_connection(&peer, second));
            }
        }
    })
    .await
    .expect("bounded future-selection compatibility");
}

#[tokio::test]
async fn exact_dispatch_codec_and_terminal_notification_remain_owned_when_disabled() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let peer = PeerId::random();
        let mut native = native(PeerId::random());
        native.add_address(&peer, address());
        let first = ConnectionId::new_unchecked(101);
        let second = ConnectionId::new_unchecked(102);
        let _first_handler = attach(&mut native, peer, first, 0);
        let mut handler = attach(&mut native, peer, second, 1);
        assert!(native.set_connection_outbound_enabled(&peer, first, false));
        let query = native.get_closest_peers(peer.to_bytes());
        let event = loop {
            match poll_fn(|cx| native.poll(cx)).await {
                ToSwarm::NotifyHandler {
                    peer_id,
                    handler: NotifyHandler::One(owner),
                    event,
                } => {
                    assert_eq!(peer_id, peer);
                    assert_eq!(owner, second);
                    break event;
                }
                ToSwarm::NotifyHandler {
                    handler: NotifyHandler::Any,
                    ..
                } => panic!("RPC must own an exact connection"),
                ToSwarm::Dial { .. } => panic!("an enabled existing connection is available"),
                _ => {}
            }
        };
        assert!(
            native.has_pending_requests_on_connection(&peer, second),
            "dispatch is not delivered yet"
        );
        assert!(!native.has_pending_requests_on_connection(&peer, first));
        assert!(native.set_connection_outbound_enabled(&peer, second, false));
        handler.on_behaviour_event(event);
        assert!(native.has_pending_requests_on_connection(&peer, second));
        loop {
            if let ConnectionHandlerEvent::OutboundSubstreamRequest { .. } =
                poll_fn(|cx| handler.poll(cx)).await
            {
                break;
            }
        }
        assert!(native.has_pending_requests_on_connection(&peer, second));
        handler.on_connection_event(ConnectionEvent::DialUpgradeError(DialUpgradeError {
            info: (),
            error: StreamUpgradeError::Io(io::ErrorKind::ConnectionReset.into()),
        }));
        let terminal = loop {
            if let ConnectionHandlerEvent::NotifyBehaviour(event) =
                poll_fn(|cx| handler.poll(cx)).await
            {
                break event;
            }
        };
        assert!(
            native.has_pending_requests_on_connection(&peer, second),
            "terminal event is not delivered yet"
        );
        native.on_connection_handler_event(peer, second, terminal);
        assert!(!native.has_pending_requests_on_connection(&peer, second));
        let result = loop {
            if let ToSwarm::GenerateEvent(kad::Event::OutboundQueryProgressed { id, .. }) =
                poll_fn(|cx| native.poll(cx)).await
            {
                break id;
            }
        };
        assert_eq!(result, query);
    })
    .await
    .expect("bounded native ownership lifecycle");
}

#[tokio::test]
async fn all_disabled_holds_unassigned_work_without_dial_then_enable_dispatches_it() {
    tokio::time::timeout(Duration::from_secs(5), async {
    let peer = PeerId::random();
    let mut native = native(PeerId::random());
    native.add_address(&peer, address());
    let id = ConnectionId::new_unchecked(101);
    let _handler = attach(&mut native, peer, id, 0);
    assert!(native.set_connection_outbound_enabled(&peer, id, false));
    native.get_closest_peers(peer.to_bytes());
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    for _ in 0..32 {
        match native.poll(&mut cx) {
            Poll::Pending
            | Poll::Ready(ToSwarm::GenerateEvent(_))
            | Poll::Ready(ToSwarm::NewExternalAddrOfPeer { .. }) => {}
            other => {
                panic!("disabled connections must neither receive nor trigger a dial: {other:?}")
            }
        }
    }
    assert!(
        !native.has_pending_requests_on_connection(&peer, id),
        "unassigned work is not connection-owned"
    );
    assert!(native.set_connection_outbound_enabled(&peer, id, true));
    let event = poll_fn(|cx| native.poll(cx)).await;
    assert!(
        matches!(event, ToSwarm::NotifyHandler { peer_id, handler: NotifyHandler::One(owner), .. } if peer_id == peer && owner == id)
    );
    assert!(native.has_pending_requests_on_connection(&peer, id));
    }).await.expect("bounded disabled-connection queue");
}

#[tokio::test]
async fn newly_established_handler_preloading_is_also_owned() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let peer = PeerId::random();
        let mut native = native(PeerId::random());
        native.add_address(&peer, address());
        native.get_closest_peers(peer.to_bytes());
        loop {
            if let ToSwarm::Dial { .. } = poll_fn(|cx| native.poll(cx)).await {
                break;
            }
        }
        let id = ConnectionId::new_unchecked(101);
        let handler = attach(&mut native, peer, id, 0);
        assert!(native.has_pending_requests_on_connection(&peer, id));
        assert!(native.set_connection_outbound_enabled(&peer, id, false));
        assert!(native.has_pending_requests_on_connection(&peer, id));
        drop(handler);
        assert!(!native.set_connection_outbound_enabled(&peer, id, true));
        let waker = noop_waker();
        let _ = native.poll(&mut Context::from_waker(&waker));
        assert!(!native.has_pending_requests_on_connection(&peer, id));
    })
    .await
    .expect("bounded preloaded native handler");
}

fn host() -> Swarm<Kad> {
    SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|key| native(key.public().to_peer_id()))
        .unwrap()
        .with_swarm_config(|config| config.with_idle_connection_timeout(Duration::from_secs(30)))
        .build()
}

#[tokio::test]
async fn real_noise_tcp_queries_use_enabled_sibling_and_disabled_server_still_replies() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut client = host();
        let mut server = host();
        server.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
        let address = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = server.select_next_some().await { break address; }
        };
        let peer = *server.local_peer_id();
        let client_peer = *client.local_peer_id();
        let mut pairs = Vec::new();
        for _ in 0..2 {
            let dial = DialOpts::peer_id(peer).addresses(vec![address.clone()]).condition(PeerCondition::Always).allocate_new_port().build();
            let id = dial.connection_id();
            client.dial(dial).unwrap();
            let mut client_established = false;
            let mut server_id = None;
            while !client_established || server_id.is_none() {
                tokio::select! {
                    event = client.select_next_some() => match event {
                        SwarmEvent::ConnectionEstablished { connection_id, .. } => { assert_eq!(connection_id, id); client_established = true; },
                        SwarmEvent::OutgoingConnectionError { .. } | SwarmEvent::ConnectionClosed { .. } => panic!("client churn: {event:?}"),
                        _ => {}
                    },
                    event = server.select_next_some() => match event {
                        SwarmEvent::ConnectionEstablished { connection_id, .. } => server_id = Some(connection_id),
                        SwarmEvent::IncomingConnectionError { .. } | SwarmEvent::ConnectionClosed { .. } => panic!("server churn: {event:?}"),
                        _ => {}
                    }
                }
            }
            pairs.push((id, server_id.unwrap()));
        }
        client.behaviour_mut().add_address(&peer, address);
        assert!(client.behaviour_mut().set_connection_outbound_enabled(&peer, pairs[0].0, false));
        for (_, id) in &pairs {
            assert!(server.behaviour_mut().set_connection_outbound_enabled(&client_peer, *id, false));
        }
        let query = client.behaviour_mut().get_closest_peers(peer.to_bytes());
        let mut received = false;
        loop {
            tokio::select! {
                event = client.select_next_some() => match event {
                    SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed { id, result, .. }) if id == query => {
                        assert!(matches!(result, kad::QueryResult::GetClosestPeers(Ok(_))), "{result:?}");
                        break;
                    },
                    SwarmEvent::ConnectionClosed { .. } | SwarmEvent::OutgoingConnectionError { .. } => panic!("client churn: {event:?}"),
                    _ => {}
                },
                event = server.select_next_some() => match event {
                    SwarmEvent::Behaviour(kad::Event::InboundRequest { .. }) => {
                        received = true;
                        assert!(server.behaviour().has_pending_requests_on_connection(&client_peer, pairs[1].1));
                        assert!(!server.behaviour().has_pending_requests_on_connection(&client_peer, pairs[0].1));
                        assert!(client.behaviour_mut().set_connection_outbound_enabled(&peer, pairs[1].0, false));
                    },
                    SwarmEvent::ConnectionClosed { .. } => panic!("server churn: {event:?}"),
                    _ => {}
                }
            }
        }
        assert!(received, "reply must come from an inbound RPC, not cache-only completion");
        poll_fn(|cx| {
            for swarm in [&mut client, &mut server] {
                if let Poll::Ready(Some(event)) = swarm.poll_next_unpin(cx) {
                    assert!(!matches!(event, SwarmEvent::ConnectionClosed { .. }), "drain must not close a sibling");
                }
            }
            if !client.behaviour().has_pending_requests_on_connection(&peer, pairs[1].0)
                && !server.behaviour().has_pending_requests_on_connection(&client_peer, pairs[1].1) { Poll::Ready(()) }
            else { Poll::Pending }
        }).await;
    }).await.expect("bounded real Noise/TCP infrastructure RPC and drain");
}
