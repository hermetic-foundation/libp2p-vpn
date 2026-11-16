//! Native listener binding and make-before-break reservation draining over TCP.
use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures::{AsyncReadExt, AsyncWriteExt, StreamExt, future::poll_fn};
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, Transport,
    core::{
        ConnectedPoint, Endpoint,
        transport::{DialOpts as TransportDialOpts, ListenerId, PortUse, TransportEvent},
    },
    identity::Keypair,
    multiaddr::Protocol,
    noise, relay,
    swarm::{
        ConnectionId, DialError, NetworkBehaviour, NotifyHandler, SwarmEvent, ToSwarm,
        behaviour::{
            ConnectionClosed, ConnectionEstablished, DialFailure, FromSwarm, toggle::Toggle,
        },
        dial_opts::{DialOpts, PeerCondition},
    },
    tcp, yamux,
};

const DEADLINE: Duration = Duration::from_secs(15);
type ClientHandler = <relay::client::Behaviour as NetworkBehaviour>::ConnectionHandler;
type PendingCircuit = (
    relay::client::Connection,
    <relay::client::Transport as Transport>::Dial,
);

fn context() -> Context<'static> {
    Context::from_waker(futures::task::noop_waker_ref())
}

fn endpoint() -> ConnectedPoint {
    ConnectedPoint::Dialer {
        address: "/ip4/127.0.0.1/tcp/12345".parse().unwrap(),
        role_override: Endpoint::Dialer,
        port_use: PortUse::Reuse,
    }
}

fn establish(
    client: &mut relay::client::Behaviour,
    peer: PeerId,
    id: ConnectionId,
) -> ClientHandler {
    let endpoint = endpoint();
    let handler = client
        .handle_established_outbound_connection(
            id,
            peer,
            endpoint.get_remote_address(),
            Endpoint::Dialer,
            PortUse::Reuse,
        )
        .unwrap();
    client.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
        peer_id: peer,
        connection_id: id,
        endpoint: &endpoint,
        failed_addresses: &[],
        other_established: 0,
    }));
    handler
}

fn close(client: &mut relay::client::Behaviour, peer: PeerId, id: ConnectionId) {
    client.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
        peer_id: peer,
        connection_id: id,
        endpoint: &endpoint(),
        cause: None,
        remaining_established: 1,
    }));
}

fn listen(transport: &mut relay::client::Transport, peer: PeerId) -> ListenerId {
    let listener = ListenerId::next();
    transport
        .listen_on(
            listener,
            endpoint()
                .get_remote_address()
                .clone()
                .with(Protocol::P2p(peer))
                .with(Protocol::P2pCircuit),
        )
        .unwrap();
    listener
}

#[test]
fn exact_pin_survives_preference_changes_and_rejects_invalid_bindings() {
    let (mut transport, mut client) = relay::client::new(PeerId::random());
    let peer = PeerId::random();
    let other = PeerId::random();
    let first = ConnectionId::new_unchecked(100);
    let selected = ConnectionId::new_unchecked(101);
    let wrong = ConnectionId::new_unchecked(102);
    let unknown = ConnectionId::new_unchecked(103);
    let _first = establish(&mut client, peer, first);
    let _selected = establish(&mut client, peer, selected);
    let _wrong = establish(&mut client, other, wrong);
    let listener = listen(&mut transport, peer);
    assert!(!client.pin_reservation_listener(peer, ListenerId::next(), selected));
    assert!(!client.pin_reservation_listener(other, listener, wrong));
    assert!(!client.pin_reservation_listener(peer, listener, wrong));
    assert!(!client.pin_reservation_listener(peer, listener, unknown));
    assert!(client.pin_reservation_listener(peer, listener, selected));
    assert_eq!(client.reservation_listener_connection(peer, listener), None);
    assert!(Pin::new(&mut transport).poll(&mut context()).is_pending());
    assert!(client.prefer_relay_connection(peer, first));
    let Poll::Ready(action) = client.poll(&mut context()) else {
        panic!("missing reservation")
    };
    assert!(
        matches!(&action, ToSwarm::NotifyHandler { peer_id, handler: NotifyHandler::One(id), .. }
        if *peer_id == peer && *id == selected)
    );
    assert_eq!(
        client.reservation_listener_connection(peer, listener),
        Some(selected)
    );
    assert_eq!(
        client.reservation_listener_connection(other, listener),
        None
    );
    assert!(client.pin_reservation_listener(peer, listener, selected));
    assert!(!client.pin_reservation_listener(peer, listener, first));
    assert!(client.has_connection_dependencies(peer, selected));
    assert!(!client.has_connection_dependencies(peer, first));
    drop(action);
    assert!(
        matches!(Pin::new(&mut transport).poll(&mut context()), Poll::Ready(TransportEvent::ListenerClosed { listener_id, .. }) if listener_id == listener)
    );
    assert_eq!(client.reservation_listener_connection(peer, listener), None);
    assert!(!client.pin_reservation_listener(peer, listener, selected));
    assert!(client.poll(&mut context()).is_pending());
}

#[test]
fn removed_queued_listener_and_vanished_pinned_owner_never_fall_back() {
    for removed in [true, false] {
        let (mut transport, mut client) = relay::client::new(PeerId::random());
        let peer = PeerId::random();
        let first = ConnectionId::new_unchecked(200);
        let selected = ConnectionId::new_unchecked(201);
        let _first = establish(&mut client, peer, first);
        let _selected = establish(&mut client, peer, selected);
        let listener = listen(&mut transport, peer);
        assert!(client.pin_reservation_listener(peer, listener, selected));
        // Queue the request before cancelling it, as can happen between swarm polls.
        assert!(Pin::new(&mut transport).poll(&mut context()).is_pending());
        if removed {
            assert!(transport.remove_listener(listener));
        } else {
            close(&mut client, peer, selected);
        }
        assert!(client.poll(&mut context()).is_pending());
        assert_eq!(client.reservation_listener_connection(peer, listener), None);
        assert!(!client.has_connection_dependencies(peer, first));
        assert!(!client.has_connection_dependencies(peer, selected));
        assert!(
            matches!(Pin::new(&mut transport).poll(&mut context()), Poll::Ready(TransportEvent::ListenerClosed { listener_id, reason })
            if listener_id == listener && (removed || reason.is_err()))
        );
        assert!(!client.pin_reservation_listener(peer, listener, first));
    }
}

#[test]
fn unpinned_listeners_report_the_actual_pending_dial_and_cleanup() {
    let (mut transport, mut client) = relay::client::new(PeerId::random());
    let peer = PeerId::random();
    let listener = listen(&mut transport, peer);
    assert!(Pin::new(&mut transport).poll(&mut context()).is_pending());
    let Poll::Ready(ToSwarm::Dial { opts }) = client.poll(&mut context()) else {
        panic!("missing physical dial")
    };
    let id = opts.connection_id();
    assert_eq!(
        client.reservation_listener_connection(peer, listener),
        Some(id)
    );
    assert_eq!(
        client.reservation_listener_connection(PeerId::random(), listener),
        None
    );
    assert!(!client.pin_reservation_listener(peer, listener, id));
    client.on_swarm_event(FromSwarm::DialFailure(DialFailure {
        peer_id: Some(peer),
        connection_id: id,
        error: &DialError::NoAddresses,
    }));
    assert_eq!(client.reservation_listener_connection(peer, listener), None);
    assert!(!client.has_connection_dependencies(peer, id));
}

#[test]
fn invalid_or_unconfirmed_drain_pairs_do_not_issue_io() {
    let (mut transport, mut client) = relay::client::new(PeerId::random());
    let peer = PeerId::random();
    let other = PeerId::random();
    let old = ConnectionId::new_unchecked(300);
    let replacement = ConnectionId::new_unchecked(301);
    let wrong = ConnectionId::new_unchecked(302);
    let unknown = ConnectionId::new_unchecked(303);
    let _old = establish(&mut client, peer, old);
    let _replacement = establish(&mut client, peer, replacement);
    let _wrong = establish(&mut client, other, wrong);
    for (a, b) in [
        (old, old),
        (old, replacement),
        (old, wrong),
        (old, unknown),
        (unknown, old),
    ] {
        assert!(!client.begin_reservation_drain(peer, a, b));
    }
    let listener = listen(&mut transport, peer);
    assert!(client.pin_reservation_listener(peer, listener, old));
    assert!(Pin::new(&mut transport).poll(&mut context()).is_pending());
    let Poll::Ready(command) = client.poll(&mut context()) else {
        panic!("missing reserve")
    };
    for _ in 0..1000 {
        assert!(!client.begin_reservation_drain(peer, old, replacement));
        assert!(!client.begin_reservation_drain(other, old, wrong));
        assert!(!client.is_reservation_draining(peer, unknown));
    }
    assert!(client.has_connection_dependencies(peer, old));
    assert!(!client.is_reservation_draining(peer, old));
    assert!(!client.has_connection_dependencies(peer, replacement));
    assert!(client.poll(&mut context()).is_pending());
    drop(command);
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    relay: relay::client::Behaviour,
    server: Toggle<relay::Behaviour>,
}

struct Host {
    swarm: Swarm<Behaviour>,
    transport: relay::client::Transport,
}

fn host(server: Option<relay::Config>, idle: Duration) -> Host {
    let key = Keypair::generate_ed25519();
    let (transport, relay) = relay::client::new(key.public().to_peer_id());
    let swarm = SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(move |key: &Keypair| Behaviour {
            relay,
            server: server
                .map(|config| relay::Behaviour::new(key.public().to_peer_id(), config))
                .into(),
        })
        .unwrap()
        .with_swarm_config(|config| config.with_idle_connection_timeout(idle))
        .build();
    Host { swarm, transport }
}

fn client() -> Host {
    host(None, Duration::from_secs(60))
}

async fn relay_server(max_reservations: usize, duration: Duration) -> (Host, Multiaddr) {
    let mut server = host(
        Some(relay::Config {
            max_reservations,
            reservation_duration: duration,
            reservation_rate_limiters: vec![],
            ..relay::Config::default()
        }),
        Duration::from_secs(60),
    );
    server
        .swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let address = tokio::time::timeout(DEADLINE, async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = server.swarm.select_next_some().await
            {
                server.swarm.add_external_address(address.clone());
                break address.with(Protocol::P2p(*server.swarm.local_peer_id()));
            }
        }
    })
    .await
    .unwrap();
    (server, address)
}

async fn connect(client: &mut Host, server: &mut Host, address: Multiaddr) -> ConnectionId {
    let opts = DialOpts::peer_id(*server.swarm.local_peer_id())
        .condition(PeerCondition::Always)
        .addresses(vec![address])
        .build();
    let id = opts.connection_id();
    client.swarm.dial(opts).unwrap();
    tokio::time::timeout(DEADLINE, async {
        loop {
            tokio::select! {
                _ = server.swarm.select_next_some() => {},
                event = client.swarm.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { connection_id, endpoint, .. } if connection_id == id => {
                        assert!(!endpoint.is_relayed());
                        break id;
                    }
                    SwarmEvent::OutgoingConnectionError { error, .. } => panic!("direct dial: {error}"),
                    _ => {},
                }
            }
        }
    }).await.expect("direct TCP deadline")
}

fn no_extra_dial(event: &SwarmEvent<BehaviourEvent>) {
    assert!(
        !matches!(
            event,
            SwarmEvent::Dialing { .. } | SwarmEvent::ConnectionEstablished { .. }
        ),
        "unexpected physical connection: {event:?}"
    );
}

fn required(host: &Host, peer: PeerId, id: ConnectionId) -> bool {
    host.swarm
        .behaviour()
        .relay
        .has_connection_dependencies(peer, id)
}

async fn reserve(
    client: &mut Host,
    server: &mut Host,
    address: &Multiaddr,
    owner: ConnectionId,
) -> (ListenerId, Multiaddr) {
    let peer = *server.swarm.local_peer_id();
    let listener = ListenerId::next();
    client
        .transport
        .listen_on(listener, address.clone().with(Protocol::P2pCircuit))
        .unwrap();
    assert!(
        client
            .swarm
            .behaviour_mut()
            .relay
            .pin_reservation_listener(peer, listener, owner)
    );
    let mut advertised = None;
    let mut accepted = false;
    tokio::time::timeout(DEADLINE, async {
        loop {
            if accepted && client.swarm.behaviour().relay.confirmed_reservation_connections(peer).any(|id| id == owner) {
                if let Some(address) = advertised.take() {
                    assert_eq!(client.swarm.behaviour().relay.reservation_listener_connection(peer, listener), Some(owner));
                    return (listener, address);
                }
            }
            tokio::select! {
                _ = server.swarm.select_next_some() => {},
                event = client.swarm.select_next_some() => {
                    no_extra_dial(&event);
                    if matches!(event, SwarmEvent::Behaviour(BehaviourEvent::Relay(relay::client::Event::ReservationReqAccepted { renewal: false, .. }))) {
                        accepted = true;
                    }
                },
                event = poll_fn(|cx| Pin::new(&mut client.transport).poll(cx)) => match event {
                    TransportEvent::NewAddress { listener_id, listen_addr } if listener_id == listener => advertised = Some(listen_addr),
                    TransportEvent::ListenerClosed { listener_id, reason } if listener_id == listener => panic!("reservation failed: {reason:?}"),
                    _ => {},
                }
            }
        }
    }).await.expect("exact reservation confirmation deadline")
}

async fn start_raw_circuit(
    receiver: &mut Host,
    sender: &mut Host,
    server: &mut Host,
    address: &Multiaddr,
) -> PendingCircuit {
    let mut outbound = sender
        .transport
        .dial(
            address
                .clone()
                .with(Protocol::P2pCircuit)
                .with(Protocol::P2p(*receiver.swarm.local_peer_id())),
            TransportDialOpts {
                role: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            },
        )
        .unwrap();
    let incoming = tokio::time::timeout(DEADLINE, async {
        loop {
            tokio::select! {
                _ = server.swarm.select_next_some() => {},
                event = receiver.swarm.select_next_some() => no_extra_dial(&event),
                event = sender.swarm.select_next_some() => no_extra_dial(&event),
                result = &mut outbound => panic!("circuit completed before STOP acceptance: {}", result.is_ok()),
                event = poll_fn(|cx| Pin::new(&mut receiver.transport).poll(cx)) => {
                    if let TransportEvent::Incoming { upgrade, .. } = event { break upgrade.await.unwrap(); }
                }
            }
        }
    }).await.expect("raw inbound circuit deadline");
    (incoming, outbound)
}

async fn accept_raw_circuit(
    receiver: &mut Host,
    sender: &mut Host,
    server: &mut Host,
    (mut incoming, mut outbound): PendingCircuit,
) -> (relay::client::Connection, relay::client::Connection) {
    let outgoing = tokio::time::timeout(DEADLINE, async {
        let accept = incoming.flush();
        tokio::pin!(accept);
        let mut accepted = false;
        loop {
            tokio::select! {
                _ = server.swarm.select_next_some() => {},
                event = receiver.swarm.select_next_some() => no_extra_dial(&event),
                event = sender.swarm.select_next_some() => no_extra_dial(&event),
                result = &mut accept, if !accepted => { result.unwrap(); accepted = true; },
                result = &mut outbound => break result.unwrap(),
            }
        }
    })
    .await
    .expect("STOP acceptance deadline");
    (incoming, outgoing)
}

#[tokio::test]
async fn held_tcp_circuit_survives_drain_and_old_owner_can_reserve_normally_again() {
    let (mut server, address) = relay_server(128, Duration::from_secs(4)).await;
    let peer = *server.swarm.local_peer_id();
    let mut receiver = client();
    let mut sender = client();
    let old = connect(&mut receiver, &mut server, address.clone()).await;
    let replacement = connect(&mut receiver, &mut server, address.clone()).await;
    let sender_owner = connect(&mut sender, &mut server, address.clone()).await;
    let (old_listener, _) = reserve(&mut receiver, &mut server, &address, old).await;
    assert!(
        !receiver
            .swarm
            .behaviour_mut()
            .relay
            .begin_reservation_drain(peer, old, replacement)
    );
    // Establish before reserving the sibling: the server uses a HashSet of owners.
    let pending = start_raw_circuit(&mut receiver, &mut sender, &mut server, &address).await;
    let (mut incoming, mut outgoing) =
        accept_raw_circuit(&mut receiver, &mut sender, &mut server, pending).await;
    // Hold a second STOP handshake unaccepted on that same deterministic owner.
    let pending_stop = start_raw_circuit(&mut receiver, &mut sender, &mut server, &address).await;
    let (new_listener, _) = reserve(&mut receiver, &mut server, &address, replacement).await;
    assert_eq!(
        receiver
            .swarm
            .behaviour()
            .relay
            .confirmed_reservation_connections(peer)
            .count(),
        2
    );
    for _ in 0..1000 {
        assert!(
            receiver
                .swarm
                .behaviour_mut()
                .relay
                .begin_reservation_drain(peer, old, replacement)
        );
    }
    assert_eq!(
        receiver
            .swarm
            .behaviour()
            .relay
            .confirmed_reservation_connections(peer)
            .collect::<Vec<_>>(),
        vec![replacement]
    );
    assert!(required(&receiver, peer, old));
    let (late_incoming, late_outgoing) =
        accept_raw_circuit(&mut receiver, &mut sender, &mut server, pending_stop).await;
    drop(late_incoming);
    drop(late_outgoing);
    let mut new_renewals = 0;
    let grace = tokio::time::Instant::now() + Duration::from_secs(1);
    tokio::time::timeout(DEADLINE, async {
        let elapsed = tokio::time::sleep(Duration::from_secs(6));
        tokio::pin!(elapsed);
        loop {
            tokio::select! {
                _ = server.swarm.select_next_some() => {},
                event = receiver.swarm.select_next_some() => no_extra_dial(&event),
                event = sender.swarm.select_next_some() => no_extra_dial(&event),
                event = poll_fn(|cx| Pin::new(&mut receiver.transport).poll(cx)) => match event {
                    TransportEvent::NewAddress { listener_id, .. } if listener_id == old_listener => {
                        assert!(tokio::time::Instant::now() < grace, "old reservation kept renewing");
                    }
                    TransportEvent::NewAddress { listener_id, .. } if listener_id == new_listener => new_renewals += 1,
                    TransportEvent::ListenerClosed { listener_id, .. } => panic!("drain closed a live listener: {listener_id:?}"),
                    _ => {},
                },
                () = &mut elapsed => break,
            }
        }
    }).await.unwrap();
    assert!(new_renewals > 0);
    assert!(required(&receiver, peer, old));
    assert!(required(&sender, peer, sender_owner));
    let mut bytes = [0; 7];
    tokio::time::timeout(DEADLINE, async {
        let transfer = async {
            incoming.write_all(b"payload").await.unwrap();
            incoming.flush().await.unwrap();
            outgoing.read_exact(&mut bytes).await.unwrap();
        };
        tokio::pin!(transfer);
        loop {
            tokio::select! {
                _ = server.swarm.select_next_some() => {},
                event = receiver.swarm.select_next_some() => no_extra_dial(&event),
                event = sender.swarm.select_next_some() => no_extra_dial(&event),
                () = &mut transfer => break,
            }
        }
    })
    .await
    .expect("draining circuit payload deadline");
    assert_eq!(bytes, *b"payload");
    drop(incoming);
    drop(outgoing);
    tokio::time::timeout(DEADLINE, async {
        while required(&receiver, peer, old) {
            tokio::select! {
                _ = server.swarm.select_next_some() => {},
                event = receiver.swarm.select_next_some() => no_extra_dial(&event),
                event = sender.swarm.select_next_some() => no_extra_dial(&event),
                _ = poll_fn(|cx| Pin::new(&mut receiver.transport).poll(cx)) => {},
            }
        }
    })
    .await
    .expect("old circuit lease release deadline");
    assert!(
        receiver
            .swarm
            .behaviour()
            .relay
            .is_reservation_draining(peer, old)
    );
    assert_eq!(
        receiver
            .swarm
            .behaviour()
            .relay
            .reservation_listener_connection(peer, old_listener),
        Some(old)
    );
    let (fresh_listener, _) = reserve(&mut receiver, &mut server, &address, old).await;
    assert_ne!(fresh_listener, old_listener);
    assert!(
        !receiver
            .swarm
            .behaviour()
            .relay
            .is_reservation_draining(peer, old)
    );
    assert!(required(&receiver, peer, old));
    assert_eq!(
        receiver
            .swarm
            .behaviour()
            .relay
            .confirmed_reservation_connections(peer)
            .count(),
        2
    );
}

#[tokio::test]
async fn drained_tcp_owner_loses_keepalive_without_expiring_the_shared_replacement_address() {
    let (mut server, address) = relay_server(128, Duration::from_secs(4)).await;
    let peer = *server.swarm.local_peer_id();
    let mut receiver = host(None, Duration::from_secs(1));
    let old = connect(&mut receiver, &mut server, address.clone()).await;
    let replacement = connect(&mut receiver, &mut server, address.clone()).await;
    let (old_listener, old_address) = reserve(&mut receiver, &mut server, &address, old).await;
    let (new_listener, new_address) =
        reserve(&mut receiver, &mut server, &address, replacement).await;
    assert_eq!(old_address, new_address);
    assert!(
        receiver
            .swarm
            .behaviour_mut()
            .relay
            .begin_reservation_drain(peer, old, replacement)
    );
    let mut closed = false;
    tokio::time::timeout(DEADLINE, async {
        loop {
            tokio::select! {
                _ = server.swarm.select_next_some() => {},
                event = receiver.swarm.select_next_some() => {
                    no_extra_dial(&event);
                    match event {
                        SwarmEvent::ConnectionClosed { connection_id, .. } if connection_id == old => closed = true,
                        SwarmEvent::ConnectionClosed { connection_id, .. } if connection_id == replacement => panic!("replacement closed"),
                        SwarmEvent::ExternalAddrExpired { address } if address == new_address => panic!("old close expired shared address"),
                        _ => {},
                    }
                },
                event = poll_fn(|cx| Pin::new(&mut receiver.transport).poll(cx)) => match event {
                    TransportEvent::ListenerClosed { listener_id, .. } if listener_id == new_listener => panic!("replacement listener closed"),
                    TransportEvent::NewAddress { listener_id, .. } if listener_id == new_listener && closed => break,
                    _ => {},
                }
            }
        }
    }).await.expect("idle old close and replacement renewal deadline");
    assert!(closed, "draining reservation retained keepalive");
    assert!(
        receiver
            .swarm
            .external_addresses()
            .any(|addr| addr == &new_address)
    );
    assert!(!required(&receiver, peer, old));
    assert_eq!(
        receiver
            .swarm
            .behaviour()
            .relay
            .reservation_listener_connection(peer, old_listener),
        None
    );
    assert!(
        !receiver
            .swarm
            .behaviour()
            .relay
            .is_reservation_draining(peer, old)
    );
    assert_eq!(
        receiver
            .swarm
            .behaviour()
            .relay
            .reservation_listener_connection(peer, new_listener),
        Some(replacement)
    );
    assert_eq!(
        receiver
            .swarm
            .behaviour()
            .relay
            .confirmed_reservation_connections(peer)
            .collect::<Vec<_>>(),
        vec![replacement]
    );
}

#[tokio::test]
async fn rejected_tcp_replacement_leaves_old_reservation_and_listener_untouched() {
    let (mut server, address) = relay_server(1, Duration::from_secs(60)).await;
    let peer = *server.swarm.local_peer_id();
    let mut receiver = client();
    let old = connect(&mut receiver, &mut server, address.clone()).await;
    let replacement = connect(&mut receiver, &mut server, address.clone()).await;
    let (old_listener, old_address) = reserve(&mut receiver, &mut server, &address, old).await;
    let listener = ListenerId::next();
    receiver
        .transport
        .listen_on(listener, address.with(Protocol::P2pCircuit))
        .unwrap();
    assert!(
        receiver
            .swarm
            .behaviour_mut()
            .relay
            .pin_reservation_listener(peer, listener, replacement)
    );
    tokio::time::timeout(DEADLINE, async {
        loop {
            tokio::select! {
                _ = server.swarm.select_next_some() => {},
                event = receiver.swarm.select_next_some() => no_extra_dial(&event),
                event = poll_fn(|cx| Pin::new(&mut receiver.transport).poll(cx)) => match event {
                    TransportEvent::ListenerClosed { listener_id, reason } if listener_id == listener => {
                        assert!(reason.is_err());
                        break;
                    }
                    TransportEvent::ListenerClosed { listener_id, .. } if listener_id == old_listener => panic!("failed replacement closed old listener"),
                    _ => {},
                }
            }
        }
    }).await.expect("replacement denial deadline");
    assert!(
        !receiver
            .swarm
            .behaviour_mut()
            .relay
            .begin_reservation_drain(peer, old, replacement)
    );
    assert!(
        !receiver
            .swarm
            .behaviour()
            .relay
            .is_reservation_draining(peer, old)
    );
    assert!(required(&receiver, peer, old));
    assert!(!required(&receiver, peer, replacement));
    assert_eq!(
        receiver
            .swarm
            .behaviour()
            .relay
            .reservation_listener_connection(peer, old_listener),
        Some(old)
    );
    assert_eq!(
        receiver
            .swarm
            .behaviour()
            .relay
            .reservation_listener_connection(peer, listener),
        None
    );
    assert_eq!(
        receiver
            .swarm
            .behaviour()
            .relay
            .confirmed_reservation_connections(peer)
            .collect::<Vec<_>>(),
        vec![old]
    );
    // Aborting the failed/uncertain move reverses the drain direction: quiesce
    // its pending owner against the still-confirmed original reservation.
    assert!(
        receiver
            .swarm
            .behaviour_mut()
            .relay
            .begin_reservation_drain(peer, replacement, old)
    );
    assert!(required(&receiver, peer, replacement));
    assert!(
        !receiver
            .swarm
            .behaviour()
            .relay
            .is_reservation_draining(peer, old)
    );
    tokio::time::timeout(
        DEADLINE,
        poll_fn(|cx| {
            // Applying a drain emits no public event. Inspect ownership after polling
            // the swarm even when its event stream remains pending.
            if let Poll::Ready(Some(event)) = receiver.swarm.poll_next_unpin(cx) {
                no_extra_dial(&event);
                cx.waker().wake_by_ref();
            }
            if required(&receiver, peer, replacement) {
                // Connection handlers run on the executor and may release the lease
                // without waking the public event stream. Yield for that local work.
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        }),
    )
    .await
    .expect("failed replacement drain delivery deadline");
    assert!(receiver.swarm.close_connection(replacement));
    tokio::time::timeout(DEADLINE, async {
        loop {
            tokio::select! {
                _ = server.swarm.select_next_some() => {},
                event = receiver.swarm.select_next_some() => {
                    no_extra_dial(&event);
                    match event {
                        SwarmEvent::ConnectionClosed { connection_id, .. } if connection_id == replacement => break,
                        SwarmEvent::ConnectionClosed { connection_id, .. } if connection_id == old => panic!("failed replacement cleanup closed old owner"),
                        SwarmEvent::ExternalAddrExpired { address } if address == old_address => panic!("failed replacement cleanup expired old address"),
                        _ => {},
                    }
                },
                event = poll_fn(|cx| Pin::new(&mut receiver.transport).poll(cx)) => {
                    if let TransportEvent::ListenerClosed { listener_id, .. } = event {
                        assert_ne!(listener_id, old_listener, "failed replacement cleanup closed old listener");
                    }
                }
            }
        }
    })
    .await
    .expect("failed replacement physical cleanup deadline");
    assert!(required(&receiver, peer, old));
    assert!(
        receiver
            .swarm
            .external_addresses()
            .any(|address| address == &old_address)
    );
    assert!(
        !receiver
            .swarm
            .behaviour()
            .relay
            .is_reservation_draining(peer, replacement)
    );
    assert_eq!(
        receiver
            .swarm
            .behaviour()
            .relay
            .reservation_listener_connection(peer, old_listener),
        Some(old)
    );
    assert_eq!(
        receiver
            .swarm
            .behaviour()
            .relay
            .confirmed_reservation_connections(peer)
            .collect::<Vec<_>>(),
        vec![old]
    );
}
