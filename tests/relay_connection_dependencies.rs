//! Native relay ownership, including raw stream handoff over loopback TCP.
use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures::{AsyncReadExt, AsyncWriteExt, FutureExt, StreamExt, future::poll_fn};
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
        ConnectionHandler, ConnectionHandlerEvent, ConnectionId, DialError, NetworkBehaviour,
        NotifyHandler, StreamUpgradeError, SwarmEvent, ToSwarm,
        behaviour::{
            ConnectionClosed, ConnectionEstablished, DialFailure, FromSwarm, toggle::Toggle,
        },
        dial_opts::{DialOpts, PeerCondition},
        handler::{ConnectionEvent, DialUpgradeError},
    },
    tcp, yamux,
};

const DEADLINE: Duration = Duration::from_secs(15);
type ClientHandler = <relay::client::Behaviour as NetworkBehaviour>::ConnectionHandler;

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

fn listen(transport: &mut relay::client::Transport, peer: PeerId) {
    transport
        .listen_on(
            ListenerId::next(),
            endpoint()
                .get_remote_address()
                .clone()
                .with(Protocol::P2p(peer))
                .with(Protocol::P2pCircuit),
        )
        .unwrap();
    assert!(Pin::new(transport).poll(&mut context()).is_pending());
}

fn dial(
    transport: &mut relay::client::Transport,
    peer: PeerId,
) -> <relay::client::Transport as Transport>::Dial {
    transport
        .dial(
            endpoint()
                .get_remote_address()
                .clone()
                .with(Protocol::P2p(peer))
                .with(Protocol::P2pCircuit)
                .with(Protocol::P2p(PeerId::random())),
            TransportDialOpts {
                role: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            },
        )
        .unwrap()
}

#[test]
fn undispatched_commands_pin_only_the_exact_selected_owner() {
    for reservation in [true, false] {
        let (mut transport, mut client) = relay::client::new(PeerId::random());
        let peer = PeerId::random();
        let first = ConnectionId::new_unchecked(100);
        let selected = ConnectionId::new_unchecked(101);
        let _first = establish(&mut client, peer, first);
        let _selected = establish(&mut client, peer, selected);
        assert!(client.prefer_relay_connection(peer, selected));
        assert!(!client.has_connection_dependencies(peer, selected));
        let mut pending_dial = None;
        if reservation {
            listen(&mut transport, peer);
        } else {
            let mut future = dial(&mut transport, peer);
            assert!(future.poll_unpin(&mut context()).is_pending());
            pending_dial = Some(future);
        }
        let Poll::Ready(action) = client.poll(&mut context()) else {
            panic!("missing command")
        };
        assert!(
            matches!(&action, ToSwarm::NotifyHandler { peer_id, handler: NotifyHandler::One(id), .. }
            if *peer_id == peer && *id == selected)
        );
        assert!(client.has_connection_dependencies(peer, selected));
        assert!(!client.has_connection_dependencies(PeerId::random(), selected));
        assert!(!client.has_connection_dependencies(peer, first));
        assert!(!client.has_connection_dependencies(peer, ConnectionId::new_unchecked(102)));
        assert_eq!(client.confirmed_reservation_connections(peer).count(), 0);
        assert!(client.prefer_relay_connection(peer, first));
        assert!(client.has_connection_dependencies(peer, selected));
        // A command dropped before dispatch must not leave a sticky dependency.
        drop(action);
        assert!(!client.has_connection_dependencies(peer, selected));
        drop(pending_dial);
    }
}

#[test]
fn multiple_undispatched_circuits_release_only_after_the_last_command() {
    let (mut transport, mut client) = relay::client::new(PeerId::random());
    let peer = PeerId::random();
    let id = ConnectionId::new_unchecked(150);
    let _handler = establish(&mut client, peer, id);
    let mut first_dial = dial(&mut transport, peer);
    let mut second_dial = dial(&mut transport, peer);
    assert!(first_dial.poll_unpin(&mut context()).is_pending());
    assert!(second_dial.poll_unpin(&mut context()).is_pending());
    let Poll::Ready(first) = client.poll(&mut context()) else {
        panic!("missing first command")
    };
    let Poll::Ready(second) = client.poll(&mut context()) else {
        panic!("missing second command")
    };
    assert!(client.has_connection_dependencies(peer, id));
    drop(first);
    assert!(client.has_connection_dependencies(peer, id));
    drop(second);
    assert!(!client.has_connection_dependencies(peer, id));
}

#[test]
fn pending_physical_dials_are_owned_through_failure_or_handler_handoff() {
    for (reservation, fail) in [(true, true), (false, true), (true, false), (false, false)] {
        let (mut transport, mut client) = relay::client::new(PeerId::random());
        let peer = PeerId::random();
        let mut pending_dial = None;
        if reservation {
            listen(&mut transport, peer);
        } else {
            let mut future = dial(&mut transport, peer);
            assert!(future.poll_unpin(&mut context()).is_pending());
            pending_dial = Some(future);
        }
        let Poll::Ready(ToSwarm::Dial { opts }) = client.poll(&mut context()) else {
            panic!("missing dial")
        };
        let id = opts.connection_id();
        assert!(client.has_connection_dependencies(peer, id));
        assert!(!client.has_connection_dependencies(PeerId::random(), id));
        if fail {
            client.on_swarm_event(FromSwarm::DialFailure(DialFailure {
                peer_id: Some(peer),
                connection_id: id,
                error: &DialError::NoAddresses,
            }));
        } else {
            let mut handler = establish(&mut client, peer, id);
            assert!(client.has_connection_dependencies(peer, id));
            let Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest { protocol }) =
                handler.poll(&mut context())
            else {
                panic!("pending command was not handed to handler")
            };
            // Negotiation ownership outlives the handler's pending codec future.
            drop(handler);
            assert!(client.has_connection_dependencies(peer, id));
            drop(protocol);
        }
        assert!(!client.has_connection_dependencies(peer, id));
        drop(pending_dial);
    }
}

#[test]
fn inner_relayed_connections_are_not_physical_owners() {
    let (_transport, mut client) = relay::client::new(PeerId::random());
    let peer = PeerId::random();
    let id = ConnectionId::new_unchecked(300);
    let address = endpoint()
        .get_remote_address()
        .clone()
        .with(Protocol::P2pCircuit);
    let handler = client
        .handle_established_outbound_connection(
            id,
            peer,
            &address,
            Endpoint::Dialer,
            PortUse::Reuse,
        )
        .unwrap();
    let _inbound = handler.listen_protocol();
    assert!(!client.has_connection_dependencies(peer, id));
}

#[test]
fn native_negotiation_and_failed_commands_release_leases() {
    for reservation in [true, false] {
        let (mut transport, mut client) = relay::client::new(PeerId::random());
        let peer = PeerId::random();
        let id = ConnectionId::new_unchecked(200);
        let mut handler = establish(&mut client, peer, id);
        let inbound = handler.listen_protocol();
        assert!(client.has_connection_dependencies(peer, id));
        drop(inbound);
        assert!(!client.has_connection_dependencies(peer, id));
        let mut pending_dial = None;
        if reservation {
            listen(&mut transport, peer);
        } else {
            let mut future = dial(&mut transport, peer);
            assert!(future.poll_unpin(&mut context()).is_pending());
            pending_dial = Some(future);
        }
        let Poll::Ready(ToSwarm::NotifyHandler { event, .. }) = client.poll(&mut context()) else {
            panic!("missing command")
        };
        handler.on_behaviour_event(event);
        let Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest { protocol }) =
            handler.poll(&mut context())
        else {
            panic!("missing substream")
        };
        assert!(client.has_connection_dependencies(peer, id));
        let (_, info) = protocol.into_upgrade();
        handler.on_connection_event(ConnectionEvent::DialUpgradeError(DialUpgradeError {
            info,
            error: StreamUpgradeError::NegotiationFailed,
        }));
        assert!(handler.poll(&mut context()).is_pending());
        assert!(!client.has_connection_dependencies(peer, id));
        // A closed owner is unknown even if negotiation still retains a lease.
        let inbound = handler.listen_protocol();
        assert!(client.has_connection_dependencies(peer, id));
        client.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id: peer,
            connection_id: id,
            endpoint: &endpoint(),
            cause: None,
            remaining_established: 0,
        }));
        assert!(!client.has_connection_dependencies(peer, id));
        drop(inbound);
        drop(pending_dial);
    }
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    relay: relay::client::Behaviour,
    server: Toggle<relay::Behaviour>,
}

struct Host {
    swarm: Swarm<Behaviour>,
    // Kept separate deliberately: tests retain the actual raw Connection output.
    transport: relay::client::Transport,
}

fn host(server: bool) -> Host {
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
                .then(|| {
                    relay::Behaviour::new(
                        key.public().to_peer_id(),
                        relay::Config {
                            reservation_duration: Duration::from_secs(4),
                            ..relay::Config::default()
                        },
                    )
                })
                .into(),
        })
        .unwrap()
        .with_swarm_config(|config| config.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    Host { swarm, transport }
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
                    SwarmEvent::ConnectionEstablished {connection_id, endpoint, ..} if connection_id == id => {
                        assert!(!endpoint.is_relayed());
                        return id;
                    }
                    SwarmEvent::OutgoingConnectionError {error, ..} => panic!("direct dial: {error}"),
                    _ => {}
                }
            }
        }
    }).await.expect("direct TCP deadline")
}

fn required(host: &Host, peer: PeerId, id: ConnectionId) -> bool {
    host.swarm
        .behaviour()
        .relay
        .has_connection_dependencies(peer, id)
}

#[tokio::test]
async fn real_tcp_raw_connections_retain_both_physical_owners_until_drop() {
    let mut server = host(true);
    server
        .swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let address = tokio::time::timeout(DEADLINE, async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = server.swarm.select_next_some().await
            {
                server.swarm.add_external_address(address.clone());
                return address.with(Protocol::P2p(*server.swarm.local_peer_id()));
            }
        }
    })
    .await
    .unwrap();
    let relay_peer = *server.swarm.local_peer_id();
    let mut receiver = host(false);
    let mut sender = host(false);
    let receiver_owner = connect(&mut receiver, &mut server, address.clone()).await;
    let receiver_sibling = connect(&mut receiver, &mut server, address.clone()).await;
    let sender_owner = connect(&mut sender, &mut server, address.clone()).await;
    let sender_sibling = connect(&mut sender, &mut server, address.clone()).await;
    assert!(!required(&receiver, relay_peer, receiver_owner));
    assert!(!required(&sender, relay_peer, sender_owner));
    let listener = ListenerId::next();
    receiver
        .transport
        .listen_on(listener, address.clone().with(Protocol::P2pCircuit))
        .unwrap();
    tokio::time::timeout(DEADLINE, async {
        let mut address_announced = false;
        let mut reservation_confirmed = false;
        while !address_announced || !reservation_confirmed {
            tokio::select! {
                _ = server.swarm.select_next_some() => {},
                event = receiver.swarm.select_next_some() => {
                    if matches!(event, SwarmEvent::Behaviour(BehaviourEvent::Relay(
                        relay::client::Event::ReservationReqAccepted { relay_peer_id, .. }
                    )) if relay_peer_id == relay_peer) {
                        reservation_confirmed = true;
                    }
                },
                event = poll_fn(|cx| Pin::new(&mut receiver.transport).poll(cx)) => {
                    if let TransportEvent::NewAddress { listener_id, .. } = event {
                        assert_eq!(listener_id, listener);
                        address_announced = true;
                    }
                }
            }
        }
    })
    .await
    .expect("raw reservation deadline");
    assert!(required(&receiver, relay_peer, receiver_owner));
    assert!(!required(&receiver, relay_peer, receiver_sibling));
    assert_eq!(
        receiver
            .swarm
            .behaviour()
            .relay
            .confirmed_reservation_connections(relay_peer)
            .collect::<Vec<_>>(),
        vec![receiver_owner]
    );

    let mut outbound = sender
        .transport
        .dial(
            address
                .with(Protocol::P2pCircuit)
                .with(Protocol::P2p(*receiver.swarm.local_peer_id())),
            TransportDialOpts {
                role: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            },
        )
        .unwrap();
    let mut incoming = tokio::time::timeout(DEADLINE, async {
        loop {
            tokio::select! {
                _ = server.swarm.select_next_some() => {},
                _ = receiver.swarm.select_next_some() => {},
                _ = sender.swarm.select_next_some() => {},
                result = &mut outbound => panic!("circuit completed before STOP acceptance: {}", result.is_ok()),
                event = poll_fn(|cx| Pin::new(&mut receiver.transport).poll(cx)) => {
                    if let TransportEvent::Incoming {upgrade, ..} = event { break upgrade.await.unwrap(); }
                }
            }
        }
    }).await.expect("raw inbound handoff deadline");
    assert!(required(&receiver, relay_peer, receiver_owner));
    assert!(required(&sender, relay_peer, sender_owner));
    assert!(!required(&sender, relay_peer, sender_sibling));
    // Preference changes do not move a stream's owner.
    assert!(
        sender
            .swarm
            .behaviour_mut()
            .relay
            .prefer_relay_connection(relay_peer, sender_sibling)
    );
    assert!(required(&sender, relay_peer, sender_owner));
    assert!(!required(&sender, relay_peer, sender_sibling));

    let mut outgoing = tokio::time::timeout(DEADLINE, async {
        let accept = incoming.flush();
        tokio::pin!(accept);
        let mut accepted = false;
        loop {
            tokio::select! {
                _ = server.swarm.select_next_some() => {},
                _ = receiver.swarm.select_next_some() => {},
                _ = sender.swarm.select_next_some() => {},
                result = &mut accept, if !accepted => { result.unwrap(); accepted = true; },
                result = &mut outbound => { break result.unwrap(); }
            }
        }
    })
    .await
    .expect("STOP acceptance deadline");
    assert!(
        sender
            .swarm
            .behaviour()
            .relay
            .confirmed_reservation_connections(relay_peer)
            .next()
            .is_none()
    );
    assert!(receiver.transport.remove_listener(listener));
    // Let reservation renewal discover the removed listener while retaining both streams.
    // The reservation-address index is intentionally not a source of live ownership.
    tokio::time::timeout(DEADLINE, async {
        let settled = tokio::time::sleep(Duration::from_secs(6));
        tokio::pin!(settled);
        loop {
            tokio::select! {
                _ = server.swarm.select_next_some() => {},
                _ = receiver.swarm.select_next_some() => {},
                _ = sender.swarm.select_next_some() => {},
                _ = poll_fn(|cx| Pin::new(&mut receiver.transport).poll(cx)) => {},
                () = &mut settled => break,
            }
        }
    })
    .await
    .expect("reservation cleanup deadline");
    assert!(required(&receiver, relay_peer, receiver_owner));
    assert!(required(&sender, relay_peer, sender_owner));
    let mut bytes = [0; 7];
    // Prove the operational raw stream still carries bytes after reservation teardown.
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
                _ = receiver.swarm.select_next_some() => {},
                _ = sender.swarm.select_next_some() => {},
                () = &mut transfer => break,
            }
        }
    })
    .await
    .expect("operational stream deadline");
    assert_eq!(bytes, *b"payload");
    tokio::time::timeout(DEADLINE, async {
        let close = outgoing.close();
        tokio::pin!(close);
        loop {
            tokio::select! {
                _ = server.swarm.select_next_some() => {},
                _ = receiver.swarm.select_next_some() => {},
                _ = sender.swarm.select_next_some() => {},
                result = &mut close => { result.unwrap(); break; }
            }
        }
    })
    .await
    .expect("raw stream close deadline");
    assert!(required(&sender, relay_peer, sender_owner));
    assert!(required(&receiver, relay_peer, receiver_owner));
    drop(outgoing);
    assert!(!required(&sender, relay_peer, sender_owner));
    assert!(!required(&sender, relay_peer, sender_sibling));
    drop(incoming);
    tokio::time::timeout(DEADLINE, async {
        while required(&receiver, relay_peer, receiver_owner) {
            tokio::select! {
                _ = server.swarm.select_next_some() => {},
                _ = receiver.swarm.select_next_some() => {},
                _ = sender.swarm.select_next_some() => {},
                _ = poll_fn(|cx| Pin::new(&mut receiver.transport).poll(cx)) => {},
            }
        }
    })
    .await
    .expect("last inbound lease release deadline");
    assert!(!required(&receiver, relay_peer, receiver_sibling));
}
