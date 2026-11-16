//! Exact circuit ownership and directed dial cancellation, including authenticated TCP.
use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use futures::{FutureExt, StreamExt, future::BoxFuture};
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, Transport, allow_block_list,
    core::{
        ConnectedPoint, Endpoint,
        transport::{
            DialOpts as TransportDialOpts, ListenerId, PortUse, TransportError, TransportEvent,
        },
    },
    identity::Keypair,
    multiaddr::Protocol,
    noise, ping, relay,
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
type Handler = <relay::client::Behaviour as NetworkBehaviour>::ConnectionHandler;

fn cx() -> Context<'static> {
    Context::from_waker(futures::task::noop_waker_ref())
}
fn endpoint() -> ConnectedPoint {
    ConnectedPoint::Dialer {
        address: "/ip4/127.0.0.1/tcp/12345".parse().unwrap(),
        role_override: Endpoint::Dialer,
        port_use: PortUse::Reuse,
    }
}
fn establish(client: &mut relay::client::Behaviour, peer: PeerId, id: ConnectionId) -> Handler {
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
fn address(relay: PeerId, peer: PeerId) -> Multiaddr {
    endpoint()
        .get_remote_address()
        .clone()
        .with(Protocol::P2p(relay))
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(peer))
}
fn options() -> TransportDialOpts {
    TransportDialOpts {
        role: Endpoint::Dialer,
        port_use: PortUse::Reuse,
    }
}

#[test]
fn exact_pins_survive_preference_races_and_cancellation_keeps_codec_leases() {
    for stage in 0..4 {
        let (mut transport, mut client) = relay::client::new(PeerId::random());
        let relay = PeerId::random();
        let peer = PeerId::random();
        let old = ConnectionId::new_unchecked(100);
        let selected = ConnectionId::new_unchecked(101);
        let inner = ConnectionId::new_unchecked(102);
        let _old = establish(&mut client, relay, old);
        let mut selected_handler = establish(&mut client, relay, selected);
        assert!(
            client
                .pin_circuit_dial(peer, inner, PeerId::random(), selected)
                .is_none()
        );
        assert!(
            client
                .pin_circuit_dial(peer, inner, relay, ConnectionId::new_unchecked(999))
                .is_none()
        );
        assert!(client.prefer_relay_connection(relay, old));
        let mut dial = transport
            .dial_with_connection_id(address(relay, peer), options(), 102)
            .unwrap();
        assert!(
            client
                .pin_circuit_dial(PeerId::random(), inner, relay, selected)
                .is_none()
        );
        if stage == 0 {
            drop(dial);
            assert!(
                client
                    .pin_circuit_dial(peer, inner, relay, selected)
                    .is_none()
            );
            assert!(!client.has_connection_dependencies(relay, selected));
            assert!(client.poll(&mut cx()).is_pending());
            continue;
        }
        let pin = client
            .pin_circuit_dial(peer, inner, relay, selected)
            .unwrap();
        if stage == 1 {
            drop(pin);
            assert!(matches!(dial.poll_unpin(&mut cx()), Poll::Ready(Err(_))));
            drop(dial);
            assert!(client.poll(&mut cx()).is_pending());
            assert!(!client.has_connection_dependencies(relay, selected));
            continue;
        }
        assert!(dial.poll_unpin(&mut cx()).is_pending());
        if stage == 2 {
            drop(pin);
            assert!(client.poll(&mut cx()).is_pending());
            assert!(matches!(dial.poll_unpin(&mut cx()), Poll::Ready(Err(_))));
            drop(dial);
            assert!(!client.has_connection_dependencies(relay, selected));
            continue;
        }
        let Poll::Ready(ToSwarm::NotifyHandler {
            handler: NotifyHandler::One(id),
            event,
            ..
        }) = client.poll(&mut cx())
        else {
            panic!("missing directed command")
        };
        assert_eq!(id, selected);
        selected_handler.on_behaviour_event(event);
        drop(pin);
        assert!(matches!(dial.poll_unpin(&mut cx()), Poll::Ready(Err(_))));
        drop(dial);
        assert!(
            client.has_connection_dependencies(relay, selected),
            "cancelled codec must finish before becoming idle"
        );
        let Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest { protocol }) =
            selected_handler.poll(&mut cx())
        else {
            panic!("missing negotiation")
        };
        let (_, info) = protocol.into_upgrade();
        selected_handler.on_connection_event(ConnectionEvent::DialUpgradeError(DialUpgradeError {
            info,
            error: StreamUpgradeError::NegotiationFailed,
        }));
        assert!(selected_handler.poll(&mut cx()).is_pending());
        assert!(!client.has_connection_dependencies(relay, selected));
        assert!(!client.has_connection_dependencies(relay, old));
    }
}

#[test]
fn cancelled_records_are_reclaimed_and_vanished_outer_never_falls_back() {
    let (mut transport, mut client) = relay::client::new(PeerId::random());
    let relay = PeerId::random();
    let peer = PeerId::random();
    let outer = ConnectionId::new_unchecked(200);
    let fallback = ConnectionId::new_unchecked(201);
    let _outer = establish(&mut client, relay, outer);
    let _fallback = establish(&mut client, relay, fallback);
    for index in 0..256 {
        let dial = transport
            .dial_with_connection_id(address(relay, peer), options(), 1000 + index)
            .unwrap();
        let inner = ConnectionId::new_unchecked(1000 + index);
        let pin = client.pin_circuit_dial(peer, inner, relay, outer).unwrap();
        drop(pin);
        drop(dial);
        assert!(client.pin_circuit_dial(peer, inner, relay, outer).is_none());
        assert!(!client.has_connection_dependencies(relay, outer));
    }
    assert!(
        client
            .pin_circuit_dial(peer, ConnectionId::new_unchecked(2000), relay, outer)
            .is_none()
    );
    let mut dial = transport
        .dial_with_connection_id(address(relay, peer), options(), 2000)
        .unwrap();
    let pin = client
        .pin_circuit_dial(peer, ConnectionId::new_unchecked(2000), relay, outer)
        .unwrap();
    client.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
        peer_id: relay,
        connection_id: outer,
        endpoint: &endpoint(),
        cause: None,
        remaining_established: 1,
    }));
    assert!(matches!(dial.poll_unpin(&mut cx()), Poll::Ready(Err(_))));
    drop(pin);
    drop(dial);
    assert!(client.poll(&mut cx()).is_pending());
    assert!(!client.has_connection_dependencies(relay, fallback));
    let mut invalid = transport
        .dial_with_connection_id(address(relay, peer), options(), 2001)
        .unwrap();
    assert!(
        client
            .pin_circuit_dial(peer, ConnectionId::new_unchecked(2001), relay, outer)
            .is_none()
    );
    assert!(matches!(invalid.poll_unpin(&mut cx()), Poll::Ready(Err(_))));
    drop(invalid);
    assert!(client.poll(&mut cx()).is_pending());
    let next = transport
        .dial_with_connection_id(address(relay, peer), options(), 2002)
        .unwrap();
    assert!(
        client
            .pin_circuit_dial(peer, ConnectionId::new_unchecked(2002), relay, fallback)
            .is_some()
    );
    drop(next);
}

#[derive(Default)]
struct DropDialOnWake {
    dial: Mutex<Option<BoxFuture<'static, io::Result<relay::client::Connection>>>>,
    wakes: std::sync::atomic::AtomicUsize,
}

impl futures::task::ArcWake for DropDialOnWake {
    fn wake_by_ref(this: &Arc<Self>) {
        this.wakes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dial = this.dial.lock().unwrap().take();
        // A scheduler may synchronously discard the now-cancelled future. Its
        // native lifetime cleanup must not reenter a held registry mutex.
        drop(dial);
    }
}

#[test]
fn pin_cancellation_can_synchronously_drop_standalone_dial_futures() {
    for valid_selection in [false, true] {
        let (mut transport, mut client) = relay::client::new(PeerId::random());
        let relay = PeerId::random();
        let alternative = PeerId::random();
        let peer = PeerId::random();
        let outer = ConnectionId::new_unchecked(250);
        let inner = ConnectionId::new_unchecked(251);
        let _handler = establish(&mut client, relay, outer);
        let chosen = transport
            .dial_with_connection_id(address(relay, peer), options(), 251)
            .unwrap();
        let cancelled = if valid_selection {
            transport
                .dial_with_connection_id(address(alternative, peer), options(), 251)
                .unwrap()
        } else {
            chosen
        };
        let wake = Arc::new(DropDialOnWake::default());
        let waker = futures::task::waker(wake.clone());
        let mut cancelled = cancelled
            .map(|result| result.map_err(io::Error::other))
            .boxed();
        assert!(
            cancelled
                .poll_unpin(&mut Context::from_waker(&waker))
                .is_pending()
        );
        *wake.dial.lock().unwrap() = Some(cancelled);
        let pin = client.pin_circuit_dial(
            peer,
            inner,
            relay,
            if valid_selection {
                outer
            } else {
                ConnectionId::new_unchecked(999)
            },
        );
        assert_eq!(pin.is_some(), valid_selection);
        assert!(wake.wakes.load(std::sync::atomic::Ordering::Relaxed) > 0);
        assert!(wake.dial.lock().unwrap().is_none());
        assert!(client.poll(&mut cx()).is_pending());
        drop(pin);
        assert!(!client.has_connection_dependencies(relay, outer));
    }
}

// Like DNS, this legacy wrapper creates its inner dial only when its future polls.
struct Deferred(Arc<Mutex<relay::client::Transport>>);
impl Transport for Deferred {
    type Output = relay::client::Connection;
    type Error = io::Error;
    type Dial = BoxFuture<'static, io::Result<Self::Output>>;
    type ListenerUpgrade = Self::Dial;
    fn listen_on(
        &mut self,
        _: ListenerId,
        address: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        Err(TransportError::MultiaddrNotSupported(address))
    }
    fn remove_listener(&mut self, _: ListenerId) -> bool {
        false
    }
    fn dial(
        &mut self,
        address: Multiaddr,
        options: TransportDialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        let inner = self.0.clone();
        Ok(async move {
            let future = inner
                .lock()
                .unwrap()
                .dial(address, options)
                .map_err(io::Error::other)?;
            future.await.map_err(io::Error::other)
        }
        .boxed())
    }
    fn poll(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Poll::Pending
    }
}

#[test]
fn boxed_deferred_legacy_wrapper_retains_exact_identity_and_restores_scope() {
    let (transport, mut client) = relay::client::new(PeerId::random());
    let relay = PeerId::random();
    let peer = PeerId::random();
    let old = ConnectionId::new_unchecked(300);
    let selected = ConnectionId::new_unchecked(301);
    let _old = establish(&mut client, relay, old);
    let _selected = establish(&mut client, relay, selected);
    let inner = ConnectionId::new_unchecked(302);
    client
        .handle_pending_outbound_connection(
            inner,
            Some(peer),
            &[address(relay, peer)],
            Endpoint::Dialer,
        )
        .unwrap();
    let mut transport = Deferred(Arc::new(Mutex::new(transport)))
        .map(|connection, _| connection)
        .boxed();
    let mut dial = transport
        .dial_with_connection_id(address(relay, peer), options(), 302)
        .unwrap();
    let pin = client
        .pin_circuit_dial(peer, inner, relay, selected)
        .unwrap();
    assert_eq!(libp2p::core::transport::dial_connection_id(), None);
    assert!(dial.poll_unpin(&mut cx()).is_pending());
    assert_eq!(libp2p::core::transport::dial_connection_id(), None);
    let Poll::Ready(command) = client.poll(&mut cx()) else {
        panic!("missing deferred request")
    };
    assert!(
        matches!(&command, ToSwarm::NotifyHandler { handler: NotifyHandler::One(id), .. } if *id == selected)
    );
    drop(pin);
    drop(command);
    drop(dial);
    client.on_swarm_event(FromSwarm::DialFailure(DialFailure {
        peer_id: Some(peer),
        connection_id: inner,
        error: &DialError::NoAddresses,
    }));
    assert!(!client.has_connection_dependencies(relay, selected));
}

#[test]
fn admitted_attempt_cancellation_is_reclaimed_and_invalid_matching_pin_fails_closed() {
    let (transport, mut client) = relay::client::new(PeerId::random());
    let relay = PeerId::random();
    let peer = PeerId::random();
    let outer = ConnectionId::new_unchecked(400);
    let _handler = establish(&mut client, relay, outer);
    let mut transport = Deferred(Arc::new(Mutex::new(transport))).boxed();
    for index in 0..256 {
        let id = 4000 + index;
        let inner = ConnectionId::new_unchecked(id);
        client
            .handle_pending_outbound_connection(
                inner,
                Some(peer),
                &[address(relay, peer)],
                Endpoint::Dialer,
            )
            .unwrap();
        let mut dial = transport
            .dial_with_connection_id(address(relay, peer), options(), id)
            .unwrap();
        assert!(
            client
                .pin_circuit_dial(PeerId::random(), inner, relay, outer)
                .is_none()
        );
        if index % 2 == 0 {
            let pin = client.pin_circuit_dial(peer, inner, relay, outer).unwrap();
            drop(pin);
        } else {
            // This is the correct pending peer/ID but an invalid relay owner.
            assert!(
                client
                    .pin_circuit_dial(peer, inner, PeerId::random(), outer)
                    .is_none()
            );
        }
        assert!(matches!(dial.poll_unpin(&mut cx()), Poll::Ready(Err(_))));
        assert!(
            client.poll(&mut cx()).is_pending(),
            "cancelled request must not select a default or dial"
        );
        drop(dial);
        client.on_swarm_event(FromSwarm::DialFailure(DialFailure {
            peer_id: Some(peer),
            connection_id: inner,
            error: &DialError::NoAddresses,
        }));
        assert!(client.pin_circuit_dial(peer, inner, relay, outer).is_none());
        assert!(!client.has_connection_dependencies(relay, outer));
    }
}

#[test]
fn late_extended_relay_branches_obey_the_cid_selection_and_cancellation() {
    for mode in 0..3 {
        let (transport, mut client) = relay::client::new(PeerId::random());
        let offered_relay = PeerId::random();
        let extended_relay = PeerId::random();
        let peer = PeerId::random();
        let outer = ConnectionId::new_unchecked(600);
        let inner = ConnectionId::new_unchecked(601);
        let _handler = establish(&mut client, offered_relay, outer);
        client
            .handle_pending_outbound_connection(
                inner,
                Some(peer),
                &[address(offered_relay, peer)],
                Endpoint::Dialer,
            )
            .unwrap();
        let mut transport = Deferred(Arc::new(Mutex::new(transport))).boxed();
        let mut offered = Some(
            transport
                .dial_with_connection_id(address(offered_relay, peer), options(), 601)
                .unwrap(),
        );
        // The extra address is supplied after relay admission, as with behaviour
        // address extension. Its raw relay dial is still deferred until polling.
        let mut extended = transport
            .dial_with_connection_id(address(extended_relay, peer), options(), 601)
            .unwrap();
        let mut pin = None;
        if mode == 2 {
            assert!(
                client
                    .pin_circuit_dial(peer, inner, extended_relay, outer)
                    .is_none()
            );
        } else {
            pin = Some(
                client
                    .pin_circuit_dial(peer, inner, offered_relay, outer)
                    .unwrap(),
            );
            if mode == 1 {
                drop(pin.take());
                // Cancellation must survive loss of the originally offered
                // future while the real CID still owns another deferred branch.
                drop(offered.take());
            }
        }
        assert!(matches!(
            extended.poll_unpin(&mut cx()),
            Poll::Ready(Err(_))
        ));
        assert!(
            client.poll(&mut cx()).is_pending(),
            "late alternative dispatched or dialed a physical relay"
        );
        if mode == 0 {
            assert!(offered.as_mut().unwrap().poll_unpin(&mut cx()).is_pending());
            let Poll::Ready(command) = client.poll(&mut cx()) else {
                panic!("selected branch was lost")
            };
            assert!(
                matches!(&command, ToSwarm::NotifyHandler { peer_id, handler: NotifyHandler::One(id), .. }
                if *peer_id == offered_relay && *id == outer)
            );
            drop(command);
        } else if let Some(offered) = &mut offered {
            assert!(matches!(offered.poll_unpin(&mut cx()), Poll::Ready(Err(_))));
            assert!(client.poll(&mut cx()).is_pending());
        }
        drop(pin);
        drop(offered);
        drop(extended);
        client.on_swarm_event(FromSwarm::DialFailure(DialFailure {
            peer_id: Some(peer),
            connection_id: inner,
            error: &DialError::NoAddresses,
        }));
        assert!(!client.has_connection_dependencies(offered_relay, outer));
        assert!(
            client
                .pin_circuit_dial(peer, inner, offered_relay, outer)
                .is_none()
        );
    }
}

#[test]
fn mixed_offered_relays_pin_the_selected_relay_and_cancel_the_other_branches() {
    let (transport, mut client) = relay::client::new(PeerId::random());
    let first_relay = PeerId::random();
    let chosen_relay = PeerId::random();
    let peer = PeerId::random();
    let first_outer = ConnectionId::new_unchecked(700);
    let chosen_outer = ConnectionId::new_unchecked(701);
    let inner = ConnectionId::new_unchecked(702);
    let _first = establish(&mut client, first_relay, first_outer);
    let _chosen = establish(&mut client, chosen_relay, chosen_outer);
    client
        .handle_pending_outbound_connection(
            inner,
            Some(peer),
            &[address(first_relay, peer), address(chosen_relay, peer)],
            Endpoint::Dialer,
        )
        .unwrap();
    let mut transport = Deferred(Arc::new(Mutex::new(transport))).boxed();
    let mut first = transport
        .dial_with_connection_id(address(first_relay, peer), options(), 702)
        .unwrap();
    let mut chosen = transport
        .dial_with_connection_id(address(chosen_relay, peer), options(), 702)
        .unwrap();
    let pin = client
        .pin_circuit_dial(peer, inner, chosen_relay, chosen_outer)
        .expect("a different offered relay must not invalidate a valid choice");
    assert!(matches!(first.poll_unpin(&mut cx()), Poll::Ready(Err(_))));
    assert!(client.poll(&mut cx()).is_pending());
    assert!(chosen.poll_unpin(&mut cx()).is_pending());
    let Poll::Ready(command) = client.poll(&mut cx()) else {
        panic!("missing chosen relay command")
    };
    assert!(
        matches!(&command, ToSwarm::NotifyHandler { peer_id, handler: NotifyHandler::One(id), .. }
        if *peer_id == chosen_relay && *id == chosen_outer)
    );
    assert!(!client.has_connection_dependencies(first_relay, first_outer));
    assert!(client.has_connection_dependencies(chosen_relay, chosen_outer));
    drop(command);
    drop(pin);
    drop(first);
    drop(chosen);
    client.on_swarm_event(FromSwarm::DialFailure(DialFailure {
        peer_id: Some(peer),
        connection_id: inner,
        error: &DialError::NoAddresses,
    }));
    assert!(!client.has_connection_dependencies(chosen_relay, chosen_outer));
}

#[test]
fn extended_branch_registration_racing_pin_cannot_dispatch_a_default() {
    for _ in 0..32 {
        let (transport, mut client) = relay::client::new(PeerId::random());
        let relay = PeerId::random();
        let extended = PeerId::random();
        let peer = PeerId::random();
        let outer = ConnectionId::new_unchecked(750);
        let inner = ConnectionId::new_unchecked(751);
        let _handler = establish(&mut client, relay, outer);
        client
            .handle_pending_outbound_connection(
                inner,
                Some(peer),
                &[address(relay, peer)],
                Endpoint::Dialer,
            )
            .unwrap();
        let mut transport = Deferred(Arc::new(Mutex::new(transport))).boxed();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let worker_barrier = barrier.clone();
        let worker = std::thread::spawn(move || {
            let mut dial = transport
                .dial_with_connection_id(address(extended, peer), options(), 751)
                .unwrap();
            worker_barrier.wait();
            let done = match dial.poll_unpin(&mut cx()) {
                Poll::Ready(Err(_)) => true,
                Poll::Pending => false,
                Poll::Ready(Ok(_)) => panic!("alternative completed without dispatch"),
            };
            (transport, dial, done)
        });
        barrier.wait();
        let pin = client.pin_circuit_dial(peer, inner, relay, outer).unwrap();
        let (_transport, mut dial, done) = worker.join().unwrap();
        assert!(
            client.poll(&mut cx()).is_pending(),
            "racing alternative selected a default or dialed"
        );
        if !done {
            assert!(matches!(dial.poll_unpin(&mut cx()), Poll::Ready(Err(_))));
        }
        drop(pin);
        drop(dial);
        client.on_swarm_event(FromSwarm::DialFailure(DialFailure {
            peer_id: Some(peer),
            connection_id: inner,
            error: &DialError::NoAddresses,
        }));
        assert!(!client.has_connection_dependencies(relay, outer));
    }
}

#[test]
fn wholly_unpinned_offered_and_late_extended_alternatives_keep_legacy_selection() {
    let (transport, mut client) = relay::client::new(PeerId::random());
    let peer = PeerId::random();
    let relays = [PeerId::random(), PeerId::random(), PeerId::random()];
    let outers = [
        ConnectionId::new_unchecked(800),
        ConnectionId::new_unchecked(801),
        ConnectionId::new_unchecked(802),
    ];
    let _handlers = relays
        .iter()
        .zip(outers)
        .map(|(relay, outer)| establish(&mut client, *relay, outer))
        .collect::<Vec<_>>();
    let inner = ConnectionId::new_unchecked(803);
    client
        .handle_pending_outbound_connection(
            inner,
            Some(peer),
            &[address(relays[0], peer), address(relays[1], peer)],
            Endpoint::Dialer,
        )
        .unwrap();
    let mut transport = Deferred(Arc::new(Mutex::new(transport))).boxed();
    let mut dials = Vec::new();
    let mut commands = Vec::new();
    for (relay, outer) in relays.into_iter().zip(outers) {
        let mut dial = transport
            .dial_with_connection_id(address(relay, peer), options(), 803)
            .unwrap();
        assert!(dial.poll_unpin(&mut cx()).is_pending());
        let Poll::Ready(command) = client.poll(&mut cx()) else {
            panic!("unpinned alternative was rejected")
        };
        assert!(
            matches!(&command, ToSwarm::NotifyHandler { peer_id, handler: NotifyHandler::One(id), .. }
            if *peer_id == relay && *id == outer)
        );
        dials.push(dial);
        commands.push(command);
    }
    drop(commands);
    drop(dials);
    client.on_swarm_event(FromSwarm::DialFailure(DialFailure {
        peer_id: Some(peer),
        connection_id: inner,
        error: &DialError::NoAddresses,
    }));
    for (relay, outer) in relays.into_iter().zip(outers) {
        assert!(!client.has_connection_dependencies(relay, outer));
    }
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    relay: relay::client::Behaviour,
    server: Toggle<relay::Behaviour>,
    ping: ping::Behaviour,
    blocked: allow_block_list::Behaviour<allow_block_list::BlockedPeers>,
}
type Host = Swarm<Behaviour>;

fn host(server: bool) -> Host {
    let key = Keypair::generate_ed25519();
    let (transport, relay) = relay::client::new(key.public().to_peer_id());
    let noise = noise::Config::new(&key).unwrap();
    let transport = transport.and_then(move |connection, endpoint| {
        let binding = connection.circuit_binding();
        let noise = noise.clone();
        async move {
            let (peer, stream) = libp2p::core::upgrade::apply(
                connection,
                noise,
                endpoint.clone(),
                libp2p::core::upgrade::Version::V1Lazy,
            )
            .await
            .map_err(io::Error::other)?;
            let muxer = libp2p::core::upgrade::apply(
                stream,
                yamux::Config::default(),
                endpoint,
                libp2p::core::upgrade::Version::V1Lazy,
            )
            .await
            .map_err(io::Error::other)?;
            Ok::<_, io::Error>((peer, binding.wrap_muxer(peer, muxer)))
        }
        .boxed()
    });
    SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_other_transport(|_| transport)
        .unwrap()
        .with_behaviour(move |key: &Keypair| Behaviour {
            relay,
            server: server
                .then(|| {
                    relay::Behaviour::new(
                        key.public().to_peer_id(),
                        relay::Config {
                            reservation_duration: Duration::from_secs(4),
                            reservation_rate_limiters: vec![],
                            ..relay::Config::default()
                        },
                    )
                })
                .into(),
            ping: ping::Behaviour::new(
                ping::Config::new().with_interval(Duration::from_millis(100)),
            ),
            blocked: Default::default(),
        })
        .unwrap()
        .with_swarm_config(|config| config.with_idle_connection_timeout(Duration::from_secs(60)))
        .build()
}

async fn server() -> (Host, Multiaddr) {
    let mut server = host(true);
    server
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let address = tokio::time::timeout(DEADLINE, async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = server.select_next_some().await {
                server.add_external_address(address.clone());
                break address.with(Protocol::P2p(*server.local_peer_id()));
            }
        }
    })
    .await
    .unwrap();
    (server, address)
}

async fn connect(client: &mut Host, server: &mut Host, address: &Multiaddr) -> ConnectionId {
    let options = DialOpts::peer_id(*server.local_peer_id())
        .condition(PeerCondition::Always)
        .addresses(vec![address.clone()])
        .build();
    let id = options.connection_id();
    client.dial(options).unwrap();
    tokio::time::timeout(DEADLINE, async {
        loop {
            tokio::select! {
                _ = server.select_next_some() => {},
                event = client.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { connection_id, endpoint, .. } if connection_id == id => { assert!(!endpoint.is_relayed()); break; },
                    SwarmEvent::OutgoingConnectionError { error, .. } => panic!("direct TCP: {error}"),
                    _ => {},
                }
            }
        }
    }).await.unwrap();
    id
}

async fn reserve(client: &mut Host, server: &mut Host, address: &Multiaddr, outer: ConnectionId) {
    let relay = *server.local_peer_id();
    let listener = client
        .listen_on(address.clone().with(Protocol::P2pCircuit))
        .unwrap();
    assert!(
        client
            .behaviour_mut()
            .relay
            .pin_reservation_listener(relay, listener, outer)
    );
    tokio::time::timeout(DEADLINE, async {
        loop {
            tokio::select! {
                _ = server.select_next_some() => {},
                event = client.select_next_some() => {
                    if let SwarmEvent::NewListenAddr { listener_id, .. } = event {
                        if listener_id == listener {
                            assert_eq!(client.behaviour().relay.reservation_listener_connection(relay, listener), Some(outer));
                            assert!(client.behaviour().relay.confirmed_reservation_connections(relay).any(|id| id == outer));
                            break;
                        }
                    }
                }
            }
        }
    }).await.unwrap();
}

fn circuit(
    client: &mut Host,
    peer: PeerId,
    relay: PeerId,
    outer: ConnectionId,
    address: &Multiaddr,
) -> (ConnectionId, relay::client::CircuitDialPin) {
    let options = DialOpts::peer_id(peer)
        .condition(PeerCondition::Always)
        .addresses(vec![
            address
                .clone()
                .with(Protocol::P2pCircuit)
                .with(Protocol::P2p(peer)),
        ])
        .build();
    let inner = options.connection_id();
    client.dial(options).unwrap();
    let pin = client
        .behaviour_mut()
        .relay
        .pin_circuit_dial(peer, inner, relay, outer)
        .unwrap();
    (inner, pin)
}

#[tokio::test]
async fn concurrent_authenticated_same_peer_circuits_map_both_directions_and_survive_preference_changes()
 {
    let (mut server, address) = server().await;
    let relay = *server.local_peer_id();
    let mut receiver = host(false);
    let mut sender = host(false);
    let receiver_peer = *receiver.local_peer_id();
    let sender_peer = *sender.local_peer_id();
    let receive_old = connect(&mut receiver, &mut server, &address).await;
    let receive_new = connect(&mut receiver, &mut server, &address).await;
    let send_old = connect(&mut sender, &mut server, &address).await;
    let send_new = connect(&mut sender, &mut server, &address).await;
    reserve(&mut receiver, &mut server, &address, receive_old).await;
    let (first, pin_first) = circuit(&mut sender, receiver_peer, relay, send_old, &address);
    let (second, pin_second) = circuit(&mut sender, receiver_peer, relay, send_new, &address);
    assert!(
        sender
            .behaviour_mut()
            .relay
            .prefer_relay_connection(relay, send_old)
    );
    let expected = HashMap::from([(first, send_old), (second, send_new)]);
    let mut established = Vec::new();
    let mut inbound = Vec::new();
    tokio::time::timeout(DEADLINE, async {
        while established.len() < 2 || inbound.len() < 2 {
            tokio::select! {
                _ = server.select_next_some() => {},
                event = sender.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } => {
                        assert!(endpoint.is_relayed());
                        assert_eq!(sender.behaviour().relay.circuit_connection_owner(peer_id, connection_id), Some((relay, expected[&connection_id])));
                        assert_eq!(sender.behaviour().relay.circuit_connection_owner(PeerId::random(), connection_id), None);
                        established.push(connection_id);
                    }
                    SwarmEvent::OutgoingConnectionError { error, .. } => panic!("directed circuit: {error}"),
                    _ => {},
                },
                event = receiver.select_next_some() => if let SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } = event {
                    assert!(endpoint.is_relayed());
                    assert_eq!(receiver.behaviour().relay.circuit_connection_owner(peer_id, connection_id), Some((relay, receive_old)));
                    inbound.push(connection_id);
                },
            }
        }
    }).await.expect("authenticated circuit ownership deadline");
    drop(pin_first);
    drop(pin_second);
    assert_eq!(
        sender
            .behaviour()
            .relay
            .circuit_connection_owner(relay, send_old),
        None
    );
    reserve(&mut receiver, &mut server, &address, receive_new).await;
    assert!(receiver.behaviour_mut().relay.begin_reservation_drain(
        relay,
        receive_old,
        receive_new
    ));
    // The server independently selects its destination reservation. Wait until
    // the old one expires while keeping both authenticated old circuits alive.
    tokio::time::timeout(DEADLINE, async {
        loop {
            tokio::select! {
                event = server.select_next_some() => if matches!(event, SwarmEvent::Behaviour(BehaviourEvent::Server(relay::Event::ReservationTimedOut { src_peer_id })) if src_peer_id == receiver_peer) { break; },
                _ = sender.select_next_some() => {},
                _ = receiver.select_next_some() => {},
            }
        }
    }).await.expect("drained receiver reservation expiry");
    for inner in &inbound {
        assert_eq!(
            receiver
                .behaviour()
                .relay
                .circuit_connection_owner(sender_peer, *inner),
            Some((relay, receive_old))
        );
    }
    let (third, pin_third) = circuit(&mut sender, receiver_peer, relay, send_new, &address);
    let mut sent = false;
    let mut received = false;
    tokio::time::timeout(DEADLINE, async {
        while !sent || !received {
            tokio::select! {
                _ = server.select_next_some() => {},
                event = sender.select_next_some() => if let SwarmEvent::ConnectionEstablished { connection_id, .. } = event {
                    assert_eq!(connection_id, third);
                    assert_eq!(sender.behaviour().relay.circuit_connection_owner(receiver_peer, third), Some((relay, send_new)));
                    sent = true;
                },
                event = receiver.select_next_some() => if let SwarmEvent::ConnectionEstablished { connection_id, .. } = event {
                    assert_eq!(receiver.behaviour().relay.circuit_connection_owner(sender_peer, connection_id), Some((relay, receive_new)));
                    received = true;
                },
            }
        }
    }).await.expect("replacement inbound outer mapping");
    drop(pin_third);
    for inner in &established {
        assert!(sender.close_connection(*inner));
    }
    tokio::time::timeout(DEADLINE, async {
        loop {
            if established.iter().all(|inner| {
                sender
                    .behaviour()
                    .relay
                    .circuit_connection_owner(receiver_peer, *inner)
                    .is_none()
            }) && inbound.iter().all(|inner| {
                receiver
                    .behaviour()
                    .relay
                    .circuit_connection_owner(sender_peer, *inner)
                    .is_none()
            }) && !receiver
                .behaviour()
                .relay
                .has_connection_dependencies(relay, receive_old)
            {
                break;
            }
            tokio::select! {
                _ = server.select_next_some() => {},
                _ = sender.select_next_some() => {},
                _ = receiver.select_next_some() => {},
                _ = tokio::task::yield_now() => {},
            }
        }
    })
    .await
    .expect("inner teardown releases old outer ownership");
    for inner in established {
        assert_eq!(
            sender
                .behaviour()
                .relay
                .circuit_connection_owner(receiver_peer, inner),
            None
        );
    }
    assert!(
        sender
            .behaviour()
            .relay
            .has_connection_dependencies(relay, send_new)
    );
}

#[tokio::test]
async fn cancelled_pin_before_dispatch_never_establishes_or_redials() {
    let (mut server, address) = server().await;
    let relay = *server.local_peer_id();
    let mut sender = host(false);
    let outer = connect(&mut sender, &mut server, &address).await;
    let peer = PeerId::random();
    let (inner, pin) = circuit(&mut sender, peer, relay, outer, &address);
    drop(pin);
    tokio::time::timeout(DEADLINE, async {
        loop {
            tokio::select! {
                _ = server.select_next_some() => {},
                event = sender.select_next_some() => match event {
                    SwarmEvent::OutgoingConnectionError { connection_id, .. } if connection_id == inner => break,
                    SwarmEvent::ConnectionEstablished { .. } | SwarmEvent::Dialing { .. } => panic!("cancelled pin started extra I/O"),
                    _ => {},
                }
            }
        }
    }).await.expect("cancelled directed circuit deadline");
    assert_eq!(
        sender
            .behaviour()
            .relay
            .circuit_connection_owner(peer, inner),
        None
    );
    assert!(
        !sender
            .behaviour()
            .relay
            .has_connection_dependencies(relay, outer)
    );
}

#[tokio::test]
async fn rejected_authenticated_inbound_never_registers_an_owner() {
    let (mut server, address) = server().await;
    let relay = *server.local_peer_id();
    let mut receiver = host(false);
    let mut sender = host(false);
    let peer = *receiver.local_peer_id();
    let sender_peer = *sender.local_peer_id();
    let receive_outer = connect(&mut receiver, &mut server, &address).await;
    let send_outer = connect(&mut sender, &mut server, &address).await;
    reserve(&mut receiver, &mut server, &address, receive_outer).await;
    receiver.behaviour_mut().blocked.block_peer(sender_peer);
    let (inner, pin) = circuit(&mut sender, peer, relay, send_outer, &address);
    tokio::time::timeout(DEADLINE, async {
        loop {
            tokio::select! {
                _ = server.select_next_some() => {},
                _ = sender.select_next_some() => {},
                event = receiver.select_next_some() => match event {
                    SwarmEvent::IncomingConnectionError { connection_id, .. } => {
                        assert_eq!(receiver.behaviour().relay.circuit_connection_owner(sender_peer, connection_id), None);
                        break;
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == sender_peer => panic!("blocked authenticated inner was admitted"),
                    _ => {},
                }
            }
        }
    }).await.expect("authenticated admission rejection deadline");
    drop(pin);
    sender.close_connection(inner);
    tokio::time::timeout(DEADLINE, async {
        while sender
            .behaviour()
            .relay
            .circuit_connection_owner(peer, inner)
            .is_some()
            || sender
                .behaviour()
                .relay
                .has_connection_dependencies(relay, send_outer)
        {
            tokio::select! {
                _ = server.select_next_some() => {},
                _ = sender.select_next_some() => {},
                _ = receiver.select_next_some() => {},
                _ = tokio::task::yield_now() => {},
            }
        }
    })
    .await
    .expect("rejected circuit ownership cleanup");
}
