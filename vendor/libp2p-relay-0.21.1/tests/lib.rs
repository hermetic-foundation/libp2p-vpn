// Copyright 2021 Protocol Labs.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::{error::Error, time::Duration};

use futures::{
    io::{AsyncRead, AsyncWrite},
    stream::StreamExt,
};
use libp2p_core::{
    multiaddr::{Multiaddr, Protocol},
    muxing::StreamMuxerBox,
    transport::{choice::OrTransport, Boxed, MemoryTransport, Transport},
    upgrade,
};
use libp2p_identity as identity;
use libp2p_identity::PeerId;
use libp2p_ping as ping;
use libp2p_plaintext as plaintext;
use libp2p_relay as relay;
use libp2p_swarm::{
    dial_opts::{DialOpts, PeerCondition},
    Config, ConnectionId, DialError, NetworkBehaviour, Swarm, SwarmEvent,
};
use libp2p_swarm_test::SwarmExt;
use tracing_subscriber::EnvFilter;

#[tokio::test]
async fn reservation() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let relay_addr = Multiaddr::empty().with(Protocol::Memory(rand::random::<u64>()));
    let mut relay = build_relay();
    let relay_peer_id = *relay.local_peer_id();

    relay.listen_on(relay_addr.clone()).unwrap();
    relay.add_external_address(relay_addr.clone());
    tokio::spawn(async move {
        relay.collect::<Vec<_>>().await;
    });

    let client_addr = relay_addr
        .with(Protocol::P2p(relay_peer_id))
        .with(Protocol::P2pCircuit);
    let mut client = build_client();
    let client_peer_id = *client.local_peer_id();

    client.listen_on(client_addr.clone()).unwrap();

    // Wait for connection to relay.
    assert!(wait_for_dial(&mut client, relay_peer_id).await);

    // Wait for initial reservation.
    wait_for_reservation(
        &mut client,
        client_addr.clone().with(Protocol::P2p(client_peer_id)),
        relay_peer_id,
        false, // No renewal.
    )
    .await;

    // Wait for renewal.
    wait_for_reservation(
        &mut client,
        client_addr.with(Protocol::P2p(client_peer_id)),
        relay_peer_id,
        true, // Renewal.
    )
    .await;
}

#[tokio::test]
async fn new_reservation_to_same_relay_replaces_old() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let relay_addr = Multiaddr::empty().with(Protocol::Memory(rand::random::<u64>()));
    let mut relay = build_relay();
    let relay_peer_id = *relay.local_peer_id();

    relay.listen_on(relay_addr.clone()).unwrap();
    relay.add_external_address(relay_addr.clone());
    tokio::spawn(async move {
        relay.collect::<Vec<_>>().await;
    });

    let mut client = build_client();
    let client_peer_id = *client.local_peer_id();
    let client_addr = relay_addr
        .with(Protocol::P2p(relay_peer_id))
        .with(Protocol::P2pCircuit);
    let client_addr_with_peer_id = client_addr.clone().with(Protocol::P2p(client_peer_id));

    let old_listener = client.listen_on(client_addr.clone()).unwrap();

    // Wait for connection to relay.
    assert!(wait_for_dial(&mut client, relay_peer_id).await);

    // Wait for first (old) reservation.
    wait_for_reservation(
        &mut client,
        client_addr_with_peer_id.clone(),
        relay_peer_id,
        false, // No renewal.
    )
    .await;

    // Trigger new reservation.
    let new_listener = client.listen_on(client_addr.clone()).unwrap();

    // Wait for
    // - listener of old reservation to close
    // - new reservation to be accepted
    // - new listener address to be reported
    let mut old_listener_closed = false;
    let mut new_reservation_accepted = false;
    let mut new_listener_address_reported = false;
    loop {
        match client.select_next_some().await {
            SwarmEvent::ListenerClosed {
                addresses,
                listener_id,
                ..
            } => {
                assert_eq!(addresses, vec![client_addr_with_peer_id.clone()]);
                assert_eq!(listener_id, old_listener);

                old_listener_closed = true;
                if new_reservation_accepted && new_listener_address_reported {
                    break;
                }
            }
            SwarmEvent::Behaviour(ClientEvent::Relay(
                relay::client::Event::ReservationReqAccepted {
                    relay_peer_id: peer_id,
                    ..
                },
            )) => {
                assert_eq!(relay_peer_id, peer_id);

                new_reservation_accepted = true;
                if old_listener_closed && new_listener_address_reported {
                    break;
                }
            }
            SwarmEvent::NewListenAddr {
                address,
                listener_id,
            } => {
                assert_eq!(address, client_addr_with_peer_id);
                assert_eq!(listener_id, new_listener);

                new_listener_address_reported = true;
                if old_listener_closed && new_reservation_accepted {
                    break;
                }
            }
            SwarmEvent::ExternalAddrConfirmed { address } => {
                assert_eq!(
                    address,
                    client_addr.clone().with(Protocol::P2p(client_peer_id))
                );
            }
            SwarmEvent::Behaviour(ClientEvent::Ping(_)) => {}
            e => panic!("{e:?}"),
        }
    }
}

#[tokio::test]
async fn connect() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let relay_addr = Multiaddr::empty().with(Protocol::Memory(rand::random::<u64>()));
    let mut relay = build_relay();
    let relay_peer_id = *relay.local_peer_id();

    relay.listen_on(relay_addr.clone()).unwrap();
    relay.add_external_address(relay_addr.clone());
    tokio::spawn(async move {
        relay.collect::<Vec<_>>().await;
    });

    let mut dst = build_client();
    let dst_peer_id = *dst.local_peer_id();
    let dst_addr = relay_addr
        .with(Protocol::P2p(relay_peer_id))
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(dst_peer_id));

    dst.listen_on(dst_addr.clone()).unwrap();

    assert!(wait_for_dial(&mut dst, relay_peer_id).await);

    wait_for_reservation(
        &mut dst,
        dst_addr.clone(),
        relay_peer_id,
        false, // No renewal.
    )
    .await;

    let mut src = build_client();
    let src_peer_id = *src.local_peer_id();

    src.dial(dst_addr).unwrap();

    futures::future::join(
        connection_established_to(&mut src, relay_peer_id, dst_peer_id),
        connection_established_to(&mut dst, relay_peer_id, src_peer_id),
    )
    .await;
}

#[tokio::test]
async fn server_prefers_new_reservation_preserves_old_circuit_and_falls_back() {
    let test = async {
        let relay_addr = Multiaddr::empty().with(Protocol::Memory(rand::random::<u64>()));
        let mut relay = build_relay_with_config(relay::Config {
            max_reservations: 2,
            max_reservations_per_peer: 2,
            reservation_duration: Duration::from_secs(60),
            reservation_rate_limiters: vec![],
            circuit_src_rate_limiters: vec![],
            ..Default::default()
        });
        let relay_peer_id = *relay.local_peer_id();
        relay.listen_on(relay_addr.clone()).unwrap();
        relay.add_external_address(relay_addr.clone());

        // Separate clients with one identity give the server two live physical owners.
        let key = identity::Keypair::generate_ed25519();
        let mut old = build_client_with_key(key.clone(), Config::with_tokio_executor());
        let mut new = build_client_with_key(key, Config::with_tokio_executor());
        let dst_peer_id = *old.local_peer_id();
        old.behaviour_mut().ping =
            ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_millis(50)));
        let dst_addr = relay_addr
            .with(Protocol::P2p(relay_peer_id))
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(dst_peer_id));
        let mut src = build_client();

        reserve_on_server(&mut relay, &mut old, dst_addr.clone()).await;
        let (old_src_circuit, old_dst_circuit) =
            connect_on_reservation(&mut relay, &mut src, &mut old, &mut new, &dst_addr).await;

        reserve_on_server(&mut relay, &mut new, dst_addr.clone()).await;
        connect_on_reservation(&mut relay, &mut src, &mut new, &mut old, &dst_addr).await;
        assert_old_circuit_live(
            &mut relay,
            &mut src,
            &mut old,
            &mut new,
            old_src_circuit,
            old_dst_circuit,
        )
        .await;

        new.disconnect_peer_id(relay_peer_id).unwrap();
        loop {
            futures::select! {
                event = relay.select_next_some() => {
                    if matches!(event, SwarmEvent::Behaviour(RelayEvent::Relay(
                        relay::Event::ReservationClosed { src_peer_id }
                    )) if src_peer_id == dst_peer_id) {
                        break;
                    }
                },
                _ = src.select_next_some() => {},
                _ = old.select_next_some() => {},
                _ = new.select_next_some() => {},
            }
        }

        connect_on_reservation(&mut relay, &mut src, &mut old, &mut new, &dst_addr).await;
        assert_old_circuit_live(
            &mut relay,
            &mut src,
            &mut old,
            &mut new,
            old_src_circuit,
            old_dst_circuit,
        )
        .await;
    };
    futures::pin_mut!(test);
    let timeout = futures_timer::Delay::new(Duration::from_secs(10));
    futures::pin_mut!(timeout);
    assert!(
        matches!(
            futures::future::select(test, timeout).await,
            futures::future::Either::Left(_)
        ),
        "reservation owner handoff timed out"
    );
}

async fn reserve_on_server(relay: &mut Swarm<Relay>, client: &mut Swarm<Client>, addr: Multiaddr) {
    let peer = *client.local_peer_id();
    let relay_peer = *relay.local_peer_id();
    client.listen_on(addr.clone()).unwrap();
    futures::future::join(
        relay.wait(|event| match event {
            SwarmEvent::Behaviour(RelayEvent::Relay(relay::Event::ReservationReqAccepted {
                src_peer_id,
                renewed: false,
            })) if src_peer_id == peer => Some(()),
            _ => None,
        }),
        async {
            assert!(wait_for_dial(client, relay_peer).await);
            wait_for_reservation(client, addr, relay_peer, false).await;
        },
    )
    .await;
}

async fn connect_on_reservation(
    relay: &mut Swarm<Relay>,
    src: &mut Swarm<Client>,
    owner: &mut Swarm<Client>,
    other: &mut Swarm<Client>,
    addr: &Multiaddr,
) -> (ConnectionId, ConnectionId) {
    let src_peer = *src.local_peer_id();
    let opts = DialOpts::peer_id(*owner.local_peer_id())
        .condition(PeerCondition::Always)
        .addresses(vec![addr.clone()])
        .build();
    let src_connection = opts.connection_id();
    src.dial(opts).unwrap();
    let mut src_established = false;
    let mut dst_inbound = false;
    let mut dst_connection = None;
    loop {
        futures::select! {
            _ = relay.select_next_some() => {},
            event = src.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished { connection_id, endpoint, .. }
                    if connection_id == src_connection => {
                        assert!(endpoint.is_relayed());
                        src_established = true;
                    },
                SwarmEvent::OutgoingConnectionError { connection_id, error, .. }
                    if connection_id == src_connection => panic!("circuit dial failed: {error}"),
                _ => {},
            },
            event = owner.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. }
                    if peer_id == src_peer => {
                        assert!(endpoint.is_relayed());
                        dst_connection = Some(connection_id);
                    },
                SwarmEvent::Behaviour(ClientEvent::Relay(
                    relay::client::Event::InboundCircuitEstablished { src_peer_id, .. }
                )) if src_peer_id == src_peer => dst_inbound = true,
                _ => {},
            },
            event = other.select_next_some() => {
                assert!(!matches!(event, SwarmEvent::Behaviour(ClientEvent::Relay(
                    relay::client::Event::InboundCircuitEstablished { src_peer_id, .. }
                )) if src_peer_id == src_peer), "new circuit used the wrong reservation");
            },
        }
        if let (true, true, Some(dst_connection)) = (src_established, dst_inbound, dst_connection) {
            return (src_connection, dst_connection);
        }
    }
}

async fn assert_old_circuit_live(
    relay: &mut Swarm<Relay>,
    src: &mut Swarm<Client>,
    old: &mut Swarm<Client>,
    new: &mut Swarm<Client>,
    src_connection: ConnectionId,
    dst_connection: ConnectionId,
) {
    let src_peer = *src.local_peer_id();
    // Drain a possibly queued ping and require another round trip on the exact old circuit.
    let mut pings = 0;
    while pings < 2 {
        futures::select! {
            _ = relay.select_next_some() => {},
            _ = new.select_next_some() => {},
            event = src.select_next_some() => {
                assert!(!matches!(event, SwarmEvent::ConnectionClosed { connection_id, .. }
                    if connection_id == src_connection), "old source circuit closed");
            },
            event = old.select_next_some() => match event {
                SwarmEvent::Behaviour(ClientEvent::Ping(ping::Event { peer, connection, result, .. }))
                    if peer == src_peer && connection == dst_connection => {
                        result.unwrap();
                        pings += 1;
                    },
                SwarmEvent::ConnectionClosed { connection_id, .. }
                    if connection_id == dst_connection => panic!("old destination circuit closed"),
                _ => {},
            },
        }
    }
}

async fn connection_established_to(
    swarm: &mut Swarm<Client>,
    relay_peer_id: PeerId,
    other: PeerId,
) {
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::Dialing {
                peer_id: Some(peer_id),
                ..
            } if peer_id == relay_peer_id => {}
            SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == relay_peer_id => {}
            SwarmEvent::Behaviour(ClientEvent::Ping(ping::Event { peer, .. })) if peer == other => {
                break
            }
            SwarmEvent::Behaviour(ClientEvent::Relay(
                relay::client::Event::OutboundCircuitEstablished { .. },
            )) => {}
            SwarmEvent::Behaviour(ClientEvent::Relay(
                relay::client::Event::InboundCircuitEstablished { src_peer_id, .. },
            )) => {
                assert_eq!(src_peer_id, other);
            }
            SwarmEvent::Behaviour(ClientEvent::Ping(ping::Event { peer, .. }))
                if peer == relay_peer_id => {}
            SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == other => break,
            SwarmEvent::IncomingConnection { send_back_addr, .. } => {
                let peer_id_from_addr = send_back_addr
                    .iter()
                    .find_map(|protocol| match protocol {
                        Protocol::P2p(peer_id) => Some(peer_id),
                        _ => None,
                    })
                    .expect("to have /p2p");

                assert_eq!(peer_id_from_addr, other)
            }
            e => panic!("{e:?}"),
        }
    }
}

#[tokio::test]
async fn handle_dial_failure() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let relay_addr = Multiaddr::empty().with(Protocol::Memory(rand::random::<u64>()));
    let relay_peer_id = PeerId::random();

    let mut client = build_client();
    let client_peer_id = *client.local_peer_id();
    let client_addr = relay_addr
        .with(Protocol::P2p(relay_peer_id))
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(client_peer_id));

    client.listen_on(client_addr).unwrap();
    assert!(!wait_for_dial(&mut client, relay_peer_id).await);
}

#[tokio::test]
async fn propagate_reservation_error_to_listener() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let relay_addr = Multiaddr::empty().with(Protocol::Memory(rand::random::<u64>()));
    let mut relay = build_relay_with_config(relay::Config {
        max_reservations: 0, // Will make us fail to make the reservation
        ..relay::Config::default()
    });
    let relay_peer_id = *relay.local_peer_id();

    relay.listen_on(relay_addr.clone()).unwrap();
    relay.add_external_address(relay_addr.clone());
    tokio::spawn(async move {
        relay.collect::<Vec<_>>().await;
    });

    let client_addr = relay_addr
        .with(Protocol::P2p(relay_peer_id))
        .with(Protocol::P2pCircuit);
    let mut client = build_client();

    let reservation_listener = client.listen_on(client_addr.clone()).unwrap();

    // Wait for connection to relay.
    assert!(wait_for_dial(&mut client, relay_peer_id).await);

    let error = client
        .wait(|e| match e {
            SwarmEvent::ListenerClosed {
                listener_id,
                reason: Err(e),
                ..
            } if listener_id == reservation_listener => Some(e),
            _ => None,
        })
        .await;

    let error = error
        .source()
        .unwrap()
        .downcast_ref::<relay::outbound::hop::ReserveError>()
        .unwrap();

    assert!(matches!(
        error,
        relay::outbound::hop::ReserveError::ResourceLimitExceeded
    ));
}

#[tokio::test]
async fn propagate_connect_error_to_unknown_peer_to_dialer() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let relay_addr = Multiaddr::empty().with(Protocol::Memory(rand::random::<u64>()));
    let mut relay = build_relay();
    let relay_peer_id = *relay.local_peer_id();

    relay.listen_on(relay_addr.clone()).unwrap();
    relay.add_external_address(relay_addr.clone());
    tokio::spawn(async move {
        relay.collect::<Vec<_>>().await;
    });

    let mut src = build_client();

    let dst_peer_id = PeerId::random(); // We don't have a destination peer in this test, so the CONNECT request will fail.
    let dst_addr = relay_addr
        .with(Protocol::P2p(relay_peer_id))
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(dst_peer_id));

    let opts = DialOpts::from(dst_addr.clone());
    let circuit_connection_id = opts.connection_id();

    src.dial(opts).unwrap();

    let (failed_address, error) = src
        .wait(|e| match e {
            SwarmEvent::OutgoingConnectionError {
                connection_id,
                error: DialError::Transport(mut errors),
                ..
            } if connection_id == circuit_connection_id => {
                assert_eq!(errors.len(), 1);
                Some(errors.remove(0))
            }
            _ => None,
        })
        .await;

    // This is a bit wonky but we need to get the _actual_ source error :)
    let error = error
        .source()
        .unwrap()
        .source()
        .unwrap()
        .downcast_ref::<relay::outbound::hop::ConnectError>()
        .unwrap();

    assert_eq!(failed_address, dst_addr);
    assert!(matches!(
        error,
        relay::outbound::hop::ConnectError::NoReservation
    ));
}

#[tokio::test]
async fn reuse_connection() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let relay_addr = Multiaddr::empty().with(Protocol::Memory(rand::random::<u64>()));
    let mut relay = build_relay();
    let relay_peer_id = *relay.local_peer_id();

    relay.listen_on(relay_addr.clone()).unwrap();
    relay.add_external_address(relay_addr.clone());
    tokio::spawn(async move {
        relay.collect::<Vec<_>>().await;
    });

    let client_addr = relay_addr
        .clone()
        .with(Protocol::P2p(relay_peer_id))
        .with(Protocol::P2pCircuit);

    let mut client = build_client();
    let client_peer_id = *client.local_peer_id();

    client.dial(relay_addr).unwrap();
    assert!(wait_for_dial(&mut client, relay_peer_id).await);

    client.listen_on(client_addr.clone()).unwrap();

    wait_for_reservation(
        &mut client,
        client_addr.with(Protocol::P2p(client_peer_id)),
        relay_peer_id,
        false, // No renewal.
    )
    .await;
}

fn build_relay() -> Swarm<Relay> {
    build_relay_with_config(relay::Config {
        reservation_duration: Duration::from_secs(2),
        ..Default::default()
    })
}

fn build_relay_with_config(config: relay::Config) -> Swarm<Relay> {
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = local_key.public().to_peer_id();

    let transport = upgrade_transport(MemoryTransport::default().boxed(), &local_key);

    Swarm::new(
        transport,
        Relay {
            ping: ping::Behaviour::new(ping::Config::new()),
            relay: relay::Behaviour::new(local_peer_id, config),
        },
        local_peer_id,
        Config::with_tokio_executor(),
    )
}

fn build_client() -> Swarm<Client> {
    build_client_with_config(Config::with_tokio_executor())
}

fn build_client_with_config(config: Config) -> Swarm<Client> {
    build_client_with_key(identity::Keypair::generate_ed25519(), config)
}

fn build_client_with_key(local_key: identity::Keypair, config: Config) -> Swarm<Client> {
    let local_peer_id = local_key.public().to_peer_id();

    let (relay_transport, behaviour) = relay::client::new(local_peer_id);
    let transport = upgrade_transport(
        OrTransport::new(relay_transport, MemoryTransport::default()).boxed(),
        &local_key,
    );

    Swarm::new(
        transport,
        Client {
            ping: ping::Behaviour::new(ping::Config::new()),
            relay: behaviour,
        },
        local_peer_id,
        config,
    )
}

fn upgrade_transport<StreamSink>(
    transport: Boxed<StreamSink>,
    identity: &identity::Keypair,
) -> Boxed<(PeerId, StreamMuxerBox)>
where
    StreamSink: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    transport
        .upgrade(upgrade::Version::V1)
        .authenticate(plaintext::Config::new(identity))
        .multiplex(libp2p_yamux::Config::default())
        .boxed()
}

#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p_swarm::derive_prelude")]
struct Relay {
    relay: relay::Behaviour,
    ping: ping::Behaviour,
}

#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p_swarm::derive_prelude")]
struct Client {
    relay: relay::client::Behaviour,
    ping: ping::Behaviour,
}

async fn wait_for_reservation(
    client: &mut Swarm<Client>,
    client_addr: Multiaddr,
    relay_peer_id: PeerId,
    is_renewal: bool,
) {
    let mut new_listen_addr = false;
    let mut reservation_req_accepted = false;

    loop {
        match client.select_next_some().await {
            SwarmEvent::ExternalAddrConfirmed { address } if !is_renewal => {
                assert_eq!(address, client_addr);
            }
            SwarmEvent::Behaviour(ClientEvent::Relay(
                relay::client::Event::ReservationReqAccepted {
                    relay_peer_id: peer_id,
                    renewal,
                    ..
                },
            )) if relay_peer_id == peer_id && renewal == is_renewal => {
                reservation_req_accepted = true;
                if new_listen_addr {
                    break;
                }
            }
            SwarmEvent::NewListenAddr { address, .. } if address == client_addr => {
                new_listen_addr = true;
                if reservation_req_accepted {
                    break;
                }
            }
            SwarmEvent::Behaviour(ClientEvent::Ping(_)) => {}
            e => panic!("{e:?}"),
        }
    }
}

async fn wait_for_dial(client: &mut Swarm<Client>, remote: PeerId) -> bool {
    loop {
        match client.select_next_some().await {
            SwarmEvent::Dialing {
                peer_id: Some(peer_id),
                ..
            } if peer_id == remote => {}
            SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == remote => return true,
            SwarmEvent::OutgoingConnectionError { peer_id, .. } if peer_id == Some(remote) => {
                return false
            }
            SwarmEvent::Behaviour(ClientEvent::Ping(_)) => {}
            e => panic!("{e:?}"),
        }
    }
}
