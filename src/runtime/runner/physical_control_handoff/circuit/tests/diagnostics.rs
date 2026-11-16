use super::*;
use std::task::Poll;

fn node() -> P2pNode {
    crate::runtime::runner::tests::membership_sync_test_node(
        NodeIdentity::generate_ed25519().unwrap(),
    )
}

async fn connect(node: &mut P2pNode, server: &mut P2pNode, address: &Multiaddr) -> ConnectionId {
    let options = DialOpts::peer_id(server.local_peer_id)
        .addresses(vec![address.clone()])
        .condition(PeerCondition::Always)
        .allocate_new_port()
        .build();
    let expected = options.connection_id();
    node.swarm.dial(options).unwrap();
    let owners = node
        .swarm
        .behaviour()
        .connection_retention
        .physical_routes()
        .unwrap()
        .clone();
    let mut established_owner: Option<Snapshot> = None;
    let mut delayed_adoption = false;
    // TCP adopts on its first muxer poll, which can follow ConnectionEstablished.
    // Continue driving both native Swarms until the exact physical owner exists.
    futures::future::poll_fn(|cx| {
        let mut progressed = false;
        match node.swarm.poll_next_unpin(cx) {
            Poll::Ready(Some(event)) => {
                progressed = true;
                match event {
                    SwarmEvent::ConnectionEstablished {
                        connection_id,
                        endpoint,
                        ..
                    } if connection_id == expected => {
                        assert!(!endpoint.is_relayed());
                        let owner = owners.bound_connection(server.local_peer_id, expected)
                            .expect("established native outer must already have an exact live bound owner");
                        assert!(owner.is_live());
                        delayed_adoption = !owner.is_adopted();
                        eprintln!("diagnostic_outer_established connection_id={expected} owner={} protocol={:?} live={} adopted={}",
                            owner.id, owner.lease.context.protocol, owner.is_live(), owner.is_adopted());
                        assert!(established_owner.replace(owner).is_none());
                    }
                    SwarmEvent::ConnectionClosed { connection_id, cause, .. }
                        if connection_id == expected => panic!("native outer closed before adoption: {cause:?}"),
                    SwarmEvent::OutgoingConnectionError { error, .. } => {
                        panic!("native outer dial failed: {error}")
                    }
                    _ => {}
                }
            }
            Poll::Ready(None) => panic!("native client Swarm ended"),
            Poll::Pending => {}
        }
        match server.swarm.poll_next_unpin(cx) {
            Poll::Ready(Some(_)) => progressed = true,
            Poll::Ready(None) => panic!("native server Swarm ended"),
            Poll::Pending => {}
        }
        if let Some(bound) = &established_owner {
            assert!(bound.is_live(), "native bound owner was revoked before adoption");
            if let Some(adopted) = owners.connection(server.local_peer_id, expected) {
                assert_eq!(adopted.id, bound.id, "adoption must preserve the original owner token");
                assert!(adopted.is_adopted());
                eprintln!("diagnostic_outer_adopted connection_id={expected} owner={} delayed={delayed_adoption}", adopted.id);
                return Poll::Ready(expected);
            }
        }
        if progressed {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    })
    .await
}

fn assert_fields(
    behaviour: &Behaviour,
    peer: Libp2pPeerId,
    inner: ConnectionId,
    relay: Libp2pPeerId,
    outer: ConnectionId,
    physical: &Snapshot,
) {
    let expected = [
        ("peer", peer.to_string()),
        ("connection_id", inner.to_string()),
        ("relay", relay.to_string()),
        ("outer", outer.to_string()),
        (
            "physical_transport",
            match physical.lease.context.protocol {
                SocketProtocol::Tcp => "tcp",
                SocketProtocol::Udp => "quic",
            }
            .to_owned(),
        ),
        ("source", physical.lease.local_addr.to_string()),
        (
            "interface",
            physical.lease.route.interface_index.to_string(),
        ),
        ("generation", physical.lease.route.generation.to_string()),
    ];
    assert_eq!(
        established_binding_fields(behaviour, peer, inner),
        Some(expected)
    );
}

#[tokio::test]
async fn tcp_circuit_diagnostic_requires_real_binding_and_live_adopted_owner() {
    diagnostic_ownership(SocketProtocol::Tcp).await;
}

#[tokio::test]
async fn quic_circuit_diagnostic_requires_real_binding_and_live_adopted_owner() {
    diagnostic_ownership(SocketProtocol::Udp).await;
}

async fn diagnostic_ownership(protocol: SocketProtocol) {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut server = node();
        server.swarm.behaviour_mut().relay_server = Some(relay::Behaviour::new(
            server.local_peer_id,
            relay::Config {
                reservation_rate_limiters: Vec::new(),
                circuit_src_rate_limiters: Vec::new(),
                ..Default::default()
            },
        )).into();
        let listen = match protocol {
            SocketProtocol::Tcp => "/ip4/127.0.0.1/tcp/0",
            SocketProtocol::Udp => "/ip4/127.0.0.1/udp/0/quic-v1",
        };
        server.swarm.listen_on(listen.parse().unwrap()).unwrap();
        let address = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = server.swarm.select_next_some().await {
                break address;
            }
        };
        server.swarm.add_external_address(address.clone());
        let relay = server.local_peer_id;
        let address = address.with(Protocol::P2p(relay));
        let mut sender = node();
        let mut receiver = node();
        let peer = receiver.local_peer_id;
        let sender_peer = sender.local_peer_id;
        let receive_outer = connect(&mut receiver, &mut server, &address).await;
        let outer = connect(&mut sender, &mut server, &address).await;
        let sibling = connect(&mut sender, &mut server, &address).await;
        let owners = sender.swarm.behaviour().connection_retention.physical_routes().unwrap().clone();
        let physical = owners.connection(relay, outer).unwrap();
        assert_eq!(physical.lease.context.protocol, protocol);
        assert_ne!(physical.lease.local_addr, owners.connection(relay, sibling).unwrap().lease.local_addr);
        assert!(established_binding_fields(sender.swarm.behaviour(), relay, outer).is_none(), "a direct physical owner is not a circuit");
        let receiver_physical = receiver.swarm.behaviour().connection_retention.physical_routes().unwrap().connection(relay, receive_outer).unwrap();
        let listener = receiver.swarm.listen_on(address.clone().with(Protocol::P2pCircuit)).unwrap();
        assert!(receiver.swarm.behaviour_mut().relay.pin_reservation_listener(relay, listener, receive_outer));
        loop {
            tokio::select! {
                event = receiver.swarm.select_next_some() => {
                    if let SwarmEvent::NewListenAddr { listener_id, .. } = event
                        && listener_id == listener {
                        assert_eq!(receiver.swarm.behaviour().relay.reservation_listener_connection(relay, listener), Some(receive_outer));
                        break;
                    }
                },
                _ = server.swarm.select_next_some() => {},
                _ = sender.swarm.select_next_some() => {},
            }
        }
        let options = DialOpts::peer_id(peer)
            .addresses(vec![address.with(Protocol::P2pCircuit).with(Protocol::P2p(peer))])
            .condition(PeerCondition::Always)
            .build();
        let inner = options.connection_id();
        sender.swarm.dial(options).unwrap();
        let _pin = sender.swarm.behaviour_mut().relay.pin_circuit_dial(peer, inner, relay, outer).unwrap();
        assert!(sender.swarm.behaviour_mut().relay.prefer_relay_connection(relay, sibling));
        let mut sent = false;
        let mut received = None;
        while !sent || received.is_none() {
            tokio::select! {
                event = sender.swarm.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } if peer_id == peer => {
                        assert_eq!(connection_id, inner);
                        assert!(endpoint.is_relayed());
                        assert_fields(sender.swarm.behaviour(), peer, inner, relay, outer, &physical);
                        sent = true;
                    }
                    SwarmEvent::OutgoingConnectionError { error, .. } => panic!("authenticated circuit dial failed: {error}"),
                    _ => {},
                },
                event = receiver.swarm.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } = event
                        && peer_id == sender_peer {
                        assert!(endpoint.is_relayed());
                        assert_fields(receiver.swarm.behaviour(), sender_peer, connection_id, relay, receive_outer, &receiver_physical);
                        received = Some(connection_id);
                    }
                },
                _ = server.swarm.select_next_some() => {},
            }
        }
        assert!(established_binding_fields(sender.swarm.behaviour(), Libp2pPeerId::random(), inner).is_none());
        assert!(established_binding_fields(sender.swarm.behaviour(), peer, ConnectionId::new_unchecked(usize::MAX)).is_none());

        // Keep the native authenticated mapping; vary only the diagnostic's
        // physical registry to exercise absent, mismatched, and revoked tokens.
        let original = std::mem::take(&mut sender.swarm.behaviour_mut().connection_retention);
        assert!(established_binding_fields(sender.swarm.behaviour(), peer, inner).is_none());
        let missing = Arc::new(ControlRoutes::new(4));
        sender.swarm.behaviour_mut().connection_retention =
            crate::runtime::connection_retention::Behaviour::with_physical_routes(missing.clone());
        assert_eq!(binding(sender.swarm.behaviour(), peer, inner, true), Some(Route { relay, outer }));
        assert!(established_binding_fields(sender.swarm.behaviour(), peer, inner).is_none());
        let wrong_peer = missing.register(Libp2pPeerId::random(), physical.lease.clone()).unwrap();
        wrong_peer.bind_connection(outer).unwrap();
        wrong_peer.adopt().unwrap();
        assert!(established_binding_fields(sender.swarm.behaviour(), peer, inner).is_none());
        drop(wrong_peer);
        let wrong_outer = missing.register(relay, physical.lease.clone()).unwrap();
        wrong_outer.bind_connection(sibling).unwrap();
        wrong_outer.adopt().unwrap();
        assert!(established_binding_fields(sender.swarm.behaviour(), peer, inner).is_none());
        drop(wrong_outer);
        let unadopted = missing.register(relay, physical.lease.clone()).unwrap();
        unadopted.bind_connection(outer).unwrap();
        assert!(missing.bound_connection(relay, outer).is_some());
        assert!(established_binding_fields(sender.swarm.behaviour(), peer, inner).is_none());
        unadopted.adopt().unwrap();
        drop(unadopted);
        assert!(missing.connection(relay, outer).is_none());
        assert!(established_binding_fields(sender.swarm.behaviour(), peer, inner).is_none());
        sender.swarm.behaviour_mut().connection_retention = original;
        assert_fields(sender.swarm.behaviour(), peer, inner, relay, outer, &physical);
        log_established_binding(sender.swarm.behaviour(), peer, inner);
        assert!(sender.swarm.close_connection(inner));
        while sender.swarm.behaviour().relay.circuit_connection_owner(peer, inner).is_some() {
            tokio::select! {
                _ = sender.swarm.select_next_some() => {},
                _ = receiver.swarm.select_next_some() => {},
                _ = server.swarm.select_next_some() => {},
            }
        }
        assert!(physical.is_live(), "an extant physical sibling cannot resurrect a closed circuit mapping");
        assert!(established_binding_fields(sender.swarm.behaviour(), peer, inner).is_none());
    }).await.expect("bounded native circuit diagnostic fixture");
}
