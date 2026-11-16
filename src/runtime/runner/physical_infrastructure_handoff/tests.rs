use super::*;
use crate::runtime::physical_network::linux::control::{ControlRoutes, Registration};
use std::sync::Arc;

mod quic_namespace;

async fn register(
    owners: &Arc<ControlRoutes>,
    peer: Libp2pPeerId,
    id: ConnectionId,
) -> Registration {
    register_with_protocol(owners, peer, id, SocketProtocol::Tcp, false).await
}

async fn register_with_protocol(
    owners: &Arc<ControlRoutes>,
    peer: Libp2pPeerId,
    id: ConnectionId,
    protocol: SocketProtocol,
    stale: bool,
) -> Registration {
    let destination = "127.0.0.1:4001".parse().unwrap();
    let mut lease = match protocol {
        SocketProtocol::Tcp => {
            owners
                .egress
                .prepare_tcp(destination, false, &[])
                .await
                .unwrap()
                .1
        }
        SocketProtocol::Udp => owners.egress.prepare(destination).await.unwrap().1,
    };
    if stale {
        lease.route.interface_index = lease.route.interface_index.checked_add(1).unwrap();
    }
    let owner = owners.register(peer, lease).unwrap();
    owner.bind_connection(id).unwrap();
    owner.adopt().unwrap();
    owner
}

#[tokio::test]
async fn protection_is_exact_and_exhaustion_does_not_become_an_idle_retry_timer() {
    let peer = Libp2pPeerId::random();
    let owners = Arc::new(ControlRoutes::new(4));
    let id = ConnectionId::new_unchecked(1);
    let candidate = ConnectionId::new_unchecked(2);
    let _owner = register(&owners, peer, id).await;
    let anchor = owners.connection(peer, id).unwrap();
    let now = Instant::now();
    let mut state = State::default();
    state.rounds.insert(
        peer,
        Round {
            replacement_protocol: Some(anchor.lease.context.protocol),
            epoch: anchor.lease.epoch(),
            anchor,
            required: IdentifiedServices {
                primary_dht: true,
                ..Default::default()
            },
            attempts: MAX_ATTEMPTS,
            recovery: Recovery::default(),
            phase: Phase::Dialing(candidate, now + CONNECT_WINDOW),
        },
    );
    assert!(state.protects(peer, id));
    assert!(state.protects(peer, candidate));
    assert!(!state.protects(peer, ConnectionId::new_unchecked(3)));
    assert!(!state.protects(Libp2pPeerId::random(), id));
    assert!(state.is_candidate(peer, candidate));
    let round = state.rounds.get_mut(&peer).unwrap();
    retry(round, now);
    assert!(matches!(round.phase, Phase::Exhausted));
    assert!(
        round
            .recovery
            .rearm(&[], None, now + Duration::from_secs(86400))
            .is_none()
    );
    assert!(!state.protects(peer, id));
    assert!(!state.is_candidate(peer, candidate));
}

#[tokio::test]
async fn validated_owner_is_exact_and_survives_fallback_loss_but_not_candidate_drop() {
    let peer = Libp2pPeerId::random();
    let owners = Arc::new(ControlRoutes::new(4));
    let first = ConnectionId::new_unchecked(1);
    let second = ConnectionId::new_unchecked(2);
    let first_owner = register(&owners, peer, first).await;
    let second_owner = register(&owners, peer, second).await;
    let anchor = owners.connection(peer, first).unwrap();
    let mut round = Round {
        replacement_protocol: Some(anchor.lease.context.protocol),
        epoch: anchor.lease.epoch(),
        anchor,
        required: IdentifiedServices {
            primary_dht: true,
            ..Default::default()
        },
        attempts: 1,
        recovery: Recovery::default(),
        phase: Phase::Dialing(second, Instant::now() + CONNECT_WINDOW),
    };
    drop(first_owner);
    assert!(
        round.current(&owners.snapshot()),
        "an owned replacement survives losing its fallback"
    );
    round.phase = Phase::Draining(second, Instant::now() + DRAIN_WINDOW);
    assert!(round.current(&owners.snapshot()));
    assert!(!round.current(&[]));
    let candidate = owners.connection(peer, second).unwrap();
    assert!(candidate_is_current(&candidate, &round.epoch));
    owners.egress.retire_observer_for_test();
    assert!(
        !candidate_is_current(&candidate, &round.epoch),
        "retired observer results cannot validate a candidate"
    );
    assert!(
        round.current(std::slice::from_ref(&candidate)),
        "already validated service awaits a fresh audit"
    );
    drop(second_owner);
    assert!(!round.current(std::slice::from_ref(&candidate)));
}

#[tokio::test]
async fn public_service_reuse_and_dialing_accept_selected_alternate_with_exact_identify() {
    use libp2p::swarm::{FromSwarm, NetworkBehaviour};
    for dialing in [false, true] {
        for protocol in [SocketProtocol::Tcp, SocketProtocol::Udp] {
            for identified in [false, true] {
                let peer = Libp2pPeerId::random();
                let mut fixture = Fixture::new(peer);
                let owners = fixture
                    .node
                    .swarm
                    .behaviour()
                    .connection_retention
                    .physical_routes()
                    .unwrap()
                    .clone();
                let old = ConnectionId::new_unchecked(800);
                let candidate = ConnectionId::new_unchecked(801);
                let _old_owner =
                    register_with_protocol(&owners, peer, old, SocketProtocol::Udp, true).await;
                let _new_owner =
                    register_with_protocol(&owners, peer, candidate, protocol, false).await;
                let required = IdentifiedServices {
                    primary_dht: true,
                    ..Default::default()
                };
                for (id, protocol) in [(old, SocketProtocol::Udp), (candidate, protocol)] {
                    let transport = match protocol {
                        SocketProtocol::Tcp => "tcp/4001",
                        SocketProtocol::Udp => "udp/4001/quic-v1",
                    };
                    let endpoint = ConnectedPoint::Listener {
                        local_addr: format!("/ip4/127.0.0.1/{transport}").parse().unwrap(),
                        send_back_addr: format!("/ip4/127.0.0.1/{transport}").parse().unwrap(),
                    };
                    let retention = &mut fixture.node.swarm.behaviour_mut().connection_retention;
                    retention.on_swarm_event(FromSwarm::ConnectionEstablished(
                        libp2p::swarm::behaviour::ConnectionEstablished {
                            peer_id: peer,
                            connection_id: id,
                            endpoint: &endpoint,
                            failed_addresses: &[],
                            other_established: 0,
                        },
                    ));
                    if id == old || identified {
                        assert!(retention.record_services(peer, id, required));
                    }
                    fixture.epochs.record_started(id);
                    assert!(fixture.epochs.record_established(id));
                    fixture.connections.insert((peer, id), endpoint);
                }
                let mut observer =
                    crate::runtime::physical_network::linux::control::reconcile::Reconciler::new(
                        owners.clone(),
                    );
                let anchor = tokio::time::timeout(
                    Duration::from_secs(5),
                    futures::future::poll_fn(|cx| {
                        observer.poll(cx);
                        match owners
                            .connection(peer, old)
                            .filter(|route| route.refresh_required() == Some(true))
                        {
                            Some(route) => std::task::Poll::Ready(route),
                            None => std::task::Poll::Pending,
                        }
                    }),
                )
                .await
                .expect("exact stale anchor audit");
                let epoch = anchor.inspection_epoch().unwrap();
                let round = Round {
                    replacement_protocol: dialing.then_some(protocol),
                    anchor,
                    epoch,
                    required,
                    attempts: 0,
                    recovery: Recovery::default(),
                    phase: if dialing {
                        Phase::Dialing(candidate, Instant::now() + CONNECT_WINDOW)
                    } else {
                        Phase::Waiting(Instant::now())
                    },
                };
                assert!(candidate_is_current(
                    &owners.connection(peer, candidate).unwrap(),
                    &round.epoch
                ));
                fixture
                    .node
                    .swarm
                    .behaviour_mut()
                    .connection_retention
                    .infrastructure_handoff
                    .rounds
                    .insert(peer, round);
                fixture.drive();
                let round = &fixture
                    .node
                    .swarm
                    .behaviour()
                    .connection_retention
                    .infrastructure_handoff
                    .rounds[&peer];
                assert_eq!(
                    matches!(round.phase, Phase::Draining(id, _) if id == candidate),
                    identified,
                    "dialing={dialing}, protocol={protocol:?}, identified={identified}"
                );
                assert!(
                    fixture.epochs.is_usable(old),
                    "retain the fallback until matching exact proof"
                );
            }
        }
    }
}

#[tokio::test]
async fn public_service_validation_rejects_a_snapshot_different_from_the_selected_protocol() {
    let peer = Libp2pPeerId::random();
    let owners = Arc::new(ControlRoutes::new(4));
    let old = ConnectionId::new_unchecked(1);
    let candidate = ConnectionId::new_unchecked(2);
    let _old_owner = register_with_protocol(&owners, peer, old, SocketProtocol::Udp, false).await;
    let _new_owner = register(&owners, peer, candidate).await;
    let anchor = owners.connection(peer, old).unwrap();
    let mut round = Round {
        replacement_protocol: Some(anchor.lease.context.protocol),
        epoch: anchor.lease.epoch(),
        anchor,
        required: IdentifiedServices {
            primary_dht: true,
            ..Default::default()
        },
        attempts: 1,
        recovery: Recovery::default(),
        phase: Phase::Draining(candidate, Instant::now() + DRAIN_WINDOW),
    };
    let tcp = owners.connection(peer, candidate).unwrap();
    assert!(candidate_is_current(&tcp, &round.epoch));
    assert!(!round.candidate_is_current(&tcp));
    assert!(!round.current(&owners.snapshot()));
    round.phase = Phase::Complete(candidate);
    assert!(!round.current(&owners.snapshot()));
    owners.egress.retire_observer_for_test();
    assert!(validated_path_awaits_audit(&tcp));
    assert!(
        !round.current(&owners.snapshot()),
        "pending audit cannot erase a protocol mismatch"
    );

    let mut fixture = Fixture::new(peer);
    fixture.bootstrap = vec![
        (peer, "/ip4/127.0.0.1/tcp/4001".parse().unwrap()),
        (peer, "/ip4/127.0.0.1/udp/4001/quic-v1".parse().unwrap()),
        (
            peer,
            "/ip4/127.0.0.1/udp/4001/quic-v1/webtransport"
                .parse()
                .unwrap(),
        ),
    ];
    let context = Context {
        swarm: &mut fixture.node.swarm,
        epochs: &mut fixture.epochs,
        forwarder: &fixture.forwarder,
        membership: &fixture.membership,
        routing: &fixture.routing,
        infrastructure: &fixture.infrastructure,
        auto_relay: &mut fixture.auto_relay,
        readiness: &mut fixture.readiness,
        configured_listeners: &mut fixture.node.configured_relay_reservation_listeners,
        retiring_listeners: &mut fixture.node.retiring_configured_relay_reservation_listeners,
        pairing: &fixture.pairing,
        probes: &fixture.probes,
        relays: &fixture.relays,
        bootstrap: &fixture.bootstrap,
        discovered: &fixture.discovered,
        connections: &fixture.connections,
        now: Instant::now(),
    };
    assert_eq!(
        addresses(&context, peer, &round.anchor),
        vec![
            format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{peer}")
                .parse::<Multiaddr>()
                .unwrap(),
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{peer}")
                .parse::<Multiaddr>()
                .unwrap(),
        ]
    );
}

#[tokio::test]
async fn mixed_stale_owners_share_recovery_and_require_the_union_of_exact_services() {
    use libp2p::swarm::{FromSwarm, NetworkBehaviour};
    for primary in [SocketProtocol::Tcp, SocketProtocol::Udp] {
        let alternate = match primary {
            SocketProtocol::Tcp => SocketProtocol::Udp,
            SocketProtocol::Udp => SocketProtocol::Tcp,
        };
        let peer = Libp2pPeerId::random();
        let mut fixture = Fixture::new(peer);
        let owners = fixture
            .node
            .swarm
            .behaviour()
            .connection_retention
            .physical_routes()
            .unwrap()
            .clone();
        let first = ConnectionId::new_unchecked(800);
        let second = ConnectionId::new_unchecked(801);
        let candidate = ConnectionId::new_unchecked(802);
        let failed = ConnectionId::new_unchecked(803);
        let first_owner = register_with_protocol(&owners, peer, first, primary, true).await;
        let second_owner = register_with_protocol(&owners, peer, second, alternate, true).await;
        let _candidate_owner =
            register_with_protocol(&owners, peer, candidate, alternate, false).await;
        let primary_services = IdentifiedServices {
            primary_dht: true,
            ..Default::default()
        };
        let public_services = IdentifiedServices {
            public_dht: true,
            ..Default::default()
        };
        let mut union = primary_services;
        union.include(public_services);
        for (id, protocol, services) in [
            (first, primary, primary_services),
            (second, alternate, public_services),
            (candidate, alternate, primary_services),
        ] {
            let transport = match protocol {
                SocketProtocol::Tcp => "tcp/4001",
                SocketProtocol::Udp => "udp/4001/quic-v1",
            };
            let endpoint = ConnectedPoint::Listener {
                local_addr: format!("/ip4/127.0.0.1/{transport}").parse().unwrap(),
                send_back_addr: format!("/ip4/127.0.0.1/{transport}").parse().unwrap(),
            };
            let retention = &mut fixture.node.swarm.behaviour_mut().connection_retention;
            retention.on_swarm_event(FromSwarm::ConnectionEstablished(
                libp2p::swarm::behaviour::ConnectionEstablished {
                    peer_id: peer,
                    connection_id: id,
                    endpoint: &endpoint,
                    failed_addresses: &[],
                    other_established: 0,
                },
            ));
            assert!(retention.record_services(peer, id, services));
            fixture.epochs.record_started(id);
            assert!(fixture.epochs.record_established(id));
            fixture.connections.insert((peer, id), endpoint);
        }
        let mut observer =
            crate::runtime::physical_network::linux::control::reconcile::Reconciler::new(
                owners.clone(),
            );
        tokio::time::timeout(
            Duration::from_secs(5),
            futures::future::poll_fn(|cx| {
                observer.poll(cx);
                if [first, second]
                    .into_iter()
                    .all(|id| owners.connection(peer, id).unwrap().refresh_required() == Some(true))
                {
                    std::task::Poll::Ready(())
                } else {
                    std::task::Poll::Pending
                }
            }),
        )
        .await
        .expect("both exact stale owner audits");
        let anchor = owners.connection(peer, first).unwrap();
        let epoch = anchor.inspection_epoch().unwrap();
        fixture
            .node
            .swarm
            .behaviour_mut()
            .connection_retention
            .infrastructure_handoff
            .rounds
            .insert(
                peer,
                Round {
                    anchor,
                    epoch,
                    replacement_protocol: Some(primary),
                    required: primary_services,
                    attempts: 1,
                    recovery: Recovery::default(),
                    phase: Phase::Dialing(failed, Instant::now() + CONNECT_WINDOW),
                },
            );
        fixture.epochs.record_started(failed);
        fixture.epochs.mark_retiring(failed);
        fixture.drive();
        {
            let state = &mut fixture
                .node
                .swarm
                .behaviour_mut()
                .connection_retention
                .infrastructure_handoff;
            assert_eq!(state.rounds.len(), 1);
            let round = state.rounds.get_mut(&peer).unwrap();
            assert!(matches!(round.phase, Phase::Waiting(_)));
            assert_eq!(round.replacement_protocol, None);
            assert_eq!(round.required, union);
            round.phase = Phase::Waiting(Instant::now());
        }
        fixture.drive();
        {
            let round = fixture
                .node
                .swarm
                .behaviour_mut()
                .connection_retention
                .infrastructure_handoff
                .rounds
                .get_mut(&peer)
                .unwrap();
            assert!(
                !matches!(round.phase, Phase::Draining(..)),
                "partial Identify services cannot drain either owner"
            );
            assert!(round.attempts < MAX_ATTEMPTS);
            round.phase = Phase::Waiting(Instant::now());
        }
        assert!(
            fixture
                .node
                .swarm
                .behaviour_mut()
                .connection_retention
                .record_services(peer, candidate, union)
        );
        fixture.drive();
        {
            let state = &fixture
                .node
                .swarm
                .behaviour()
                .connection_retention
                .infrastructure_handoff;
            assert_eq!(state.rounds.len(), 1);
            let round = &state.rounds[&peer];
            assert!(matches!(round.phase, Phase::Draining(id, _) if id == candidate));
            assert_eq!(round.replacement_protocol, Some(alternate));
            assert_eq!(
                round.event("tcp", "quic"),
                if alternate == SocketProtocol::Tcp {
                    "tcp"
                } else {
                    "quic"
                }
            );
            assert_eq!(
                fallback_routes(&owners.snapshot(), peer, candidate, round).count(),
                2
            );
        }
        fixture.drive();
        assert!(!fixture.epochs.is_usable(first));
        assert!(!fixture.epochs.is_usable(second));
        assert!(fixture.epochs.is_usable(candidate));
        drop(first_owner);
        drop(second_owner);
        fixture.drive();
        fixture.drive();
        assert!(
            fixture
                .node
                .swarm
                .behaviour()
                .connection_retention
                .infrastructure_handoff
                .rounds
                .is_empty(),
            "neither protocol leaves a permanently blocking peer round"
        );
    }
}

struct Fixture {
    node: P2pNode,
    forwarder: Forwarder,
    membership: OverlayMembership,
    routing: RoutingInfrastructurePeers,
    infrastructure: InfrastructurePeers,
    auto_relay: AutoRelayState,
    readiness: RelayReadiness,
    pairing: CodePairingSessions,
    probes: MembershipProbeConnections,
    discovered: DiscoveredPeerAddresses,
    epochs: ConnectionEpochs,
    connections: HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
    bootstrap: Vec<(Libp2pPeerId, Multiaddr)>,
    relays: Vec<(Libp2pPeerId, Multiaddr)>,
    require_incoming: bool,
}

#[tokio::test]
async fn losing_last_connection_does_not_cancel_an_already_owned_infrastructure_recovery() {
    let peer = Libp2pPeerId::random();
    let mut fixture = Fixture::new(peer);
    let owners = fixture
        .node
        .swarm
        .behaviour()
        .connection_retention
        .physical_routes()
        .unwrap()
        .clone();
    let old = ConnectionId::new_unchecked(800);
    let candidate = ConnectionId::new_unchecked(801);
    let owner = register(&owners, peer, old).await;
    let anchor = owners.connection(peer, old).unwrap();
    let epoch = anchor.lease.epoch();
    fixture
        .node
        .swarm
        .behaviour_mut()
        .connection_retention
        .infrastructure_handoff
        .rounds
        .insert(
            peer,
            Round {
                replacement_protocol: Some(anchor.lease.context.protocol),
                anchor,
                epoch,
                required: IdentifiedServices {
                    public_dht: true,
                    ..Default::default()
                },
                attempts: 1,
                recovery: Recovery::default(),
                phase: Phase::Dialing(candidate, Instant::now() + CONNECT_WINDOW),
            },
        );
    fixture.epochs.record_started(candidate);
    fixture.routing.remove(peer);
    drop(owner);
    fixture.drive();
    assert!(
        fixture
            .node
            .swarm
            .behaviour()
            .connection_retention
            .infrastructure_handoff
            .is_candidate(peer, candidate)
    );
    assert!(fixture.epochs.is_usable(candidate));
}

fn isolated_dht(node: &mut P2pNode) {
    let protocol =
        libp2p::StreamProtocol::try_from_owned(node.discovery.kademlia_protocol.clone()).unwrap();
    node.swarm.behaviour_mut().kad = kad::Behaviour::with_config(
        node.local_peer_id,
        kad::store::MemoryStore::new(node.local_peer_id),
        crate::runtime::p2p::controlled_kademlia_config(protocol),
    );
    node.swarm
        .behaviour_mut()
        .kad
        .set_mode(Some(kad::Mode::Server));
    node.swarm
        .behaviour_mut()
        .kad
        .set_background_jobs_paused(true);
    node.swarm.behaviour_mut().pairing_kad = None.into();
}

impl Fixture {
    fn new(peer: Libp2pPeerId) -> Self {
        let identity = NodeIdentity::generate_ed25519().unwrap();
        let config: Config = serde_json::from_value(serde_json::json!({"network": {"name": "lab", "private_key": identity.private_key}, "peers": []})).unwrap();
        let mut node = super::super::tests::membership_sync_test_node(identity);
        isolated_dht(&mut node);
        let mut routing = RoutingInfrastructurePeers::default();
        routing.admit(peer);
        Self {
            node,
            forwarder: Forwarder::from_config(&config).unwrap(),
            membership: OverlayMembership::from_config(&config).unwrap(),
            routing,
            infrastructure: InfrastructurePeers::default(),
            auto_relay: AutoRelayState::default(),
            readiness: RelayReadiness::default(),
            pairing: CodePairingSessions::new(),
            probes: MembershipProbeConnections::default(),
            discovered: DiscoveredPeerAddresses::default(),
            epochs: ConnectionEpochs::default(),
            connections: HashMap::new(),
            bootstrap: Vec::new(),
            relays: Vec::new(),
            require_incoming: false,
        }
    }

    fn drive(&mut self) {
        drive(&mut Context {
            swarm: &mut self.node.swarm,
            epochs: &mut self.epochs,
            forwarder: &self.forwarder,
            membership: &self.membership,
            routing: &self.routing,
            infrastructure: &self.infrastructure,
            auto_relay: &mut self.auto_relay,
            readiness: &mut self.readiness,
            configured_listeners: &mut self.node.configured_relay_reservation_listeners,
            retiring_listeners: &mut self.node.retiring_configured_relay_reservation_listeners,
            pairing: &self.pairing,
            probes: &self.probes,
            relays: &self.relays,
            bootstrap: &self.bootstrap,
            discovered: &self.discovered,
            connections: &self.connections,
            now: Instant::now(),
        });
        if self.require_incoming {
            assert!(
                self.relays
                    .iter()
                    .all(|(peer, _)| self.readiness.relay_ready(*peer)),
                "handoff lost incoming readiness"
            );
        }
    }

    fn event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            SwarmEvent::Dialing { connection_id, .. } => self.epochs.record_started(connection_id),
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } => {
                assert!(self.epochs.record_established(connection_id));
                self.connections.insert((peer_id, connection_id), endpoint);
                observe_established(&mut self.node.swarm, peer_id, connection_id);
            }
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                connection_id,
                info,
            })) => {
                assert_eq!(info.public_key.to_peer_id(), peer_id);
                let services = IdentifiedServices {
                    primary_dht: identify_protocols_include(
                        &info.protocols,
                        &self.node.discovery.kademlia_protocol,
                    ),
                    public_dht: identify_protocols_include(
                        &info.protocols,
                        PUBLIC_IPFS_KADEMLIA_PROTOCOL,
                    ),
                    relay: identify_protocols_include_relay_hop(&info.protocols),
                    autonat: identify_protocols_include(&info.protocols, "/libp2p/autonat/1.0.0"),
                };
                assert!(
                    self.node
                        .swarm
                        .behaviour_mut()
                        .connection_retention
                        .record_services(peer_id, connection_id, services)
                );
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                ..
            } => {
                self.connections.remove(&(peer_id, connection_id));
                self.epochs.remove(connection_id);
            }
            SwarmEvent::Behaviour(BehaviourEvent::Relay(
                relay::client::Event::ReservationReqAccepted { relay_peer_id, .. },
            )) => {
                self.readiness.record_reservation_accepted(relay_peer_id);
            }
            SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } => {
                if !self
                    .node
                    .retiring_configured_relay_reservation_listeners
                    .contains(&listener_id)
                    && let Some(peer) = relayed_address_relay_peer(&address)
                    && (self
                        .node
                        .configured_relay_reservation_listeners
                        .contains(&listener_id)
                        || self.auto_relay.owns_listener(peer, listener_id)
                        || self
                            .node
                            .swarm
                            .behaviour()
                            .connection_retention
                            .relay_handoff_owns_listener(peer, listener_id))
                    && let Some(base) = relay_base_address_from_relayed_listen_address(&address)
                {
                    self.readiness
                        .record_relay_listen_address(peer, listener_id, base);
                }
            }
            SwarmEvent::ListenerClosed { listener_id, .. } => {
                self.node
                    .swarm
                    .behaviour_mut()
                    .connection_retention
                    .relay_handoff_listener_closed(listener_id);
                self.node
                    .configured_relay_reservation_listeners
                    .remove(&listener_id);
                self.node
                    .retiring_configured_relay_reservation_listeners
                    .remove(&listener_id);
                for (peer, _) in &self.relays {
                    self.readiness.forget_listener(*peer, listener_id);
                }
            }
            SwarmEvent::OutgoingConnectionError { error, .. } => {
                panic!("unexpected candidate dial failure: {error}")
            }
            _ => {}
        }
    }

    async fn until(&mut self, server: &mut P2pNode, ready: impl Fn(&Self) -> bool) {
        let result = tokio::time::timeout(Duration::from_secs(8), async {
            while !ready(self) {
                tokio::select! {
                    event = self.node.swarm.select_next_some() => self.event(event),
                    _ = server.swarm.select_next_some() => {},
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                }
                self.drive();
            }
        })
        .await;
        if result.is_err() {
            for route in self
                .node
                .swarm
                .behaviour()
                .connection_retention
                .physical_routes()
                .unwrap()
                .snapshot()
                .iter()
                .take(16)
            {
                eprintln!(
                    "handoff timeout: route={route:?} refresh={:?} services={:?}",
                    route.refresh_required(),
                    route.connection_id.and_then(|id| self
                        .node
                        .swarm
                        .behaviour()
                        .connection_retention
                        .services(route.peer, id)),
                );
            }
        }
        result.expect("bounded infrastructure handoff progress");
    }
}

#[test]
#[ignore = "isolated namespace; real relay reservation migration and TCP source-route return"]
fn source_route_return_transfers_configured_and_automatic_relay_reservations() {
    use crate::runtime::physical_network::linux::{isolated_namespace, test_ip as ip};
    const NAME: &str = "runtime::runner::physical_infrastructure_handoff::tests::source_route_return_transfers_configured_and_automatic_relay_reservations";
    if !isolated_namespace(NAME) {
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    for address in ["192.0.2.1/32", "198.51.100.1/32", "203.0.113.9/32"] {
        ip(&["addr", "add", address, "dev", "lo"]);
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            for automatic in [false, true] {
                ip(&[
                    "route",
                    "replace",
                    "local",
                    "203.0.113.9/32",
                    "dev",
                    "lo",
                    "table",
                    "local",
                    "src",
                    "192.0.2.1",
                ]);
                let mut server = super::super::tests::membership_sync_test_node(
                    NodeIdentity::generate_ed25519().unwrap(),
                );
                isolated_dht(&mut server);
                server.swarm.behaviour_mut().relay_server = Some(relay::Behaviour::new(
                    server.local_peer_id,
                    relay::Config {
                        reservation_rate_limiters: Vec::new(),
                        ..Default::default()
                    },
                ))
                .into();
                server
                    .swarm
                    .listen_on("/ip4/203.0.113.9/tcp/0".parse().unwrap())
                    .unwrap();
                let address = loop {
                    if let SwarmEvent::NewListenAddr { address, .. } =
                        server.swarm.select_next_some().await
                    {
                        break address;
                    }
                };
                server.swarm.add_external_address(address.clone());
                let peer = server.local_peer_id;
                let mut fixture = Fixture::new(peer);
                fixture.bootstrap.push((peer, address.clone()));
                fixture.relays.push((peer, address.clone()));
                let options = DialOpts::peer_id(peer)
                    .addresses(vec![address.clone()])
                    .allocate_new_port()
                    .build();
                let mut old = options.connection_id();
                fixture
                    .epochs
                    .dial(&mut fixture.node.swarm, options)
                    .unwrap();
                fixture
                    .until(&mut server, |fixture| {
                        fixture
                            .node
                            .swarm
                            .behaviour()
                            .connection_retention
                            .services(peer, old)
                            .is_some_and(|services| services.relay)
                    })
                    .await;
                let listener = fixture
                    .node
                    .swarm
                    .listen_on(address.with(Protocol::P2p(peer)).with(Protocol::P2pCircuit))
                    .unwrap();
                assert!(
                    fixture
                        .node
                        .swarm
                        .behaviour_mut()
                        .relay
                        .pin_reservation_listener(peer, listener, old)
                );
                if automatic {
                    fixture.auto_relay.reservation_listeners.insert(
                        peer,
                        AutoRelayListener {
                            id: listener,
                            connection: old,
                        },
                    );
                } else {
                    fixture
                        .node
                        .configured_relay_reservation_listeners
                        .insert(listener);
                }
                fixture
                    .until(&mut server, |fixture| fixture.readiness.relay_ready(peer))
                    .await;
                if automatic {
                    fixture.auto_relay.record_reservation_accepted(peer);
                }
                fixture.require_incoming = true;
                for source in ["198.51.100.1", "192.0.2.1"] {
                    ip(&[
                        "route",
                        "replace",
                        "local",
                        "203.0.113.9/32",
                        "dev",
                        "lo",
                        "table",
                        "local",
                        "src",
                        source,
                    ]);
                    fixture
                        .until(&mut server, |fixture| {
                            !fixture.connections.contains_key(&(peer, old))
                                && fixture.readiness.relay_ready(peer)
                                && fixture
                                    .node
                                    .swarm
                                    .behaviour()
                                    .relay
                                    .confirmed_reservation_connections(peer)
                                    .any(|id| id != old)
                        })
                        .await;
                    let replacement = fixture
                        .node
                        .swarm
                        .behaviour()
                        .relay
                        .confirmed_reservation_connections(peer)
                        .next()
                        .unwrap();
                    assert_ne!(replacement, old);
                    let owners = fixture
                        .node
                        .swarm
                        .behaviour()
                        .connection_retention
                        .physical_routes()
                        .unwrap();
                    assert!(
                        owners.connection(peer, old).is_none(),
                        "retired TCP owner remains live"
                    );
                    assert_eq!(
                        owners
                            .connection(peer, replacement)
                            .unwrap()
                            .lease
                            .local_addr
                            .ip()
                            .to_string(),
                        source
                    );
                    let bindings = &fixture.readiness.relayed_listen_addresses[&peer];
                    assert_eq!(
                        bindings.len(),
                        1,
                        "duplicate retired listener survived promotion"
                    );
                    let listener = bindings[0].0;
                    assert_eq!(
                        fixture
                            .node
                            .swarm
                            .behaviour()
                            .relay
                            .reservation_listener_connection(peer, listener),
                        Some(replacement)
                    );
                    if automatic {
                        assert_eq!(
                            fixture.auto_relay.reservation_listeners[&peer].connection,
                            replacement
                        );
                    } else {
                        assert!(
                            fixture
                                .node
                                .configured_relay_reservation_listeners
                                .contains(&listener)
                        );
                    }
                    old = replacement;
                }
            }
        });
}

#[test]
#[ignore = "isolated namespace; actual kernel source-route replacement, Noise TCP, Identify and DHT RPCs"]
fn source_route_return_validates_public_service_and_closes_old_tcp_socket() {
    use crate::runtime::physical_network::linux::{isolated_namespace, test_ip as ip};
    const NAME: &str = "runtime::runner::physical_infrastructure_handoff::tests::source_route_return_validates_public_service_and_closes_old_tcp_socket";
    if !isolated_namespace(NAME) {
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    for address in ["192.0.2.1/32", "198.51.100.1/32", "203.0.113.9/32"] {
        ip(&["addr", "add", address, "dev", "lo"]);
    }
    ip(&[
        "route",
        "replace",
        "local",
        "203.0.113.9/32",
        "dev",
        "lo",
        "table",
        "local",
        "src",
        "192.0.2.1",
    ]);
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let mut server = super::super::tests::membership_sync_test_node(NodeIdentity::generate_ed25519().unwrap());
        isolated_dht(&mut server);
        server.swarm.listen_on("/ip4/203.0.113.9/tcp/0".parse().unwrap()).unwrap();
        let address = loop { if let SwarmEvent::NewListenAddr { address, .. } = server.swarm.select_next_some().await { break address; } };
        let peer = server.local_peer_id;
        let mut fixture = Fixture::new(peer);
        fixture.node.swarm.behaviour_mut().kad.set_background_jobs_paused(true);
        fixture.bootstrap.push((peer, address.clone()));
        fixture.node.swarm.behaviour_mut().kad.add_address(&peer, address.clone());
        let options = DialOpts::peer_id(peer).addresses(vec![address]).allocate_new_port().build();
        let mut old = options.connection_id();
        fixture.epochs.dial(&mut fixture.node.swarm, options).unwrap();
        fixture.until(&mut server, |fixture| {
            fixture.node.swarm.behaviour().connection_retention.services(peer, old).is_some()
                && fixture.node.swarm.behaviour().connection_retention.physical_routes().unwrap().connection(peer, old).is_some_and(|route| route.refresh_required() == Some(false))
        }).await;
        for source in ["198.51.100.1", "192.0.2.1"] {
            ip(&["route", "replace", "local", "203.0.113.9/32", "dev", "lo", "table", "local", "src", source]);
            fixture.until(&mut server, |fixture| fixture.node.swarm.behaviour().connection_retention.infrastructure_handoff.rounds.get(&peer).is_some_and(|round| matches!(round.phase, Phase::Draining(..)))).await;
            let replacement = fixture.node.swarm.behaviour().connection_retention.infrastructure_handoff.rounds[&peer].candidate().unwrap();
            assert_ne!(replacement, old);
            let owners = fixture.node.swarm.behaviour().connection_retention.physical_routes().unwrap().clone();
            assert_eq!(owners.connection(peer, replacement).unwrap().lease.local_addr.ip().to_string(), source);
            assert!(owners.connection(peer, old).is_some(), "fallback survives until authenticated validation completes");
            let query = fixture.node.swarm.behaviour_mut().kad.get_closest_peers(peer.to_bytes());
            let mut inbound = false;
            tokio::time::timeout(Duration::from_secs(8), async {
                loop {
                    tokio::select! {
                        event = fixture.node.swarm.select_next_some() => match event {
                            SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { id, result, step, .. })) if id == query && step.last => {
                                assert!(matches!(result, kad::QueryResult::GetClosestPeers(Ok(_))), "{result:?}");
                                break;
                            },
                            event => fixture.event(event),
                        },
                        event = server.swarm.select_next_some() => if matches!(event, SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::InboundRequest { .. }))) { inbound = true; },
                        _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                    }
                    fixture.drive();
                }
            }).await.expect("DHT RPC on promoted physical source");
            assert!(inbound, "not a cache-only query completion");
            fixture.until(&mut server, |fixture| !fixture.connections.contains_key(&(peer, old))).await;
            assert!(owners.connection(peer, old).is_none(), "actual old socket owner is gone, not only close-requested");
            assert!(fixture.epochs.is_usable(replacement));
            old = replacement;
        }
    });
}
