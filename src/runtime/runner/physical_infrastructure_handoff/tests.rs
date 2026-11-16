use super::*;
use crate::runtime::physical_network::linux::control::{ControlRoutes, Registration};
use std::sync::Arc;

async fn register(
    owners: &Arc<ControlRoutes>,
    peer: Libp2pPeerId,
    id: ConnectionId,
) -> Registration {
    let (_, lease) = owners
        .egress
        .prepare_tcp("127.0.0.1:4001".parse().unwrap(), false, &[])
        .await
        .unwrap();
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

struct Fixture {
    node: P2pNode,
    forwarder: Forwarder,
    membership: OverlayMembership,
    routing: RoutingInfrastructurePeers,
    infrastructure: InfrastructurePeers,
    auto_relay: AutoRelayState,
    pairing: CodePairingSessions,
    probes: MembershipProbeConnections,
    discovered: DiscoveredPeerAddresses,
    epochs: ConnectionEpochs,
    connections: HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
    bootstrap: Vec<(Libp2pPeerId, Multiaddr)>,
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
            pairing: CodePairingSessions::new(),
            probes: MembershipProbeConnections::default(),
            discovered: DiscoveredPeerAddresses::default(),
            epochs: ConnectionEpochs::default(),
            connections: HashMap::new(),
            bootstrap: Vec::new(),
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
            auto_relay: &self.auto_relay,
            pairing: &self.pairing,
            probes: &self.probes,
            relays: &[],
            bootstrap: &self.bootstrap,
            discovered: &self.discovered,
            connections: &self.connections,
            now: Instant::now(),
        });
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
            SwarmEvent::OutgoingConnectionError { error, .. } => {
                panic!("unexpected candidate dial failure: {error}")
            }
            _ => {}
        }
    }

    async fn until(&mut self, server: &mut P2pNode, ready: impl Fn(&Self) -> bool) {
        tokio::time::timeout(Duration::from_secs(8), async {
            while !ready(self) {
                tokio::select! {
                    event = self.node.swarm.select_next_some() => self.event(event),
                    _ = server.swarm.select_next_some() => {},
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                }
                self.drive();
            }
        })
        .await
        .expect("bounded infrastructure handoff progress");
    }
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
