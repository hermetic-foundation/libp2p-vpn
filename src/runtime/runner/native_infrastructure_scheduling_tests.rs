use super::*;
use crate::{
    identity::NodeIdentity,
    runtime::{
        connection_retention::IdentifiedServices,
        physical_network::control::{ControlRoutes, Registration},
    },
};
use libp2p::swarm::{FromSwarm, NetworkBehaviour};

async fn stale_owner(
    routes: &Arc<ControlRoutes>,
    peer: Libp2pPeerId,
    id: ConnectionId,
) -> Registration {
    let (_, mut lease) = routes
        .egress
        .prepare_tcp("127.0.0.1:4001".parse().unwrap(), false, &[])
        .await
        .unwrap();
    lease.route.interface_index = lease.route.interface_index.checked_add(1).unwrap();
    let owner = routes.register(peer, lease).unwrap();
    owner.bind_connection(id).unwrap();
    owner.adopt().unwrap();
    owner
}

async fn await_stale_audit(
    schedule: &mut InfrastructureHandoffSchedule,
    node: &mut P2pNode,
    routes: &ControlRoutes,
    peer: Libp2pPeerId,
    id: ConnectionId,
) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let event = schedule.next_swarm_event(&mut node.swarm).await;
            if routes.connection(peer, id).unwrap().refresh_required() == Some(true) {
                assert!(event.is_none(), "audit must wake without a swarm event");
                return;
            }
        }
    })
    .await
    .expect("route audit must not wait for the ten-second redial tick");
}

#[tokio::test]
async fn completed_audits_wake_pending_swarm_and_unchanged_routes_stay_quiet() {
    let mut node = tests::membership_sync_test_node(NodeIdentity::generate_ed25519().unwrap());
    let routes = node
        .swarm
        .behaviour()
        .connection_retention
        .physical_routes()
        .unwrap()
        .clone();
    let peer = Libp2pPeerId::random();
    let id = ConnectionId::new_unchecked(1701);
    let owner = stale_owner(&routes, peer, id).await;
    let mut schedule = InfrastructureHandoffSchedule::default();
    await_stale_audit(&mut schedule, &mut node, &routes, peer, id).await;
    assert!(
        tokio::time::timeout(
            Duration::from_millis(80),
            schedule.next_swarm_event(&mut node.swarm),
        )
        .await
        .is_err(),
        "unchanged audits must not create an always-ready runner branch"
    );
    drop(owner);
    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            schedule.next_swarm_event(&mut node.swarm),
        )
        .await
        .expect("owner retirement must wake the runner")
        .is_none()
    );
}

#[tokio::test]
async fn idle_handoff_has_no_deadline_or_periodic_wake() {
    let node = tests::membership_sync_test_node(NodeIdentity::generate_ed25519().unwrap());
    let schedule = InfrastructureHandoffSchedule::default();
    assert!(
        schedule
            .next_deadline(&node.swarm, Instant::now())
            .is_none()
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(80),
            infrastructure_handoff_deadline_due(None),
        )
        .await
        .is_err()
    );
}

#[test]
fn relay_completion_and_native_lifecycle_events_wake_handoff() {
    let peer = Libp2pPeerId::random();
    let id = ConnectionId::new_unchecked(1702);
    let endpoint = ConnectedPoint::Listener {
        local_addr: "/ip4/127.0.0.1/tcp/4001".parse().unwrap(),
        send_back_addr: "/ip4/127.0.0.1/tcp/4001".parse().unwrap(),
    };
    assert!(infrastructure_handoff_event(
        &SwarmEvent::ConnectionEstablished {
            peer_id: peer,
            connection_id: id,
            endpoint: endpoint.clone(),
            num_established: std::num::NonZeroU32::new(1).unwrap(),
            concurrent_dial_errors: None,
            established_in: Duration::ZERO,
        }
    ));
    assert!(infrastructure_handoff_event(
        &SwarmEvent::ConnectionClosed {
            peer_id: peer,
            connection_id: id,
            endpoint,
            num_established: 0,
            cause: None,
        }
    ));
    assert!(infrastructure_handoff_event(&SwarmEvent::Behaviour(
        BehaviourEvent::Relay(relay::client::Event::ReservationReqAccepted {
            relay_peer_id: peer,
            renewal: false,
            limit: None,
        }),
    )));
    assert!(infrastructure_handoff_event(&SwarmEvent::NewListenAddr {
        listener_id: ListenerId::next(),
        address: "/ip4/127.0.0.1/tcp/4001".parse().unwrap(),
    }));
    assert!(!infrastructure_handoff_event(&SwarmEvent::Dialing {
        peer_id: Some(peer),
        connection_id: id,
    }));
}

#[allow(clippy::too_many_arguments)]
fn drive(
    node: &mut P2pNode,
    epochs: &mut ConnectionEpochs,
    forwarder: &Forwarder,
    membership: &OverlayMembership,
    peer: Libp2pPeerId,
    connections: &HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
    now: Instant,
) {
    let mut routing = RoutingInfrastructurePeers::default();
    routing.admit(peer);
    advance_infrastructure_handoff(&mut physical_infrastructure_handoff::Context {
        swarm: &mut node.swarm,
        epochs,
        forwarder,
        membership_scope: MembershipValidationScope {
            network: &forwarder.config().network.name,
            current_tag: None,
            previous_tags: &[],
        },
        membership,
        routing: &routing,
        infrastructure: &InfrastructurePeers::default(),
        auto_relay: &mut AutoRelayState::default(),
        readiness: &mut RelayReadiness::default(),
        configured_listeners: &mut HashSet::new(),
        retiring_listeners: &mut HashSet::new(),
        pairing: &CodePairingSessions::new(),
        probes: &MembershipProbeConnections::default(),
        relays: &[],
        bootstrap: &[(
            peer,
            format!("/ip4/127.0.0.1/tcp/9/p2p/{peer}").parse().unwrap(),
        )],
        discovered: &DiscoveredPeerAddresses::default(),
        connections,
        now,
    });
}

#[tokio::test]
async fn stale_infrastructure_schedules_settle_then_connect_deadline_without_redial() {
    let identity = NodeIdentity::generate_ed25519().unwrap();
    let config: Config = serde_json::from_value(serde_json::json!({
        "network": {"name": "lab", "private_key": identity.private_key},
        "peers": []
    }))
    .unwrap();
    let forwarder = Forwarder::from_config(&config).unwrap();
    let membership = OverlayMembership::from_config(&config).unwrap();
    let mut node = tests::membership_sync_test_node(identity);
    let routes = node
        .swarm
        .behaviour()
        .connection_retention
        .physical_routes()
        .unwrap()
        .clone();
    let peer = Libp2pPeerId::random();
    let id = ConnectionId::new_unchecked(1703);
    let _owner = stale_owner(&routes, peer, id).await;
    let endpoint = ConnectedPoint::Listener {
        local_addr: "/ip4/127.0.0.1/tcp/4001".parse().unwrap(),
        send_back_addr: "/ip4/127.0.0.1/tcp/4001".parse().unwrap(),
    };
    let retention = &mut node.swarm.behaviour_mut().connection_retention;
    retention.on_swarm_event(FromSwarm::ConnectionEstablished(
        libp2p::swarm::behaviour::ConnectionEstablished {
            peer_id: peer,
            connection_id: id,
            endpoint: &endpoint,
            failed_addresses: &[],
            other_established: 0,
        },
    ));
    assert!(retention.record_services(
        peer,
        id,
        IdentifiedServices {
            primary_dht: true,
            ..Default::default()
        },
    ));
    let mut epochs = ConnectionEpochs::default();
    epochs.record_started(id);
    assert!(epochs.record_established(id));
    let connections = HashMap::from([((peer, id), endpoint)]);
    let mut schedule = InfrastructureHandoffSchedule::default();
    await_stale_audit(&mut schedule, &mut node, &routes, peer, id).await;
    let start = Instant::now();
    drive(
        &mut node,
        &mut epochs,
        &forwarder,
        &membership,
        peer,
        &connections,
        start,
    );
    let settle = schedule.next_deadline(&node.swarm, start).unwrap();
    assert_eq!(settle, start + Duration::from_secs(1));
    assert!(
        tokio::time::timeout(
            Duration::from_millis(80),
            infrastructure_handoff_deadline_due(Some(settle)),
        )
        .await
        .is_err(),
        "route events must not bypass settling"
    );
    assert_eq!(schedule.next_deadline(&node.swarm, start), Some(settle));
    tokio::time::timeout(
        Duration::from_secs(2),
        infrastructure_handoff_deadline_due(Some(settle)),
    )
    .await
    .expect("settle wake must not wait for redial");
    drive(
        &mut node,
        &mut epochs,
        &forwarder,
        &membership,
        peer,
        &connections,
        settle,
    );
    assert_eq!(
        schedule.next_deadline(&node.swarm, settle),
        Some(settle + Duration::from_secs(30)),
        "a pending dial must sleep until its stage deadline, not poll every second"
    );
    let connect_deadline = settle + Duration::from_secs(30);
    drive(
        &mut node,
        &mut epochs,
        &forwarder,
        &membership,
        peer,
        &connections,
        connect_deadline,
    );
    assert_eq!(
        schedule.next_deadline(&node.swarm, connect_deadline),
        Some(connect_deadline + Duration::from_secs(10)),
        "stage timeout must preserve the existing retry backoff"
    );
}
