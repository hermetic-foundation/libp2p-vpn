//! Native AutoNAT ownership must outlive request delivery and pending Swarm dials.
use std::time::Duration;

use futures::{StreamExt as _, future::poll_fn};
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, autonat, noise,
    swarm::{
        ConnectionId, DialError, FromSwarm, NetworkBehaviour, SwarmEvent, ToSwarm,
        behaviour::DialFailure,
        dial_opts::{DialOpts, PeerCondition},
    },
    tcp, yamux,
};

const DEADLINE: Duration = Duration::from_secs(10);
const QUIET: Duration = Duration::from_secs(3600);

fn config(boot_delay: Duration, retry_interval: Duration) -> autonat::Config {
    autonat::Config {
        boot_delay,
        retry_interval,
        refresh_interval: QUIET,
        timeout: Duration::from_secs(30),
        use_connected: false,
        only_global_ips: false,
        ..autonat::Config::default()
    }
}

fn host(config: autonat::Config) -> Swarm<autonat::Behaviour> {
    SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|key| autonat::Behaviour::new(key.public().to_peer_id(), config))
        .unwrap()
        .with_swarm_config(|config| config.with_idle_connection_timeout(QUIET))
        .build()
}

async fn listen(swarm: &mut Swarm<autonat::Behaviour>) -> Multiaddr {
    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            return address;
        }
    }
}

async fn connect(
    client: &mut Swarm<autonat::Behaviour>,
    server: &mut Swarm<autonat::Behaviour>,
    address: Multiaddr,
) -> (ConnectionId, ConnectionId) {
    let client_peer = *client.local_peer_id();
    let server_peer = *server.local_peer_id();
    let opts = DialOpts::peer_id(server_peer)
        .condition(PeerCondition::Always)
        .addresses(vec![address])
        .allocate_new_port()
        .build();
    let expected = opts.connection_id();
    client.dial(opts).unwrap();
    let (mut outbound, mut inbound) = (None, None);
    while outbound.is_none() || inbound.is_none() {
        tokio::select! {
            event = client.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished { peer_id, connection_id, .. } => {
                    assert_eq!(peer_id, server_peer);
                    assert_eq!(connection_id, expected);
                    outbound = Some(connection_id);
                }
                SwarmEvent::OutgoingConnectionError { error, .. } => panic!("TCP dial failed: {error}"),
                _ => {},
            },
            event = server.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished { peer_id, connection_id, .. } => {
                    assert_eq!(peer_id, client_peer);
                    inbound = Some(connection_id);
                }
                SwarmEvent::IncomingConnectionError { error, .. } => panic!("TCP accept failed: {error}"),
                _ => {},
            },
        }
    }
    (outbound.unwrap(), inbound.unwrap())
}

#[track_caller]
fn assert_no_pending_transports(swarm: &Swarm<autonat::Behaviour>) {
    assert_eq!(swarm.network_info().connection_counters().num_pending(), 0);
}

#[test]
fn cached_servers_and_future_probe_timers_are_not_pending_work() {
    let mut native = autonat::Behaviour::new(PeerId::random(), config(QUIET, QUIET));
    assert!(!native.has_pending_work());
    native.add_server(
        PeerId::random(),
        Some("/ip4/127.0.0.1/tcp/9".parse().unwrap()),
    );
    native.probe_address("/ip4/127.0.0.1/tcp/10".parse().unwrap());
    for _ in 0..1000 {
        assert!(!native.has_pending_work());
    }
}

#[test]
fn unknown_connection_controls_and_queries_do_not_create_work() {
    let peer = PeerId::random();
    let id = DialOpts::peer_id(peer).build().connection_id();
    let mut native = autonat::Behaviour::new(PeerId::random(), config(QUIET, QUIET));
    for _ in 0..1000 {
        assert!(!native.set_connection_outbound_enabled(&peer, id, false));
        assert!(!native.set_connection_outbound_enabled(&peer, id, true));
        assert!(!native.has_pending_requests_on_connection(&peer, id));
        assert!(!native.has_pending_work());
    }
    assert_eq!(native.nat_status(), autonat::NatStatus::Unknown);
    assert_eq!(native.confidence(), 0);
    assert!(!native.client_probes_paused());
}

#[tokio::test]
async fn disconnected_probe_and_undelivered_failure_remain_busy() {
    tokio::time::timeout(DEADLINE, async {
        let peer = PeerId::random();
        let mut native = autonat::Behaviour::new(PeerId::random(), config(Duration::ZERO, QUIET));
        native.add_server(peer, Some("/ip4/127.0.0.1/tcp/9".parse().unwrap()));
        native.probe_address("/ip4/127.0.0.1/tcp/10".parse().unwrap());
        assert!(!native.has_pending_work());

        let request = poll_fn(|cx| NetworkBehaviour::poll(&mut native, cx)).await;
        assert!(matches!(
            request,
            ToSwarm::GenerateEvent(autonat::Event::OutboundProbe(
                autonat::OutboundProbeEvent::Request { peer: owner, .. }
            )) if owner == peer
        ));
        assert!(native.has_pending_work());

        let ToSwarm::Dial { opts } = poll_fn(|cx| NetworkBehaviour::poll(&mut native, cx)).await
        else {
            panic!("expected the native disconnected request to select a dial");
        };
        assert!(native.has_pending_work());
        assert!(
            !native.has_pending_requests_on_connection(&peer, opts.connection_id()),
            "the unassigned dial queue has no connection owner"
        );
        assert!(!native.set_connection_outbound_enabled(&peer, opts.connection_id(), false));
        NetworkBehaviour::on_swarm_event(
            &mut native,
            FromSwarm::DialFailure(DialFailure {
                peer_id: Some(peer),
                connection_id: opts.connection_id(),
                error: &DialError::NoAddresses,
            }),
        );
        assert!(native.has_pending_work(), "failure has not been delivered");

        let failure = poll_fn(|cx| NetworkBehaviour::poll(&mut native, cx)).await;
        assert!(matches!(
            failure,
            ToSwarm::GenerateEvent(autonat::Event::OutboundProbe(
                autonat::OutboundProbeEvent::Error {
                    peer: Some(owner),
                    error: autonat::OutboundProbeError::OutboundRequest(_),
                    ..
                }
            )) if owner == peer
        ));
        assert!(
            !native.has_pending_work(),
            "a scheduled retry is not live work"
        );
    })
    .await
    .expect("disconnected AutoNAT work deadline");
}

#[tokio::test]
async fn established_tcp_probe_selects_enabled_sibling_and_drains_disabled_owner() {
    exercise_established_probe(false).await;
}

#[tokio::test]
async fn paused_autonat_client_drains_owned_probe_and_paused_server_still_serves() {
    exercise_established_probe(true).await;
}

async fn exercise_established_probe(paused: bool) {
    tokio::time::timeout(DEADLINE, async {
        let mut client = host(config(Duration::ZERO, Duration::from_millis(50)));
        let mut server = host(config(QUIET, QUIET));
        server.behaviour_mut().set_client_probes_paused(paused);
        let client_address = listen(&mut client).await;
        let server_address = listen(&mut server).await;
        let client_peer = *client.local_peer_id();
        let server_peer = *server.local_peer_id();
        let (disabled, server_disabled) =
            connect(&mut client, &mut server, server_address.clone()).await;
        let (owner, server_owner) = connect(&mut client, &mut server, server_address).await;
        assert_ne!(disabled, owner);
        assert_ne!(server_disabled, server_owner);
        assert_no_pending_transports(&client);
        assert_no_pending_transports(&server);
        assert!(!client.behaviour().has_pending_work());
        assert!(!server.behaviour().has_pending_work());
        let unknown = DialOpts::peer_id(server_peer).build().connection_id();
        for _ in 0..1000 {
            for id in [disabled, owner, unknown] {
                assert!(
                    !client
                        .behaviour()
                        .has_pending_requests_on_connection(&server_peer, id)
                );
            }
            assert!(!client.behaviour_mut().set_connection_outbound_enabled(
                &server_peer,
                unknown,
                false
            ));
            assert!(!client.behaviour_mut().set_connection_outbound_enabled(
                &client_peer,
                owner,
                false
            ));
            assert!(!client.behaviour().has_pending_work());
            assert_no_pending_transports(&client);
            assert_no_pending_transports(&server);
        }
        assert!(client.behaviour_mut().set_connection_outbound_enabled(
            &server_peer,
            disabled,
            false
        ));
        // Valid pairs return true even when the policy is unchanged.
        assert!(client.behaviour_mut().set_connection_outbound_enabled(
            &server_peer,
            disabled,
            false
        ));
        // Outbound selection policy must not prevent either connection serving inbound probes.
        for id in [server_disabled, server_owner] {
            assert!(server.behaviour_mut().set_connection_outbound_enabled(
                &client_peer,
                id,
                false
            ));
        }

        // Registration happens only after TCP is established; no probe can open it.
        client.behaviour_mut().add_server(server_peer, None);
        client.behaviour_mut().probe_address(client_address);
        loop {
            tokio::select! {
                event = client.select_next_some() => {
                    if let SwarmEvent::Behaviour(autonat::Event::OutboundProbe(
                        autonat::OutboundProbeEvent::Request { peer, .. }
                    )) = event {
                        assert_eq!(peer, server_peer);
                        break;
                    }
                }
                _ = server.select_next_some() => {},
            }
        }
        client.behaviour_mut().remove_server(&server_peer);
        client.behaviour_mut().set_client_probes_paused(paused);
        assert_no_pending_transports(&client);
        assert!(client.behaviour().has_pending_work());
        assert!(
            client
                .behaviour()
                .has_pending_requests_on_connection(&server_peer, owner)
        );
        assert!(
            !client
                .behaviour()
                .has_pending_requests_on_connection(&server_peer, disabled)
        );
        assert!(
            client
                .behaviour_mut()
                .set_connection_outbound_enabled(&server_peer, owner, false)
        );
        for _ in 0..1000 {
            assert!(
                client
                    .behaviour()
                    .has_pending_requests_on_connection(&server_peer, owner)
            );
            assert!(
                !client
                    .behaviour()
                    .has_pending_requests_on_connection(&server_peer, disabled)
            );
            assert!(
                !client
                    .behaviour()
                    .has_pending_requests_on_connection(&client_peer, owner)
            );
            assert!(!client.behaviour_mut().set_connection_outbound_enabled(
                &client_peer,
                owner,
                true
            ));
            assert_no_pending_transports(&client);
            assert_no_pending_transports(&server);
        }

        loop {
            tokio::select! {
                _ = client.select_next_some() => {},
                event = server.select_next_some() => {
                    if let SwarmEvent::Behaviour(autonat::Event::InboundProbe(
                        autonat::InboundProbeEvent::Request { peer, .. }
                    )) = event {
                        assert_eq!(peer, client_peer);
                        break;
                    }
                }
            }
        }
        // Native AutoNAT has queued the dial-back, but Swarm has not admitted it yet.
        for _ in 0..1000 {
            assert_no_pending_transports(&client);
            assert_no_pending_transports(&server);
            assert!(client.behaviour().has_pending_work());
            assert!(server.behaviour().has_pending_work());
            assert!(
                client
                    .behaviour()
                    .has_pending_requests_on_connection(&server_peer, owner)
            );
            assert!(
                !client
                    .behaviour()
                    .has_pending_requests_on_connection(&server_peer, disabled)
            );
            assert!(
                server
                    .behaviour()
                    .has_pending_requests_on_connection(&client_peer, server_owner),
                "retained inbound reply channel owns the pending dial-back"
            );
            assert!(
                !server
                    .behaviour()
                    .has_pending_requests_on_connection(&client_peer, server_disabled)
            );
            assert!(
                !server
                    .behaviour()
                    .has_pending_requests_on_connection(&server_peer, server_owner)
            );
        }

        finish_probe(&mut client, &mut server, server_owner).await;
        assert_no_pending_transports(&client);
        assert_no_pending_transports(&server);
        assert!(client.is_connected(&server_peer));
        assert!(server.is_connected(&client_peer));
        assert!(!client.behaviour().has_pending_work());
        assert!(!server.behaviour().has_pending_work());
        for id in [disabled, owner] {
            assert!(
                !client
                    .behaviour()
                    .has_pending_requests_on_connection(&server_peer, id)
            );
            assert!(
                client
                    .behaviour_mut()
                    .set_connection_outbound_enabled(&server_peer, id, true)
            );
        }
        for id in [server_disabled, server_owner] {
            assert!(
                !server
                    .behaviour()
                    .has_pending_requests_on_connection(&client_peer, id)
            );
        }
        assert_eq!(client.behaviour().client_probes_paused(), paused);
        assert_eq!(server.behaviour().client_probes_paused(), paused);
        assert!(matches!(
            client.behaviour().nat_status(),
            autonat::NatStatus::Public(_)
        ));
        let status = client.behaviour().nat_status();
        let confidence = client.behaviour().confidence();
        for next in [!paused, paused] {
            client.behaviour_mut().set_client_probes_paused(next);
            assert_eq!(client.behaviour().nat_status(), status);
            assert_eq!(client.behaviour().confidence(), confidence);
            assert!(!client.behaviour().has_pending_work());
        }
    })
    .await
    .expect("established TCP AutoNAT work deadline");
}

#[tokio::test]
async fn paused_autonat_due_timer_is_silent_and_resume_preserves_native_ownership() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct WakeCount(AtomicUsize);
    impl futures::task::ArcWake for WakeCount {
        fn wake_by_ref(this: &Arc<Self>) {
            this.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    tokio::time::timeout(DEADLINE, async {
        let peer = PeerId::random();
        let mut native = autonat::Behaviour::new(PeerId::random(), config(Duration::ZERO, QUIET));
        native.add_server(peer, Some("/ip4/127.0.0.1/tcp/9".parse().unwrap()));
        native.probe_address("/ip4/127.0.0.1/tcp/10".parse().unwrap());
        assert!(!native.client_probes_paused());
        assert!(native.set_client_probes_paused(true));
        assert!(!native.set_client_probes_paused(true));
        tokio::time::sleep(Duration::from_millis(5)).await;
        let wake = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = futures::task::waker(wake.clone());
        let mut context = std::task::Context::from_waker(&waker);
        for _ in 0..1000 {
            assert!(NetworkBehaviour::poll(&mut native, &mut context).is_pending());
            assert!(!native.has_pending_work());
        }
        let before = wake.0.load(Ordering::Relaxed);
        assert!(native.set_client_probes_paused(false));
        assert!(wake.0.load(Ordering::Relaxed) > before, "resume must wake the existing poller");
        assert!(!native.set_client_probes_paused(false));
        assert!(matches!(poll_fn(|cx| native.poll(cx)).await,
            ToSwarm::GenerateEvent(autonat::Event::OutboundProbe(autonat::OutboundProbeEvent::Request {peer: owner, ..})) if owner == peer));
        assert!(native.has_pending_work());
        native.set_client_probes_paused(true);
        let ToSwarm::Dial {opts} = poll_fn(|cx| native.poll(cx)).await else { panic!("owned native dial must drain while paused"); };
        native.on_swarm_event(FromSwarm::DialFailure(DialFailure {
            peer_id: Some(peer), connection_id: opts.connection_id(), error: &DialError::NoAddresses,
        }));
        assert!(native.has_pending_work());
        assert!(matches!(poll_fn(|cx| native.poll(cx)).await,
            ToSwarm::GenerateEvent(autonat::Event::OutboundProbe(autonat::OutboundProbeEvent::Error {peer: Some(owner), ..})) if owner == peer));
        for _ in 0..1000 {
            assert!(native.poll(&mut context).is_pending(), "failure must not rearm a paused retry");
            assert!(!native.has_pending_work());
        }
        assert_eq!(native.nat_status(), autonat::NatStatus::Unknown);
        assert_eq!(native.confidence(), 0);
    }).await.expect("paused native AutoNAT deadline");
}

async fn finish_probe(
    client: &mut Swarm<autonat::Behaviour>,
    server: &mut Swarm<autonat::Behaviour>,
    server_owner: ConnectionId,
) {
    let client_peer = *client.local_peer_id();
    let server_peer = *server.local_peer_id();
    let (mut answered, mut dialed_back, mut status_delivered) = (false, false, false);
    // The reply can finish before both Swarms admit the dial-back transport.
    while !answered
        || !dialed_back
        || !status_delivered
        || client.behaviour().has_pending_work()
        || server.behaviour().has_pending_work()
        || client.network_info().connection_counters().num_pending() > 0
        || server.network_info().connection_counters().num_pending() > 0
    {
        tokio::select! {
            event = client.select_next_some() => match event {
                SwarmEvent::Behaviour(autonat::Event::OutboundProbe(
                    autonat::OutboundProbeEvent::Response { peer, .. }
                )) => {
                    assert_eq!(peer, server_peer);
                    assert!(client.behaviour().has_pending_work(), "status/address actions are still queued");
                    answered = true;
                }
                SwarmEvent::Behaviour(autonat::Event::StatusChanged {
                    new: autonat::NatStatus::Public(_), ..
                }) => status_delivered = true,
                SwarmEvent::Behaviour(autonat::Event::OutboundProbe(
                    autonat::OutboundProbeEvent::Error { peer: Some(peer), error, .. }
                )) if peer == server_peer => panic!("native probe failed: {error:?}"),
                SwarmEvent::ConnectionClosed { .. } => panic!("client TCP connection closed during probe"),
                _ => {},
            },
            event = server.select_next_some() => match event {
                SwarmEvent::Behaviour(autonat::Event::InboundProbe(
                    autonat::InboundProbeEvent::Response { peer, .. }
                )) => {
                    assert_eq!(peer, client_peer);
                    assert!(server.behaviour().has_pending_work(), "reply/terminal work has not drained");
                    assert!(server.behaviour().has_pending_requests_on_connection(&client_peer, server_owner));
                    dialed_back = true;
                }
                SwarmEvent::Behaviour(autonat::Event::InboundProbe(
                    autonat::InboundProbeEvent::Error { error, .. }
                )) => panic!("native dial-back failed: {error:?}"),
                SwarmEvent::ConnectionClosed { .. } => panic!("server TCP connection closed during probe"),
                _ => {},
            },
            () = tokio::time::sleep(Duration::from_millis(1)) => {},
        }
    }
}
