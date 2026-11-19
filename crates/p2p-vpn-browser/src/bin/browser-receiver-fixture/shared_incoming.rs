use std::{io::BufRead, sync::Arc};

use tokio::sync::{Barrier, mpsc, oneshot};

use super::*;

const SECOND_IP: Ipv4Addr = Ipv4Addr::new(10, 204, 0, 4);

pub(super) async fn run(entrance: Multiaddr) -> Result<()> {
    let first = NodeIdentity::generate_ed25519().map_err(debug_error)?;
    let second = NodeIdentity::generate_ed25519().map_err(debug_error)?;
    let browser = NodeIdentity::generate_ed25519().map_err(debug_error)?;
    let outsider = PeerId::random();
    let network = format!("browser-shared-{}", first.peer_id);
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let records = [
        (&first, NATIVE_IP),
        (&second, SECOND_IP),
        (&browser, BROWSER_IP),
    ]
    .into_iter()
    .map(|(identity, ip)| {
        issue_membership_record_at(
            &first,
            MembershipRecordOptions {
                network_name: network.clone(),
                member: identity.clone(),
                membership_epoch: 1,
                sequence: 1,
                roles: vec![
                    MembershipRole::OverlayMember,
                    MembershipRole::RouteAuthority,
                ],
                route_grants: vec![RouteConfig {
                    prefix: format!("{ip}/32"),
                    metric: 0,
                }],
                expires_at_unix_seconds: Some(now + 300),
            },
            now,
        )
        .map_err(debug_error)
    })
    .collect::<std::io::Result<Vec<_>>>()?;
    let config = |identity: &NodeIdentity, ip: Ipv4Addr| {
        serde_json::from_value::<Config>(json!({
            "network": {
                "name": network, "local_peer": identity.peer_id, "private_key": identity.private_key,
                "vpn_ip": ip, "member_records": records, "listen_addresses": [],
                "packet_plane": {"listen": [], "quic_listen": []},
            },
            "interface": {"name": "p2p-shared", "mtu": MTU},
        }))
    };
    let browser_id = browser.peer_id.parse::<PeerId>()?;
    let relay = match entrance.iter().last() {
        Some(Protocol::P2p(peer)) => peer,
        _ => return Err("expected a pinned relay".into()),
    };
    let mut a = native(config(&first, NATIVE_IP)?, browser_id, relay, NATIVE_MTU)?;
    let mut b = native(config(&second, SECOND_IP)?, browser_id, relay, 576)?;
    direct_listener(&mut a.swarm, "192.0.2.1").await?;
    direct_listener(&mut b.swarm, "192.0.2.1").await?;
    println!(
        "{}",
        json!({
            "config": config(&browser, BROWSER_IP)?,
            "route": entrance.clone().with(Protocol::P2pCircuit).with(Protocol::P2p(*a.swarm.local_peer_id())).to_string(),
            "first_peer": first.peer_id,
            "additional_peer": second.peer_id,
            "outsider": outsider.to_string(),
        })
    );
    let reservation = entrance
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(browser_id));
    let (send_command, mut commands) = mpsc::channel(1);
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            if send_command.blocking_send(line).is_err() {
                break;
            }
        }
    });
    let offered = commands.recv().await.ok_or("missing reservation")??;
    assert_eq!(offered, reservation.to_string());

    let both = Arc::new(Barrier::new(2));
    let (closed, wait_closed) = oneshot::channel();
    let (begin_second, wait_begin_second) = oneshot::channel();
    let (begin_close, wait_begin_close) = oneshot::channel();
    let (continue_after_close, wait_continue_after_close) = oneshot::channel();
    tokio::try_join!(
        async {
            let id = incoming::exchange_on_reservation(&mut a, reservation.clone()).await?;
            packet(&mut a, 1, NATIVE_IP, 1000, PacketResponse::Accepted).await?;
            both.wait().await;
            packet(&mut a, 2, NATIVE_IP, 1000, PacketResponse::Accepted).await?;
            packet(
                &mut a,
                3,
                SECOND_IP,
                28,
                PacketResponse::Rejected(PacketRejectionReason::UnauthorizedSource),
            )
            .await?;
            wait_begin_close.await?;
            assert!(a.swarm.close_connection(id));
            loop {
                if matches!(a.swarm.select_next_some().await, SwarmEvent::ConnectionClosed { connection_id, .. } if connection_id == id)
                {
                    break;
                }
            }
            println!("{}", json!({"first_closed": true}));
            closed
                .send(())
                .map_err(|_| "second member stopped before first closed")?;
            Ok::<_, Box<dyn std::error::Error>>(())
        },
        async {
            wait_begin_second.await?;
            let id = incoming::exchange_on_reservation(&mut b, reservation.clone()).await?;
            packet(&mut b, 1, SECOND_IP, 28, PacketResponse::Accepted).await?;
            packet(
                &mut b,
                2,
                SECOND_IP,
                1000,
                PacketResponse::Rejected(PacketRejectionReason::PacketTooLarge),
            )
            .await?;
            both.wait().await;
            wait_closed.await?;
            wait_continue_after_close.await?;
            assert!(b.swarm.is_connected(&b.peer));
            let request = b
                .swarm
                .behaviour_mut()
                .packet
                .send_request_on_connection_with_deadline(
                    &b.peer,
                    id,
                    frame(3, SECOND_IP, 28)?,
                    web_time::Instant::now() + Duration::from_secs(5),
                )
                .map_err(debug_error)?;
            loop {
                if let BehaviourEvent::Packet(request_response::Event::Message {
                    connection_id,
                    message:
                        Message::Response {
                            request_id,
                            response,
                        },
                    ..
                }) = b.next().await?
                {
                    assert_eq!(connection_id, id);
                    assert_eq!(request_id, request);
                    assert_eq!(response, PacketResponse::Accepted);
                    break;
                }
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        },
        async {
            assert_eq!(
                commands.recv().await.transpose()?.as_deref(),
                Some("start-second")
            );
            begin_second
                .send(())
                .map_err(|_| "second member stopped before dialing")?;
            assert_eq!(
                commands.recv().await.transpose()?.as_deref(),
                Some("close-first")
            );
            begin_close
                .send(())
                .map_err(|_| "first member stopped before close")?;
            assert_eq!(
                commands.recv().await.transpose()?.as_deref(),
                Some("send-second")
            );
            continue_after_close
                .send(())
                .map_err(|_| "second member stopped before continuing")?;
            Ok::<_, Box<dyn std::error::Error>>(())
        },
    )?;
    println!("{}", json!({"second_used_original_connection": true}));
    Ok(())
}

fn native(config: Config, browser: PeerId, relay: PeerId, mtu: u16) -> Result<Fixture> {
    let forwarder = Forwarder::from_config(&config).map_err(debug_error)?;
    let mut caps = ControlCapabilities::local(&config.network.name, None, mtu)
        .with_advertised_routes(forwarder.local_advertised_routes());
    caps.preferred_path = PathKind::CircuitRelay.wire_name().into();
    let key = config
        .identity()
        .map_err(debug_error)?
        .keypair()
        .map_err(debug_error)?;
    let certificate = libp2p_webrtc::tokio::Certificate::generate(&mut rand::rngs::OsRng)?;
    let swarm = SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_other_transport(|key| libp2p_webrtc::tokio::Transport::new(key.clone(), certificate))?
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|_, relay| Behaviour {
            relay: Some(relay).into(),
            control: control::behaviour(8),
            demand: None.into(),
            packet: packet::behaviour(MTU, 32),
            service: service::behaviour(8),
        })?
        .with_swarm_config(|config| config.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    Ok(Fixture {
        swarm,
        peer: browser,
        relay_peer: Some(relay),
        expected_path: PathKind::CircuitRelay,
        forwarder,
        caps,
        records_to_serve: Vec::new(),
        report_revocation: false,
        membership_pages_served: 0,
        capture_recovery_probe: false,
        recovery_probe: None,
        abandoned_probe: None,
    })
}

fn frame(sequence: u64, source: Ipv4Addr, len: u16) -> Result<Frame> {
    let mut bytes = ipv4_packet(source, BROWSER_IP);
    bytes.resize(usize::from(len), 0);
    let mut ip = Ipv4Packet::new_unchecked(bytes.as_mut_slice());
    ip.set_total_len(len);
    ip.fill_checksum();
    Ok(Frame::packet(1, sequence, bytes).map_err(debug_error)?)
}

async fn packet(
    fixture: &mut Fixture,
    sequence: u64,
    source: Ipv4Addr,
    len: u16,
    expected: PacketResponse,
) -> Result<()> {
    assert_eq!(
        fixture.send_packet(frame(sequence, source, len)?).await?,
        expected
    );
    Ok(())
}
