use super::*;
use libp2p::{
    core::transport::ListenerId,
    kad::{self, store::RecordStore},
};
use p2p_vpn::runtime::p2p::kademlia_peer_addresses_key;

pub(super) fn initial_authority(
    config: &mut Config,
    member: &NodeIdentity,
    now: u64,
) -> Result<u64> {
    config.network.discovery.mdns = false;
    config.network.discovery.kademlia = true;
    config.network.discovery.kademlia_protocol = gateway::DHT_PROTOCOL.into();
    let expires = now + 20;
    set_member_record(config, member, now, expires, 1)?;
    Ok(expires)
}

fn set_member_record(
    config: &mut Config,
    member: &NodeIdentity,
    now: u64,
    expires: u64,
    sequence: u64,
) -> Result<()> {
    let record = config
        .network
        .member_records
        .iter_mut()
        .find(|record| record.payload.member_peer == member.peer_id)
        .ok_or("missing fixture member")?;
    *record = issue_membership_record_at(
        member,
        MembershipRecordOptions {
            network_name: config.network.name.clone(),
            member: member.clone(),
            membership_epoch: 1,
            sequence,
            roles: vec![
                MembershipRole::OverlayMember,
                MembershipRole::RouteAuthority,
            ],
            route_grants: vec![RouteConfig {
                prefix: format!("{NATIVE_IP}/32"),
                metric: 0,
            }],
            expires_at_unix_seconds: Some(expires),
        },
        now,
    )
    .map_err(debug_error)?;
    Ok(())
}

pub(super) async fn serve_seed() -> Result<()> {
    let initial: gateway::SignedRecord = serde_json::from_str(&gateway::stdin_line()?)?;
    let key = kademlia_peer_addresses_key(&initial.network, None, initial.member.parse()?);
    let (mut swarm, bootstrap) = gateway::seed(initial).await?;
    println!("{bootstrap}");
    let update = tokio::task::spawn_blocking(gateway::stdin_line);
    tokio::pin!(update);
    let current: gateway::SignedRecord = loop {
        tokio::select! {
            line = &mut update => break serde_json::from_str(&line??)?,
            _ = swarm.select_next_some() => {}
        }
    };
    assert_eq!(
        key,
        kademlia_peer_addresses_key(&current.network, None, current.member.parse()?)
    );
    swarm
        .behaviour_mut()
        .store_mut()
        .put(kad::Record::new(key, current.value))?;
    println!("signed hint updated");
    while swarm.next().await.is_some() {}
    Ok(())
}

pub(super) async fn exercise(
    fixture: &mut Fixture,
    member: &NodeIdentity,
    mut config: Config,
    replacement: Multiaddr,
    original: ListenerId,
) -> Result<()> {
    assert_eq!(
        fixture
            .send_packet(Frame::keepalive(1, 1).map_err(debug_error)?)
            .await?,
        PacketResponse::Accepted,
    );
    println!("initial keepalive accepted");
    wait_for_command(fixture, original, "disconnect").await?;
    if fixture.swarm.disconnect_peer_id(fixture.peer).is_ok() {
        loop {
            if let SwarmEvent::ConnectionClosed {
                peer_id,
                num_established: 0,
                ..
            } = fixture.swarm.select_next_some().await
                && peer_id == fixture.peer
            {
                break;
            }
        }
    }
    println!("initial session closed");
    wait_for_command(fixture, original, "publish").await?;
    assert_eq!(fixture.swarm.listeners().count(), 2);
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    set_member_record(&mut config, member, now, now + 300, 2)?;
    let hint = gateway::SignedRecord::new(&config.network.name, member, vec![replacement], now)?;
    println!("{}", json!({ "config": config, "hint": hint }));
    let current = fixture.exchange_capabilities(false).await?;
    recovery_http::serve(fixture, current).await
}

async fn wait_for_command(
    fixture: &mut Fixture,
    original: ListenerId,
    expected: &str,
) -> Result<()> {
    let update = tokio::task::spawn_blocking(gateway::stdin_line);
    tokio::pin!(update);
    loop {
        tokio::select! {
            line = &mut update => {
                assert_eq!(line??.trim(), expected);
                return Ok(());
            }
            event = fixture.swarm.select_next_some() => match event {
                SwarmEvent::ListenerClosed { listener_id, .. } if listener_id == original => {
                    return Err("original WebRTC listener closed".into());
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == fixture.peer => {
                    return Err("browser redialed before renewed authority".into());
                }
                SwarmEvent::Behaviour(BehaviourEvent::Packet(request_response::Event::Message {
                    message: Message::Request { request, .. }, ..
                })) => assert_ne!(request.header.payload_type, PayloadType::IpPacket),
                _ => {}
            }
        }
    }
}
