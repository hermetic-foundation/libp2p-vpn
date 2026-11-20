use std::{
    collections::HashSet,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use libp2p::{
    Multiaddr, PeerId, Swarm,
    swarm::{ConnectionId, behaviour::toggle::Toggle},
};
use p2p_vpn::{
    config::membership_tag,
    membership::checkpoint::{
        CheckpointMember, CooperativeMembershipState, MembershipChange, NetworkAnchor,
        NetworkCapability, SignedHostnameClaim, SnapshotChallenge, SnapshotPolicy,
    },
    pairing::{
        PairingCheckpointGrant, PairingOfferOptions, PairingRequestOptions, PairingResponseOptions,
        build_checkpoint_pairing_response_at, build_named_pairing_request_at,
        checkpoint_grant::VerifiedCheckpointEnrollment, export_pairing_offer_at,
    },
    route::{builtin_ipv4, builtin_ipv6},
    runtime::control::checkpoint::{
        self, CheckpointCodec, CheckpointPageResponse, CheckpointSync, CheckpointSyncIndicator,
        CheckpointSyncLimits, MAX_PAGE_BYTES,
    },
    runtime::control::checkpoint_mutation::{
        self, CheckpointMutationCodec, CheckpointMutationRequest, MutationOutcome,
    },
};

use super::{
    ControlCapabilities, ControlRequest, ControlResponse, Message, NATIVE_MTU, NetworkBehaviour,
    NodeIdentity, PacketResponse, PathKind, Protocol, Result, StreamExt, SwarmBuilder, SwarmEvent,
    control, debug_error, json, packet, recovery_http::HttpProof, request_response,
};

const NETWORK: &str = "checkpoint-interrupted";
const SECRET: [u8; 32] = [37; 32];

#[derive(NetworkBehaviour)]
struct Wire {
    control: request_response::Behaviour<control::ControlCodec>,
    checkpoint: request_response::Behaviour<CheckpointCodec>,
    mutation: Toggle<request_response::Behaviour<CheckpointMutationCodec>>,
    packet: request_response::Behaviour<packet::PacketCodec>,
}

fn wall_now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

async fn listen(native: &NodeIdentity, live_mutations: bool) -> Result<(Swarm<Wire>, Multiaddr)> {
    let certificate = libp2p_webrtc::tokio::Certificate::generate(&mut rand::rngs::OsRng)?;
    let mut swarm = SwarmBuilder::with_existing_identity(native.keypair().map_err(debug_error)?)
        .with_tokio()
        .with_other_transport(|key| libp2p_webrtc::tokio::Transport::new(key.clone(), certificate))?
        .with_behaviour(|_| Wire {
            control: control::behaviour(8),
            checkpoint: checkpoint::behaviour(8),
            mutation: live_mutations
                .then(|| checkpoint_mutation::behaviour(4))
                .into(),
            packet: packet::behaviour(NATIVE_MTU, 8),
        })?
        .with_swarm_config(|config| config.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    swarm.listen_on("/ip4/192.0.2.1/udp/0/webrtc-direct".parse()?)?;
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                let local = *swarm.local_peer_id();
                return Ok((swarm, address.with(Protocol::P2p(local))));
            }
            SwarmEvent::ListenerError { error, .. } => return Err(error.into()),
            _ => {}
        }
    }
}

pub(super) async fn run() -> Result<()> {
    let mut used_addresses = HashSet::new();
    let mut identity = || loop {
        let id = NodeIdentity::generate_ed25519().unwrap();
        let peer = p2p_vpn::PeerId::from_libp2p(id.peer_id.parse().unwrap());
        if used_addresses.insert(builtin_ipv4(peer)) {
            break id;
        }
    };
    let native = identity();
    let browser = identity();
    let browser_peer = browser.peer_id.parse()?;
    let anchor = NetworkAnchor::new([75; 32])?;
    let mut members = vec![
        CheckpointMember::new(&native)?,
        CheckpointMember::new(&browser)?,
    ];
    for _ in 0..40 {
        members.push(CheckpointMember::new(&identity())?);
    }
    let removed = members.last().unwrap().subject.peer_id.clone();
    let mut state = CooperativeMembershipState::bootstrap_at(
        NetworkCapability::from_secret(anchor.clone(), Some(&SECRET))?,
        native.peer_id.clone(),
        members,
        SnapshotPolicy::default(),
        wall_now()?,
    )?;
    let prior = state.snapshot().payload.boundary()?;
    let retained = state.retained();
    let update = state.sign_mutation_at(
        &native,
        MembershipChange::RemoveMember(removed),
        wall_now()?,
    )?;
    state.apply_mutation_at(&update, wall_now()?)?;
    let offered = state.snapshot().payload.boundary()?;

    let mut caps =
        ControlCapabilities::local(NETWORK, Some(membership_tag(NETWORK, &SECRET)), NATIVE_MTU)
            .with_checkpoint(&state)?;
    caps.preferred_path = PathKind::DirectWebRtcStream.wire_name().into();
    let (mut swarm, address) = listen(&native, false).await?;
    let local = *swarm.local_peer_id();
    let mut sync = CheckpointSync::new(local, anchor.clone(), CheckpointSyncLimits::default())?;
    println!(
        "{}",
        json!({
            "config": {
                "network": {"name": NETWORK, "local_peer": browser.peer_id, "private_key": browser.private_key},
                "peers": [{"id": native.peer_id, "addresses": []}],
            },
            "address": address.to_string(),
            "bootstrap": {"anchor": anchor, "retained": retained},
            "secret": SECRET,
            "prior": prior,
            "offered": offered,
        })
    );

    let mut pages = 0;
    let mut rounds: [Option<(ConnectionId, SnapshotChallenge)>; 2] = [None, None];
    let mut held = None;
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::Behaviour(WireEvent::Control(request_response::Event::Message {
                peer,
                connection_id,
                message:
                    Message::Request {
                        request: ControlRequest::Capabilities(offer),
                        channel,
                        ..
                    },
                ..
            })) => {
                assert_eq!(peer, browser_peer);
                let installed = offer
                    .checkpoint
                    .filter(|descriptor| descriptor.sync == CheckpointSyncIndicator::Participating);
                if let Some(descriptor) = &installed {
                    assert_eq!(pages, 4);
                    assert_eq!(descriptor.boundary, offered);
                    assert_eq!(connection_id, rounds[1].as_ref().unwrap().0);
                }
                swarm
                    .behaviour_mut()
                    .control
                    .send_response(channel, ControlResponse::CapabilitiesAccepted(caps.clone()))
                    .map_err(|_| "capabilities stream closed")?;
                if installed.is_some() {
                    println!("{}", json!({"retry_installed": offered}));
                }
            }
            SwarmEvent::Behaviour(WireEvent::Checkpoint(request_response::Event::Message {
                peer,
                connection_id,
                message:
                    Message::Request {
                        request, channel, ..
                    },
                ..
            })) => {
                assert_eq!(peer, browser_peer);
                let response = sync.respond_at(
                    peer,
                    &request,
                    &state,
                    &native,
                    &SECRET,
                    Instant::now(),
                    wall_now()?,
                )?;
                let CheckpointPageResponse::Page(page) = &response else {
                    return Err("expected a valid checkpoint page".into());
                };
                match pages {
                    0 | 2 => {
                        assert_eq!(page.cursor, 0);
                        assert_eq!(page.bytes.len(), MAX_PAGE_BYTES);
                        assert_eq!(sync.stats().buffered_bytes, page.total_bytes as usize);
                        if pages == 2 {
                            let (old_connection, old_challenge) = rounds[0].as_ref().unwrap();
                            assert_ne!(connection_id, *old_connection);
                            assert_ne!(page.challenge, *old_challenge);
                            drop(held.take().expect("interrupted final page"));
                        }
                        rounds[pages / 2] = Some((connection_id, page.challenge.clone()));
                    }
                    1 | 3 => {
                        let (expected_connection, challenge) = rounds[pages / 2].as_ref().unwrap();
                        assert_eq!(connection_id, *expected_connection);
                        assert_eq!(page.challenge, *challenge);
                        assert_eq!(page.cursor as usize, MAX_PAGE_BYTES);
                        assert_eq!(
                            page.cursor as usize + page.bytes.len(),
                            page.total_bytes as usize
                        );
                        let stats = sync.stats();
                        assert_eq!(stats.buffered_bytes, 0);
                        assert_eq!(stats.publisher_sessions, 0);
                        assert_eq!(stats.retired_sessions, pages / 2 + 1);
                    }
                    _ => return Err("unexpected checkpoint page after retry".into()),
                }
                pages += 1;
                if pages == 2 {
                    // Hold exactly one genuine final response without sending or replaying it.
                    held = Some((channel, response));
                    println!(
                        "{}",
                        json!({"final_cursor": MAX_PAGE_BYTES, "final_page_held": true})
                    );
                    continue;
                }
                swarm
                    .behaviour_mut()
                    .checkpoint
                    .send_response(channel, response)
                    .map_err(|_| "checkpoint page stream closed")?;
            }
            _ => {}
        }
    }
}

pub(super) async fn pending_exclusion() -> Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let network = "checkpoint-pending-exclusion";
    let native = NodeIdentity::generate_ed25519().map_err(debug_error)?;
    let browser = NodeIdentity::generate_ed25519().map_err(debug_error)?;
    let browser_peer: PeerId = browser.peer_id.parse()?;
    let (mut swarm, address) = listen(&native, false).await?;
    let anchor = NetworkAnchor::new([76; 32])?;
    let mut state = CooperativeMembershipState::bootstrap_at(
        NetworkCapability::from_secret(anchor.clone(), Some(&SECRET))?,
        native.peer_id.clone(),
        vec![CheckpointMember::new(&native)?],
        SnapshotPolicy::default(),
        wall_now()?,
    )?;
    let config = serde_json::from_value(json!({
        "network": {"name": network, "local_peer": native.peer_id, "private_key": native.private_key,
                    "external_addresses": [address]},
    }))?;
    let now = wall_now()?;
    let offer = export_pairing_offer_at(
        &config,
        PairingOfferOptions {
            expires_in_seconds: 120,
            rendezvous_token: None,
        },
        now,
    )
    .map_err(debug_error)?;
    let request = build_named_pairing_request_at(
        &offer,
        PairingRequestOptions {
            identity: browser.clone(),
            requested_vpn_ip: None,
            requested_routes: vec![],
        },
        Some("pending-browser"),
        now,
    )
    .map_err(debug_error)?;
    request
        .verify_for_offer_at(&offer, now)
        .map_err(debug_error)?;
    let admission = state.sign_mutation_at(
        &native,
        MembershipChange::UpsertMember(CheckpointMember::new(&browser)?),
        now,
    )?;
    state.apply_mutation_at(&admission, now)?;
    let grant = PairingCheckpointGrant::from_state_at(&state, &SECRET, &browser.peer_id, now)
        .map_err(debug_error)?;
    let response = build_checkpoint_pairing_response_at(
        &config,
        &offer,
        PairingResponseOptions {
            joiner_peer: browser.peer_id.clone(),
            assigned_vpn_ip: None,
            membership_key: None,
            member_records: vec![],
            expires_in_seconds: 90,
        },
        grant,
        now,
    )
    .map_err(debug_error)?;
    let pending = VerifiedCheckpointEnrollment::verify_at(&offer, &response, &browser, now)
        .map_err(debug_error)?
        .ok_or("missing approved checkpoint grant")?
        .into_pending_seed()?;
    let prior = pending.retained.snapshot.payload.boundary()?;
    let floor = pending.enrollment_floor;
    assert!(pending.retained.snapshot.payload.rank()? < floor);
    println!(
        "{}",
        json!({
            "config": {"network": {"name": network, "local_peer": browser.peer_id,
                                   "private_key": browser.private_key}},
            "address": address,
            "bootstrap": {"anchor": anchor, "retained": pending.retained, "enrollment_floor": floor},
            "secret": SECRET, "prior": prior, "floor": floor,
            "native_ip": builtin_ipv4(p2p_vpn::PeerId::from_libp2p(*swarm.local_peer_id())),
        })
    );

    let mut commands = BufReader::new(tokio::io::stdin()).lines();
    assert_eq!(commands.next_line().await?.as_deref(), Some("remove"));
    let removal = state.sign_mutation_at(
        &native,
        MembershipChange::RemoveMember(browser.peer_id.clone()),
        wall_now()?,
    )?;
    state.apply_mutation_at(&removal, wall_now()?)?;
    assert!(state.snapshot().payload.rank()? >= floor);
    let offered = state.snapshot().payload.boundary()?;
    let mut caps =
        ControlCapabilities::local(network, Some(membership_tag(network, &SECRET)), NATIVE_MTU)
            .with_checkpoint(&state)?;
    caps.preferred_path = PathKind::DirectWebRtcStream.wire_name().into();
    let mut sync = CheckpointSync::new(
        *swarm.local_peer_id(),
        anchor,
        CheckpointSyncLimits::default(),
    )?;
    println!("{}", json!({"offered": offered}));

    let mut sent = 0;
    loop {
        tokio::select! {
            command = commands.next_line() => {
                assert_eq!(command?.as_deref(), Some("finish"));
                assert_eq!(sent, 1);
                let stats = sync.stats();
                assert_eq!(stats.publisher_sessions, 0);
                assert_eq!(stats.buffered_bytes, 0);
                println!("{}", json!({"snapshots_sent": sent, "packets_seen": 0}));
                return Ok(());
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(WireEvent::Control(request_response::Event::Message {
                    peer, message: Message::Request { request: ControlRequest::Capabilities(offer), channel, .. }, ..
                })) => {
                    assert_eq!(peer, browser_peer);
                    assert_ne!(offer.checkpoint.ok_or("missing requester checkpoint")?.sync,
                               CheckpointSyncIndicator::Participating);
                    swarm.behaviour_mut().control
                        .send_response(channel, ControlResponse::CapabilitiesAccepted(caps.clone()))
                        .map_err(|_| "capabilities stream closed")?;
                }
                SwarmEvent::Behaviour(WireEvent::Checkpoint(request_response::Event::Message {
                    peer, message: Message::Request { request, channel, .. }, ..
                })) => {
                    assert_eq!(peer, browser_peer);
                    let response = sync.respond_at(peer, &request, &state, &native, &SECRET, Instant::now(), wall_now()?)?;
                    assert!(matches!(response, CheckpointPageResponse::Page(_)));
                    swarm.behaviour_mut().checkpoint.send_response(channel, response)
                        .map_err(|_| "checkpoint page stream closed")?;
                }
                SwarmEvent::Behaviour(WireEvent::Checkpoint(request_response::Event::ResponseSent { .. })) => sent += 1,
                SwarmEvent::Behaviour(WireEvent::Packet(request_response::Event::Message { .. })) =>
                    return Err("VPN packet reached native fixture".into()),
                _ => {}
            }
        }
    }
}

pub(super) async fn live_mutations(network: &str) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let dns = network == "checkpoint-dns";
    let native = NodeIdentity::generate_ed25519().map_err(debug_error)?;
    let native_ip = builtin_ipv4(native.peer_id.parse().map_err(debug_error)?);
    let (browser, browser_ip) = loop {
        let id = NodeIdentity::generate_ed25519().map_err(debug_error)?;
        let ip = builtin_ipv4(id.peer_id.parse().map_err(debug_error)?);
        if ip != native_ip {
            break (id, ip);
        }
    };
    let browser_peer = browser.peer_id.parse()?;
    let anchor = NetworkAnchor::new([77; 32])?;
    let (subject, subject_peer) = loop {
        let id = NodeIdentity::generate_ed25519().map_err(debug_error)?;
        let peer = id.peer_id.parse().map_err(debug_error)?;
        if ![native_ip, browser_ip].contains(&builtin_ipv4(peer)) {
            break (id, peer);
        }
    };
    let mut disposable = CheckpointMember::new(&subject)?;
    let now = wall_now()?;
    // Start from an authentic history where the disposable lease was once active.
    let initial_time = if dns {
        now
    } else {
        disposable.expires_at_unix_seconds = Some(now - 1);
        now - 2
    };
    let mut state = CooperativeMembershipState::bootstrap_at(
        NetworkCapability::from_secret(anchor.clone(), Some(&SECRET))?,
        native.peer_id.clone(),
        vec![
            CheckpointMember::new(&native)?,
            CheckpointMember::new(&browser)?,
            disposable.clone(),
        ],
        SnapshotPolicy::default(),
        initial_time,
    )?;
    if dns {
        state.merge_hostname_claims(&[SignedHostnameClaim::issue(
            anchor.clone(),
            &subject,
            disposable.incarnation,
            1,
            "signed-subject",
        )?])?;
    }
    let (mut swarm, address) = listen(&native, true).await?;
    let mut sync = CheckpointSync::new(
        *swarm.local_peer_id(),
        anchor.clone(),
        CheckpointSyncLimits::default(),
    )?;
    println!(
        "{}",
        json!({
            "config": {
                "network": {"name": network, "local_peer": browser.peer_id, "private_key": browser.private_key,
                            "dns": {"enabled": dns, "hostname": dns.then_some("browser-peer")}},
                "peers": [{"id": native.peer_id}],
            },
        "address": address.to_string(),
            "bootstrap": {"anchor": anchor, "retained": state.retained()},
            "secret": SECRET,
            "prior": state.snapshot().payload.boundary()?,
            "disposable": disposable.subject.peer_id,
            "native_ip": native_ip,
            "dns_subject": dns.then(|| json!({
                "peer_id": subject.peer_id,
                "fallback": p2p_vpn::dns::peer_fallback_label(subject_peer),
                "ipv4": [builtin_ipv4(subject_peer)],
                "ipv6": [builtin_ipv6(subject_peer)],
            })),
        })
    );

    let mut commands = BufReader::new(tokio::io::stdin()).lines();
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    let mut connection = None;
    let mut pending = None;
    let mut refresh = None;
    let capabilities = |state: &CooperativeMembershipState| -> Result<ControlCapabilities> {
        let mut caps =
            ControlCapabilities::local(network, Some(membership_tag(network, &SECRET)), NATIVE_MTU)
                .with_checkpoint(state)?;
        caps.preferred_path = PathKind::DirectWebRtcStream.wire_name().into();
        Ok(caps)
    };
    let mut http = None;
    let mut sequence = 2;
    loop {
        tokio::select! {
            command = commands.next_line() => {
                assert!(pending.is_none());
                let revision = state.snapshot().payload.authority_revision;
                let change = match (dns, command?.as_deref(), revision) {
                    (true, Some("remove"), 0) => MembershipChange::RemoveMember(subject.peer_id.clone()),
                    (true, Some("readmit"), 1) => MembershipChange::UpsertMember(CheckpointMember::new(&subject)?),
                    (false, Some("policy"), 0) => MembershipChange::SetPolicy(SnapshotPolicy {
                        route_grants_enabled: false,
                        ..state.snapshot().payload.policy.clone()
                    }),
                    (false, Some("prune"), 1) => {
                        assert!(!state.snapshot().payload.member(&disposable.subject.peer_id)
                            .expect("disposable still in roster").active_at(wall_now()?));
                        MembershipChange::PruneExpired
                    }
                    (_, Some("finish"), 2) => return Ok(()),
                    _ => return Err("unexpected checkpoint fixture command".into()),
                };
                let now = wall_now()?;
                let mutation = state.sign_mutation_at(&native, change, now)?;
                state.apply_mutation_at(&mutation, now)?;
                let request = CheckpointMutationRequest::new(mutation)?;
                let wire = swarm.behaviour_mut().mutation.as_mut().expect("live mutation scenario");
                let id = wire.send_request(&browser_peer, request.clone());
                pending = Some((id, request));
            }
            _ = tick.tick() => {}
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(WireEvent::Control(request_response::Event::Message {
                    peer, connection_id, message: Message::Request { request: ControlRequest::Capabilities(_), channel, .. }, ..
                })) => {
                    assert_eq!(peer, browser_peer);
                    assert_eq!(*connection.get_or_insert(connection_id), connection_id);
                    let caps = capabilities(&state)?;
                    swarm.behaviour_mut().control.send_response(channel, ControlResponse::CapabilitiesAccepted(caps))
                        .map_err(|_| "capabilities stream closed")?;
                }
                SwarmEvent::Behaviour(WireEvent::Control(request_response::Event::Message {
                    peer, connection_id, message: Message::Response { request_id, response }, ..
                })) => {
                    assert_eq!((peer, Some(connection_id), Some(request_id)), (browser_peer, connection, refresh.take()));
                    let ControlResponse::CapabilitiesAccepted(caps) = response else {
                        return Err(format!("capabilities refresh rejected: {response:?}").into());
                    };
                    let boundary = state.snapshot().payload.boundary()?;
                    assert_eq!(caps.checkpoint.expect("checkpoint capabilities").boundary, boundary);
                    println!("{}", json!({"reauthorized": boundary}));
                }
                SwarmEvent::Behaviour(WireEvent::Control(request_response::Event::OutboundFailure { error, .. })) =>
                    return Err(error.into()),
                SwarmEvent::Behaviour(WireEvent::Checkpoint(request_response::Event::Message {
                    peer, connection_id, message: Message::Request { request, channel, .. }, ..
                })) => {
                    assert_eq!((peer, Some(connection_id)), (browser_peer, connection));
                    let response = sync.respond_at(peer, &request, &state, &native, &SECRET, Instant::now(), wall_now()?)?;
                    swarm.behaviour_mut().checkpoint.send_response(channel, response)
                        .map_err(|_| "checkpoint page stream closed")?;
                }
                SwarmEvent::Behaviour(WireEvent::Mutation(request_response::Event::Message {
                    peer, connection_id, message: Message::Response { request_id, response }, ..
                })) => {
                    let (id, request) = pending.take().expect("outstanding mutation");
                    assert_eq!((peer, Some(connection_id), request_id), (browser_peer, connection, id));
                    let boundary = state.snapshot().payload.boundary()?;
                    assert_eq!(response.validate_for(&request)?, MutationOutcome::Applied(boundary));
                    assert!(refresh.is_none());
                    refresh = Some(swarm.behaviour_mut().control.send_request(
                        &browser_peer, ControlRequest::Capabilities(capabilities(&state)?)));
                    if !dns {
                        let path = if boundary.authority_revision == 1 { "/policy" } else { "/prune" };
                        http = Some(HttpProof::new(native_ip, browser_ip, path)?);
                    }
                    println!("{}", json!({
                        "base": request.mutation.payload.base,
                        "reply": response,
                        "snapshot": state.snapshot(),
                    }));
                }
                SwarmEvent::Behaviour(WireEvent::Mutation(request_response::Event::OutboundFailure { error, .. })) =>
                    return Err(error.into()),
                SwarmEvent::Behaviour(WireEvent::Packet(request_response::Event::Message {
                    peer, connection_id, message: Message::Request { request, channel, .. }, ..
                })) => {
                    assert_eq!((peer, Some(connection_id)), (browser_peer, connection));
                    http.as_mut().ok_or("unexpected VPN packet")?.receive(request)?;
                    swarm.behaviour_mut().packet.send_response(channel, PacketResponse::Accepted)
                        .map_err(|_| "packet response stream closed")?;
                }
                _ => {}
            }
        }
        if let Some(http) = &mut http {
            for frame in http.poll(&mut sequence)? {
                swarm
                    .behaviour_mut()
                    .packet
                    .send_request(&browser_peer, frame);
            }
        }
    }
}
