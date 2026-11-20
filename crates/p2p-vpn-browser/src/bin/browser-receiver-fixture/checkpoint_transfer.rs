use std::{
    collections::HashSet,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use libp2p::swarm::ConnectionId;
use p2p_vpn::{
    config::membership_tag,
    membership::checkpoint::{
        CheckpointMember, CooperativeMembershipState, MembershipChange, NetworkAnchor,
        NetworkCapability, SnapshotChallenge, SnapshotPolicy,
    },
    route::builtin_ipv4,
    runtime::control::checkpoint::{
        self, CheckpointCodec, CheckpointPageResponse, CheckpointSync, CheckpointSyncIndicator,
        CheckpointSyncLimits, MAX_PAGE_BYTES,
    },
};

use super::{
    ControlCapabilities, ControlRequest, ControlResponse, Message, NATIVE_MTU, NetworkBehaviour,
    NodeIdentity, PathKind, Protocol, Result, StreamExt, SwarmBuilder, SwarmEvent, control,
    debug_error, json, request_response,
};

const NETWORK: &str = "checkpoint-interrupted";
const SECRET: [u8; 32] = [37; 32];

#[derive(NetworkBehaviour)]
struct Wire {
    control: request_response::Behaviour<control::ControlCodec>,
    checkpoint: request_response::Behaviour<CheckpointCodec>,
}

pub(super) async fn run() -> Result<()> {
    let wall_now = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|time| time.as_secs())
    };
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
    let certificate = libp2p_webrtc::tokio::Certificate::generate(&mut rand::rngs::OsRng)?;
    let mut swarm = SwarmBuilder::with_existing_identity(native.keypair().map_err(debug_error)?)
        .with_tokio()
        .with_other_transport(|key| libp2p_webrtc::tokio::Transport::new(key.clone(), certificate))?
        .with_behaviour(|_| Wire {
            control: control::behaviour(8),
            checkpoint: checkpoint::behaviour(8),
        })?
        .build();
    let local = *swarm.local_peer_id();
    let mut sync = CheckpointSync::new(local, anchor.clone(), CheckpointSyncLimits::default())?;
    swarm.listen_on("/ip4/192.0.2.1/udp/0/webrtc-direct".parse()?)?;
    let address = loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => break address.with(Protocol::P2p(local)),
            SwarmEvent::ListenerError { error, .. } => return Err(error.into()),
            _ => {}
        }
    };
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
