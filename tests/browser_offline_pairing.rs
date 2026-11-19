use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use p2p_vpn::{
    config::Config,
    identity::NodeIdentity,
    membership::{
        MembershipRole,
        checkpoint::{
            CheckpointMember, CooperativeMembershipState, MembershipChange, NetworkAnchor,
            NetworkCapability, SnapshotPolicy, SnapshotPublisher,
        },
    },
    pairing::{
        MAX_PAIRING_MESSAGE_LEN, PairingCheckpointGrant, PairingConfigOptions, PairingError,
        PairingOffer, PairingOfferOptions, PairingRequest, PairingRequestOptions, PairingResponse,
        PairingResponseOptions, build_checkpoint_pairing_response_at,
        build_named_pairing_request_at, build_pairing_response_at,
        checkpoint_grant::VerifiedCheckpointEnrollment, export_code_pairing_offer_at,
        export_pairing_offer_at, import_pairing_response_config_at,
    },
};

#[path = "../crates/p2p-vpn-browser/src/offline_pairing.rs"]
mod offline_pairing;
use offline_pairing::{OfflineError, OfflineSession};

const NOW: u64 = 1_000;

fn identity(seed: u8) -> NodeIdentity {
    let keys = libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).expect("fixture key");
    NodeIdentity::from_private_key(&STANDARD.encode(keys.to_protobuf_encoding().unwrap())).unwrap()
}

fn inviter_config(inviter: &NodeIdentity) -> Config {
    serde_json::from_value(serde_json::json!({
        "network": {
            "name": "offline-lab",
            "local_peer": inviter.peer_id,
            "private_key": inviter.private_key,
            "listen_addresses": [],
            "external_addresses": ["/ip4/192.0.2.1/udp/4433/webrtc-direct"],
        },
    }))
    .unwrap()
}

fn offer_options(token: u8) -> PairingOfferOptions {
    PairingOfferOptions {
        expires_in_seconds: 300,
        rendezvous_token: Some(URL_SAFE_NO_PAD.encode([token; 16])),
    }
}

fn config_options(identity: NodeIdentity) -> PairingConfigOptions {
    PairingConfigOptions {
        identity,
        interface_name: "p2p-browser".to_owned(),
        mtu: 1280,
        local_routes: Vec::new(),
        peer_name: None,
    }
}

fn legacy_response(config: &Config, offer: &PairingOffer, joiner: &str) -> PairingResponse {
    build_pairing_response_at(
        config,
        offer,
        PairingResponseOptions {
            joiner_peer: joiner.to_owned(),
            assigned_vpn_ip: Some("10.90.0.2".to_owned()),
            membership_key: Some(STANDARD.encode([9_u8; 32])),
            member_records: Vec::new(),
            expires_in_seconds: 60,
        },
        NOW + 2,
    )
    .expect("signed native response")
}

#[test]
fn offline_json_and_uri_produce_the_same_native_request_and_import_legacy() {
    let config = inviter_config(&identity(1));
    let joiner = identity(2);
    let offer = export_pairing_offer_at(&config, offer_options(3), NOW).unwrap();
    let native_request = build_named_pairing_request_at(
        &offer,
        PairingRequestOptions {
            identity: joiner.clone(),
            requested_vpn_ip: None,
            requested_routes: Vec::new(),
        },
        Some("browser-node"),
        NOW + 1,
    )
    .unwrap();
    let expected = serde_json::to_string(&native_request).unwrap();
    for artifact in [
        serde_json::to_string_pretty(&offer).unwrap(),
        format!("{}\n", offer.to_uri().unwrap()),
    ] {
        let session =
            OfflineSession::begin_at(&artifact, joiner.clone(), Some(" Browser-Node "), NOW + 1)
                .expect("signed file-bearer request");
        assert_eq!(session.request_json, expected);
        assert!(!session.request_json.contains(&joiner.private_key));
        let request: PairingRequest = serde_json::from_str(&session.request_json).unwrap();
        request.verify_for_offer_at(&offer, NOW + 2).unwrap();
        assert!(request.code_authentication.is_none());

        let response = legacy_response(&config, &offer, &request.payload.joiner_peer);
        let decoded = session
            .verify_response_at(&serde_json::to_string_pretty(&response).unwrap(), NOW + 3)
            .expect("approved native response");
        let imported = import_pairing_response_config_at(
            &session.offer,
            &decoded,
            config_options(session.identity),
            NOW + 3,
        )
        .expect("legacy config");
        assert_eq!(imported.identity().unwrap().peer_id, joiner.peer_id);
        assert_eq!(imported.network.vpn_ip.as_deref(), Some("10.90.0.2"));
        assert_eq!(
            imported.network.membership_key,
            response.payload.membership_key
        );
    }
}

#[test]
fn offline_rejects_code_approval_tampering_and_wrong_binding() {
    let config = inviter_config(&identity(1));
    let joiner = identity(2);
    let code_offer = export_code_pairing_offer_at(&config, offer_options(3), NOW).unwrap();
    for artifact in [
        code_offer.to_uri().unwrap(),
        serde_json::to_string(&code_offer).unwrap(),
    ] {
        assert!(matches!(
            OfflineSession::begin_at(&artifact, joiner.clone(), None, NOW),
            Err(OfflineError::RequiresFileBearer)
        ));
    }
    let offer = export_pairing_offer_at(&config, offer_options(4), NOW).unwrap();
    let session =
        OfflineSession::begin_at(&offer.to_uri().unwrap(), joiner.clone(), None, NOW).unwrap();
    let oversized = " ".repeat(MAX_PAIRING_MESSAGE_LEN * 2 + 1);
    assert!(matches!(
        OfflineSession::begin_at(&oversized, joiner.clone(), None, NOW),
        Err(OfflineError::TooLarge)
    ));
    assert!(matches!(
        session.verify_response_at(&oversized, NOW + 3),
        Err(OfflineError::TooLarge)
    ));
    assert!(matches!(
        OfflineSession::begin_at(&offer.to_uri().unwrap(), joiner.clone(), None, NOW + 301),
        Err(OfflineError::Verification(PairingError::Expired { .. }))
    ));
    let mut tampered_offer = offer.clone();
    tampered_offer.payload.network_name = "different-lab".to_owned();
    assert!(matches!(
        OfflineSession::begin_at(
            &serde_json::to_string(&tampered_offer).unwrap(),
            joiner.clone(),
            None,
            NOW
        ),
        Err(OfflineError::Verification(PairingError::InvalidSignature))
    ));
    let wrong_peer = legacy_response(&config, &offer, &identity(5).peer_id);
    assert!(matches!(
        session.verify_response_at(&serde_json::to_string(&wrong_peer).unwrap(), NOW + 3),
        Err(OfflineError::Verification(
            PairingError::JoinerMismatch { .. }
        ))
    ));
    let other_offer = export_pairing_offer_at(&config, offer_options(6), NOW).unwrap();
    let wrong_token = legacy_response(&config, &other_offer, &joiner.peer_id);
    assert!(matches!(
        session.verify_response_at(&serde_json::to_string(&wrong_token).unwrap(), NOW + 3),
        Err(OfflineError::Verification(
            PairingError::RendezvousTokenMismatch
        ))
    ));
    let mut response = legacy_response(&config, &offer, &joiner.peer_id);
    assert!(matches!(
        session.verify_response_at(&serde_json::to_string(&response).unwrap(), NOW + 63),
        Err(OfflineError::Verification(PairingError::Expired { .. }))
    ));
    response.payload.assigned_vpn_ip = Some("10.90.0.3".to_owned());
    assert!(matches!(
        session.verify_response_at(&serde_json::to_string(&response).unwrap(), NOW + 3),
        Err(OfflineError::Verification(PairingError::InvalidSignature))
    ));
}

fn checkpoint_response(
    config: &Config,
    offer: &PairingOffer,
    inviter: &NodeIdentity,
    request: &PairingRequest,
) -> PairingResponse {
    request.verify_for_offer_at(offer, NOW + 1).unwrap();
    let member = |subject, byte| CheckpointMember {
        subject,
        incarnation: [byte; 32],
        roles: vec![MembershipRole::OverlayMember],
        route_grants: Vec::new(),
        expires_at_unix_seconds: None,
    };
    let secret = [7; 32];
    let capability =
        NetworkCapability::from_secret(NetworkAnchor::new([8; 32]).unwrap(), Some(&secret))
            .unwrap();
    let mut state = CooperativeMembershipState::bootstrap_at(
        capability,
        inviter.peer_id.clone(),
        vec![member(
            SnapshotPublisher::from_identity(inviter).unwrap(),
            1,
        )],
        SnapshotPolicy::default(),
        NOW,
    )
    .unwrap();
    let mutation = state
        .sign_mutation_at(
            inviter,
            MembershipChange::UpsertMember(member(
                SnapshotPublisher {
                    peer_id: request.payload.joiner_peer.clone(),
                    public_key: request.payload.joiner_public_key.clone(),
                },
                2,
            )),
            NOW + 1,
        )
        .unwrap();
    state.apply_mutation_at(&mutation, NOW + 1).unwrap();
    let grant = PairingCheckpointGrant::from_state_at(
        &state,
        &secret,
        &request.payload.joiner_peer,
        NOW + 2,
    )
    .unwrap();
    build_checkpoint_pairing_response_at(
        config,
        offer,
        PairingResponseOptions {
            joiner_peer: request.payload.joiner_peer.clone(),
            assigned_vpn_ip: None,
            membership_key: None,
            member_records: Vec::new(),
            expires_in_seconds: 60,
        },
        grant,
        NOW + 2,
    )
    .unwrap()
}

#[test]
fn offline_checkpoint_response_has_a_pending_floor_and_no_legacy_import() {
    let inviter = identity(1);
    let joiner = identity(2);
    let config = inviter_config(&inviter);
    let offer = export_pairing_offer_at(&config, offer_options(3), NOW).unwrap();
    let session =
        OfflineSession::begin_at(&offer.to_uri().unwrap(), joiner.clone(), None, NOW).unwrap();
    let request: PairingRequest = serde_json::from_str(&session.request_json).unwrap();
    let response = checkpoint_response(&config, &offer, &inviter, &request);
    let floor = response.payload.checkpoint.as_ref().unwrap().minimum;
    let decoded = session
        .verify_response_at(&serde_json::to_string(&response).unwrap(), NOW + 3)
        .expect("approved native checkpoint response");
    let seed = VerifiedCheckpointEnrollment::verify_at(
        &session.offer,
        &decoded,
        &session.identity,
        NOW + 3,
    )
    .unwrap()
    .unwrap()
    .into_pending_seed()
    .unwrap();
    assert_eq!(seed.enrollment_floor, floor);
    assert!(seed.retained.snapshot.payload.rank().unwrap() < floor);
    assert!(matches!(
        import_pairing_response_config_at(
            &session.offer,
            &decoded,
            config_options(joiner),
            NOW + 3
        ),
        Err(PairingError::CheckpointEnrollmentRequired)
    ));
}
