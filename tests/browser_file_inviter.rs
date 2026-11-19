use p2p_vpn::{
    config::Config,
    identity::NodeIdentity,
    membership::{
        MembershipRecordIssueOptions, MembershipRecordSubject, MembershipRole,
        issue_membership_record_for_subject_at,
    },
    pairing::{
        PairingConfigOptions, PairingOffer, PairingRequest, PairingRequestOptions, PairingResponse,
        build_named_pairing_request_at, import_pairing_response_config_at,
    },
};

#[path = "../crates/p2p-vpn-browser/src/file_inviter_core.rs"]
mod file_inviter;

use file_inviter::{ApprovalError, FileInviter};

const NOW: u64 = 10_000;

fn config(founder: &NodeIdentity) -> Config {
    serde_json::from_value(serde_json::json!({
        "network": {
            "name": "file-inviter-native",
            "local_peer": founder.peer_id,
            "private_key": founder.private_key,
            "external_addresses": ["/ip4/192.0.2.1/udp/4433/webrtc-direct"],
        },
    }))
    .unwrap()
}

fn request(offer: &PairingOffer, joiner: &NodeIdentity, ip: Option<String>) -> PairingRequest {
    build_named_pairing_request_at(
        offer,
        PairingRequestOptions {
            identity: joiner.clone(),
            requested_routes: Vec::new(),
            requested_vpn_ip: ip,
        },
        Some("new-peer"),
        NOW + 1,
    )
    .unwrap()
}

#[test]
fn native_request_and_import_match_the_detached_inviter() {
    let founder = NodeIdentity::generate_ed25519().unwrap();
    let joiner = NodeIdentity::generate_ed25519().unwrap();
    let mut inviter = FileInviter::open(config(&founder), &[], NOW).unwrap();
    let offer = PairingOffer::from_uri(&inviter.create_offer(None, NOW).unwrap()).unwrap();
    let request = request(&offer, &joiner, None);
    inviter
        .review_request(&serde_json::to_string(&request).unwrap(), NOW + 1)
        .unwrap();
    let response: PairingResponse = serde_json::from_str(
        &inviter
            .approve(&joiner.peer_id, NOW + 2, |records| {
                assert_eq!(records.len(), 2);
                Ok::<_, ()>(())
            })
            .unwrap(),
    )
    .unwrap();
    let config = import_pairing_response_config_at(
        &offer,
        &response,
        PairingConfigOptions {
            identity: joiner.clone(),
            interface_name: "p2p-test".into(),
            mtu: 1280,
            local_routes: Vec::new(),
            peer_name: None,
        },
        NOW + 3,
    )
    .unwrap();
    assert_eq!(config.identity().unwrap().peer_id, joiner.peer_id);
    assert!(
        config
            .network
            .member_records
            .iter()
            .any(|record| record.payload.member_peer == joiner.peer_id
                && record.payload.roles == [MembershipRole::OverlayMember]
                && record.payload.route_grants.is_empty()
                && record.payload.hostname.as_deref() == Some("new-peer"))
    );
}

#[test]
fn expiry_route_requests_and_revoked_root_fail_closed() {
    let founder = NodeIdentity::generate_ed25519().unwrap();
    let joiner = NodeIdentity::generate_ed25519().unwrap();
    let config = config(&founder);
    let mut inviter = FileInviter::open(config.clone(), &[], NOW).unwrap();
    let offer = PairingOffer::from_uri(&inviter.create_offer(Some(2), NOW).unwrap()).unwrap();
    let custom = request(&offer, &joiner, Some("10.1.2.3".into()));
    assert!(
        inviter
            .review_request(&serde_json::to_string(&custom).unwrap(), NOW + 1)
            .is_err()
    );
    let valid = request(&offer, &joiner, None);
    inviter
        .review_request(&serde_json::to_string(&valid).unwrap(), NOW + 1)
        .unwrap();
    assert!(matches!(
        inviter.approve(&joiner.peer_id, NOW + 3, |_| -> Result<(), ()> {
            panic!("expired offer reached persistence")
        }),
        Err(ApprovalError::Rejected(
            "Expired or invalid signed pairing request"
        ))
    ));
    inviter.cancel_offer();
    let revoked = issue_membership_record_for_subject_at(
        &founder,
        MembershipRecordIssueOptions {
            network_name: config.network.name.clone(),
            member: MembershipRecordSubject::from_identity(&founder).unwrap(),
            membership_epoch: 1,
            sequence: NOW,
            revoked: true,
            roles: Vec::new(),
            route_grants: Vec::new(),
            expires_at_unix_seconds: None,
        },
        NOW,
    )
    .unwrap();
    assert!(FileInviter::open(config, &[revoked], NOW + 1).is_err());
}
