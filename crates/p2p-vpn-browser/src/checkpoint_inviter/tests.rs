//! Portable browser issuer and native verifier interoperability (no daemon needed).

use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use p2p_vpn::{
    config::Config,
    identity::NodeIdentity,
    membership::checkpoint::{
        CheckpointMember, CooperativeMembershipState, MembershipSyncState, NetworkAnchor,
        NetworkCapability, RetainedCheckpointState, SnapshotPolicy,
    },
    pairing::{
        PairingOffer, PairingOfferOptions, PairingRequest, PairingRequestOptions,
        build_named_pairing_request_at, checkpoint_grant::VerifiedCheckpointEnrollment,
        export_pairing_offer_at,
    },
    pairing_code::{
        PairingCode, answer_pairing_code_hello_v2_at, authenticate_pairing_request,
        open_pairing_code_challenge_v2_at, start_pairing_code_hello_v2_at,
        verify_pairing_request_code_authentication,
    },
    runtime::{
        control::checkpoint::{CheckpointProgress, CheckpointSync, CheckpointSyncLimits},
        forward::Forwarder,
    },
};

use super::{AdmissionError, CodeRecovery, CommitError, FileApproval, PreparedAdmission};

const NOW: u64 = 1_000;
const SECRET: [u8; 32] = [8; 32];

struct Fixture {
    config: Config,
    inviter: NodeIdentity,
    joiner: NodeIdentity,
    installed: CooperativeMembershipState,
    forwarder: Forwarder,
    offer: PairingOffer,
    request: PairingRequest,
}

fn fixture() -> Fixture {
    let (inviter, joiner) = loop {
        let inviter = NodeIdentity::generate_ed25519().unwrap();
        let joiner = NodeIdentity::generate_ed25519().unwrap();
        let address = |identity: &NodeIdentity| {
            p2p_vpn::route::builtin_ipv4(identity.peer_id.parse().unwrap())
        };
        if address(&inviter) != address(&joiner) {
            break (inviter, joiner);
        }
    };
    let relay = NodeIdentity::generate_ed25519().unwrap().peer_id;
    let circuit = format!(
        "/ip4/127.0.0.1/tcp/4001/p2p/{relay}/p2p-circuit/p2p/{}",
        inviter.peer_id
    );
    let config = serde_json::from_value(serde_json::json!({
        "network": {
            "name": "checkpoint-inviter",
            "private_key": inviter.private_key,
            "listen_addresses": [],
            "external_addresses": [circuit],
        },
    }))
    .unwrap();
    let anchor = NetworkAnchor::new([12; 32]).unwrap();
    let installed = CooperativeMembershipState::bootstrap_at(
        NetworkCapability::from_secret(anchor.clone(), Some(&SECRET)).unwrap(),
        inviter.peer_id.clone(),
        vec![CheckpointMember::new(&inviter).unwrap()],
        SnapshotPolicy::default(),
        NOW,
    )
    .unwrap();
    let forwarder = Forwarder::from_checkpoint_config(&config, &installed, &anchor, NOW).unwrap();
    let offer = export_pairing_offer_at(&config, PairingOfferOptions::default(), NOW).unwrap();
    let request = build_named_pairing_request_at(
        &offer,
        PairingRequestOptions {
            identity: joiner.clone(),
            requested_vpn_ip: None,
            requested_routes: vec![],
        },
        None,
        NOW,
    )
    .unwrap();
    Fixture {
        config,
        inviter,
        joiner,
        installed,
        forwarder,
        offer,
        request,
    }
}

fn ready<T>(future: impl Future<Output = T>) -> T {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("fixture store became asynchronous"),
    }
}

fn prepare(f: &mut Fixture) -> PreparedAdmission<'_> {
    let expected = f.installed.snapshot().payload.boundary().unwrap();
    PreparedAdmission::prepare(
        &f.config,
        &mut f.installed,
        &mut f.forwarder,
        &SECRET,
        FileApproval {
            expected,
            offer: &f.offer,
            request: &f.request,
            wall_now: NOW,
        },
    )
    .unwrap()
}

#[test]
fn issued_file_grant_activates_through_native_checkpoint_transfer() {
    let mut f = fixture();
    let mut durable = f.installed.retained();
    let mut survivor = f.installed.clone();
    let mut gated = false;
    let issued = ready(prepare(&mut f).commit(&mut gated, async |base, next| {
        assert_eq!(durable, base);
        durable = next;
        Ok::<_, ()>(())
    }))
    .unwrap();
    assert!(gated, "only the live owner can reopen packet forwarding");
    assert_eq!(f.installed.retained(), durable);
    let joiner = f.joiner.peer_id.parse().unwrap();
    assert!(f.forwarder.is_configured_transport_peer(joiner));
    survivor.apply_mutation_at(&issued.mutation, NOW).unwrap();
    assert_eq!(survivor.retained(), durable);

    let response = serde_json::from_slice(&serde_json::to_vec(&issued.response).unwrap()).unwrap();
    let verified = VerifiedCheckpointEnrollment::verify_at(&f.offer, &response, &f.joiner, NOW)
        .unwrap()
        .unwrap();
    assert_eq!(
        verified.grant().minimum,
        durable.snapshot.payload.rank().unwrap()
    );
    assert_eq!(
        &verified.grant().joiner,
        durable.snapshot.payload.member(&f.joiner.peer_id).unwrap()
    );
    assert_ne!(verified.grant().joiner.incarnation, [1; 32]);
    let anchor = verified.grant().anchor.clone();
    let secret = verified.grant().secret_bytes().unwrap();
    let capability = NetworkCapability::from_secret(anchor.clone(), Some(&secret)).unwrap();
    let pending = verified.into_pending_seed().unwrap();
    let mut receiver =
        CooperativeMembershipState::restore(capability, f.joiner.peer_id, pending.retained)
            .unwrap();
    assert_eq!(receiver.sync_state(), MembershipSyncState::ResyncRequired);

    let start = Instant::now();
    let window = Duration::from_secs(1);
    let challenge = receiver.begin_resync(start, window).unwrap();
    let inviter = f.inviter.peer_id.parse().unwrap();
    let mut client =
        CheckpointSync::new(joiner, anchor.clone(), CheckpointSyncLimits::default()).unwrap();
    let mut server = CheckpointSync::new(inviter, anchor, CheckpointSyncLimits::default()).unwrap();
    let mut page = client
        .start_request(inviter, challenge, &secret, start, start + window)
        .unwrap();
    loop {
        let reply = server
            .respond_at(joiner, &page, &f.installed, &f.inviter, &SECRET, start, NOW)
            .unwrap();
        match client
            .accept_response(inviter, &page, reply, &secret, start)
            .unwrap()
        {
            CheckpointProgress::More(next) => page = next,
            CheckpointProgress::Complete(offer) => {
                receiver.collect_offer(&offer, inviter, start).unwrap();
                break;
            }
        }
    }
    let selected = receiver.finish_resync(start + window, NOW).unwrap();
    assert!(selected.observed_remote_offer);
    assert_eq!(selected.sync_state, MembershipSyncState::Participating);
    assert_eq!(
        receiver.snapshot().payload.rank().unwrap(),
        pending.enrollment_floor
    );
    assert_eq!(receiver.retained(), durable);
}

#[test]
fn v2_checkpoint_lost_acceptance_recovers_after_reopen_without_readmission() {
    let mut f = fixture();
    let code = PairingCode::generate();
    let inviter = f.inviter.peer_id.parse().unwrap();
    let joiner = f.joiner.peer_id.parse().unwrap();
    let (hello, pending) = start_pairing_code_hello_v2_at(&code, &f.joiner, inviter, NOW).unwrap();
    let (challenge, inviter_session) = answer_pairing_code_hello_v2_at(
        &f.config,
        &code,
        &hello,
        joiner,
        PairingOfferOptions::default(),
        NOW,
    )
    .unwrap();
    let (offer, joiner_session) =
        open_pairing_code_challenge_v2_at(pending, &challenge, inviter, NOW).unwrap();
    let mut request = build_named_pairing_request_at(
        &offer,
        PairingRequestOptions {
            identity: f.joiner.clone(),
            requested_vpn_ip: None,
            requested_routes: vec![],
        },
        None,
        NOW,
    )
    .unwrap();
    authenticate_pairing_request(&mut request, &joiner_session).unwrap();
    verify_pairing_request_code_authentication(&request, &inviter_session).unwrap();
    request.verify_for_offer_at(&offer, NOW).unwrap();

    let expected = f.installed.snapshot().payload.boundary().unwrap();
    assert!(matches!(
        PreparedAdmission::prepare(
            &f.config,
            &mut f.installed,
            &mut f.forwarder,
            &SECRET,
            FileApproval {
                expected,
                offer: &offer,
                request: &request,
                wall_now: NOW
            },
        ),
        Err(AdmissionError::InvalidFileRequest)
    ));
    assert!(!f.forwarder.is_configured_transport_peer(joiner));

    let approval = || FileApproval {
        expected,
        offer: &offer,
        request: &request,
        wall_now: NOW,
    };
    assert!(matches!(
        PreparedAdmission::prepare_bound(
            &f.config,
            &mut f.installed,
            &mut f.forwarder,
            &SECRET,
            approval(),
            Some((&inviter_session, inviter)),
        ),
        Err(AdmissionError::InvalidCodeRequest)
    ));
    let base = f.installed.retained();
    let mut gated = false;
    let failed = PreparedAdmission::prepare_bound(
        &f.config,
        &mut f.installed,
        &mut f.forwarder,
        &SECRET,
        approval(),
        Some((&inviter_session, joiner)),
    )
    .unwrap();
    assert!(matches!(
        ready(failed.commit(&mut gated, async |_, _| Err(()))),
        Err(CommitError::Storage(()))
    ));
    assert!(gated);
    assert_eq!(f.installed.retained(), base);
    assert!(!f.forwarder.is_configured_transport_peer(joiner));

    // The owner has reconciled the unchanged durable base and may retry.
    gated = false;
    let retry = PreparedAdmission::prepare_bound(
        &f.config,
        &mut f.installed,
        &mut f.forwarder,
        &SECRET,
        approval(),
        Some((&inviter_session, joiner)),
    )
    .unwrap();
    let recovery = retry.code_recovery("exact pending ticket".into(), NOW + 60);
    let mut durable = None;
    let response = ready(retry.commit(&mut gated, async |saved, next| {
        assert_eq!(saved, base);
        assert_ne!(saved, next);
        durable = Some(serde_json::to_vec(&(next, recovery)).unwrap());
        Ok::<_, ()>(())
    }))
    .unwrap()
    .response;
    // Drop the first Accepted and reopen from the one durable write.
    let (retained, receipt): (RetainedCheckpointState, CodeRecovery) =
        serde_json::from_slice(&durable.unwrap()).unwrap();
    assert!(receipt.owns_admission(joiner, &retained));
    assert!(!receipt.owns_admission(inviter, &retained));
    assert!(!receipt.owns_admission(joiner, &base));
    let boundary = retained.snapshot.payload.boundary().unwrap();
    let address = &offer.payload.inviter_addresses[0];
    let ticket = "exact pending ticket";
    assert_eq!(
        receipt.recover(joiner, ticket, boundary, address, NOW + 1, &SECRET),
        Some(response.clone())
    );
    assert_eq!(
        receipt.recover(joiner, ticket, boundary, address, NOW + 2, &SECRET),
        Some(response.clone())
    );
    assert_eq!(retained, f.installed.retained());
    assert_eq!(boundary.authority_revision, expected.authority_revision + 1);
    assert!(
        receipt
            .recover(inviter, ticket, boundary, address, NOW + 1, &SECRET)
            .is_none()
    );
    assert!(
        receipt
            .recover(
                joiner,
                "different ticket",
                boundary,
                address,
                NOW + 1,
                &SECRET
            )
            .is_none()
    );
    assert!(
        receipt
            .recover(joiner, ticket, expected, address, NOW + 1, &SECRET)
            .is_none()
    );
    assert!(
        receipt
            .recover(joiner, ticket, boundary, "/different", NOW + 1, &SECRET)
            .is_none()
    );
    assert!(
        receipt
            .recover(joiner, ticket, boundary, address, NOW + 60, &SECRET)
            .is_none()
    );
    assert!(
        receipt
            .response
            .payload
            .checkpoint
            .as_ref()
            .unwrap()
            .capability_secret
            .is_empty()
    );
    let verified = VerifiedCheckpointEnrollment::verify_at(&offer, &response, &f.joiner, NOW)
        .unwrap()
        .unwrap();
    let capability = NetworkCapability::from_secret(
        verified.grant().anchor.clone(),
        Some(&verified.grant().secret_bytes().unwrap()),
    )
    .unwrap();
    let seed = verified.into_pending_seed().unwrap();
    let receiver =
        CooperativeMembershipState::restore(capability, f.joiner.peer_id, seed.retained).unwrap();
    assert_eq!(receiver.sync_state(), MembershipSyncState::ResyncRequired);
}

#[test]
fn failed_or_unfinished_save_never_releases_an_enrollment() {
    let mut f = fixture();
    let base = f.installed.retained();
    let mut gated = false;
    let mut visible = None;
    let result = ready(prepare(&mut f).commit(&mut gated, async |_, next| {
        visible = Some(next);
        Err("failed after write")
    }));
    assert!(matches!(
        result,
        Err(CommitError::Storage("failed after write"))
    ));
    assert!(visible.is_some());
    assert!(gated);
    assert_eq!(f.installed.retained(), base);
    assert!(
        !f.forwarder
            .is_configured_transport_peer(f.joiner.peer_id.parse().unwrap())
    );

    let result = ready(
        prepare(&mut f).commit(&mut gated, async |_, _| -> Result<(), ()> {
            panic!("a gated issuer must not write another admission");
        }),
    );
    assert!(matches!(result, Err(CommitError::AlreadyGated)));

    gated = false;
    {
        let mut transaction = pin!(prepare(&mut f).commit(&mut gated, async |_, _| {
            std::future::pending::<Result<(), ()>>().await
        }));
        assert!(
            transaction
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    assert!(gated);
    assert_eq!(f.installed.retained(), base);
}

#[test]
fn refuses_stale_review_and_bad_signed_requests_before_storage() {
    let mut f = fixture();
    let expected = f.installed.snapshot().payload.boundary().unwrap();
    let mut stale = expected;
    stale.digest[0] ^= 1;
    assert!(matches!(
        PreparedAdmission::prepare(
            &f.config,
            &mut f.installed,
            &mut f.forwarder,
            &SECRET,
            FileApproval {
                expected: stale,
                offer: &f.offer,
                request: &f.request,
                wall_now: NOW
            },
        ),
        Err(AdmissionError::StaleApproval)
    ));
    f.request.signature.clear();
    assert!(matches!(
        PreparedAdmission::prepare(
            &f.config,
            &mut f.installed,
            &mut f.forwarder,
            &SECRET,
            FileApproval {
                expected,
                offer: &f.offer,
                request: &f.request,
                wall_now: NOW
            },
        ),
        Err(AdmissionError::Pairing(_))
    ));
    assert_eq!(f.installed.snapshot().payload.boundary().unwrap(), expected);
}
