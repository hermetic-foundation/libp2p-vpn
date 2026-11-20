//! Signed legacy page scripts for receiver conformance.
use super::*;
use p2p_vpn::runtime::control::MembershipRecordsRejectionReason;

pub(super) fn is_scenario(scenario: &str) -> bool {
    matches!(
        scenario,
        "snapshot-interrupted"
            | "snapshot-invalid"
            | "snapshot-changed"
            | "snapshot-churn"
            | "snapshot-conflict"
            | "snapshot-expired"
    )
}

pub(super) fn name(identity: &NodeIdentity, network: &str) -> Result<String> {
    let peer = p2p_vpn::PeerId::from_libp2p(identity.peer_id.parse()?);
    let label = p2p_vpn::dns::peer_fallback_label(peer);
    let zone = p2p_vpn::dns::zone_name(network).map_err(debug_error)?;
    Ok(p2p_vpn::dns::fully_qualified_name(&label, &zone).map_err(debug_error)?)
}

pub(super) fn add_history(
    scenario: &str,
    records: &mut Vec<SignedMembershipRecord>,
    issuer: &NodeIdentity,
    subject: &NodeIdentity,
    network: &str,
    now: u64,
) -> Result<()> {
    let grant = |sequence, issued, expires| {
        issue_membership_record_at(
            issuer,
            MembershipRecordOptions {
                network_name: network.into(),
                member: subject.clone(),
                membership_epoch: 1,
                sequence,
                roles: vec![MembershipRole::OverlayMember],
                route_grants: vec![],
                expires_at_unix_seconds: Some(expires),
            },
            issued,
        )
        .map_err(debug_error)
    };
    records.push(grant(1, now - 100, now + 300)?);
    match scenario {
        "snapshot-conflict" => records.push(grant(1, now - 100, now + 301)?),
        "snapshot-expired" => records.push(grant(2, now - 90, now - 1)?),
        _ => {}
    }
    Ok(())
}

pub(super) struct Probe {
    scenario: String,
    cursors: Vec<u16>,
    changes: usize,
}

impl Probe {
    pub(super) fn new(scenario: &str) -> Self {
        Self {
            scenario: scenario.into(),
            cursors: Vec::new(),
            changes: 0,
        }
    }
}

impl Fixture {
    pub(super) fn serve_snapshot_probe(
        &mut self,
        request: MembershipRecordsRequest,
        channel: request_response::ResponseChannel<ControlResponse>,
    ) -> Result<()> {
        let probe = self.membership_probe.as_mut().expect("snapshot scenario");
        let cursor = request.cursor;
        probe.cursors.push(cursor);
        if cursor == 0 && probe.changes != 0 {
            assert!(
                request.snapshot.is_none(),
                "restart kept the stale snapshot"
            );
        }
        if cursor != 0 && probe.scenario == "snapshot-interrupted" {
            println!("{}", json!({ "cursors": probe.cursors }));
            let _ = self.swarm.disconnect_peer_id(self.peer);
            return Ok(());
        }
        if cursor != 0
            && (probe.scenario == "snapshot-churn"
                || probe.scenario == "snapshot-changed" && probe.changes == 0)
        {
            // Keep both incumbents and the candidate; remove one filler event.
            self.records_to_serve.remove(2);
            probe.changes += 1;
        }
        let (response, report) = match control::build_membership_records_page(
            &request,
            &self.records_to_serve,
            &self.caps.network_name,
            None,
            &[],
        ) {
            Ok(mut page) => {
                if cursor != 0 && probe.scenario == "snapshot-invalid" {
                    page.cursor -= 1;
                }
                let report = page
                    .next_cursor
                    .is_none()
                    .then(|| json!({ "cursors": probe.cursors, "snapshot": page.snapshot }));
                (ControlResponse::MembershipRecordsPage(page), report)
            }
            Err(reason) => {
                assert_eq!(reason, MembershipRecordsRejectionReason::SnapshotChanged);
                let report = (probe.changes == 4).then(|| json!({ "cursors": probe.cursors }));
                (ControlResponse::MembershipRecordsRejected(reason), report)
            }
        };
        self.swarm
            .behaviour_mut()
            .control
            .send_response(channel, response)
            .map_err(debug_error)?;
        if let Some(report) = report {
            println!("{report}");
        }
        Ok(())
    }
}
