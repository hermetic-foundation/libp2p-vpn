//! Detached first-time enrollment with native legacy issuer proofs.
use std::net::IpAddr;

use p2p_vpn::{
    PeerId,
    config::{Config, RouteConfig},
    dns::{DnsConfig, DnsZone, canonical_dns_label, peer_fallback_label},
    membership::{
        MembershipRecordIssueOptions, MembershipRecordSubject, MembershipRole,
        SignedMembershipRecord, effective_membership_at,
        issue_named_membership_record_for_subject_at, overlay_membership_proof_at,
    },
    pairing::{
        DEFAULT_PAIRING_EXPIRES_IN_SECONDS, MAX_PAIRING_MESSAGE_LEN, PairingOffer,
        PairingOfferOptions, PairingRequest, PairingResponse, PairingResponseOptions,
        build_pairing_response_at, export_pairing_offer_at,
    },
    route::builtin_ipv4,
    runtime::forward::Forwarder,
};
use serde::Serialize;

type Result<T> = std::result::Result<T, &'static str>;

pub(super) struct FileInviter {
    config: Config,
    pending: Option<Pending>,
}

struct Pending {
    offer: PairingOffer,
    request: Option<PairingRequest>,
}

#[derive(Serialize)]
struct Review<'a> {
    joiner_peer: &'a str,
    requested_hostname: Option<&'a str>,
    vpn_ipv4: std::net::Ipv4Addr,
}

impl FileInviter {
    pub(super) fn open(config: Config, saved: &[SignedMembershipRecord], now: u64) -> Result<Self> {
        Ok(Self {
            config: open_legacy_config(config, saved, now)?,
            pending: None,
        })
    }

    pub(super) fn create_offer(&mut self, seconds: Option<u32>, now: u64) -> Result<String> {
        let expires = seconds.map_or(DEFAULT_PAIRING_EXPIRES_IN_SECONDS, u64::from);
        if !(1..=DEFAULT_PAIRING_EXPIRES_IN_SECONDS).contains(&expires) {
            return Err("Offer lifetime must be between 1 and 600 seconds");
        }
        inviter_proof(
            &self.config.network.member_records,
            &self.config.network.name,
            &self.config.network.local_peer,
            now,
        )?;
        let offer = export_pairing_offer_at(
            &self.config,
            PairingOfferOptions {
                expires_in_seconds: expires,
                rendezvous_token: None,
            },
            now,
        )
        .map_err(|_| "Could not create signed file-bearer offer")?;
        let uri = offer.to_uri().map_err(|_| "Could not encode offer")?;
        self.pending = Some(Pending {
            offer,
            request: None,
        });
        Ok(uri)
    }

    pub(super) fn review_request(&mut self, json: &str, now: u64) -> Result<String> {
        let pending = self.pending.as_mut().ok_or("No active offer")?;
        if pending.request.is_some() {
            return Err("A request is already staged; cancel it or create a new offer");
        }
        if json.len() > MAX_PAIRING_MESSAGE_LEN * 2 {
            return Err("Pairing request exceeds its size limit");
        }
        let request = serde_json::from_str(json).map_err(|_| "Invalid pairing request JSON")?;
        validate_file_binding(&pending.offer, &request)?;
        let (_, ip, name) = validate_legacy_request(&self.config, &pending.offer, &request, now)?;
        let review = serde_json::to_string(&Review {
            joiner_peer: &request.payload.joiner_peer,
            requested_hostname: name.as_deref(),
            vpn_ipv4: ip,
        })
        .map_err(|_| "Could not encode pairing review")?;
        pending.request = Some(request);
        Ok(review)
    }

    pub(super) fn cancel_offer(&mut self) {
        self.pending = None;
    }

    /// The persistence callback must atomically replace the origin's legacy
    /// ledger under its identity lock. No response can escape before it succeeds.
    pub(super) fn approve<E>(
        &mut self,
        expected_peer: &str,
        now: u64,
        persist: impl FnOnce(&Config, &[SignedMembershipRecord]) -> std::result::Result<(), E>,
    ) -> std::result::Result<String, ApprovalError<E>> {
        let (encoded, ledger) = self
            .prepare_approval(expected_peer, now)
            .map_err(ApprovalError::Rejected)?;
        persist(&self.config, &ledger).map_err(ApprovalError::Storage)?;
        self.config.network.member_records = ledger;
        self.pending = None;
        Ok(encoded)
    }

    fn prepare_approval(
        &self,
        expected_peer: &str,
        now: u64,
    ) -> Result<(String, Vec<SignedMembershipRecord>)> {
        let pending = self.pending.as_ref().ok_or("No active offer")?;
        let request = pending.request.as_ref().ok_or("No reviewed request")?;
        if expected_peer != request.payload.joiner_peer {
            return Err("Approval did not name the reviewed joiner");
        }
        validate_file_binding(&pending.offer, request)?;
        let (response, ledger) = prepare_legacy_approval(
            &self.config,
            &pending.offer,
            request,
            now,
            DEFAULT_PAIRING_EXPIRES_IN_SECONDS,
        )?;
        let encoded =
            serde_json::to_string(&response).map_err(|_| "Could not encode pairing response")?;
        Ok((encoded, ledger))
    }
}

pub(super) fn open_legacy_config(
    mut config: Config,
    saved: &[SignedMembershipRecord],
    now: u64,
) -> Result<Config> {
    config
        .validate_runtime()
        .map_err(|_| "Invalid legacy config")?;
    config
        .identity()
        .map_err(|_| "Missing or mismatched inviter identity")?;
    let local = config
        .local_peer()
        .map_err(|_| "Invalid inviter identity")?;
    config.network.local_peer.clone_from(&local);
    let saved_proof = inviter_proof(saved, &config.network.name, &local, now)?;
    if config.network.member_records.is_empty()
        && proof_root(&saved_proof).is_some_and(|root| root != local)
    {
        return Err("Open a rooted config matching the saved legacy issuer root");
    }
    let forwarder = Forwarder::from_config(&config).map_err(|_| "Invalid legacy membership")?;
    let (merged, _) = forwarder
        .prepare_legacy_membership_merge(saved, now)
        .map_err(|_| "Could not load legacy membership")?;
    config.network.member_records = merged.member_records().to_vec();
    let merged_proof = inviter_proof(
        &config.network.member_records,
        &config.network.name,
        &local,
        now,
    )?;
    if let Some(root) = proof_root(&saved_proof)
        && proof_root(&merged_proof) != Some(root)
    {
        return Err("The config cannot replace the saved legacy issuer root");
    }
    Ok(config)
}

// Both callers authenticate their own enrollment transcript before preparing a grant.
pub(super) fn prepare_legacy_approval(
    config: &Config,
    offer: &PairingOffer,
    request: &PairingRequest,
    now: u64,
    response_lifetime: u64,
) -> Result<(PairingResponse, Vec<SignedMembershipRecord>)> {
    let (peer, _, name) = validate_legacy_request(config, offer, request, now)?;
    let identity = config.identity().map_err(|_| "Invalid inviter identity")?;
    let network = &config.network.name;
    let records = &config.network.member_records;
    let issue = |member, routes: Vec<RouteConfig>, name| {
        let mut roles = vec![MembershipRole::OverlayMember];
        if !routes.is_empty() {
            roles.push(MembershipRole::RouteAuthority);
        }
        issue_named_membership_record_for_subject_at(
            &identity,
            MembershipRecordIssueOptions {
                network_name: network.clone(),
                member,
                membership_epoch: 1,
                sequence: now,
                revoked: false,
                roles,
                route_grants: routes,
                expires_at_unix_seconds: None,
            },
            name,
            now,
        )
        .map_err(|_| "Could not sign legacy membership")
    };
    let mut proof = inviter_proof(records, network, &identity.peer_id, now)?;
    if proof.is_empty() {
        let mut routes = config.network.routes.clone();
        if let Some(ip) = &config.network.vpn_ip {
            let ip: IpAddr = ip.parse().map_err(|_| "Invalid inviter address")?;
            let route = RouteConfig {
                prefix: format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }),
                metric: 0,
            };
            if !routes.contains(&route) {
                routes.push(route);
            }
        }
        proof.push(issue(
            MembershipRecordSubject::from_identity(&identity).map_err(|_| "Invalid inviter key")?,
            routes,
            config.network.dns.hostname.as_deref(),
        )?);
    }
    let joiner = issue(
        MembershipRecordSubject {
            peer_id: request.payload.joiner_peer.clone(),
            public_key: request.payload.joiner_public_key.clone(),
        },
        Vec::new(),
        name.as_deref(),
    )?;
    proof.push(joiner.clone());
    let response = build_pairing_response_at(
        config,
        offer,
        PairingResponseOptions {
            joiner_peer: request.payload.joiner_peer.clone(),
            assigned_vpn_ip: request.payload.requested_vpn_ip.clone(),
            membership_key: config.network.membership_key.clone(),
            member_records: proof,
            expires_in_seconds: response_lifetime,
        },
        now,
    )
    .map_err(|_| "Could not sign pairing response")?;
    let (update, _) = Forwarder::from_config(config)
        .and_then(|forwarder| {
            forwarder.prepare_legacy_membership_merge(&response.payload.member_records, now)
        })
        .map_err(|_| "The legacy ledger rejected the admission")?;
    let ledger = update.member_records();
    let membership = effective_membership_at(ledger, network, now)
        .map_err(|_| "Could not evaluate the proposed legacy membership")?;
    let overlay_peer = PeerId::from_libp2p(peer);
    if !ledger.contains(&joiner) || !membership.overlay_members().any(|m| m.peer == overlay_peer) {
        return Err("The joiner did not receive active legacy membership");
    }
    if name.is_some() {
        // Name ownership does not depend on a local DNS listener.
        let mut dns_config = config.clone();
        let local = dns_config
            .local_peer_id()
            .map_err(|_| "Invalid inviter identity")?;
        // The zone builder requires a local name. Its fallback is already
        // owned by this identity, so this adds no new claim.
        dns_config.network.dns = DnsConfig {
            enabled: true,
            hostname: config
                .network
                .dns
                .hostname
                .clone()
                .or_else(|| Some(peer_fallback_label(local))),
            ..DnsConfig::default()
        };
        let zone = DnsZone::from_config_at(&dns_config, ledger, now)
            .map_err(|_| "Could not validate the proposed legacy hostname")?;
        if zone
            .conflicts()
            .any(|conflict| conflict.peers.contains(&overlay_peer))
        {
            return Err("The requested hostname is already in use");
        }
    }
    Ok((response, ledger.to_vec()))
}

#[derive(Debug)]
pub(super) enum ApprovalError<E> {
    Rejected(&'static str),
    Storage(E),
}

fn validate_file_binding(offer: &PairingOffer, request: &PairingRequest) -> Result<()> {
    let payload = &request.payload;
    if request.code_authentication.is_some()
        || request
            .offer
            .as_ref()
            .is_some_and(|attached| attached != offer)
        || payload.offer_signature != offer.signature
        || payload.offer_issued_at_unix_seconds != offer.payload.issued_at_unix_seconds
        || payload.offer_expires_at_unix_seconds != offer.payload.expires_at_unix_seconds
    {
        return Err("Request is not bound to this file-bearer offer");
    }
    Ok(())
}

pub(super) fn validate_legacy_request(
    config: &Config,
    offer: &PairingOffer,
    request: &PairingRequest,
    now: u64,
) -> Result<(libp2p::PeerId, std::net::Ipv4Addr, Option<String>)> {
    let payload = &request.payload;
    request
        .verify_for_offer_at(offer, now)
        .map_err(|_| "Expired or invalid signed pairing request")?;
    let peer = payload
        .joiner_peer
        .parse()
        .map_err(|_| "Invalid joiner identity")?;
    validate_new_joiner(config, peer)?;
    let ip = builtin_ipv4(PeerId::from_libp2p(peer));
    if !payload.requested_routes.is_empty()
        || payload
            .requested_vpn_ip
            .as_ref()
            .is_some_and(|value| value.parse::<IpAddr>() != Ok(ip.into()))
    {
        return Err("This profile does not approve routes or custom addresses");
    }
    let name = payload
        .requested_hostname
        .as_deref()
        .map(canonical_dns_label)
        .transpose()
        .map_err(|_| "Invalid requested hostname")?;
    Ok((peer, ip, name))
}

pub(super) fn validate_new_joiner(config: &Config, peer: libp2p::PeerId) -> Result<()> {
    let peer = peer.to_string();
    if peer == config.network.local_peer
        || config
            .network
            .member_records
            .iter()
            .any(|record| record.payload.member_peer == peer)
        || config.peers.iter().any(|configured| configured.id == peer)
    {
        return Err("This profile only admits a new peer with no prior membership");
    }
    Ok(())
}

fn inviter_proof(
    records: &[SignedMembershipRecord],
    network: &str,
    local: &str,
    now: u64,
) -> Result<Vec<SignedMembershipRecord>> {
    if records.is_empty() {
        return Ok(Vec::new());
    }
    if records
        .iter()
        .any(|record| record.payload.network_name != network)
    {
        return Err("Invalid legacy authority history");
    }
    if proof_root(records).is_none() {
        return Err("The legacy ledger has no explicit issuer root");
    }
    overlay_membership_proof_at(records, local, now)
        .map_err(|_| "Invalid legacy authority history")?
        .filter(|proof| proof_root(proof).is_some())
        .ok_or("The inviter has no active rooted legacy membership proof")
}

fn proof_root(records: &[SignedMembershipRecord]) -> Option<&str> {
    records
        .iter()
        .find(|record| record.payload.issuer_peer == record.payload.member_peer)
        .map(|record| record.payload.member_peer.as_str())
}
