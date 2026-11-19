//! The detached file-bearer profile admits first-time peers as a legacy founder.
use std::net::IpAddr;

use p2p_vpn::{
    PeerId,
    config::{Config, RouteConfig},
    dns::{DnsConfig, DnsZone, canonical_dns_label, peer_fallback_label},
    membership::{
        MembershipRecordIssueOptions, MembershipRecordSubject, MembershipRole,
        SignedMembershipRecord, effective_membership_at,
        issue_named_membership_record_for_subject_at, trusted_membership_issuers_at,
    },
    pairing::{
        DEFAULT_PAIRING_EXPIRES_IN_SECONDS, MAX_PAIRING_MESSAGE_LEN, PairingOffer,
        PairingOfferOptions, PairingRequest, PairingResponseOptions, build_pairing_response_at,
        export_pairing_offer_at,
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
    pub(super) fn open(
        mut config: Config,
        saved: &[SignedMembershipRecord],
        now: u64,
    ) -> Result<Self> {
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
        // Never bootstrap on top of an existing ledger which this config cannot
        // merge. In particular, an empty input config cannot discard a stored root.
        if !saved.is_empty() {
            active_root(saved, &config.network.name, &local, now)?;
        }
        let forwarder = Forwarder::from_config(&config).map_err(|_| "Invalid legacy membership")?;
        let (merged, _) = forwarder
            .prepare_legacy_membership_merge(saved, now)
            .map_err(|_| "Could not load legacy membership")?;
        config.network.member_records = merged.member_records().to_vec();
        active_root(
            &config.network.member_records,
            &config.network.name,
            &local,
            now,
        )?;
        Ok(Self {
            config,
            pending: None,
        })
    }

    pub(super) fn create_offer(&mut self, seconds: Option<u32>, now: u64) -> Result<String> {
        let expires = seconds.map_or(DEFAULT_PAIRING_EXPIRES_IN_SECONDS, u64::from);
        if !(1..=DEFAULT_PAIRING_EXPIRES_IN_SECONDS).contains(&expires) {
            return Err("Offer lifetime must be between 1 and 600 seconds");
        }
        active_root(
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
        let (_, ip, name) = validate_request(&self.config, &pending.offer, &request, now)?;
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
        persist: impl FnOnce(&[SignedMembershipRecord]) -> std::result::Result<(), E>,
    ) -> std::result::Result<String, ApprovalError<E>> {
        let (encoded, ledger) = self
            .prepare_approval(expected_peer, now)
            .map_err(ApprovalError::Rejected)?;
        persist(&ledger).map_err(ApprovalError::Storage)?;
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
        let (peer, _, name) = validate_request(&self.config, &pending.offer, request, now)?;
        let identity = self
            .config
            .identity()
            .map_err(|_| "Invalid inviter identity")?;
        let network = &self.config.network.name;
        let records = &self.config.network.member_records;
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
        let root = match active_root(records, network, &identity.peer_id, now)? {
            Some(root) => root.clone(),
            None => {
                let mut routes = self.config.network.routes.clone();
                if let Some(ip) = &self.config.network.vpn_ip {
                    let ip: IpAddr = ip.parse().map_err(|_| "Invalid inviter address")?;
                    let route = RouteConfig {
                        prefix: format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }),
                        metric: 0,
                    };
                    if !routes.contains(&route) {
                        routes.push(route);
                    }
                }
                issue(
                    MembershipRecordSubject::from_identity(&identity)
                        .map_err(|_| "Invalid inviter key")?,
                    routes,
                    self.config.network.dns.hostname.as_deref(),
                )?
            }
        };
        let joiner = issue(
            MembershipRecordSubject {
                peer_id: request.payload.joiner_peer.clone(),
                public_key: request.payload.joiner_public_key.clone(),
            },
            Vec::new(),
            name.as_deref(),
        )?;
        let response = build_pairing_response_at(
            &self.config,
            &pending.offer,
            PairingResponseOptions {
                joiner_peer: request.payload.joiner_peer.clone(),
                assigned_vpn_ip: request.payload.requested_vpn_ip.clone(),
                membership_key: self.config.network.membership_key.clone(),
                member_records: vec![root, joiner.clone()],
                expires_in_seconds: DEFAULT_PAIRING_EXPIRES_IN_SECONDS,
            },
            now,
        )
        .map_err(|_| "Could not sign pairing response")?;
        let (update, _) = Forwarder::from_config(&self.config)
            .and_then(|forwarder| {
                forwarder.prepare_legacy_membership_merge(&response.payload.member_records, now)
            })
            .map_err(|_| "The legacy ledger rejected the admission")?;
        let ledger = update.member_records();
        let membership = effective_membership_at(ledger, network, now)
            .map_err(|_| "Could not evaluate the proposed legacy membership")?;
        let overlay_peer = PeerId::from_libp2p(peer);
        if !ledger.contains(&joiner)
            || !membership.overlay_members().any(|m| m.peer == overlay_peer)
        {
            return Err("The joiner did not receive active legacy membership");
        }
        if name.is_some() {
            // Name ownership does not depend on a local DNS listener.
            let mut dns_config = self.config.clone();
            let local = dns_config
                .local_peer_id()
                .map_err(|_| "Invalid inviter identity")?;
            // The zone builder requires a local name. Its fallback is already
            // owned by this identity, so this adds no new claim.
            dns_config.network.dns = DnsConfig {
                enabled: true,
                hostname: self
                    .config
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
        let encoded =
            serde_json::to_string(&response).map_err(|_| "Could not encode pairing response")?;
        Ok((encoded, ledger.to_vec()))
    }
}

#[derive(Debug)]
pub(super) enum ApprovalError<E> {
    Rejected(&'static str),
    Storage(E),
}

fn validate_request(
    config: &Config,
    offer: &PairingOffer,
    request: &PairingRequest,
    now: u64,
) -> Result<(libp2p::PeerId, std::net::Ipv4Addr, Option<String>)> {
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
    request
        .verify_for_offer_at(offer, now)
        .map_err(|_| "Expired or invalid signed pairing request")?;
    if payload.joiner_peer == offer.payload.inviter_peer
        || config
            .network
            .member_records
            .iter()
            .any(|record| record.payload.member_peer == payload.joiner_peer)
        || config
            .peers
            .iter()
            .any(|peer| peer.id == payload.joiner_peer)
    {
        return Err("This profile only admits a new peer with no prior membership");
    }
    let peer = payload
        .joiner_peer
        .parse()
        .map_err(|_| "Invalid joiner identity")?;
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

fn active_root<'a>(
    records: &'a [SignedMembershipRecord],
    network: &str,
    local: &str,
    now: u64,
) -> Result<Option<&'a SignedMembershipRecord>> {
    if records.is_empty() {
        return Ok(None);
    }
    let root = records
        .iter()
        .filter(|r| {
            r.payload.issuer_peer == r.payload.member_peer && r.payload.member_peer == local
        })
        .max_by_key(|r| (r.payload.membership_epoch, r.payload.sequence))
        .ok_or("This profile requires an active local legacy founder")?;
    let trusted = trusted_membership_issuers_at(records, network, now)
        .map_err(|_| "Invalid legacy authority history")?;
    if !trusted.contains(local)
        || root.payload.revoked
        || root.payload.issued_at_unix_seconds > now
        || root.is_expired_at(now)
        || !root.payload.roles.contains(&MembershipRole::OverlayMember)
        || !effective_membership_at(records, network, now)
            .map_err(|_| "Invalid legacy authority history")?
            .overlay_members()
            .any(|m| m.transport_peer.to_string() == local)
    {
        return Err("This profile requires an active local legacy founder");
    }
    Ok(Some(root))
}
