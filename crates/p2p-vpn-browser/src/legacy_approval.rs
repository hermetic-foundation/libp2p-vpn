//! One exact code reply, bound to the issuer and its committed legacy grant.

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApprovalReceipt {
    nonce: [u8; 24],
    ciphertext: String,
}

mod recovery {
    use super::ApprovalReceipt;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use chacha20poly1305::{
        XChaCha20Poly1305, XNonce,
        aead::{Aead as _, KeyInit as _, Payload},
    };
    use hkdf::Hkdf;
    #[cfg(any(feature = "relay-client", test))]
    use libp2p::PeerId;
    use p2p_vpn::{
        config::Config,
        membership::{SignedMembershipRecord, legacy_approval_is_current_at},
        pairing::{MAX_PAIRING_MESSAGE_LEN, PairingResponse},
    };
    #[cfg(any(feature = "relay-client", test))]
    use rand_core::{OsRng, RngCore as _};
    use serde::{Deserialize, Serialize};
    use sha2::Sha256;

    const DOMAIN: &[u8] = b"p2p-vpn browser legacy approval receipt v1";
    const MAX_PAYLOAD: usize = MAX_PAIRING_MESSAGE_LEN + 128;

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct ExactReply {
        ticket: String,
        response: PairingResponse,
    }

    #[cfg(any(feature = "relay-client", test))]
    pub(crate) struct Recovery {
        reply: ExactReply,
        peer: PeerId,
    }

    fn cipher(config: &Config) -> Option<XChaCha20Poly1305> {
        let identity = config.identity().ok()?;
        let mut key = [0; 32];
        Hkdf::<Sha256>::new(Some(DOMAIN), identity.private_key.as_bytes())
            .expand(config.network.name.as_bytes(), &mut key)
            .ok()?;
        let cipher = XChaCha20Poly1305::new((&key).into());
        key.fill(0);
        Some(cipher)
    }

    fn context(config: &Config) -> Option<Vec<u8>> {
        // An imported config with a different membership key cannot recover the
        // old signed response. The key itself never enters the stored envelope.
        serde_json::to_vec(&(DOMAIN, &config.network.membership_key)).ok()
    }

    impl ApprovalReceipt {
        #[cfg(any(feature = "relay-client", test))]
        pub(crate) fn seal(
            config: &Config,
            ticket: String,
            mut response: PairingResponse,
        ) -> Option<Self> {
            if ticket.is_empty() || ticket.len() > 64 || response.payload.checkpoint.is_some() {
                return None;
            }
            response.payload.membership_key = None;
            let plaintext = serde_json::to_vec(&ExactReply { ticket, response }).ok()?;
            if plaintext.len() > MAX_PAYLOAD {
                return None;
            }
            let mut nonce = [0; 24];
            OsRng.try_fill_bytes(&mut nonce).ok()?;
            let ciphertext = cipher(config)?
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &plaintext,
                        aad: &context(config)?,
                    },
                )
                .ok()?;
            Some(Self {
                nonce,
                ciphertext: STANDARD.encode(ciphertext),
            })
        }

        fn decrypt(&self, config: &Config) -> Option<ExactReply> {
            if self.ciphertext.len() > (MAX_PAYLOAD + 16).div_ceil(3) * 4 {
                return None;
            }
            let ciphertext = STANDARD.decode(&self.ciphertext).ok()?;
            if !(16..=MAX_PAYLOAD + 16).contains(&ciphertext.len()) {
                return None;
            }
            let plaintext = cipher(config)?
                .decrypt(
                    XNonce::from_slice(&self.nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: &context(config)?,
                    },
                )
                .ok()?;
            let mut reply: ExactReply = serde_json::from_slice(&plaintext).ok()?;
            if reply.response.payload.membership_key.is_some() {
                return None;
            }
            reply
                .response
                .payload
                .membership_key
                .clone_from(&config.network.membership_key);
            Some(reply)
        }

        pub(crate) fn is_current(
            &self,
            config: &Config,
            ledger: &[SignedMembershipRecord],
            now: u64,
        ) -> bool {
            self.decrypt(config)
                .is_some_and(|reply| current(&reply.response, config, ledger, now))
        }

        #[cfg(any(feature = "relay-client", test))]
        pub(crate) fn open(&self, config: &Config, address: &str, now: u64) -> Option<Recovery> {
            let reply = self.decrypt(config)?;
            let payload = &reply.response.payload;
            if payload.inviter_addresses != [address]
                || !current(&reply.response, config, &config.network.member_records, now)
            {
                return None;
            }
            let peer = payload.joiner_peer.parse().ok()?;
            Some(Recovery { reply, peer })
        }
    }

    pub(crate) fn current(
        response: &PairingResponse,
        config: &Config,
        ledger: &[SignedMembershipRecord],
        now: u64,
    ) -> bool {
        let payload = &response.payload;
        if payload.checkpoint.is_some()
            || payload.network_name != config.network.name
            || config.local_peer().ok().as_deref() != Some(payload.inviter_peer.as_str())
            || !(payload.issued_at_unix_seconds..payload.expires_at_unix_seconds).contains(&now)
        {
            return false;
        }
        let Some(grant) = payload.member_records.iter().find(|record| {
            record.payload.member_peer == payload.joiner_peer
                && record.payload.issuer_peer == payload.inviter_peer
        }) else {
            return false;
        };
        legacy_approval_is_current_at(ledger, &config.network.name, grant, now).unwrap_or(false)
    }

    #[cfg(any(feature = "relay-client", test))]
    impl Recovery {
        pub(crate) fn peer(&self) -> PeerId {
            self.peer
        }

        pub(crate) fn expires(&self) -> u64 {
            self.reply.response.payload.expires_at_unix_seconds
        }

        pub(crate) fn poll(
            &self,
            peer: PeerId,
            ticket: &str,
            address: &str,
            now: u64,
        ) -> Option<&PairingResponse> {
            (peer == self.peer
                && (self.reply.response.payload.issued_at_unix_seconds..self.expires())
                    .contains(&now)
                && self.reply.response.payload.inviter_addresses == [address]
                && self.reply.ticket == ticket)
                .then_some(&self.reply.response)
        }
    }
}

#[cfg(all(target_arch = "wasm32", feature = "relay-client"))]
pub(crate) use recovery::Recovery;
#[cfg(all(target_arch = "wasm32", feature = "relay-client"))]
pub(crate) use recovery::current;

#[cfg(all(
    target_arch = "wasm32",
    feature = "relay-client",
    feature = "test-hooks"
))]
pub(crate) fn test_response_digest(response: &p2p_vpn::pairing::PairingResponse) -> Option<String> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use sha2::{Digest as _, Sha256};

    Some(STANDARD.encode(Sha256::digest(serde_json::to_vec(response).ok()?)))
}

#[cfg(test)]
mod tests {
    use super::ApprovalReceipt;
    use p2p_vpn::{
        config::Config,
        identity::NodeIdentity,
        membership::{MembershipRecordOptions, MembershipRole, issue_membership_record_at},
        pairing::{
            PairingOfferOptions, PairingResponseOptions, build_pairing_response_at,
            export_code_pairing_offer_at,
        },
    };

    #[test]
    fn legacy_approval_receipt_requires_the_same_peer_ticket_circuit_and_deadline() {
        const NETWORK: &str = "receipt-test";
        const NOW: u64 = 1000;
        const TICKET: &str = "fixture-approval-ticket";
        let issuer = NodeIdentity::generate_ed25519().unwrap();
        let applicant = NodeIdentity::generate_ed25519().unwrap();
        let relay = NodeIdentity::generate_ed25519().unwrap();
        let address = format!(
            "/ip4/11.250.0.2/tcp/1/p2p/{}/p2p-circuit/p2p/{}",
            relay.peer_id, issuer.peer_id
        );
        let issue = |member: &NodeIdentity| {
            issue_membership_record_at(
                &issuer,
                MembershipRecordOptions {
                    network_name: NETWORK.into(),
                    member: member.clone(),
                    membership_epoch: 1,
                    sequence: 1,
                    roles: vec![MembershipRole::OverlayMember],
                    route_grants: Vec::new(),
                    expires_at_unix_seconds: None,
                },
                NOW,
            )
            .unwrap()
        };
        let records = vec![issue(&issuer), issue(&applicant)];
        let config: Config = serde_json::from_value(serde_json::json!({
            "network": {
                "name": NETWORK,
                "local_peer": issuer.peer_id,
                "private_key": issuer.private_key,
                "external_addresses": [&address],
                "member_records": records,
            },
        }))
        .unwrap();
        let offer = export_code_pairing_offer_at(
            &config,
            PairingOfferOptions {
                expires_in_seconds: 30,
                rendezvous_token: None,
            },
            NOW,
        )
        .unwrap();
        let response = build_pairing_response_at(
            &config,
            &offer,
            PairingResponseOptions {
                joiner_peer: applicant.peer_id.clone(),
                assigned_vpn_ip: None,
                membership_key: None,
                member_records: config.network.member_records.clone(),
                expires_in_seconds: 30,
            },
            NOW,
        )
        .unwrap();
        let receipt = ApprovalReceipt::seal(&config, TICKET.into(), response.clone()).unwrap();
        let encoded = serde_json::to_string(&receipt).unwrap();
        assert!(!encoded.contains(TICKET));
        assert!(!encoded.contains(&response.payload.rendezvous_token));
        assert!(receipt.is_current(&config, &config.network.member_records, NOW));
        assert!(!receipt.is_current(&config, &config.network.member_records, NOW + 30));
        let recovered = receipt.open(&config, &address, NOW + 1).unwrap();
        let peer = recovered.peer();
        assert!(recovered.poll(peer, TICKET, &address, NOW + 1) == Some(&response));
        assert!(
            recovered
                .poll(relay.peer_id.parse().unwrap(), TICKET, &address, NOW + 1)
                .is_none()
        );
        assert!(recovered.poll(peer, "wrong", &address, NOW + 1).is_none());
        assert!(
            recovered
                .poll(peer, TICKET, "/another-route", NOW + 1)
                .is_none()
        );
        assert!(recovered.poll(peer, TICKET, &address, NOW + 30).is_none());
        assert!(receipt.open(&config, &address, NOW + 30).is_none());
    }
}
