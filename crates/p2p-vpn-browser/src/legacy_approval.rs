//! One exact code reply, bound to the issuer and its committed legacy grant.

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApprovalReceipt {
    nonce: [u8; 24],
    ciphertext: String,
}

#[cfg(feature = "relay-client")]
mod recovery {
    use super::ApprovalReceipt;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use chacha20poly1305::{
        XChaCha20Poly1305, XNonce,
        aead::{Aead as _, KeyInit as _, Payload},
    };
    use hkdf::Hkdf;
    use libp2p::PeerId;
    use p2p_vpn::{
        config::Config,
        membership::effective_membership_at,
        pairing::{MAX_PAIRING_MESSAGE_LEN, PairingResponse},
    };
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

        pub(crate) fn open(self, config: &Config, address: &str, now: u64) -> Option<Recovery> {
            if self.ciphertext.len() > (MAX_PAYLOAD + 16).div_ceil(3) * 4 {
                return None;
            }
            let ciphertext = STANDARD.decode(self.ciphertext).ok()?;
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
            let payload = &mut reply.response.payload;
            if payload.checkpoint.is_some()
                || payload.membership_key.is_some()
                || payload.network_name != config.network.name
                || payload.inviter_peer != config.network.local_peer
                || payload.inviter_addresses != [address]
                || !(payload.issued_at_unix_seconds..payload.expires_at_unix_seconds).contains(&now)
            {
                return None;
            }
            let peer = payload.joiner_peer.parse().ok()?;
            let ledger = &config.network.member_records;
            let grant = payload.member_records.iter().find(|record| {
                record.payload.member_peer == payload.joiner_peer
                    && record.payload.issuer_peer == payload.inviter_peer
            })?;
            if !payload
                .member_records
                .iter()
                .all(|record| ledger.contains(record))
                || !effective_membership_at(ledger, &config.network.name, now)
                    .ok()?
                    .overlay_members()
                    .any(|member| {
                        member.transport_peer == peer
                            && member.membership_epoch == grant.payload.membership_epoch
                            && member.sequence == grant.payload.sequence
                    })
            {
                return None;
            }
            payload
                .membership_key
                .clone_from(&config.network.membership_key);
            Some(Recovery { reply, peer })
        }
    }

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
                && now < self.reply.response.payload.expires_at_unix_seconds
                && self.reply.response.payload.inviter_addresses == [address]
                && self.reply.ticket == ticket)
                .then_some(&self.reply.response)
        }
    }
}

#[cfg(feature = "relay-client")]
pub(crate) use recovery::Recovery;

#[cfg(all(feature = "relay-client", feature = "test-hooks"))]
pub(crate) fn test_response_digest(response: &p2p_vpn::pairing::PairingResponse) -> Option<String> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use sha2::{Digest as _, Sha256};

    Some(STANDARD.encode(Sha256::digest(serde_json::to_vec(response).ok()?)))
}
