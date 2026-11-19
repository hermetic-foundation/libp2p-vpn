//! Local authorization envelope for submitting a version-1 peer address record.
//! Only the canonical signed record, not this envelope, goes into the DHT.

use std::io;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use serde::{Deserialize, Serialize};

use super::{KademliaPeerAddressRecord, NodeIdentity, decode, encode_until};

pub const MAX_SUBMISSION_BYTES: usize = 4096;
pub const MAX_CIRCUIT_BYTES: usize = 256;
pub const RECORD_LIFETIME: u64 = 60;
pub const CHALLENGE_LIFETIME: u64 = 15;
const MAX_RECORD_BYTES: usize = 2048;
const DOMAIN: &[u8] = b"p2p-vpn/browser-relay-advertisement/1\0";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub nonce: String,
    pub network_name: String,
    pub membership_tag: Option<String>,
    pub kademlia_protocol: String,
    pub browser_peer: String,
    pub destination: String,
    pub address: String,
    pub issued_at_unix_seconds: u64,
}

impl Challenge {
    pub fn parse(json: &str) -> io::Result<Self> {
        if json.len() > MAX_SUBMISSION_BYTES {
            return Err(invalid());
        }
        let challenge: Self = serde_json::from_str(json).map_err(|_| invalid())?;
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn validate(&self) -> io::Result<()> {
        let scope_field = |value: &str| {
            !value.is_empty()
                && value.len() <= 256
                && !value.contains('/')
                && !value.chars().any(char::is_control)
        };
        // Public membership tags use standard Base64, including '/'.
        let membership_tag = |tag: &str| {
            tag.len() == 44 && STANDARD.decode(tag).is_ok_and(|bytes| bytes.len() == 32)
        };
        if self.nonce.len() != 32
            || !self
                .nonce
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || !scope_field(&self.network_name)
            || self
                .membership_tag
                .as_deref()
                .is_some_and(|tag| !membership_tag(tag))
            || self.kademlia_protocol.len() > 256
            || !self.kademlia_protocol.starts_with('/')
            || self.address.len() > MAX_CIRCUIT_BYTES
        {
            return Err(invalid());
        }
        let browser: PeerId = self.browser_peer.parse().map_err(|_| invalid())?;
        let destination: PeerId = self.destination.parse().map_err(|_| invalid())?;
        let address: Multiaddr = self.address.parse().map_err(|_| invalid())?;
        if address.to_string() != self.address
            || browser == destination
            || circuit_relay(&address, browser).is_none_or(|relay| relay == destination)
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn is_current(&self, now: u64) -> bool {
        (self.issued_at_unix_seconds
            ..self
                .issued_at_unix_seconds
                .saturating_add(CHALLENGE_LIFETIME))
            .contains(&now)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub nonce: String,
    record: String,
    proof: Vec<u8>,
}

impl Submission {
    pub fn parse(value: &[u8]) -> io::Result<Self> {
        if value.len() > MAX_SUBMISSION_BYTES {
            return Err(invalid());
        }
        serde_json::from_slice(value).map_err(|_| invalid())
    }

    /// Call only after the browser has checked its current scope and exact listener.
    pub fn sign(challenge: &Challenge, identity: &NodeIdentity, now: u64) -> io::Result<String> {
        challenge.validate()?;
        if !challenge.is_current(now) || identity.peer_id != challenge.browser_peer {
            return Err(invalid());
        }
        let expires = now.checked_add(RECORD_LIFETIME).ok_or_else(invalid)?;
        let record = encode_until(
            &challenge.network_name,
            challenge.membership_tag.as_deref(),
            identity,
            vec![challenge.address.parse().map_err(|_| invalid())?],
            now,
            expires,
        )
        .map_err(|_| invalid())?;
        let record = String::from_utf8(record).map_err(|_| invalid())?;
        let proof = identity
            .sign(&proof_bytes(challenge, &record)?)
            .map_err(|_| invalid())?;
        let value = serde_json::to_string(&Self {
            nonce: challenge.nonce.clone(),
            record,
            proof,
        })
        .map_err(|_| invalid())?;
        if value.len() > MAX_SUBMISSION_BYTES {
            return Err(invalid());
        }
        Ok(value)
    }

    /// Verify the exact host-issued challenge, current scope, owner and address.
    pub fn verify(self, challenge: &Challenge, now: u64) -> io::Result<(Vec<u8>, u64)> {
        challenge.validate()?;
        if self.nonce != challenge.nonce
            || !challenge.is_current(now)
            || self.record.len() > MAX_RECORD_BYTES
            || self.proof.len() != 64
        {
            return Err(invalid());
        }
        let value = self.record.as_bytes();
        let record: KademliaPeerAddressRecord =
            serde_json::from_slice(value).map_err(|_| invalid())?;
        let payload = &record.payload;
        if payload.sequence < challenge.issued_at_unix_seconds
            || payload.sequence > now
            || payload.sequence.checked_add(RECORD_LIFETIME)
                != Some(payload.expires_at_unix_seconds)
            || payload.membership_tag != challenge.membership_tag
            || payload.addresses.as_slice() != [challenge.address.as_str()]
            || serde_json::to_vec(&record).map_err(|_| invalid())? != value
        {
            return Err(invalid());
        }
        decode(
            &challenge.network_name,
            challenge.membership_tag.as_deref(),
            &[],
            value,
            || now,
            |peer| peer.to_string() == challenge.browser_peer,
        )
        .map_err(|_| invalid())?;
        let key = libp2p::identity::PublicKey::try_decode_protobuf(&payload.public_key_protobuf)
            .map_err(|_| invalid())?;
        if !key.verify(&proof_bytes(challenge, &self.record)?, &self.proof) {
            return Err(invalid());
        }
        Ok((self.record.into_bytes(), payload.expires_at_unix_seconds))
    }
}

fn proof_bytes(challenge: &Challenge, record: &str) -> io::Result<Vec<u8>> {
    let mut bytes = DOMAIN.to_vec();
    serde_json::to_writer(&mut bytes, &(challenge, record)).map_err(|_| invalid())?;
    Ok(bytes)
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid browser relay advertisement",
    )
}

/// Recognize only literal public IP + nonzero TCP or QUIC-v1 + exact circuit.
pub fn circuit_relay(address: &Multiaddr, owner: PeerId) -> Option<PeerId> {
    let mut parts = address.iter();
    let public = match parts.next()? {
        Protocol::Ip4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_documentation()
                || a == 0
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && (18..=19).contains(&b)))
        }
        Protocol::Ip6(ip) => {
            let [a, b, ..] = ip.segments();
            (0x2000..=0x3fff).contains(&a)
                && !(a == 0x2001 && (b < 0x0200 || b == 0xdb8))
                && a != 0x2002
                && a != 0x3fff
        }
        _ => false,
    };
    if !public {
        return None;
    }
    match parts.next()? {
        Protocol::Tcp(port) if port != 0 => {}
        Protocol::Udp(port) if port != 0 && parts.next() == Some(Protocol::QuicV1) => {}
        _ => return None,
    }
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (
            Some(Protocol::P2p(relay)),
            Some(Protocol::P2pCircuit),
            Some(Protocol::P2p(peer)),
            None,
        ) if peer == owner && relay != owner => Some(relay),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000;
    const TAG: &str = "//////////////////////////////////////////8=";

    fn challenge(identity: &NodeIdentity) -> Challenge {
        Challenge {
            nonce: "a".repeat(32),
            network_name: "lab".into(),
            membership_tag: Some(TAG.into()),
            kademlia_protocol: "/vpn-test/kad/1".into(),
            browser_peer: identity.peer_id.clone(),
            destination: PeerId::random().to_string(),
            address: format!(
                "/ip4/8.8.8.8/tcp/4001/p2p/{}/p2p-circuit/p2p/{}",
                PeerId::random(),
                identity.peer_id
            ),
            issued_at_unix_seconds: NOW,
        }
    }

    #[test]
    fn only_the_browser_signed_record_is_published_and_its_expiry_is_strict() {
        let identity = NodeIdentity::generate_ed25519().unwrap();
        let challenge = challenge(&identity);
        let signed = Submission::sign(&challenge, &identity, NOW).unwrap();
        let (value, expiry) = Submission::parse(signed.as_bytes())
            .unwrap()
            .verify(&challenge, NOW + 2)
            .unwrap();
        assert_eq!(expiry, NOW + RECORD_LIFETIME);
        let json = String::from_utf8(value.clone()).unwrap();
        for excluded in [
            &identity.private_key,
            &challenge.nonce,
            &challenge.destination,
        ] {
            assert!(!json.contains(excluded));
        }
        let address = challenge.address.parse::<Multiaddr>().unwrap();
        let verify = |now| decode("lab", Some(TAG), &[], &value, || now, |_| true);
        assert_eq!(verify(expiry - 1).unwrap().1, [address]);
        assert_eq!(
            verify(expiry),
            Err(super::super::KademliaPeerAddressRecordError::Expired)
        );
    }

    #[test]
    fn proof_binds_current_recipient_protocol_scope_and_fresh_challenge() {
        let identity = NodeIdentity::generate_ed25519().unwrap();
        let challenge = challenge(&identity);
        let signed = Submission::sign(&challenge, &identity, NOW).unwrap();
        for changed in [
            Challenge {
                nonce: "b".repeat(32),
                ..challenge.clone()
            },
            Challenge {
                destination: PeerId::random().to_string(),
                ..challenge.clone()
            },
            Challenge {
                kademlia_protocol: "/other/kad/1".into(),
                ..challenge.clone()
            },
            Challenge {
                membership_tag: None,
                ..challenge.clone()
            },
            Challenge {
                network_name: "other".into(),
                ..challenge.clone()
            },
        ] {
            assert!(
                Submission::parse(signed.as_bytes())
                    .unwrap()
                    .verify(&changed, NOW)
                    .is_err()
            );
        }
        assert!(
            Submission::parse(signed.as_bytes())
                .unwrap()
                .verify(&challenge, NOW + CHALLENGE_LIFETIME)
                .is_err()
        );
        let imposter = NodeIdentity::generate_ed25519().unwrap();
        assert!(Submission::sign(&challenge, &imposter, NOW).is_err());

        // An unsigned extra JSON field cannot be relayed into the DHT.
        let mut altered = Submission::parse(signed.as_bytes()).unwrap();
        altered.record.insert_str(1, "\"extra\":\"data\",");
        altered.proof = identity
            .sign(&proof_bytes(&challenge, &altered.record).unwrap())
            .unwrap();
        assert!(altered.verify(&challenge, NOW).is_err());
        assert!(Submission::parse(&[b' '; MAX_SUBMISSION_BYTES + 1]).is_err());
    }

    #[test]
    fn only_literal_public_native_relay_circuits_are_eligible() {
        let owner = PeerId::random();
        let relay = PeerId::random();
        let route = |entrance| {
            format!("{entrance}/p2p/{relay}/p2p-circuit/p2p/{owner}")
                .parse::<Multiaddr>()
                .unwrap()
        };
        for entrance in ["/ip4/8.8.8.8/tcp/4001", "/ip6/2600::1/udp/4001/quic-v1"] {
            assert_eq!(circuit_relay(&route(entrance), owner), Some(relay));
        }
        for entrance in [
            "/ip4/127.0.0.1/tcp/4001",
            "/ip4/192.168.1.1/tcp/4001",
            "/ip4/100.64.0.1/tcp/4001",
            "/ip6/::1/tcp/4001",
            "/ip6/::ffff:127.0.0.1/tcp/4001",
            "/ip6/2001:db8::1/tcp/4001",
            "/ip4/8.8.8.8/tcp/0",
            "/ip4/8.8.8.8/udp/4001/webrtc-direct",
            "/dns4/relay.example/tcp/4001",
        ] {
            assert!(
                circuit_relay(&route(entrance), owner).is_none(),
                "{entrance}"
            );
        }
        let public = route("/ip4/8.8.8.8/tcp/4001");
        assert!(circuit_relay(&public, relay).is_none());
        assert!(circuit_relay(&public.with(Protocol::P2pCircuit), owner).is_none());
    }
}
