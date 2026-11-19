//! Signed Kademlia peer address record values, shared by native and browser hosts.
//!
//! Verification authenticates address hints. Hosts still enforce their own
//! transport, network egress, and dialing policies.

use libp2p::{Multiaddr, PeerId, identity::PublicKey, multiaddr::Protocol};
use serde::{Deserialize, Serialize};

use crate::identity::NodeIdentity;

pub(crate) const MAX_KADEMLIA_PEER_ADDRESS_RECORD_BYTES: usize = 64 * 1024;
pub(crate) const MAX_KADEMLIA_PEER_ADDRESS_RECORD_ADDRESSES: usize = 32;
pub(crate) const KADEMLIA_PEER_ADDRESS_RECORD_TTL: u64 = 30 * 60;
pub(crate) const KADEMLIA_PEER_ADDRESS_RECORD_STALE_GRACE: u64 = 60 * 60;

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct KademliaPeerAddressRecordPayload {
    pub(crate) version: u8,
    pub(crate) network_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) membership_tag: Option<String>,
    pub(crate) peer_id: String,
    public_key_protobuf: Vec<u8>,
    pub(crate) sequence: u64,
    pub(crate) expires_at_unix_seconds: u64,
    pub(crate) addresses: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct KademliaPeerAddressRecord {
    pub(crate) payload: KademliaPeerAddressRecordPayload,
    pub(crate) signature: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum KademliaPeerAddressRecordError {
    NoAddresses,
    TooLarge,
    Decode,
    Encode,
    UnsupportedVersion,
    WrongNetwork,
    WrongMembershipScope,
    WrongPeer,
    InvalidPeerId,
    InvalidPublicKey,
    InvalidSignature,
    Expired,
    TooManyAddresses,
}

impl std::fmt::Display for KademliaPeerAddressRecordError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAddresses => formatter.write_str("no_addresses"),
            Self::TooLarge => formatter.write_str("too_large"),
            Self::Decode => formatter.write_str("decode_failed"),
            Self::Encode => formatter.write_str("encode_failed"),
            Self::UnsupportedVersion => formatter.write_str("unsupported_version"),
            Self::WrongNetwork => formatter.write_str("wrong_network"),
            Self::WrongMembershipScope => formatter.write_str("wrong_membership_scope"),
            Self::WrongPeer => formatter.write_str("wrong_peer"),
            Self::InvalidPeerId => formatter.write_str("invalid_peer_id"),
            Self::InvalidPublicKey => formatter.write_str("invalid_public_key"),
            Self::InvalidSignature => formatter.write_str("invalid_signature"),
            Self::Expired => formatter.write_str("expired"),
            Self::TooManyAddresses => formatter.write_str("too_many_addresses"),
        }
    }
}

/// Encodes a version-1 record from addresses selected for publication by the caller.
pub fn encode(
    network_name: &str,
    membership_tag: Option<&str>,
    identity: &NodeIdentity,
    addresses: Vec<Multiaddr>,
    now_unix_seconds: u64,
) -> Result<Vec<u8>, KademliaPeerAddressRecordError> {
    if addresses.is_empty() {
        return Err(KademliaPeerAddressRecordError::NoAddresses);
    }
    let payload = KademliaPeerAddressRecordPayload {
        version: 1,
        network_name: network_name.to_owned(),
        membership_tag: membership_tag.map(str::to_owned),
        peer_id: identity.peer_id.clone(),
        public_key_protobuf: identity
            .public_key_protobuf()
            .map_err(|_| KademliaPeerAddressRecordError::InvalidPublicKey)?,
        sequence: now_unix_seconds,
        expires_at_unix_seconds: now_unix_seconds + KADEMLIA_PEER_ADDRESS_RECORD_TTL,
        addresses: addresses
            .into_iter()
            .map(|address| address.to_string())
            .collect(),
    };
    let payload_bytes =
        serde_json::to_vec(&payload).map_err(|_| KademliaPeerAddressRecordError::Encode)?;
    let signature = identity
        .sign(&payload_bytes)
        .map_err(|_| KademliaPeerAddressRecordError::InvalidSignature)?;
    serde_json::to_vec(&KademliaPeerAddressRecord { payload, signature })
        .map_err(|_| KademliaPeerAddressRecordError::Encode)
}

/// Validates a record against the caller's scope, clock, and peer authorization.
///
/// The peer ID passed to `authorized` is not yet authenticated; a successful
/// return also requires the public key to bind that ID and verify the signature.
/// Unparseable addresses and addresses targeting a different peer are discarded.
pub fn decode(
    expected_network_name: &str,
    current_membership_tag: Option<&str>,
    previous_membership_tags: &[String],
    value: &[u8],
    now_unix_seconds: impl FnOnce() -> u64,
    authorized: impl FnOnce(PeerId) -> bool,
) -> Result<(PeerId, Vec<Multiaddr>), KademliaPeerAddressRecordError> {
    if value.len() > MAX_KADEMLIA_PEER_ADDRESS_RECORD_BYTES {
        return Err(KademliaPeerAddressRecordError::TooLarge);
    }
    let record: KademliaPeerAddressRecord =
        serde_json::from_slice(value).map_err(|_| KademliaPeerAddressRecordError::Decode)?;
    let payload_bytes =
        serde_json::to_vec(&record.payload).map_err(|_| KademliaPeerAddressRecordError::Encode)?;
    if record.payload.version != 1 {
        return Err(KademliaPeerAddressRecordError::UnsupportedVersion);
    }
    if record.payload.network_name != expected_network_name {
        return Err(KademliaPeerAddressRecordError::WrongNetwork);
    }
    if !membership_tag_allowed(
        record.payload.membership_tag.as_deref(),
        current_membership_tag,
        previous_membership_tags,
    ) {
        return Err(KademliaPeerAddressRecordError::WrongMembershipScope);
    }
    if record
        .payload
        .expires_at_unix_seconds
        .saturating_add(KADEMLIA_PEER_ADDRESS_RECORD_STALE_GRACE)
        < now_unix_seconds()
    {
        return Err(KademliaPeerAddressRecordError::Expired);
    }
    if record.payload.addresses.len() > MAX_KADEMLIA_PEER_ADDRESS_RECORD_ADDRESSES {
        return Err(KademliaPeerAddressRecordError::TooManyAddresses);
    }
    let peer = record
        .payload
        .peer_id
        .parse::<PeerId>()
        .map_err(|_| KademliaPeerAddressRecordError::InvalidPeerId)?;
    if !authorized(peer) {
        return Err(KademliaPeerAddressRecordError::WrongPeer);
    }
    let public_key = PublicKey::try_decode_protobuf(&record.payload.public_key_protobuf)
        .map_err(|_| KademliaPeerAddressRecordError::InvalidPublicKey)?;
    if PeerId::from_public_key(&public_key) != peer {
        return Err(KademliaPeerAddressRecordError::InvalidPublicKey);
    }
    if !public_key.verify(&payload_bytes, &record.signature) {
        return Err(KademliaPeerAddressRecordError::InvalidSignature);
    }
    let addresses = record
        .payload
        .addresses
        .iter()
        .filter_map(|address| address.parse::<Multiaddr>().ok())
        .filter(|address| address_targets_peer(peer, address))
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(KademliaPeerAddressRecordError::NoAddresses);
    }
    Ok((peer, addresses))
}

pub(crate) fn membership_tag_allowed(
    tag: Option<&str>,
    current_membership_tag: Option<&str>,
    previous_membership_tags: &[String],
) -> bool {
    tag == current_membership_tag
        || tag.is_none()
        || tag.is_some_and(|tag| {
            previous_membership_tags
                .iter()
                .any(|previous| previous == tag)
        })
}

pub(crate) fn address_targets_peer(peer: PeerId, address: &Multiaddr) -> bool {
    discovered_address_target(address).is_none_or(|target| target == peer)
}

pub(crate) fn discovered_address_target(address: &Multiaddr) -> Option<PeerId> {
    let mut direct_target = None;
    let mut relayed_target = None;
    let mut after_circuit = false;

    for protocol in address {
        match protocol {
            Protocol::P2p(peer) if after_circuit => relayed_target = Some(peer),
            Protocol::P2p(peer) => direct_target = Some(peer),
            Protocol::P2pCircuit => after_circuit = true,
            _ => {}
        }
    }

    if after_circuit {
        relayed_target
    } else {
        direct_target
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000;
    const ADDRESS: &str = "/ip4/8.8.8.8/tcp/4001";

    fn identity(seed: u8) -> NodeIdentity {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let key = libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap();
        NodeIdentity::from_private_key(&STANDARD.encode(key.to_protobuf_encoding().unwrap()))
            .unwrap()
    }

    #[test]
    fn retains_version_one_wire_format_and_scope_rules() {
        let identity = identity(1);
        let peer = identity.peer_id.parse().unwrap();
        let address: Multiaddr = ADDRESS.parse().unwrap();
        let public_key = serde_json::to_string(&identity.public_key_protobuf().unwrap()).unwrap();
        let previous = ["old".to_owned()];

        for (tag, wire_tag, accepted) in [
            (None, "", true),
            (Some("current"), r#","membership_tag":"current""#, true),
            (Some("old"), r#","membership_tag":"old""#, true),
            (Some("unknown"), r#","membership_tag":"unknown""#, false),
        ] {
            let payload = format!(
                r#"{{"version":1,"network_name":"lab"{wire_tag},"peer_id":"{peer}","public_key_protobuf":{public_key},"sequence":1000,"expires_at_unix_seconds":2800,"addresses":["{ADDRESS}"]}}"#,
            );
            let signature =
                serde_json::to_string(&identity.sign(payload.as_bytes()).unwrap()).unwrap();
            let wire = format!(r#"{{"payload":{payload},"signature":{signature}}}"#);
            assert_eq!(
                encode("lab", tag, &identity, vec![address.clone()], NOW).unwrap(),
                wire.as_bytes(),
            );
            let result = decode(
                "lab",
                Some("current"),
                &previous,
                wire.as_bytes(),
                || NOW,
                |id| id == peer,
            );
            if accepted {
                assert_eq!(result, Ok((peer, vec![address.clone()])));
            } else {
                assert_eq!(
                    result,
                    Err(KademliaPeerAddressRecordError::WrongMembershipScope)
                );
            }
        }
    }

    #[test]
    fn rejects_tampering_and_a_signing_key_for_another_peer() {
        let signer = identity(1);
        let address: Multiaddr = ADDRESS.parse().unwrap();
        let value = encode("lab", None, &signer, vec![address.clone()], NOW).unwrap();
        let mut record: KademliaPeerAddressRecord = serde_json::from_slice(&value).unwrap();
        record.payload.addresses[0] = "/ip4/8.8.4.4/tcp/4001".to_owned();
        let tampered = serde_json::to_vec(&record).unwrap();
        assert_eq!(
            decode("lab", None, &[], &tampered, || NOW, |_| true),
            Err(KademliaPeerAddressRecordError::InvalidSignature),
        );

        let imposter = NodeIdentity {
            peer_id: identity(2).peer_id,
            ..signer
        };
        let claimed_peer = imposter.peer_id.parse().unwrap();
        let value = encode("lab", None, &imposter, vec![address], NOW).unwrap();
        assert_eq!(
            decode("lab", None, &[], &value, || NOW, |id| id == claimed_peer),
            Err(KademliaPeerAddressRecordError::InvalidPublicKey),
        );
    }

    #[test]
    fn discards_invalid_and_wrong_target_addresses_without_confusing_relay_and_peer() {
        let signer = identity(1);
        let peer = signer.peer_id.parse().unwrap();
        let relay = identity(2).peer_id;
        let address = format!("{ADDRESS}/p2p/{relay}/p2p-circuit");
        let wrong_direct = format!("{ADDRESS}/p2p/{relay}");
        let wrong_relayed = format!("{address}/p2p/{relay}");
        let right_relayed = format!("{address}/p2p/{peer}");
        let value = encode("lab", None, &signer, vec![ADDRESS.parse().unwrap()], NOW).unwrap();
        let mut record: KademliaPeerAddressRecord = serde_json::from_slice(&value).unwrap();
        record.payload.addresses = vec![
            wrong_direct,
            "not a multiaddr".to_owned(),
            wrong_relayed,
            address.clone(),
            right_relayed.clone(),
        ];
        record.signature = signer
            .sign(&serde_json::to_vec(&record.payload).unwrap())
            .unwrap();
        let value = serde_json::to_vec(&record).unwrap();
        assert_eq!(
            decode("lab", None, &[], &value, || NOW, |id| id == peer),
            Ok((
                peer,
                vec![address.parse().unwrap(), right_relayed.parse().unwrap()]
            )),
        );
    }

    #[test]
    fn enforces_expiration_and_input_limits() {
        let signer = identity(1);
        let address: Multiaddr = ADDRESS.parse().unwrap();
        let value = encode("lab", None, &signer, vec![address.clone(); 32], NOW).unwrap();
        let stale_boundary = 6_400;
        assert!(decode("lab", None, &[], &value, || stale_boundary, |_| true).is_ok());
        assert_eq!(
            decode("lab", None, &[], &value, || stale_boundary + 1, |_| true),
            Err(KademliaPeerAddressRecordError::Expired),
        );
        let too_many = encode("lab", None, &signer, vec![address; 33], NOW).unwrap();
        assert_eq!(
            decode("lab", None, &[], &too_many, || NOW, |_| true),
            Err(KademliaPeerAddressRecordError::TooManyAddresses),
        );
        let too_large = vec![b' '; 64 * 1024 + 1];
        assert_eq!(
            decode("lab", None, &[], &too_large, || NOW, |_| true),
            Err(KademliaPeerAddressRecordError::TooLarge),
        );
    }
}
