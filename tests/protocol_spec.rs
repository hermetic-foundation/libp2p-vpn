//! Lock independently generated specification vectors to the deployed codecs.
use futures::io::Cursor;
use libp2p::{PeerId as TransportPeerId, StreamProtocol, request_response::Codec as _};
use p2p_vpn::{
    PeerId,
    membership::checkpoint::{AuthenticatedSnapshot, NetworkAnchor, NetworkCapability},
    pairing_code::PairingCode,
    route::{builtin_ipv4, builtin_ipv6},
    runtime::{
        control::{CONTROL_PROTOCOL, ControlCodec, ControlRequest, validate_capabilities},
        p2p::{kademlia_peer_addresses_key, kademlia_rendezvous_key},
        packet::{PACKET_PROTOCOL, PacketCodec, PacketRejectionReason, PacketResponse},
    },
    wire::Frame,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    network: String,
    control_request_hex: String,
    keepalive_hex: String,
    packet_accepted_hex: String,
    unauthorized_source_hex: String,
    peer_id: String,
    peer_id_bytes_hex: String,
    overlay_id: String,
    ipv4: String,
    ipv6: String,
    provider_key: String,
    address_key: String,
    pairing_test_code: String,
    locator_v1: String,
    locator_v2: String,
    checkpoint_fixture: CheckpointFixture,
}

#[derive(Deserialize)]
struct CheckpointFixture {
    test_secret_hex: String,
    snapshot: serde_json::Value,
    boundary_digest_hex: String,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("../docs/developer/protocol/vectors.json")).unwrap()
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

#[tokio::test]
async fn stream_wire_vectors() {
    let v = vectors();
    let control = StreamProtocol::new(CONTROL_PROTOCOL);
    let mut framed = Cursor::new(decode_hex(&v.control_request_hex));
    let ControlRequest::Capabilities(capabilities) = ControlCodec
        .read_request(&control, &mut framed)
        .await
        .unwrap()
    else {
        panic!("expected Capabilities");
    };
    assert_eq!(
        validate_capabilities(&capabilities, &v.network, None, &[]),
        None
    );
    assert_eq!(capabilities.effective_mtu, 1280);
    assert_eq!(capabilities.preferred_path, "direct_tcp_stream");
    assert_eq!(framed.position(), framed.get_ref().len() as u64);

    let packet = StreamProtocol::new(PACKET_PROTOCOL);
    let mut codec = PacketCodec::new(1280);
    let expected_frame = Frame::keepalive(7, 42).unwrap();
    let expected_bytes = decode_hex(&v.keepalive_hex);
    assert_eq!(expected_frame.encode(), expected_bytes);
    assert_eq!(
        codec
            .read_request(&packet, &mut Cursor::new(expected_bytes))
            .await
            .unwrap(),
        expected_frame
    );
    for (wire, response) in [
        (v.packet_accepted_hex, PacketResponse::Accepted),
        (
            v.unauthorized_source_hex,
            PacketResponse::Rejected(PacketRejectionReason::UnauthorizedSource),
        ),
    ] {
        let bytes = decode_hex(&wire);
        assert_eq!(
            codec
                .read_response(&packet, &mut Cursor::new(bytes.clone()))
                .await
                .unwrap(),
            response
        );
        let mut output = Cursor::new(Vec::new());
        codec
            .write_response(&packet, &mut output, response)
            .await
            .unwrap();
        assert_eq!(output.into_inner(), bytes);
    }
}

#[test]
fn identity_and_discovery_vectors() {
    let v = vectors();
    let peer: TransportPeerId = v.peer_id.parse().unwrap();
    assert_eq!(peer.to_bytes(), decode_hex(&v.peer_id_bytes_hex));
    let overlay = PeerId::from_libp2p(peer);
    assert_eq!(overlay.to_string(), v.overlay_id);
    assert_eq!(builtin_ipv4(overlay).to_string(), v.ipv4);
    assert_eq!(builtin_ipv6(overlay).to_string(), v.ipv6);
    assert_eq!(
        kademlia_rendezvous_key(&v.network, None).as_ref(),
        v.provider_key.as_bytes()
    );
    assert_eq!(
        kademlia_peer_addresses_key(&v.network, None, peer).as_ref(),
        v.address_key.as_bytes()
    );

    let code: PairingCode = v.pairing_test_code.parse().unwrap();
    assert_eq!(code.locator(&v.network).unwrap(), v.locator_v1);
    assert_eq!(code.global_locator(), v.locator_v2);
}

#[test]
fn checkpoint_authentication_vector() {
    let mut fixture = vectors().checkpoint_fixture;
    let anchor: NetworkAnchor =
        serde_json::from_value(fixture.snapshot["payload"]["anchor"].clone()).unwrap();
    let secret = decode_hex(&fixture.test_secret_hex);
    let capability = NetworkCapability::from_secret(anchor, Some(&secret)).unwrap();
    let bytes = serde_json::to_vec(&fixture.snapshot).unwrap();
    let snapshot = AuthenticatedSnapshot::decode(&bytes, &capability).unwrap();
    let rank = snapshot.payload.rank().unwrap();
    assert_eq!(rank.authority_revision, 0);
    assert_eq!(rank.active_member_count, 1);
    assert_eq!(
        rank.digest.as_slice(),
        decode_hex(&fixture.boundary_digest_hex)
    );

    fixture.snapshot["mac"][0] = 0.into();
    let tampered = serde_json::to_vec(&fixture.snapshot).unwrap();
    assert!(AuthenticatedSnapshot::decode(&tampered, &capability).is_err());
}
