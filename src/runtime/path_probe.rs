//! Shared packet-path probe payload codec; preserves the existing v1 wire format.

pub(crate) const PATH_PROBE_PAYLOAD: &[u8] = b"path-probe-v1";
pub(crate) const PATH_PROBE_ACK_PAYLOAD: &[u8] = b"path-probe-ack-v1";
pub(crate) const PATH_PROBE_TOKEN_LEN: usize = 8;

pub(crate) fn mtu_sized_path_probe_payload(peer_mtu: u16, token: Option<u64>) -> Vec<u8> {
    let len = usize::from(peer_mtu).max(PATH_PROBE_PAYLOAD.len());
    let mut payload = vec![0; len];
    payload[..PATH_PROBE_PAYLOAD.len()].copy_from_slice(PATH_PROBE_PAYLOAD);
    let mtu_offset = PATH_PROBE_PAYLOAD.len();
    if payload.len() >= mtu_offset + 2 {
        payload[mtu_offset..mtu_offset + 2].copy_from_slice(&peer_mtu.to_be_bytes());
    }
    let token_offset = mtu_offset + 2;
    if let Some(token) = token
        && payload.len() >= token_offset + PATH_PROBE_TOKEN_LEN
    {
        payload[token_offset..token_offset + PATH_PROBE_TOKEN_LEN]
            .copy_from_slice(&token.to_be_bytes());
    }
    payload
}

pub(crate) fn path_probe_ack_payload(probed_mtu: u16, token: Option<u64>) -> Vec<u8> {
    let mut payload = Vec::with_capacity(PATH_PROBE_ACK_PAYLOAD.len() + 2 + PATH_PROBE_TOKEN_LEN);
    payload.extend_from_slice(PATH_PROBE_ACK_PAYLOAD);
    payload.extend_from_slice(&probed_mtu.to_be_bytes());
    if let Some(token) = token {
        payload.extend_from_slice(&token.to_be_bytes());
    }
    payload
}

pub(crate) fn path_probe_request_mtu(payload: &[u8]) -> Option<u16> {
    let mtu_offset = PATH_PROBE_PAYLOAD.len();
    if payload.len() < mtu_offset || !payload.starts_with(PATH_PROBE_PAYLOAD) {
        return None;
    }
    payload
        .get(mtu_offset..mtu_offset + 2)
        .map(|mtu| u16::from_be_bytes([mtu[0], mtu[1]]))
        .or_else(|| u16::try_from(payload.len()).ok())
}

pub(crate) fn path_probe_ack_mtu(payload: &[u8]) -> Option<u16> {
    let mtu_offset = PATH_PROBE_ACK_PAYLOAD.len();
    if payload.len() < mtu_offset + 2 || !payload.starts_with(PATH_PROBE_ACK_PAYLOAD) {
        return None;
    }
    Some(u16::from_be_bytes([
        payload[mtu_offset],
        payload[mtu_offset + 1],
    ]))
}

pub(crate) fn path_probe_request_token(payload: &[u8]) -> Option<u64> {
    path_probe_token(payload, PATH_PROBE_PAYLOAD.len() + 2, PATH_PROBE_PAYLOAD)
}

pub(crate) fn path_probe_ack_token(payload: &[u8]) -> Option<u64> {
    path_probe_token(
        payload,
        PATH_PROBE_ACK_PAYLOAD.len() + 2,
        PATH_PROBE_ACK_PAYLOAD,
    )
}

pub(crate) fn path_probe_token(payload: &[u8], offset: usize, prefix: &[u8]) -> Option<u64> {
    if !payload.starts_with(prefix) {
        return None;
    }
    let token = payload.get(offset..offset + PATH_PROBE_TOKEN_LEN)?;
    Some(u64::from_be_bytes([
        token[0], token[1], token[2], token[3], token[4], token[5], token[6], token[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_and_ack_preserve_v1_prefixes_big_endian_fields_and_padding() {
        let mtu = 1280_u16;
        let token = 0x0123_4567_89ab_cdef_u64;
        let payload = mtu_sized_path_probe_payload(mtu, Some(token));
        let offset = PATH_PROBE_PAYLOAD.len();
        assert_eq!(payload.len(), usize::from(mtu));
        assert_eq!(&payload[..offset], b"path-probe-v1");
        assert_eq!(&payload[offset..offset + 2], &mtu.to_be_bytes());
        assert_eq!(&payload[offset + 2..offset + 10], &token.to_be_bytes());
        assert!(payload[offset + 10..].iter().all(|byte| *byte == 0));
        assert_eq!(path_probe_request_mtu(&payload), Some(mtu));
        assert_eq!(path_probe_request_token(&payload), Some(token));
        assert_eq!(path_probe_ack_mtu(&payload), None);
        assert_eq!(path_probe_ack_token(&payload), None);

        let ack = path_probe_ack_payload(mtu, Some(token));
        let offset = PATH_PROBE_ACK_PAYLOAD.len();
        assert_eq!(ack.len(), offset + 2 + PATH_PROBE_TOKEN_LEN);
        assert_eq!(&ack[..offset], b"path-probe-ack-v1");
        assert_eq!(&ack[offset..offset + 2], &mtu.to_be_bytes());
        assert_eq!(&ack[offset + 2..], &token.to_be_bytes());
        assert_eq!(path_probe_ack_mtu(&ack), Some(mtu));
        assert_eq!(path_probe_ack_token(&ack), Some(token));
        assert_eq!(path_probe_request_mtu(&ack), None);
        assert_eq!(path_probe_request_token(&ack), None);
    }

    #[test]
    fn parsers_preserve_legacy_requests_and_reject_truncated_or_wrong_prefix_tokens() {
        let legacy = mtu_sized_path_probe_payload(0, None);
        assert_eq!(legacy, PATH_PROBE_PAYLOAD);
        assert_eq!(path_probe_request_mtu(&legacy), Some(13));
        assert_eq!(path_probe_request_token(&legacy), None);
        for end in 0..PATH_PROBE_PAYLOAD.len() {
            assert_eq!(path_probe_request_mtu(&legacy[..end]), None);
        }
        let mut partial_mtu = legacy;
        partial_mtu.push(0xff);
        assert_eq!(path_probe_request_mtu(&partial_mtu), Some(14));

        let request = mtu_sized_path_probe_payload(1280, Some(7));
        let ack = path_probe_ack_payload(1280, Some(7));
        for bytes in 0..PATH_PROBE_TOKEN_LEN {
            assert_eq!(
                path_probe_request_token(&request[..PATH_PROBE_PAYLOAD.len() + 2 + bytes]),
                None
            );
            assert_eq!(
                path_probe_ack_token(&ack[..PATH_PROBE_ACK_PAYLOAD.len() + 2 + bytes]),
                None
            );
        }
        for end in 0..PATH_PROBE_ACK_PAYLOAD.len() + 2 {
            assert_eq!(path_probe_ack_mtu(&ack[..end]), None);
        }
        let mut wrong = request;
        wrong[0] ^= 1;
        assert_eq!(path_probe_request_mtu(&wrong), None);
        assert_eq!(path_probe_request_token(&wrong), None);
        let mut wrong = ack;
        wrong[0] ^= 1;
        assert_eq!(path_probe_ack_mtu(&wrong), None);
        assert_eq!(path_probe_ack_token(&wrong), None);
        let no_token = path_probe_ack_payload(1280, None);
        assert_eq!(path_probe_ack_mtu(&no_token), Some(1280));
        assert_eq!(path_probe_ack_token(&no_token), None);
    }
}
