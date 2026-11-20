use std::net::SocketAddr;

use libp2p::multiaddr::Protocol;

/// Consume the numeric WebRTC Direct transport prefix, leaving peer and circuit
/// components for the caller. Address eligibility is a separate policy.
pub fn take_direct_prefix<'a>(
    parts: &mut impl Iterator<Item = Protocol<'a>>,
) -> Option<SocketAddr> {
    let ip = match parts.next()? {
        Protocol::Ip4(ip) => ip.into(),
        Protocol::Ip6(ip) => ip.into(),
        _ => return None,
    };
    let Some(Protocol::Udp(port @ 1..)) = parts.next() else {
        return None;
    };
    if parts.next()? != Protocol::WebRTCDirect {
        return None;
    }
    let Some(Protocol::Certhash(hash)) = parts.next() else {
        return None;
    };
    (hash.code() == 0x12 && hash.size() == 32).then_some(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use libp2p::{Multiaddr, PeerId, multihash::Multihash};

    use super::*;

    fn address(ip: Protocol<'static>, port: u16, hash: Multihash<64>) -> Multiaddr {
        Multiaddr::empty()
            .with(ip)
            .with(Protocol::Udp(port))
            .with(Protocol::WebRTCDirect)
            .with(Protocol::Certhash(hash))
    }

    #[test]
    fn parses_both_families_without_consuming_peer_or_circuit() {
        let relay = PeerId::random();
        let member = PeerId::random();
        let hash = Multihash::wrap(0x12, &[7; 32]).unwrap();
        for (ip, expected) in [
            (
                Protocol::Ip4("127.0.0.1".parse().unwrap()),
                "127.0.0.1:4001",
            ),
            (Protocol::Ip6("::".parse().unwrap()), "[::]:4001"),
        ] {
            let route = address(ip, 4001, hash)
                .with(Protocol::P2p(relay))
                .with(Protocol::P2pCircuit)
                .with(Protocol::P2p(member));
            let mut parts = route.iter();
            assert_eq!(
                take_direct_prefix(&mut parts),
                Some(expected.parse().unwrap())
            );
            assert_eq!(parts.next(), Some(Protocol::P2p(relay)));
            assert_eq!(parts.next(), Some(Protocol::P2pCircuit));
            assert_eq!(parts.next(), Some(Protocol::P2p(member)));
            assert_eq!(parts.next(), None);
        }
    }

    #[test]
    fn requires_webrtc_direct_with_a_nonzero_port_and_sha256_fingerprint() {
        let ip = Protocol::Ip4("192.0.2.1".parse().unwrap());
        let fingerprint = Multihash::wrap(0x12, &[7; 32]).unwrap();
        for route in [
            address(ip.clone(), 0, fingerprint),
            address(ip.clone(), 4001, Multihash::wrap(0x13, &[7; 32]).unwrap()),
            address(ip.clone(), 4001, Multihash::wrap(0x12, &[7; 31]).unwrap()),
            Multiaddr::empty()
                .with(ip)
                .with(Protocol::Udp(4001))
                .with(Protocol::QuicV1),
        ] {
            assert_eq!(take_direct_prefix(&mut route.iter()), None);
        }
    }
}
