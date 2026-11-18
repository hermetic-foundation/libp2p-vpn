use libp2p_core::{multiaddr::Protocol, Multiaddr};
use libp2p_identity::PeerId;

const MAX_RESERVATION_ADDRESSES: usize = 4;

pub(crate) trait MultiaddrExt {
    fn is_relayed(&self) -> bool;
}

impl MultiaddrExt for Multiaddr {
    fn is_relayed(&self) -> bool {
        self.iter().any(|p| p == Protocol::P2pCircuit)
    }
}

/// Keep a bounded set of entrances for a single HOP identity, not addresses
/// for a different relay or routes that themselves require a circuit.
pub(crate) fn reservation_addresses(
    relay: PeerId,
    candidates: impl IntoIterator<Item = Multiaddr>,
) -> Vec<Multiaddr> {
    let mut selected = Vec::with_capacity(MAX_RESERVATION_ADDRESSES);
    let mut first_by_family = [None, None];
    for candidate in candidates {
        let Some(last) = candidate.iter().last() else {
            continue;
        };
        let base_len = candidate.iter().count() - usize::from(matches!(last, Protocol::P2p(_)));
        if base_len == 0
            || candidate
                .iter()
                .take(base_len)
                .any(|protocol| match protocol {
                    Protocol::P2p(_) | Protocol::P2pCircuit => true,
                    Protocol::Ip4(ip) => {
                        ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast()
                    }
                    Protocol::Ip6(ip) => {
                        ip.is_unspecified()
                            || ip.is_multicast()
                            || ip.to_ipv4_mapped().is_some_and(|ip| {
                                ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast()
                            })
                    }
                    Protocol::Tcp(port) | Protocol::Udp(port) => port == 0,
                    _ => false,
                })
        {
            continue;
        }
        let Ok(address) = candidate.with_p2p(relay) else {
            continue;
        };
        if let Some(family) = address_family(&address) {
            first_by_family[family].get_or_insert_with(|| address.clone());
        }
        if selected.len() < MAX_RESERVATION_ADDRESSES && !selected.contains(&address) {
            selected.push(address);
        }
    }
    if first_by_family.iter().all(Option::is_some) {
        let mut next = selected.len();
        for (family, first) in first_by_family.into_iter().enumerate() {
            if !selected
                .iter()
                .any(|address| address_family(address) == Some(family))
            {
                next -= 1;
                selected[next] = first.expect("both address families represented");
            }
        }
    }
    selected
}

fn address_family(address: &Multiaddr) -> Option<usize> {
    address.iter().find_map(|protocol| match protocol {
        Protocol::Ip4(_) | Protocol::Dns4(_) => Some(0),
        Protocol::Ip6(ip) if ip.to_ipv4_mapped().is_some() => Some(0),
        Protocol::Ip6(_) | Protocol::Dns6(_) => Some(1),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_entrances_are_bounded_and_tied_to_the_hop_identity() {
        let relay = PeerId::random();
        let other = PeerId::random();
        let v4 = (4100..4110)
            .map(|port| format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap())
            .collect::<Vec<Multiaddr>>();
        let invalid = [
            format!("/ip6/::1/tcp/4100/p2p/{other}"),
            format!("/ip6/::/tcp/4100/p2p/{relay}"),
            format!("/ip6/::1/tcp/0/p2p/{relay}"),
            format!("/ip6/::1/tcp/4100/p2p/{relay}/p2p-circuit/p2p/{relay}"),
            format!("/ip6/::1/p2p/{relay}/tcp/4100/p2p/{relay}"),
        ]
        .map(|address| address.parse::<Multiaddr>().unwrap());
        let mapped: Multiaddr = "/ip6/::ffff:127.0.0.1/tcp/4100".parse().unwrap();
        let v6: Multiaddr = "/ip6/::1/tcp/4100".parse().unwrap();
        let single = reservation_addresses(relay, invalid.iter().cloned().chain([mapped.clone()]));
        assert_eq!(single, [mapped.with_p2p(relay).unwrap()]);

        let selected = reservation_addresses(
            relay,
            invalid
                .into_iter()
                .chain(v4.iter().cloned())
                .chain([v6.clone()]),
        );
        assert_eq!(selected.len(), MAX_RESERVATION_ADDRESSES);
        assert_eq!(
            selected.first(),
            Some(&v4[0].clone().with_p2p(relay).unwrap())
        );
        assert_eq!(selected.last(), Some(&v6.with_p2p(relay).unwrap()));
    }
}
