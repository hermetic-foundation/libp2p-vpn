//! Pairing providers supply hints, never proof of membership or enrollment.

use std::{collections::HashSet, io};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::StreamExt as _;
use libp2p::{Multiaddr, PeerId, StreamProtocol, kad, swarm::SwarmEvent};

use crate::runtime::p2p::{
    kademlia_pairing_code_key, kademlia_pairing_code_v2_key, kademlia_provider_wire_key,
};

use super::{DhtSwarm, browser_address, with_default_dht};

const MAX_PROVIDERS: usize = 16;
const MAX_HINTS_PER_PROVIDER: usize = 4;
const MAX_HINTS: usize = 8;

#[derive(Clone, Copy)]
pub(super) enum KeySpace {
    Scoped,
    Global,
}

pub(super) struct Locator<'a>(&'a str);

impl<'a> Locator<'a> {
    pub(super) fn parse(value: &'a str) -> Option<Self> {
        let mut digest = [0; 32];
        (value.len() == 43 && URL_SAFE_NO_PAD.decode_slice(value, &mut digest) == Ok(32))
            .then_some(Self(value))
    }

    fn key(&self, space: KeySpace) -> kad::RecordKey {
        match space {
            KeySpace::Scoped => kademlia_pairing_code_key(self.0),
            KeySpace::Global => kademlia_pairing_code_v2_key(self.0),
        }
    }
}

pub(super) async fn discover(
    locator: Locator<'_>,
    space: KeySpace,
    protocol: &StreamProtocol,
    bootstrap: &[Multiaddr],
    owned_interface: Option<&str>,
) -> io::Result<Vec<Multiaddr>> {
    with_default_dht(protocol, bootstrap, owned_interface, |swarm| {
        lookup(swarm, locator.key(space))
    })
    .await
}

async fn lookup(mut swarm: DhtSwarm, logical_key: kad::RecordKey) -> io::Result<Vec<Multiaddr>> {
    let key = kademlia_provider_wire_key(swarm.behaviour(), &logical_key);
    let query = swarm
        .behaviour_mut()
        .try_get_providers(key.clone())
        .map_err(io::Error::other)?;
    let mut admitted = HashSet::new();
    loop {
        let SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
            id, result, step, ..
        }) = swarm.select_next_some().await
        else {
            continue;
        };
        if id != query {
            continue;
        }
        match result {
            kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders {
                key: found_key,
                providers,
            })) if key == found_key => {
                // Addresses may only be retained by the running provider query.
                let hints = provider_hints(&mut swarm, &mut admitted, providers);
                if !hints.is_empty() {
                    return Ok(hints);
                }
            }
            kad::QueryResult::GetProviders(Err(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "pairing provider lookup timed out",
                ));
            }
            _ => {}
        }
        if step.last {
            return Ok(Vec::new());
        }
    }
}

fn provider_hints(
    swarm: &mut DhtSwarm,
    admitted: &mut HashSet<PeerId>,
    providers: HashSet<PeerId>,
) -> Vec<Multiaddr> {
    let mut providers: Vec<_> = providers.into_iter().collect();
    providers.sort_unstable();
    let mut hints = Vec::new();
    let mut seen = HashSet::new();
    for peer in providers {
        if &peer == swarm.local_peer_id()
            || (admitted.len() == MAX_PROVIDERS && !admitted.contains(&peer))
        {
            continue;
        }
        admitted.insert(peer);
        for address in swarm
            .behaviour_mut()
            .addresses_of_peer(peer)
            .into_iter()
            .filter_map(|address| browser_address(peer, address))
            .filter(|address| seen.insert(address.clone()))
            .take(MAX_HINTS_PER_PROVIDER)
        {
            hints.push(address);
            if hints.len() == MAX_HINTS {
                return hints;
            }
        }
    }
    hints
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_canonical_sha256_locators_select_existing_provider_keys() {
        let encoded = URL_SAFE_NO_PAD.encode([0; 32]);
        let locator = Locator::parse(&encoded).unwrap();
        assert_eq!(
            locator.key(KeySpace::Global),
            kademlia_pairing_code_v2_key(&encoded)
        );
        assert_eq!(
            locator.key(KeySpace::Scoped),
            kademlia_pairing_code_key(&encoded)
        );
        for invalid in [
            format!("{encoded}="),
            format!("{}B", &encoded[..42]),
            format!("{}+", &encoded[..42]),
            "1234-5678-ABCD-EFGH".into(),
        ] {
            assert!(Locator::parse(&invalid).is_none());
        }
    }
}
