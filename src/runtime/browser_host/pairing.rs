//! Pairing providers supply hints, never proof of membership or enrollment.

use std::{collections::HashSet, io, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::StreamExt as _;
use libp2p::{Multiaddr, PeerId, StreamProtocol, kad, multiaddr::Protocol, swarm::SwarmEvent};
use tokio::time::{Instant, sleep_until};

use crate::{
    config::PUBLIC_IPFS_KADEMLIA_PROTOCOL,
    runtime::{
        p2p::{
            kademlia_pairing_code_key, kademlia_pairing_code_v2_key, kademlia_provider_wire_key,
        },
        runner::public_discovery_transport_is_publicly_dialable,
    },
};

use super::{
    DhtSwarm, browser_address,
    relay::{AuthorizedCircuit, Gateway, Resolution},
    with_default_dht_scope,
};

const MAX_PROVIDERS: usize = 16;
const MAX_HINTS_PER_PROVIDER: usize = 4;
const MAX_HINTS: usize = 8;
const DIRECT_PREFERENCE_WINDOW: Duration = Duration::from_secs(1);

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

/// A provider can select an operator-pinned entrance, but cannot supply the
/// first endpoint of an Identify probe or act as a signed member record.
///
/// The issued relay lease is for the pairing swarm's UDP tuple. After browser
/// approval, exchange it and its exact address at `/api/relay/handoff` before
/// constructing the data swarm. The locator need not still be advertised.
pub(super) async fn resolve(
    gateway: &Gateway,
    locator: Locator<'_>,
    space: KeySpace,
    protocol: &StreamProtocol,
    bootstrap: &[Multiaddr],
    owned_interface: Option<&str>,
) -> io::Result<Resolution> {
    if protocol.as_ref() != PUBLIC_IPFS_KADEMLIA_PROTOCOL {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pairing relay lookup requires public Kademlia",
        ));
    }
    let (addresses, prepared) = with_default_dht_scope(
        protocol,
        bootstrap,
        owned_interface,
        |swarm, path| async move {
            let Hints { addresses, circuit } = lookup(swarm, locator.key(space), gateway).await?;
            let Some(circuit) = circuit else {
                return Ok((addresses, None));
            };
            match gateway
                .lease_manager()
                .lease(path.scope, AuthorizedCircuit::after_lookup(circuit))
                .await
            {
                Ok(prepared) => Ok((addresses, Some(prepared))),
                Err(_) if !addresses.is_empty() => Ok((addresses, None)),
                Err(error) => Err(error),
            }
        },
    )
    .await?;
    let relay = prepared.map(|lease| lease.publish()).transpose()?;
    Ok(Resolution { addresses, relay })
}

#[derive(Default)]
struct Hints {
    addresses: Vec<Multiaddr>,
    circuit: Option<Multiaddr>,
}

async fn lookup(
    mut swarm: DhtSwarm,
    logical_key: kad::RecordKey,
    gateway: &Gateway,
) -> io::Result<Hints> {
    let key = kademlia_provider_wire_key(swarm.behaviour(), &logical_key);
    let query = swarm
        .behaviour_mut()
        .try_get_providers(key.clone())
        .map_err(io::Error::other)?;
    let mut admitted = HashSet::new();
    let mut hints = Hints::default();
    let mut direct_deadline = None;
    loop {
        let event = if let Some(deadline) = direct_deadline {
            tokio::select! {
                biased;
                () = sleep_until(deadline) => return Ok(hints),
                event = swarm.select_next_some() => event,
            }
        } else {
            swarm.select_next_some().await
        };
        let SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
            id, result, step, ..
        }) = event
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
                provider_hints(
                    *swarm.local_peer_id(),
                    &mut admitted,
                    providers,
                    gateway,
                    &mut hints,
                    |peer| swarm.behaviour_mut().addresses_of_peer(peer),
                );
                if !hints.addresses.is_empty() {
                    return Ok(hints);
                }
                if hints.circuit.is_some() && direct_deadline.is_none() {
                    direct_deadline = Some(Instant::now() + DIRECT_PREFERENCE_WINDOW);
                }
            }
            kad::QueryResult::GetProviders(Err(_)) => {
                if hints.circuit.is_some() {
                    return Ok(hints);
                }
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "pairing provider lookup timed out",
                ));
            }
            _ => {}
        }
        if step.last {
            return Ok(hints);
        }
    }
}

fn provider_hints(
    local_peer: PeerId,
    admitted: &mut HashSet<PeerId>,
    providers: HashSet<PeerId>,
    gateway: &Gateway,
    hints: &mut Hints,
    mut addresses_of: impl FnMut(PeerId) -> Vec<Multiaddr>,
) {
    let mut providers: Vec<_> = providers.into_iter().collect();
    providers.sort_unstable();
    for peer in providers {
        if peer == local_peer || (admitted.len() == MAX_PROVIDERS && !admitted.contains(&peer)) {
            continue;
        }
        admitted.insert(peer);
        let mut direct_count = 0;
        for address in addresses_of(peer) {
            if direct_count < MAX_HINTS_PER_PROVIDER
                && hints.addresses.len() < MAX_HINTS
                && let Some(address) = browser_address(peer, address.clone())
                && !hints.addresses.contains(&address)
            {
                hints.addresses.push(address);
                direct_count += 1;
            }
            if hints.circuit.is_none() {
                hints.circuit = approved_circuit(gateway, peer, address);
            }
            if hints.addresses.len() == MAX_HINTS && hints.circuit.is_some() {
                return;
            }
        }
    }
}

fn approved_circuit(
    gateway: &Gateway,
    provider: PeerId,
    mut route: Multiaddr,
) -> Option<Multiaddr> {
    if route.pop()? != Protocol::P2p(provider) || route.pop()? != Protocol::P2pCircuit {
        return None;
    }
    let mut parts = route.iter();
    if !public_relay_ip(&route) {
        return None;
    }
    parts.next()?;
    let (relay, exact) = match parts.next()? {
        Protocol::Tcp(port) if port != 0 => (parts.next()?, false),
        Protocol::Udp(port) if port != 0 => match parts.next()? {
            Protocol::QuicV1 => (parts.next()?, false),
            Protocol::WebRTCDirect
                if matches!(
                    parts.next(),
                    Some(Protocol::Certhash(hash)) if hash.code() == 0x12 && hash.size() == 32
                ) =>
            {
                (parts.next()?, true)
            }
            _ => return None,
        },
        _ => return None,
    };
    let Protocol::P2p(relay) = relay else {
        return None;
    };
    if relay == provider || parts.next().is_some() {
        return None;
    }
    let entrance = gateway.pinned_entrance(relay)?;
    if !public_relay_ip(entrance) || (exact && entrance != &route) {
        return None;
    }
    // Native provider records may advertise TCP or QUIC for the same relay
    // reservation. They never supply the actual WebRTC UDP destination.
    Some(
        entrance
            .clone()
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(provider)),
    )
}

fn public_relay_ip(address: &Multiaddr) -> bool {
    let ordinary_unicast = match address.iter().next() {
        Some(Protocol::Ip4(_)) => true,
        Some(Protocol::Ip6(ip)) => {
            let [first, second, ..] = ip.segments();
            // Accept ordinary native IPv6 unicast, not mapped/translation,
            // tunneling, IETF protocol assignments, or documentation ranges.
            (0x2000..0x4000).contains(&first)
                && first != 0x2002
                && !(first == 0x2001 && second < 0x0200)
                && !(first == 0x3fff && second < 0x1000)
        }
        _ => false,
    };
    ordinary_unicast && public_discovery_transport_is_publicly_dialable(address)
}

#[cfg(test)]
mod tests;
