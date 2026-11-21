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
const MAX_RELAY_HINTS: usize = 3;
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

    pub(super) fn key(&self, space: KeySpace) -> kad::RecordKey {
        match space {
            KeySpace::Scoped => kademlia_pairing_code_key(self.0),
            KeySpace::Global => kademlia_pairing_code_v2_key(self.0),
        }
    }
}

/// A provider can name a relay, but cannot supply the first endpoint of
/// an Identify probe or act as a signed member record.
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
        |mut swarm, path| async move {
            let Hints {
                addresses,
                mut circuits,
            } = lookup(&mut swarm, locator.key(space), gateway).await?;
            circuits.sort_by_key(|hint| !hint.preferred());
            for circuit in circuits {
                path.scope.check()?;
                let address = match circuit {
                    RelayHint::Pinned(address) => address,
                    RelayHint::Discover {
                        relay, provider, ..
                    } => {
                        let Ok(entrance) =
                            gateway.verify_pairing_relay(relay, &mut swarm, &path).await
                        else {
                            continue;
                        };
                        if !public_relay_ip(&entrance) {
                            continue;
                        }
                        entrance
                            .with(Protocol::P2pCircuit)
                            .with(Protocol::P2p(provider))
                    }
                };
                return match gateway
                    .lease_manager()
                    .lease(path.scope, AuthorizedCircuit::after_lookup(address))
                    .await
                {
                    Ok(prepared) => Ok((addresses, Some(prepared))),
                    Err(_) if !addresses.is_empty() => Ok((addresses, None)),
                    Err(error) => Err(error),
                };
            }
            Ok((addresses, None))
        },
    )
    .await?;
    let relay = prepared.map(|lease| lease.publish()).transpose()?;
    Ok(Resolution { addresses, relay })
}

#[derive(Default)]
struct Hints {
    addresses: Vec<Multiaddr>,
    circuits: Vec<RelayHint>,
}

#[derive(Debug, Eq, PartialEq)]
enum RelayHint {
    Pinned(Multiaddr),
    Discover {
        relay: PeerId,
        provider: PeerId,
        advertised_webrtc: bool,
    },
}

impl RelayHint {
    fn preferred(&self) -> bool {
        !matches!(
            self,
            Self::Discover {
                advertised_webrtc: false,
                ..
            }
        )
    }
}

impl Hints {
    fn remember_circuit(&mut self, hint: RelayHint) {
        let RelayHint::Discover {
            relay, provider, ..
        } = hint
        else {
            if self.circuits.is_empty() {
                self.circuits.push(hint);
            }
            return;
        };
        if let Some(old) = self.circuits.iter_mut().find(|old| {
            matches!(
                old, RelayHint::Discover { relay: other, provider: owner, .. }
                    if *other == relay && *owner == provider
            )
        }) {
            if hint.preferred() {
                *old = hint;
            }
        } else if self.circuits.len() < MAX_RELAY_HINTS {
            self.circuits.push(hint);
        } else if hint.preferred()
            && let Some(old) = self.circuits.iter_mut().rfind(|old| !old.preferred())
        {
            *old = hint;
        }
    }
}

async fn lookup(
    swarm: &mut DhtSwarm,
    logical_key: kad::RecordKey,
    gateway: &Gateway,
) -> io::Result<Hints> {
    let key = kademlia_provider_wire_key(swarm.behaviour(), &logical_key);
    let query = swarm
        .behaviour_mut()
        .try_get_providers(key.clone())
        .map_err(io::Error::other)?;
    let result = collect_hints(swarm, gateway, query, key).await;
    if let Some(mut running) = swarm.behaviour_mut().query_mut(&query) {
        running.finish();
    }
    result
}

async fn collect_hints(
    swarm: &mut DhtSwarm,
    gateway: &Gateway,
    query: kad::QueryId,
    key: kad::RecordKey,
) -> io::Result<Hints> {
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
                if !hints.circuits.is_empty() && direct_deadline.is_none() {
                    direct_deadline = Some(Instant::now() + DIRECT_PREFERENCE_WINDOW);
                }
            }
            kad::QueryResult::GetProviders(Err(_)) => {
                if !hints.circuits.is_empty() {
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
            if let Some(hint) = circuit_hint(gateway, peer, address) {
                hints.remember_circuit(hint);
            }
        }
    }
}

fn circuit_hint(gateway: &Gateway, provider: PeerId, mut route: Multiaddr) -> Option<RelayHint> {
    if route.pop()? != Protocol::P2p(provider) || route.pop()? != Protocol::P2pCircuit {
        return None;
    }
    let mut parts = route.iter();
    if !public_relay_ip(&route) {
        return None;
    }
    let exact = crate::path::webrtc::take_direct_prefix(&mut parts).is_some();
    let relay = if exact {
        parts.next()?
    } else {
        parts = route.iter();
        parts.next()?;
        match parts.next()? {
            Protocol::Tcp(1..) => parts.next()?,
            Protocol::Udp(1..) if parts.next()? == Protocol::QuicV1 => parts.next()?,
            _ => return None,
        }
    };
    let Protocol::P2p(relay) = relay else {
        return None;
    };
    if relay == provider || parts.next().is_some() {
        return None;
    }
    let Some(entrance) = gateway.pinned_entrance(relay) else {
        return gateway
            .allows_unpinned_pairing_relay()
            .then_some(RelayHint::Discover {
                relay,
                provider,
                advertised_webrtc: exact,
            });
    };
    if !public_relay_ip(entrance) || (exact && entrance != &route) {
        return None;
    }
    // Native provider records may advertise TCP or QUIC for the same relay
    // reservation. They never supply the actual WebRTC UDP destination.
    Some(RelayHint::Pinned(
        entrance
            .clone()
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(provider)),
    ))
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
