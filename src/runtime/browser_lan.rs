//! Bounded Linux LAN lookup for a browser that already authorizes the target.

use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    future::{pending, poll_fn},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket},
    num::NonZeroU32,
    sync::Arc,
    time::Duration,
};

use if_addrs::IfAddr;
use libp2p::{
    Multiaddr, PeerId,
    mdns::{self, InterfaceSocketBinding},
    multiaddr::Protocol,
    swarm::{NetworkBehaviour, ToSwarm},
};
use socket2::SockRef;
use tokio::{sync::watch, time::timeout};

use super::physical_network::{PhysicalNetworkSnapshot, linux::LinuxDiscovery};

const LOOKUP_BUDGET: Duration = Duration::from_secs(3);
const QUERY_INTERVAL: Duration = Duration::from_millis(500);
const MAX_CANDIDATES: usize = 8;
const MAX_EVENTS: usize = 256;

/// Looks up LAN hints for a peer already authorized by the caller. The mDNS
/// peer ID is unauthenticated; this function neither admits nor dials candidates.
/// The Linux selector admits only eligible LAN links, including when a
/// cellular or overlay device is the default. An optional interface name also
/// excludes an overlay that has not yet registered its kernel ownership.
pub(super) async fn discover(
    peer: PeerId,
    owned_interface: Option<&str>,
) -> io::Result<Vec<Multiaddr>> {
    let discovery = LinuxDiscovery::start(owned_interface.map(str::to_owned));
    timeout(LOOKUP_BUDGET, lookup(peer, discovery.subscribe()))
        .await
        .unwrap_or_else(|_| Ok(Vec::new()))
}

async fn lookup(
    peer: PeerId,
    mut selection: watch::Receiver<PhysicalNetworkSnapshot>,
) -> io::Result<Vec<Multiaddr>> {
    let (name, generation, allowed) = {
        let Ok(snapshot) = selection
            .wait_for(|snapshot| !snapshot.mdns_addresses().is_empty())
            .await
        else {
            return Ok(Vec::new());
        };
        let Some(name) = snapshot.interface_name.clone() else {
            return Ok(Vec::new());
        };
        (name, snapshot.generation, snapshot.mdns_addresses())
    };

    let mut index = None;
    let mut sources = Vec::new();
    for interface in if_addrs::get_if_addrs()? {
        if interface.name != name || !allowed.contains(&interface.ip()) {
            continue;
        }
        let Some(found) = interface.index.and_then(NonZeroU32::new) else {
            continue;
        };
        if index.is_some_and(|index| index != found) {
            return Ok(Vec::new());
        }
        index = Some(found);
        sources.push(interface.addr);
    }
    let Some(index) = index else {
        return Ok(Vec::new());
    };
    let binding = Arc::new(LanBinding {
        generation,
        index,
        name,
        selection: selection.clone(),
    });
    if !binding.is_current() {
        return Ok(Vec::new());
    }

    // Poll only mDNS. No transport, swarm, listener, or dial is needed.
    let local = PeerId::random();
    let mut ipv4 = mdns_on_link(local, false, &sources, &binding)?;
    let mut ipv6 = mdns_on_link(local, true, &sources, &binding)?;

    for _ in 0..MAX_EVENTS {
        let event = tokio::select! {
            biased;
            _ = selection.changed() => return Ok(Vec::new()),
            event = async {
                tokio::select! {
                    event = next_event(&mut ipv4) => event,
                    event = next_event(&mut ipv6) => event,
                }
            } => event,
        };
        let ToSwarm::GenerateEvent(mdns::Event::Discovered(addresses)) = event else {
            continue;
        };
        let mut seen = HashSet::new();
        let candidates: Vec<_> = addresses
            .into_iter()
            .filter_map(|(reported, address)| candidate(peer, reported, address, &sources))
            .filter(|address| seen.insert(address.clone()))
            .take(MAX_CANDIDATES)
            .collect();
        if !binding.is_current() {
            return Ok(Vec::new());
        }
        if !candidates.is_empty() {
            return Ok(candidates);
        }
    }
    Ok(Vec::new())
}

fn mdns_on_link(
    local: PeerId,
    enable_ipv6: bool,
    sources: &[IfAddr],
    binding: &Arc<LanBinding>,
) -> io::Result<Option<mdns::tokio::Behaviour>> {
    let bindings: HashMap<IpAddr, Arc<dyn InterfaceSocketBinding>> = sources
        .iter()
        .map(IfAddr::ip)
        .filter(|source| source.is_ipv6() == enable_ipv6)
        .map(|source| {
            (
                source,
                Arc::clone(binding) as Arc<dyn InterfaceSocketBinding>,
            )
        })
        .collect();
    if bindings.is_empty() {
        return Ok(None);
    }
    let mut behaviour = mdns::tokio::Behaviour::new(
        mdns::Config {
            enable_ipv6,
            query_interval: QUERY_INTERVAL,
            ..mdns::Config::default()
        },
        local,
    )?;
    let allowed = bindings.keys().copied().collect();
    behaviour.set_allowed_interfaces(Some(HashSet::new()));
    behaviour.set_interface_bindings(Some(bindings));
    behaviour.set_allowed_interfaces(Some(allowed));
    Ok(Some(behaviour))
}

async fn next_event(
    behaviour: &mut Option<mdns::tokio::Behaviour>,
) -> ToSwarm<mdns::Event, Infallible> {
    match behaviour {
        Some(behaviour) => poll_fn(|cx| behaviour.poll(cx)).await,
        None => pending().await,
    }
}

#[derive(Debug)]
struct LanBinding {
    generation: u64,
    index: NonZeroU32,
    name: String,
    selection: watch::Receiver<PhysicalNetworkSnapshot>,
}

impl InterfaceSocketBinding for LanBinding {
    fn identity(&self) -> [u64; 3] {
        [self.generation, u64::from(self.index.get()), 0]
    }

    fn interface_index(&self) -> NonZeroU32 {
        self.index
    }

    fn bind(&self, socket: &UdpSocket) -> io::Result<()> {
        SockRef::from(socket).bind_device(Some(self.name.as_bytes()))
    }

    fn is_current(&self) -> bool {
        self.selection.has_changed().is_ok()
            && self.selection.borrow().generation == self.generation
    }
}

fn candidate(
    peer: PeerId,
    reported: PeerId,
    address: Multiaddr,
    sources: &[IfAddr],
) -> Option<Multiaddr> {
    if reported != peer {
        return None;
    }
    let mut protocols = address.iter();
    let on_link = match protocols.next() {
        Some(Protocol::Ip4(ip)) => on_link_v4(ip, sources),
        Some(Protocol::Ip6(ip)) => on_link_v6(ip, sources),
        _ => false,
    };
    if !on_link
        || !matches!(protocols.next(), Some(Protocol::Udp(port)) if port != 0)
        || protocols.next() != Some(Protocol::WebRTCDirect)
        || !matches!(protocols.next(), Some(Protocol::Certhash(hash)) if hash.code() == 0x12 && hash.size() == 32)
        || protocols.next() != Some(Protocol::P2p(peer))
        || protocols.next().is_some()
    {
        return None;
    }
    Some(address)
}

fn on_link_v4(ip: Ipv4Addr, sources: &[IfAddr]) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && sources
            .iter()
            .all(|source| !matches!(source, IfAddr::V4(source) if source.ip == ip || source.broadcast == Some(ip)))
        && sources.iter().any(|source| {
            let IfAddr::V4(source) = source else {
                return false;
            };
            let ip = u32::from(ip);
            let mask = u32::from(source.netmask);
            let network = u32::from(source.ip) & mask;
            mask != 0
                && (ip & mask) == network
                && (source.prefixlen >= 31 || (ip != network && ip != (network | !mask)))
        })
}

fn on_link_v6(ip: Ipv6Addr, sources: &[IfAddr]) -> bool {
    // mDNS sockets are scoped to the interface, but the browser's WebRTC
    // transport cannot dial an address with a zone (or infer a local zone).
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_unicast_link_local()
        && !ip.is_multicast()
        && ip.to_ipv4().is_none()
        && sources.iter().all(|source| source.ip() != IpAddr::V6(ip))
        && sources.iter().any(|source| {
            let IfAddr::V6(source) = source else {
                return false;
            };
            let mask = u128::from(source.netmask);
            mask != 0 && (u128::from(ip) & mask) == (u128::from(source.ip) & mask)
        })
}

#[cfg(test)]
mod tests;
