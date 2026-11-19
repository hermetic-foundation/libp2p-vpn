//! Bounded Linux LAN lookup for a browser that already authorizes the target.

use std::{
    collections::HashSet,
    future::poll_fn,
    io,
    net::{IpAddr, Ipv4Addr, UdpSocket},
    num::NonZeroU32,
    sync::Arc,
    time::Duration,
};

use if_addrs::{IfAddr, Ifv4Addr};
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

/// Looks up IPv4 LAN hints for a peer already authorized by the caller. The mDNS
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
        let Ok(snapshot) = selection.wait_for(has_ipv4_source).await else {
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
        let (Some(found), IfAddr::V4(source)) =
            (interface.index.and_then(NonZeroU32::new), interface.addr)
        else {
            continue;
        };
        if index.is_some_and(|index| index != found) {
            return Ok(Vec::new());
        }
        index = Some(found);
        sources.push(source);
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
    let mut behaviour = mdns::tokio::Behaviour::new(
        mdns::Config {
            query_interval: QUERY_INTERVAL,
            ..mdns::Config::default()
        },
        PeerId::random(),
    )?;
    behaviour.set_allowed_interfaces(Some(HashSet::new()));
    behaviour.set_interface_bindings(Some(
        sources
            .iter()
            .map(|source| {
                (
                    source.ip.into(),
                    Arc::clone(&binding) as Arc<dyn mdns::InterfaceSocketBinding>,
                )
            })
            .collect(),
    ));
    behaviour.set_allowed_interfaces(Some(
        sources.iter().map(|source| source.ip.into()).collect(),
    ));

    for _ in 0..MAX_EVENTS {
        let event = tokio::select! {
            biased;
            _ = selection.changed() => return Ok(Vec::new()),
            event = poll_fn(|cx| behaviour.poll(cx)) => event,
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

fn has_ipv4_source(snapshot: &PhysicalNetworkSnapshot) -> bool {
    snapshot.mdns_addresses().iter().any(IpAddr::is_ipv4)
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
    sources: &[Ifv4Addr],
) -> Option<Multiaddr> {
    if reported != peer {
        return None;
    }
    let mut protocols = address.iter();
    let Some(Protocol::Ip4(ip)) = protocols.next() else {
        return None;
    };
    if !on_link(ip, sources)
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

fn on_link(ip: Ipv4Addr, sources: &[Ifv4Addr]) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && sources
            .iter()
            .all(|source| source.ip != ip && source.broadcast != Some(ip))
        && sources.iter().any(|source| {
            let ip = u32::from(ip);
            let mask = u32::from(source.netmask);
            let network = u32::from(source.ip) & mask;
            mask != 0
                && (ip & mask) == network
                && (source.prefixlen >= 31 || (ip != network && ip != (network | !mask)))
        })
}

#[cfg(test)]
mod tests;
