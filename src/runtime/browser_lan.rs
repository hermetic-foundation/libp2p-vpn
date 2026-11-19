//! Bounded Linux LAN hints for browser discovery and code pairing.

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
use tokio::{
    sync::watch,
    time::{Instant, sleep_until, timeout_at},
};

use super::physical_network::{PhysicalNetworkSnapshot, linux::LinuxDiscovery};

const LOOKUP_BUDGET: Duration = Duration::from_secs(3);
const QUERY_INTERVAL: Duration = Duration::from_millis(500);
const MAX_CANDIDATES: usize = 8;
const MAX_ENROLLMENT_ADDRESSES_PER_PEER: usize = 2;
const MAX_EVENTS: usize = 256;
const MAX_SELECTIONS_PER_LOOKUP: usize = 4;

/// Looks up LAN hints for a peer already authorized by the caller. The mDNS
/// peer ID is unauthenticated; this function neither admits nor dials candidates.
/// The Linux selector admits only eligible LAN links, including when a
/// cellular or overlay device is the default. An optional interface name also
/// excludes an overlay that has not yet registered its kernel ownership.
pub(super) async fn discover(
    peer: PeerId,
    owned_interface: Option<&str>,
) -> io::Result<Vec<Multiaddr>> {
    Ok(discover_on_link(Lookup::Peer(peer), owned_interface)
        .await?
        .into_iter()
        .map(|(_, address)| address)
        .collect())
}

/// Collects up to eight unverified LAN hints, at most two per reported peer,
/// when the inviter is not known yet. The browser must complete PAKE before
/// admitting an inviter.
pub(super) async fn discover_enrollment_candidates(
    owned_interface: Option<&str>,
) -> io::Result<Vec<(PeerId, Multiaddr)>> {
    discover_on_link(Lookup::Enrollment, owned_interface).await
}

async fn discover_on_link(
    mode: Lookup,
    owned_interface: Option<&str>,
) -> io::Result<Vec<(PeerId, Multiaddr)>> {
    let discovery = LinuxDiscovery::start(owned_interface.map(str::to_owned));
    lookup(mode, discovery.subscribe()).await
}

#[derive(Clone, Copy)]
enum Lookup {
    Peer(PeerId),
    Enrollment,
}

impl Lookup {
    fn accepts(self, reported: PeerId) -> bool {
        match self {
            Self::Peer(peer) => peer == reported,
            Self::Enrollment => true,
        }
    }

    fn address_limit(self) -> usize {
        match self {
            Self::Peer(_) => MAX_CANDIDATES,
            Self::Enrollment => MAX_ENROLLMENT_ADDRESSES_PER_PEER,
        }
    }
}

#[derive(Default)]
struct Hints(Vec<(PeerId, Vec<Multiaddr>)>);

impl Hints {
    fn extend(&mut self, mode: Lookup, addresses: Vec<(PeerId, Multiaddr)>, sources: &[IfAddr]) {
        for (peer, address) in addresses {
            if !mode.accepts(peer) {
                continue;
            }
            let Some(address) = candidate(peer, address, sources) else {
                continue;
            };
            if let Some((_, known)) = self.0.iter_mut().find(|(id, _)| *id == peer) {
                if known.len() < mode.address_limit() && !known.contains(&address) {
                    known.push(address);
                }
            } else if self.0.len() < MAX_CANDIDATES {
                self.0.push((peer, vec![address]));
            }
        }
    }

    fn enough(&self, mode: Lookup) -> bool {
        match mode {
            Lookup::Peer(_) => !self.0.is_empty(),
            Lookup::Enrollment => self.0.len() == MAX_CANDIDATES,
        }
    }

    fn candidates(&self, mode: Lookup) -> Vec<(PeerId, Multiaddr)> {
        // Give each peer one attempt before returning additional endpoints.
        (0..mode.address_limit())
            .flat_map(|index| {
                self.0.iter().filter_map(move |(peer, addresses)| {
                    addresses.get(index).map(|address| (*peer, address.clone()))
                })
            })
            .take(MAX_CANDIDATES)
            .collect()
    }
}

async fn lookup(
    mode: Lookup,
    selection: watch::Receiver<PhysicalNetworkSnapshot>,
) -> io::Result<Vec<(PeerId, Multiaddr)>> {
    let deadline = Instant::now() + LOOKUP_BUDGET;
    for _ in 0..MAX_SELECTIONS_PER_LOOKUP {
        match lookup_on_selection(mode, selection.clone(), deadline).await? {
            Some(hints) => return Ok(hints),
            None if Instant::now() < deadline => {
                eprintln!("level=debug event=browser_lan_lookup_selection_changed");
            }
            None => break,
        }
    }
    Ok(Vec::new())
}

async fn lookup_on_selection(
    mode: Lookup,
    mut selection: watch::Receiver<PhysicalNetworkSnapshot>,
    deadline: Instant,
) -> io::Result<Option<Vec<(PeerId, Multiaddr)>>> {
    // A changed selection invalidates all accumulated hints and bound sockets.
    let (name, generation, allowed) = {
        let Ok(Ok(snapshot)) = timeout_at(
            deadline,
            selection.wait_for(|snapshot| !snapshot.mdns_addresses().is_empty()),
        )
        .await
        else {
            return Ok(Some(Vec::new()));
        };
        let Some(name) = snapshot.interface_name.clone() else {
            return Ok(Some(Vec::new()));
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
            return Ok(Some(Vec::new()));
        }
        index = Some(found);
        sources.push(interface.addr);
    }
    let Some(index) = index else {
        return Ok(Some(Vec::new()));
    };
    let binding = Arc::new(LanBinding {
        generation,
        index,
        name,
        selection: selection.clone(),
    });
    if !binding.is_current() || Instant::now() >= deadline {
        return Ok(None);
    }

    // Poll only mDNS. No transport, swarm, listener, or dial is needed.
    let local = PeerId::random();
    let mut ipv4 = mdns_on_link(local, false, &sources, &binding)?;
    let mut ipv6 = mdns_on_link(local, true, &sources, &binding)?;
    let mut hints = Hints::default();
    let budget = sleep_until(deadline);
    tokio::pin!(budget);

    for _ in 0..MAX_EVENTS {
        let event = tokio::select! {
            biased;
            _ = selection.changed() => return Ok(None),
            () = &mut budget => break,
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
        hints.extend(mode, addresses, &sources);
        if hints.enough(mode) {
            break;
        }
    }
    Ok(binding.is_current().then(|| hints.candidates(mode)))
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

fn candidate(peer: PeerId, address: Multiaddr, sources: &[IfAddr]) -> Option<Multiaddr> {
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
