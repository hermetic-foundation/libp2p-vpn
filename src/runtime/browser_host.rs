//! One-shot Linux discovery for a browser that owns its own VPN identity.

use std::{collections::HashSet, future::Future, io, num::NonZeroU8, sync::Arc, time::Duration};

use futures::StreamExt as _;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm,
    identity::Keypair,
    kad,
    multiaddr::Protocol,
    swarm::{self, ConnectionId, SwarmEvent},
};

use crate::{
    config::{PUBLIC_IPFS_KADEMLIA_PROTOCOL, public_ipfs_bootstrap_peer_configs},
    peer_address_record,
};

use super::{
    p2p::{
        controlled_kademlia_config, kademlia_peer_addresses_key, managed_physical_transport,
        managed_public::discovery_only_transport,
    },
    physical_network::{control::ControlRoutes, public_discovery::Scope},
    runner::public_discovery_transport_is_publicly_dialable,
};

const LOOKUP_BUDGET: Duration = Duration::from_secs(20);
const MAX_BOOTSTRAP_ADDRESSES: usize = 32;
const MAX_SCOPE_FIELD_BYTES: usize = 256;

/// Public inputs for a lookup of a peer the browser already authorizes.
pub struct DiscoveryRequest<'a> {
    pub network_name: &'a str,
    pub membership_tag: Option<&'a str>,
    pub peer: PeerId,
    pub protocol: StreamProtocol,
    /// Pinned seed multiaddrs. An empty list selects the built-in IPFS seeds
    /// only for the public IPFS protocol.
    pub bootstrap: Vec<Multiaddr>,
}

/// Returns signed, public WebRTC Direct hints for a single expected peer.
///
/// This opens no listener and does not dial the returned addresses. The
/// browser must still authenticate the peer and enforce overlay admission.
pub async fn discover(request: DiscoveryRequest<'_>) -> io::Result<Vec<Multiaddr>> {
    let seeds = bootstrap_addresses(&request)?;
    let routes = Arc::new(ControlRoutes::new(32));
    let scope = Scope::new(Arc::clone(&routes.egress))?;
    tokio::time::timeout(
        LOOKUP_BUDGET,
        while_current(&scope, async {
            // Refuse before polling any transport (including bootstrap DNS).
            scope.link().await?;
            lookup(&request, seeds, routes, scope.clone()).await
        }),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "browser discovery lookup timed out",
        )
    })?
}

fn bootstrap_addresses(request: &DiscoveryRequest<'_>) -> io::Result<Vec<(PeerId, Multiaddr)>> {
    let invalid = |message| io::Error::new(io::ErrorKind::InvalidInput, message);
    if request.network_name.is_empty()
        || request.network_name.len() > MAX_SCOPE_FIELD_BYTES
        || request
            .membership_tag
            .is_some_and(|tag| tag.is_empty() || tag.len() > MAX_SCOPE_FIELD_BYTES)
    {
        return Err(invalid("invalid browser discovery scope"));
    }
    if request.bootstrap.is_empty() {
        if request.protocol.as_ref() != PUBLIC_IPFS_KADEMLIA_PROTOCOL {
            return Err(invalid(
                "a non-default DHT requires pinned bootstrap addresses",
            ));
        }
        return public_ipfs_bootstrap_peer_configs()
            .iter()
            .map(|seed| {
                seed.peer_address()
                    .map_err(|_| invalid("invalid built-in bootstrap address"))
            })
            .collect();
    }
    if request.bootstrap.len() > MAX_BOOTSTRAP_ADDRESSES {
        return Err(invalid("too many browser discovery bootstrap addresses"));
    }
    request
        .bootstrap
        .iter()
        .map(|address| {
            if address
                .iter()
                .any(|protocol| protocol == Protocol::P2pCircuit)
            {
                return Err(invalid(
                    "a discovery bootstrap address cannot be a relay circuit",
                ));
            }
            match address.iter().last() {
                Some(Protocol::P2p(peer)) => Ok((peer, address.clone())),
                _ => Err(invalid("a discovery bootstrap address must pin a peer ID")),
            }
        })
        .collect()
}

async fn while_current<T>(
    scope: &Scope,
    operation: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::select! {
        biased;
        () = scope.invalidated() => Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "default physical network changed during browser discovery",
        )),
        result = operation => {
            scope.check()?;
            result
        }
    }
}

struct LookupPolicy {
    routes: Arc<ControlRoutes>,
    scope: Scope,
}

impl kad::OutboundDiscoveryPolicy for LookupPolicy {
    fn start_dial(&self, connection: ConnectionId) -> bool {
        if !self.scope.is_current() || self.routes.mark_public_discovery_dial(connection).is_err() {
            return false;
        }
        if !self.scope.is_current() {
            self.finish_dial(connection);
            return false;
        }
        true
    }

    fn finish_dial(&self, connection: ConnectionId) {
        self.routes.finish_public_discovery_dial(connection);
    }

    fn allows_connection(&self, peer: PeerId, connection: ConnectionId) -> bool {
        self.scope.is_current()
            && self
                .routes
                .public_discovery_connection_available(peer, connection)
    }
}

async fn lookup(
    request: &DiscoveryRequest<'_>,
    seeds: Vec<(PeerId, Multiaddr)>,
    routes: Arc<ControlRoutes>,
    scope: Scope,
) -> io::Result<Vec<Multiaddr>> {
    // The ephemeral libp2p identity is for DHT RPCs only.
    let keypair = Keypair::generate_ed25519();
    let local_peer = keypair.public().to_peer_id();
    let physical =
        managed_physical_transport(&keypair, Arc::clone(&routes)).map_err(io::Error::other)?;
    let transport = discovery_only_transport(physical, Arc::clone(&routes));
    let mut config = controlled_kademlia_config(request.protocol.clone());
    config.set_caching(kad::Caching::Disabled);
    let mut behaviour =
        kad::Behaviour::with_config(local_peer, kad::store::MemoryStore::new(local_peer), config);
    behaviour.set_mode(Some(kad::Mode::Client));
    behaviour.set_outbound_discovery_policy(Arc::new(LookupPolicy { routes, scope }));
    for (peer, address) in seeds {
        behaviour.add_protected_address(&peer, address);
    }
    let key =
        kademlia_peer_addresses_key(request.network_name, request.membership_tag, request.peer);
    let query = behaviour
        .try_get_record(key.clone())
        .map_err(io::Error::other)?;
    let mut swarm = Swarm::new(
        transport,
        behaviour,
        local_peer,
        swarm::Config::with_tokio_executor()
            .with_dial_concurrency_factor(NonZeroU8::MIN)
            .with_idle_connection_timeout(LOOKUP_BUDGET),
    );
    loop {
        if let SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
            id, result, step, ..
        }) = swarm.select_next_some().await
            && id == query
        {
            if let kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(found))) = result
                && found.record.key == key
            {
                let addresses = verified_candidates(request, &found.record.value);
                if !addresses.is_empty() {
                    return Ok(addresses);
                }
            }
            if step.last {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no signed public WebRTC Direct candidates found on the default network",
                ));
            }
        }
    }
}

fn verified_candidates(request: &DiscoveryRequest<'_>, value: &[u8]) -> Vec<Multiaddr> {
    let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return Vec::new();
    };
    let Ok((peer, addresses)) = peer_address_record::decode(
        request.network_name,
        request.membership_tag,
        &[],
        value,
        || now.as_secs(),
        |peer| peer == request.peer,
    ) else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    addresses
        .into_iter()
        .filter_map(|address| browser_address(peer, address))
        .filter(|address| seen.insert(address.clone()))
        .collect()
}

fn browser_address(peer: PeerId, address: Multiaddr) -> Option<Multiaddr> {
    let mut parts = address.iter();
    if !matches!(parts.next(), Some(Protocol::Ip4(_) | Protocol::Ip6(_)))
        || !public_discovery_transport_is_publicly_dialable(&address)
        || !matches!(parts.next(), Some(Protocol::Udp(port)) if port != 0)
        || parts.next() != Some(Protocol::WebRTCDirect)
        || !matches!(parts.next(), Some(Protocol::Certhash(hash)) if hash.code() == 0x12 && hash.size() == 32)
        || !matches!(parts.next(), None | Some(Protocol::P2p(_)))
        || parts.next().is_some()
    {
        return None;
    }
    address.with_p2p(peer).ok()
}

#[cfg(test)]
mod tests;
