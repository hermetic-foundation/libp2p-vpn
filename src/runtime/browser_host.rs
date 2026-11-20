//! One-shot Linux discovery for a browser that owns its own VPN identity.

use std::{
    collections::HashSet,
    future::Future,
    io,
    num::NonZeroU8,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

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
        controlled_kademlia_config, kademlia_peer_addresses_key, kademlia_provider_wire_key,
        kademlia_rendezvous_key, managed_physical_transport,
        managed_public::discovery_only_transport,
    },
    physical_network::{
        control::ControlRoutes, linux::egress::LinuxEgress, public_discovery::Scope,
    },
    runner::public_discovery_transport_is_publicly_dialable,
};

pub mod advertisement;
pub mod http;
mod pairing;
mod relay;

const LOOKUP_BUDGET: Duration = Duration::from_secs(20);
const MAX_BOOTSTRAP_ADDRESSES: usize = 32;
const MAX_SCOPE_FIELD_BYTES: usize = 256;
pub(crate) type DhtSwarm = Swarm<kad::Behaviour<kad::store::MemoryStore>>;

struct DiscoveryPath {
    scope: Scope,
    routes: Arc<ControlRoutes>,
}

/// Public inputs for a lookup of a peer the browser already authorizes.
pub struct DiscoveryRequest<'a> {
    pub network_name: &'a str,
    pub membership_tag: Option<&'a str>,
    pub peer: PeerId,
    pub protocol: StreamProtocol,
    /// An additional interface to exclude even if it has no overlay ownership marker.
    pub owned_interface: Option<&'a str>,
    /// Pinned seed multiaddrs. An empty list selects the built-in IPFS seeds
    /// only for the public IPFS protocol.
    pub bootstrap: Vec<Multiaddr>,
}

/// Returns public WebRTC Direct hints for a single expected peer.
///
/// This opens no listener and does not dial the returned addresses. The
/// browser must still authenticate the peer and enforce overlay admission.
pub async fn discover(request: DiscoveryRequest<'_>) -> io::Result<Vec<Multiaddr>> {
    validate_scope(request.network_name, request.membership_tag)?;
    with_member_dht(
        &request.protocol,
        &request.bootstrap,
        request.owned_interface,
        |mut swarm, _| {
            let request = &request;
            async move {
                if request.protocol.as_ref() == PUBLIC_IPFS_KADEMLIA_PROTOCOL {
                    match lookup_member_provider(request, &mut swarm).await {
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        result => return result,
                    }
                }
                lookup(request, &mut swarm, |value| {
                    let addresses = verified_candidates(request, value);
                    (!addresses.is_empty()).then_some(addresses)
                })
                .await
            }
        },
    )
    .await
}

fn validate_scope(network_name: &str, membership_tag: Option<&str>) -> io::Result<()> {
    if network_name.is_empty()
        || network_name.len() > MAX_SCOPE_FIELD_BYTES
        || membership_tag.is_some_and(|tag| tag.is_empty() || tag.len() > MAX_SCOPE_FIELD_BYTES)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid browser discovery scope",
        ));
    }
    Ok(())
}

/// Gives a lookup a client-only DHT swarm for one pinned physical route
/// generation. No result is returned after that generation is replaced.
/// Callers must still validate the query result and bound its candidates.
pub(crate) async fn with_default_dht<T, F>(
    protocol: &StreamProtocol,
    bootstrap: &[Multiaddr],
    owned_interface: Option<&str>,
    operation: impl FnOnce(DhtSwarm) -> F,
) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    with_default_dht_scope(protocol, bootstrap, owned_interface, |swarm, _| {
        operation(swarm)
    })
    .await
}

async fn with_default_dht_scope<T, F>(
    protocol: &StreamProtocol,
    bootstrap: &[Multiaddr],
    owned_interface: Option<&str>,
    operation: impl FnOnce(DhtSwarm, DiscoveryPath) -> F,
) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    with_limited_dht_scope(protocol, bootstrap, owned_interface, None, operation).await
}

async fn with_member_dht<T, F>(
    protocol: &StreamProtocol,
    bootstrap: &[Multiaddr],
    owned_interface: Option<&str>,
    operation: impl FnOnce(DhtSwarm, DiscoveryPath) -> F,
) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    with_limited_dht_scope(
        protocol,
        bootstrap,
        owned_interface,
        Some(DiscoveryLimits {
            dial_attempts: MAX_BOOTSTRAP_ADDRESSES,
            query_timeout: LOOKUP_BUDGET / 2,
        }),
        operation,
    )
    .await
}

async fn with_limited_dht_scope<T, F>(
    protocol: &StreamProtocol,
    bootstrap: &[Multiaddr],
    owned_interface: Option<&str>,
    limits: Option<DiscoveryLimits>,
    operation: impl FnOnce(DhtSwarm, DiscoveryPath) -> F,
) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    let seeds = bootstrap_addresses(protocol, bootstrap)?;
    with_default_path(owned_interface, LOOKUP_BUDGET, |path| async move {
        let swarm = build_dht_swarm(
            protocol,
            seeds,
            Arc::clone(&path.routes),
            path.scope.clone(),
            limits,
        )?;
        operation(swarm, path).await
    })
    .await
}

async fn with_default_path<T, F>(
    owned_interface: Option<&str>,
    budget: Duration,
    operation: impl FnOnce(DiscoveryPath) -> F,
) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    let egress = owned_interface.map_or_else(LinuxEgress::for_control, |name| {
        LinuxEgress::new(name.to_owned())
    });
    let routes = Arc::new(ControlRoutes::with_egress(32, egress));
    let scope = Scope::new(Arc::clone(&routes.egress))?;
    tokio::time::timeout(
        budget,
        while_current(&scope, async {
            // Refuse before polling any transport (including bootstrap DNS).
            scope.link().await?;
            operation(DiscoveryPath {
                scope: scope.clone(),
                routes,
            })
            .await
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

fn bootstrap_addresses(
    protocol: &StreamProtocol,
    bootstrap: &[Multiaddr],
) -> io::Result<Vec<(PeerId, Multiaddr)>> {
    let invalid = |message| io::Error::new(io::ErrorKind::InvalidInput, message);
    if bootstrap.is_empty() {
        if protocol.as_ref() != PUBLIC_IPFS_KADEMLIA_PROTOCOL {
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
    if bootstrap.len() > MAX_BOOTSTRAP_ADDRESSES {
        return Err(invalid("too many browser discovery bootstrap addresses"));
    }
    bootstrap
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
    remaining_dials: Option<AtomicUsize>,
}

impl kad::OutboundDiscoveryPolicy for LookupPolicy {
    fn start_dial(&self, connection: ConnectionId) -> bool {
        if self.remaining_dials.as_ref().is_some_and(|remaining| {
            remaining
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                    left.checked_sub(1)
                })
                .is_err()
        }) {
            return false;
        }
        if self
            .routes
            .mark_public_discovery_dial_in_scope(connection, &self.scope)
            .is_err()
        {
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

struct DiscoveryLimits {
    dial_attempts: usize,
    query_timeout: Duration,
}

fn build_dht_swarm(
    protocol: &StreamProtocol,
    seeds: Vec<(PeerId, Multiaddr)>,
    routes: Arc<ControlRoutes>,
    scope: Scope,
    limits: Option<DiscoveryLimits>,
) -> io::Result<DhtSwarm> {
    // The ephemeral libp2p identity is for DHT RPCs only.
    let keypair = Keypair::generate_ed25519();
    let local_peer = keypair.public().to_peer_id();
    let physical =
        managed_physical_transport(&keypair, Arc::clone(&routes)).map_err(io::Error::other)?;
    let transport = discovery_only_transport(physical, Arc::clone(&routes));
    let mut config = controlled_kademlia_config(protocol.clone());
    config.set_caching(kad::Caching::Disabled);
    if let Some(limits) = &limits {
        config.set_query_timeout(limits.query_timeout);
    }
    let mut behaviour =
        kad::Behaviour::with_config(local_peer, kad::store::MemoryStore::new(local_peer), config);
    behaviour.set_mode(Some(kad::Mode::Client));
    behaviour.set_outbound_discovery_policy(Arc::new(LookupPolicy {
        routes,
        scope,
        remaining_dials: limits.map(|limits| AtomicUsize::new(limits.dial_attempts)),
    }));
    for (peer, address) in seeds {
        behaviour.add_protected_address(&peer, address);
    }
    Ok(Swarm::new(
        transport,
        behaviour,
        local_peer,
        swarm::Config::with_tokio_executor()
            .with_dial_concurrency_factor(NonZeroU8::MIN)
            .with_idle_connection_timeout(LOOKUP_BUDGET),
    ))
}

async fn lookup<T>(
    request: &DiscoveryRequest<'_>,
    swarm: &mut DhtSwarm,
    select: impl Fn(&[u8]) -> Option<T>,
) -> io::Result<T> {
    let key =
        kademlia_peer_addresses_key(request.network_name, request.membership_tag, request.peer);
    let query = swarm
        .behaviour_mut()
        .try_get_record(key.clone())
        .map_err(io::Error::other)?;
    loop {
        if let SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
            id, result, step, ..
        }) = swarm.select_next_some().await
            && id == query
        {
            if let kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(found))) = result
                && found.record.key == key
                && let Some(candidate) = select(&found.record.value)
            {
                return Ok(candidate);
            }
            if step.last {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no approved signed WebRTC candidates found on the default network",
                ));
            }
        }
    }
}

async fn lookup_member_provider(
    request: &DiscoveryRequest<'_>,
    swarm: &mut DhtSwarm,
) -> io::Result<Vec<Multiaddr>> {
    let logical = kademlia_rendezvous_key(request.network_name, request.membership_tag);
    let key = kademlia_provider_wire_key(swarm.behaviour(), &logical);
    let query = swarm
        .behaviour_mut()
        .try_get_providers(key.clone())
        .map_err(io::Error::other)?;
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
        if let kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders {
            key: found,
            providers,
        })) = result
            && found == key
            && providers.contains(&request.peer)
        {
            let mut seen = HashSet::new();
            let addresses: Vec<_> = swarm
                .behaviour_mut()
                .addresses_of_peer(request.peer)
                .into_iter()
                .filter_map(|address| browser_address(request.peer, address))
                .filter(|address| seen.insert(address.clone()))
                .take(8)
                .collect();
            if !addresses.is_empty() {
                return Ok(addresses);
            }
        }
        if step.last {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no public WebRTC provider hint found for the expected member",
            ));
        }
    }
}

fn verified_candidates(request: &DiscoveryRequest<'_>, value: &[u8]) -> Vec<Multiaddr> {
    let mut seen = HashSet::new();
    verified_addresses(request, value)
        .into_iter()
        .filter_map(|address| browser_address(request.peer, address))
        .filter(|address| seen.insert(address.clone()))
        .collect()
}

fn verified_addresses(request: &DiscoveryRequest<'_>, value: &[u8]) -> Vec<Multiaddr> {
    let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return Vec::new();
    };
    let Ok((_, addresses)) = peer_address_record::decode(
        request.network_name,
        request.membership_tag,
        &[],
        value,
        || now.as_secs(),
        |peer| peer == request.peer,
    ) else {
        return Vec::new();
    };
    addresses
}

fn browser_address(peer: PeerId, address: Multiaddr) -> Option<Multiaddr> {
    let mut parts = address.iter();
    if crate::path::webrtc::take_direct_prefix(&mut parts).is_none()
        || !public_discovery_transport_is_publicly_dialable(&address)
        || !matches!(parts.next(), None | Some(Protocol::P2p(_)))
        || parts.next().is_some()
    {
        return None;
    }
    address.with_p2p(peer).ok()
}

#[cfg(test)]
mod tests;
