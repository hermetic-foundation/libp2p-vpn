//! One bounded standard DHT query followed by independent relay authentication.

use std::{io, time::Duration};

use futures::StreamExt as _;
use libp2p::{Multiaddr, PeerId, StreamProtocol, kad, swarm::SwarmEvent};

use super::probe::{self, scoped_webrtc};
use crate::runtime::browser_host::{DiscoveryLimits, DiscoveryPath, build_dht_swarm};

pub(super) const BUDGET: Duration = Duration::from_secs(15);
const DHT_DIALS: usize = 8;
const DHT_QUERY_BUDGET: Duration = Duration::from_secs(3);
const MAX_PROBES: usize = 3;
const IDENTIFY_BUDGET: Duration = Duration::from_secs(2);

pub(super) async fn select(
    path: &DiscoveryPath,
    protocol: &StreamProtocol,
    bootstrap: &[(PeerId, Multiaddr)],
) -> io::Result<(Multiaddr, Multiaddr, scoped_webrtc::Verified)> {
    let mut dht = build_dht_swarm(
        protocol,
        bootstrap.to_vec(),
        path.routes.clone(),
        path.scope.clone(),
        Some(DiscoveryLimits {
            dial_attempts: DHT_DIALS,
            query_timeout: DHT_QUERY_BUDGET,
        }),
    )?;
    let target = PeerId::random();
    let query = dht
        .behaviour_mut()
        .try_get_closest_peers(target)
        .map_err(io::Error::other)?;
    let peers = loop {
        if let SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
            id,
            step,
            result: kad::QueryResult::GetClosestPeers(result),
            ..
        }) = dht.select_next_some().await
            && id == query
            && step.last
        {
            let (key, peers) = match result {
                Ok(result) => (result.key, result.peers),
                Err(kad::GetClosestPeersError::Timeout { key, peers }) => (key, peers),
            };
            if key != target.to_bytes() {
                return Err(unavailable());
            }
            break peers;
        }
    };
    let contacts: Vec<_> = peers
        .into_iter()
        .filter_map(|entry| {
            // Kademlia provides candidates, never permission. Configured seeds
            // can answer without appearing in their own FIND_NODE response.
            entry
                .addrs
                .into_iter()
                .chain(dht.behaviour_mut().addresses_of_peer(entry.peer_id))
                .find_map(|address| probe::native_contact(entry.peer_id, address))
                .map(|address| (entry.peer_id, address))
        })
        .take(MAX_PROBES)
        .collect();
    drop(dht);

    for (relay, native) in contacts {
        path.scope.check()?;
        let Ok(Ok(entrance)) = tokio::time::timeout(
            IDENTIFY_BUDGET,
            probe::identify_relay(path, relay, vec![native.clone()], None),
        )
        .await
        else {
            continue;
        };
        if let Ok(proof) = scoped_webrtc::authenticate(path.scope.clone(), relay, &entrance).await {
            return Ok((native, entrance, proof));
        }
    }
    path.scope.check()?;
    Err(unavailable())
}

fn unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "no authenticated public inviter relay",
    )
}
