use std::time::Duration;

use futures::StreamExt as _;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, SwarmBuilder, kad, multiaddr::Protocol, noise,
    swarm::SwarmEvent, tcp, yamux,
};
use p2p_vpn::{config::PUBLIC_IPFS_KADEMLIA_PROTOCOL, runtime::p2p::kademlia_pairing_code_v2_key};

pub(super) type Wire = kad::Behaviour<kad::store::MemoryStore>;

fn dht(peer: PeerId, mode: kad::Mode) -> Wire {
    let mut config = kad::Config::new(StreamProtocol::new(PUBLIC_IPFS_KADEMLIA_PROTOCOL));
    config
        .set_periodic_bootstrap_interval(None)
        .set_automatic_bootstrap_throttle(None)
        .set_provider_publication_interval(None)
        .set_provider_record_ttl(Some(Duration::from_secs(30)))
        .set_query_timeout(Duration::from_secs(4));
    let mut kad = Wire::with_config(peer, kad::store::MemoryStore::new(peer), config);
    kad.set_mode(Some(mode));
    kad
}

pub(super) fn server(peer: PeerId) -> Wire {
    dht(peer, kad::Mode::Server)
}

pub(super) async fn lookup(
    bootstrap: Multiaddr,
    locator: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(Protocol::P2p(seed)) = bootstrap.iter().last() else {
        return Err("expected pinned DHT identity".into());
    };
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| dht(key.public().to_peer_id(), kad::Mode::Client))?
        .build();
    swarm.behaviour_mut().add_address(&seed, bootstrap);
    let key = kademlia_pairing_code_v2_key(locator);
    let query = swarm.behaviour_mut().try_get_providers(key)?;
    let providers =
        tokio::time::timeout(Duration::from_secs(6), async {
            loop {
                let SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
                    id,
                    result: kad::QueryResult::GetProviders(result),
                    step,
                    ..
                }) = swarm.select_next_some().await
                else {
                    continue;
                };
                if id != query {
                    continue;
                }
                if let kad::GetProvidersOk::FoundProviders { providers, .. } = result? {
                    break Ok::<_, kad::GetProvidersError>(providers.into_iter().map(|peer| {
                    let addresses = swarm.behaviour_mut().addresses_of_peer(peer);
                    serde_json::json!({ "peer": peer.to_string(), "addresses": addresses })
                }).collect::<Vec<_>>());
                }
                if step.last {
                    break Ok(Vec::new());
                }
            }
        })
        .await??;
    println!("{}", serde_json::json!(providers));
    Ok(())
}
