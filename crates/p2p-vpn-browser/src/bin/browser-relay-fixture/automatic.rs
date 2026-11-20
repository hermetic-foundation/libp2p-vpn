//! Standard FIND_NODE sees a relay that was not configured in the companion.

use std::{error::Error, net::Ipv4Addr, time::Duration};

use futures::StreamExt as _;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder, identify, kad, noise, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};

type Dht = kad::Behaviour<kad::store::MemoryStore>;

fn dht(peer: PeerId) -> Dht {
    let mut behaviour = Dht::with_config(
        peer,
        kad::store::MemoryStore::new(peer),
        kad::Config::new(StreamProtocol::new("/ipfs/kad/1.0.0")),
    );
    behaviour.set_mode(Some(kad::Mode::Server));
    behaviour
}

#[derive(NetworkBehaviour)]
struct Relay {
    kad: Dht,
    identify: identify::Behaviour,
    relay: relay::Behaviour,
}

pub(super) async fn run(
    seed_ip: Ipv4Addr,
    relay_ip: Ipv4Addr,
    storage_ip: Option<Ipv4Addr>,
) -> Result<(), Box<dyn Error>> {
    let cert = libp2p_webrtc::tokio::Certificate::generate(&mut rand::rngs::OsRng)?;
    let mut relay = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_other_transport(|key| libp2p_webrtc::tokio::Transport::new(key.clone(), cert))?
        .with_behaviour(|key| {
            let peer = key.public().to_peer_id();
            Relay {
                kad: dht(peer),
                identify: identify::Behaviour::new(identify::Config::new(
                    "/p2p-vpn/automatic-relay-fixture/1".into(),
                    key.public(),
                )),
                relay: relay::Behaviour::new(
                    peer,
                    relay::Config {
                        max_reservations: 1,
                        ..relay::Config::default()
                    },
                ),
            }
        })?
        .build();
    let native = listen(&mut relay, format!("/ip4/{relay_ip}/tcp/0").parse()?).await?;
    let webrtc = listen(
        &mut relay,
        format!("/ip4/{relay_ip}/udp/0/webrtc-direct").parse()?,
    )
    .await?;
    let peer = *relay.local_peer_id();
    let mut seed = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| dht(key.public().to_peer_id()))?
        .build();
    let mut storage = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| dht(key.public().to_peer_id()))?
        .build();
    let storage_peer = *storage.local_peer_id();
    let storage_addr = if let Some(storage_ip) = storage_ip {
        let address = listen(&mut storage, format!("/ip4/{storage_ip}/tcp/0").parse()?).await?;
        seed.behaviour_mut()
            .add_address(&storage_peer, address.clone());
        relay
            .behaviour_mut()
            .kad
            .add_address(&storage_peer, address.clone());
        Some(address)
    } else {
        seed.behaviour_mut().add_address(&peer, native.clone());
        None
    };
    let bootstrap = listen(&mut seed, format!("/ip4/{seed_ip}/tcp/0").parse()?).await?;
    println!(
        "{}",
        serde_json::json!({
            "bootstrap": bootstrap.to_string(),
            "native": native.to_string(),
            "webrtc": webrtc.to_string(),
            "relay_peer": peer.to_string(),
            "storage": storage_addr.map(|address| address.to_string()),
        })
    );
    tokio::time::timeout(Duration::from_secs(90), async move {
        loop {
            tokio::select! {
                event = seed.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(kad::Event::InboundRequest {
                            request: kad::InboundRequest::FindNode { .. },
                        }) => eprintln!("fixture FIND_NODE"),
                        SwarmEvent::Behaviour(kad::Event::InboundRequest {
                            request: kad::InboundRequest::GetProvider {
                                num_closer_peers, num_provider_peers,
                            },
                        }) => eprintln!("fixture seed GET_PROVIDERS closer={num_closer_peers} providers={num_provider_peers}"),
                        _ => {}
                    }
                }
                event = relay.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(RelayEvent::Relay(event)) => eprintln!("{event:?}"),
                        SwarmEvent::Behaviour(RelayEvent::Kad(kad::Event::InboundRequest {
                            request: kad::InboundRequest::GetProvider { num_provider_peers, .. },
                        })) => eprintln!("fixture relay GET_PROVIDERS providers={num_provider_peers}"),
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                            eprintln!("relay-hop {peer_id} {}", endpoint.get_remote_address());
                        }
                        _ => {}
                    }
                }
                event = storage.select_next_some(), if storage_ip.is_some() => {
                    match event {
                        SwarmEvent::Behaviour(kad::Event::InboundRequest {
                            request: kad::InboundRequest::GetProvider { num_closer_peers, num_provider_peers },
                        }) => eprintln!("fixture storage GET_PROVIDERS closer={num_closer_peers} providers={num_provider_peers}"),
                        SwarmEvent::Behaviour(kad::Event::InboundRequest {
                            request: kad::InboundRequest::AddProvider { .. },
                        }) => eprintln!("fixture storage ADD_PROVIDER accepted"),
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                            eprintln!("storage-hop {peer_id} {}", endpoint.get_remote_address());
                        }
                        _ => {}
                    }
                }
            }
        }
    })
    .await?
}

async fn listen<B: NetworkBehaviour>(
    swarm: &mut Swarm<B>,
    requested: Multiaddr,
) -> Result<Multiaddr, Box<dyn Error>> {
    let listener = swarm.listen_on(requested)?;
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } if listener == listener_id => {
                let address = address
                    .with_p2p(*swarm.local_peer_id())
                    .expect("local PeerId");
                swarm.add_external_address(address.clone());
                return Ok(address);
            }
            SwarmEvent::ListenerError { error, .. } => return Err(error.into()),
            _ => {}
        }
    }
}
