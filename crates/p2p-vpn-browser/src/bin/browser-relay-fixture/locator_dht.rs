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
        .set_provider_record_ttl(Some(Duration::from_secs(90)))
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
                if let kad::GetProvidersOk::FoundProviders { providers, .. } = result?
                    && !providers.is_empty()
                {
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

/// Adapt the real profile-free Linux bootstrap and production config importer
/// to the fixture. The sole hint is the cooperating DHT node, not the inviter.
#[cfg(target_os = "linux")]
pub(super) async fn enroll(
    bootstrap: Multiaddr,
    output: &std::path::Path,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    use p2p_vpn::{
        config::BootstrapPeerConfig,
        identity::NodeIdentity,
        pairing::{PairingConfigOptions, import_pairing_response_config_at},
        runtime::pairing_bootstrap::{PairingBootstrapOptions, join_by_code_v2},
    };
    use std::{
        fs::OpenOptions,
        io,
        os::unix::fs::OpenOptionsExt,
        time::{SystemTime, UNIX_EPOCH},
    };

    let Some(Protocol::P2p(seed)) = bootstrap.iter().last() else {
        return Err("expected pinned DHT identity".into());
    };
    let mut code = String::new();
    io::stdin().read_line(&mut code)?;
    let code = code.trim().parse().map_err(|_| "invalid pairing code")?;
    let identity =
        NodeIdentity::generate_ed25519().map_err(|_| "could not generate joiner identity")?;
    println!(
        "{}",
        serde_json::json!({ "joining_peer": identity.peer_id })
    );
    let enrollment = join_by_code_v2(
        identity.clone(),
        code,
        PairingBootstrapOptions {
            // The stock bootstrap can also try its built-in public DHT seeds,
            // which have no external egress in this fixture.
            timeout,
            lan_grace: Duration::from_millis(100),
            candidate_hints: vec![BootstrapPeerConfig {
                id: seed.to_string(),
                address: bootstrap.to_string(),
            }],
            ..PairingBootstrapOptions::default()
        },
    )
    .await?;
    let mut config = import_pairing_response_config_at(
        &enrollment.offer,
        &enrollment.response,
        PairingConfigOptions {
            identity,
            interface_name: "pv-native".into(),
            mtu: 1280,
            local_routes: Vec::new(),
            peer_name: None,
        },
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )
    .map_err(|error| io::Error::other(format!("enrolled config import failed: {error:?}")))?;
    // This fixture measures the relay stream's TUN traffic, not datagram upgrades.
    config.network.packet_plane.listen.clear();
    config.network.packet_plane.quic_listen.clear();
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)?;
    serde_json::to_writer(file, &config)?;
    println!(
        "{}",
        serde_json::json!({ "enrolled_peer": config.network.local_peer })
    );
    Ok(())
}
