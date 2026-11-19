// Native relay server and standalone WASM probe for tests/relay.mjs.
#[cfg(any(target_arch = "wasm32", test))]
#[path = "../relay.rs"]
mod relay_transport;

#[cfg(target_arch = "wasm32")]
#[path = "browser-relay-fixture/probe.rs"]
mod probe;

#[cfg(target_arch = "wasm32")]
fn main() {}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::{net::Ipv6Addr, time::Duration};

    use futures::StreamExt;
    use libp2p::{
        SwarmBuilder, identify,
        identity::Keypair,
        noise, relay,
        swarm::{NetworkBehaviour, SwarmEvent},
        tcp, yamux,
    };

    #[derive(NetworkBehaviour)]
    struct Behaviour {
        relay: relay::Behaviour,
        identify: identify::Behaviour,
    }

    let mut args = std::env::args().skip(1);
    let ip = args.next().ok_or("expected a local IPv4 bind address")?;
    let ip: std::net::Ipv4Addr = ip.parse()?;
    let second = args.next();
    let long_lived = second.as_deref() == Some("--demand");
    let v6 = second
        .filter(|_| !long_lived)
        .map(|arg| arg.parse::<Ipv6Addr>())
        .transpose()?;
    if ip.is_unspecified() || v6.is_some_and(|ip| ip.is_unspecified()) || args.next().is_some() {
        return Err("expected specific local IPv4 and optional IPv6 addresses".into());
    }
    let keys = Keypair::generate_ed25519();
    let peer = keys.public().to_peer_id();
    let certificate = libp2p_webrtc::tokio::Certificate::generate(&mut rand::rngs::OsRng)?;
    let mut swarm = SwarmBuilder::with_existing_identity(keys)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_other_transport(|key| libp2p_webrtc::tokio::Transport::new(key.clone(), certificate))?
        .with_behaviour(|key| Behaviour {
            relay: relay::Behaviour::new(
                peer,
                relay::Config {
                    max_reservations: 1,
                    max_circuits: 2,
                    max_circuit_duration: Duration::from_secs(if long_lived { 80 } else { 30 }),
                    ..relay::Config::default()
                },
            ),
            identify: identify::Behaviour::new(identify::Config::new(
                "/p2p-vpn/browser-relay-fixture/1".into(),
                key.public(),
            )),
        })?
        .with_swarm_config(|config| config.with_idle_connection_timeout(Duration::from_secs(30)))
        .build();

    let listener = swarm.listen_on(format!("/ip4/{ip}/udp/0/webrtc-direct").parse()?)?;
    let tcp_listeners = if let Some(v6) = v6 {
        Some((
            swarm.listen_on(format!("/ip4/{ip}/tcp/0").parse()?)?,
            swarm.listen_on(format!("/ip6/{v6}/tcp/0").parse()?)?,
        ))
    } else {
        None
    };
    tokio::time::timeout(Duration::from_secs(90), async move {
        let (mut webrtc, mut identify, mut reservation) = (None, None, None);
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::NewListenAddr {
                    listener_id,
                    address,
                } => {
                    let address = address.with_p2p(peer).expect("local relay peer");
                    swarm.add_external_address(address.clone());
                    if listener_id == listener {
                        if tcp_listeners.is_none() {
                            println!("{address}");
                        }
                        webrtc = Some(address);
                    } else if let Some((v4, v6)) = tcp_listeners {
                        if listener_id == v4 {
                            identify = Some(address);
                        } else if listener_id == v6 {
                            reservation = Some(address);
                        }
                    }
                    if let (Some(webrtc), Some(identify), Some(reservation)) =
                        (&webrtc, &identify, &reservation)
                    {
                        println!(
                            "{}",
                            serde_json::json!({
                                "webrtc": webrtc.to_string(),
                                "identify": identify.to_string(),
                                "reservation": reservation.to_string(),
                            })
                        );
                    }
                }
                SwarmEvent::ListenerError { error, .. } => return Err(error.into()),
                SwarmEvent::ListenerClosed { reason, .. } => {
                    reason?;
                    return Err("relay listener unexpectedly closed".into());
                }
                SwarmEvent::Behaviour(BehaviourEvent::Relay(event)) => eprintln!("{event:?}"),
                SwarmEvent::ConnectionEstablished {
                    peer_id, endpoint, ..
                } => {
                    eprintln!("relay-hop {peer_id} {}", endpoint.get_remote_address())
                }
                _ => {}
            }
        }
    })
    .await?
}
