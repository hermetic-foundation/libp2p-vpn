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
    use std::time::Duration;

    use futures::StreamExt;
    use libp2p::{SwarmBuilder, identity::Keypair, relay, swarm::SwarmEvent};

    let ip = std::env::args()
        .nth(1)
        .ok_or("expected a local IPv4 bind address")?;
    let ip: std::net::Ipv4Addr = ip.parse()?;
    if ip.is_unspecified() {
        return Err("the test relay must bind one specific local address".into());
    }
    let keys = Keypair::generate_ed25519();
    let peer = keys.public().to_peer_id();
    let certificate = libp2p_webrtc::tokio::Certificate::generate(&mut rand::rngs::OsRng)?;
    let mut swarm = SwarmBuilder::with_existing_identity(keys)
        .with_tokio()
        .with_other_transport(|key| libp2p_webrtc::tokio::Transport::new(key.clone(), certificate))?
        .with_behaviour(|_| {
            relay::Behaviour::new(
                peer,
                relay::Config {
                    max_reservations: 1,
                    max_circuits: 2,
                    max_circuit_duration: Duration::from_secs(30),
                    ..relay::Config::default()
                },
            )
        })?
        .with_swarm_config(|config| config.with_idle_connection_timeout(Duration::from_secs(30)))
        .build();

    let listener = swarm.listen_on(format!("/ip4/{ip}/udp/0/webrtc-direct").parse()?)?;
    tokio::time::timeout(Duration::from_secs(90), async move {
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::NewListenAddr {
                    listener_id,
                    address,
                } if listener_id == listener => {
                    let address = address.with_p2p(peer).expect("local relay peer");
                    swarm.add_external_address(address.clone());
                    println!("{address}");
                }
                SwarmEvent::ListenerError { error, .. } => return Err(error.into()),
                SwarmEvent::ListenerClosed { reason, .. } => {
                    reason?;
                    return Err("relay listener unexpectedly closed".into());
                }
                SwarmEvent::Behaviour(event) => eprintln!("{event:?}"),
                _ => {}
            }
        }
    })
    .await?
}
