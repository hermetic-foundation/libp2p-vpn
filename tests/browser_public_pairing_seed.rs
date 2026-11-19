//! Test-only public DHT seed for the Chromium pairing relay harness.

use std::io::{self, BufRead as _};

use futures::StreamExt as _;
use libp2p::{
    Multiaddr, StreamProtocol, SwarmBuilder,
    kad::{self, store::RecordStore as _},
    swarm::SwarmEvent,
};

#[tokio::test]
#[ignore = "subprocess driven by the isolated Chromium pairing relay harness"]
async fn serve_pairing_seed() {
    let namespace = std::fs::read_link("/proc/self/ns/net").unwrap();
    assert_ne!(
        namespace.into_os_string(),
        std::env::var_os("P2P_VPN_TEST_NETNS").unwrap()
    );
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|key| {
            let peer = key.public().to_peer_id();
            let mut kad = kad::Behaviour::with_config(
                peer,
                kad::store::MemoryStore::new(peer),
                kad::Config::new(StreamProtocol::new("/ipfs/kad/1.0.0")),
            );
            kad.set_mode(Some(kad::Mode::Server));
            kad
        })
        .unwrap()
        .build();
    swarm
        .listen_on("/ip4/11.255.48.2/tcp/0".parse().unwrap())
        .unwrap();
    let (sender, mut commands) = tokio::sync::mpsc::channel(1);
    std::thread::spawn(move || {
        for command in io::stdin().lock().lines() {
            if sender.blocking_send(command.unwrap()).is_err() {
                break;
            }
        }
    });
    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { break };
                let fields: Vec<_> = command.split_whitespace().collect();
                let [locator, peer, circuit] = fields.as_slice() else { panic!("expected locator, peer and circuit"); };
                let key = kad::RecordKey::new(&format!("/p2p-vpn/pairing-code/{locator}/providers/2"));
                let circuit: Multiaddr = circuit.parse().unwrap();
                swarm.behaviour_mut().store_mut().add_provider(kad::ProviderRecord::new(
                    key, peer.parse().unwrap(), vec![circuit],
                )).unwrap();
                println!("pairing-provider-ready");
            },
            event = swarm.select_next_some() => {
                if let SwarmEvent::NewListenAddr { address, .. } = event {
                    println!("pairing-seed:{}", address.with_p2p(*swarm.local_peer_id()).unwrap());
                }
            },
        }
    }
}
