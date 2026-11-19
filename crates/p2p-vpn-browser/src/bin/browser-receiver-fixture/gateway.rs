use futures::StreamExt;
use libp2p::{
    Multiaddr, StreamProtocol, SwarmBuilder,
    identity::Keypair,
    kad::{self, store::RecordStore},
    multiaddr::Protocol,
    noise,
    swarm::SwarmEvent,
    tcp, yamux,
};
use p2p_vpn::{
    identity::NodeIdentity, peer_address_record, runtime::p2p::kademlia_peer_addresses_key,
};
use serde::Serialize;

use super::{Result, debug_error};

pub(super) const MEMBER_IP: &str = "11.250.0.2";
pub(super) const DHT_PROTOCOL: &str = "/p2p-vpn/browser-gateway-test/1";

#[derive(Serialize)]
pub(super) struct SignedFixture {
    bootstrap: String,
    unavailable_direct: String,
    #[serde(skip)]
    saw_direct: Arc<AtomicBool>,
}

impl SignedFixture {
    pub(super) fn saw_direct(&self) -> bool {
        self.saw_direct.load(Ordering::Relaxed)
    }
}

pub(super) async fn publish(
    network: &str,
    member: &NodeIdentity,
    direct: &Multiaddr,
    circuit: Multiaddr,
    now: u64,
) -> Result<SignedFixture> {
    // Keep the alternate direct socket bound without speaking WebRTC. It cannot
    // accidentally become a working direct path during the test.
    let unused_direct = tokio::net::UdpSocket::bind((MEMBER_IP, 0)).await?;
    let port = unused_direct.local_addr()?.port();
    let unavailable_direct = direct
        .replace(1, |protocol| match protocol {
            Protocol::Udp(_) => Some(Protocol::Udp(port)),
            _ => None,
        })
        .ok_or("expected fixture WebRTC Direct UDP address")?;
    // Construct the signed record only after the member's reservation is ready.
    let value = peer_address_record::encode(
        network,
        None,
        member,
        vec![unavailable_direct.clone(), circuit],
        now,
    )
    .map_err(debug_error)?;
    let seed = Keypair::generate_ed25519();
    let peer = seed.public().to_peer_id();
    let member_peer = member.peer_id.parse()?;
    let mut store = kad::store::MemoryStore::new(peer);
    store.put(kad::Record::new(
        kademlia_peer_addresses_key(network, None, member_peer),
        value,
    ))?;
    let mut behaviour = kad::Behaviour::with_config(
        peer,
        store,
        kad::Config::new(StreamProtocol::new(DHT_PROTOCOL)),
    );
    behaviour.set_mode(Some(kad::Mode::Server));
    let mut swarm = SwarmBuilder::with_existing_identity(seed)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|_| behaviour)?
        .build();
    swarm.listen_on(format!("/ip4/{MEMBER_IP}/tcp/0").parse()?)?;
    let bootstrap = loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => break address.with(Protocol::P2p(peer)),
            SwarmEvent::ListenerError { error, .. } => return Err(error.into()),
            _ => {}
        }
    };
    let saw_direct = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&saw_direct);
    tokio::spawn(async move {
        let mut probe = [0_u8; 2048];
        loop {
            tokio::select! {
                event = swarm.next() => if event.is_none() { break; },
                size = unused_direct.recv(&mut probe) => match size {
                    Ok(1..) => observed.store(true, Ordering::Relaxed),
                    Ok(0) => {}
                    Err(_) => break,
                }
            }
        }
    });
    Ok(SignedFixture {
        bootstrap: bootstrap.to_string(),
        unavailable_direct: unavailable_direct.to_string(),
        saw_direct,
    })
}
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
