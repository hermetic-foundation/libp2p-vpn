use futures::StreamExt;
use libp2p::{
    Multiaddr, StreamProtocol, Swarm, SwarmBuilder,
    identity::Keypair,
    kad::{self, store::RecordStore},
    multiaddr::Protocol,
    noise,
    swarm::SwarmEvent,
    tcp, yamux,
};
use p2p_vpn::{
    config::PUBLIC_IPFS_KADEMLIA_PROTOCOL,
    identity::NodeIdentity,
    peer_address_record,
    runtime::p2p::{kademlia_peer_addresses_key, kademlia_rendezvous_key},
};
use serde::{Deserialize, Serialize};

use super::{Result, debug_error};

pub(super) const MEMBER_IP: &str = "11.250.0.2";
pub(super) const MEMBER_V6: &str = "fd42:250::2";
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
    let record = SignedRecord::new(
        network,
        member,
        vec![unavailable_direct.clone(), circuit],
        now,
    )?;
    let (mut swarm, bootstrap) = seed(record).await?;
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

#[derive(Serialize, Deserialize)]
pub(super) struct SignedRecord {
    pub(super) network: String,
    pub(super) member: String,
    pub(super) value: Vec<u8>,
}

impl SignedRecord {
    pub(super) fn new(
        network: &str,
        member: &NodeIdentity,
        addresses: Vec<Multiaddr>,
        now: u64,
    ) -> Result<Self> {
        Ok(Self {
            network: network.into(),
            member: member.peer_id.clone(),
            value: peer_address_record::encode(network, None, member, addresses, now)
                .map_err(debug_error)?,
        })
    }
}

pub(super) async fn serve_seed() -> Result<()> {
    let record = serde_json::from_reader(std::io::stdin().lock())?;
    let (mut swarm, bootstrap) = seed(record).await?;
    println!("{bootstrap}");
    while swarm.next().await.is_some() {}
    Ok(())
}

#[derive(Deserialize)]
struct MemberProvider {
    network: String,
    member: String,
    address: Multiaddr,
    #[serde(default)]
    unreachable: Option<Multiaddr>,
    #[serde(default)]
    switch_route: bool,
}

pub(super) fn stdin_line() -> std::io::Result<String> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line)
}

pub(super) async fn serve_member_provider() -> Result<()> {
    let provider: MemberProvider = serde_json::from_str(&stdin_line()?)?;
    let seed = Keypair::generate_ed25519();
    let mut store = kad::store::MemoryStore::new(seed.public().to_peer_id());
    let key = kademlia_rendezvous_key(&provider.network, None);
    assert!(
        key.as_ref().len() <= 80,
        "fixture uses the untransformed key"
    );
    let member = provider.member.parse()?;
    store.add_provider(kad::ProviderRecord::new(
        key.clone(),
        member,
        provider
            .unreachable
            .into_iter()
            .chain([provider.address])
            .collect(),
    ))?;
    let (mut swarm, bootstrap) = serve_store(seed, store, PUBLIC_IPFS_KADEMLIA_PROTOCOL).await?;
    println!("{bootstrap}");
    if provider.switch_route {
        let replacement = tokio::task::spawn_blocking(stdin_line);
        tokio::pin!(replacement);
        let replacement: Multiaddr = loop {
            tokio::select! {
                line = &mut replacement => break line??.trim().parse()?,
                _ = swarm.select_next_some() => {}
            }
        };
        assert_eq!(replacement.iter().last(), Some(Protocol::P2p(member)));
        let store = swarm.behaviour_mut().store_mut();
        store.remove_provider(&key, &member);
        store.add_provider(kad::ProviderRecord::new(key, member, vec![replacement]))?;
        println!("provider switched");
    }
    while swarm.next().await.is_some() {}
    Ok(())
}

pub(super) async fn seed(
    record: SignedRecord,
) -> Result<(Swarm<kad::Behaviour<kad::store::MemoryStore>>, Multiaddr)> {
    let seed = Keypair::generate_ed25519();
    let peer = seed.public().to_peer_id();
    let mut store = kad::store::MemoryStore::new(peer);
    store.put(kad::Record::new(
        kademlia_peer_addresses_key(&record.network, None, record.member.parse()?),
        record.value,
    ))?;
    serve_store(seed, store, DHT_PROTOCOL).await
}

async fn serve_store(
    seed: Keypair,
    store: kad::store::MemoryStore,
    protocol: &'static str,
) -> Result<(Swarm<kad::Behaviour<kad::store::MemoryStore>>, Multiaddr)> {
    let mut behaviour = kad::Behaviour::with_config(
        seed.public().to_peer_id(),
        store,
        kad::Config::new(StreamProtocol::new(protocol)),
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
            SwarmEvent::NewListenAddr { address, .. } => {
                break address.with(Protocol::P2p(*swarm.local_peer_id()));
            }
            SwarmEvent::ListenerError { error, .. } => return Err(error.into()),
            _ => {}
        }
    };
    Ok((swarm, bootstrap))
}
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
