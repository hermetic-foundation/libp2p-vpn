//! Two local SDK peers with host-supplied packet I/O and no OS VPN setup.
use std::{
    io,
    net::{Ipv4Addr, SocketAddr, TcpListener},
    sync::mpsc,
    time::Duration,
};

use p2p_vpn::{
    config::{Config, DiscoveryConfig},
    identity::NodeIdentity,
    route::builtin_ipv4,
    runtime::{
        runner::{ShutdownReason, run_config_until_with_packet_io},
        tun::{PacketIo, PacketRead, PacketWrite},
    },
};
use tokio::sync::{mpsc as async_mpsc, oneshot};

struct HostReader {
    packets: mpsc::Receiver<Option<Vec<u8>>>,
    cancel: mpsc::Sender<Option<Vec<u8>>>,
}

impl PacketRead for HostReader {
    fn read_packet(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let Ok(Some(packet)) = self.packets.recv() else {
            return Ok(0);
        };
        let output = buffer
            .get_mut(..packet.len())
            .ok_or(io::ErrorKind::InvalidData)?;
        output.copy_from_slice(&packet);
        Ok(packet.len())
    }

    fn cancellation(&self) -> Option<Box<dyn FnOnce() + Send>> {
        let cancel = self.cancel.clone();
        Some(Box::new(move || {
            let _ = cancel.send(None);
        }))
    }
}

struct HostWriter(async_mpsc::UnboundedSender<Vec<u8>>);

impl PacketWrite for HostWriter {
    fn write_packet(&mut self, packet: &[u8]) -> io::Result<usize> {
        self.0
            .send(packet.to_vec())
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        Ok(packet.len())
    }
}

fn peer_config(
    local: &NodeIdentity,
    remote: &NodeIdentity,
    listen: SocketAddr,
    dial: SocketAddr,
) -> Config {
    let mut config: Config = serde_json::from_value(serde_json::json!({
        "network": {
            "name": "native-embedding",
            "private_key": local.private_key,
            "listen_addresses": [format!("/ip4/{}/tcp/{}", listen.ip(), listen.port())],
            "packet_plane": { "listen": [], "quic_listen": [] }
        },
        "peers": [{
            "id": remote.peer_id,
            "addresses": [format!("/ip4/{}/tcp/{}", dial.ip(), dial.port())]
        }]
    }))
    .expect("valid local peer settings");
    config.network.discovery = DiscoveryConfig {
        mdns: false,
        kademlia: false,
        autonat: false,
        dcutr: false,
        kademlia_provider_advertisement: false,
        ..DiscoveryConfig::default()
    };
    config.network.relay.auto.max_reservations = 0;
    config
}

fn ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
    let mut packet = vec![0_u8; 32];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&32_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    packet[20..22].copy_from_slice(&42001_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&42002_u16.to_be_bytes());
    packet[24..26].copy_from_slice(&12_u16.to_be_bytes());
    packet[28..].copy_from_slice(b"ping");
    let mut sum: u32 = packet[..20]
        .chunks_exact(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!u16::try_from(sum).expect("folded checksum")).to_be_bytes());
    packet
}

async fn exchange() {
    let alice = NodeIdentity::generate_ed25519().expect("Alice identity");
    let peer_ip =
        |identity: &NodeIdentity| builtin_ipv4(identity.peer_id.parse().expect("peer ID"));
    let bob = loop {
        let candidate = NodeIdentity::generate_ed25519().expect("Bob identity");
        if peer_ip(&candidate) != peer_ip(&alice) {
            break candidate;
        }
    };
    let listeners =
        [(); 2].map(|()| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback"));
    let [alice_listen, bob_listen] = listeners
        .each_ref()
        .map(|listener| listener.local_addr().expect("socket address"));
    drop(listeners);

    let configs = [
        peer_config(&alice, &bob, alice_listen, bob_listen),
        peer_config(&bob, &alice, bob_listen, alice_listen),
    ];
    let [
        (alice_tx, _alice_rx, alice_stop, alice_task),
        (_bob_tx, mut bob_rx, bob_stop, bob_task),
    ] = configs.map(|config| {
        let (input, packets) = mpsc::channel();
        let (writer, output) = async_mpsc::unbounded_channel();
        let io = PacketIo::new(
            HostReader {
                packets,
                cancel: input.clone(),
            },
            HostWriter(writer),
        );
        let (stop, shutdown) = oneshot::channel();
        let task = tokio::spawn(run_config_until_with_packet_io(
            config,
            io,
            None,
            None,
            None,
            async {
                let _ = shutdown.await;
                ShutdownReason::ControlSocket
            },
        ));
        (input, output, stop, task)
    });

    let expected = ipv4_packet(peer_ip(&alice), peer_ip(&bob));
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            alice_tx
                .send(Some(expected.clone()))
                .expect("send to Alice");
            if let Ok(packet) =
                tokio::time::timeout(Duration::from_millis(250), bob_rx.recv()).await
            {
                return packet;
            }
        }
    })
    .await;
    let _ = alice_stop.send(());
    let _ = bob_stop.send(());
    for peer in [alice_task, bob_task] {
        tokio::time::timeout(Duration::from_secs(5), peer)
            .await
            .expect("peer stops")
            .expect("peer task")
            .expect("peer runtime");
    }
    assert_eq!(
        result.expect("Bob receives a packet by the deadline"),
        Some(expected)
    );
    println!("Bob received Alice's packet through the SDK");
}

fn main() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(8 * 1024 * 1024)
                .enable_all()
                .build()
                .expect("Tokio runtime")
                .block_on(exchange());
        })
        .expect("peer owner thread")
        .join()
        .expect("packet exchange");
}
