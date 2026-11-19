//! Authenticate relay discovery on the same physical epoch as the signed lookup.

use std::{io, net::IpAddr, num::NonZeroU8, sync::Arc, time::Duration};

use futures::StreamExt as _;
use libp2p::{
    Multiaddr, PeerId, Swarm, identify,
    identity::Keypair,
    kad,
    multiaddr::Protocol,
    relay::HOP_PROTOCOL_NAME,
    swarm::{self, ConnectionId, SwarmEvent, dial_opts::DialOpts},
};

use super::super::{
    DhtSwarm, DiscoveryPath, browser_address, discovery_only_transport, managed_physical_transport,
    public_discovery_transport_is_publicly_dialable,
};
use crate::runtime::physical_network::control::ControlRoutes;

const PROBE_BUDGET: Duration = Duration::from_secs(5);
const MAX_DIAL_ADDRESSES: usize = 4;
const MAX_IDENTIFY_ADDRESSES: usize = 32;

#[cfg(all(test, feature = "webrtc"))]
mod scoped_webrtc;

pub(super) enum Contact {
    Native(Multiaddr),
    WebRtc(Multiaddr),
}

impl Contact {
    pub(super) fn from_signed(relay: PeerId, entrance: Multiaddr) -> Option<Self> {
        if let Some(address) = native_contact(relay, entrance.clone()) {
            return Some(Self::Native(address));
        }
        browser_address(relay, entrance).map(Self::WebRtc)
    }

    pub(super) async fn verify(
        &self,
        relay: PeerId,
        dht: &mut DhtSwarm,
        path: &DiscoveryPath,
    ) -> io::Result<Multiaddr> {
        tokio::time::timeout(PROBE_BUDGET, async {
            let (addresses, signed_webrtc) = match self {
                Self::Native(address) => (vec![address.clone()], None),
                Self::WebRtc(address) => {
                    let host = numeric_host(address).ok_or_else(unavailable)?;
                    (
                        lookup_native_contacts(dht, relay, host).await?,
                        Some(address),
                    )
                }
            };
            identify_relay(path, relay, addresses, signed_webrtc).await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "relay Identify probe timed out"))?
    }
}

fn unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "no authenticated public WebRTC relay entrance",
    )
}

async fn lookup_native_contacts(
    dht: &mut DhtSwarm,
    relay: PeerId,
    host: IpAddr,
) -> io::Result<Vec<Multiaddr>> {
    let eligible = |addresses: Vec<Multiaddr>| {
        addresses
            .into_iter()
            .filter_map(|address| native_contact(relay, address))
            .filter(|address| numeric_host(address) == Some(host))
            .take(MAX_DIAL_ADDRESSES)
            .collect::<Vec<_>>()
    };
    let addresses = eligible(dht.behaviour_mut().addresses_of_peer(relay));
    if !addresses.is_empty() {
        return Ok(addresses);
    }
    let query = dht
        .behaviour_mut()
        .try_get_closest_peers(relay)
        .map_err(io::Error::other)?;
    loop {
        if let SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
            id, result, step, ..
        }) = dht.select_next_some().await
            && id == query
        {
            if let kad::QueryResult::GetClosestPeers(Ok(result)) = result
                && result.key == relay.to_bytes()
                && let Some(relay) = result.peers.into_iter().find(|info| info.peer_id == relay)
            {
                let addresses = eligible(relay.addrs);
                if !addresses.is_empty() {
                    return Ok(addresses);
                }
            }
            if step.last {
                return Err(unavailable());
            }
        }
    }
}

async fn identify_relay(
    path: &DiscoveryPath,
    relay: PeerId,
    addresses: Vec<Multiaddr>,
    signed_webrtc: Option<&Multiaddr>,
) -> io::Result<Multiaddr> {
    path.scope.check()?;
    let key = Keypair::generate_ed25519();
    let physical =
        managed_physical_transport(&key, Arc::clone(&path.routes)).map_err(io::Error::other)?;
    let transport = discovery_only_transport(physical, Arc::clone(&path.routes));
    let identify = identify::Behaviour::new(
        identify::Config::new("/p2p-vpn/0.1.0".into(), key.public())
            .with_hide_listen_addrs(true)
            .with_cache_size(0),
    );
    let mut swarm = Swarm::new(
        transport,
        identify,
        key.public().to_peer_id(),
        swarm::Config::with_tokio_executor()
            .with_dial_concurrency_factor(NonZeroU8::MIN)
            .with_idle_connection_timeout(PROBE_BUDGET),
    );
    let opts = DialOpts::peer_id(relay)
        .addresses(addresses)
        .allocate_new_port()
        .build();
    let connection = opts.connection_id();
    path.routes
        .mark_public_discovery_dial_in_scope(connection, &path.scope)?;
    let _intent = DialIntent {
        routes: &path.routes,
        connection,
    };
    path.scope.check()?;
    swarm.dial(opts).map_err(io::Error::other)?;
    let mut host = None;
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::ConnectionEstablished {
                connection_id,
                peer_id,
                endpoint,
                ..
            } if connection_id == connection && peer_id == relay => {
                if !path
                    .routes
                    .public_discovery_connection_available(relay, connection)
                {
                    return Err(unavailable());
                }
                host = numeric_host(endpoint.get_remote_address());
            }
            SwarmEvent::Behaviour(identify::Event::Received {
                connection_id,
                peer_id,
                info,
            }) if connection_id == connection && peer_id == relay => {
                path.scope.check()?;
                if !path
                    .routes
                    .public_discovery_connection_available(relay, connection)
                {
                    return Err(unavailable());
                }
                return identified_entrance(
                    relay,
                    host.ok_or_else(unavailable)?,
                    signed_webrtc,
                    info,
                )
                .ok_or_else(unavailable);
            }
            SwarmEvent::OutgoingConnectionError { connection_id, .. }
            | SwarmEvent::ConnectionClosed { connection_id, .. }
            | SwarmEvent::Behaviour(identify::Event::Error { connection_id, .. })
                if connection_id == connection =>
            {
                return Err(unavailable());
            }
            _ => {}
        }
    }
}

struct DialIntent<'a> {
    routes: &'a ControlRoutes,
    connection: ConnectionId,
}

impl Drop for DialIntent<'_> {
    fn drop(&mut self) {
        self.routes.finish_public_discovery_dial(self.connection);
    }
}

fn identified_entrance(
    relay: PeerId,
    host: IpAddr,
    signed_webrtc: Option<&Multiaddr>,
    info: identify::Info,
) -> Option<Multiaddr> {
    if info.public_key.to_peer_id() != relay || !info.protocols.contains(&HOP_PROTOCOL_NAME) {
        return None;
    }
    info.listen_addrs
        .into_iter()
        .take(MAX_IDENTIFY_ADDRESSES)
        .filter_map(|address| browser_address(relay, address))
        .find(|address| {
            numeric_host(address) == Some(host)
                && signed_webrtc.is_none_or(|signed| signed == address)
        })
}

pub(super) async fn verify_pinned_pair(
    path: &DiscoveryPath,
    relay: PeerId,
    native: &Multiaddr,
    webrtc: &Multiaddr,
) -> io::Result<()> {
    // A single explicit address is dialed, not the address list in Identify.
    identify_relay(path, relay, vec![native.clone()], Some(webrtc))
        .await
        .map(|_| ())
}

pub(super) fn native_contact(relay: PeerId, address: Multiaddr) -> Option<Multiaddr> {
    let mut parts = address.iter();
    if !matches!(parts.next(), Some(Protocol::Ip4(_) | Protocol::Ip6(_)))
        || !public_discovery_transport_is_publicly_dialable(&address)
    {
        return None;
    }
    match parts.next()? {
        Protocol::Tcp(port) if port != 0 => {}
        Protocol::Udp(port) if port != 0 && parts.next() == Some(Protocol::QuicV1) => {}
        _ => return None,
    }
    if !matches!(parts.next(), None | Some(Protocol::P2p(_))) || parts.next().is_some() {
        return None;
    }
    address.with_p2p(relay).ok()
}

pub(super) fn numeric_host(address: &Multiaddr) -> Option<IpAddr> {
    match address.iter().next()? {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip).to_canonical()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERT: &str = "uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g";

    #[test]
    fn identify_requires_hop_role_and_same_host_and_confirms_signed_webrtc() {
        let key = Keypair::generate_ed25519().public();
        let relay = key.to_peer_id();
        let host = "8.8.8.8".parse().unwrap();
        let addr = |ip, port| {
            format!("/ip4/{ip}/udp/{port}/webrtc-direct/certhash/{CERT}/p2p/{relay}")
                .parse::<Multiaddr>()
                .unwrap()
        };
        let signed = addr("8.8.8.8", 4002);
        let mut info = identify::Info {
            public_key: key,
            protocol_version: String::new(),
            agent_version: String::new(),
            listen_addrs: vec![
                addr("8.8.4.4", 4002),
                addr("192.168.1.1", 4002),
                signed.clone(),
            ],
            protocols: vec![HOP_PROTOCOL_NAME],
            observed_addr: Multiaddr::empty(),
            signed_peer_record: None,
        };
        assert_eq!(
            identified_entrance(relay, host, Some(&signed), info.clone()),
            Some(signed)
        );
        assert!(
            identified_entrance(relay, host, Some(&addr("8.8.8.8", 4003)), info.clone()).is_none()
        );
        assert!(identified_entrance(PeerId::random(), host, None, info.clone()).is_none());
        assert!(
            identified_entrance(relay, "1.1.1.1".parse().unwrap(), None, info.clone()).is_none()
        );
        info.protocols.clear();
        assert!(identified_entrance(relay, host, None, info).is_none());
    }

    #[test]
    fn probe_contacts_reject_dns_private_and_non_native_transports() {
        let relay = PeerId::random();
        let parse = |address: &str| address.parse().unwrap();
        for address in [
            "/dns4/relay.example/tcp/4001",
            "/ip4/192.168.1.2/tcp/4001",
            "/ip4/8.8.8.8/tcp/0",
            "/ip4/8.8.8.8/udp/4001",
            "/ip4/8.8.8.8/tcp/4001/p2p-circuit",
        ] {
            assert!(native_contact(relay, parse(address)).is_none(), "{address}");
        }
        let quic = parse("/ip4/8.8.8.8/udp/4001/quic-v1");
        assert_eq!(
            native_contact(relay, quic),
            Some(
                format!("/ip4/8.8.8.8/udp/4001/quic-v1/p2p/{relay}")
                    .parse()
                    .unwrap()
            )
        );
    }
}
