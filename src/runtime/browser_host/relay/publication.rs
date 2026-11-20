//! Host-side byte transport for a fixed set of DHT contacts.

use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use futures::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, StreamExt as _};
use libp2p::{Multiaddr, PeerId, StreamProtocol, kad, multiaddr::Protocol, swarm::SwarmEvent};
use tokio::{
    sync::{Semaphore, watch},
    time::{Instant, sleep_until},
};

use super::probe;
use crate::runtime::physical_network::{
    platform::SocketProtocol,
    public_discovery::{GuardedIo, Scope, connect_tcp},
};
use crate::runtime::{
    browser_host::{ControlRoutes, DiscoveryLimits, build_dht_swarm, while_current},
    browser_relay_egress::LeaseControl,
};

const CONTACTS: usize = 12;
const CONCURRENT: usize = 3;
const BYTES_PER_DIRECTION: u64 = 128 * 1024;
const LIFETIME: Duration = Duration::from_secs(15);
const DISCOVERY_BUDGET: Duration = Duration::from_secs(4);

#[derive(Clone, Copy)]
pub(in crate::runtime::browser_host) enum Operation {
    Publish,
    Readback,
}

impl Operation {
    fn bit(self, index: usize) -> u32 {
        1 << (index
            + if matches!(self, Self::Readback) {
                CONTACTS
            } else {
                0
            })
    }
}

pub(in crate::runtime::browser_host) struct Publication {
    scope: Scope,
    deadline: Instant,
    contacts: Vec<(PeerId, SocketAddr)>,
    used: AtomicU32,
    streams: Semaphore,
    canceled: watch::Sender<bool>,
    lease: LeaseControl,
}

impl Publication {
    pub(super) async fn discover(
        lease: LeaseControl,
        protocol: &StreamProtocol,
        bootstrap: &[(PeerId, Multiaddr)],
        key: Vec<u8>,
    ) -> io::Result<Self> {
        let deadline = lease.publication_deadline()?.min(Instant::now() + LIFETIME);
        let relay = lease.reservation_relay()?;
        let scope = lease.scope();
        let routes = Arc::new(ControlRoutes::with_shared_egress(
            32,
            Arc::clone(scope.egress()),
        ));
        let lookup = tokio::time::timeout(
            DISCOVERY_BUDGET,
            while_current(&scope, async {
                let mut swarm = build_dht_swarm(
                    protocol,
                    bootstrap.to_vec(),
                    routes,
                    scope.clone(),
                    Some(DiscoveryLimits {
                        dial_attempts: CONTACTS,
                        query_timeout: DISCOVERY_BUDGET - Duration::from_millis(250),
                    }),
                )?;
                let query = swarm
                    .behaviour_mut()
                    .try_get_closest_peers(key)
                    .map_err(io::Error::other)?;
                loop {
                    if let SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetClosestPeers(result),
                        step,
                        ..
                    }) = swarm.select_next_some().await
                        && id == query
                        && step.last
                    {
                        let peers = match result {
                            Ok(result) => result.peers,
                            Err(kad::GetClosestPeersError::Timeout { peers, .. }) => peers,
                        };
                        let contacts = peers
                            .into_iter()
                            .filter(|entry| entry.peer_id != relay)
                            .filter_map(|entry| {
                                entry
                                    .addrs
                                    .into_iter()
                                    .chain(swarm.behaviour_mut().addresses_of_peer(entry.peer_id))
                                    .find(|address| {
                                        tcp_contact(entry.peer_id, address.clone()).is_some()
                                    })
                                    .map(|address| (entry.peer_id, address))
                            })
                            .take(CONTACTS)
                            .collect::<Vec<_>>();
                        return Ok(contacts);
                    }
                }
            }),
        );
        let contacts = tokio::select! {
            biased;
            () = lease.publication_ended() => return Err(interrupted()),
            result = lookup => result.map_err(io::Error::other)??,
        };
        lease.publication_deadline()?;
        if contacts.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no eligible locator DHT contacts",
            ));
        }
        Ok(Self::new(lease, scope, deadline, contacts))
    }

    /// Contacts must come from the host's bounded DHT discovery, never HTTP.
    fn new(
        lease: LeaseControl,
        scope: Scope,
        deadline: Instant,
        contacts: impl IntoIterator<Item = (PeerId, Multiaddr)>,
    ) -> Self {
        let mut admitted = Vec::new();
        for (peer, address) in contacts.into_iter().take(CONTACTS) {
            if let Some(destination) = tcp_contact(peer, address)
                && !admitted.iter().any(|&(id, _)| id == peer)
            {
                admitted.push((peer, destination));
            }
        }
        Self {
            scope,
            deadline,
            contacts: admitted,
            used: AtomicU32::new(0),
            streams: Semaphore::new(CONCURRENT),
            canceled: watch::Sender::new(false),
            lease,
        }
    }

    pub(in crate::runtime::browser_host) fn peers(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.contacts.iter().map(|&(peer, _)| peer)
    }

    pub(super) fn cancel(&self) {
        self.canceled.send_replace(true);
    }

    pub(in crate::runtime::browser_host) fn check(
        &self,
        index: usize,
        operation: Operation,
    ) -> io::Result<()> {
        self.lease.publication_deadline()?;
        if index >= self.contacts.len()
            || *self.canceled.borrow()
            || Instant::now() >= self.deadline
        {
            return Err(interrupted());
        }
        let used = self.used.load(Ordering::Relaxed);
        if used & operation.bit(index) != 0
            || matches!(operation, Operation::Readback) && used & Operation::Publish.bit(index) == 0
        {
            return Err(interrupted());
        }
        Ok(())
    }

    pub(in crate::runtime::browser_host) async fn forward(
        &self,
        index: usize,
        operation: Operation,
        ingress: impl AsyncRead + AsyncWrite + Unpin,
    ) -> io::Result<()> {
        self.check(index, operation)?;
        let &(_, destination) = self
            .contacts
            .get(index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown DHT contact"))?;
        let bit = operation.bit(index);
        if self.used.fetch_or(bit, Ordering::Relaxed) & bit != 0 {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "DHT contact already attempted",
            ));
        }
        let mut cancel = self.canceled.subscribe();
        tokio::select! {
            biased;
            _ = cancel.wait_for(|closed| *closed) => Err(interrupted()),
            () = self.scope.invalidated() => Err(interrupted()),
            () = sleep_until(self.deadline) => Err(interrupted()),
            () = self.lease.publication_ended() => Err(interrupted()),
            result = async {
                let _slot = self.streams.acquire().await.map_err(io::Error::other)?;
                self.lease.publication_deadline()?;
                self.scoped_copy(destination, ingress).await
            } => result,
        }
    }

    async fn scoped_copy(
        &self,
        destination: SocketAddr,
        ingress: impl AsyncRead + AsyncWrite + Unpin,
    ) -> io::Result<()> {
        let (socket, lease) = self
            .scope
            .prepare_socket(destination, SocketProtocol::Tcp)
            .await?;
        let stream = connect_tcp(socket, lease.context.destination, &self.scope).await?;
        let shutdown = socket2::SockRef::from(&stream).try_clone()?;
        let stream = GuardedIo::new(
            libp2p::tcp::tokio::TcpStream(stream),
            self.scope.clone(),
            shutdown,
        )?;
        let (mut from_browser, to_browser) = ingress.split();
        let (mut from_dht, to_dht) = stream.split();
        futures::try_join!(
            copy_bounded(&mut from_browser, to_dht),
            copy_bounded(&mut from_dht, to_browser),
        )?;
        Ok(())
    }
}

async fn copy_bounded(
    source: &mut (impl AsyncRead + Unpin),
    mut destination: impl AsyncWrite + Unpin,
) -> io::Result<()> {
    let mut source = source.take(BYTES_PER_DIRECTION);
    let bytes = futures::io::copy(&mut source, &mut destination).await?;
    if bytes == BYTES_PER_DIRECTION {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "DHT byte limit",
        ));
    }
    destination.close().await
}

fn tcp_contact(peer: PeerId, address: Multiaddr) -> Option<SocketAddr> {
    let contact = probe::native_contact(peer, address)?;
    let host = probe::numeric_host(&contact)?;
    let Protocol::Tcp(port) = contact.iter().nth(1)? else {
        return None;
    };
    Some(SocketAddr::new(host, port))
}

fn interrupted() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "DHT publication ended")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_requires_a_numeric_public_tcp_contact_for_the_pinned_peer() {
        let peer = PeerId::random();
        let other = PeerId::random();
        let contact =
            |address: &str, id| tcp_contact(peer, format!("{address}/p2p/{id}").parse().unwrap());
        assert_eq!(
            contact("/ip4/11.250.7.1/tcp/4001", peer),
            Some("11.250.7.1:4001".parse().unwrap())
        );
        assert_eq!(contact("/ip4/11.250.7.1/tcp/4001", other), None);
        assert_eq!(contact("/ip4/127.0.0.1/tcp/4001", peer), None);
        assert_eq!(contact("/dns4/example.net/tcp/4001", peer), None);
        assert_eq!(contact("/ip4/11.250.7.1/udp/4001/quic-v1", peer), None);
    }

    #[tokio::test]
    async fn stops_forwarding_at_the_byte_limit() {
        let mut source = futures::io::Cursor::new(vec![7; BYTES_PER_DIRECTION as usize + 1]);
        let mut destination = Vec::new();
        let error = copy_bounded(&mut source, &mut destination)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(destination.len(), BYTES_PER_DIRECTION as usize);
    }
}
