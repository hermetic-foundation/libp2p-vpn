//! Host-side byte transport for a fixed set of DHT contacts.

use std::{
    io,
    net::SocketAddr,
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};

use futures::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use tokio::{
    sync::{Semaphore, watch},
    time::{Instant, sleep_until},
};

use super::probe;
use crate::runtime::physical_network::{
    platform::SocketProtocol,
    public_discovery::{GuardedIo, Scope, connect_tcp},
};

const CONTACTS: usize = 12;
const CONCURRENT: usize = 3;
const BYTES_PER_DIRECTION: u64 = 128 * 1024;
const LIFETIME: Duration = Duration::from_secs(15);

pub(super) struct Publication {
    scope: Scope,
    deadline: Instant,
    contacts: Vec<(PeerId, SocketAddr)>,
    used: AtomicU16,
    streams: Semaphore,
    canceled: watch::Sender<bool>,
}

impl Publication {
    /// Contacts must come from the host's bounded DHT discovery, never HTTP.
    pub(super) fn new(
        scope: Scope,
        invitation_end: Instant,
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
            deadline: invitation_end.min(Instant::now() + LIFETIME),
            contacts: admitted,
            used: AtomicU16::new(0),
            streams: Semaphore::new(CONCURRENT),
            canceled: watch::Sender::new(false),
        }
    }

    pub(super) fn peers(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.contacts.iter().map(|&(peer, _)| peer)
    }

    pub(super) fn cancel(&self) {
        self.canceled.send_replace(true);
    }

    pub(super) async fn forward(
        &self,
        index: usize,
        ingress: impl AsyncRead + AsyncWrite + Unpin,
    ) -> io::Result<()> {
        let &(_, destination) = self
            .contacts
            .get(index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown DHT contact"))?;
        let _slot = self
            .streams
            .try_acquire()
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "DHT stream limit"))?;
        let bit = 1 << index;
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
            result = self.scoped_copy(destination, ingress) => result,
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
