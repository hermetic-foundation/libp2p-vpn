//! Optional pre-handshake selection and authenticated connection ownership.

use futures::future::BoxFuture;
use libp2p_core::Endpoint;
use libp2p_identity::PeerId;
use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
};

/// Actual shared socket tuple before any connection handshake is started.
#[derive(Clone, Copy, Debug)]
pub struct SocketContext {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub role: Endpoint,
    pub mark: u32,
}

/// Optional route selection. Default transports do not install a policy.
pub trait SocketPolicy: fmt::Debug + Send + Sync + 'static {
    fn prepare(&self, context: SocketContext) -> BoxFuture<'static, io::Result<Selection>>;
}

/// A connection's immutable transmit policy and ownership sidecar.
#[derive(Debug)]
pub struct Selection {
    pub source: IpAddr,
    pub interface: NonZeroU32,
    pub owner: Box<dyn ConnectionOwner>,
}

/// Ownership is authenticated before admission and released by normal RAII drop.
pub trait ConnectionOwner: fmt::Debug + Send + Sync + 'static {
    /// Reject stale selection before starting a handshake or hole-punch probe.
    fn before_handshake(&self) -> io::Result<()>;
    /// The native TLS engine has authenticated this exact peer.
    fn authenticated(&mut self, peer: PeerId) -> io::Result<()>;
    /// Called only after swarm admission with its exact process-local ID.
    fn admitted(&mut self, connection_id: usize) -> io::Result<()>;
}

pub(crate) struct SelectedIncoming(pub(crate) Option<quinn::Incoming>);

impl Drop for SelectedIncoming {
    fn drop(&mut self) {
        if let Some(incoming) = self.0.take() {
            incoming.ignore();
        }
    }
}
