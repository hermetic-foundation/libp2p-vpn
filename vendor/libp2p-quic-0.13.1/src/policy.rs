//! Optional pre-handshake selection and authenticated connection ownership.

use futures::future::BoxFuture;
use libp2p_core::Endpoint;
use libp2p_identity::PeerId;
use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    time::Duration,
};

/// A fresh native handshake for a selected immutable socket owner.
pub type DialOperation = Box<
    dyn FnMut(Selection) -> BoxFuture<'static, Result<(PeerId, crate::Connection), crate::Error>>
        + Send,
>;

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

    /// Existing policies retain their original single-selection dial behavior.
    fn dial(
        &self,
        context: SocketContext,
        _peer: Option<PeerId>,
        _handshake_timeout: Duration,
        mut operation: DialOperation,
    ) -> BoxFuture<'static, Result<(PeerId, crate::Connection), crate::Error>> {
        let preparation = self.prepare(context);
        Box::pin(async move { operation(preparation.await?).await })
    }

    /// An optional policy may budget several handshakes within one outgoing dial.
    /// Incoming upgrades and hole-punch listeners retain their configured timeout.
    fn dial_timeout(
        &self,
        _context: SocketContext,
        _peer: Option<PeerId>,
        configured: Duration,
    ) -> Duration {
        configured
    }
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
    /// Real platform Network ownership, independent of source/interface metadata.
    /// Existing policy owners retain their current interface-only behavior.
    fn socket_binding(&self) -> Option<std::sync::Arc<dyn quinn::UdpSocketBinding>> {
        None
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct ExistingOwner;

    impl ConnectionOwner for ExistingOwner {
        fn before_handshake(&self) -> io::Result<()> {
            Ok(())
        }
        fn authenticated(&mut self, _: PeerId) -> io::Result<()> {
            Ok(())
        }
        fn admitted(&mut self, _: usize) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn existing_selection_literals_and_owners_default_to_no_network_binding() {
        let selection = Selection {
            source: "127.0.0.1".parse().unwrap(),
            interface: NonZeroU32::new(1).unwrap(),
            owner: Box::new(ExistingOwner),
        };
        assert!(selection.owner.socket_binding().is_none());
        selection.owner.before_handshake().unwrap();
    }
}
