//! Native libp2p TLS and multiplexing with exact physical-route ownership.

use crate::runtime::physical_network::linux::{
    control::{ControlRoutes, Registration},
    egress::RouteLease,
};
use futures::{FutureExt, future::BoxFuture};
use libp2p::{
    PeerId,
    quic::{ConnectionOwner, Selection, SocketContext, SocketPolicy},
    swarm::ConnectionId,
};
use std::{fmt, io, num::NonZeroU32, sync::Arc};

pub(crate) struct Policy {
    routes: Arc<ControlRoutes>,
    preparing: Arc<tokio::sync::Semaphore>,
}

impl fmt::Debug for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeQuicPolicy")
            .field("available_handshakes", &self.preparing.available_permits())
            .finish_non_exhaustive()
    }
}

impl Policy {
    pub(crate) fn new(routes: Arc<ControlRoutes>) -> Self {
        Self {
            routes,
            preparing: Arc::new(tokio::sync::Semaphore::new(16)),
        }
    }
}

impl SocketPolicy for Policy {
    fn prepare(&self, context: SocketContext) -> BoxFuture<'static, io::Result<Selection>> {
        let routes = Arc::clone(&self.routes);
        let preparing = Arc::clone(&self.preparing);
        async move {
            let permit = preparing.try_acquire_owned().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "native QUIC handshake preparation limit",
                )
            })?;
            let lease = if context.role.is_dialer() {
                routes
                    .egress
                    .prepare_shared_datagram(context.local, context.remote, context.mark)
                    .await?
            } else {
                routes
                    .egress
                    .prepare_incoming(context.local, context.remote, context.mark)
                    .await?
            };
            let interface = NonZeroU32::new(lease.route.interface_index).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "zero native QUIC interface")
            })?;
            Ok(Selection {
                source: lease.local_addr.ip(),
                interface,
                owner: Box::new(Owner {
                    routes,
                    lease,
                    registered: None,
                    permit: Some(permit),
                }),
            })
        }
        .boxed()
    }
}

struct Owner {
    routes: Arc<ControlRoutes>,
    lease: RouteLease,
    registered: Option<Registration>,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl fmt::Debug for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeQuicOwner")
            .field("lease", &self.lease)
            .field("authenticated", &self.registered.is_some())
            .finish()
    }
}

impl ConnectionOwner for Owner {
    fn before_handshake(&self) -> io::Result<()> {
        if !self.lease.is_current() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "native QUIC route selection is stale",
            ));
        }
        Ok(())
    }

    fn authenticated(&mut self, peer: PeerId) -> io::Result<()> {
        self.before_handshake()?;
        if self.registered.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native QUIC owner authenticated twice",
            ));
        }
        self.registered = Some(self.routes.register(peer, self.lease.clone())?);
        self.permit = None;
        Ok(())
    }

    fn admitted(&mut self, id: usize) -> io::Result<()> {
        let registration = self.registered.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "native QUIC admission lacks authentication",
            )
        })?;
        registration.bind_connection(ConnectionId::new_unchecked(id))?;
        registration.adopt()
    }
}

#[cfg(test)]
mod tests;
