//! Native libp2p TLS and multiplexing with exact physical-route ownership.

use crate::runtime::physical_network::{
    control::{ControlRoutes, Registration},
    platform::egress::RouteLease,
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

    fn selection(
        routes: Arc<ControlRoutes>,
        lease: RouteLease,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> io::Result<Selection> {
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
            Self::selection(routes, lease, permit)
        }
        .boxed()
    }

    #[cfg(target_os = "android")]
    fn dial_timeout(
        &self,
        context: SocketContext,
        peer: Option<PeerId>,
        configured: std::time::Duration,
    ) -> std::time::Duration {
        if context.local.ip().is_unspecified() && self.routes.network_fallback_allowed(peer) {
            configured
                .min(std::time::Duration::from_secs(6))
                .saturating_mul(3)
        } else {
            configured
        }
    }

    #[cfg(target_os = "android")]
    fn dial(
        &self,
        context: SocketContext,
        peer: Option<PeerId>,
        handshake_timeout: std::time::Duration,
        mut operation: libp2p::quic::DialOperation,
    ) -> BoxFuture<'static, Result<(PeerId, libp2p::quic::Connection), libp2p::quic::Error>> {
        // Explicit source overrides and non-recovery discovery keep the legacy
        // single-attempt budget. Incoming and hole-punch listeners use prepare.
        if !context.local.ip().is_unspecified() || !self.routes.network_fallback_allowed(peer) {
            let preparation = self.prepare(context);
            return async move { operation(preparation.await?).await }.boxed();
        }
        let routes = Arc::clone(&self.routes);
        let preparing = Arc::clone(&self.preparing);
        async move {
            let _permit = routes.egress.connect_permit()?;
            let operation_routes = Arc::clone(&routes);
            let permission_routes = Arc::clone(&routes);
            routes
                .egress
                .attempt_networks_if_with_timeout(
                    context.local,
                    context.remote,
                    crate::runtime::physical_network::android::SocketProtocol::Udp,
                    context.mark,
                    handshake_timeout.min(std::time::Duration::from_secs(6)),
                    move |lease| {
                        let selection = Arc::clone(&preparing)
                            .try_acquire_owned()
                            .map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::WouldBlock,
                                    "native QUIC handshake preparation limit",
                                )
                            })
                            .and_then(|permit| {
                                Self::selection(Arc::clone(&operation_routes), lease, permit)
                            });
                        let attempt = selection.map(&mut operation);
                        async move { attempt?.await.map_err(native_dial_error) }.boxed()
                    },
                    move || permission_routes.network_fallback_allowed(peer),
                )
                .await
                .map_err(restore_native_error)
        }
        .boxed()
    }
}

#[cfg(any(target_os = "android", test))]
fn native_dial_error(error: libp2p::quic::Error) -> io::Error {
    use libp2p::quic::Error;
    let kind = match &error {
        Error::Io(error) => error.kind(),
        Error::HandshakeTimedOut => io::ErrorKind::TimedOut,
        Error::Connection(error) => native_connection_error_kind(error.as_ref()),
        _ => io::ErrorKind::InvalidInput,
    };
    io::Error::new(kind, error)
}

#[cfg(any(target_os = "android", test))]
fn native_connection_error_kind(error: &quinn::ConnectionError) -> io::ErrorKind {
    match error {
        quinn::ConnectionError::TimedOut => io::ErrorKind::TimedOut,
        quinn::ConnectionError::Reset => io::ErrorKind::ConnectionReset,
        quinn::ConnectionError::LocallyClosed => io::ErrorKind::Interrupted,
        // Explicit peer closes include TLS/protocol rejection. They do not
        // establish a failed physical Network and must not authorize a retry.
        _ => io::ErrorKind::InvalidData,
    }
}

#[cfg(any(target_os = "android", test))]
fn restore_native_error(error: io::Error) -> libp2p::quic::Error {
    if !error
        .get_ref()
        .is_some_and(|source| source.is::<libp2p::quic::Error>())
    {
        return libp2p::quic::Error::Io(error);
    }
    let kind = error.kind();
    match error.into_inner() {
        Some(source) => match source.downcast::<libp2p::quic::Error>() {
            Ok(error) => *error,
            Err(source) => libp2p::quic::Error::Io(io::Error::new(kind, source)),
        },
        None => libp2p::quic::Error::Io(kind.into()),
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
    #[cfg(target_os = "android")]
    fn socket_binding(&self) -> Option<Arc<dyn quinn::UdpSocketBinding>> {
        Some(self.lease.socket_binding())
    }

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

#[cfg(all(test, target_os = "linux"))]
mod tests;
