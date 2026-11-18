//! Exact UDP route ownership lives with the authenticated key session.

use super::super::physical_network::platform::egress::{Egress, RouteLease};
use super::*;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug)]
pub(super) struct Routes {
    pub(super) token: Arc<()>,
    pub(super) valid: AtomicBool,
    pub(super) sockets: Vec<Slot>,
    #[cfg(target_os = "android")]
    pub(super) recovery: Option<super::udp_retry::Candidate>,
}

impl Routes {
    pub(super) fn new(listeners: usize) -> Arc<Self> {
        Arc::new(Self {
            token: Arc::new(()),
            valid: AtomicBool::new(true),
            sockets: (0..listeners).map(|_| Slot::default()).collect(),
            #[cfg(target_os = "android")]
            recovery: None,
        })
    }

    pub(super) fn current_sources(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        let current = self.valid.load(Ordering::Acquire);
        #[cfg(target_os = "android")]
        let current = current
            && self
                .recovery
                .as_ref()
                .is_none_or(|candidate| candidate.is_current());
        self.sockets.iter().filter_map(move |slot| {
            if !current {
                return None;
            }
            let route = slot.path.get()?;
            let source = udp_socket::canonical(route.lease.local_addr);
            (route.lease.is_current()
                && source.port() != 0
                && !source.ip().is_unspecified()
                && !source.ip().is_multicast())
            .then_some(source)
        })
    }

    pub(super) fn retained_sources(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        let valid = self.valid.load(Ordering::Acquire);
        self.sockets.iter().filter_map(move |slot| {
            if !valid {
                return None;
            }
            let route = slot.path.get()?;
            #[cfg(target_os = "android")]
            let available = route.lease.is_available();
            #[cfg(target_os = "linux")]
            let available = route.lease.is_current();
            let source = udp_socket::canonical(route.lease.local_addr);
            (available
                && source.port() != 0
                && !source.ip().is_unspecified()
                && !source.ip().is_multicast())
            .then_some(source)
        })
    }
}

#[derive(Debug)]
pub(super) struct Slot {
    pub(super) path: tokio::sync::OnceCell<Route>,
    retry: Mutex<Retry>,
}

#[derive(Debug)]
struct Retry {
    until: Option<Instant>,
    delay: Duration,
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            path: tokio::sync::OnceCell::new(),
            retry: Mutex::new(Retry {
                until: None,
                delay: Duration::from_secs(1),
            }),
        }
    }
}

struct Attempt<'a> {
    slot: &'a Slot,
    succeeded: bool,
}

impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        let mut retry = self
            .slot
            .retry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.succeeded {
            retry.until = None;
            retry.delay = Duration::from_secs(1);
        } else {
            retry.until = Some(Instant::now() + retry.delay);
            retry.delay = (retry.delay * 2).min(Duration::from_secs(30));
        }
    }
}

impl Slot {
    pub(super) async fn prepare(
        &self,
        socket: &udp_socket::Socket,
        owner: &Egress,
        destination: SocketAddr,
        incoming: Option<SocketAddr>,
        #[cfg(target_os = "android")] recovery: Option<&super::udp_retry::Candidate>,
    ) -> io::Result<&Route> {
        #[cfg(target_os = "android")]
        if recovery.is_some_and(|candidate| !candidate.is_current()) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "UDP recovery candidate was retired",
            ));
        }
        let initializing = self.path.get().is_none();
        let prepared = self
            .path
            .get_or_try_init(|| async {
                if self
                    .retry
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .until
                    .is_some_and(|until| until > Instant::now())
                {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "UDP route preparation cooldown",
                    ));
                }
                let mut attempt = Attempt {
                    slot: self,
                    succeeded: false,
                };
                #[cfg(target_os = "android")]
                let route = if let Some(recovery) = recovery {
                    let lease = recovery.prepare(owner).await?;
                    let route = Route::from_lease(socket, owner, lease).await?;
                    if !recovery.is_current() {
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "UDP recovery changed during binding",
                        ));
                    }
                    route
                } else {
                    Route::prepare(socket, owner, destination, incoming).await?
                };
                #[cfg(not(target_os = "android"))]
                let route = Route::prepare(socket, owner, destination, incoming).await?;
                attempt.succeeded = true;
                Ok(route)
            })
            .await;
        if initializing && prepared.is_ok() {
            owner.paths_changed();
        }
        let route = prepared?;
        #[cfg(target_os = "android")]
        if recovery.is_some_and(|candidate| !candidate.is_current()) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "UDP recovery changed after acquisition",
            ));
        }
        route.validate(destination, incoming)?;
        Ok(route)
    }
}

#[derive(Debug)]
pub(super) struct Route {
    pub(super) lease: RouteLease,
    io: Arc<dyn quinn::AsyncUdpSocket>,
}

impl Route {
    fn validate_receive_scope(&self, scope: quinn::UdpRecvScope) -> io::Result<()> {
        #[cfg(target_os = "android")]
        return self.lease.validate_receive_scope(scope);
        #[cfg(target_os = "linux")]
        {
            // Linux leases own TX selection. A valid authenticated reply may
            // follow the peer's different destination-specific incoming route.
            // Do not impose Android Network identity or symmetric routing here.
            let _ = scope;
            Ok(())
        }
    }

    pub(super) fn validate(
        &self,
        destination: SocketAddr,
        incoming: Option<SocketAddr>,
    ) -> io::Result<()> {
        if !same_destination(destination, self.lease.context.destination)
            || incoming.is_some_and(|local| udp_socket::canonical(local) != self.lease.local_addr)
        {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "UDP datagram tuple differs from immutable owner",
            ));
        }
        #[cfg(target_os = "android")]
        if !self.lease.is_available() {
            return Err(io::Error::new(
                io::ErrorKind::NetworkUnreachable,
                "UDP owner Network was withdrawn",
            ));
        }
        Ok(())
    }
    pub(super) async fn prepare(
        socket: &udp_socket::Socket,
        owner: &Egress,
        destination: SocketAddr,
        incoming: Option<SocketAddr>,
    ) -> io::Result<Self> {
        let local = socket.local_addr()?;
        let local = if local.ip().is_unspecified() && destination.is_ipv4() && local.is_ipv6() {
            SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), local.port())
        } else {
            local
        };
        let lease = if let Some(local) = incoming {
            owner
                .prepare_incoming(local, destination, socket.mark)
                .await?
        } else {
            owner
                .prepare_shared_datagram(local, destination, socket.mark)
                .await?
        };
        Self::from_lease(socket, owner, lease).await
    }

    async fn from_lease(
        socket: &udp_socket::Socket,
        _owner: &Egress,
        lease: RouteLease,
    ) -> io::Result<Self> {
        let io = Arc::clone(&socket.io);
        #[cfg(target_os = "android")]
        let route = _owner.prepare_io(move || Self::bind_io(io, lease)).await?;
        #[cfg(not(target_os = "android"))]
        let route = Self::bind_io(io, lease)?;
        if !route.lease.is_current() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "UDP route changed during acquisition",
            ));
        }
        Ok(route)
    }

    fn bind_io(base: Arc<dyn quinn::AsyncUdpSocket>, lease: RouteLease) -> io::Result<Self> {
        if !lease.is_current() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "UDP route changed before binding",
            ));
        }
        let interface = NonZeroU32::new(lease.route.interface_index)
            .ok_or_else(|| io::Error::other("zero UDP route interface"))?;
        #[cfg(target_os = "android")]
        let binding = Some(lease.socket_binding());
        #[cfg(target_os = "linux")]
        let binding = None;
        let io = base
            .transmit_socket_with_binding(lease.local_addr.ip(), interface, binding)?
            .unwrap_or(base);
        if !lease.is_current() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "UDP route changed during acquisition",
            ));
        }
        Ok(Self { lease, io })
    }

    #[cfg(test)]
    pub(super) async fn send(&self, bytes: &[u8]) -> io::Result<usize> {
        self.send_before(bytes, None).await
    }

    pub(super) async fn send_before(
        &self,
        bytes: &[u8],
        deadline: Option<Instant>,
    ) -> io::Result<usize> {
        self.validate(self.lease.context.destination, None)?;
        udp_socket::send_before(
            &self.io,
            bytes,
            self.lease.context.destination,
            Some(self.lease.local_addr.ip()),
            NonZeroU32::new(self.lease.route.interface_index),
            deadline,
        )
        .await
    }
}

pub(super) fn same_destination(requested: SocketAddr, selected: SocketAddr) -> bool {
    let mut requested = udp_socket::canonical(requested);
    let selected = udp_socket::canonical(selected);
    if let (SocketAddr::V6(requested), SocketAddr::V6(selected)) = (&mut requested, selected)
        && requested.ip().is_unicast_link_local()
        && requested.scope_id() == 0
    {
        requested.set_scope_id(selected.scope_id());
    }
    requested == selected
}

pub(super) async fn before_deadline<T>(
    deadline: Option<Instant>,
    operation: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    let Some(deadline) = deadline else {
        return operation.await;
    };
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "UDP owner expired before send",
        ));
    }
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), operation)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP owner expired during send"))?
}

impl PacketPlaneRuntime {
    pub(crate) fn follow_physical_routes(&mut self, owned_interface: String) {
        self.udp_owner = Some(Arc::new(Egress::new(owned_interface)));
    }

    pub(super) async fn send_owned_datagram(
        &self,
        peer: PeerId,
        retiring: bool,
        listener: usize,
        destination: SocketAddr,
        bytes: &[u8],
    ) -> io::Result<usize> {
        let socket = &self.sockets[listener];
        let Some(owner) = &self.udp_owner else {
            return socket.send_to(bytes, destination).await;
        };
        let routes = if retiring {
            self.retiring_sessions
                .get(&peer)
                .and_then(|retiring| retiring.routes.as_ref())
        } else {
            self.udp_routes.get(&peer)
        }
        .ok_or_else(|| io::Error::other("missing authenticated UDP route owner"))?;
        let _ = (socket, owner);
        self.send_route_datagram(routes, listener, destination, bytes, false, None)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn send_route_datagram(
        &self,
        routes: &udp_path::Routes,
        listener: usize,
        destination: SocketAddr,
        bytes: &[u8],
        require_current: bool,
        deadline: Option<Instant>,
    ) -> io::Result<usize> {
        let socket = self
            .sockets
            .get(listener)
            .ok_or_else(|| io::Error::other("missing UDP listener"))?;
        let owner = self
            .udp_owner
            .as_ref()
            .ok_or_else(|| io::Error::other("missing UDP route policy"))?;
        let slot = routes
            .sockets
            .get(listener)
            .ok_or_else(|| io::Error::other("missing UDP route slot"))?;
        let route = before_deadline(
            deadline,
            slot.prepare(
                socket,
                owner,
                destination,
                None,
                #[cfg(target_os = "android")]
                if require_current && listener == 0 {
                    routes.recovery.as_ref()
                } else {
                    None
                },
            ),
        )
        .await?;
        if require_current && !route.lease.is_current() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                format!("UDP candidate route changed: {:?}", route.lease),
            ));
        }
        before_deadline(deadline, route.send_before(bytes, deadline)).await
    }

    pub(crate) async fn remember_incoming_route(&self, scoped: &ScopedUdpFrame) -> io::Result<()> {
        let Some(owner) = &self.udp_owner else {
            return Ok(());
        };
        let received = &scoped.received;
        let peer = received
            .peer
            .ok_or_else(|| io::Error::other("missing authenticated UDP peer"))?;
        let routes = scoped
            .routes
            .as_ref()
            .ok_or_else(|| io::Error::other("missing authenticated incoming UDP owner"))?;
        let session = self
            .udp_scoped_session(peer, scoped.phase, Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::Interrupted, "UDP session expired"))?;
        if !self
            .udp_scoped_routes(peer, scoped.phase)
            .is_some_and(|current| Arc::ptr_eq(current, routes))
        {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "UDP session owner was retired",
            ));
        }
        let slot = routes
            .sockets
            .get(scoped.listener)
            .ok_or_else(|| io::Error::other("missing UDP route slot"))?;
        #[cfg(target_os = "android")]
        if scoped.phase == udp_handoff::Phase::Candidate
            && self.udp_candidate_receive_authorized(peer)
            && routes
                .recovery
                .as_ref()
                .is_some_and(|candidate| !candidate.is_current())
            && slot.path.get().is_none()
        {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "authorized old UDP RX cannot acquire another route",
            ));
        }
        if matches!(scoped.phase, udp_handoff::Phase::Retiring(_)) && slot.path.get().is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "unprepared retired UDP owner",
            ));
        }
        let route = before_deadline(
            self.udp_scoped_deadline(peer, scoped.phase),
            slot.prepare(
                &self.sockets[scoped.listener],
                owner,
                session.endpoint,
                (scoped.phase != udp_handoff::Phase::Candidate).then_some(received.local_addr),
                #[cfg(target_os = "android")]
                if scoped.phase == udp_handoff::Phase::Candidate
                    && scoped.listener == 0
                    && !(self.udp_candidate_receive_authorized(peer) && slot.path.get().is_some())
                {
                    routes.recovery.as_ref()
                } else {
                    None
                },
            ),
        )
        .await?;
        route.validate(received.remote_addr, Some(received.local_addr))?;
        route.validate_receive_scope(scoped.receive_scope)?;
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
