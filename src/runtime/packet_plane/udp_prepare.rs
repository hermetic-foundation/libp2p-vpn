//! Prepare immutable UDP I/O before signing a transcript, without sending data.

use super::*;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod platform {
    use super::*;
    use crate::runtime::physical_network::platform::egress::{Egress, RouteEpoch};
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug)]
    struct Owner {
        routes: Arc<udp_path::Routes>,
        epoch: RouteEpoch,
        adopted: AtomicBool,
    }

    impl Owner {
        fn current(&self) -> bool {
            self.routes.valid.load(Ordering::Acquire) && self.epoch.is_current() && {
                #[cfg(target_os = "android")]
                {
                    self.routes
                        .recovery
                        .as_ref()
                        .is_none_or(|candidate| candidate.is_current())
                }
                #[cfg(target_os = "linux")]
                {
                    true
                }
            }
        }
    }

    impl Drop for Owner {
        fn drop(&mut self) {
            #[cfg(target_os = "android")]
            if !self.adopted.load(Ordering::Acquire)
                && let Some(candidate) = &self.routes.recovery
            {
                candidate.failed(io::ErrorKind::Interrupted, Instant::now());
            }
        }
    }

    #[derive(Clone, Debug)]
    pub(crate) struct UdpPreparation {
        peer: PeerId,
        destination: SocketAddr,
        socket: Arc<udp_socket::Socket>,
        egress: Arc<Egress>,
        owner: Arc<Owner>,
    }

    impl UdpPreparation {
        pub(crate) fn is_current(&self) -> bool {
            self.owner.current()
        }

        pub(crate) fn destination(&self) -> SocketAddr {
            self.destination
        }

        pub(crate) fn cancel(&self) {
            self.failed(io::ErrorKind::Interrupted, Instant::now());
        }

        pub(crate) fn failed(&self, kind: io::ErrorKind, now: Instant) {
            self.owner.routes.valid.store(false, Ordering::Release);
            #[cfg(target_os = "android")]
            if let Some(candidate) = &self.owner.routes.recovery {
                candidate.failed(kind, now);
            }
            #[cfg(target_os = "linux")]
            let _ = (kind, now);
        }

        pub(crate) async fn prepare(self) -> io::Result<PreparedUdpRoute> {
            if !self.is_current() {
                return Err(stale());
            }
            let slot = self.owner.routes.sockets.first().ok_or_else(stale)?;
            let route = slot
                .prepare(
                    &self.socket,
                    &self.egress,
                    self.destination,
                    None,
                    #[cfg(target_os = "android")]
                    self.owner.routes.recovery.as_ref(),
                )
                .await?;
            if !self.is_current() || !route.lease.is_current() {
                return Err(stale());
            }
            Ok(PreparedUdpRoute { preparation: self })
        }
    }

    #[derive(Clone, Debug)]
    pub(crate) struct PreparedUdpRoute {
        preparation: UdpPreparation,
    }

    impl PreparedUdpRoute {
        pub(crate) fn is_current(&self) -> bool {
            self.preparation.is_current()
                && self.preparation.owner.routes.sockets[0]
                    .path
                    .get()
                    .is_some_and(|route| route.lease.is_current())
        }

        pub(crate) fn source(&self) -> SocketAddr {
            self.preparation.owner.routes.sockets[0]
                .path
                .get()
                .expect("prepared route")
                .lease
                .local_addr
        }

        pub(crate) fn matches_source(&self, endpoint: SocketAddr) -> bool {
            udp_path::same_destination(endpoint, self.source())
        }

        /// Configured mappings are explicit assertions, not automatically learned NAT proof.
        /// The session still requires its matching authenticated path ACK before promotion.
        pub(crate) fn bind_endpoint(
            &self,
            endpoint: SocketAddr,
            configured: &[SocketAddr],
        ) -> io::Result<PreparedUdpBinding> {
            let claimed = endpoint;
            let endpoint = udp_socket::canonical(endpoint);
            if !self.is_current() {
                return Err(stale());
            }
            if !self.matches_source(endpoint)
                && !configured
                    .iter()
                    .any(|candidate| udp_socket::canonical(*candidate) == endpoint)
            {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "UDP endpoint has no selected-source or configured-mapping provenance",
                ));
            }
            if endpoint.is_ipv4() != self.source().is_ipv4()
                || endpoint.port() == 0
                || endpoint.ip().is_unspecified()
                || endpoint.ip().is_multicast()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP advertised endpoint is incompatible with its selected source",
                ));
            }
            Ok(PreparedUdpBinding {
                route: self.clone(),
                endpoint: claimed,
            })
        }
    }

    #[derive(Clone, Debug)]
    pub(crate) struct PreparedUdpBinding {
        route: PreparedUdpRoute,
        endpoint: SocketAddr,
    }

    impl PreparedUdpBinding {
        pub(crate) fn is_current(&self) -> bool {
            self.route.is_current()
        }
        pub(crate) fn endpoint(&self) -> SocketAddr {
            self.endpoint
        }
        /// The actual socket source, not an advertised configured mapping.
        pub(crate) fn source(&self) -> SocketAddr {
            self.route.source()
        }
        pub(crate) fn destination(&self) -> SocketAddr {
            self.route.preparation.destination
        }

        pub(crate) fn failed(&self, kind: io::ErrorKind, now: Instant) {
            self.route.preparation.failed(kind, now);
        }

        pub(crate) fn into_preparation(self, destination: SocketAddr) -> Option<UdpPreparation> {
            if !self.is_current()
                || self.route.preparation.owner.adopted.load(Ordering::Acquire)
                || udp_socket::canonical(destination) != udp_socket::canonical(self.destination())
            {
                return None;
            }
            Some(self.route.preparation)
        }

        pub(in crate::runtime::packet_plane) fn adopt(
            self,
            runtime: &PacketPlaneRuntime,
            peer: PeerId,
            local: SocketAddr,
            remote: SocketAddr,
        ) -> io::Result<Arc<udp_path::Routes>> {
            if !runtime
                .sockets
                .first()
                .is_some_and(|socket| Arc::ptr_eq(socket, &self.route.preparation.socket))
                || !runtime
                    .udp_owner
                    .as_ref()
                    .is_some_and(|owner| Arc::ptr_eq(owner, &self.route.preparation.egress))
                || !self.is_current()
                || self.route.preparation.peer != peer
                || udp_socket::canonical(local) != udp_socket::canonical(self.endpoint)
                || udp_socket::canonical(remote)
                    != udp_socket::canonical(self.route.preparation.destination)
            {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "UDP signed transcript differs from prepared peer/source/destination owner",
                ));
            }
            self.route
                .preparation
                .owner
                .adopted
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "UDP prepared owner was already installed",
                    )
                })?;
            Ok(Arc::clone(&self.route.preparation.owner.routes))
        }
    }

    impl PacketPlaneRuntime {
        pub(crate) fn udp_source_endpoints(&self) -> Vec<SocketAddr> {
            if self.udp_owner.is_none() {
                return Vec::new();
            }
            let now = Instant::now();
            let mut endpoints = self
                .udp_routes
                .iter()
                .filter_map(|(peer, routes)| {
                    let session = self.sessions.get(peer)?;
                    let lifetime = (*self.session_lifetimes.get(peer)?).min(self.session_ttl);
                    (now.saturating_duration_since(session.established_at) < lifetime)
                        .then_some(routes.as_ref())
                })
                .flat_map(udp_path::Routes::current_sources)
                .chain(self.udp_handoffs.source_endpoints(now))
                .collect::<Vec<_>>();
            endpoints.sort_unstable();
            endpoints.dedup();
            endpoints
        }

        /// Retention evidence for existing aliases only, never fresh source admission.
        pub(crate) fn udp_retained_source_endpoints(&self) -> Vec<SocketAddr> {
            if self.udp_owner.is_none() {
                return Vec::new();
            }
            let now = Instant::now();
            let mut endpoints = self
                .udp_routes
                .iter()
                .filter_map(|(peer, routes)| {
                    let session = self.sessions.get(peer)?;
                    let lifetime = (*self.session_lifetimes.get(peer)?).min(self.session_ttl);
                    (now.saturating_duration_since(session.established_at) < lifetime)
                        .then_some(routes.as_ref())
                })
                .flat_map(udp_path::Routes::retained_sources)
                .collect::<Vec<_>>();
            endpoints.sort_unstable();
            endpoints.dedup();
            endpoints
        }

        pub(crate) fn udp_preparation_required(&self) -> bool {
            let enabled = cfg!(target_os = "android");
            #[cfg(all(test, target_os = "linux"))]
            let enabled = enabled || self.test_udp_preparation;
            enabled && self.udp_owner.is_some()
        }

        #[cfg(all(test, target_os = "linux"))]
        pub(crate) fn enable_udp_preparation_for_test(&mut self) {
            self.test_udp_preparation = true;
        }

        pub(crate) fn udp_preparation(
            &self,
            peer: PeerId,
            destination: SocketAddr,
            _active_failure: bool,
        ) -> io::Result<UdpPreparation> {
            let egress = self.udp_owner.as_ref().ok_or_else(stale)?.clone();
            let socket = self.sockets.first().ok_or_else(stale)?.clone();
            let epoch = egress.current_epoch()?;
            #[allow(unused_mut)]
            let mut routes = udp_path::Routes::new(self.sockets.len());
            #[cfg(target_os = "android")]
            {
                let recovery = self.attach_udp_recovery(
                    peer,
                    destination,
                    _active_failure,
                    Arc::clone(&routes.token),
                )?;
                Arc::get_mut(&mut routes)
                    .expect("fresh preparation routes")
                    .recovery = recovery;
            }
            if !epoch.is_current() {
                return Err(stale());
            }
            Ok(UdpPreparation {
                peer,
                destination,
                socket,
                egress,
                owner: Arc::new(Owner {
                    routes,
                    epoch,
                    adopted: AtomicBool::new(false),
                }),
            })
        }
    }

    fn stale() -> io::Error {
        io::Error::new(io::ErrorKind::Interrupted, "UDP preparation owner changed")
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use platform::{PreparedUdpBinding, PreparedUdpRoute, UdpPreparation};

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod unsupported {
    use super::*;
    #[derive(Clone, Debug)]
    pub(crate) enum UdpPreparation {}
    #[derive(Clone, Debug)]
    pub(crate) enum PreparedUdpRoute {}
    #[derive(Clone, Debug)]
    pub(crate) enum PreparedUdpBinding {}
    impl UdpPreparation {
        pub(crate) fn is_current(&self) -> bool {
            match *self {}
        }
        pub(crate) fn destination(&self) -> SocketAddr {
            match *self {}
        }
        pub(crate) fn cancel(&self) {
            match *self {}
        }
        pub(crate) fn failed(&self, _: io::ErrorKind, _: Instant) {
            match *self {}
        }
        pub(crate) async fn prepare(self) -> io::Result<PreparedUdpRoute> {
            match self {}
        }
    }
    impl PreparedUdpRoute {
        pub(crate) fn is_current(&self) -> bool {
            match *self {}
        }
        pub(crate) fn source(&self) -> SocketAddr {
            match *self {}
        }
        pub(crate) fn matches_source(&self, _: SocketAddr) -> bool {
            match *self {}
        }
        pub(crate) fn bind_endpoint(
            &self,
            _: SocketAddr,
            _: &[SocketAddr],
        ) -> io::Result<PreparedUdpBinding> {
            match *self {}
        }
    }
    impl PreparedUdpBinding {
        pub(crate) fn is_current(&self) -> bool {
            match *self {}
        }
        pub(crate) fn endpoint(&self) -> SocketAddr {
            match *self {}
        }
        pub(crate) fn source(&self) -> SocketAddr {
            match *self {}
        }
        pub(crate) fn destination(&self) -> SocketAddr {
            match *self {}
        }
        pub(crate) fn failed(&self, _: io::ErrorKind, _: Instant) {
            match *self {}
        }
        pub(crate) fn into_preparation(self, _: SocketAddr) -> Option<UdpPreparation> {
            match self {}
        }
    }
    impl PacketPlaneRuntime {
        pub(crate) fn udp_source_endpoints(&self) -> Vec<SocketAddr> {
            Vec::new()
        }

        pub(crate) fn udp_retained_source_endpoints(&self) -> Vec<SocketAddr> {
            Vec::new()
        }

        pub(crate) fn udp_preparation_required(&self) -> bool {
            false
        }
        pub(crate) fn udp_preparation(
            &self,
            _: PeerId,
            _: SocketAddr,
            _: bool,
        ) -> io::Result<UdpPreparation> {
            Err(io::ErrorKind::Unsupported.into())
        }
    }
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) use unsupported::{PreparedUdpBinding, PreparedUdpRoute, UdpPreparation};

#[cfg(all(test, target_os = "linux"))]
#[path = "udp_prepare/tests.rs"]
mod tests;
