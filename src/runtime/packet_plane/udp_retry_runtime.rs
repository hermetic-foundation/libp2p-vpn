//! Runtime admission stays separate from the Android recovery ledger.

use super::*;
use crate::runtime::lifecycle::activity::{DemandSnapshot, DemandVersion};

#[derive(Clone, Copy, Debug, Default)]
pub(crate) enum UdpRecoveryIntent {
    #[default]
    Maintenance,
    Application(DemandSnapshot),
    // Created only after the peer, signed Hello and capability checks pass.
    AuthenticatedControl(Instant),
}

impl UdpRecoveryIntent {
    pub(crate) fn application(snapshot: Option<DemandSnapshot>) -> Self {
        snapshot.map_or(Self::Maintenance, Self::Application)
    }

    pub(super) fn demand(self, now: Instant) -> Option<DemandVersion> {
        match self {
            Self::Application(snapshot)
                if snapshot.last_demand.is_some_and(|last| {
                    last <= now
                        && now.saturating_duration_since(last)
                            < crate::runtime::lifecycle::IDLE_AFTER
                }) =>
            {
                snapshot.version
            }
            _ => None,
        }
    }

    pub(super) fn control(self, since: Instant, now: Instant) -> bool {
        matches!(self, Self::AuthenticatedControl(received) if received >= since && received <= now
            && now.saturating_duration_since(received) < crate::runtime::lifecycle::IDLE_AFTER)
    }

    pub(super) fn active(self, now: Instant) -> bool {
        self.demand(now).is_some()
            || matches!(self, Self::AuthenticatedControl(received) if received <= now
                && now.saturating_duration_since(received) < crate::runtime::lifecycle::IDLE_AFTER)
    }
}

#[cfg(target_os = "android")]
struct Context {
    owner: Arc<super::super::physical_network::android::egress::Egress>,
    local: SocketAddr,
    mark: u32,
    failed_owner: Option<Arc<()>>,
    preferred_only: bool,
    active: Option<Arc<()>>,
}

impl PacketPlaneRuntime {
    #[cfg(target_os = "android")]
    fn udp_retry_context(
        &self,
        peer: PeerId,
        destination: SocketAddr,
        active_failure: bool,
    ) -> io::Result<Context> {
        let owner = self
            .udp_owner
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
        let socket = self
            .sockets
            .first()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
        let mut local = udp_socket::canonical(socket.local_addr()?);
        if local.ip().is_unspecified() && local.is_ipv6() && destination.is_ipv4() {
            local = SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), local.port());
        }
        let active = self.udp_routes.get(&peer);
        let available = active.is_some_and(|routes| {
            routes
                .sockets
                .first()
                .and_then(|slot| slot.path.get())
                .is_some_and(|path| path.lease.is_available())
        });
        let active_failure = self.has_session(peer) && (active_failure || !available);
        Ok(Context {
            owner: Arc::clone(owner),
            local,
            mark: socket.mark,
            failed_owner: active_failure
                .then(|| active.map(|routes| Arc::clone(&routes.token)))
                .flatten(),
            preferred_only: !active_failure && self.route_refresh_needed(peer),
            active: (!active_failure && available && self.has_session(peer))
                .then(|| active.map(|routes| Arc::clone(&routes.token)))
                .flatten(),
        })
    }

    pub(crate) fn udp_recovery_ready(
        &self,
        peer: PeerId,
        destination: SocketAddr,
        active_failure: bool,
        renewal: bool,
        intent: UdpRecoveryIntent,
    ) -> bool {
        #[cfg(target_os = "android")]
        {
            if self.udp_owner.is_none() {
                return true;
            }
            let Ok(context) = self.udp_retry_context(peer, destination, active_failure) else {
                return false;
            };
            if !context.local.ip().is_unspecified() {
                return true;
            }
            return self
                .udp_retries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .admit(
                    context.owner,
                    peer,
                    context.local,
                    destination,
                    context.mark,
                    context.failed_owner,
                    context.preferred_only,
                    renewal,
                    intent,
                    context.active,
                    Instant::now(),
                )
                .unwrap_or(false);
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = (peer, destination, active_failure, renewal, intent);
            true
        }
    }

    pub(crate) fn udp_recovery_due(
        &self,
        peer: PeerId,
        active_failure: bool,
        intent: UdpRecoveryIntent,
    ) -> bool {
        #[cfg(target_os = "android")]
        {
            let active = self.session_endpoint_for(peer).and_then(|destination| {
                self.udp_retry_context(peer, destination, active_failure)
                    .ok()
            });
            return self
                .udp_retries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .due(
                    peer,
                    active
                        .as_ref()
                        .and_then(|context| context.failed_owner.as_ref()),
                    active.as_ref().and_then(|context| context.active.as_ref()),
                    intent,
                    Instant::now(),
                );
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = (peer, active_failure, intent);
            false
        }
    }

    pub(crate) fn udp_preferred_validation_due(
        &self,
        peer: PeerId,
        intent: UdpRecoveryIntent,
    ) -> bool {
        #[cfg(target_os = "android")]
        {
            let Some(context) = self
                .session_endpoint_for(peer)
                .and_then(|destination| self.udp_retry_context(peer, destination, false).ok())
            else {
                return false;
            };
            return self
                .udp_retries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .preferred_due(peer, context.active.as_ref(), intent, Instant::now());
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = (peer, intent);
            false
        }
    }

    #[cfg(target_os = "android")]
    pub(super) fn attach_udp_recovery(
        &self,
        peer: PeerId,
        destination: SocketAddr,
        active_failure: bool,
        token: Arc<()>,
    ) -> io::Result<Option<super::udp_retry::Candidate>> {
        let context = self.udp_retry_context(peer, destination, active_failure)?;
        if !context.local.ip().is_unspecified() {
            return Ok(None);
        }
        self.udp_retries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .attach(
                context.owner,
                peer,
                context.local,
                destination,
                context.mark,
                context.failed_owner,
                context.preferred_only,
                token,
                Instant::now(),
            )
            .map(Some)
    }

    pub(super) fn clear_udp_recovery(&self) {
        #[cfg(target_os = "android")]
        self.udp_retries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
}
