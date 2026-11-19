//! Per-operation UDP ingress for an authorized browser relay circuit.
//! WebRTC DTLS, libp2p Noise and circuit negotiation remain end to end.

use std::{
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use libp2p::{Multiaddr, multiaddr::Protocol};
use rand_core::{OsRng, RngCore as _};
use socket2::{SockAddr, SockRef};
use tokio::{
    net::UdpSocket,
    sync::{Notify, OwnedSemaphorePermit},
    time::{Instant, sleep_until},
};

use super::{
    physical_network::{
        platform::{
            SocketProtocol,
            egress::{RouteLease, canonical_socket_address},
        },
        public_discovery::Scope,
    },
    runner::public_discovery_transport_is_publicly_dialable,
};

const MAX_DATAGRAM: usize = 2048;
const OPERATION_LIMITS: Limits = Limits {
    idle: Duration::from_secs(30),
    pending: Duration::from_secs(120),
    active: Duration::from_secs(120),
    traffic: Budget {
        bytes: 64 * 1024 * 1024,
        packets: 128 * 1024,
    },
};

#[derive(Clone, Copy)]
struct Limits {
    idle: Duration,
    pending: Duration,
    active: Duration,
    traffic: Budget,
}

#[derive(Clone, Copy)]
struct Budget {
    bytes: usize,
    packets: usize,
}

/// Unguessable bearer held by the same-origin owner of this candidate.
pub(crate) type LeaseId = [u8; 24];

#[derive(Clone)]
pub(crate) struct LeaseControl {
    id: LeaseId,
    candidate: Multiaddr,
    upstream: Multiaddr,
    slot: Weak<OwnedSemaphorePermit>,
    shared: Arc<Lease>,
}

impl LeaseControl {
    pub(crate) fn id(&self) -> LeaseId {
        self.id
    }

    pub(crate) fn scope(&self) -> Scope {
        self.shared.scope.clone()
    }

    pub(crate) fn holds_slot(&self) -> bool {
        self.slot.strong_count() != 0
    }

    /// Call only after same-origin admission, when the trusted app reports
    /// this exact candidate is the live outbound circuit authorized by its
    /// VPN capability exchange. A dial result or UDP activity is not that
    /// report. This only moves the control deadline, never idle or traffic limits.
    pub(crate) fn activate_or_renew(&self, id: LeaseId, selected: &Multiaddr) -> io::Result<()> {
        self.activate_or_renew_with_clock(id, selected, Instant::now)
    }

    fn activate_or_renew_with_clock(
        &self,
        id: LeaseId,
        selected: &Multiaddr,
        clock: impl FnOnce() -> Instant,
    ) -> io::Result<()> {
        self.authorize(id)?;
        if selected != &self.candidate {
            return Err(unauthorized());
        }
        self.shared.with_live(clock, |state, now| {
            if matches!(state.phase, Phase::Handoff(_)) {
                return Err(closed());
            }
            if state.client.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "browser relay egress has not forwarded a client datagram",
                ));
            }
            state.phase = Phase::Active(now + self.shared.limits.active);
            Ok(())
        })?;
        self.shared.changed.notify_one();
        Ok(())
    }

    pub(crate) fn cancel(&self, id: LeaseId) -> io::Result<()> {
        self.authorize(id)?;
        self.shared.lock()?.phase = Phase::Closed;
        self.shared.changed.notify_one();
        Ok(())
    }

    /// Rebind an approved pairing circuit without changing its upstream,
    /// epoch, slot, remaining traffic, or deadlines. The registry must admit
    /// only the trusted same-origin app after it verifies pairing approval.
    pub(crate) async fn handoff(
        &self,
        id: LeaseId,
        selected: &Multiaddr,
    ) -> io::Result<(
        Multiaddr,
        LeaseControl,
        impl Future<Output = io::Result<()>> + Send + use<>,
    )> {
        self.authorize(id)?;
        if selected != &self.candidate {
            return Err(unauthorized());
        }
        let slot = self.slot.upgrade().ok_or_else(closed)?;
        self.shared.with_live(Instant::now, |state, _| {
            let Phase::Pending(deadline) = state.phase else {
                return Err(closed());
            };
            if state.client.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "pairing relay has no client",
                ));
            }
            state.phase = Phase::Handoff(deadline);
            Ok(())
        })?;
        // Consuming a handoff is terminal for the old pump even if binding or
        // publication fails. Keep its socket bound until the fresh port exists.
        let _close = CloseOnDrop(self);
        let (candidate, pump) =
            prepare_with_limits(self.scope(), &self.upstream, self.shared.limits, Some(slot))
                .await?;
        let control = pump.control(&candidate, &self.upstream)?;
        if control.id() == id {
            return Err(io::Error::other("relay lease ID collision"));
        }
        self.shared.with_live(Instant::now, |old, _| {
            let Phase::Handoff(deadline) = old.phase else {
                return Err(closed());
            };
            let mut fresh = pump.shared.lock()?;
            fresh.phase = Phase::Pending(deadline);
            fresh.idle_at = old.idle_at;
            fresh.remaining = old.remaining;
            old.phase = Phase::Closed;
            Ok(())
        })?;
        Ok((candidate, control, pump.run()))
    }

    fn authorize(&self, id: LeaseId) -> io::Result<()> {
        if self.id != id {
            return Err(unauthorized());
        }
        Ok(())
    }
}

struct CloseOnDrop<'a>(&'a LeaseControl);

impl Drop for CloseOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.cancel(self.0.id());
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "browser relay egress closed")
}

fn unauthorized() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "browser relay lease authorization failed",
    )
}

fn new_lease_id() -> io::Result<LeaseId> {
    let mut bytes = [0; 24];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(bytes)
}

/// Drive the returned pump for the whole lease. It owns the slot and the
/// route-bound sockets even after activation. Drop it on shutdown. The host
/// must authorize the nominated public route and keep the returned candidate
/// private to this operation: the first successfully forwarded loopback source
/// pins the tuple, but loopback is not authentication of a local process.
pub(crate) async fn prepare_owned(
    scope: Scope,
    authorized_route: &Multiaddr,
    slot: OwnedSemaphorePermit,
) -> io::Result<(
    Multiaddr,
    LeaseControl,
    impl Future<Output = io::Result<()>> + Send + use<>,
)> {
    let (candidate, pump) = prepare_with_limits(
        scope,
        authorized_route,
        OPERATION_LIMITS,
        Some(Arc::new(slot)),
    )
    .await?;
    let control = pump.control(&candidate, authorized_route)?;
    Ok((candidate, control, pump.run()))
}

/// Drive the same bounded pump for a locally owned incoming reservation,
/// authorized by an exact configured WebRTC entrance. No circuit target is
/// supplied: the browser authenticates its own identity to the relay.
pub(crate) async fn prepare_reservation(
    scope: Scope,
    authorized_entrance: &Multiaddr,
    slot: OwnedSemaphorePermit,
) -> io::Result<(
    Multiaddr,
    LeaseControl,
    impl Future<Output = io::Result<()>> + Send + use<>,
)> {
    let upstream = pinned_relay_route(authorized_entrance, EntranceKind::Reservation)?;
    let (candidate, pump) =
        prepare_upstream(scope, upstream, OPERATION_LIMITS, Some(Arc::new(slot))).await?;
    let control = pump.control(&candidate, authorized_entrance)?;
    Ok((candidate, control, pump.run()))
}

async fn prepare_with_limits(
    scope: Scope,
    authorized_route: &Multiaddr,
    limits: Limits,
    slot: Option<Arc<OwnedSemaphorePermit>>,
) -> io::Result<(Multiaddr, Pump)> {
    prepare_upstream(scope, pinned_relay(authorized_route)?, limits, slot).await
}

async fn prepare_upstream(
    scope: Scope,
    (destination, suffix): (SocketAddr, Multiaddr),
    limits: Limits,
    slot: Option<Arc<OwnedSemaphorePermit>>,
) -> io::Result<(Multiaddr, Pump)> {
    let (socket, route) = scope
        .prepare_socket(destination, SocketProtocol::Udp)
        .await?;
    scope.with_current(|| socket.connect(&SockAddr::from(destination)))?;
    let uplink = UdpSocket::from_std(socket.into())?;
    let local = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = local.local_addr()?.port();
    // Preserve the checked certificate, relay identity and circuit destination.
    let mut candidate = Multiaddr::empty()
        .with(Protocol::Ip4(Ipv4Addr::LOCALHOST))
        .with(Protocol::Udp(port));
    for protocol in &suffix {
        candidate.push(protocol);
    }
    let shared = Arc::new(Lease::new(scope, Instant::now(), limits));
    shared.scope.check()?;
    let pump = Pump {
        shared,
        local,
        uplink,
        _route: route,
        slot,
    };
    Ok((candidate, pump))
}

fn pinned_relay(route: &Multiaddr) -> io::Result<(SocketAddr, Multiaddr)> {
    pinned_relay_route(route, EntranceKind::Circuit)
}

enum EntranceKind {
    Circuit,
    Reservation,
}

fn pinned_relay_route(
    route: &Multiaddr,
    kind: EntranceKind,
) -> io::Result<(SocketAddr, Multiaddr)> {
    fn invalid() -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected an exact public numeric pinned WebRTC Direct relay route",
        )
    }

    let mut parts = route.iter();
    let ip = match parts.next() {
        Some(Protocol::Ip4(ip)) => ip.into(),
        Some(Protocol::Ip6(ip)) => ip.into(),
        _ => return Err(invalid()),
    };
    let (
        Some(Protocol::Udp(port)),
        Some(Protocol::WebRTCDirect),
        Some(Protocol::Certhash(cert)),
        Some(Protocol::P2p(relay)),
    ) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid());
    };
    if port == 0
        || !public_discovery_transport_is_publicly_dialable(route)
        || cert.code() != 0x12
        || cert.size() != 32
    {
        return Err(invalid());
    }
    let destination = canonical_socket_address(SocketAddr::new(ip, port));
    let mut suffix = Multiaddr::empty()
        .with(Protocol::WebRTCDirect)
        .with(Protocol::Certhash(cert))
        .with(Protocol::P2p(relay));
    match (kind, parts.next(), parts.next(), parts.next()) {
        (EntranceKind::Circuit, Some(Protocol::P2pCircuit), Some(Protocol::P2p(peer)), None)
            if relay != peer =>
        {
            suffix.push(Protocol::P2pCircuit);
            suffix.push(Protocol::P2p(peer));
        }
        (EntranceKind::Reservation, None, None, None) => {}
        _ => return Err(invalid()),
    }
    Ok((destination, suffix))
}

enum Phase {
    Pending(Instant),
    Handoff(Instant),
    Active(Instant),
    Closed,
}

struct LeaseState {
    phase: Phase,
    idle_at: Instant,
    remaining: Budget,
    client: Option<SocketAddr>,
}

impl LeaseState {
    fn deadline(&self, now: Instant) -> io::Result<Instant> {
        let authority_at = match self.phase {
            Phase::Pending(end) | Phase::Handoff(end) | Phase::Active(end) => end,
            Phase::Closed => return Err(closed()),
        };
        if now >= self.idle_at.min(authority_at) {
            let reason = if self.idle_at < authority_at {
                "browser relay egress idle timeout"
            } else {
                match self.phase {
                    Phase::Pending(_) | Phase::Handoff(_) => {
                        "browser relay egress pending lifetime expired"
                    }
                    _ => "browser relay egress authenticated renewal expired",
                }
            };
            return Err(io::Error::new(io::ErrorKind::TimedOut, reason));
        }
        self.remaining.check(1)?;
        Ok(self.idle_at.min(authority_at))
    }

    fn forwarded(&mut self, bytes: usize, source: Option<SocketAddr>, idle_at: Instant) {
        if let Some(source) = source {
            self.client = Some(source);
        }
        self.remaining.bytes -= bytes;
        self.remaining.packets -= 1;
        self.idle_at = idle_at;
    }
}

impl Budget {
    fn check(self, len: usize) -> io::Result<()> {
        if self.packets == 0 || self.bytes < len {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "browser relay egress traffic budget exhausted",
            ));
        }
        Ok(())
    }
}

struct Lease {
    scope: Scope,
    limits: Limits,
    state: Mutex<LeaseState>,
    changed: Notify,
}

impl Lease {
    fn new(scope: Scope, started: Instant, limits: Limits) -> Self {
        Self {
            scope,
            limits,
            state: Mutex::new(LeaseState {
                phase: Phase::Pending(started + limits.pending),
                idle_at: started + limits.idle,
                remaining: limits.traffic,
                client: None,
            }),
            changed: Notify::new(),
        }
    }

    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, LeaseState>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("browser relay egress lease lock poisoned"))
    }

    fn with_live<T>(
        &self,
        clock: impl FnOnce() -> Instant,
        action: impl FnOnce(&mut LeaseState, Instant) -> io::Result<T>,
    ) -> io::Result<T> {
        self.scope.with_current(|| {
            let mut state = self.lock()?;
            let now = clock();
            state.deadline(now)?;
            action(&mut state, now)
        })
    }
}

enum Datagram {
    Local(usize, SocketAddr),
    Relay(usize),
}

struct Pump {
    shared: Arc<Lease>,
    local: UdpSocket,
    uplink: UdpSocket,
    _route: RouteLease,
    slot: Option<Arc<OwnedSemaphorePermit>>,
}

impl Drop for Pump {
    fn drop(&mut self) {
        if let Ok(mut state) = self.shared.lock() {
            state.phase = Phase::Closed;
        }
    }
}

impl Pump {
    fn control(&self, candidate: &Multiaddr, upstream: &Multiaddr) -> io::Result<LeaseControl> {
        Ok(LeaseControl {
            id: new_lease_id()?,
            candidate: candidate.clone(),
            upstream: upstream.clone(),
            slot: self.slot.as_ref().map_or_else(Weak::new, Arc::downgrade),
            shared: Arc::clone(&self.shared),
        })
    }

    async fn run(self) -> io::Result<()> {
        let shared = &self.shared;
        let timer = sleep_until(Instant::now());
        tokio::pin!(timer);
        // An extra byte detects truncation so an oversized input is never relayed.
        let mut local_buf = [0; MAX_DATAGRAM + 1];
        let mut relay_buf = [0; MAX_DATAGRAM + 1];

        loop {
            let deadline = shared
                .scope
                .with_current(|| shared.lock()?.deadline(Instant::now()))?;
            timer.as_mut().reset(deadline);
            let packet = tokio::select! {
                biased;
                () = shared.scope.invalidated() => {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "browser relay egress route changed"));
                }
                () = shared.changed.notified() => continue,
                () = &mut timer => continue,
                packet = async {
                    tokio::select! {
                        result = self.local.recv_from(&mut local_buf) => result.map(|(len, source)| Datagram::Local(len, source)),
                        result = self.uplink.recv(&mut relay_buf) => result.map(Datagram::Relay),
                    }
                } => packet?,
            };

            shared.with_live(Instant::now, |state, now| {
                let (socket, bytes, source, target) = match packet {
                    Datagram::Local(len, source)
                        if (1..=MAX_DATAGRAM).contains(&len)
                            && source.ip().is_loopback()
                            && state.client.is_none_or(|owned| owned == source) =>
                    {
                        (&self.uplink, &local_buf[..len], Some(source), None)
                    }
                    Datagram::Relay(len) if (1..=MAX_DATAGRAM).contains(&len) => {
                        let Some(target) = state.client else {
                            return Ok(());
                        };
                        (&self.local, &relay_buf[..len], None, Some(target))
                    }
                    _ => return Ok(()),
                };
                state.remaining.check(bytes.len())?;
                let sock = SockRef::from(socket);
                let sent = match target {
                    Some(target) => sock.send_to(bytes, &SockAddr::from(target)),
                    None => sock.send(bytes),
                };
                if sent_datagram(sent, bytes.len())? {
                    state.forwarded(bytes.len(), source, now + shared.limits.idle);
                }
                Ok(())
            })?;
        }
    }
}

fn sent_datagram(result: io::Result<usize>, expected: usize) -> io::Result<bool> {
    match result {
        Ok(sent) if sent == expected => Ok(true),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "partial browser relay datagram",
        )),
        // UDP is lossy; do not add an application queue or wait with the route
        // generation held. Only a successful datagram renews the idle deadline.
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
#[path = "browser_relay_egress/tests.rs"]
mod tests;
