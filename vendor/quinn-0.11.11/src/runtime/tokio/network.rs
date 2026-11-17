//! Immutable platform Network-bound companions, separate from Linux strict routes.

use super::*;
use crate::UdpSocketBinding;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr, SocketAddrV6},
    num::NonZeroU32,
    sync::{Mutex, Weak},
    task::Waker,
};

const MAX_NETWORKS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Key {
    identity: [u64; 3],
    platform_routing: bool,
    ipv6_scope_id: Option<NonZeroU32>,
    source: IpAddr,
    interface: NonZeroU32,
}

#[derive(Debug)]
pub(super) struct Selection {
    key: Key,
    binding: Arc<dyn UdpSocketBinding>,
    scope: u32,
}

impl Selection {
    pub(super) fn identity(&self) -> [u64; 3] {
        self.key.identity
    }

    pub(super) fn send(
        &self,
        socket: &UdpSocket,
        transmit: &udp::Transmit<'_>,
        interface: Option<NonZeroU32>,
    ) -> io::Result<()> {
        self.validate(transmit, interface)?;
        // Endpoint dual-stack normalization must not pass a mapped destination to a v4 FD.
        let destination = match transmit.destination.ip().to_canonical() {
            IpAddr::V4(ip) => SocketAddr::new(ip.into(), transmit.destination.port()),
            IpAddr::V6(_) => transmit.destination,
        };
        let transmit = udp::Transmit {
            destination,
            // The platform-bound FD already has a concrete source. Avoid packet
            // info entirely so the Network can choose its own virtual interface.
            src_ip: (!self.key.platform_routing).then_some(self.key.source),
            ..*transmit
        };
        let send = || {
            if self.key.platform_routing {
                socket.inner.send((&socket.io).into(), &transmit)
            } else {
                socket
                    .inner
                    .send_on_interface((&socket.io).into(), &transmit, self.key.interface)
            }
        };
        let result = socket.io.try_io(Interest::WRITABLE, send);
        if result
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
        {
            // Fresh companions may not yet have their first Mio readiness event.
            return send();
        }
        result
    }

    fn validate(
        &self,
        transmit: &udp::Transmit<'_>,
        interface: Option<NonZeroU32>,
    ) -> io::Result<()> {
        if self.binding.identity() != self.key.identity
            || self.binding.uses_platform_routing() != self.key.platform_routing
            || self.binding.ipv6_scope_id() != self.key.ipv6_scope_id
        {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Network binding identity, routing mode, or IPv6 scope changed",
            ));
        }
        if interface.is_some_and(|index| index != self.key.interface)
            || transmit.src_ip.map(|ip| ip.to_canonical()) != Some(self.key.source)
            || transmit.destination.ip().to_canonical().is_ipv4() != self.key.source.is_ipv4()
            || matches!(transmit.destination, SocketAddr::V6(address)
                if address.ip().is_unicast_link_local()
                    && address.scope_id() != 0
                    && self.scope != 0
                    && address.scope_id() != self.scope)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transmit does not match immutable Network socket",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub(super) struct Networks(Mutex<State>);

#[derive(Debug, Default)]
struct State {
    sockets: BTreeMap<Key, Weak<UdpSocket>>,
    pending: BTreeSet<Key>,
    cursor: usize,
    receiver: Option<Waker>,
}

// This guard belongs to the synchronous backend operation, not its async waiter.
// A timeout must not free capacity while an offloaded bind is still running.
struct Reservation<'a> {
    networks: &'a Networks,
    key: Key,
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.networks
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .remove(&self.key);
    }
}

impl State {
    fn prune(&mut self) {
        self.sockets.retain(|_, socket| socket.strong_count() != 0);
    }
}

impl Networks {
    pub(super) fn acquire(
        &self,
        base: &UdpSocket,
        source: IpAddr,
        interface: NonZeroU32,
        binding: Arc<dyn UdpSocketBinding>,
    ) -> io::Result<Option<Arc<dyn AsyncUdpSocket>>> {
        let source = source.to_canonical();
        let key = Key {
            identity: binding.identity(),
            platform_routing: binding.uses_platform_routing(),
            ipv6_scope_id: binding.ipv6_scope_id(),
            source,
            interface,
        };
        if source.is_unspecified()
            || source.is_multicast()
            || matches!(source, IpAddr::V4(ip) if ip.is_broadcast())
            || interface.get() > i32::MAX as u32
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Network route",
            ));
        }
        if let Some(selected) = &base.network_selection {
            return if selected.key == key
                && selected.binding.identity() == key.identity
                && selected.binding.uses_platform_routing() == key.platform_routing
                && selected.binding.ipv6_scope_id() == key.ipv6_scope_id
            {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "cannot retarget an immutable Network socket",
                ))
            };
        }
        #[cfg(target_os = "linux")]
        if base.selected.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot retarget a strict IPv6 companion to a Network",
            ));
        }
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.prune();
        if state
            .sockets
            .keys()
            .chain(state.pending.iter())
            .any(|existing| {
                existing.identity == key.identity
                    && (existing.platform_routing != key.platform_routing
                        || (existing.source == key.source
                            && existing.ipv6_scope_id != key.ipv6_scope_id))
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot change a live Network route's routing mode or IPv6 scope",
            ));
        }
        if let Some(socket) = state.sockets.get(&key).and_then(Weak::upgrade) {
            drop(state);
            let selected = socket.network_selection.as_ref().unwrap();
            if selected.binding.identity() != key.identity
                || selected.binding.uses_platform_routing() != key.platform_routing
                || selected.binding.ipv6_scope_id() != key.ipv6_scope_id
            {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "Network binding identity, routing mode, or IPv6 scope changed",
                ));
            }
            return Ok(Some(socket));
        }
        if state.pending.contains(&key) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Network socket acquisition pending",
            ));
        }
        if state.sockets.len() + state.pending.len() >= MAX_NETWORKS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Network socket limit",
            ));
        }
        state.pending.insert(key);
        let reservation = Reservation {
            networks: self,
            key,
        };
        drop(state);
        let socket = Arc::new(derive(
            base,
            Selection {
                key,
                binding,
                scope: 0,
            },
        )?);
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.sockets.insert(key, Arc::downgrade(&socket));
        state.pending.remove(&key);
        let receiver = state.receiver.take();
        drop(state);
        drop(reservation);
        if let Some(receiver) = receiver {
            receiver.wake();
        }
        Ok(Some(socket))
    }

    pub(super) fn poll_recv(
        &self,
        base: &UdpSocket,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.poll_recv_scoped(base, cx, bufs, meta, None)
    }

    pub(super) fn poll_recv_scoped(
        &self,
        base: &UdpSocket,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
        mut scopes: Option<&mut [UdpRecvScope]>,
    ) -> Poll<io::Result<usize>> {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Even the empty path registers under the insertion lock to avoid lost wakeups.
        state.receiver = Some(cx.waker().clone());
        state.prune();
        if state.sockets.is_empty() {
            drop(state);
            if scopes.is_none() {
                return base.poll_recv_core(cx, bufs, meta);
            }
            return base.poll_recv_core_scoped(cx, bufs, meta, scopes);
        }
        let mut sockets: [Option<Arc<UdpSocket>>; MAX_NETWORKS] = std::array::from_fn(|_| None);
        let mut count = 0;
        for socket in state.sockets.values().filter_map(Weak::upgrade) {
            sockets[count] = Some(socket);
            count += 1;
        }
        let start = state.cursor % (count + 1);
        drop(state);
        for offset in 0..=count {
            let index = (start + offset) % (count + 1);
            let result = if index == 0 {
                base.poll_recv_core_scoped(cx, bufs, meta, scopes.as_deref_mut())
            } else {
                sockets[index - 1]
                    .as_ref()
                    .unwrap()
                    .poll_recv_single_scoped(cx, bufs, meta, scopes.as_deref_mut())
            };
            if let Poll::Ready(result) = result {
                self.0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .cursor = (index + 1) % (count + 1);
                return Poll::Ready(result);
            }
        }
        Poll::Pending
    }
}

fn derive(base: &UdpSocket, mut selection: Selection) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, SockRef, Socket, Type};

    let local = base.io.local_addr()?;
    let key = selection.key;
    if local.is_ipv6() && key.source.is_ipv4() && SockRef::from(&base.io).only_v6()? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Network source conflicts with endpoint bind",
        ));
    }
    let (local, scope) = bind_address(local, key)?;
    selection.scope = scope;
    let socket = Socket::new(Domain::for_address(local), Type::DGRAM, Some(Protocol::UDP))?;
    if local.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.set_reuse_port(true)?;
    let socket: std::net::UdpSocket = socket.into();
    // The safe parent callback owns NDK Network acquisition and currentness checks.
    // Do not copy marks: Android's Network binder must preserve per-UID isolation.
    selection.binding.bind(&socket)?;
    if selection.binding.identity() != key.identity
        || selection.binding.uses_platform_routing() != key.platform_routing
        || selection.binding.ipv6_scope_id() != key.ipv6_scope_id
    {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "Network binding identity, routing mode, or IPv6 scope changed during acquisition",
        ));
    }
    SockRef::from(&base.io).set_reuse_port(true)?;
    SockRef::from(&socket).bind(&local.into())?;
    Ok(UdpSocket {
        inner: udp::UdpSocketState::new((&socket).into())?,
        io: tokio::net::UdpSocket::from_std(socket)?,
        #[cfg(target_os = "linux")]
        routes: super::strict::Routes::default(),
        #[cfg(target_os = "linux")]
        selected: None,
        networks: Networks::default(),
        network_selection: Some(selection),
    })
}

fn bind_address(local: SocketAddr, key: Key) -> io::Result<(SocketAddr, u32)> {
    if (local.is_ipv4() && key.source.is_ipv6())
        || (!local.ip().is_unspecified() && local.ip().to_canonical() != key.source)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Network source conflicts with endpoint bind",
        ));
    }
    let scope = crate::runtime::udp_source_scope(
        local,
        key.interface,
        key.platform_routing,
        key.ipv6_scope_id,
    )?;
    let address = match key.source {
        IpAddr::V4(ip) => SocketAddr::new(ip.into(), local.port()),
        IpAddr::V6(ip) => {
            let scope = if ip.is_unicast_link_local() {
                scope
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "link-local Network source requires an explicit IPv6 scope",
                        )
                    })?
                    .get()
            } else {
                0
            };
            SocketAddr::V6(SocketAddrV6::new(ip, local.port(), 0, scope))
        }
    };
    Ok((address, scope.map_or(0, NonZeroU32::get)))
}

#[cfg(test)]
mod tests;
