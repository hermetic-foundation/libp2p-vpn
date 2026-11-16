//! Source/device-bound transmit sockets feeding the original endpoint's receiver.

use super::*;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    num::NonZeroU32,
    sync::{Mutex, Weak},
    task::Waker,
};

const MAX_ROUTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Route {
    pub(super) source: Ipv6Addr,
    pub(super) interface: NonZeroU32,
}

impl Route {
    pub(super) fn validate(
        self,
        transmit: &udp::Transmit<'_>,
        interface: Option<NonZeroU32>,
    ) -> io::Result<()> {
        if interface.is_some_and(|index| index != self.interface)
            || transmit.src_ip != Some(IpAddr::V6(self.source))
            || !transmit.destination.ip().to_canonical().is_ipv6()
            || matches!(transmit.destination, SocketAddr::V6(address)
                if address.ip().is_unicast_link_local()
                    && address.scope_id() != 0
                    && address.scope_id() != self.interface.get())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transmit does not match immutable IPv6 socket route",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub(super) struct Routes(Mutex<State>);

#[derive(Debug, Default)]
struct State {
    sockets: BTreeMap<Route, Weak<UdpSocket>>,
    cursor: usize,
    receiver: Option<Waker>,
}

impl State {
    fn prune(&mut self) {
        self.sockets.retain(|_, socket| socket.strong_count() != 0);
    }
}

impl Routes {
    pub(super) fn acquire(
        &self,
        base: &UdpSocket,
        source: IpAddr,
        interface: NonZeroU32,
    ) -> io::Result<Option<Arc<dyn AsyncUdpSocket>>> {
        if let Some(selected) = base.selected {
            return if source == IpAddr::V6(selected.source) && interface == selected.interface {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "cannot retarget an immutable IPv6 socket",
                ))
            };
        }
        let source = match source.to_canonical() {
            IpAddr::V4(_) => return Ok(None),
            IpAddr::V6(source) => source,
        };
        if source.is_unspecified() || source.is_multicast() || interface.get() > i32::MAX as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid IPv6 route",
            ));
        }
        let route = Route { source, interface };
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.prune();
        if let Some(socket) = state.sockets.get(&route).and_then(Weak::upgrade) {
            return Ok(Some(socket));
        }
        if state.sockets.len() >= MAX_ROUTES {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "IPv6 route socket limit",
            ));
        }
        let socket = Arc::new(derive(base, route)?);
        state.sockets.insert(route, Arc::downgrade(&socket));
        let receiver = state.receiver.take();
        drop(state);
        if let Some(receiver) = receiver {
            receiver.wake();
        }
        Ok(Some(socket))
    }

    pub(super) fn live(&self, route: Route) -> io::Result<Arc<UdpSocket>> {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.prune();
        state
            .sockets
            .get(&route)
            .and_then(Weak::upgrade)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "IPv6 transmit route is not reserved",
                )
            })
    }

    pub(super) fn poll_recv(
        &self,
        base: &UdpSocket,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut sockets: [Option<Arc<UdpSocket>>; MAX_ROUTES] = std::array::from_fn(|_| None);
        let (start, count) = {
            let mut state = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Registration and insertion share this lock, closing the lost-wakeup window.
            state.receiver = Some(cx.waker().clone());
            state.prune();
            let mut count = 0;
            for socket in state.sockets.values().filter_map(Weak::upgrade) {
                sockets[count] = Some(socket);
                count += 1;
            }
            (state.cursor % (count + 1), count)
        };
        for offset in 0..=count {
            let index = (start + offset) % (count + 1);
            let socket = if index == 0 {
                base
            } else {
                sockets[index - 1]
                    .as_deref()
                    .expect("populated receive socket")
            };
            if let Poll::Ready(result) = socket.poll_recv_single(cx, bufs, meta) {
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

fn derive(base: &UdpSocket, route: Route) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, SockRef, Socket, Type};

    let local = base.io.local_addr()?;
    if !local.is_ipv6() || (!local.ip().is_unspecified() && local.ip() != IpAddr::V6(route.source))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPv6 source conflicts with endpoint bind",
        ));
    }
    let original = SockRef::from(&base.io);
    let bound = original.device_index_v6()?;
    if bound.is_some_and(|bound| bound != route.interface) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPv6 interface conflicts with endpoint bind",
        ));
    }
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_port(true)?;
    let mark = original.mark()?;
    if mark != 0 {
        socket.set_mark(mark)?;
    }
    // On Linux socket2 uses SO_BINDTOIFINDEX, setting sk_bound_dev_if.
    socket.bind_device_by_index_v6(Some(route.interface))?;
    original.set_reuse_port(true)?;
    let local = SocketAddr::V6(SocketAddrV6::new(
        route.source,
        local.port(),
        0,
        if route.source.is_unicast_link_local() {
            route.interface.get()
        } else {
            0
        },
    ));
    socket.bind(&local.into())?;
    let socket: std::net::UdpSocket = socket.into();
    Ok(UdpSocket {
        inner: udp::UdpSocketState::new((&socket).into())?,
        io: tokio::net::UdpSocket::from_std(socket)?,
        routes: Routes::default(),
        selected: Some(route),
    })
}

#[cfg(test)]
mod tests;
