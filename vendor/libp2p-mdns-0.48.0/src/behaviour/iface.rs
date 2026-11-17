// Copyright 2018 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

mod dns;
mod query;

use std::{
    collections::VecDeque,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket},
    num::NonZeroU32,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures::{channel::mpsc, SinkExt, StreamExt};
use libp2p_core::{multiaddr::Protocol, Multiaddr};
use libp2p_identity::PeerId;
use libp2p_swarm::ListenAddresses;
use socket2::{Domain, Socket, Type};

use self::{
    dns::{build_query, build_query_response, build_service_discovery_response},
    query::MdnsPacket,
};
use super::{InterfaceFilter, InterfaceTaskState, OwnedDiscovery};
use crate::{
    behaviour::{socket::AsyncSocket, timer::Builder},
    Config,
};

/// Initial interval for starting probe
const INITIAL_TIMEOUT_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Debug, Clone)]
enum ProbeState {
    Probing(Duration),
    Finished(Duration),
}

impl Default for ProbeState {
    fn default() -> Self {
        ProbeState::Probing(INITIAL_TIMEOUT_INTERVAL)
    }
}

impl ProbeState {
    fn interval(&self) -> &Duration {
        match self {
            ProbeState::Probing(query_interval) => query_interval,
            ProbeState::Finished(query_interval) => query_interval,
        }
    }
}

/// An mDNS instance for a networking interface. To discover all peers when having multiple
/// interfaces an [`InterfaceState`] is required for each interface.
#[derive(Debug)]
pub(crate) struct InterfaceState<U, T> {
    /// Address this instance is bound to.
    addr: IpAddr,
    allowed_interfaces: InterfaceFilter,
    task_state: Arc<InterfaceTaskState>,
    /// Receive socket.
    recv_socket: U,
    /// Send socket.
    send_socket: U,

    listen_addresses: Arc<RwLock<ListenAddresses>>,

    query_response_sender: mpsc::Sender<OwnedDiscovery>,

    /// Buffer used for receiving data from the main socket.
    /// RFC6762 discourages packets larger than the interface MTU, but allows sizes of up to 9000
    /// bytes, if it can be ensured that all participating devices can handle such large packets.
    /// For computers with several interfaces and IP addresses responses can easily reach sizes in
    /// the range of 3000 bytes, so 4096 seems sensible for now. For more information see
    /// [rfc6762](https://tools.ietf.org/html/rfc6762#page-46).
    recv_buffer: [u8; 4096],
    /// Buffers pending to send on the main socket.
    send_buffer: VecDeque<Vec<u8>>,
    /// Discovery interval.
    query_interval: Duration,
    /// Discovery timer.
    timeout: T,
    /// Multicast address.
    multicast_addr: SocketAddr,
    /// Discovered addresses.
    discovered: VecDeque<(PeerId, Multiaddr, Instant)>,
    /// TTL
    ttl: Duration,
    probe_state: ProbeState,
    local_peer_id: PeerId,
}

impl<U, T> InterfaceState<U, T>
where
    U: AsyncSocket,
    T: Builder + futures::Stream,
{
    /// Builds a new [`InterfaceState`].
    pub(super) fn new(
        addr: IpAddr,
        config: Config,
        local_peer_id: PeerId,
        listen_addresses: Arc<RwLock<ListenAddresses>>,
        query_response_sender: mpsc::Sender<OwnedDiscovery>,
        allowed_interfaces: InterfaceFilter,
        task_state: Arc<InterfaceTaskState>,
        prepared: Option<(UdpSocket, UdpSocket)>,
    ) -> io::Result<Self> {
        tracing::info!(address=%addr, "creating instance on iface address");
        let restricted = allowed_interfaces
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_some();
        let sockets = match prepared {
            Some((recv, send)) => (recv.into(), send.into()),
            None => unbound_sockets(addr, &task_state)?,
        };
        let (recv_socket, send_socket) = create_sockets(addr, restricted, &task_state, sockets)?;
        let recv_socket = U::from_std(recv_socket)?;
        let send_socket = U::from_std(send_socket)?;
        ensure_current(&task_state)?;

        // randomize timer to prevent all converging and firing at the same time.
        let query_interval = {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let jitter = rng.gen_range(0..100);
            config.query_interval + Duration::from_millis(jitter)
        };
        let (_, multicast_addr) = socket_addresses(addr, task_state.identity.map(|(_, i)| i));
        task_state
            .installed
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(Self {
            addr,
            allowed_interfaces,
            task_state,
            recv_socket,
            send_socket,
            listen_addresses,
            query_response_sender,
            recv_buffer: [0; 4096],
            send_buffer: Default::default(),
            discovered: Default::default(),
            query_interval,
            timeout: T::interval_at(Instant::now(), INITIAL_TIMEOUT_INTERVAL),
            multicast_addr,
            ttl: config.ttl,
            probe_state: Default::default(),
            local_peer_id,
        })
    }

    pub(crate) fn reset_timer(&mut self) {
        tracing::trace!(address=%self.addr, probe_state=?self.probe_state, "reset timer");
        let interval = *self.probe_state.interval();
        self.timeout = T::interval(interval);
    }

    fn mdns_socket(&self) -> SocketAddr {
        self.multicast_addr
    }

    fn is_current(&self) -> bool {
        self.task_state.is_current() && source_allowed(self.addr, &self.allowed_interfaces)
    }
}

fn ensure_current(state: &InterfaceTaskState) -> io::Result<()> {
    if !state.is_current() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "stale mDNS socket binding",
        ));
    }
    Ok(())
}

// Both ownership callbacks run before either socket is address-bound or joins
// a group. Dropping either socket on error leaves no partially installed task.
fn unbound_sockets(addr: IpAddr, state: &InterfaceTaskState) -> io::Result<(Socket, Socket)> {
    ensure_current(state)?;
    let (recv, send) = socket_pair(addr)?;
    if let Some(binding) = &state.binding {
        ensure_current(state)?;
        binding.bind(&recv)?;
        ensure_current(state)?;
        binding.bind(&send)?;
        ensure_current(state)?;
    }
    Ok((recv.into(), send.into()))
}

pub(super) fn socket_pair(addr: IpAddr) -> io::Result<(UdpSocket, UdpSocket)> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let recv = UdpSocket::from(Socket::new(
        domain,
        Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?);
    let send = UdpSocket::from(Socket::new(
        domain,
        Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?);
    Ok((recv, send))
}

fn socket_addresses(addr: IpAddr, index: Option<NonZeroU32>) -> (SocketAddr, SocketAddr) {
    match (addr, index) {
        (IpAddr::V4(_), _) => (
            SocketAddr::new(addr, 0),
            SocketAddr::new(IpAddr::V4(crate::IPV4_MDNS_MULTICAST_ADDRESS), 5353),
        ),
        (IpAddr::V6(source), Some(index)) => (
            SocketAddrV6::new(source, 0, 0, index.get()).into(),
            SocketAddrV6::new(crate::IPV6_MDNS_MULTICAST_ADDRESS, 5353, 0, index.get()).into(),
        ),
        (IpAddr::V6(_), None) => (
            // Preserve the upstream unscoped wildcard sender only in legacy mode.
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            SocketAddr::new(IpAddr::V6(crate::IPV6_MDNS_MULTICAST_ADDRESS), 5353),
        ),
    }
}

fn create_sockets(
    addr: IpAddr,
    restricted: bool,
    state: &InterfaceTaskState,
    sockets: (Socket, Socket),
) -> io::Result<(UdpSocket, UdpSocket)> {
    ensure_current(state)?;
    let (recv, send) = sockets;
    if state.binding.is_some() {
        super::socket::require_interface_metadata(&recv, addr.is_ipv6())?;
    }
    let index = state.identity.map(|(_, index)| index);
    let (source, _) = socket_addresses(addr, index);
    recv.set_reuse_address(true)?;
    #[cfg(unix)]
    recv.set_reuse_port(true)?;
    ensure_current(state)?;
    match addr {
        IpAddr::V4(ip) => {
            recv.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5353).into())?;
            ensure_current(state)?;
            recv.set_multicast_loop_v4(true)?;
            recv.set_multicast_ttl_v4(255)?;
            restrict_multicast_reception(&recv)?;
            if let Some(index) = index {
                join_bound_multicast_v4(&recv, index)?;
            } else {
                recv.join_multicast_v4(&crate::IPV4_MDNS_MULTICAST_ADDRESS, &ip)?;
            }
            if let Some(index) = index {
                set_bound_multicast_v4(&send, index)?;
            } else if restricted {
                send.set_multicast_if_v4(&ip)?;
            }
        }
        IpAddr::V6(_) => {
            if state.binding.is_some() {
                recv.set_only_v6(true)?;
                send.set_only_v6(true)?;
            }
            let index = index.map_or(0, NonZeroU32::get);
            let receive = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 5353, 0, index);
            recv.bind(&SocketAddr::V6(receive).into())?;
            ensure_current(state)?;
            recv.set_multicast_loop_v6(true)?;
            if restricted || state.binding.is_some() {
                restrict_multicast_reception_v6(&recv)?;
            }
            recv.join_multicast_v6(&crate::IPV6_MDNS_MULTICAST_ADDRESS, index)?;
            if state.binding.is_some() {
                send.set_multicast_if_v6(index)?;
            }
        }
    }
    ensure_current(state)?;
    send.bind(&source.into())?;
    ensure_current(state)?;
    Ok((recv.into(), send.into()))
}

fn set_bound_multicast_v4(socket: &Socket, index: NonZeroU32) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::fd::AsRawFd;
        let request = libc::ip_mreqn {
            imr_multiaddr: libc::in_addr { s_addr: 0 },
            imr_address: libc::in_addr { s_addr: 0 },
            imr_ifindex: i32::try_from(index.get()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "mDNS interface index exceeds kernel bound",
                )
            })?,
        };
        // ip_mreqn selects an exact device even when two links share a source IP.
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MULTICAST_IF,
                std::ptr::from_ref(&request).cast(),
                std::mem::size_of_val(&request) as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = (socket, index);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "indexed mDNS multicast output is unavailable",
        ))
    }
}

fn join_bound_multicast_v4(socket: &Socket, index: NonZeroU32) -> io::Result<()> {
    #[cfg(not(any(
        target_os = "aix",
        target_os = "haiku",
        target_os = "illumos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "solaris",
        target_os = "nto",
        target_os = "espidf",
        target_os = "vita",
        target_os = "cygwin",
    )))]
    {
        socket.join_multicast_v4_n(
            &crate::IPV4_MDNS_MULTICAST_ADDRESS,
            &socket2::InterfaceIndexOrAddress::Index(index.get()),
        )
    }
    #[cfg(any(
        target_os = "aix",
        target_os = "haiku",
        target_os = "illumos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "solaris",
        target_os = "nto",
        target_os = "espidf",
        target_os = "vita",
        target_os = "cygwin",
    ))]
    {
        let _ = (socket, index);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "indexed mDNS membership is unavailable",
        ))
    }
}

fn restrict_multicast_reception_v6(socket: &Socket) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    socket.set_multicast_all_v6(false)?;
    #[cfg(target_os = "android")]
    {
        use std::os::fd::AsRawFd;
        let disabled: libc::c_int = 0;
        // As with IP_MULTICAST_ALL below, socket2 exposes this only on Linux.
        // The live socket, pointer and length have the setsockopt ABI types.
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_MULTICAST_ALL,
                std::ptr::from_ref(&disabled).cast(),
                std::mem::size_of_val(&disabled) as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = socket;
    Ok(())
}

fn restrict_multicast_reception(socket: &Socket) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    socket.set_multicast_all_v4(false)?;
    #[cfg(target_os = "android")]
    {
        use std::os::fd::AsRawFd;
        let disabled: libc::c_int = 0;
        // socket2 0.5 exposes this option only on Linux, although Android uses
        // the same kernel socket option. The pointer and length match c_int.
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MULTICAST_ALL,
                std::ptr::from_ref(&disabled).cast(),
                std::mem::size_of_val(&disabled) as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = socket;
    Ok(())
}

pub(super) fn source_allowed(addr: IpAddr, filter: &InterfaceFilter) -> bool {
    filter
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .is_none_or(|allowed| allowed.contains(&addr))
}

pub(super) fn advertisement_allowed(
    address: &Multiaddr,
    allowed: Option<&std::collections::HashSet<IpAddr>>,
) -> bool {
    let Some(allowed) = allowed else {
        return true;
    };
    match address.iter().next() {
        Some(Protocol::Ip4(addr)) => allowed.contains(&IpAddr::V4(addr)),
        Some(Protocol::Ip6(addr)) => allowed.contains(&IpAddr::V6(addr)),
        _ => false,
    }
}

impl<U, T> Future for InterfaceState<U, T>
where
    U: AsyncSocket,
    T: Builder + futures::Stream,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            if !this.is_current() {
                return Poll::Ready(());
            }
            // 1st priority: Low latency: Create packet ASAP after timeout.
            if this.timeout.poll_next_unpin(cx).is_ready() {
                tracing::trace!(address=%this.addr, "sending query on iface");
                this.send_buffer.push_back(build_query());
                tracing::trace!(address=%this.addr, probe_state=?this.probe_state, "tick");

                // Stop to probe when the initial interval reach the query interval
                if let ProbeState::Probing(interval) = this.probe_state {
                    let interval = interval * 2;
                    this.probe_state = if interval >= this.query_interval {
                        ProbeState::Finished(this.query_interval)
                    } else {
                        ProbeState::Probing(interval)
                    };
                }

                this.reset_timer();
            }

            // 2nd priority: Keep local buffers small: Send packets to remote.
            if let Some(packet) = this.send_buffer.pop_front() {
                if !this.is_current() {
                    return Poll::Ready(());
                }
                match this.send_socket.poll_write(cx, &packet, this.mdns_socket()) {
                    Poll::Ready(Ok(_)) => {
                        tracing::trace!(address=%this.addr, "sent packet on iface address");
                        continue;
                    }
                    Poll::Ready(Err(err)) => {
                        tracing::error!(address=%this.addr, "error sending packet on iface address {}", err);
                        continue;
                    }
                    Poll::Pending => {
                        this.send_buffer.push_front(packet);
                    }
                }
            }

            // 3rd priority: Keep local buffers small: Return discovered addresses.
            if !this.is_current() {
                return Poll::Ready(());
            }
            if this.query_response_sender.poll_ready_unpin(cx).is_ready() {
                if let Some(discovered) = this.discovered.pop_front() {
                    if !this.is_current() {
                        return Poll::Ready(());
                    }
                    match this
                        .query_response_sender
                        .try_send((discovered, Arc::clone(&this.task_state)))
                    {
                        Ok(()) => {}
                        Err(e) if e.is_disconnected() => {
                            return Poll::Ready(());
                        }
                        Err(e) => {
                            this.discovered.push_front(e.into_inner().0);
                        }
                    }

                    continue;
                }
            }

            // 4th priority: Remote work: Answer incoming requests.
            if !this.is_current() {
                return Poll::Ready(());
            }
            let received = if let Some((_, index)) = this.task_state.identity {
                this.recv_socket
                    .poll_read_scoped(cx, &mut this.recv_buffer, index)
            } else {
                this.recv_socket.poll_read(cx, &mut this.recv_buffer)
            };
            match received
                .map_ok(|(len, from)| MdnsPacket::new_from_bytes(&this.recv_buffer[..len], from))
            {
                Poll::Ready(Ok(Ok(Some(MdnsPacket::Query(query))))) => {
                    tracing::trace!(
                        address=%this.addr,
                        remote_address=%query.remote_addr(),
                        "received query from remote address on address"
                    );

                    let allowed = this
                        .allowed_interfaces
                        .read()
                        .unwrap_or_else(|e| e.into_inner());
                    let listen_addresses = this
                        .listen_addresses
                        .read()
                        .unwrap_or_else(|e| e.into_inner());
                    let addresses: Vec<_> = listen_addresses
                        .iter()
                        .filter(|address| advertisement_allowed(address, allowed.as_ref()))
                        .collect();
                    this.send_buffer.extend(build_query_response(
                        query.query_id(),
                        this.local_peer_id,
                        addresses.into_iter(),
                        this.ttl,
                    ));
                    continue;
                }
                Poll::Ready(Ok(Ok(Some(MdnsPacket::Response(response))))) => {
                    tracing::trace!(
                        address=%this.addr,
                        remote_address=%response.remote_addr(),
                        "received response from remote address on address"
                    );

                    this.discovered
                        .extend(response.extract_discovered(Instant::now(), this.local_peer_id));

                    // Stop probing when we have a valid response
                    if !this.discovered.is_empty() {
                        this.probe_state = ProbeState::Finished(this.query_interval);
                        this.reset_timer();
                    }
                    continue;
                }
                Poll::Ready(Ok(Ok(Some(MdnsPacket::ServiceDiscovery(disc))))) => {
                    tracing::trace!(
                        address=%this.addr,
                        remote_address=%disc.remote_addr(),
                        "received service discovery from remote address on address"
                    );

                    this.send_buffer
                        .push_back(build_service_discovery_response(disc.query_id(), this.ttl));
                    continue;
                }
                Poll::Ready(Err(err)) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    // No more bytes available on the socket to read
                    continue;
                }
                Poll::Ready(Err(err)) => {
                    tracing::error!("failed reading datagram: {}", err);
                    return Poll::Ready(());
                }
                Poll::Ready(Ok(Err(err))) => {
                    tracing::debug!("Parsing mdns packet failed: {:?}", err);
                    continue;
                }
                Poll::Ready(Ok(Ok(None))) => continue,
                Poll::Pending => {}
            }

            return Poll::Pending;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use futures::task::AtomicWaker;

    use super::*;
    use crate::InterfaceSocketBinding;

    #[derive(Debug)]
    struct RecordingBinding {
        current: AtomicBool,
        calls: AtomicUsize,
        revoke_after: usize,
    }

    impl RecordingBinding {
        fn new(revoke_after: usize) -> Arc<Self> {
            Arc::new(Self {
                current: AtomicBool::new(true),
                calls: AtomicUsize::new(0),
                revoke_after,
            })
        }
    }

    impl InterfaceSocketBinding for RecordingBinding {
        fn identity(&self) -> [u64; 3] {
            [1, 2, 3]
        }
        fn interface_index(&self) -> NonZeroU32 {
            NonZeroU32::new(7).unwrap()
        }
        fn is_current(&self) -> bool {
            self.current.load(Ordering::Acquire)
        }
        fn bind(&self, socket: &UdpSocket) -> io::Result<()> {
            let local = socket.local_addr()?;
            assert!(local.ip().is_unspecified());
            assert_eq!(local.port(), 0);
            // An observable, harmless real socket option proves that each
            // callback receives the socket later used for address binding.
            socket.set_broadcast(true)?;
            let count = self.calls.fetch_add(1, Ordering::AcqRel) + 1;
            if count == self.revoke_after {
                self.current.store(false, Ordering::Release);
            }
            Ok(())
        }
    }

    fn state(binding: Arc<RecordingBinding>) -> Arc<InterfaceTaskState> {
        Arc::new(InterfaceTaskState::new(
            Some(binding),
            Arc::new(AtomicWaker::new()),
        ))
    }

    #[test]
    fn binding_reaches_both_real_sockets_before_address_binding() {
        let binding = RecordingBinding::new(0);
        let state = state(binding.clone());
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let (recv, send) = unbound_sockets(ip, &state).unwrap();
        assert_eq!(binding.calls.load(Ordering::Acquire), 2);
        for socket in [recv, send] {
            assert!(socket.broadcast().unwrap());
            assert_eq!(socket.local_addr().unwrap().as_socket().unwrap().port(), 0);
            socket.bind(&SocketAddr::new(ip, 0).into()).unwrap();
            assert_ne!(socket.local_addr().unwrap().as_socket().unwrap().port(), 0);
        }
    }

    #[test]
    fn stale_binding_is_rejected_before_and_after_each_callback() {
        for revoke_after in [0, 1, 2] {
            let binding = RecordingBinding::new(revoke_after);
            let state = state(binding.clone());
            if revoke_after == 0 {
                binding.current.store(false, Ordering::Release);
            }
            let error = unbound_sockets(IpAddr::V4(Ipv4Addr::LOCALHOST), &state).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(binding.calls.load(Ordering::Acquire), revoke_after);
        }
    }

    #[test]
    fn owned_ipv6_source_and_destination_use_the_exact_interface_scope() {
        for ip in ["fe80::1234", "2001:db8::1234"] {
            for index in [7, 19] {
                let ip: Ipv6Addr = ip.parse().unwrap();
                let (source, destination) =
                    socket_addresses(IpAddr::V6(ip), NonZeroU32::new(index));
                assert_eq!(source, SocketAddr::V6(SocketAddrV6::new(ip, 0, 0, index)));
                assert_eq!(
                    destination,
                    SocketAddr::V6(SocketAddrV6::new(
                        crate::IPV6_MDNS_MULTICAST_ADDRESS,
                        5353,
                        0,
                        index,
                    ))
                );
                assert!(!source.ip().is_unspecified());
            }
        }
    }

    #[test]
    fn legacy_socket_addresses_are_unchanged() {
        let (source, destination) = socket_addresses("fe80::1234".parse().unwrap(), None);
        assert_eq!(source, "[::]:0".parse().unwrap());
        assert_eq!(destination, "[ff02::fb]:5353".parse().unwrap());
        let (source, destination) = socket_addresses("192.0.2.1".parse().unwrap(), None);
        assert_eq!(source, "192.0.2.1:0".parse().unwrap());
        assert_eq!(destination, "224.0.0.251:5353".parse().unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn restricted_ipv6_receive_disables_multicast_all_on_a_real_socket() {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(socket2::Protocol::UDP)).unwrap();
        restrict_multicast_reception_v6(&socket).unwrap();
        assert!(!socket.multicast_all_v6().unwrap());
    }

    struct ObservedSocket {
        _socket: UdpSocket,
        polls: Arc<AtomicUsize>,
    }

    impl AsyncSocket for ObservedSocket {
        fn from_std(socket: UdpSocket) -> io::Result<Self> {
            Ok(Self {
                _socket: socket,
                polls: Arc::new(AtomicUsize::new(0)),
            })
        }
        fn poll_read(
            &mut self,
            _: &mut Context<'_>,
            _: &mut [u8],
        ) -> Poll<io::Result<(usize, SocketAddr)>> {
            self.polls.fetch_add(1, Ordering::Relaxed);
            Poll::Pending
        }
        fn poll_write(
            &mut self,
            _: &mut Context<'_>,
            _: &[u8],
            _: SocketAddr,
        ) -> Poll<io::Result<()>> {
            self.polls.fetch_add(1, Ordering::Relaxed);
            Poll::Pending
        }
    }

    #[derive(Default)]
    struct ObservedTimer {
        revoke: Option<Arc<RecordingBinding>>,
        polls: usize,
    }

    impl Builder for ObservedTimer {
        fn at(_: Instant) -> Self {
            Self::default()
        }
        fn interval(_: Duration) -> Self {
            Self::default()
        }
        fn interval_at(_: Instant, _: Duration) -> Self {
            Self::default()
        }
    }

    impl futures::Stream for ObservedTimer {
        type Item = ();
        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<()>> {
            self.polls += 1;
            if let Some(binding) = self.revoke.take() {
                binding.current.store(false, Ordering::Release);
                return Poll::Ready(Some(()));
            }
            Poll::Pending
        }
    }

    fn observed_future(
        binding: Arc<RecordingBinding>,
    ) -> InterfaceState<ObservedSocket, ObservedTimer> {
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        InterfaceState {
            addr,
            allowed_interfaces: Arc::new(RwLock::new(None)),
            task_state: state(binding),
            recv_socket: ObservedSocket::from_std(
                UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            )
            .unwrap(),
            send_socket: ObservedSocket::from_std(
                UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            )
            .unwrap(),
            listen_addresses: Default::default(),
            query_response_sender: mpsc::channel(1).0,
            recv_buffer: [0; 4096],
            send_buffer: VecDeque::from([vec![0]]),
            query_interval: Duration::from_secs(1),
            timeout: ObservedTimer::default(),
            multicast_addr: socket_addresses(addr, None).1,
            discovered: Default::default(),
            ttl: Duration::from_secs(1),
            probe_state: Default::default(),
            local_peer_id: PeerId::random(),
        }
    }

    #[test]
    fn stale_future_exits_before_polling_timer_or_sockets() {
        let binding = RecordingBinding::new(0);
        let mut future = observed_future(binding.clone());
        binding.current.store(false, Ordering::Release);
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(Pin::new(&mut future).poll(&mut cx).is_ready());
        assert_eq!(future.timeout.polls, 0);
        assert_eq!(future.recv_socket.polls.load(Ordering::Relaxed), 0);
        assert_eq!(future.send_socket.polls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn revocation_during_timer_poll_fences_the_queued_send() {
        let binding = RecordingBinding::new(0);
        let mut future = observed_future(binding.clone());
        future.timeout.revoke = Some(binding);
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(Pin::new(&mut future).poll(&mut cx).is_ready());
        assert_eq!(future.recv_socket.polls.load(Ordering::Relaxed), 0);
        assert_eq!(future.send_socket.polls.load(Ordering::Relaxed), 0);
    }
}
