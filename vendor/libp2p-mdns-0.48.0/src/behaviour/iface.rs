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
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
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
use super::InterfaceFilter;
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
    /// Receive socket.
    recv_socket: U,
    /// Send socket.
    send_socket: U,

    listen_addresses: Arc<RwLock<ListenAddresses>>,

    query_response_sender: mpsc::Sender<(PeerId, Multiaddr, Instant)>,

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
    multicast_addr: IpAddr,
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
    pub(crate) fn new(
        addr: IpAddr,
        config: Config,
        local_peer_id: PeerId,
        listen_addresses: Arc<RwLock<ListenAddresses>>,
        query_response_sender: mpsc::Sender<(PeerId, Multiaddr, Instant)>,
        allowed_interfaces: InterfaceFilter,
    ) -> io::Result<Self> {
        tracing::info!(address=%addr, "creating instance on iface address");
        let recv_socket = match addr {
            IpAddr::V4(addr) => {
                let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(socket2::Protocol::UDP))?;
                socket.set_reuse_address(true)?;
                #[cfg(unix)]
                socket.set_reuse_port(true)?;
                socket.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5353).into())?;
                socket.set_multicast_loop_v4(true)?;
                socket.set_multicast_ttl_v4(255)?;
                restrict_multicast_reception(&socket)?;
                socket.join_multicast_v4(&crate::IPV4_MDNS_MULTICAST_ADDRESS, &addr)?;
                U::from_std(UdpSocket::from(socket))?
            }
            IpAddr::V6(_) => {
                let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(socket2::Protocol::UDP))?;
                socket.set_reuse_address(true)?;
                #[cfg(unix)]
                socket.set_reuse_port(true)?;
                socket.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 5353).into())?;
                socket.set_multicast_loop_v6(true)?;
                // TODO: find interface matching addr.
                socket.join_multicast_v6(&crate::IPV6_MDNS_MULTICAST_ADDRESS, 0)?;
                U::from_std(UdpSocket::from(socket))?
            }
        };
        let bind_addr = match addr {
            IpAddr::V4(_) => SocketAddr::new(addr, 0),
            IpAddr::V6(_addr) => {
                // TODO: if-watch should return the scope_id of an address
                // as a workaround we bind to unspecified, which means that
                // this probably won't work when using multiple interfaces.
                // SocketAddr::V6(SocketAddrV6::new(addr, 0, 0, scope_id))
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            }
        };
        let socket = UdpSocket::bind(bind_addr)?;
        if allowed_interfaces
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            if let IpAddr::V4(addr) = addr {
                socket2::SockRef::from(&socket).set_multicast_if_v4(&addr)?;
            }
        }
        let send_socket = U::from_std(socket)?;

        // randomize timer to prevent all converging and firing at the same time.
        let query_interval = {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let jitter = rng.gen_range(0..100);
            config.query_interval + Duration::from_millis(jitter)
        };
        let multicast_addr = match addr {
            IpAddr::V4(_) => IpAddr::V4(crate::IPV4_MDNS_MULTICAST_ADDRESS),
            IpAddr::V6(_) => IpAddr::V6(crate::IPV6_MDNS_MULTICAST_ADDRESS),
        };
        Ok(Self {
            addr,
            allowed_interfaces,
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
        SocketAddr::new(self.multicast_addr, 5353)
    }
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

fn source_allowed(addr: IpAddr, filter: &InterfaceFilter) -> bool {
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
            if !source_allowed(this.addr, &this.allowed_interfaces) {
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
            if this.query_response_sender.poll_ready_unpin(cx).is_ready() {
                if let Some(discovered) = this.discovered.pop_front() {
                    match this.query_response_sender.try_send(discovered) {
                        Ok(()) => {}
                        Err(e) if e.is_disconnected() => {
                            return Poll::Ready(());
                        }
                        Err(e) => {
                            this.discovered.push_front(e.into_inner());
                        }
                    }

                    continue;
                }
            }

            // 4th priority: Remote work: Answer incoming requests.
            match this
                .recv_socket
                .poll_read(cx, &mut this.recv_buffer)
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
