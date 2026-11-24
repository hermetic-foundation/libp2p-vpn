//! Bounded IP packet device and TCP client. There are no OS sockets here.
use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use p2p_vpn::runtime::stream_admission::MIN_IPV4_MTU;
use rand_core::{OsRng, RngCore};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp,
    time::{Duration, Instant},
    wire::{HardwareAddress, IpAddress, IpCidr, IpVersion},
};

const MAX_PACKETS: usize = 128;
const MAX_RESPONSE: usize = 1024 * 1024;
pub const MTU: usize = 1280;
const MIN_IPV6_MTU: u16 = smoltcp::wire::IPV6_MIN_MTU as u16;

pub struct IpDevice {
    mtu: u16,
    incoming: VecDeque<Vec<u8>>,
    outgoing: VecDeque<Vec<u8>>,
}

impl Default for IpDevice {
    fn default() -> Self {
        Self::new(MTU as u16).expect("default IPv4 MTU is valid")
    }
}

impl IpDevice {
    pub(crate) fn new(mtu: u16) -> Result<Self, String> {
        if mtu < MIN_IPV4_MTU {
            return Err(format!("IPv4 MTU must be at least {MIN_IPV4_MTU}"));
        }
        Ok(Self {
            mtu,
            incoming: VecDeque::new(),
            outgoing: VecDeque::new(),
        })
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn mtu(&self) -> u16 {
        self.mtu
    }

    pub fn receive_packet(&mut self, packet: &[u8]) -> Result<(), String> {
        if packet.len() > usize::from(self.mtu) || self.incoming.len() >= MAX_PACKETS {
            return Err("virtual interface receive limit exceeded".into());
        }
        self.incoming.push_back(packet.to_vec());
        Ok(())
    }

    pub fn take_packet(&mut self) -> Option<Vec<u8>> {
        self.outgoing.pop_front()
    }
}

pub struct Receive(Vec<u8>);
pub struct Transmit<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for Receive {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl TxToken for Transmit<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}

impl Device for IpDevice {
    type RxToken<'a> = Receive;
    type TxToken<'a> = Transmit<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Receive, Transmit<'_>)> {
        if self.outgoing.len() >= MAX_PACKETS {
            return None;
        }
        let packet = loop {
            let packet = self.incoming.pop_front()?;
            if packet.is_empty() {
                continue;
            }
            if self.mtu >= MIN_IPV6_MTU
                || !matches!(IpVersion::of_packet(&packet), Ok(IpVersion::Ipv6))
            {
                break packet;
            }
        };
        Some((Receive(packet), Transmit(&mut self.outgoing)))
    }

    fn transmit(&mut self, _: Instant) -> Option<Transmit<'_>> {
        (self.outgoing.len() < MAX_PACKETS).then_some(Transmit(&mut self.outgoing))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = usize::from(self.mtu);
        caps.max_burst_size = Some(16);
        caps
    }
}

pub struct HttpConnection {
    pub device: IpDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    handle: SocketHandle,
    request: Vec<u8>,
    sent: usize,
    response: Vec<u8>,
}

impl HttpConnection {
    pub fn new(local: Ipv4Addr, remote: Ipv4Addr, port: u16, path: &str) -> Result<Self, String> {
        Self::new_with_mtu(local, remote, port, path, MTU as u16)
    }

    pub fn new_with_mtu(
        local: Ipv4Addr,
        remote: Ipv4Addr,
        port: u16,
        path: &str,
        mtu: u16,
    ) -> Result<Self, String> {
        Self::new_ip_with_mtu(local.into(), remote.into(), port, path, mtu)
    }

    /// Open a userspace TCP connection between same-family overlay addresses.
    ///
    /// The packet MTU must be at least 68 bytes for IPv4 or 1280 bytes for IPv6.
    pub fn new_ip_with_mtu(
        local: IpAddr,
        remote: IpAddr,
        port: u16,
        path: &str,
        mtu: u16,
    ) -> Result<Self, String> {
        if port == 0
            || !path.starts_with('/')
            || !path.is_ascii()
            || path.bytes().any(|b| b <= 0x20 || b == 0x7f)
            || path.len() > 4096
        {
            return Err("expected a nonzero port and an ASCII HTTP path without whitespace".into());
        }
        let prefix_len = match (local, remote) {
            (IpAddr::V4(_), IpAddr::V4(_)) => 32,
            (IpAddr::V6(_), IpAddr::V6(_)) => {
                if mtu < MIN_IPV6_MTU {
                    return Err(format!("IPv6 MTU must be at least {MIN_IPV6_MTU}"));
                }
                128
            }
            _ => return Err("local and remote IP address families must match".into()),
        };
        let mut device = IpDevice::new(mtu)?;
        let local_ip = IpAddress::from(local);
        if !local_ip.is_unicast() {
            return Err("TCP connect: local IP address must be unicast".into());
        }
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = OsRng.next_u64();
        let now = Instant::from_millis(0);
        let mut iface = Interface::new(config, &mut device, now);
        iface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(local_ip, prefix_len)).unwrap();
        });
        let routes = iface.routes_mut();
        match remote {
            IpAddr::V4(remote) => routes.add_default_ipv4_route(remote),
            IpAddr::V6(remote) => routes.add_default_ipv6_route(remote),
        }
        .map_err(|e| format!("route: {e:?}"))?;
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 64 * 1024]),
            tcp::SocketBuffer::new(vec![0; 16 * 1024]),
        );
        socket.set_timeout(Some(Duration::from_secs(20)));
        socket.set_ack_delay(None);
        socket.set_nagle_enabled(false);
        let source_port = 49152 + (OsRng.next_u32() % 16384) as u16;
        let remote = SocketAddr::new(remote, port);
        socket
            .connect(iface.context(), remote, SocketAddr::new(local, source_port))
            .map_err(|e| format!("TCP connect: {e:?}"))?;
        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(socket);
        Ok(Self {
            device,
            iface,
            sockets,
            handle,
            request: format!("GET {path} HTTP/1.1\r\nHost: {remote}\r\nConnection: close\r\n\r\n")
                .into_bytes(),
            sent: 0,
            response: Vec::new(),
        })
    }

    pub fn poll(&mut self, elapsed_ms: i64) -> Result<Option<String>, String> {
        let now = Instant::from_millis(elapsed_ms);
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        let socket = self.sockets.get_mut::<tcp::Socket>(self.handle);
        if socket.can_send() && self.sent < self.request.len() {
            self.sent += socket
                .send_slice(&self.request[self.sent..])
                .map_err(|e| format!("TCP send: {e:?}"))?;
        }
        while socket.can_recv() {
            socket
                .recv(|bytes| {
                    self.response.extend_from_slice(bytes);
                    (bytes.len(), ())
                })
                .map_err(|e| format!("TCP receive: {e:?}"))?;
            if self.response.len() > MAX_RESPONSE {
                socket.abort();
                return Err("HTTP response exceeds 1 MiB".into());
            }
        }
        if !socket.may_recv()
            && !matches!(
                socket.state(),
                tcp::State::SynSent | tcp::State::SynReceived
            )
        {
            socket.close();
            if self.response.is_empty() {
                return Err("TCP connection closed without an HTTP response".into());
            }
            self.iface.poll(now, &mut self.device, &mut self.sockets);
            return String::from_utf8(std::mem::take(&mut self.response))
                .map(Some)
                .map_err(|_| "response is not UTF-8".into());
        }
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::{
        phy::ChecksumCapabilities,
        wire::{IpProtocol, Ipv6Packet, TcpControl, TcpPacket, TcpRepr},
    };
    use std::net::Ipv6Addr;

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn dtls_ignores_unknown_groups_but_requires_a_supported_curve() {
        use webrtc_dtls::curve::named_curve::NamedCurve;
        assert_eq!(
            NamedCurve::select_supported(&[
                NamedCurve::Unsupported,
                NamedCurve::X25519,
                NamedCurve::P256
            ]),
            Some(NamedCurve::X25519)
        );
        assert_eq!(
            NamedCurve::select_supported(&[NamedCurve::Unsupported]),
            None
        );
        assert_eq!(NamedCurve::select_supported(&[]), None);
    }

    #[test]
    fn emits_valid_ip_tcp_syn_and_waits_for_the_peer() {
        let local = Ipv4Addr::new(10, 203, 0, 2);
        let remote = Ipv4Addr::new(10, 203, 0, 1);
        let mut connection = HttpConnection::new(local, remote, 8080, "/proof").unwrap();
        assert!(connection.poll(0).unwrap().is_none());
        let bytes = connection.device.take_packet().expect("real TCP SYN");
        let ip = smoltcp::wire::Ipv4Packet::new_checked(bytes.as_slice()).unwrap();
        assert_eq!(ip.src_addr(), local);
        assert_eq!(ip.dst_addr(), remote);
        assert!(ip.verify_checksum());
        let tcp = smoltcp::wire::TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.syn());
        assert_eq!(tcp.dst_port(), 8080);
        assert!(connection.poll(5).unwrap().is_none());
    }

    #[test]
    fn uses_stream_mtu_for_the_receive_limit_and_tcp_mss() {
        let local = Ipv4Addr::new(10, 203, 0, 2);
        let remote = Ipv4Addr::new(10, 203, 0, 1);
        assert!(HttpConnection::new_with_mtu(local, remote, 80, "/", MIN_IPV4_MTU - 1).is_err());
        for mtu in [MIN_IPV4_MTU, 1200, 1420] {
            let mut connection = HttpConnection::new_with_mtu(local, remote, 80, "/", mtu).unwrap();
            assert!(connection.poll(0).unwrap().is_none());
            let bytes = connection.device.take_packet().expect("real TCP SYN");
            assert!(bytes.len() <= usize::from(mtu));
            let ip = smoltcp::wire::Ipv4Packet::new_checked(bytes.as_slice()).unwrap();
            let tcp = smoltcp::wire::TcpPacket::new_checked(ip.payload()).unwrap();
            let repr = smoltcp::wire::TcpRepr::parse(
                &tcp,
                &local.into(),
                &remote.into(),
                &smoltcp::phy::ChecksumCapabilities::default(),
            )
            .unwrap();
            assert_eq!(repr.max_seg_size, Some(mtu - 40));
            let limit = usize::from(mtu);
            assert!(
                connection
                    .device
                    .receive_packet(&vec![0; limit + 1])
                    .is_err()
            );
            connection.device.receive_packet(&vec![0; limit]).unwrap();
        }
    }

    #[test]
    fn rejects_mixed_families_and_ipv6_below_minimum_mtu() {
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 203, 0, 2));
        let local_v6 = "fd00:203::2".parse().unwrap();
        let remote_v6 = "fd00:204::1".parse().unwrap();
        assert!(HttpConnection::new_ip_with_mtu(local_v6, remote_v6, 80, "/", 1279).is_err());
        assert!(HttpConnection::new_ip_with_mtu(v4, remote_v6, 80, "/", 1280).is_err());
        assert!(HttpConnection::new_ip_with_mtu(local_v6, v4, 80, "/", 1280).is_err());
    }

    #[test]
    fn emits_valid_ipv6_syn_with_tcp_mss_from_the_stream_mtu() {
        let local: Ipv6Addr = "fd00:203::2".parse().unwrap();
        let remote: Ipv6Addr = "fd00:204::1".parse().unwrap();
        for mtu in [1280, 1420] {
            let mut connection =
                HttpConnection::new_ip_with_mtu(local.into(), remote.into(), 8080, "/", mtu)
                    .unwrap();
            assert!(connection.poll(0).unwrap().is_none());
            let bytes = connection.device.take_packet().expect("real IPv6 TCP SYN");
            let limit = usize::from(mtu);
            assert!(bytes.len() <= limit);
            let ip = Ipv6Packet::new_checked(bytes.as_slice()).unwrap();
            assert_eq!(ip.version(), 6);
            assert_eq!(ip.src_addr(), local);
            assert_eq!(ip.dst_addr(), remote);
            assert_eq!(ip.next_header(), IpProtocol::Tcp);
            let packet = TcpPacket::new_checked(ip.payload()).unwrap();
            let syn = TcpRepr::parse(
                &packet,
                &ip.src_addr().into(),
                &ip.dst_addr().into(),
                &ChecksumCapabilities::default(),
            )
            .unwrap();
            assert_eq!(syn.control, TcpControl::Syn);
            assert_eq!(syn.ack_number, None);
            assert_eq!(syn.dst_port, 8080);
            assert_eq!(syn.max_seg_size, Some(mtu - 60));
            assert!(connection.poll(5).unwrap().is_none());
            let mut ipv4_only = IpDevice::new(1279).unwrap();
            ipv4_only.receive_packet(&[]).unwrap();
            ipv4_only.receive_packet(&bytes).unwrap();
            assert!(ipv4_only.receive(Instant::ZERO).is_none());
            assert!(
                connection
                    .device
                    .receive_packet(&vec![0; limit + 1])
                    .is_err()
            );
            connection.device.receive_packet(&vec![0; limit]).unwrap();
        }
    }

    #[test]
    fn exchanges_http_over_userspace_ipv6_with_a_bracketed_host() {
        let local = "fd00:203::2".parse().unwrap();
        let remote = "fd00:204::1".parse().unwrap();
        let port = 8080;
        let mut client =
            HttpConnection::new_ip_with_mtu(local, remote, port, "/proof", 1280).unwrap();

        let mut device = IpDevice::default();
        let mut server =
            Interface::new(Config::new(HardwareAddress::Ip), &mut device, Instant::ZERO);
        server.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(remote.into(), 128)).unwrap();
        });
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 256]),
            tcp::SocketBuffer::new(vec![0; 256]),
        );
        socket.listen(port).unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(socket);
        let mut request = Vec::new();
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
        for elapsed in (0..1000).step_by(10) {
            if let Some(received) = client.poll(elapsed).unwrap() {
                assert_eq!(received, response);
                assert_eq!(
                    request,
                    b"GET /proof HTTP/1.1\r\nHost: [fd00:204::1]:8080\r\nConnection: close\r\n\r\n"
                );
                return;
            }
            while let Some(packet) = client.device.take_packet() {
                device.receive_packet(&packet).unwrap();
            }
            server.poll(Instant::from_millis(elapsed), &mut device, &mut sockets);
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            if socket.can_recv() {
                socket
                    .recv(|bytes| {
                        request.extend_from_slice(bytes);
                        (bytes.len(), ())
                    })
                    .unwrap();
            }
            if request.ends_with(b"\r\n\r\n") && socket.can_send() {
                assert_eq!(
                    socket.send_slice(response.as_bytes()).unwrap(),
                    response.len()
                );
                socket.close();
            }
            while let Some(packet) = device.take_packet() {
                client.device.receive_packet(&packet).unwrap();
            }
        }
        panic!("userspace IPv6 HTTP exchange did not complete");
    }

    #[test]
    fn bounds_packets_and_rejects_http_header_injection() {
        let local = Ipv4Addr::new(10, 203, 0, 2);
        let remote = Ipv4Addr::new(10, 203, 0, 1);
        assert!(HttpConnection::new(local, remote, 80, "/\r\nHost: attacker").is_err());
        let mut device = IpDevice::default();
        assert!(device.receive_packet(&vec![0; MTU + 1]).is_err());
        for _ in 0..MAX_PACKETS {
            device.receive_packet(&[0; 20]).unwrap();
        }
        assert!(device.receive_packet(&[0; 20]).is_err());
    }
}
