//! Bounded IP packet device and TCP client. There are no OS sockets here.
use std::{collections::VecDeque, net::Ipv4Addr};

use rand_core::{OsRng, RngCore};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp,
    time::{Duration, Instant},
    wire::{HardwareAddress, IpAddress, IpCidr},
};

const MAX_PACKETS: usize = 128;
const MAX_RESPONSE: usize = 1024 * 1024;
pub const MTU: usize = 1280;

#[derive(Default)]
pub struct IpDevice {
    incoming: VecDeque<Vec<u8>>,
    outgoing: VecDeque<Vec<u8>>,
}

impl IpDevice {
    pub fn receive_packet(&mut self, packet: &[u8]) -> Result<(), String> {
        if packet.len() > MTU || self.incoming.len() >= MAX_PACKETS {
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
        let packet = self.incoming.pop_front()?;
        Some((Receive(packet), Transmit(&mut self.outgoing)))
    }

    fn transmit(&mut self, _: Instant) -> Option<Transmit<'_>> {
        (self.outgoing.len() < MAX_PACKETS).then_some(Transmit(&mut self.outgoing))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
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
        if port == 0
            || !path.starts_with('/')
            || !path.is_ascii()
            || path.bytes().any(|b| b <= 0x20 || b == 0x7f)
            || path.len() > 4096
        {
            return Err("expected a nonzero port and an ASCII HTTP path without whitespace".into());
        }
        let mut device = IpDevice::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = OsRng.next_u64();
        let now = Instant::from_millis(0);
        let mut iface = Interface::new(config, &mut device, now);
        iface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(IpAddress::Ipv4(local), 32)).unwrap();
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(remote)
            .map_err(|e| format!("route: {e:?}"))?;
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 64 * 1024]),
            tcp::SocketBuffer::new(vec![0; 16 * 1024]),
        );
        socket.set_timeout(Some(Duration::from_secs(20)));
        socket.set_ack_delay(None);
        socket.set_nagle_enabled(false);
        let source_port = 49152 + (OsRng.next_u32() % 16384) as u16;
        socket
            .connect(
                iface.context(),
                (IpAddress::Ipv4(remote), port),
                source_port,
            )
            .map_err(|e| format!("TCP connect: {e:?}"))?;
        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(socket);
        Ok(Self {
            device,
            iface,
            sockets,
            handle,
            request: format!(
                "GET {path} HTTP/1.1\r\nHost: {remote}:{port}\r\nConnection: close\r\n\r\n"
            )
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
