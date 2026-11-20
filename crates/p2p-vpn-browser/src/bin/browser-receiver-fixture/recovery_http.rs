use p2p_vpn_browser::net::IpDevice;
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    socket::tcp,
    time::Instant as StackTime,
    wire::{HardwareAddress, IpCidr},
};

use super::*;

pub(super) async fn serve(fixture: &mut Fixture, connection: ConnectionId) -> Result<()> {
    let mut http = HttpProof::new(NATIVE_IP, BROWSER_IP, "/recovery-proof")?;
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    let mut sequence = 2;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            event = fixture.next() => {
                if let BehaviourEvent::Packet(request_response::Event::Message {
                    peer, connection_id, message: Message::Request { request, channel, .. }
                }) = event? {
                    assert_eq!((peer, connection_id), (fixture.peer, connection));
                    http.receive(request)?;
                    fixture.swarm.behaviour_mut().packet
                        .send_response(channel, PacketResponse::Accepted).map_err(debug_error)?;
                }
            }
        }
        for frame in http.poll(&mut sequence)? {
            fixture
                .swarm
                .behaviour_mut()
                .packet
                .send_request(&fixture.peer, frame);
        }
    }
}

pub(super) struct HttpProof {
    device: IpDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    listener: smoltcp::iface::SocketHandle,
    started: tokio::time::Instant,
    request: Vec<u8>,
    path: &'static str,
    replied: bool,
}

impl HttpProof {
    pub(super) fn new(local: Ipv4Addr, remote: Ipv4Addr, path: &'static str) -> Result<Self> {
        let mut device = IpDevice::default();
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            StackTime::ZERO,
        );
        iface.update_ip_addrs(|addrs| addrs.push(IpCidr::new(local.into(), 32)).unwrap());
        iface.routes_mut().add_default_ipv4_route(remote)?;
        let mut sockets = SocketSet::new(vec![]);
        let mut http = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 4096]),
            tcp::SocketBuffer::new(vec![0; 4096]),
        );
        http.listen(8080)?;
        let listener = sockets.add(http);
        Ok(Self {
            device,
            iface,
            sockets,
            listener,
            started: tokio::time::Instant::now(),
            request: Vec::new(),
            path,
            replied: false,
        })
    }

    pub(super) fn receive(&mut self, frame: Frame) -> Result<()> {
        assert_eq!(frame.header.payload_type, PayloadType::IpPacket);
        self.device
            .receive_packet(&frame.payload)
            .map_err(debug_error)?;
        Ok(())
    }

    pub(super) fn poll(&mut self, sequence: &mut u64) -> Result<Vec<Frame>> {
        self.iface.poll(
            StackTime::from_millis(self.started.elapsed().as_millis() as i64),
            &mut self.device,
            &mut self.sockets,
        );
        let http = self.sockets.get_mut::<tcp::Socket>(self.listener);
        if !self.replied && http.can_recv() {
            http.recv(|data| {
                self.request.extend_from_slice(data);
                (data.len(), ())
            })?;
            assert!(self.request.len() <= 4096);
            if self.request.ends_with(b"\r\n\r\n") {
                assert!(
                    self.request
                        .starts_with(format!("GET {} HTTP/1.1\r\n", self.path).as_bytes())
                );
                let response = b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\nrecovered-route";
                assert_eq!(http.send_slice(response)?, response.len());
                http.close();
                self.replied = true;
            }
        }
        let mut frames = Vec::new();
        while let Some(packet) = self.device.take_packet() {
            frames.push(Frame::packet(1, *sequence, packet).map_err(debug_error)?);
            *sequence += 1;
        }
        Ok(frames)
    }
}
