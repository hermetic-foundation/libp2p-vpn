use p2p_vpn_browser::net::IpDevice;
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    socket::tcp,
    time::Instant as StackTime,
    wire::{HardwareAddress, IpCidr},
};

use super::*;

pub(super) async fn serve(fixture: &mut Fixture, connection: ConnectionId) -> Result<()> {
    let mut device = IpDevice::default();
    let mut iface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        StackTime::ZERO,
    );
    iface.update_ip_addrs(|addrs| addrs.push(IpCidr::new(NATIVE_IP.into(), 32)).unwrap());
    iface.routes_mut().add_default_ipv4_route(BROWSER_IP)?;
    let mut sockets = SocketSet::new(vec![]);
    let mut http = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 4096]),
        tcp::SocketBuffer::new(vec![0; 4096]),
    );
    http.listen(8080)?;
    let http = sockets.add(http);
    let now = tokio::time::Instant::now();
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    let mut sequence = 2;
    let mut request = Vec::new();
    let mut replied = false;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            event = fixture.next() => {
                if let BehaviourEvent::Packet(request_response::Event::Message {
                    peer, connection_id, message: Message::Request { request, channel, .. }
                }) = event? {
                    assert_eq!((peer, connection_id), (fixture.peer, connection));
                    assert_eq!(request.header.payload_type, PayloadType::IpPacket);
                    device.receive_packet(&request.payload).map_err(debug_error)?;
                    fixture.swarm.behaviour_mut().packet
                        .send_response(channel, PacketResponse::Accepted).map_err(debug_error)?;
                }
            }
        }
        iface.poll(
            StackTime::from_millis(now.elapsed().as_millis() as i64),
            &mut device,
            &mut sockets,
        );
        let http = sockets.get_mut::<tcp::Socket>(http);
        if !replied && http.can_recv() {
            http.recv(|data| {
                request.extend_from_slice(data);
                (data.len(), ())
            })?;
            assert!(request.len() <= 4096);
            if request.ends_with(b"\r\n\r\n") {
                assert!(request.starts_with(b"GET /recovery-proof HTTP/1.1\r\n"));
                let response = b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\nrecovered-route";
                assert_eq!(http.send_slice(response)?, response.len());
                http.close();
                replied = true;
            }
        }
        while let Some(packet) = device.take_packet() {
            let frame = Frame::packet(1, sequence, packet).map_err(debug_error)?;
            sequence += 1;
            fixture
                .swarm
                .behaviour_mut()
                .packet
                .send_request(&fixture.peer, frame);
        }
    }
}
