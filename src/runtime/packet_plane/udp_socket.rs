//! Datagram boundaries and shared receive fan-in for owned UDP sockets.

use super::*;
use quinn::{AsyncUdpSocket, Runtime as _};
use std::{io::IoSliceMut, task::Poll};

const MAX_RECEIVE_SEGMENTS: usize = 64;

#[derive(Debug)]
pub(super) struct Socket {
    pub(super) io: Arc<dyn AsyncUdpSocket>,
    receive: tokio::sync::Mutex<Receive>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(super) mark: u32,
}

#[derive(Debug)]
struct Receive {
    bytes: Vec<u8>,
    pending: Option<quinn::udp::RecvMeta>,
    offset: usize,
}

#[derive(Debug)]
pub(super) struct Received {
    pub(super) len: usize,
    pub(super) remote: SocketAddr,
    pub(super) local: SocketAddr,
}

impl Socket {
    pub(super) async fn bind(address: SocketAddr) -> io::Result<Self> {
        let socket = tokio::net::UdpSocket::bind(address).await?.into_std()?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let mark = socket2::SockRef::from(&socket).mark()?;
        let io = quinn::TokioRuntime.wrap_udp_socket(socket)?;
        let receive_capacity = batch_capacity(io.max_receive_segments())?;
        Ok(Self {
            io,
            receive: tokio::sync::Mutex::new(Receive {
                bytes: vec![0; receive_capacity],
                pending: None,
                offset: 0,
            }),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            mark,
        })
    }

    pub(super) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    pub(super) async fn send_to(&self, bytes: &[u8], remote: SocketAddr) -> io::Result<usize> {
        send(&self.io, bytes, remote, None, None).await
    }

    pub(super) async fn recv_from(&self, bytes: &mut [u8]) -> io::Result<Received> {
        let mut receive = self.receive.lock().await;
        if receive.pending.is_none() {
            let mut meta = [quinn::udp::RecvMeta::default()];
            futures::future::poll_fn(|context| {
                let mut buffers = [IoSliceMut::new(&mut receive.bytes)];
                match self.io.poll_recv(context, &mut buffers, &mut meta) {
                    Poll::Ready(Ok(1)) => Poll::Ready(Ok(())),
                    Poll::Ready(Ok(_)) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid UDP receive batch count",
                    ))),
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await?;
            if meta[0].len > receive.bytes.len()
                || meta[0].stride > PACKET_PLANE_MAX_UDP_DATAGRAM_LEN
                || (meta[0].stride == 0 && meta[0].len > PACKET_PLANE_MAX_UDP_DATAGRAM_LEN)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid UDP receive length",
                ));
            }
            receive.offset = 0;
            receive.pending = Some(meta[0]);
        }
        // GRO is a socket/runtime detail. Never pass coalesced ciphertexts to
        // the packet decoder or lose the remaining datagrams on cancellation.
        let (len, meta) = receive.take(bytes);
        let mut local = self.local_addr()?;
        if let Some(destination) = meta.dst_ip {
            local.set_ip(destination.to_canonical());
        }
        if let (SocketAddr::V6(local), SocketAddr::V6(remote)) = (&mut local, meta.addr)
            && local.ip().is_unicast_link_local()
        {
            local.set_scope_id(remote.scope_id());
        }
        Ok(Received {
            len,
            remote: canonical(meta.addr),
            local: canonical(local),
        })
    }
}

fn batch_capacity(segments: usize) -> io::Result<usize> {
    if !(1..=MAX_RECEIVE_SEGMENTS).contains(&segments) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "UDP receive segment capacity exceeds bound",
        ));
    }
    Ok(PACKET_PLANE_MAX_UDP_DATAGRAM_LEN * segments)
}

impl Receive {
    fn take(&mut self, output: &mut [u8]) -> (usize, quinn::udp::RecvMeta) {
        let meta = self.pending.expect("a received datagram is pending");
        let stride = if meta.stride == 0 {
            meta.len
        } else {
            meta.stride
        };
        let end = self.offset.saturating_add(stride).min(meta.len);
        let len = (end - self.offset).min(output.len());
        output[..len].copy_from_slice(&self.bytes[self.offset..self.offset + len]);
        self.offset = end;
        if end == meta.len {
            self.pending = None;
        }
        (len, meta)
    }
}

pub(super) async fn send(
    socket: &Arc<dyn AsyncUdpSocket>,
    bytes: &[u8],
    destination: SocketAddr,
    source: Option<std::net::IpAddr>,
    interface: Option<std::num::NonZeroU32>,
) -> io::Result<usize> {
    send_before(socket, bytes, destination, source, interface, None).await
}

pub(super) async fn send_before(
    socket: &Arc<dyn AsyncUdpSocket>,
    bytes: &[u8],
    destination: SocketAddr,
    source: Option<std::net::IpAddr>,
    interface: Option<std::num::NonZeroU32>,
    deadline: Option<std::time::Instant>,
) -> io::Result<usize> {
    let transmit = quinn::udp::Transmit {
        destination,
        ecn: None,
        contents: bytes,
        segment_size: None,
        src_ip: source,
    };
    let mut writable = Arc::clone(socket).create_io_poller();
    loop {
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "UDP owner expired before transmission",
            ));
        }
        match socket.try_send_on_interface(&transmit, interface) {
            Ok(()) => return Ok(bytes.len()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                futures::future::poll_fn(|context| writable.as_mut().poll_writable(context))
                    .await?;
            }
            Err(error) => return Err(error),
        }
    }
}

pub(super) fn canonical(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(address) if address.ip().to_ipv4_mapped().is_some() => {
            SocketAddr::new(address.ip().to_canonical(), address.port())
        }
        address => address,
    }
}

#[cfg(test)]
mod tests;
