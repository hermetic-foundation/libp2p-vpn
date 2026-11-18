use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
    time::Instant,
};

use tokio::{
    io::Interest,
    time::{sleep_until, Sleep},
};

use super::{AsyncTimer, AsyncUdpSocket, Runtime, UdpPollHelper, UdpRecvScope};

#[cfg(target_os = "linux")]
mod strict;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod network;

/// A Quinn runtime for Tokio
#[derive(Debug)]
pub struct TokioRuntime;

#[cfg(any(target_os = "linux", target_os = "android"))]
impl TokioRuntime {
    /// Wrap a caller-owned UDP socket already bound to the exact Network and
    /// concrete source. Apply ownership to all endpoint traffic, including
    /// stateless responses; do not create an unbound receive socket.
    pub fn wrap_bound_udp_socket(
        &self,
        sock: std::net::UdpSocket,
        source: std::net::IpAddr,
        interface: std::num::NonZeroU32,
        binding: Arc<dyn super::UdpSocketBinding>,
    ) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let selected = network::Selection::for_bound(sock.local_addr()?, source, interface, binding)?;
        Ok(Arc::new(UdpSocket {
            inner: udp::UdpSocketState::new((&sock).into())?,
            io: tokio::net::UdpSocket::from_std(sock)?,
            #[cfg(target_os = "linux")]
            routes: strict::Routes::default(),
            #[cfg(target_os = "linux")]
            selected: None,
            networks: network::Networks::default(),
            network_selection: Some(selected),
        }))
    }
}

impl Runtime for TokioRuntime {
    fn new_timer(&self, t: Instant) -> Pin<Box<dyn AsyncTimer>> {
        Box::pin(sleep_until(t.into()))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }

    fn wrap_udp_socket(&self, sock: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        Ok(Arc::new(UdpSocket {
            inner: udp::UdpSocketState::new((&sock).into())?,
            io: tokio::net::UdpSocket::from_std(sock)?,
            #[cfg(target_os = "linux")]
            routes: strict::Routes::default(),
            #[cfg(target_os = "linux")]
            selected: None,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            networks: network::Networks::default(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            network_selection: None,
        }))
    }

    fn now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }
}

impl AsyncTimer for Sleep {
    fn reset(self: Pin<&mut Self>, t: Instant) {
        Self::reset(self, t.into())
    }
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        Future::poll(self, cx)
    }
}

#[derive(Debug)]
struct UdpSocket {
    io: tokio::net::UdpSocket,
    inner: udp::UdpSocketState,
    #[cfg(target_os = "linux")]
    routes: strict::Routes,
    #[cfg(target_os = "linux")]
    selected: Option<strict::Route>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    networks: network::Networks,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    network_selection: Option<network::Selection>,
}

impl UdpSocket {
    // The original socket and Linux strict companions remain a separate fan-in.
    fn poll_recv_core(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.poll_recv_core_scoped(cx, bufs, meta, None)
    }

    fn poll_recv_core_scoped(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
        scopes: Option<&mut [UdpRecvScope]>,
    ) -> Poll<io::Result<usize>> {
        #[cfg(target_os = "linux")]
        if self.selected.is_none() {
            if scopes.is_none() {
                return self.routes.poll_recv(self, cx, bufs, meta);
            }
            return self.routes.poll_recv_scoped(self, cx, bufs, meta, scopes);
        }
        match scopes {
            Some(scopes) => self.poll_recv_single_scoped(cx, bufs, meta, Some(scopes)),
            None => self.poll_recv_single(cx, bufs, meta),
        }
    }

    fn poll_recv_single(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.poll_recv_single_scoped(cx, bufs, meta, None)
    }

    fn poll_recv_single_scoped(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
        mut scopes: Option<&mut [UdpRecvScope]>,
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            let result = self.io.try_io(Interest::READABLE, || {
                let Some(scopes) = scopes.as_deref_mut() else {
                    return self.inner.recv((&self.io).into(), bufs, meta);
                };
                let mut interfaces = [None; udp::BATCH_SIZE];
                let count = bufs
                    .len()
                    .min(meta.len())
                    .min(scopes.len())
                    .min(udp::BATCH_SIZE);
                let received = self.inner.recv_scoped(
                    (&self.io).into(),
                    &mut bufs[..count],
                    meta,
                    &mut interfaces[..count],
                )?;
                #[cfg(not(any(target_os = "linux", target_os = "android")))]
                let network = None;
                #[cfg(any(target_os = "linux", target_os = "android"))]
                let network = self
                    .network_selection
                    .as_ref()
                    .map(network::Selection::identity);
                for (scope, interface_index) in scopes[..received].iter_mut().zip(interfaces) {
                    *scope = UdpRecvScope {
                        network,
                        interface_index,
                    };
                }
                Ok(received)
            });
            match result {
                Ok(received) => return Poll::Ready(Ok(received)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) if scopes.is_some() => return Poll::Ready(Err(error)),
                Err(_) => continue,
            }
        }
    }
}

impl AsyncUdpSocket for UdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn super::UdpPoller>> {
        Box::pin(UdpPollHelper::new(move || {
            let socket = self.clone();
            async move { socket.io.writable().await }
        }))
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(selection) = &self.network_selection {
            return selection.send(self, transmit, None);
        }
        #[cfg(target_os = "linux")]
        if let Some(selected) = self.selected {
            selected.validate(transmit, None)?;
        }
        let result = self.io.try_io(Interest::WRITABLE, || {
            self.inner.send((&self.io).into(), transmit)
        });
        #[cfg(target_os = "linux")]
        if self.selected.is_some()
            && result
                .as_ref()
                .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
        {
            // A fresh companion may not have received its first Mio readiness event.
            return self.inner.send((&self.io).into(), transmit);
        }
        result
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn supports_interface_selection(&self) -> bool {
        true
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn transmit_socket(
        &self,
        source: std::net::IpAddr,
        interface: std::num::NonZeroU32,
    ) -> io::Result<Option<Arc<dyn AsyncUdpSocket>>> {
        if self.network_selection.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot discard immutable Network binding",
            ));
        }
        #[cfg(target_os = "linux")]
        return self.routes.acquire(self, source, interface);
        #[cfg(target_os = "android")]
        {
            let _ = interface;
            if source.is_ipv6() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "strict IPv6 interface isolation is unsupported",
                ));
            }
            Ok(None)
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn transmit_socket_with_binding(
        &self,
        source: std::net::IpAddr,
        interface: std::num::NonZeroU32,
        binding: Option<Arc<dyn super::UdpSocketBinding>>,
    ) -> io::Result<Option<Arc<dyn AsyncUdpSocket>>> {
        match binding {
            Some(binding) => self.networks.acquire(self, source, interface, binding),
            None if self.network_selection.is_some() => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot discard immutable Network binding",
            )),
            None => self.transmit_socket(source, interface),
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn try_send_on_interface(
        &self,
        transmit: &udp::Transmit,
        interface: Option<std::num::NonZeroU32>,
    ) -> io::Result<()> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(selection) = &self.network_selection {
            return selection.send(self, transmit, interface);
        }
        #[cfg(target_os = "linux")]
        if let Some(interface) = interface {
            if let Some(selected) = self.selected {
                selected.validate(transmit, Some(interface))?;
            } else if let Some(std::net::IpAddr::V6(source)) = transmit.src_ip {
                if source.to_ipv4_mapped().is_none() {
                    return self
                        .routes
                        .live(strict::Route { source, interface })?
                        .try_send_on_interface(transmit, Some(interface));
                }
            } else if transmit.destination.is_ipv6()
                && transmit.destination.ip().to_canonical().is_ipv6()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "selected IPv6 send requires a concrete source",
                ));
            }
        }
        match interface {
            None => self.try_send(transmit),
            Some(interface) => {
                let send = || {
                    self.inner
                        .send_on_interface((&self.io).into(), transmit, interface)
                };
                let result = self.io.try_io(Interest::WRITABLE, send);
                #[cfg(target_os = "linux")]
                if self.selected.is_some()
                    && result
                        .as_ref()
                        .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
                {
                    return send();
                }
                result
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        return self.networks.poll_recv(self, cx, bufs, meta);
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        self.poll_recv_core(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.io.local_addr()
    }

    fn poll_recv_scoped(
        &self,
        cx: &mut Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
        scopes: &mut [UdpRecvScope],
    ) -> Poll<io::Result<usize>> {
        scopes.fill(UdpRecvScope::default());
        if bufs.is_empty() || meta.is_empty() || scopes.len() < bufs.len().min(meta.len()) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "insufficient UDP receive scope slots",
            )));
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        return self
            .networks
            .poll_recv_scoped(self, cx, bufs, meta, Some(scopes));
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        self.poll_recv_core_scoped(cx, bufs, meta, Some(scopes))
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.gro_segments()
    }
}
