//! Per-dial proof shared by DNS, every resolved address, and established I/O.

use super::platform::{
    SocketProtocol,
    egress::{Egress, RouteEpoch, RouteLease},
};
use futures::{AsyncRead, AsyncWrite};
use std::{
    io,
    net::{IpAddr, Shutdown, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

#[cfg(target_os = "linux")]
use super::linux::egress::public_discovery::DefaultLink;
#[cfg(target_os = "linux")]
use tokio::sync::OnceCell;

#[derive(Clone, Debug)]
pub(crate) struct Scope {
    epoch: RouteEpoch,
    #[cfg(target_os = "linux")]
    link: Arc<OnceCell<DefaultLink>>,
    egress: Arc<Egress>,
}

tokio::task_local! {
    pub(crate) static DIAL: Scope;
}

pub(crate) fn current() -> Option<Scope> {
    DIAL.try_with(Clone::clone).ok()
}

impl Scope {
    pub(crate) fn new(egress: Arc<Egress>) -> io::Result<Self> {
        Ok(Self {
            epoch: egress.current_epoch()?,
            #[cfg(target_os = "linux")]
            link: Arc::new(OnceCell::new()),
            egress,
        })
    }

    pub(crate) async fn prepare_socket(
        &self,
        destination: SocketAddr,
        protocol: SocketProtocol,
    ) -> io::Result<(socket2::Socket, RouteLease)> {
        #[cfg(target_os = "linux")]
        let selection = self;
        #[cfg(target_os = "android")]
        let selection = self.epoch();
        self.egress
            .prepare_public_socket(selection, destination, protocol)
            .await
    }

    pub(crate) async fn invalidated(&self) {
        self.epoch.invalidated().await;
    }

    pub(crate) fn epoch(&self) -> &RouteEpoch {
        &self.epoch
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn link(&self) -> io::Result<&DefaultLink> {
        self.check()?;
        let link = self
            .link
            .get_or_try_init(|| self.egress.public_default_link(&self.epoch))
            .await?;
        self.check()?;
        Ok(link)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn initialized_link(&self) -> io::Result<&DefaultLink> {
        self.link.get().ok_or_else(stale)
    }

    pub(crate) fn is_current(&self) -> bool {
        self.epoch.is_current()
    }

    pub(crate) fn check(&self) -> io::Result<()> {
        self.with_current(|| Ok(()))
    }

    pub(crate) fn with_current<T>(&self, action: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        self.epoch.with_current(action)
    }
}

/// Revokes application writes and shuts the live TCP socket down even if the
/// encrypted connection is waiting for input when its selection is replaced.
pub(crate) struct GuardedIo<T> {
    inner: T,
    scope: Option<Scope>,
    shutdown: Option<tokio::task::JoinHandle<()>>,
}

impl<T> GuardedIo<T> {
    pub(crate) fn unrestricted(inner: T) -> Self {
        Self {
            inner,
            scope: None,
            shutdown: None,
        }
    }

    pub(crate) fn new(inner: T, scope: Scope, socket: socket2::Socket) -> io::Result<Self> {
        scope.check()?;
        let monitor = scope.clone();
        let shutdown = tokio::spawn(async move {
            monitor.invalidated().await;
            let _ = socket.shutdown(Shutdown::Both);
        });
        Ok(Self {
            inner,
            scope: Some(scope),
            shutdown: Some(shutdown),
        })
    }

    fn poll_current<R>(
        &mut self,
        poll: impl FnOnce(Pin<&mut T>) -> Poll<io::Result<R>>,
    ) -> Poll<io::Result<R>>
    where
        T: Unpin,
    {
        let inner = Pin::new(&mut self.inner);
        match &self.scope {
            Some(scope) => scope
                .with_current(|| Ok(poll(inner)))
                .unwrap_or_else(|error| Poll::Ready(Err(error))),
            None => poll(inner),
        }
    }
}

impl<T> Drop for GuardedIo<T> {
    fn drop(&mut self) {
        if let Some(task) = &self.shutdown {
            task.abort();
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for GuardedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_current(|stream| stream.poll_read(cx, buf))
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        self.poll_current(|stream| stream.poll_read_vectored(cx, bufs))
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for GuardedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_current(|stream| stream.poll_write(cx, buf))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.poll_current(|stream| stream.poll_write_vectored(cx, bufs))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_current(|stream| stream.poll_flush(cx))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_current(|stream| stream.poll_close(cx))
    }
}

pub(super) fn stale() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "public discovery physical network changed",
    )
}

pub(crate) fn valid_destination(address: SocketAddr) -> bool {
    let ip = address.ip().to_canonical();
    address.port() != 0
        && !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !matches!(ip, IpAddr::V4(ip) if ip.is_broadcast() || ip.is_link_local())
        && !matches!(ip, IpAddr::V6(ip) if ip.is_unicast_link_local())
}

pub(crate) async fn connect_tcp(
    socket: socket2::Socket,
    destination: SocketAddr,
    scope: &Scope,
) -> io::Result<tokio::net::TcpStream> {
    let socket = tokio::net::TcpSocket::from_std_stream(socket.into());
    let connection = socket.connect(destination);
    tokio::pin!(connection);
    tokio::select! {
        biased;
        () = scope.invalidated() => Err(stale()),
        result = futures::future::poll_fn(|cx| {
            use std::future::Future as _;
            scope.with_current(|| Ok(connection.as_mut().poll(cx)))
                .unwrap_or_else(|error| Poll::Ready(Err(error)))
        }) => result,
    }
}
