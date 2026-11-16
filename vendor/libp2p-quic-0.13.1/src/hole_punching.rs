use std::{
    convert::Infallible,
    net::{SocketAddr, UdpSocket},
    time::Duration,
};

use futures::{future::Either, FutureExt};
use rand::{distributions, Rng};

use crate::{provider::Provider, Error};

pub(crate) async fn selected_hole_puncher<P: Provider>(
    endpoint: quinn::Endpoint,
    socket: UdpSocket,
    remote: SocketAddr,
    timeout: Duration,
    policy: std::sync::Arc<dyn crate::SocketPolicy>,
    keep_alive: std::sync::Arc<std::sync::OnceLock<quinn::PreparedInterfaceSend>>,
) -> Error {
    let send = async move {
        let context = crate::transport::context(&socket, remote, libp2p_core::Endpoint::Dialer)?;
        let selection = policy.prepare(context).await?;
        crate::transport::selection_is_current(&socket, context, &selection)?;
        let sender =
            endpoint.prepare_send_on_interface(remote, selection.source, selection.interface)?;
        keep_alive
            .set(sender)
            .map_err(|_| std::io::Error::other("hole-punch I/O already prepared"))?;
        let sender = keep_alive.get().expect("prepared hole-punch I/O");
        loop {
            crate::transport::selection_is_current(&socket, context, &selection)?;
            let contents: Vec<u8> = rand::thread_rng()
                .sample_iter(distributions::Standard)
                .take(64)
                .collect();
            match sender.send(&contents) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err::<Infallible, std::io::Error>(error),
            }
            let delay = Duration::from_millis(rand::thread_rng().gen_range(10..=200));
            P::sleep(delay).await;
        }
    }
    .boxed();
    match futures::future::select(P::sleep(timeout), send).await {
        Either::Left(_) => Error::HandshakeTimedOut,
        Either::Right((Err(error), _)) => Error::Io(error),
        Either::Right((Ok(never), _)) => match never {},
    }
}

pub(crate) async fn hole_puncher<P: Provider>(
    socket: UdpSocket,
    remote_addr: SocketAddr,
    timeout_duration: Duration,
) -> Error {
    let punch_holes_future = punch_holes::<P>(socket, remote_addr);
    futures::pin_mut!(punch_holes_future);
    match futures::future::select(P::sleep(timeout_duration), punch_holes_future).await {
        Either::Left(_) => Error::HandshakeTimedOut,
        Either::Right((Err(hole_punch_err), _)) => hole_punch_err,
        Either::Right((Ok(never), _)) => match never {},
    }
}

async fn punch_holes<P: Provider>(
    socket: UdpSocket,
    remote_addr: SocketAddr,
) -> Result<Infallible, Error> {
    loop {
        let contents: Vec<u8> = rand::thread_rng()
            .sample_iter(distributions::Standard)
            .take(64)
            .collect();

        tracing::trace!("Sending random UDP packet to {remote_addr}");

        P::send_to(&socket, &contents, remote_addr).await?;

        let sleep_duration = Duration::from_millis(rand::thread_rng().gen_range(10..=200));
        P::sleep(sleep_duration).await;
    }
}
