//! Per-operation UDP ingress for an already authorized browser relay circuit.
//! WebRTC DTLS, libp2p Noise and circuit negotiation remain end to end.

use std::{
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use libp2p::{Multiaddr, multiaddr::Protocol};
use socket2::{SockAddr, SockRef};
use tokio::{
    net::UdpSocket,
    time::{Instant, sleep_until},
};

use super::physical_network::{
    platform::{
        SocketProtocol,
        egress::{RouteLease, canonical_socket_address},
    },
    public_discovery::{Scope, valid_destination},
};

const MAX_DATAGRAM: usize = 2048;
const OPERATION_LIMITS: Limits = Limits {
    idle: Duration::from_secs(30),
    lifetime: Duration::from_secs(120),
};

#[derive(Clone, Copy)]
struct Limits {
    idle: Duration,
    lifetime: Duration,
}

/// The host must first authorize the requested relay and destination. Never
/// expose this to caller-supplied addresses before that check. The input must
/// pin the outer WebRTC certificate, relay identity and circuit destination.
///
/// Pass only the returned candidate to the browser, and drive the returned
/// future alongside that operation. Drop it on cancellation, completion, or
/// authorization loss. Its first successfully forwarded loopback source wins
/// the client tuple; loopback is not authentication of a local process. Keep
/// the candidate private to the operation and isolate untrusted local clients.
pub(crate) async fn prepare(
    scope: Scope,
    authorized_route: &Multiaddr,
) -> io::Result<(
    Multiaddr,
    impl Future<Output = io::Result<()>> + Send + use<>,
)> {
    prepare_with_limits(scope, authorized_route, OPERATION_LIMITS).await
}

async fn prepare_with_limits(
    scope: Scope,
    authorized_route: &Multiaddr,
    limits: Limits,
) -> io::Result<(
    Multiaddr,
    impl Future<Output = io::Result<()>> + Send + use<>,
)> {
    let (destination, suffix) = pinned_relay(authorized_route)?;
    let (socket, lease) = scope
        .prepare_socket(destination, SocketProtocol::Udp)
        .await?;
    scope.with_current(|| socket.connect(&SockAddr::from(destination)))?;
    let uplink = UdpSocket::from_std(socket.into())?;
    let local = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = local.local_addr()?.port();
    // Build the browser candidate from the original checked suffix. No relay,
    // certificate or destination value can be supplied by the local UDP client.
    let mut candidate = Multiaddr::empty()
        .with(Protocol::Ip4(Ipv4Addr::LOCALHOST))
        .with(Protocol::Udp(port));
    for protocol in &suffix {
        candidate.push(protocol);
    }
    scope.check()?;
    let started = Instant::now();
    Ok((
        candidate,
        forward(scope, lease, local, uplink, started, limits),
    ))
}

fn pinned_relay(route: &Multiaddr) -> io::Result<(SocketAddr, Multiaddr)> {
    fn invalid() -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a numeric pinned WebRTC Direct relay circuit",
        )
    }

    let mut parts = route.iter();
    let ip = match parts.next() {
        Some(Protocol::Ip4(ip)) => ip.into(),
        Some(Protocol::Ip6(ip)) => ip.into(),
        _ => return Err(invalid()),
    };
    let (
        Some(Protocol::Udp(port)),
        Some(Protocol::WebRTCDirect),
        Some(Protocol::Certhash(cert)),
        Some(Protocol::P2p(relay)),
        Some(Protocol::P2pCircuit),
        Some(Protocol::P2p(peer)),
        None,
    ) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    )
    else {
        return Err(invalid());
    };
    let destination = canonical_socket_address(SocketAddr::new(ip, port));
    if !valid_destination(destination) || cert.code() != 0x12 || cert.size() != 32 || relay == peer
    {
        return Err(invalid());
    }
    let suffix = Multiaddr::empty()
        .with(Protocol::WebRTCDirect)
        .with(Protocol::Certhash(cert))
        .with(Protocol::P2p(relay))
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(peer));
    Ok((destination, suffix))
}

enum Datagram {
    Local(usize, SocketAddr),
    Relay(usize),
}

async fn forward(
    scope: Scope,
    _lease: RouteLease,
    local: UdpSocket,
    uplink: UdpSocket,
    started: Instant,
    limits: Limits,
) -> io::Result<()> {
    let hard_end = started + limits.lifetime;
    let mut idle_end = started + limits.idle;
    let deadline = sleep_until(idle_end.min(hard_end));
    tokio::pin!(deadline);
    let mut client = None;
    // An extra byte detects truncation so an oversized input is never relayed.
    let mut local_buf = [0; MAX_DATAGRAM + 1];
    let mut relay_buf = [0; MAX_DATAGRAM + 1];

    loop {
        let packet = tokio::select! {
            biased;
            () = scope.invalidated() => {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "browser relay egress route changed"));
            }
            () = &mut deadline => return Err(timeout_error(idle_end, hard_end)),
            packet = async {
                tokio::select! {
                    result = local.recv_from(&mut local_buf) => result.map(|(len, source)| Datagram::Local(len, source)),
                    result = uplink.recv(&mut relay_buf) => result.map(Datagram::Relay),
                }
            } => packet?,
        };

        let sent = scope.with_current(|| {
            if Instant::now() >= idle_end.min(hard_end) {
                return Err(timeout_error(idle_end, hard_end));
            }
            match packet {
                Datagram::Local(len, source)
                    if (1..=MAX_DATAGRAM).contains(&len)
                        && source.ip().is_loopback()
                        && client.is_none_or(|owned| owned == source) =>
                {
                    let sent = sent_datagram(SockRef::from(&uplink).send(&local_buf[..len]), len)?;
                    if sent {
                        client = Some(source);
                    }
                    Ok(sent)
                }
                Datagram::Relay(len) if (1..=MAX_DATAGRAM).contains(&len) => {
                    if let Some(target) = client {
                        sent_datagram(
                            SockRef::from(&local)
                                .send_to(&relay_buf[..len], &SockAddr::from(target)),
                            len,
                        )
                    } else {
                        Ok(false)
                    }
                }
                _ => Ok(false),
            }
        })?;
        if sent {
            idle_end = Instant::now() + limits.idle;
            deadline.as_mut().reset(idle_end.min(hard_end));
        }
    }
}

fn timeout_error(idle_end: Instant, hard_end: Instant) -> io::Error {
    let reason = if hard_end <= idle_end {
        "browser relay egress lifetime expired"
    } else {
        "browser relay egress idle timeout"
    };
    io::Error::new(io::ErrorKind::TimedOut, reason)
}

fn sent_datagram(result: io::Result<usize>, expected: usize) -> io::Result<bool> {
    match result {
        Ok(sent) if sent == expected => Ok(true),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "partial browser relay datagram",
        )),
        // UDP is lossy; do not add an application queue or wait with the route
        // generation held. Only a successful datagram renews the idle deadline.
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
#[path = "browser_relay_egress/tests.rs"]
mod tests;
