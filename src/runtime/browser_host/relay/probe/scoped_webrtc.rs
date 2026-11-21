//! Authenticate one exact WebRTC/HOP entrance through a scoped, private ingress.

use std::{
    convert::Infallible,
    future::{Ready, poll_fn, ready},
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
};

use libp2p::{
    Transport as _,
    core::{
        Endpoint,
        muxing::StreamMuxer as _,
        transport::{DialOpts as TransportDial, PortUse, TransportEvent},
        upgrade::{OutboundConnectionUpgrade, UpgradeInfo, Version, apply_outbound},
    },
};
use libp2p_webrtc::tokio::{Certificate, Transport};

use super::*;
use crate::runtime::{
    browser_relay_egress::probe::Ingress, physical_network::public_discovery::Scope,
};

#[cfg(test)]
mod tests;

pub(in crate::runtime::browser_host) struct Verified {
    _dialer: Transport,
    _ingress: Ingress,
}

struct Hop;

impl UpgradeInfo for Hop {
    type Info = libp2p::StreamProtocol;
    type InfoIter = [Self::Info; 1];

    fn protocol_info(&self) -> Self::InfoIter {
        [HOP_PROTOCOL_NAME]
    }
}

impl<C> OutboundConnectionUpgrade<C> for Hop {
    type Output = ();
    type Error = Infallible;
    type Future = Ready<Result<Self::Output, Self::Error>>;

    fn upgrade_outbound(self, _: C, _: Self::Info) -> Self::Future {
        ready(Ok(()))
    }
}

pub(in crate::runtime::browser_host) async fn authenticate(
    scope: Scope,
    relay: PeerId,
    entrance: &Multiaddr,
) -> io::Result<Verified> {
    let entrance = browser_address(relay, entrance.clone()).ok_or_else(unavailable)?;
    let key = Keypair::generate_ed25519();
    let cert = Certificate::generate(&mut rand_core::OsRng).map_err(io::Error::other)?;
    let mut dialer = Transport::new(key, cert).with_direct_v2();
    let listener = libp2p::core::transport::ListenerId::next();
    dialer
        .listen_on(
            listener,
            "/ip4/127.0.0.1/udp/0/webrtc-direct".parse().unwrap(),
        )
        .map_err(io::Error::other)?;
    let source = loop {
        match poll_fn(|cx| Pin::new(&mut dialer).poll(cx)).await {
            TransportEvent::NewAddress {
                listener_id,
                listen_addr,
            } if listener_id == listener => {
                let mut parts = listen_addr.iter();
                let (Some(Protocol::Ip4(ip)), Some(Protocol::Udp(port))) =
                    (parts.next(), parts.next())
                else {
                    return Err(unavailable());
                };
                if ip != Ipv4Addr::LOCALHOST {
                    return Err(unavailable());
                }
                break SocketAddr::from((ip, port));
            }
            TransportEvent::ListenerClosed { reason, .. } => {
                return Err(reason.err().map_or_else(unavailable, io::Error::other));
            }
            _ => {}
        }
    };
    let ingress = Ingress::prepare(scope, &entrance, source).await?;
    let dial = dialer
        .dial(
            ingress.address.clone(),
            TransportDial {
                role: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            },
        )
        .map_err(io::Error::other)?;
    let work = async {
        let (peer, mut connection) = dial.await.map_err(io::Error::other)?;
        if peer != relay {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wrong WebRTC relay identity",
            ));
        }
        let stream = poll_fn(|cx| Pin::new(&mut connection).poll_outbound(cx))
            .await
            .map_err(io::Error::other)?;
        // Negotiate the real HOP substream, but do not reserve on our probe PeerId.
        apply_outbound(stream, Hop, Version::V1)
            .await
            .map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))
    };
    ingress
        .while_driving(async {
            tokio::select! {
                biased;
                result = work => result,
                () = async {
                    loop {
                        // The vendored UDP mux advances when its transport is polled.
                        let _ = poll_fn(|cx| Pin::new(&mut dialer).poll(cx)).await;
                    }
                } => unreachable!(),
            }
        })
        .await?;
    Ok(Verified {
        _dialer: dialer,
        _ingress: ingress,
    })
}
