//! One standard ADD_PROVIDER substream on the confirmed relay connection.

use std::{
    convert::Infallible,
    fmt, io,
    task::{Context, Poll},
    time::Duration,
};

use futures::{FutureExt as _, SinkExt as _, channel::oneshot, future::BoxFuture};
use libp2p::{
    Multiaddr, PeerId, StreamProtocol,
    core::{
        Endpoint,
        transport::PortUse,
        upgrade::{DeniedUpgrade, OutboundUpgrade, UpgradeInfo},
    },
    kad::{self, KadPeer, KadRequestMsg, ProtocolConfig},
    swarm::{
        ConnectionDenied, ConnectionId, NetworkBehaviour, NotifyHandler, Stream, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm,
        behaviour::FromSwarm,
        handler::{OneShotHandler, OneShotHandlerConfig, SubstreamProtocol},
    },
};
use p2p_vpn::{config::PUBLIC_IPFS_KADEMLIA_PROTOCOL, pairing_code::pairing_code_v2_provider_key};

pub(crate) struct Announcement {
    key: kad::RecordKey,
    provider: KadPeer,
    canceled: oneshot::Receiver<()>,
}

impl fmt::Debug for Announcement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocatorAnnouncement")
    }
}

#[derive(Debug)]
pub(crate) struct Sent;

impl From<Infallible> for Sent {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl UpgradeInfo for Announcement {
    type Info = StreamProtocol;
    type InfoIter = std::iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once(StreamProtocol::new(PUBLIC_IPFS_KADEMLIA_PROTOCOL))
    }
}

impl OutboundUpgrade<Stream> for Announcement {
    type Output = Sent;
    type Error = io::Error;
    type Future = BoxFuture<'static, io::Result<Sent>>;

    fn upgrade_outbound(self, stream: Stream, protocol: Self::Info) -> Self::Future {
        Box::pin(async move {
            let send = async {
                let mut stream = ProtocolConfig::new(protocol.clone())
                    .upgrade_outbound(stream, protocol)
                    .await?;
                stream
                    .send(KadRequestMsg::AddProvider {
                        key: self.key,
                        provider: self.provider,
                    })
                    .await?;
                stream.close().await.map(|()| Sent)
            }
            .fuse();
            let canceled = self.canceled.fuse();
            futures::pin_mut!(send, canceled);
            futures::select_biased! {
                _ = canceled => Err(io::Error::from(io::ErrorKind::Interrupted)),
                result = send => result,
            }
        })
    }
}

#[derive(Default)]
pub(crate) struct Publisher {
    pending: Option<(PeerId, ConnectionId, Announcement)>,
    target: Option<(PeerId, ConnectionId)>,
    cancel: Option<oneshot::Sender<()>>,
    finished: Option<bool>,
}

impl Publisher {
    pub(super) fn start(
        &mut self,
        relay: PeerId,
        connection: ConnectionId,
        local: PeerId,
        address: Multiaddr,
        locator: &str,
    ) -> bool {
        if self.target.is_some() {
            return false;
        }
        let key = pairing_code_v2_provider_key(locator);
        // The fixed v2 locator fits the native public lookup's unchanged-key
        // budget. Do not advertise a key that a native lookup would hash.
        if key.len() > 80 {
            return false;
        }
        let (cancel, canceled) = oneshot::channel();
        self.target = Some((relay, connection));
        self.cancel = Some(cancel);
        self.pending = Some((
            relay,
            connection,
            Announcement {
                key: kad::RecordKey::new(&key),
                provider: KadPeer {
                    node_id: local,
                    multiaddrs: vec![address],
                    connection_ty: kad::ConnectionType::NotConnected,
                },
                canceled,
            },
        ));
        true
    }

    pub(super) fn result(&self) -> Option<bool> {
        self.finished
    }

    pub(super) fn cancel(&mut self) {
        self.pending = None;
        self.cancel = None;
    }
}

fn handler() -> OneShotHandler<DeniedUpgrade, Announcement, Sent> {
    OneShotHandler::new(
        SubstreamProtocol::new(DeniedUpgrade, ()),
        OneShotHandlerConfig {
            outbound_substream_timeout: Duration::from_secs(2),
            max_dial_negotiated: 1,
        },
    )
}

impl NetworkBehaviour for Publisher {
    type ConnectionHandler = OneShotHandler<DeniedUpgrade, Announcement, Sent>;
    type ToSwarm = std::convert::Infallible;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(handler())
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(handler())
    }

    fn on_swarm_event(&mut self, event: FromSwarm<'_>) {
        if let FromSwarm::ConnectionClosed(event) = event
            && self.target == Some((event.peer_id, event.connection_id))
            && self.finished.is_none()
        {
            self.cancel();
            self.finished = Some(false);
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        if self.target == Some((peer, id)) {
            self.finished = Some(event.is_ok());
            self.cancel();
        }
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        match self.pending.take() {
            Some((peer_id, id, event)) => Poll::Ready(ToSwarm::NotifyHandler {
                peer_id,
                handler: NotifyHandler::One(id),
                event,
            }),
            None => Poll::Pending,
        }
    }
}
