//! Preserve the browser's identity across an opaque, companion-scoped stream.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{
    AsyncRead, AsyncWrite, AsyncWriteExt as _, SinkExt as _, Stream as _, StreamExt as _,
    channel::{mpsc, oneshot},
    future::{Either, poll_fn, select},
};
use js_sys::{ArrayBuffer, Uint8Array};
use libp2p::{
    Multiaddr, PeerId, StreamProtocol,
    core::{
        muxing::StreamMuxerExt as _,
        upgrade::{OutboundUpgrade as _, Version, apply_outbound},
    },
    identity::Keypair,
    kad, noise, yamux,
};
use wasm_bindgen::{JsCast as _, prelude::*};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    BinaryType, Event, MessageEvent, Request, RequestInit, RequestMode, Response, WebSocket,
};

const START: &str = "/api/relay/inviter/locator";
const FRAME_BYTES: usize = 16 * 1024;
const MAX_CONTACTS: usize = 12;

pub(super) async fn publish(
    lease_id: &str,
    entrance: &Multiaddr,
    keys: &Keypair,
    key: &[u8],
    address: &Multiaddr,
) -> Result<(), JsError> {
    let work = async {
        if lease_id.len() != 32
            || !lease_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(io::Error::other("invalid invitation lease"));
        }
        let window = web_sys::window().ok_or_else(closed)?;
        let location = window.location();
        if location.protocol().map_err(|_| closed())? != "http:"
            || location.hostname().map_err(|_| closed())? != "127.0.0.1"
        {
            return Err(closed());
        }
        let host = location.host().map_err(|_| closed())?;
        let request = RequestInit::new();
        request.set_method("POST");
        request.set_mode(RequestMode::SameOrigin);
        request.set_body(&JsValue::from_str(
            &serde_json::json!({
                "lease_id": lease_id,
                "relay_entrance": entrance.to_string(),
                "provider_key": std::str::from_utf8(key).map_err(io::Error::other)?,
            })
            .to_string(),
        ));
        let request = Request::new_with_str_and_init(START, &request).map_err(|_| closed())?;
        request
            .headers()
            .set("Content-Type", "application/json")
            .map_err(|_| closed())?;
        let reply: Response = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|_| closed())?
            .dyn_into()
            .map_err(|_| closed())?;
        if !reply.ok() {
            return Err(closed());
        }
        let text = JsFuture::from(reply.text().map_err(|_| closed())?)
            .await
            .map_err(|_| closed())?
            .as_string()
            .ok_or_else(closed)?;
        if text.len() > 1024 {
            return Err(closed());
        }
        let peers: Vec<String> = serde_json::from_str(&text).map_err(io::Error::other)?;
        if peers.is_empty() || peers.len() > MAX_CONTACTS {
            return Err(closed());
        }
        let protocol = format!("p2p-vpn-locator.{lease_id}");
        let host = host.as_str();
        let protocol = protocol.as_str();
        let reader = Keypair::generate_ed25519();
        let reader = &reader;
        let provider = keys.public().to_peer_id();
        let mut results = futures::stream::iter(peers.into_iter().enumerate().map(
            |(index, peer)| async move {
                let peer: PeerId = peer.parse().map_err(io::Error::other)?;
                let url = format!("ws://{host}{START}/stream/{index}");
                let transfer = async {
                    let (written, wait_written) = oneshot::channel();
                    let (verified, wait_verified) = oneshot::channel();
                    let publish = exchange(
                        &url,
                        protocol,
                        keys,
                        peer,
                        key,
                        provider,
                        address,
                        Operation::Publish {
                            written,
                            wait_verified,
                        },
                    );
                    let readback = async {
                        wait_written.await.map_err(|_| closed())?;
                        exchange(
                            &format!("{url}/readback"),
                            protocol,
                            reader,
                            peer,
                            key,
                            provider,
                            address,
                            Operation::Readback,
                        )
                        .await?;
                        verified.send(()).map_err(|_| closed())
                    };
                    futures::try_join!(publish, readback).map(|_| ())
                };
                match select(
                    Box::pin(transfer),
                    gloo_timers::future::TimeoutFuture::new(2500),
                )
                .await
                {
                    Either::Left((result, _)) => result,
                    Either::Right(_) => Err(closed()),
                }
            },
        ))
        // Each pair holds a write and a read stream concurrently. Do not
        // occupy all companion slots with writers waiting for their readers.
        .buffer_unordered(1);
        let mut confirmed = 0;
        while let Some(result) = results.next().await {
            confirmed += usize::from(result.is_ok());
        }
        if confirmed == 0 {
            Err(closed())
        } else {
            Ok(())
        }
    };
    match select(
        Box::pin(work),
        gloo_timers::future::TimeoutFuture::new(15_000),
    )
    .await
    {
        Either::Left((Ok(()), _)) => Ok(()),
        _ => Err(JsError::new("No scoped DHT server confirmed the locator")),
    }
}

enum Operation {
    Publish {
        written: oneshot::Sender<()>,
        wait_verified: oneshot::Receiver<()>,
    },
    Readback,
}

async fn exchange(
    url: &str,
    protocol: &str,
    keys: &Keypair,
    expected: PeerId,
    key: &[u8],
    provider: PeerId,
    address: &Multiaddr,
    operation: Operation,
) -> io::Result<()> {
    let socket = WasmSocket(send_wrapper::SendWrapper::new(
        Socket::open(url, protocol).await?,
    ));
    let noise = noise::Config::new(keys).map_err(io::Error::other)?;
    let (peer, secured) = apply_outbound(socket, noise, Version::V1)
        .await
        .map_err(io::Error::other)?;
    if peer != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DHT peer identity mismatch",
        ));
    }
    let mut mux = apply_outbound(secured, yamux::Config::default(), Version::V1)
        .await
        .map_err(io::Error::other)?;
    let attempts = match &operation {
        Operation::Publish { .. } => 1,
        // The earlier one-way write may still be dispatched when we connect.
        Operation::Readback => 3,
    };
    for attempt in 0..attempts {
        let substream = poll_fn(|cx| mux.poll_outbound_unpin(cx))
            .await
            .map_err(io::Error::other)?;
        let request = async {
            let protocol = StreamProtocol::new(p2p_vpn::config::PUBLIC_IPFS_KADEMLIA_PROTOCOL);
            let (protocol, substream) = multistream_select::dialer_select_proto(
                substream,
                [protocol],
                multistream_select::Version::V1,
            )
            .await
            .map_err(io::Error::other)?;
            let mut stream = kad::ProtocolConfig::new(protocol.clone())
                .upgrade_outbound(substream, protocol)
                .await?;
            let key = kad::RecordKey::new(&key);
            match &operation {
                Operation::Publish { .. } => {
                    stream
                        .send(kad::KadRequestMsg::AddProvider {
                            key,
                            provider: kad::KadPeer {
                                node_id: keys.public().to_peer_id(),
                                multiaddrs: vec![address.clone()],
                                connection_ty: kad::ConnectionType::NotConnected,
                            },
                        })
                        .await?;
                    stream.close().await?;
                    Ok::<bool, io::Error>(true)
                }
                Operation::Readback => {
                    stream
                        .send(kad::KadRequestMsg::GetProviders { key })
                        .await?;
                    let Some(Ok(kad::KadResponseMsg::GetProviders { provider_peers, .. })) =
                        stream.next().await
                    else {
                        return Err(closed());
                    };
                    Ok(provider_peers.iter().any(|record| {
                        record.node_id == provider
                            && record.multiaddrs.as_slice() == std::slice::from_ref(address)
                    }))
                }
            }
        };
        let observed = match select(Box::pin(request), poll_fn(|cx| mux.poll_unpin(cx))).await {
            Either::Left((result, _)) => result?,
            Either::Right(_) => return Err(closed()),
        };
        if observed {
            if let Operation::Publish {
                written,
                wait_verified,
            } = operation
            {
                written.send(()).map_err(|_| closed())?;
                // Keep driving Yamux until the independent reader sees the
                // record. Closing the connection first can discard the server
                // handler's buffered one-way request.
                match select(wait_verified, poll_fn(|cx| mux.poll_unpin(cx))).await {
                    Either::Left((Ok(()), _)) => {}
                    _ => return Err(closed()),
                }
            }
            return poll_fn(|cx| mux.poll_close_unpin(cx))
                .await
                .map_err(io::Error::other);
        }
        if attempt + 1 < attempts {
            let _ = select(
                gloo_timers::future::TimeoutFuture::new(50),
                poll_fn(|cx| mux.poll_unpin(cx)),
            )
            .await;
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "DHT server did not retain the exact locator",
    ))
}

struct Socket {
    ws: WebSocket,
    input: mpsc::Receiver<Vec<u8>>,
    chunk: Vec<u8>,
    offset: usize,
    _message: Closure<dyn FnMut(MessageEvent)>,
    _end: Closure<dyn FnMut(Event)>,
}

// libp2p's upgrade traits require Send even in single-threaded browser WASM.
struct WasmSocket(send_wrapper::SendWrapper<Socket>);

impl AsyncRead for WasmSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.0).poll_read(cx, out)
    }
}

impl AsyncWrite for WasmSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_flush(cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_close(cx)
    }
}

impl Socket {
    async fn open(url: &str, protocol: &str) -> io::Result<Self> {
        let ws = WebSocket::new_with_str(url, protocol).map_err(|_| closed())?;
        ws.set_binary_type(BinaryType::Arraybuffer);
        let (mut sender, input) = mpsc::channel(8);
        let mut end = sender.clone();
        let receiver = ws.clone();
        let message = Closure::new(move |event: MessageEvent| {
            let Ok(data) = event.data().dyn_into::<ArrayBuffer>() else {
                let _ = receiver.close();
                return;
            };
            if data.byte_length() as usize > FRAME_BYTES
                || sender.try_send(Uint8Array::new(&data).to_vec()).is_err()
            {
                sender.close_channel();
                let _ = receiver.close();
            }
        });
        let ended = Closure::new(move |_: Event| end.close_channel());
        ws.set_onmessage(Some(message.as_ref().unchecked_ref()));
        ws.set_onclose(Some(ended.as_ref().unchecked_ref()));
        ws.set_onerror(Some(ended.as_ref().unchecked_ref()));
        let socket = Self {
            ws,
            input,
            chunk: Vec::new(),
            offset: 0,
            _message: message,
            _end: ended,
        };
        while socket.ws.ready_state() == WebSocket::CONNECTING {
            gloo_timers::future::TimeoutFuture::new(5).await;
        }
        if socket.ws.ready_state() != WebSocket::OPEN {
            return Err(closed());
        }
        Ok(socket)
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.ws.set_onmessage(None);
        self.ws.set_onclose(None);
        self.ws.set_onerror(None);
        let _ = self.ws.close();
    }
}

impl AsyncRead for Socket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if out.is_empty() {
            return Poll::Ready(Ok(0));
        }
        while self.offset == self.chunk.len() {
            match std::task::ready!(Pin::new(&mut self.input).poll_next(cx)) {
                Some(chunk) => {
                    self.chunk = chunk;
                    self.offset = 0;
                }
                None => return Poll::Ready(Ok(0)),
            }
        }
        let len = out.len().min(self.chunk.len() - self.offset);
        out[..len].copy_from_slice(&self.chunk[self.offset..self.offset + len]);
        self.offset += len;
        Poll::Ready(Ok(len))
    }
}

impl AsyncWrite for Socket {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.ws.ready_state() != WebSocket::OPEN || self.ws.buffered_amount() > 128 * 1024 {
            return Poll::Ready(Err(closed()));
        }
        let len = buf.len().min(FRAME_BYTES);
        Poll::Ready(
            self.ws
                .send_with_u8_array(&buf[..len])
                .map(|()| len)
                .map_err(|_| closed()),
        )
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.ws.close().map_err(|_| closed()))
    }
}

fn closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "scoped locator stream closed",
    )
}
