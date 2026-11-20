//! Same-origin admission for opaque, invitation-scoped DHT byte streams.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::{SinkExt as _, StreamExt as _};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message,
        handshake::derive_accept_key,
        protocol::{Role, WebSocketConfig},
    },
};
use tokio_util::compat::TokioAsyncReadCompatExt as _;

use super::*;
use crate::runtime::browser_host::relay::PublicationOperation;

const START: &str = "/api/relay/inviter/locator";
const STREAM: &str = "/api/relay/inviter/locator/stream/";
const PROTOCOL: &str = "p2p-vpn-locator.";
const FRAME_BYTES: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Start {
    lease_id: String,
    relay_entrance: String,
    provider_key: String,
}

pub(super) struct Upgrade {
    lease: String,
    index: usize,
    operation: PublicationOperation,
    accept: String,
}

pub(super) fn admit<'a>(
    head: &httparse::Request<'_, '_>,
    state: &'a State,
    origin: Option<&[u8]>,
    fetch_site: Option<&[u8]>,
    length: Option<usize>,
) -> Result<Option<Action<'a>>, Rejection> {
    let path = head.path.unwrap_or_default();
    let index = path.strip_prefix(STREAM);
    if path != START && index.is_none() {
        return Ok(None);
    }
    // Chromium's WebSocket handshake sets Origin but omits Fetch Metadata.
    if origin != Some(state.origin.as_bytes())
        || (index.is_none() && fetch_site != Some(b"same-origin"))
        || (index.is_some() && !matches!(fetch_site, None | Some(b"same-origin")))
    {
        return Err(FORBIDDEN);
    }
    if !state.assets.contains_key("/code-inviter.html") {
        return Err(NOT_FOUND);
    }
    let Some(index) = index else {
        if head.method != Some("POST") {
            return Err(METHOD);
        }
        if header(head, "Content-Type")? != Some(APPLICATION_JSON.as_bytes()) {
            return Err(WRONG_TYPE);
        }
        let length = length.filter(|n| *n > 0).ok_or(BAD_REQUEST)?;
        if length > MAX_RELAY_CONTROL_BODY_BYTES {
            return Err(TOO_LARGE);
        }
        return Ok(Some(Action::Lookup(LookupKind::StartPublication, length)));
    };
    if head.method != Some("GET") || length.is_some_and(|length| length != 0) {
        return Err(BAD_REQUEST);
    }
    let (index, operation) = match index.strip_suffix("/readback") {
        Some(index) => (index, PublicationOperation::Readback),
        None => (index, PublicationOperation::Publish),
    };
    let index: u8 = index.parse().map_err(|_| BAD_REQUEST)?;
    let connection = header(head, "Connection")?.unwrap_or_default();
    if !connection
        .split(|&b| b == b',')
        .any(|part| part.trim_ascii().eq_ignore_ascii_case(b"upgrade"))
        || !header(head, "Upgrade")?
            .is_some_and(|upgrade| upgrade.eq_ignore_ascii_case(b"websocket"))
        || header(head, "Sec-WebSocket-Version")? != Some(b"13")
    {
        return Err(BAD_REQUEST);
    }
    let key = header(head, "Sec-WebSocket-Key")?.ok_or(BAD_REQUEST)?;
    let mut decoded = [0; 18];
    if key.len() != 24 || STANDARD.decode_slice(key, &mut decoded) != Ok(16) {
        return Err(BAD_REQUEST);
    }
    let lease = header(head, "Sec-WebSocket-Protocol")?
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| value.strip_prefix(PROTOCOL))
        .filter(|id| {
            id.len() == 32
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
        .ok_or(BAD_REQUEST)?;
    Ok(Some(Action::PublicationStream(Upgrade {
        lease: lease.to_owned(),
        index: usize::from(index),
        operation,
        accept: derive_accept_key(key),
    })))
}

pub(super) async fn start(state: &State, query: Start) -> Result<Vec<u8>, Rejection> {
    let locator = query
        .provider_key
        .strip_prefix("/p2p-vpn/pairing-code/")
        .and_then(|rest| rest.strip_suffix("/providers/2"))
        .and_then(Locator::parse)
        .ok_or(BAD_REQUEST)?;
    let _permit = lookup_permit(state)?;
    let entrance = query.relay_entrance.parse().map_err(|_| BAD_REQUEST)?;
    let publication = state
        .relay
        .lease_manager()
        .begin_publication(
            &query.lease_id,
            &entrance,
            &state.protocol,
            &state.bootstrap,
            locator.key(KeySpace::Global).to_vec(),
        )
        .await
        .map_err(lookup_rejection)?;
    let peers = publication
        .peers()
        .map(|peer| peer.to_string())
        .collect::<Vec<_>>();
    Ok(json_body(&peers))
}

pub(super) async fn serve(mut socket: TcpStream, state: &State, upgrade: Upgrade) {
    let Ok(publication) = state.relay.lease_manager().publication(&upgrade.lease) else {
        respond_lookup(&mut socket, Err(RELAY_UNAVAILABLE)).await;
        return;
    };
    if publication.check(upgrade.index, upgrade.operation).is_err() {
        respond_lookup(&mut socket, Err(RELAY_UNAVAILABLE)).await;
        return;
    }
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: {PROTOCOL}{}\r\n\r\n",
        upgrade.accept, upgrade.lease,
    );
    if !matches!(
        timeout(IO_BUDGET, socket.write_all(response.as_bytes())).await,
        Ok(Ok(()))
    ) {
        return;
    }
    let config = WebSocketConfig::default()
        .read_buffer_size(FRAME_BYTES)
        .write_buffer_size(0)
        .max_write_buffer_size(2 * FRAME_BYTES)
        .max_frame_size(Some(FRAME_BYTES))
        .max_message_size(Some(FRAME_BYTES));
    let websocket = WebSocketStream::from_raw_socket(socket, Role::Server, Some(config)).await;
    let (mut outgoing, mut incoming) = websocket.split();
    let (bridge, ingress) = tokio::io::duplex(FRAME_BYTES);
    let (mut download, mut upload) = tokio::io::split(bridge);
    let receive = async {
        while let Some(message) = incoming.next().await {
            match message.map_err(io::Error::other)? {
                Message::Binary(bytes) => upload.write_all(&bytes).await?,
                Message::Close(_) => break,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "expected DHT stream bytes",
                    ));
                }
            }
        }
        upload.shutdown().await
    };
    let send = async {
        let mut buffer = [0; FRAME_BYTES];
        loop {
            let length = download.read(&mut buffer).await?;
            if length == 0 {
                break;
            }
            outgoing
                .send(Message::Binary(buffer[..length].to_vec().into()))
                .await
                .map_err(io::Error::other)?;
        }
        outgoing.close().await.map_err(io::Error::other)
    };
    let forward = publication.forward(upgrade.index, upgrade.operation, ingress.compat());
    let _ = tokio::try_join!(forward, receive, send);
}
