//! Same-origin loopback server for trusted browser assets and one-shot discovery.

use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read as _},
    net::Ipv4Addr,
    path::Path,
    sync::Arc,
    time::Duration,
};

use libp2p::{Multiaddr, StreamProtocol};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};

use crate::config::{BootstrapPeerConfig, PUBLIC_IPFS_KADEMLIA_PROTOCOL};
use crate::runtime::browser_lan;

use super::{
    DiscoveryRequest, MAX_BOOTSTRAP_ADDRESSES, bootstrap_addresses, discover,
    pairing::{self, KeySpace, Locator},
    relay::{Gateway, LeaseReply, Resolution},
    validate_scope,
};

const DISCOVERY_PATH: &str = "/api/discovery";
const MARKER: &str = r#"<meta name="p2p-vpn-discovery" content="/api/discovery">"#;
const PAIRING_PATH: &str = "/api/pairing/locator";
const SCOPED_PAIRING_PATH: &str = "/api/pairing/locator/scoped";
const PAIRING_LAN_PATH: &str = "/api/pairing/lan";
const RELAY_RELEASE_PATH: &str = "/api/relay/release";
const PAIRING_MARKER: &str = r#"<meta name="p2p-vpn-pairing" content="/api/pairing/locator">"#;
const PAIRING_LAN_MARKER: &str = r#"<meta name="p2p-vpn-pairing-lan" content="/api/pairing/lan">"#;
const MAX_CONNECTIONS: usize = 16;
const MAX_LOOKUPS: usize = 2;
const MAX_HEADER_BYTES: usize = 8192;
const MAX_HEADERS: usize = 32;
const MAX_BODY_BYTES: usize = 8192;
const MAX_PAIRING_BODY_BYTES: usize = 128;
const MAX_ASSET_BYTES: usize = 32 * 1024 * 1024;
const IO_BUDGET: Duration = Duration::from_secs(5);
const APPLICATION_JSON: &str = "application/json";
const AVAILABILITY: &[u8] = br#"{"available":true,"kademlia":true,"lan":true}"#;
const ASSETS: &[(&str, &str)] = &[
    ("/app.html", "text/html; charset=utf-8"),
    ("/app.js", "text/javascript; charset=utf-8"),
    ("/app.css", "text/css; charset=utf-8"),
    ("/pkg/p2p_vpn_browser.js", "text/javascript; charset=utf-8"),
    ("/pkg/p2p_vpn_browser_bg.wasm", "application/wasm"),
    ("/pkg/logo.svg", "image/svg+xml"),
];

/// Local HTTP/1.1 companion for a built browser app. It is not a proxy.
pub struct Server {
    listener: TcpListener,
    state: Arc<State>,
}

struct State {
    host: String,
    origin: String,
    assets: HashMap<&'static str, Asset>,
    protocol: StreamProtocol,
    bootstrap: Vec<(libp2p::PeerId, Multiaddr)>,
    owned_interface: Option<String>,
    lookups: Semaphore,
    relay: Gateway,
}

struct Asset {
    mime: &'static str,
    bytes: Arc<[u8]>,
}

impl Server {
    /// Loads only the known app assets and binds to 127.0.0.1.
    /// Port zero selects a free local port.
    pub async fn bind(
        assets: &Path,
        port: u16,
        protocol: StreamProtocol,
        bootstrap: Vec<Multiaddr>,
        owned_interface: Option<String>,
    ) -> io::Result<Self> {
        Self::bind_with_approved_relays(
            assets,
            port,
            protocol,
            bootstrap,
            owned_interface,
            Vec::new(),
        )
        .await
    }

    /// Enables circuit preparation through exact operator-approved WebRTC relay entrances.
    pub async fn bind_with_approved_relays(
        assets: &Path,
        port: u16,
        protocol: StreamProtocol,
        bootstrap: Vec<Multiaddr>,
        owned_interface: Option<String>,
        approved_relays: Vec<Multiaddr>,
    ) -> io::Result<Self> {
        let bootstrap = bootstrap_addresses(&protocol, &bootstrap)?;
        let relay = Gateway::new(approved_relays)?;
        let assets = load_assets(assets)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        let address = listener.local_addr()?;
        let host = if address.port() == 80 {
            address.ip().to_string()
        } else {
            address.to_string()
        };
        let state = Arc::new(State {
            origin: format!("http://{host}"),
            host,
            assets,
            protocol,
            bootstrap,
            owned_interface,
            lookups: Semaphore::new(MAX_LOOKUPS),
            relay,
        });
        Ok(Self { listener, state })
    }

    #[must_use]
    pub fn origin(&self) -> &str {
        &self.state.origin
    }

    /// Serves until stopped. Dropping the future closes the listener and requests.
    pub async fn run(self) -> io::Result<()> {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                result = self.listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                    let (socket, _) = result?;
                    connections.spawn(handle(socket, Arc::clone(&self.state)));
                }
                finished = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(error)) = finished {
                        return Err(io::Error::other(error));
                    }
                }
            }
        }
    }
}

fn load_assets(root: &Path) -> io::Result<HashMap<&'static str, Asset>> {
    let mut assets = HashMap::new();
    let mut remaining = MAX_ASSET_BYTES;
    for &(name, mime) in ASSETS {
        let path = root.join(&name[1..]);
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid or oversized browser asset: {}", path.display()),
            )
        };
        let metadata = path.metadata()?;
        if !metadata.is_file() || metadata.len() > remaining as u64 {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        File::open(path.as_path())?
            .take(remaining as u64 + 1)
            .read_to_end(&mut bytes)?;
        if name == "/app.html" {
            let head_end = bytes
                .windows(b"</head>".len())
                .position(|window| window == b"</head>")
                .ok_or_else(invalid)?;
            bytes.splice(
                head_end..head_end,
                MARKER
                    .bytes()
                    .chain(PAIRING_MARKER.bytes())
                    .chain(PAIRING_LAN_MARKER.bytes()),
            );
        }
        remaining = remaining.checked_sub(bytes.len()).ok_or_else(invalid)?;
        assets.insert(
            name,
            Asset {
                mime,
                bytes: bytes.into(),
            },
        );
    }
    Ok(assets)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoveryQuery {
    network_name: String,
    peer: String,
    membership_tag: Option<String>,
    kademlia_protocol: Option<String>,
    #[serde(default)]
    bootstrap: Vec<BootstrapAddress>,
    kademlia: Option<bool>,
    lan: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapAddress {
    id: String,
    address: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairingQuery {
    locator: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseQuery {
    lease_id: String,
}

#[derive(Serialize)]
struct DiscoveryReply {
    addresses: Vec<String>,
}

enum Request<'a> {
    Asset(&'a Asset),
    Availability,
    Lookup(DiscoveryQuery),
    Pairing(KeySpace, PairingQuery),
    PairingLan,
    ReleaseRelay(ReleaseQuery),
}

enum LookupKind {
    Member,
    Pairing(KeySpace),
    PairingLan,
    ReleaseRelay,
}

enum Action<'a> {
    Asset(&'a Asset),
    Availability,
    Lookup(LookupKind, usize),
}

#[derive(Clone, Copy)]
struct Rejection(&'static str, &'static str);

const BAD_REQUEST: Rejection = Rejection("400 Bad Request", "invalid_request");
const FORBIDDEN: Rejection = Rejection("403 Forbidden", "wrong_origin");
const NOT_FOUND: Rejection = Rejection("404 Not Found", "not_found");
const METHOD: Rejection = Rejection("405 Method Not Allowed", "wrong_method");
const REQUEST_TIMEOUT: Rejection = Rejection("408 Request Timeout", "request_timeout");
const TOO_LARGE: Rejection = Rejection("413 Content Too Large", "request_too_large");
const WRONG_TYPE: Rejection = Rejection("415 Unsupported Media Type", "expected_json");
const LAN_UNAVAILABLE: Rejection =
    Rejection("503 Service Unavailable", "lan_discovery_unavailable");

async fn handle(mut socket: TcpStream, state: Arc<State>) {
    let result = match timeout(IO_BUDGET, read_request(&mut socket, &state)).await {
        Ok(Ok(Request::Asset(asset))) => {
            let _ = timeout(
                IO_BUDGET,
                respond(&mut socket, "200 OK", asset.mime, &asset.bytes),
            )
            .await;
            return;
        }
        Ok(Ok(Request::Availability)) => {
            let _ = timeout(
                IO_BUDGET,
                respond(&mut socket, "200 OK", APPLICATION_JSON, AVAILABILITY),
            )
            .await;
            return;
        }
        Ok(Ok(Request::Lookup(query))) => {
            match find(&state, query).await {
                Ok(reply) => {
                    if !respond_lookup(&mut socket, Ok(json_body(&reply))).await
                        && let Some(lease) = reply.relay
                    {
                        let _ = state.relay.release(&lease.relay_lease_id);
                    }
                }
                Err(error) => {
                    respond_lookup(&mut socket, Err(error)).await;
                }
            }
            return;
        }
        Ok(Ok(Request::Pairing(space, query))) => find_pairing(&state, space, &query.locator)
            .await
            .map(json_body),
        Ok(Ok(Request::PairingLan)) => find_pairing_lan(&state).await.map(json_body),
        Ok(Ok(Request::ReleaseRelay(query))) => release_relay(&state, &query).map(json_body),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(REQUEST_TIMEOUT),
    };
    respond_lookup(&mut socket, result).await;
}

async fn respond_lookup(socket: &mut TcpStream, result: Result<Vec<u8>, Rejection>) -> bool {
    let (status, bytes) = match result {
        Ok(body) => ("200 OK", body),
        Err(Rejection(status, code)) => (status, format!(r#"{{"error":"{code}"}}"#).into_bytes()),
    };
    timeout(IO_BUDGET, respond(socket, status, APPLICATION_JSON, &bytes))
        .await
        .is_ok_and(|result| result.is_ok())
}

fn json_body(reply: impl Serialize) -> Vec<u8> {
    serde_json::to_vec(&reply).expect("serializable discovery reply")
}

async fn read_request<'a>(
    socket: &mut TcpStream,
    state: &'a State,
) -> Result<Request<'a>, Rejection> {
    let mut buffer = [0; MAX_HEADER_BYTES];
    let mut used = 0;
    let (end, action) = loop {
        if used == buffer.len() {
            return Err(TOO_LARGE);
        }
        let n = socket
            .read(&mut buffer[used..])
            .await
            .map_err(|_| BAD_REQUEST)?;
        if n == 0 {
            return Err(BAD_REQUEST);
        }
        used += n;
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut head = httparse::Request::new(&mut headers);
        match head.parse(&buffer[..used]) {
            Ok(httparse::Status::Partial) => {}
            Ok(httparse::Status::Complete(end)) => break (end, admit(&head, state)?),
            Err(httparse::Error::TooManyHeaders) => return Err(TOO_LARGE),
            Err(_) => return Err(BAD_REQUEST),
        }
    };
    match action {
        Action::Asset(asset) => Ok(Request::Asset(asset)),
        Action::Availability => Ok(Request::Availability),
        Action::Lookup(kind, length) => {
            let mut body = [0; MAX_BODY_BYTES];
            let buffered = (used - end).min(length);
            body[..buffered].copy_from_slice(&buffer[end..end + buffered]);
            socket
                .read_exact(&mut body[buffered..length])
                .await
                .map_err(|_| BAD_REQUEST)?;
            let body = &body[..length];
            match kind {
                LookupKind::Member => serde_json::from_slice(body)
                    .map(Request::Lookup)
                    .map_err(|_| BAD_REQUEST),
                LookupKind::Pairing(space) => serde_json::from_slice(body)
                    .map(|query| Request::Pairing(space, query))
                    .map_err(|_| BAD_REQUEST),
                LookupKind::PairingLan => match serde_json::from_slice(body) {
                    Ok(serde_json::Value::Object(fields)) if fields.is_empty() => {
                        Ok(Request::PairingLan)
                    }
                    _ => Err(BAD_REQUEST),
                },
                LookupKind::ReleaseRelay => serde_json::from_slice(body)
                    .map(Request::ReleaseRelay)
                    .map_err(|_| BAD_REQUEST),
            }
        }
    }
}

fn admit<'a>(head: &httparse::Request<'_, '_>, state: &'a State) -> Result<Action<'a>, Rejection> {
    if head.version != Some(1) || header(head, "Host")? != Some(state.host.as_bytes()) {
        return Err(FORBIDDEN);
    }
    let origin = header(head, "Origin")?;
    let fetch_site = header(head, "Sec-Fetch-Site")?;
    if origin.is_some_and(|origin| origin != state.origin.as_bytes())
        || !matches!(fetch_site, None | Some(b"none" | b"same-origin"))
    {
        return Err(FORBIDDEN);
    }
    if header(head, "Transfer-Encoding")?.is_some() || header(head, "Expect")?.is_some() {
        return Err(BAD_REQUEST);
    }
    let length = header(head, "Content-Length")?
        .map(content_length)
        .transpose()?;
    match (head.method, head.path) {
        (
            Some("POST"),
            Some(
                path @ (DISCOVERY_PATH | PAIRING_PATH | SCOPED_PAIRING_PATH | PAIRING_LAN_PATH
                | RELAY_RELEASE_PATH),
            ),
        ) => {
            if origin != Some(state.origin.as_bytes()) || fetch_site == Some(b"none") {
                return Err(FORBIDDEN);
            }
            if header(head, "Content-Type")? != Some(APPLICATION_JSON.as_bytes()) {
                return Err(WRONG_TYPE);
            }
            let length = length.filter(|length| *length > 0).ok_or(BAD_REQUEST)?;
            let kind = match path {
                PAIRING_PATH => LookupKind::Pairing(KeySpace::Global),
                SCOPED_PAIRING_PATH => LookupKind::Pairing(KeySpace::Scoped),
                PAIRING_LAN_PATH => LookupKind::PairingLan,
                RELAY_RELEASE_PATH => LookupKind::ReleaseRelay,
                _ => LookupKind::Member,
            };
            if !matches!(kind, LookupKind::Member) && length > MAX_PAIRING_BODY_BYTES {
                return Err(TOO_LARGE);
            }
            Ok(Action::Lookup(kind, length))
        }
        (Some("GET"), Some(DISCOVERY_PATH)) if length.unwrap_or(0) == 0 => Ok(Action::Availability),
        (_, Some(DISCOVERY_PATH)) => Err(METHOD),
        (Some("GET"), Some(path)) if length.unwrap_or(0) == 0 => {
            let path = if path == "/" { "/app.html" } else { path };
            state.assets.get(path).map(Action::Asset).ok_or(NOT_FOUND)
        }
        _ => Err(NOT_FOUND),
    }
}

fn header<'a>(head: &httparse::Request<'_, 'a>, name: &str) -> Result<Option<&'a [u8]>, Rejection> {
    let mut values = head
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name));
    let only = values.next().map(|header| header.value);
    if values.next().is_some() {
        return Err(BAD_REQUEST);
    }
    Ok(only)
}

fn content_length(raw: &[u8]) -> Result<usize, Rejection> {
    if raw.is_empty() || !raw.iter().all(u8::is_ascii_digit) {
        return Err(BAD_REQUEST);
    }
    let size = std::str::from_utf8(raw)
        .map_err(|_| BAD_REQUEST)?
        .parse::<usize>()
        .map_err(|_| TOO_LARGE)?;
    if size > MAX_BODY_BYTES {
        return Err(TOO_LARGE);
    }
    Ok(size)
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum MemberSource {
    Lan,
    PublicDht,
}

#[derive(Serialize)]
struct MemberReply {
    #[serde(flatten)]
    discovery: DiscoveryReply,
    source: Option<MemberSource>,
    #[serde(flatten)]
    relay: Option<LeaseReply>,
}

fn member_reply(
    addresses: Vec<Multiaddr>,
    source: Option<MemberSource>,
    relay: Option<LeaseReply>,
) -> MemberReply {
    MemberReply {
        source: source.filter(|_| !addresses.is_empty() || relay.is_some()),
        discovery: discovery_reply(addresses),
        relay,
    }
}

async fn find(state: &State, query: DiscoveryQuery) -> Result<MemberReply, Rejection> {
    let peer = query.peer.parse().map_err(|_| BAD_REQUEST)?;
    validate_scope(&query.network_name, query.membership_tag.as_deref())
        .map_err(|_| BAD_REQUEST)?;
    let lan = query.lan.unwrap_or(true);
    let kademlia = query.kademlia.unwrap_or(true);
    if !lan && !kademlia {
        return Ok(member_reply(Vec::new(), None, None));
    }
    let _permit = lookup_permit(state)?;
    if lan {
        match browser_lan::discover(peer, state.owned_interface.as_deref()).await {
            Ok(addresses) if !addresses.is_empty() => {
                return Ok(member_reply(addresses, Some(MemberSource::Lan), None));
            }
            Err(_) if !kademlia => return Err(LAN_UNAVAILABLE),
            _ => {}
        }
    }
    if !kademlia {
        return Ok(member_reply(Vec::new(), None, None));
    }
    if query
        .kademlia_protocol
        .is_some_and(|protocol| protocol != state.protocol.as_ref())
    {
        return Err(Rejection("403 Forbidden", "protocol_not_enabled"));
    }
    let bootstrap = requested_bootstrap(state, query.bootstrap)?;
    let request = DiscoveryRequest {
        network_name: &query.network_name,
        membership_tag: query.membership_tag.as_deref(),
        peer,
        protocol: state.protocol.clone(),
        owned_interface: state.owned_interface.as_deref(),
        bootstrap,
    };
    let Resolution { addresses, relay } = if state.relay.enabled() {
        state
            .relay
            .resolve(request)
            .await
            .map_err(|error| match error.kind() {
                io::ErrorKind::WouldBlock => Rejection("429 Too Many Requests", "relay_busy"),
                _ => lookup_rejection(error),
            })?
    } else {
        Resolution {
            addresses: discover(request).await.map_err(lookup_rejection)?,
            relay: None,
        }
    };
    Ok(member_reply(
        addresses,
        Some(MemberSource::PublicDht),
        relay,
    ))
}

fn release_relay(state: &State, query: &ReleaseQuery) -> Result<serde_json::Value, Rejection> {
    if query.lease_id.len() != 32 {
        return Err(BAD_REQUEST);
    }
    state
        .relay
        .release(&query.lease_id)
        .map(|released| serde_json::json!({ "released": released }))
        .map_err(lookup_rejection)
}

async fn find_pairing(
    state: &State,
    space: KeySpace,
    locator: &str,
) -> Result<DiscoveryReply, Rejection> {
    let locator = Locator::parse(locator).ok_or(BAD_REQUEST)?;
    let _permit = lookup_permit(state)?;
    let protocol = StreamProtocol::new(PUBLIC_IPFS_KADEMLIA_PROTOCOL);
    let bootstrap = public_pairing_bootstrap(state);
    let addresses = pairing::discover(
        locator,
        space,
        &protocol,
        &bootstrap,
        state.owned_interface.as_deref(),
    )
    .await
    .map_err(lookup_rejection)?;
    Ok(discovery_reply(addresses))
}

async fn find_pairing_lan(state: &State) -> Result<DiscoveryReply, Rejection> {
    let _permit = lookup_permit(state)?;
    let candidates = browser_lan::discover_enrollment_candidates(state.owned_interface.as_deref())
        .await
        .map_err(|_| LAN_UNAVAILABLE)?;
    Ok(discovery_reply(
        candidates.into_iter().map(|(_, address)| address).collect(),
    ))
}

fn public_pairing_bootstrap(state: &State) -> Vec<Multiaddr> {
    // Neither provider key space inherits a private member DHT's seed list.
    if state.protocol.as_ref() == PUBLIC_IPFS_KADEMLIA_PROTOCOL {
        state
            .bootstrap
            .iter()
            .map(|(_, address)| address.clone())
            .collect()
    } else {
        Vec::new()
    }
}

fn lookup_permit(state: &State) -> Result<tokio::sync::SemaphorePermit<'_>, Rejection> {
    state
        .lookups
        .try_acquire()
        .map_err(|_| Rejection("429 Too Many Requests", "discovery_busy"))
}

fn lookup_rejection(error: io::Error) -> Rejection {
    match error.kind() {
        io::ErrorKind::InvalidInput => BAD_REQUEST,
        io::ErrorKind::NotFound => Rejection("404 Not Found", "no_candidates"),
        io::ErrorKind::Interrupted => Rejection("409 Conflict", "network_changed"),
        io::ErrorKind::NetworkUnreachable => {
            Rejection("503 Service Unavailable", "no_default_network")
        }
        io::ErrorKind::TimedOut => Rejection("504 Gateway Timeout", "discovery_timeout"),
        _ => Rejection("503 Service Unavailable", "discovery_unavailable"),
    }
}

fn discovery_reply(addresses: Vec<Multiaddr>) -> DiscoveryReply {
    DiscoveryReply {
        addresses: addresses
            .into_iter()
            .map(|address| address.to_string())
            .collect(),
    }
}

fn requested_bootstrap(
    state: &State,
    requested: Vec<BootstrapAddress>,
) -> Result<Vec<Multiaddr>, Rejection> {
    if requested.is_empty() {
        return Ok(state
            .bootstrap
            .iter()
            .map(|(_, address)| address.clone())
            .collect());
    }
    if requested.len() > MAX_BOOTSTRAP_ADDRESSES {
        return Err(BAD_REQUEST);
    }
    requested
        .into_iter()
        .map(|seed| {
            let (peer, address) = BootstrapPeerConfig {
                id: seed.id,
                address: seed.address,
            }
            .peer_address()
            .map_err(|_| BAD_REQUEST)?;
            let address = address.with_p2p(peer).map_err(|_| BAD_REQUEST)?;
            if !state
                .bootstrap
                .iter()
                .any(|(id, allowed)| id == &peer && allowed == &address)
            {
                return Err(Rejection("403 Forbidden", "bootstrap_not_enabled"));
            }
            Ok(address)
        })
        .collect()
}

async fn respond(socket: &mut TcpStream, status: &str, mime: &str, body: &[u8]) -> io::Result<()> {
    let allow = if status == METHOD.0 {
        "Allow: GET, POST\r\n"
    } else {
        ""
    };
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\n\
        Connection: close\r\nCache-Control: no-store\r\nCross-Origin-Resource-Policy: same-origin\r\n\
        X-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n{allow}\r\n",
        body.len(),
    );
    socket.write_all(headers.as_bytes()).await?;
    socket.write_all(body).await?;
    socket.shutdown().await
}

#[cfg(test)]
pub(super) mod tests;
