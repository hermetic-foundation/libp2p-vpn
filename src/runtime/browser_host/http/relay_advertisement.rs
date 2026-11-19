//! One-shot publication endpoints on the trusted loopback origin.

use std::{
    fs::File,
    io::{self, Read as _},
    path::Path,
    sync::Arc,
};

use libp2p::{Multiaddr, PeerId};
use serde::Deserialize;

use crate::peer_address_record::browser_advertisement::MAX_SUBMISSION_BYTES;
use crate::runtime::browser_host::advertisement::{Permit, Publisher};

use super::{
    BAD_REQUEST, MAX_ASSET_BYTES, NOT_FOUND, Rejection, Server, State, json_body, lookup_permit,
    lookup_rejection,
};

pub(super) const CHALLENGE_PATH: &str = "/api/relay/advertisement/challenge";
pub(super) const PUBLISH_PATH: &str = "/api/relay/advertisement/publish";
pub(super) const MARKER: &str =
    r#"<meta name="p2p-vpn-relay-advertisement" content="/api/relay/advertisement/challenge">"#;
pub(super) const MAX_CHALLENGE_BYTES: usize = 128;
const MAX_PERMIT_BYTES: usize = 2048;
const NOT_AUTHORIZED: Rejection = Rejection("403 Forbidden", "advertisement_not_authorized");
const RATE_LIMITED: Rejection = Rejection("429 Too Many Requests", "advertisement_rate_limited");

pub(super) enum Kind {
    Challenge,
    Publish,
}

pub(super) enum Request {
    Challenge,
    Publish(Vec<u8>),
}

impl Kind {
    pub(super) fn max_body_bytes(&self) -> usize {
        match self {
            Self::Challenge => MAX_CHALLENGE_BYTES,
            Self::Publish => MAX_SUBMISSION_BYTES,
        }
    }

    pub(super) fn decode(self, body: &[u8]) -> Result<Request, Rejection> {
        match self {
            Self::Challenge => match serde_json::from_slice(body) {
                Ok(serde_json::Value::Object(fields)) if fields.is_empty() => {
                    Ok(Request::Challenge)
                }
                _ => Err(BAD_REQUEST),
            },
            Self::Publish if body.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{') => {
                Ok(Request::Publish(body.to_vec()))
            }
            Self::Publish => Err(BAD_REQUEST),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PermitFile {
    network_name: String,
    membership_tag: Option<String>,
    browser_peer: String,
    destination: String,
    address: String,
}

impl Server {
    /// Opt in to advertising one exact browser reservation on this server's DHT.
    /// The permit is trusted startup policy; it must not be supplied by the browser.
    pub fn enable_relay_advertisement(&mut self, permit: Permit) -> io::Result<()> {
        let state = Arc::get_mut(&mut self.state)
            .ok_or_else(|| io::Error::other("browser server has shared state"))?;
        if state.relay_advertisement.is_some() || permit.protocol != state.protocol {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid or duplicate browser advertisement policy",
            ));
        }
        let publisher = Publisher::new(Some(permit))?;
        if state
            .assets
            .values()
            .map(|asset| asset.bytes.len())
            .sum::<usize>()
            > MAX_ASSET_BYTES - MARKER.len()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "browser assets exceed their byte limit",
            ));
        }
        let html = state
            .assets
            .get_mut("/app.html")
            .expect("loaded browser app");
        let mut bytes = html.bytes.to_vec();
        let head_end = bytes
            .windows(b"</head>".len())
            .position(|window| window == b"</head>")
            .expect("loaded app has a closing head");
        bytes.splice(head_end..head_end, MARKER.bytes());
        html.bytes = bytes.into();
        state.relay_advertisement = Some(publisher);
        Ok(())
    }

    /// Read a small, public-only permit file selected by the local operator.
    pub fn enable_relay_advertisement_file(&mut self, path: &Path) -> io::Result<()> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid browser advertisement permit file",
            )
        };
        let file = File::open(path)?;
        if !file.metadata()?.is_file() {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        file.take(MAX_PERMIT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_PERMIT_BYTES
            || bytes.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{')
        {
            return Err(invalid());
        }
        let PermitFile {
            network_name,
            membership_tag,
            browser_peer,
            destination,
            address,
        } = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        self.enable_relay_advertisement(Permit {
            network_name,
            membership_tag,
            protocol: self.state.protocol.clone(),
            browser_peer: browser_peer.parse::<PeerId>().map_err(|_| invalid())?,
            destination: destination.parse::<PeerId>().map_err(|_| invalid())?,
            address: address.parse::<Multiaddr>().map_err(|_| invalid())?,
        })
    }
}

pub(super) async fn handle(state: &State, request: Request) -> Result<Vec<u8>, Rejection> {
    let publisher = state.relay_advertisement.as_ref().ok_or(NOT_FOUND)?;
    match request {
        Request::Challenge => publisher.challenge().map(json_body).map_err(reject),
        Request::Publish(body) => {
            let _permit = lookup_permit(state)?;
            let bootstrap: Vec<_> = state
                .bootstrap
                .iter()
                .map(|(_, addr)| addr.clone())
                .collect();
            publisher
                .publish(&body, &bootstrap, state.owned_interface.as_deref())
                .await
                .map_err(reject)?;
            Ok(br#"{"published":true}"#.to_vec())
        }
    }
}

fn reject(error: io::Error) -> Rejection {
    match error.kind() {
        io::ErrorKind::PermissionDenied => NOT_AUTHORIZED,
        io::ErrorKind::WouldBlock => RATE_LIMITED,
        io::ErrorKind::InvalidData => BAD_REQUEST,
        _ => lookup_rejection(error),
    }
}
