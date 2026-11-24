//! Bounded preferred-path handoff messages over authenticated libp2p streams.
//!
//! Decoding does not authorize a peer or change runtime state. The owner must
//! check current authorization, scope, binding, and generation before acting.
//! The owner must also match each response token to its outstanding request.

use std::{io, time::Duration};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{StreamProtocol, request_response as rr};
use serde::{Deserialize, Serialize};

pub use super::lifecycle::protocol::Scope;

pub const PROTOCOL: &str = "/p2p-vpn/handoff/1";
pub const MAX_MESSAGE_BYTES: usize = 2048;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Command {
    Offer,
    Verify,
    Commit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub scope: Scope,
    pub token: [u8; 16],
    pub command: Command,
}

impl Request {
    /// Construct a message; validation occurs when the codec reads or writes it.
    #[must_use]
    pub fn new(scope: Scope, token: [u8; 16], command: Command) -> Self {
        Self {
            scope,
            token,
            command,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ready,
    Verified,
    Committed,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub token: [u8; 16],
    pub outcome: Outcome,
}

trait WireMessage: Serialize + for<'de> Deserialize<'de> {
    fn validate(&self) -> io::Result<()>;
}

impl WireMessage for Request {
    fn validate(&self) -> io::Result<()> {
        self.scope
            .validate()
            .map_err(|_| invalid_frame("invalid handoff scope"))?;
        validate_token(self.token)
    }
}

impl WireMessage for Response {
    fn validate(&self) -> io::Result<()> {
        validate_token(self.token)
    }
}

fn validate_token(token: [u8; 16]) -> io::Result<()> {
    if token == [0; 16] {
        return Err(invalid_frame("invalid handoff token"));
    }
    Ok(())
}

#[derive(Clone, Debug, Default)]
pub struct Codec;

#[async_trait]
impl rr::Codec for Codec {
    type Protocol = StreamProtocol;
    type Request = Request;
    type Response = Response;

    async fn read_request<T>(&mut self, _: &Self::Protocol, stream: &mut T) -> io::Result<Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(stream).await
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, stream: &mut T) -> io::Result<Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(stream).await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        stream: &mut T,
        value: Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(stream, &value).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        stream: &mut T,
        value: Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(stream, &value).await
    }
}

/// The stream cap is per connection, not an authorization or rate-limit policy.
#[must_use]
pub fn behaviour(streams: usize) -> rr::Behaviour<Codec> {
    rr::Behaviour::with_codec(
        Codec,
        [(StreamProtocol::new(PROTOCOL), rr::ProtocolSupport::Full)],
        rr::Config::default()
            .with_request_timeout(REQUEST_TIMEOUT)
            .with_max_concurrent_streams(streams.max(1)),
    )
}

async fn read_frame<T: AsyncRead + Unpin + Send, M: WireMessage>(stream: &mut T) -> io::Result<M> {
    let mut length = [0; 4];
    stream.read_exact(&mut length).await?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| invalid_frame("handoff frame length out of bounds"))?;
    if length == 0 || length > MAX_MESSAGE_BYTES {
        return Err(invalid_frame("handoff frame length out of bounds"));
    }
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await?;
    let value: M = serde_json::from_slice(&payload)
        .map_err(|_| invalid_frame("invalid handoff JSON message"))?;
    value.validate()?;
    let mut extra = [0];
    if stream.read(&mut extra).await? != 0 {
        return Err(invalid_frame("trailing handoff frame bytes"));
    }
    Ok(value)
}

async fn write_frame<T: AsyncWrite + Unpin + Send, M: WireMessage>(
    stream: &mut T,
    value: &M,
) -> io::Result<()> {
    value.validate()?;
    let payload = serde_json::to_vec(value)
        .map_err(|_| invalid_frame("cannot encode handoff JSON message"))?;
    if payload.is_empty() || payload.len() > MAX_MESSAGE_BYTES {
        return Err(invalid_frame("handoff frame length out of bounds"));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| invalid_frame("handoff frame length out of bounds"))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(&payload).await?;
    stream.close().await
}

fn invalid_frame(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use futures::io::Cursor;
    use libp2p::request_response::Codec as _;

    use super::*;
    use crate::runtime::lifecycle::protocol::{MAX_MEMBERSHIP_TAG_BYTES, MAX_NETWORK_NAME_BYTES};

    fn request(command: Command) -> Request {
        Request::new(
            Scope {
                network_name: "lab".to_owned(),
                membership_tag: None,
            },
            [1; 16],
            command,
        )
    }

    fn response(outcome: Outcome) -> Response {
        Response {
            token: [1; 16],
            outcome,
        }
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut bytes = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
        bytes.extend_from_slice(payload);
        bytes
    }

    async fn assert_invalid_both(input: Vec<u8>, kind: io::ErrorKind) {
        let protocol = StreamProtocol::new(PROTOCOL);
        assert_eq!(
            Codec
                .read_request(&protocol, &mut Cursor::new(input.clone()))
                .await
                .unwrap_err()
                .kind(),
            kind
        );
        assert_eq!(
            Codec
                .read_response(&protocol, &mut Cursor::new(input))
                .await
                .unwrap_err()
                .kind(),
            kind
        );
    }

    #[tokio::test]
    async fn all_commands_and_outcomes_roundtrip_with_u32_big_endian_lengths() {
        let protocol = StreamProtocol::new(PROTOCOL);
        for command in [Command::Offer, Command::Verify, Command::Commit] {
            let value = request(command);
            let mut bytes = Cursor::new(Vec::new());
            Codec
                .write_request(&protocol, &mut bytes, value.clone())
                .await
                .unwrap();
            let payload = serde_json::to_vec(&value).unwrap();
            assert_eq!(*bytes.get_ref(), frame(&payload));
            bytes.set_position(0);
            assert_eq!(
                Codec.read_request(&protocol, &mut bytes).await.unwrap(),
                value
            );
        }
        for outcome in [
            Outcome::Ready,
            Outcome::Verified,
            Outcome::Committed,
            Outcome::Rejected,
        ] {
            let value = response(outcome);
            let mut bytes = Cursor::new(Vec::new());
            Codec
                .write_response(&protocol, &mut bytes, value)
                .await
                .unwrap();
            assert_eq!(
                *bytes.get_ref(),
                frame(&serde_json::to_vec(&value).unwrap())
            );
            bytes.set_position(0);
            assert_eq!(
                Codec.read_response(&protocol, &mut bytes).await.unwrap(),
                value
            );
        }
    }

    #[tokio::test]
    async fn maximum_escaped_scope_and_token_fit_the_bound() {
        let value = Request {
            scope: Scope {
                network_name: "\0".repeat(MAX_NETWORK_NAME_BYTES),
                membership_tag: Some("\u{0001}".repeat(MAX_MEMBERSHIP_TAG_BYTES)),
            },
            token: [255; 16],
            ..request(Command::Offer)
        };
        let mut bytes = Cursor::new(Vec::new());
        let protocol = StreamProtocol::new(PROTOCOL);
        Codec
            .write_request(&protocol, &mut bytes, value.clone())
            .await
            .unwrap();
        assert!(bytes.get_ref().len() <= MAX_MESSAGE_BYTES + 4);
        bytes.set_position(0);
        assert_eq!(
            Codec.read_request(&protocol, &mut bytes).await.unwrap(),
            value
        );
    }

    #[tokio::test]
    async fn length_is_bounded_before_payload_read_or_allocation() {
        let protocol = StreamProtocol::new(PROTOCOL);
        for length in [0, u32::try_from(MAX_MESSAGE_BYTES + 1).unwrap(), u32::MAX] {
            let mut bytes = Cursor::new(length.to_be_bytes().to_vec());
            assert_eq!(
                Codec
                    .read_request(&protocol, &mut bytes)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(bytes.position(), 4);
            bytes.set_position(0);
            assert_eq!(
                Codec
                    .read_response(&protocol, &mut bytes)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(bytes.position(), 4);
        }
    }

    #[tokio::test]
    async fn exact_limit_is_accepted_for_requests_and_responses() {
        let protocol = StreamProtocol::new(PROTOCOL);
        let mut payload = serde_json::to_vec(&request(Command::Offer)).unwrap();
        payload.resize(MAX_MESSAGE_BYTES, b' ');
        assert_eq!(
            Codec
                .read_request(&protocol, &mut Cursor::new(frame(&payload)))
                .await
                .unwrap(),
            request(Command::Offer)
        );
        let mut payload = serde_json::to_vec(&response(Outcome::Ready)).unwrap();
        payload.resize(MAX_MESSAGE_BYTES, b' ');
        assert_eq!(
            Codec
                .read_response(&protocol, &mut Cursor::new(frame(&payload)))
                .await
                .unwrap(),
            response(Outcome::Ready)
        );
    }

    #[tokio::test]
    async fn truncated_headers_and_payloads_are_rejected() {
        for input in [
            vec![],
            vec![0],
            vec![0, 0],
            vec![0, 0, 0],
            vec![0, 0, 0, 5, b'{'],
        ] {
            assert_invalid_both(input, io::ErrorKind::UnexpectedEof).await;
        }
    }

    #[tokio::test]
    async fn malformed_json_and_trailing_json_or_frame_bytes_are_rejected() {
        for payload in [b"{".as_slice(), b"[]", b"null", b"{} {}", b"\xff"] {
            assert_invalid_both(frame(payload), io::ErrorKind::InvalidData).await;
        }
        let protocol = StreamProtocol::new(PROTOCOL);
        for is_request in [true, false] {
            let payload = if is_request {
                serde_json::to_vec(&request(Command::Offer)).unwrap()
            } else {
                serde_json::to_vec(&response(Outcome::Ready)).unwrap()
            };
            let valid = frame(&payload);
            let mut json_junk = payload;
            json_junk.extend_from_slice(b" {}");
            let mut trailing_byte = valid.clone();
            trailing_byte.push(0);
            let mut second_frame = valid.clone();
            second_frame.extend(valid);
            for bytes in [frame(&json_junk), trailing_byte, second_frame] {
                let mut bytes = Cursor::new(bytes);
                let kind = if is_request {
                    Codec
                        .read_request(&protocol, &mut bytes)
                        .await
                        .unwrap_err()
                        .kind()
                } else {
                    Codec
                        .read_response(&protocol, &mut bytes)
                        .await
                        .unwrap_err()
                        .kind()
                };
                assert_eq!(kind, io::ErrorKind::InvalidData);
            }
        }
    }

    #[tokio::test]
    async fn invalid_scopes_tokens_commands_and_unknown_fields_are_rejected() {
        let protocol = StreamProtocol::new(PROTOCOL);
        for (pointer, replacement) in [
            ("/token", serde_json::to_value([0_u8; 16]).unwrap()),
            ("/token", serde_json::json!([1, 2])),
            ("/token", serde_json::to_value([256_u16; 16]).unwrap()),
            ("/scope/network_name", serde_json::json!("")),
            (
                "/scope/network_name",
                serde_json::json!("x".repeat(MAX_NETWORK_NAME_BYTES + 1)),
            ),
            ("/scope/membership_tag", serde_json::json!("")),
            (
                "/scope/membership_tag",
                serde_json::json!("x".repeat(MAX_MEMBERSHIP_TAG_BYTES + 1)),
            ),
            ("/scope/extra", serde_json::json!(true)),
            ("/command", serde_json::json!("unsupported")),
            ("/extra", serde_json::json!(true)),
        ] {
            let mut value = serde_json::to_value(request(Command::Offer)).unwrap();
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            value.pointer_mut(parent).unwrap()[key] = replacement;
            let bytes = frame(&serde_json::to_vec(&value).unwrap());
            assert_eq!(
                Codec
                    .read_request(&protocol, &mut Cursor::new(bytes))
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData,
                "{pointer}"
            );
        }
        for (key, replacement) in [
            ("token", serde_json::to_value([0_u8; 16]).unwrap()),
            ("token", serde_json::json!([1, 2])),
            ("outcome", serde_json::json!("unsupported")),
            ("extra", serde_json::json!(true)),
        ] {
            let mut value = serde_json::to_value(response(Outcome::Ready)).unwrap();
            value[key] = replacement;
            let bytes = frame(&serde_json::to_vec(&value).unwrap());
            assert_eq!(
                Codec
                    .read_response(&protocol, &mut Cursor::new(bytes))
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData,
                "{key}"
            );
        }
    }

    #[tokio::test]
    async fn invalid_outbound_messages_write_no_bytes() {
        let protocol = StreamProtocol::new(PROTOCOL);
        for value in [
            Request {
                token: [0; 16],
                ..request(Command::Offer)
            },
            Request {
                scope: Scope {
                    network_name: String::new(),
                    membership_tag: None,
                },
                ..request(Command::Offer)
            },
            Request {
                scope: Scope {
                    network_name: "x".repeat(MAX_MESSAGE_BYTES + 1),
                    membership_tag: None,
                },
                ..request(Command::Offer)
            },
            Request {
                scope: Scope {
                    network_name: "lab".to_owned(),
                    membership_tag: Some(String::new()),
                },
                ..request(Command::Offer)
            },
        ] {
            let mut bytes = Cursor::new(Vec::new());
            assert_eq!(
                Codec
                    .write_request(&protocol, &mut bytes, value)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            assert!(bytes.get_ref().is_empty());
        }
        let mut bytes = Cursor::new(Vec::new());
        assert_eq!(
            Codec
                .write_response(
                    &protocol,
                    &mut bytes,
                    Response {
                        token: [0; 16],
                        outcome: Outcome::Rejected
                    }
                )
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(bytes.get_ref().is_empty());
    }
}
