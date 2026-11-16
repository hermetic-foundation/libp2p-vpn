// Copyright 2017-2020 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Future that drives a QUIC connection until is has performed its TLS handshake.

use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures::{
    future::{select, BoxFuture, Either, FutureExt, Select},
    prelude::*,
};
use futures_timer::Delay;
use libp2p_identity::PeerId;
use quinn::rustls::pki_types::CertificateDer;

use quinn_proto::TransportError;

use crate::{Connection, ConnectionError, Error};

/// A QUIC connection currently being negotiated.
pub struct Connecting {
    connecting: Option<Select<quinn::Connecting, Delay>>,
    prepared: Option<BoxFuture<'static, Result<(PeerId, Connection), Error>>>,
    owner: Option<Box<dyn crate::ConnectionOwner>>,
}

impl std::fmt::Debug for Connecting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connecting")
            .field("preparing", &self.prepared.is_some())
            .finish_non_exhaustive()
    }
}

impl Connecting {
    pub(crate) fn new(connection: quinn::Connecting, timeout: Duration) -> Self {
        Connecting {
            connecting: Some(select(connection, Delay::new(timeout))),
            prepared: None,
            owner: None,
        }
    }

    pub(crate) fn with_owner(mut self, owner: Box<dyn crate::ConnectionOwner>) -> Self {
        self.owner = Some(owner);
        self
    }

    pub(crate) fn prepared(
        future: impl Future<Output = Result<(PeerId, Connection), Error>> + Send + 'static,
        timeout: Duration,
    ) -> Self {
        let future = future.boxed();
        Self {
            connecting: None,
            owner: None,
            prepared: Some(
                async move {
                    match select(future, Delay::new(timeout)).await {
                        Either::Left((result, _)) => result,
                        Either::Right(_) => Err(Error::HandshakeTimedOut),
                    }
                }
                .boxed(),
            ),
        }
    }
}

impl Connecting {
    fn remote_peer_id(connection: &quinn::Connection) -> Result<PeerId, Error> {
        fn transport_err(reason: &str) -> Error {
            Error::Connection(ConnectionError(quinn::ConnectionError::TransportError(
                TransportError {
                    code: quinn::TransportErrorCode::PROTOCOL_VIOLATION,
                    frame: None,
                    reason: reason.to_string(),
                },
            )))
        }

        let identity = connection
            .peer_identity()
            .ok_or_else(|| transport_err("No crypto identity in quinn's Connection"))?;
        let certificates: Box<Vec<CertificateDer>> = identity
            .downcast()
            .map_err(|_| transport_err("Could not downcast identity"))?;
        let end_entity = certificates
            .first()
            .ok_or_else(|| transport_err("No certificate found"))?;
        let p2p_cert = libp2p_tls::certificate::parse(end_entity)
            .map_err(|_| transport_err("Could not parse certificate"))?;
        Ok(p2p_cert.peer_id())
    }
}

impl Future for Connecting {
    type Output = Result<(PeerId, Connection), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(prepared) = &mut self.prepared {
            return prepared.poll_unpin(cx);
        }
        let connection = match futures::ready!(self
            .connecting
            .as_mut()
            .expect("handshake future")
            .poll_unpin(cx))
        {
            Either::Right(_) => return Poll::Ready(Err(Error::HandshakeTimedOut)),
            Either::Left((connection, _)) => connection.map_err(ConnectionError)?,
        };

        let peer_id = Self::remote_peer_id(&connection)?;
        let mut muxer = Connection::new(connection);
        if let Some(mut owner) = self.owner.take() {
            if let Err(error) = owner.authenticated(peer_id) {
                muxer
                    .connection
                    .close(0_u32.into(), b"invalid physical ownership");
                return Poll::Ready(Err(Error::Io(error)));
            }
            muxer.owner = Some(owner);
        }
        Poll::Ready(Ok((peer_id, muxer)))
    }
}
