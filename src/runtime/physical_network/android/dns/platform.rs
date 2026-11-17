//! The OS resolver owns DNS transport and Private DNS; Hickory still owns records.

use super::{NetworkRuntime, SERVER_TIMEOUT, Scope, busy, stale};
use futures::{FutureExt as _, StreamExt as _, future::BoxFuture, stream::BoxStream};
use hickory_proto::{
    ProtoError,
    op::MessageType,
    xfer::{DnsHandle, DnsRequest, DnsResponse},
};
use hickory_resolver::{
    config::{NameServerConfig, ResolverOpts},
    name_server::{ConnectionProvider, GenericConnection, GenericConnector},
};
use std::{
    io,
    os::fd::{AsRawFd, RawFd},
    sync::Arc,
};

const MAX_DNS_PACKET: usize = 65_535;

struct Descriptor(Box<dyn super::super::PlatformDnsQuery>);

impl AsRawFd for Descriptor {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

#[derive(Clone)]
pub(super) struct NetworkProvider {
    runtime: NetworkRuntime,
    plain: GenericConnector<NetworkRuntime>,
}

impl NetworkProvider {
    pub(super) fn new(runtime: NetworkRuntime) -> Self {
        Self {
            plain: GenericConnector::new(runtime.clone()),
            runtime,
        }
    }
}

impl ConnectionProvider for NetworkProvider {
    type Conn = Connection;
    type FutureConn = BoxFuture<'static, Result<Connection, ProtoError>>;
    type RuntimeProvider = NetworkRuntime;

    fn new_connection(
        &self,
        config: &NameServerConfig,
        options: &ResolverOpts,
    ) -> io::Result<Self::FutureConn> {
        self.runtime.scope.check()?;
        if self.runtime.scope.platform_dns {
            let scope = self.runtime.scope.clone();
            return Ok(async move { Ok(Connection::Platform(scope)) }.boxed());
        }
        let connection = self.plain.new_connection(config, options)?;
        Ok(async move { connection.await.map(Connection::Plain) }.boxed())
    }
}

#[derive(Clone)]
pub(super) enum Connection {
    Plain(GenericConnection),
    Platform(Scope),
}

impl DnsHandle for Connection {
    type Response = BoxStream<'static, Result<DnsResponse, ProtoError>>;

    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&self, request: R) -> Self::Response {
        match self {
            Self::Plain(connection) => connection.send(request).boxed(),
            Self::Platform(scope) => {
                let scope = scope.clone();
                let request = request.into();
                futures::stream::once(async move {
                    tokio::time::timeout(SERVER_TIMEOUT, exchange(scope, request))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "Platform DNS query deadline")
                        })?
                })
                .boxed()
            }
        }
    }
}

async fn exchange(scope: Scope, request: DnsRequest) -> Result<DnsResponse, ProtoError> {
    let (request, _) = request.into_parts();
    let encoded = request.to_vec()?;
    if !(12..=MAX_DNS_PACKET).contains(&encoded.len()) {
        return Err(
            io::Error::new(io::ErrorKind::InvalidInput, "Invalid DNS request length").into(),
        );
    }
    scope.check()?;
    let permit = Arc::clone(&scope.preparations)
        .try_acquire_owned()
        .map_err(|_| busy())?;
    let submit_scope = scope.clone();
    let submit = tokio::task::spawn_blocking(move || {
        // A canceled waiter cannot release capacity while a netd submit is running.
        let _permit = permit;
        submit_scope.check()?;
        let binder = submit_scope.epoch_networks().binder.get().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "Platform DNS binder unavailable",
            )
        })?;
        let query = binder.start_dns_query(submit_scope.network, &encoded)?;
        submit_scope.check()?;
        Ok::<_, io::Error>(query)
    });
    let query = submit
        .await
        .map_err(|_| io::Error::other("Platform DNS submit worker failed"))??;
    scope.check()?;
    let descriptor = tokio::io::unix::AsyncFd::new(Descriptor(query))?;
    let mut changed = scope.epoch_networks().changed.subscribe();
    scope.check()?;
    tokio::select! {
        biased;
        result = changed.changed() => {
            result.map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "Platform DNS inventory closed"))?;
            return Err(stale().into());
        }
        ready = descriptor.readable() => { drop(ready?); }
    }
    scope.check()?;
    let query = descriptor.into_inner().0;
    let permit = Arc::clone(&scope.preparations)
        .try_acquire_owned()
        .map_err(|_| busy())?;
    let finish_scope = scope.clone();
    let finish = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        finish_scope.check()?;
        let response = query.finish()?;
        finish_scope.check()?;
        Ok::<_, io::Error>(response)
    });
    let response = finish
        .await
        .map_err(|_| io::Error::other("Platform DNS result worker failed"))??;
    scope.check()?;
    if !(12..=MAX_DNS_PACKET).contains(&response.len()) {
        return Err(
            io::Error::new(io::ErrorKind::InvalidData, "Invalid DNS response length").into(),
        );
    }
    let response = DnsResponse::from_buffer(response)?;
    if response.message_type() != MessageType::Response
        || response.op_code() != request.op_code()
        || response.queries() != request.queries()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Platform DNS response does not match its request",
        )
        .into());
    }
    // The trusted OS resolver may choose its own transaction identifier.
    let mut message = response.into_message();
    message.set_id(request.id());
    DnsResponse::from_message(message)
}

#[cfg(test)]
mod tests;
