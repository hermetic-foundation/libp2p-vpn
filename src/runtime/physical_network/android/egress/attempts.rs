//! Active-dial fallback, never a persistent override of OS preference.

use super::*;
use std::{future::Future, time::Duration};

const MAX_NETWORK_ATTEMPTS: usize = 3;
const NETWORK_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(6);

impl Egress {
    pub(crate) async fn attempt_networks_if<T, F, Fut, P>(
        &self,
        local: SocketAddr,
        destination: SocketAddr,
        protocol: SocketProtocol,
        mark: u32,
        operation: F,
        permission: P,
    ) -> io::Result<T>
    where
        F: FnMut(RouteLease) -> Fut,
        Fut: Future<Output = io::Result<T>>,
        P: Fn() -> bool,
    {
        self.attempt_networks_if_with_timeout(
            local,
            destination,
            protocol,
            mark,
            NETWORK_ATTEMPT_TIMEOUT,
            operation,
            permission,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn attempt_networks_if_with_timeout<T, F, Fut, P>(
        &self,
        local: SocketAddr,
        destination: SocketAddr,
        protocol: SocketProtocol,
        mark: u32,
        timeout: Duration,
        operation: F,
        permission: P,
    ) -> io::Result<T>
    where
        F: FnMut(RouteLease) -> Fut,
        Fut: Future<Output = io::Result<T>>,
        P: Fn() -> bool,
    {
        self.run_network_attempts(
            local,
            destination,
            protocol,
            mark,
            timeout,
            operation,
            permission,
        )
        .await
    }

    pub(crate) async fn attempt_networks<T, F, Fut>(
        &self,
        local: SocketAddr,
        destination: SocketAddr,
        protocol: SocketProtocol,
        mark: u32,
        operation: F,
    ) -> io::Result<T>
    where
        F: FnMut(RouteLease) -> Fut,
        Fut: Future<Output = io::Result<T>>,
    {
        self.attempt_networks_with_timeout(
            local,
            destination,
            protocol,
            mark,
            NETWORK_ATTEMPT_TIMEOUT,
            operation,
        )
        .await
    }

    pub(in crate::runtime::physical_network::android) async fn attempt_networks_with_timeout<
        T,
        F,
        Fut,
    >(
        &self,
        local: SocketAddr,
        destination: SocketAddr,
        protocol: SocketProtocol,
        mark: u32,
        timeout: Duration,
        operation: F,
    ) -> io::Result<T>
    where
        F: FnMut(RouteLease) -> Fut,
        Fut: Future<Output = io::Result<T>>,
    {
        self.run_network_attempts(
            local,
            destination,
            protocol,
            mark,
            timeout,
            operation,
            || true,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_network_attempts<T, F, Fut, P>(
        &self,
        local: SocketAddr,
        destination: SocketAddr,
        protocol: SocketProtocol,
        mark: u32,
        timeout: Duration,
        mut operation: F,
        permission: P,
    ) -> io::Result<T>
    where
        F: FnMut(RouteLease) -> Fut,
        Fut: Future<Output = io::Result<T>>,
        P: Fn() -> bool,
    {
        let local = canonical_socket_address(local);
        let destination = canonical_socket_address(destination);
        if !local.ip().is_unspecified() || timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Network attempts require a wildcard source and nonzero budget",
            ));
        }
        let epoch = self.current_epoch()?;
        let mut excluded = Vec::with_capacity(MAX_NETWORK_ATTEMPTS);
        let mut last_error = None;
        for attempt in 1..=MAX_NETWORK_ATTEMPTS {
            if !epoch.is_current() {
                return Err(stale());
            }
            if attempt > 1 && !permission() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Network recovery intent withdrawn",
                ));
            }
            let mut selected = None;
            let result = tokio::time::timeout(timeout, async {
                let lease = self
                    .prepare_lease_excluding(local, destination, protocol, mark, false, &excluded)
                    .await?;
                if lease.epoch() != epoch || !lease.is_current() {
                    return Err(stale());
                }
                if attempt > 1 && !permission() {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "Network recovery intent withdrawn",
                    ));
                }
                let identity = (lease.network_handle, lease.incarnation);
                if excluded.contains(&identity) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Network attempt revisited an excluded owner",
                    ));
                }
                // Record before polling connection/authentication so cancellation
                // cannot turn a known failure into another try on the same owner.
                excluded.push(identity);
                selected = Some(identity);
                operation(lease).await
            })
            .await
            .unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Android Network connection attempt deadline",
                ))
            });
            if !epoch.is_current() {
                return Err(stale());
            }
            if attempt > 1 && !permission() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Network recovery intent withdrawn",
                ));
            }
            match result {
                Ok(result) => return Ok(result),
                Err(error) => {
                    let Some((handle, incarnation)) = selected else {
                        // An unfinished source lookup has no proven Network to
                        // exclude. Do not guess or spawn overlapping retries.
                        return Err(if error.kind() == io::ErrorKind::NetworkUnreachable {
                            last_error.unwrap_or(error)
                        } else {
                            error
                        });
                    };
                    let permitted = permission();
                    if permitted {
                        eprintln!(
                            "level=debug event=android_network_attempt_failed protocol={protocol:?} attempt={attempt} network_handle={handle} incarnation={incarnation} generation={} error_kind={:?}",
                            epoch.generation(),
                            error.kind()
                        );
                    }
                    if !retryable(error.kind()) || !permitted {
                        return Err(error);
                    }
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(no_route))
    }
}

fn retryable(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::TimedOut
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::Other
    )
}
