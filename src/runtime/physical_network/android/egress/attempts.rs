//! Active-dial fallback, never a persistent override of OS preference.

use super::*;
use std::{future::Future, time::Duration};

const MAX_NETWORK_ATTEMPTS: usize = 3;
const NETWORK_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(6);

/// One bounded recovery operation, retained across asynchronous proof callbacks.
/// Creating another Hello must not create another cursor for the same operation.
#[derive(Debug)]
pub(crate) struct NetworkAttempts {
    epoch: RouteEpoch,
    local: SocketAddr,
    destination: SocketAddr,
    protocol: SocketProtocol,
    mark: u32,
    preferred: Option<(u64, u64)>,
    excluded: Vec<(u64, u64)>,
    state: AttemptState,
}

#[derive(Debug)]
enum AttemptState {
    Ready,
    Preparing,
    AwaitingProof(Arc<()>),
    Complete,
    Stopped,
}

/// The exact selected lease and a local, unforgeable completion identity.
/// Sending a UDP packet does not complete this attempt: its caller owes proof.
#[derive(Clone, Debug)]
pub(crate) struct NetworkAttempt {
    lease: RouteLease,
    number: usize,
    preferred: bool,
    token: Arc<()>,
}

impl NetworkAttempt {
    pub(crate) fn same_attempt(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.token, &other.token)
    }
    pub(crate) fn number(&self) -> usize {
        self.number
    }
    /// Policy identity for this operation's epoch, not proof the lease is still current.
    pub(crate) fn is_preferred(&self) -> bool {
        self.preferred
    }
    pub(crate) fn lease(&self) -> &RouteLease {
        &self.lease
    }
}

impl NetworkAttempts {
    pub(crate) fn can_prepare(&self) -> bool {
        self.epoch.is_current()
            && matches!(self.state, AttemptState::Ready)
            && self.excluded.len() < MAX_NETWORK_ATTEMPTS
    }
    pub(crate) fn new(
        owner: &Egress,
        local: SocketAddr,
        destination: SocketAddr,
        protocol: SocketProtocol,
        mark: u32,
    ) -> io::Result<Self> {
        let local = canonical_socket_address(local);
        if !local.ip().is_unspecified() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Network attempts require a wildcard source",
            ));
        }
        let destination = canonical_socket_address(destination);
        let epoch = owner.current_epoch()?;
        let preferred = {
            let state = owner
                .networks
                .state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.inventory.revision != epoch.generation() {
                return Err(stale());
            }
            // Capture policy before source lookup or fallback exclusions can skip it.
            state
                .inventory
                .candidates(destination.ip())
                .into_iter()
                .find(|record| {
                    let local_scope = match local {
                        SocketAddr::V6(address) if address.scope_id() != 0 => {
                            address.scope_id() == record.interface_index
                        }
                        _ => true,
                    };
                    let destination_scope = match destination {
                        SocketAddr::V6(address)
                            if address.ip().is_unicast_link_local() && address.scope_id() != 0 =>
                        {
                            address.scope_id() == record.interface_index
                        }
                        _ => true,
                    };
                    local_scope && destination_scope
                })
                .map(|record| (record.network_handle, record.incarnation))
        };
        if !epoch.is_current() {
            return Err(stale());
        }
        Ok(Self {
            epoch,
            local,
            destination,
            protocol,
            mark,
            preferred,
            excluded: Vec::with_capacity(MAX_NETWORK_ATTEMPTS),
            state: AttemptState::Ready,
        })
    }

    pub(crate) fn epoch(&self) -> &RouteEpoch {
        &self.epoch
    }

    pub(crate) async fn prepare(
        &mut self,
        owner: &Egress,
        permission: impl Fn() -> bool,
    ) -> io::Result<NetworkAttempt> {
        self.check_epoch()?;
        if owner.current_epoch()? != self.epoch {
            return Err(stale());
        }
        match self.state {
            AttemptState::Ready => (),
            AttemptState::AwaitingProof(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Network attempt awaits authenticated proof",
                ));
            }
            AttemptState::Preparing => {
                // A cancelled lookup has no proven owner to exclude. Do not
                // guess one or overlap its still-running blocking backend.
                self.state = AttemptState::Stopped;
                return Err(stale());
            }
            AttemptState::Complete | AttemptState::Stopped => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "Network attempt operation finished",
                ));
            }
        }
        if self.excluded.len() >= MAX_NETWORK_ATTEMPTS {
            self.state = AttemptState::Stopped;
            return Err(no_route());
        }
        if !self.excluded.is_empty() && !permission() {
            self.state = AttemptState::Stopped;
            return Err(withdrawn());
        }
        self.state = AttemptState::Preparing;
        let prepared = owner
            .prepare_lease_excluding(
                self.local,
                self.destination,
                self.protocol,
                self.mark,
                false,
                &self.excluded,
            )
            .await;
        // Remain stopped for every unproven lookup outcome, including a stale
        // result or a source lookup which failed without selecting an owner.
        self.state = AttemptState::Stopped;
        self.check_epoch()?;
        let lease = prepared?;
        if lease.epoch() != self.epoch || !lease.is_current() {
            return Err(stale());
        }
        if !self.excluded.is_empty() && !permission() {
            return Err(withdrawn());
        }
        let identity = (lease.network_handle, lease.incarnation);
        if self.excluded.contains(&identity) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Network attempt revisited an excluded owner",
            ));
        }
        // Consume before the caller can transmit, wait for an ACK, or cancel.
        self.excluded.push(identity);
        let token = Arc::new(());
        self.state = AttemptState::AwaitingProof(Arc::clone(&token));
        Ok(NetworkAttempt {
            lease,
            number: self.excluded.len(),
            preferred: self.preferred == Some(identity),
            token,
        })
    }

    /// Only call after authentication and exact path proof, never after send().
    pub(crate) fn confirm(&mut self, attempt: &NetworkAttempt, permitted: bool) -> io::Result<()> {
        self.check_attempt(attempt)?;
        if attempt.number > 1 && !permitted {
            self.state = AttemptState::Stopped;
            return Err(withdrawn());
        }
        self.state = AttemptState::Complete;
        Ok(())
    }

    /// Returns whether an eligible alternate may be selected. Original errors
    /// remain the caller's to report; stale/unrelated callbacks never advance.
    pub(crate) fn failed(
        &mut self,
        attempt: &NetworkAttempt,
        kind: io::ErrorKind,
        permitted: bool,
    ) -> io::Result<bool> {
        self.check_attempt(attempt)?;
        let retry = retryable(kind) && permitted && self.excluded.len() < MAX_NETWORK_ATTEMPTS;
        self.state = if retry {
            AttemptState::Ready
        } else {
            AttemptState::Stopped
        };
        Ok(retry)
    }

    fn check_epoch(&mut self) -> io::Result<()> {
        if !self.epoch.is_current() {
            self.state = AttemptState::Stopped;
            return Err(stale());
        }
        Ok(())
    }

    fn check_attempt(&mut self, attempt: &NetworkAttempt) -> io::Result<()> {
        self.check_epoch()?;
        if !matches!(&self.state, AttemptState::AwaitingProof(token) if Arc::ptr_eq(token, &attempt.token))
            || attempt.lease.epoch() != self.epoch
            || !attempt.lease.is_current()
            || attempt.number != self.excluded.len()
        {
            return Err(stale());
        }
        Ok(())
    }
}

fn withdrawn() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "Network recovery intent withdrawn",
    )
}

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
        if timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Network attempts require a wildcard source and nonzero budget",
            ));
        }
        let mut attempts = NetworkAttempts::new(self, local, destination, protocol, mark)?;
        let mut last_error = None;
        loop {
            let attempt_number = attempts.excluded.len() + 1;
            let mut selected = None;
            let result = tokio::time::timeout(timeout, async {
                let attempt = attempts.prepare(self, &permission).await?;
                let lease = attempt.lease.clone();
                selected = Some(attempt);
                operation(lease).await
            })
            .await
            .unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Android Network connection attempt deadline",
                ))
            });
            if !attempts.epoch().is_current() {
                return Err(stale());
            }
            if attempt_number > 1 && !permission() {
                return Err(withdrawn());
            }
            match result {
                Ok(result) => {
                    attempts.confirm(
                        selected
                            .as_ref()
                            .expect("successful operation selected a Network"),
                        permission(),
                    )?;
                    return Ok(result);
                }
                Err(error) => {
                    let Some(attempt) = selected else {
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
                            "level=debug event=android_network_attempt_failed protocol={protocol:?} attempt={} network_handle={} incarnation={} generation={} error_kind={:?}",
                            attempt.number(),
                            attempt.lease.network_handle,
                            attempt.lease.incarnation,
                            attempts.epoch().generation(),
                            error.kind()
                        );
                    }
                    if !attempts.failed(&attempt, error.kind(), permitted)? {
                        return Err(error);
                    }
                    last_error = Some(error);
                }
            }
        }
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
