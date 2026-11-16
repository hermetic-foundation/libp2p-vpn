//! Event-driven rechecks of established source-bound paths. No network probes.

use super::super::{LinuxRouteMonitor, ResolvedRoute, RouteLookupError};
use super::{LinuxEgress, MAX_PREPARATIONS, RouteLease};
use crate::PeerId;
use futures::{StreamExt, stream};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
    time::sleep,
};

#[derive(Clone, Debug)]
pub(crate) struct Target {
    pub(crate) peer: PeerId,
    pub(crate) connection_id: usize,
    pub(crate) token: Arc<()>,
    pub(crate) lease: RouteLease,
    pub(crate) destination: SocketAddr,
}

#[derive(Clone)]
pub(crate) struct Decision {
    pub(crate) peer: PeerId,
    pub(crate) connection_id: usize,
    pub(crate) token: Arc<()>,
    pub(crate) replace: bool,
    pub(crate) destination: SocketAddr,
    monitor: Arc<LinuxRouteMonitor>,
    generation: u64,
}

impl Decision {
    pub(crate) fn is_current(&self) -> bool {
        self.monitor.generation() == Ok(self.generation)
    }
}

pub(crate) enum Event {
    Snapshot,
    Checked(Vec<Decision>),
    Unavailable,
}

pub(crate) struct Reconciler {
    snapshots: watch::Sender<Vec<Target>>,
    events: mpsc::Receiver<Event>,
    driver: JoinHandle<()>,
}

impl Drop for Reconciler {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl Reconciler {
    pub(crate) fn new(owner: Arc<LinuxEgress>) -> Self {
        let (snapshots, receiver) = watch::channel(Vec::new());
        let (events, output) = mpsc::channel(1);
        let driver = tokio::spawn(drive(owner, receiver, events));
        Self {
            snapshots,
            events: output,
            driver,
        }
    }

    pub(crate) fn submit(&self, targets: Vec<Target>) {
        self.snapshots.send_replace(targets);
    }

    pub(crate) async fn next(&mut self) -> Option<Event> {
        self.events.recv().await
    }
}

async fn drive(
    owner: Arc<LinuxEgress>,
    mut snapshots: watch::Receiver<Vec<Target>>,
    output: mpsc::Sender<Event>,
) {
    let mut retry = Duration::from_secs(1);
    let mut path_changes = owner.path_changes.subscribe();
    loop {
        if let Ok(monitor) = owner.monitor() {
            let mut revision = monitor.revision.clone();
            let mut query_retry = Duration::from_secs(1);
            loop {
                // The runner snapshots only on demand, never once per packet.
                if output.send(Event::Snapshot).await.is_err() || snapshots.changed().await.is_err()
                {
                    return;
                }
                let targets = snapshots.borrow_and_update().clone();
                let Ok(generation) = monitor.generation() else {
                    break;
                };
                let checks = stream::iter(targets)
                    .map(|target| check(&owner, Arc::clone(&monitor), generation, target))
                    .buffer_unordered(MAX_PREPARATIONS)
                    .collect::<Vec<_>>()
                    .await;
                let retry_checks = checks.iter().any(Result::is_err);
                let decisions = checks.into_iter().filter_map(Result::ok).collect();
                // Finish requests instead of canceling them on each event.
                // Their results are fenced against the observer and generation.
                if monitor.generation() == Ok(generation) {
                    retry = Duration::from_secs(1);
                    if output.send(Event::Checked(decisions)).await.is_err() {
                        return;
                    }
                    if retry_checks {
                        // Local lookup contention is not a failed peer path.
                        // Retry locally instead of causing unnecessary traffic.
                        sleep(query_retry).await;
                        query_retry = (query_retry * 2).min(Duration::from_secs(30));
                        continue;
                    }
                    query_retry = Duration::from_secs(1);
                }
                let changed = tokio::select! {
                    changed = super::super::coalesced_change(&mut revision) => changed.map(|_| ()),
                    changed = path_changes.changed() => changed.map_err(|_| RouteLookupError::MonitorUnavailable),
                };
                if changed.is_err() {
                    break;
                }
            }
        }
        if output.send(Event::Unavailable).await.is_err() {
            return;
        }
        sleep(retry).await;
        retry = (retry * 2).min(Duration::from_secs(30));
    }
}

async fn check(
    owner: &LinuxEgress,
    monitor: Arc<LinuxRouteMonitor>,
    generation: u64,
    target: Target,
) -> Result<Decision, RouteLookupError> {
    let result = preferred_route(owner, &monitor, &target).await;
    let replace = match result {
        Ok(preferred) => {
            preferred.interface_index != target.lease.route.interface_index
                || if target.lease.preferred_dial {
                    preferred
                        .preferred_source
                        .is_some_and(|source| source != target.lease.local_addr.ip())
                } else {
                    !owner
                        .source_is_assigned(&monitor, target.lease.local_addr.ip())
                        .await?
                }
        }
        Err(
            error @ (RouteLookupError::Busy
            | RouteLookupError::Timeout
            | RouteLookupError::MonitorUnavailable
            | RouteLookupError::StaleGeneration),
        ) => return Err(error),
        Err(_) => true,
    };
    Ok(Decision {
        peer: target.peer,
        connection_id: target.connection_id,
        token: target.token,
        destination: target.destination,
        replace,
        monitor,
        generation,
    })
}

async fn preferred_route(
    owner: &LinuxEgress,
    monitor: &LinuxRouteMonitor,
    target: &Target,
) -> Result<ResolvedRoute, RouteLookupError> {
    let excluded_interfaces = owner.configured_exclusions(monitor).await?;
    let mut context = target.lease.context;
    // New dials may select a new source. Accepted paths must keep their concrete
    // reply source so source-specific policy is checked before preserving aliases.
    if target.lease.preferred_dial {
        context.source.set_ip(if context.source.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        });
        if let SocketAddr::V6(source) = &mut context.source {
            source.set_scope_id(0);
        }
    }
    context.destination = super::canonical_socket_address(target.destination);
    context.interface_index = None;
    monitor
        .route_for_socket(context, &excluded_interfaces)
        .await
}

#[cfg(test)]
mod tests;
