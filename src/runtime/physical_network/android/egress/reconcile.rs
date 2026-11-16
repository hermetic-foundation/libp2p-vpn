//! Event-driven Android owner audits. No periodic polling or peer probes.

use super::{Egress, RouteEpoch, RouteLease};
use crate::PeerId;
use futures::{StreamExt, stream};
use std::{
    io,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
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
    epoch: RouteEpoch,
}

impl Decision {
    pub(crate) fn is_current(&self) -> bool {
        self.epoch.is_current()
    }
    pub(crate) fn generation(&self) -> u64 {
        self.epoch.generation()
    }
    pub(crate) fn epoch(&self) -> RouteEpoch {
        self.epoch.clone()
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
    pub(crate) fn new(owner: Arc<Egress>) -> Self {
        let (snapshots, targets) = watch::channel(Vec::new());
        let (output, events) = mpsc::channel(1);
        let driver = tokio::spawn(drive(owner, targets, output));
        Self {
            snapshots,
            events,
            driver,
        }
    }
    pub(crate) fn submit(&self, targets: Vec<Target>) {
        self.snapshots.send_replace(targets);
    }
    pub(crate) async fn next(&mut self) -> Option<Event> {
        self.events.recv().await
    }
    pub(crate) fn poll_next(&mut self, context: &mut Context<'_>) -> Poll<Option<Event>> {
        self.events.poll_recv(context)
    }
}

async fn drive(
    owner: Arc<Egress>,
    mut targets: watch::Receiver<Vec<Target>>,
    output: mpsc::Sender<Event>,
) {
    let mut changes = owner.networks.changed.subscribe();
    let mut paths = owner.path_changes.subscribe();
    let mut retry = Duration::from_secs(1);
    loop {
        changes.borrow_and_update();
        paths.borrow_and_update();
        if output.send(Event::Snapshot).await.is_err() || targets.changed().await.is_err() {
            return;
        }
        let epoch = RouteEpoch::new(Arc::clone(&owner.networks), owner.networks.revision());
        let targets = targets.borrow_and_update().clone();
        let checks = stream::iter(targets)
            .map(|target| check(&owner, &epoch, target))
            .buffer_unordered(super::MAX_PREPARATIONS)
            .collect::<Vec<_>>()
            .await;
        if !epoch.is_current() {
            continue;
        }
        let retry_checks = checks.iter().any(Result::is_err);
        let decisions = checks.into_iter().filter_map(Result::ok).collect();
        if output.send(Event::Checked(decisions)).await.is_err() {
            return;
        }
        if retry_checks {
            // Retry local lookup contention only. Successful idle audits have
            // no timer and neither case sends a packet to a peer.
            tokio::select! {
                _ = tokio::time::sleep(retry) => {},
                result = changes.changed() => if result.is_err() { return; },
                result = paths.changed() => if result.is_err() { return; },
            }
            retry = (retry * 2).min(Duration::from_secs(30));
        } else {
            retry = Duration::from_secs(1);
            tokio::select! {
                result = changes.changed() => if result.is_err() { return; },
                result = paths.changed() => if result.is_err() { return; },
            }
        }
    }
}

async fn check(owner: &Egress, epoch: &RouteEpoch, target: Target) -> io::Result<Decision> {
    let mut local = target.lease.local_addr;
    local.set_ip(if local.is_ipv4() {
        std::net::Ipv4Addr::UNSPECIFIED.into()
    } else {
        std::net::Ipv6Addr::UNSPECIFIED.into()
    });
    if let SocketAddr::V6(address) = &mut local {
        address.set_scope_id(0);
    }
    let preferred = owner
        .prepare_lease(
            local,
            target.destination,
            target.lease.context.protocol,
            target.lease.context.mark,
            false,
        )
        .await;
    let replace = match preferred {
        Ok(preferred) => {
            let state = owner
                .networks
                .state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            !target.lease.available_in(&state.inventory)
                || preferred.network_handle != target.lease.network_handle
                || preferred.incarnation != target.lease.incarnation
                || (target.lease.preferred_dial
                    && !target.lease.source_fixed
                    && preferred.local_addr.ip() != target.lease.local_addr.ip())
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NetworkUnreachable | io::ErrorKind::AddrNotAvailable
            ) =>
        {
            true
        }
        Err(error) => return Err(error),
    };
    Ok(Decision {
        peer: target.peer,
        connection_id: target.connection_id,
        token: target.token,
        replace,
        destination: target.destination,
        epoch: epoch.clone(),
    })
}
