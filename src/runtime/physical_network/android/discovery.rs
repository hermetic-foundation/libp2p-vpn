//! One kernel-checked LAN scope; Internet preference and packet routes stay separate.

use super::super::{PhysicalNetworkKind, PhysicalNetworkSnapshot, discovery_source::Admission};
use super::{NetworkRecord, Networks, networks};
use libp2p::mdns::InterfaceSocketBinding;
use std::{
    collections::HashMap,
    fmt, io,
    net::{IpAddr, SocketAddr, SocketAddrV6, UdpSocket},
    num::NonZeroU32,
    os::fd::AsFd,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Semaphore, watch},
    task::JoinHandle,
};

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_ATTEMPTS: u8 = 3;
static NEXT_OBSERVER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Eq, PartialEq)]
struct Candidate {
    network: NetworkRecord,
    source: IpAddr,
}

struct Selection {
    snapshot: PhysicalNetworkSnapshot,
    bindings: HashMap<IpAddr, Arc<dyn InterfaceSocketBinding>>,
    ipv6: bool,
}

impl Selection {
    fn empty(generation: u64) -> Self {
        Self {
            snapshot: PhysicalNetworkSnapshot {
                generation,
                ..PhysicalNetworkSnapshot::default()
            },
            bindings: HashMap::new(),
            ipv6: false,
        }
    }
}

/// Event-driven LAN observation. Start inside the runtime; dropping it revokes its sockets.
pub struct AndroidDiscovery {
    receiver: watch::Receiver<Selection>,
    driver: Option<JoinHandle<()>>,
    alive: Arc<AtomicBool>,
}

impl AndroidDiscovery {
    #[must_use]
    pub fn start() -> Self {
        Self::with_networks(networks())
    }

    fn with_networks(networks: Arc<Networks>) -> Self {
        let (sender, receiver) = watch::channel(Selection::empty(0));
        let alive = Arc::new(AtomicBool::new(true));
        let driver = NEXT_OBSERVER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .ok()
            .map(|observer| tokio::spawn(run(networks, sender, Arc::clone(&alive), observer)));
        if driver.is_none() {
            alive.store(false, Ordering::Release);
            eprintln!(
                "level=warn event=physical_network_android_discovery_exhausted action=disable_discovery"
            );
        }
        Self {
            receiver,
            driver,
            alive,
        }
    }

    pub(crate) fn has_changed(&self) -> Result<bool, watch::error::RecvError> {
        self.receiver.has_changed()
    }

    pub(crate) async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        self.receiver.changed().await
    }

    pub(in crate::runtime::physical_network) fn admission(&mut self, closed: bool) -> Admission {
        let selected = self.receiver.borrow_and_update();
        Admission {
            generation: selected.snapshot.generation,
            allowed: if closed {
                Default::default()
            } else {
                selected.snapshot.mdns_addresses()
            },
            bindings: Some(if closed {
                HashMap::new()
            } else {
                selected.bindings.clone()
            }),
            ipv6: Some(selected.ipv6),
        }
    }
}

impl Drop for AndroidDiscovery {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Release);
        if let Some(driver) = &self.driver {
            driver.abort();
        }
    }
}

struct Active(Arc<AtomicBool>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct Owner {
    networks: Arc<Networks>,
    record: Arc<NetworkRecord>,
    alive: Arc<AtomicBool>,
    active: Arc<AtomicBool>,
    identity: [u64; 3],
    capacity: Arc<Semaphore>,
}

impl Owner {
    fn is_current(&self) -> bool {
        self.alive.load(Ordering::Acquire)
            && self.active.load(Ordering::Acquire)
            && self
                .networks
                .state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .inventory
                .networks
                .iter()
                .any(|record| {
                    record.network_handle == self.record.network_handle
                        && record.incarnation == self.record.incarnation
                        && record.revision == self.record.revision
                        && record.interface_index == self.record.interface_index
                        && is_lan(record.kind)
                })
    }
}

impl fmt::Debug for Owner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AndroidDiscoveryOwner")
            .field("network_handle", &self.record.network_handle)
            .field("incarnation", &self.record.incarnation)
            .field("record_revision", &self.record.revision)
            .field("interface_index", &self.record.interface_index)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl InterfaceSocketBinding for Owner {
    fn identity(&self) -> [u64; 3] {
        self.identity
    }
    fn interface_index(&self) -> NonZeroU32 {
        NonZeroU32::new(self.record.interface_index).expect("validated interface index")
    }
    fn is_current(&self) -> bool {
        self.is_current()
    }
    fn bind(&self, socket: &UdpSocket) -> io::Result<()> {
        if !self.is_current() {
            return Err(stale());
        }
        self.networks
            .binder
            .get()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?
            .bind(self.record.network_handle, socket.as_fd())?;
        if !self.is_current() {
            return Err(stale());
        }
        Ok(())
    }

    fn prepare_sockets(self: Arc<Self>, source: IpAddr) -> libp2p::mdns::SocketPreparation {
        Box::pin(async move {
            if !self.is_current() || !self.record.addresses.contains(&source) {
                return Err(stale());
            }
            let permit = Arc::clone(&self.capacity)
                .try_acquire_owned()
                .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
            let shared = Arc::clone(&self.networks.discovery_preparations)
                .try_acquire_owned()
                .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
            let task = tokio::task::spawn_blocking(move || {
                // A dropped await cannot free a backend slot or authorize stale sockets.
                let _permits = (permit, shared);
                let socket = || {
                    socket2::Socket::new(
                        if source.is_ipv4() {
                            socket2::Domain::IPV4
                        } else {
                            socket2::Domain::IPV6
                        },
                        socket2::Type::DGRAM,
                        Some(socket2::Protocol::UDP),
                    )
                    .map(UdpSocket::from)
                };
                let recv = socket()?;
                let send = socket()?;
                self.bind(&recv)?;
                self.bind(&send)?;
                Ok((recv, send))
            });
            tokio::time::timeout(LOOKUP_TIMEOUT, task)
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "Android LAN binding deadline")
                })?
                .map_err(|_| io::Error::other("Android LAN binding task failed"))?
        })
    }
}

#[derive(Default)]
struct RetryRound {
    revision: Option<u64>,
    attempts: u8,
}

impl RetryRound {
    fn begin(&mut self, revision: u64) -> u8 {
        if self.revision != Some(revision) {
            self.revision = Some(revision);
            self.attempts = 0;
        }
        self.attempts += 1;
        self.attempts
    }
}

fn is_lan(kind: PhysicalNetworkKind) -> bool {
    matches!(
        kind,
        PhysicalNetworkKind::Wifi | PhysicalNetworkKind::Ethernet | PhysicalNetworkKind::Bluetooth
    )
}

fn stale() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "Android LAN selection changed")
}

fn select(
    networks: &Networks,
    previous: Option<&Candidate>,
    alive: &AtomicBool,
) -> io::Result<Option<Candidate>> {
    let inventory = networks
        .state
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .inventory
        .clone();
    let binder = networks
        .binder
        .get()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
    let mut candidates = inventory
        .networks
        .iter()
        .filter(|network| is_lan(network.kind))
        .collect::<Vec<_>>();
    candidates.sort_by_key(|network| {
        (
            inventory.preferred_network != Some(network.network_handle),
            !previous.is_some_and(|old| {
                old.network.network_handle == network.network_handle
                    && old.network.incarnation == network.incarnation
            }),
            network.interface_index,
            network.network_handle,
        )
    });
    for network in candidates {
        for ipv6 in [false, true] {
            if !alive.load(Ordering::Acquire) || networks.revision() != inventory.revision {
                return Err(stale());
            }
            if !network
                .addresses
                .iter()
                .any(|source| source.is_ipv6() == ipv6)
            {
                continue;
            }
            let destination = if ipv6 {
                SocketAddr::V6(SocketAddrV6::new(
                    libp2p::mdns::IPV6_MDNS_MULTICAST_ADDRESS,
                    5353,
                    0,
                    network.interface_index,
                ))
            } else {
                SocketAddr::new(libp2p::mdns::IPV4_MDNS_MULTICAST_ADDRESS.into(), 5353)
            };
            let source = binder.source_for(network.network_handle, destination);
            if !alive.load(Ordering::Acquire) || networks.revision() != inventory.revision {
                return Err(stale());
            }
            match source {
                Ok(source)
                    if source.is_ipv6() == ipv6
                        && network.addresses.contains(&source.ip())
                        && (match source {
                            SocketAddr::V6(v6) => {
                                v6.scope_id() == 0 || v6.scope_id() == network.interface_index
                            }
                            SocketAddr::V4(_) => true,
                        }) =>
                {
                    return Ok(Some(Candidate {
                        network: network.clone(),
                        source: source.ip(),
                    }));
                }
                Ok(_) => (),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NetworkUnreachable
                            | io::ErrorKind::HostUnreachable
                            | io::ErrorKind::AddrNotAvailable
                    ) =>
                {
                    ()
                }
                Err(error) => return Err(error),
            }
        }
    }
    Ok(None)
}

async fn prepare(
    networks: Arc<Networks>,
    previous: Option<Candidate>,
    alive: Arc<AtomicBool>,
    capacity: Arc<Semaphore>,
) -> io::Result<Option<Candidate>> {
    let permit = capacity
        .try_acquire_owned()
        .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
    let shared_permit = Arc::clone(&networks.discovery_preparations)
        .try_acquire_owned()
        .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
    let task = tokio::task::spawn_blocking(move || {
        // Cancellation/timeouts retain this slot until the actual netd work returns.
        let _permit = (permit, shared_permit);
        select(&networks, previous.as_ref(), &alive)
    });
    tokio::time::timeout(LOOKUP_TIMEOUT, task)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Android LAN lookup deadline"))?
        .map_err(|_| io::Error::other("Android LAN lookup task failed"))?
}

async fn run(
    networks: Arc<Networks>,
    sender: watch::Sender<Selection>,
    alive: Arc<AtomicBool>,
    observer: u64,
) {
    let mut updates = networks.changed.subscribe();
    let capacity = Arc::new(Semaphore::new(1));
    let mut current: Option<Candidate> = None;
    let mut owner: Option<Arc<Owner>> = None;
    let mut active: Option<Active> = None;
    let mut generation = 0_u64;
    let mut round = RetryRound::default();
    let mut retry = None;
    let mut first = true;
    loop {
        if !first {
            let changed = if let Some(delay) = retry.take() {
                tokio::select! {
                    changed = updates.changed() => Some(changed),
                    () = tokio::time::sleep(delay) => None,
                }
            } else {
                Some(updates.changed().await)
            };
            if let Some(changed) = changed {
                if changed.is_err() {
                    break;
                }
            }
        }
        first = false;
        // A timer can win concurrently with publication. The consumed revision,
        // not the select branch, owns the new round's retry budget.
        let attempts = round.begin(*updates.borrow_and_update());
        let next = prepare(
            Arc::clone(&networks),
            current.clone(),
            Arc::clone(&alive),
            Arc::clone(&capacity),
        )
        .await;
        let next = match next {
            Ok(next) => next,
            Err(error) => {
                let retryable = !matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::PermissionDenied
                        | io::ErrorKind::InvalidInput
                        | io::ErrorKind::NotConnected
                );
                if retryable && attempts < MAX_ATTEMPTS {
                    retry = Some(Duration::from_secs(u64::from(attempts)));
                }
                eprintln!(
                    "level=info event=physical_network_android_discovery_lookup_failed attempt={attempts} error_kind={:?} errno={:?} retry={}",
                    error.kind(),
                    error.raw_os_error(),
                    retry.is_some()
                );
                if owner.as_ref().is_some_and(|owner| owner.is_current()) {
                    continue;
                }
                None
            }
        };
        if next == current {
            // Re-offer an unchanged scope after a fresh inventory opportunity.
            // Healthy tasks keep their identity; exhausted setup can retry.
            sender.send_modify(|_| {});
            continue;
        }
        let Some(next_generation) = generation.checked_add(1) else {
            break;
        };
        generation = next_generation;
        active.take();
        owner = None;
        let selection = if let Some(candidate) = &next {
            let token = Arc::new(AtomicBool::new(true));
            let selected = Arc::new(Owner {
                networks: Arc::clone(&networks),
                record: Arc::new(candidate.network.clone()),
                alive: Arc::clone(&alive),
                active: Arc::clone(&token),
                identity: [observer, generation, candidate.network.incarnation],
                capacity: Arc::clone(&capacity),
            });
            if !selected.is_current() {
                current = None;
                sender.send_replace(Selection::empty(generation));
                continue;
            }
            let bindings = [(
                candidate.source,
                Arc::clone(&selected) as Arc<dyn InterfaceSocketBinding>,
            )]
            .into();
            active = Some(Active(token));
            owner = Some(selected);
            Selection {
                snapshot: PhysicalNetworkSnapshot {
                    generation,
                    kind: candidate.network.kind,
                    interface_name: Some(candidate.network.interface_name.clone()),
                    network_handle: Some(candidate.network.network_handle),
                    addresses: candidate.network.addresses.clone(),
                },
                bindings,
                ipv6: candidate.source.is_ipv6(),
            }
        } else {
            Selection::empty(generation)
        };
        eprintln!(
            "level=info event=physical_network_android_discovery generation={generation} network_handle={:?} ipv6={} advertised_sources={} socket_sources={}",
            selection.snapshot.network_handle,
            selection.ipv6,
            selection.snapshot.addresses.len(),
            selection.bindings.len()
        );
        sender.send_replace(selection);
        current = next;
    }
    drop(active);
}

#[cfg(test)]
mod tests;
