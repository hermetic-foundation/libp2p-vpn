//! Android Network identity and availability, independent of OS preference.

pub mod discovery;
pub(crate) mod dns;
pub(crate) mod egress;
mod inventory;

pub use inventory::{Inventory, NetworkRecord, NetworkRoute};
use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
    os::fd::{AsRawFd, BorrowedFd},
    sync::{Arc, OnceLock, RwLock},
};
use tokio::sync::watch;

/// Binding is per socket; implementations must never change process routing.
pub trait SocketBinder: fmt::Debug + Send + Sync + 'static {
    fn bind(&self, network_handle: u64, socket: BorrowedFd<'_>) -> io::Result<()>;

    /// Whether the public platform API can resolve raw DNS on an exact Network.
    fn supports_platform_dns(&self) -> bool {
        false
    }

    /// Submit one query without changing process routing or bypassing Private DNS.
    /// The returned owner cancels/closes on drop; finish consumes its descriptor.
    fn start_dns_query(
        &self,
        _network_handle: u64,
        _message: &[u8],
    ) -> io::Result<Box<dyn PlatformDnsQuery>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Platform DNS unavailable",
        ))
    }

    /// Resolve the kernel's source on a Network without transmitting a packet.
    /// Public LinkProperties can omit addresses on stacked CLAT interfaces.
    fn source_for(&self, network_handle: u64, destination: SocketAddr) -> io::Result<SocketAddr> {
        egress::source_for(self, network_handle, destination)
    }
}

/// A platform-owned result descriptor, polled but never read/closed by callers.
/// Implementations close exactly once in finish (success or error), or on drop.
pub trait PlatformDnsQuery: fmt::Debug + AsRawFd + Send + Sync + 'static {
    fn finish(self: Box<Self>) -> io::Result<Vec<u8>>;
}

static NETWORKS: OnceLock<Arc<Networks>> = OnceLock::new();

fn networks() -> Arc<Networks> {
    Arc::clone(NETWORKS.get_or_init(|| Arc::new(Networks::default())))
}

pub fn install_socket_binder(binder: Arc<dyn SocketBinder>) -> bool {
    networks().binder.set(binder).is_ok()
}

pub fn publish_inventory(json: &str) -> Result<bool, String> {
    networks().publish(Inventory::parse(json)?)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SocketProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SocketRouteContext {
    pub(crate) source: SocketAddr,
    pub(crate) destination: SocketAddr,
    pub(crate) protocol: SocketProtocol,
    pub(crate) mark: u32,
    pub(crate) interface_index: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedRoute {
    pub(crate) generation: u64,
    pub(crate) destination: IpAddr,
    pub(crate) interface_index: u32,
    pub(crate) preferred_source: Option<IpAddr>,
    pub(crate) gateway: Option<IpAddr>,
    pub(crate) table: u32,
}

struct Networks {
    state: RwLock<State>,
    changed: watch::Sender<u64>,
    binder: OnceLock<Arc<dyn SocketBinder>>,
    discovery_preparations: Arc<tokio::sync::Semaphore>,
}

#[derive(Default)]
struct State {
    inventory: Inventory,
    incarnation_watermark: u64,
}

impl Default for Networks {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
            changed: watch::channel(0).0,
            binder: OnceLock::new(),
            discovery_preparations: Arc::new(tokio::sync::Semaphore::new(4)),
        }
    }
}

impl Networks {
    fn publish(&self, next: Inventory) -> Result<bool, String> {
        next.validate()?;
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if next.revision <= state.inventory.revision {
            return Ok(false);
        }
        for record in &next.networks {
            if let Some(old) = state.inventory.networks.iter().find(|old| {
                old.network_handle == record.network_handle && old.incarnation == record.incarnation
            }) {
                if record.revision < old.revision
                    || (record.revision == old.revision && record != old)
                {
                    return Err("Android network record revision is stale".to_owned());
                }
            } else if record.incarnation <= state.incarnation_watermark {
                return Err("Android network incarnation was already retired".to_owned());
            }
        }
        state.incarnation_watermark = state.incarnation_watermark.max(
            next.networks
                .iter()
                .map(|record| record.incarnation)
                .max()
                .unwrap_or(0),
        );
        let revision = next.revision;
        state.inventory = next;
        // Serialize publication with inventory replacement: an older publisher
        // cannot overwrite the watch revision after a newer update completes.
        self.changed.send_replace(revision);
        Ok(true)
    }

    fn revision(&self) -> u64 {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .inventory
            .revision
    }
}

#[cfg(test)]
mod tests;
