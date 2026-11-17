//! Nonblocking hostname endpoints for the synchronous packet negotiator.

use super::{MAX_QUERIES, NetworkResolver, QUERY_TIMEOUT, RouteEpoch};
use hickory_proto::rr::Name;
use libp2p::dns::Resolver as _;
use std::{
    cell::RefCell,
    collections::BTreeMap,
    marker::PhantomData,
    net::{IpAddr, SocketAddr},
    rc::Rc,
    sync::{Arc, Mutex, OnceLock, Weak},
    time::{Duration, Instant},
};
use tokio::sync::{Semaphore, watch};

#[cfg(all(test, target_os = "linux"))]
pub(crate) mod fixture;

const MAX_HOSTS: usize = 64;
const MAX_ADDRESSES: usize = 64;
const NEGATIVE_TTL: Duration = Duration::from_secs(30);

struct Entry {
    epoch: RouteEpoch,
    token: Arc<()>,
    expires: Instant,
    addresses: Vec<IpAddr>,
    delivery_until: Option<Instant>,
    pending: bool,
}

struct View {
    _owner: Weak<Endpoints>,
    epoch: RouteEpoch,
    addresses: Vec<IpAddr>,
}

/// A handshake may retain its resolution evidence across asynchronous stages.
/// This never extends the reusable DNS cache or owns a physical socket.
#[derive(Clone, Default)]
pub(crate) struct Snapshot(Vec<((usize, String), Arc<View>)>);

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DnsNegotiationSnapshot")
            .field("hosts", &self.0.len())
            .finish()
    }
}

impl Snapshot {
    pub(crate) fn is_current(&self) -> bool {
        self.0.iter().all(|(_, view)| view.epoch.is_current())
    }

    pub(crate) fn restore(&self) -> bool {
        if !self.is_current() {
            return false;
        }
        DELIVERY.with(|state| {
            let mut state = state.borrow_mut();
            if state.depth == 0 {
                return false;
            }
            for (key, view) in &self.0 {
                if state.views.len() >= MAX_HOSTS && !state.views.contains_key(key) {
                    return false;
                }
                state.views.insert(key.clone(), Arc::clone(view));
            }
            true
        })
    }
}

pub(crate) fn capture_snapshot() -> Snapshot {
    DELIVERY.with(|state| {
        Snapshot(
            state
                .borrow()
                .views
                .iter()
                .take(MAX_HOSTS)
                .map(|(key, view)| (key.clone(), Arc::clone(view)))
                .collect(),
        )
    })
}

#[derive(Default)]
struct DeliveryState {
    depth: usize,
    views: BTreeMap<(usize, String), Arc<View>>,
}

thread_local! {
    static DELIVERY: RefCell<DeliveryState> = RefCell::new(DeliveryState::default());
}

/// A synchronous negotiation gets an immutable answer snapshot, not a minimum
/// cache TTL. This guard must never survive an await or move between threads.
pub(crate) struct Delivery(PhantomData<Rc<()>>);

pub(crate) fn delivery_scope() -> Delivery {
    DELIVERY.with(|state| state.borrow_mut().depth += 1);
    Delivery(PhantomData)
}

impl Drop for Delivery {
    fn drop(&mut self) {
        DELIVERY.with(|state| {
            let mut state = state.borrow_mut();
            state.depth -= 1;
            if state.depth == 0 {
                state.views.clear();
            }
        });
    }
}

struct Endpoints {
    resolver: NetworkResolver,
    entries: Mutex<BTreeMap<String, Entry>>,
    workers: Arc<Semaphore>,
    changed: watch::Sender<()>,
}

static ENDPOINTS: OnceLock<Arc<Endpoints>> = OnceLock::new();

fn endpoints() -> &'static Arc<Endpoints> {
    ENDPOINTS.get_or_init(|| Arc::new(Endpoints::new(NetworkResolver::new())))
}

pub(crate) fn subscribe_endpoints() -> watch::Receiver<()> {
    endpoints().changed.subscribe()
}

pub(crate) fn endpoint_candidates(candidate: &str) -> Vec<SocketAddr> {
    endpoints().candidates(candidate)
}

pub(crate) fn endpoint_pending(candidate: &str) -> bool {
    endpoints().pending(candidate)
}

impl Endpoints {
    fn new(resolver: NetworkResolver) -> Self {
        Self {
            resolver,
            entries: Mutex::new(BTreeMap::new()),
            workers: Arc::new(Semaphore::new(MAX_QUERIES)),
            changed: watch::channel(()).0,
        }
    }

    fn pending(&self, candidate: &str) -> bool {
        let Some((hostname, _)) = authority(candidate) else {
            return false;
        };
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&hostname)
            .is_some_and(|entry| {
                entry.pending && entry.expires > Instant::now() && entry.epoch.is_current()
            })
    }

    fn candidates(self: &Arc<Self>, candidate: &str) -> Vec<SocketAddr> {
        if let Ok(address) = candidate.parse::<SocketAddr>() {
            return vec![address];
        }
        let Some((hostname, port)) = authority(candidate) else {
            return Vec::new();
        };
        let key = (Arc::as_ptr(self) as usize, hostname.clone());
        if let Some(addresses) = DELIVERY.with(|state| {
            state
                .borrow()
                .views
                .get(&key)
                .filter(|view| view.epoch.is_current())
                .map(|view| view.addresses.clone())
        }) {
            return addresses
                .into_iter()
                .map(|address| SocketAddr::new(address, port))
                .collect();
        }
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.retain(|_, entry| {
            entry.epoch.is_current()
                && (entry.expires > now || entry.delivery_until.is_some_and(|until| until > now))
        });
        if let Some(entry) = entries.get(&hostname) {
            let addresses = entry.addresses.clone();
            let epoch = entry.epoch.clone();
            if entry.expires <= now {
                // A completed zero-TTL answer is consumed once; only the explicit
                // synchronous delivery scope may read that snapshot again.
                entries.remove(&hostname);
            } else if !addresses.is_empty() {
                entries
                    .get_mut(&hostname)
                    .expect("cached answer exists")
                    .delivery_until = None;
            }
            drop(entries);
            if !addresses.is_empty() {
                DELIVERY.with(|state| {
                    let mut state = state.borrow_mut();
                    if state.depth > 0 && state.views.len() < MAX_HOSTS {
                        state.views.insert(
                            key,
                            Arc::new(View {
                                _owner: Arc::downgrade(self),
                                epoch,
                                addresses: addresses.clone(),
                            }),
                        );
                    }
                });
            }
            return addresses
                .into_iter()
                .map(|address| SocketAddr::new(address, port))
                .collect();
        }
        if entries.len() >= MAX_HOSTS {
            return Vec::new();
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return Vec::new();
        };
        let Ok(permit) = Arc::clone(&self.workers).try_acquire_owned() else {
            return Vec::new();
        };
        let generation = self.resolver.0.networks.revision();
        if generation == 0 {
            return Vec::new();
        }
        let epoch = RouteEpoch::new(Arc::clone(&self.resolver.0.networks), generation);
        let token = Arc::new(());
        entries.insert(
            hostname.clone(),
            Entry {
                epoch: epoch.clone(),
                token: Arc::clone(&token),
                expires: now + QUERY_TIMEOUT + Duration::from_secs(1),
                addresses: Vec::new(),
                delivery_until: None,
                pending: true,
            },
        );
        drop(entries);
        let owner = Arc::clone(self);
        runtime.spawn(async move {
            let _permit = permit;
            let result = owner.resolver.lookup_ip(hostname.clone()).await;
            let now = Instant::now();
            let (addresses, expires) = match result {
                Ok(result) => {
                    let addresses = result
                        .iter()
                        .map(|address| address.to_canonical())
                        .take(MAX_ADDRESSES)
                        .collect();
                    (
                        addresses,
                        result.valid_until().min(now + Duration::from_secs(300)),
                    )
                }
                Err(_) => (Vec::new(), now + NEGATIVE_TTL),
            };
            let mut entries = owner
                .entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !epoch.is_current() {
                drop(entries);
                owner.changed.send_replace(());
                return;
            }
            let Some(entry) = entries
                .get_mut(&hostname)
                .filter(|entry| Arc::ptr_eq(&entry.token, &token))
            else {
                return;
            };
            entry.addresses = addresses;
            entry.expires = expires;
            entry.pending = false;
            entry.delivery_until = (!entry.addresses.is_empty()).then_some(now + QUERY_TIMEOUT);
            drop(entries);
            owner.changed.send_replace(());
        });
        Vec::new()
    }
}

fn authority(candidate: &str) -> Option<(String, u16)> {
    let (hostname, port) = candidate.rsplit_once(':')?;
    let port = port.parse().ok()?;
    if hostname.len() > 253 || hostname.is_empty() || hostname.contains(':') || port == 0 {
        return None;
    }
    let mut hostname = Name::from_ascii(hostname).ok()?.to_lowercase();
    hostname.set_fqdn(true);
    Some((hostname.to_ascii(), port))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{fixture, inventory, local_resolvers, server, server_ttl};
    use super::*;

    #[tokio::test]
    async fn endpoints_complete_asynchronously_share_names_and_reject_stale_cache() {
        let (resolver, binder) = fixture();
        let (address, server) = server(false).await;
        local_resolvers(&resolver, &[(1, address)]);
        let endpoints = Arc::new(Endpoints::new(resolver));
        let mut changed = endpoints.changed.subscribe();
        assert!(!endpoints.pending("target.example:4001"));
        assert!(endpoints.entries.lock().unwrap().is_empty());
        assert!(endpoints.candidates("Target.Example:4001").is_empty());
        assert!(endpoints.pending("target.example.:4002"));
        assert!(endpoints.candidates("target.example.:4002").is_empty());
        assert_eq!(endpoints.entries.lock().unwrap().len(), 1);
        tokio::time::timeout(Duration::from_secs(2), changed.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(!endpoints.pending("target.example:4002"));
        let addresses = endpoints.candidates("target.example:4002");
        assert!(addresses.iter().all(|address| address.port() == 4002));
        assert!(addresses.iter().any(|address| address.is_ipv4()));
        assert!(
            binder
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|handle| *handle == 1)
        );
        let permits = endpoints
            .workers
            .acquire_many(MAX_QUERIES as u32)
            .await
            .unwrap();
        endpoints
            .resolver
            .0
            .networks
            .publish(inventory(2, 2))
            .unwrap();
        assert!(endpoints.candidates("target.example:4002").is_empty());
        assert!(!endpoints.pending("target.example:4002"));
        assert!(endpoints.entries.lock().unwrap().is_empty());
        drop(permits);
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }

    #[test]
    fn hostname_authorities_are_structurally_validated() {
        assert_eq!(
            authority("EXAMPLE.com:4001"),
            Some(("example.com.".to_owned(), 4001))
        );
        for invalid in [
            "example.com",
            "example.com:0",
            "example.com:no",
            "[::1]:4001",
            "a:b:4001",
            ":4001",
        ] {
            assert!(authority(invalid).is_none(), "{invalid}");
        }
    }

    #[tokio::test]
    async fn zero_ttl_answers_are_delivered_once_per_synchronous_negotiation_scope() {
        let (resolver, _) = fixture();
        let (address, server) = server_ttl(false, 0).await;
        local_resolvers(&resolver, &[(1, address)]);
        let endpoints = Arc::new(Endpoints::new(resolver));
        let mut changed = endpoints.changed.subscribe();
        assert!(endpoints.candidates("target.example:4001").is_empty());
        tokio::time::timeout(Duration::from_secs(2), changed.changed())
            .await
            .unwrap()
            .unwrap();
        let _permits = endpoints
            .workers
            .acquire_many(MAX_QUERIES as u32)
            .await
            .unwrap();
        let snapshot = {
            let _delivery = delivery_scope();
            let first = endpoints.candidates("target.example:4001");
            assert!(!first.is_empty());
            assert_eq!(endpoints.candidates("target.example:4001"), first);
            assert!(endpoints.entries.lock().unwrap().is_empty());
            capture_snapshot()
        };
        assert!(endpoints.candidates("target.example:4001").is_empty());
        {
            let _later_stage = delivery_scope();
            assert!(snapshot.restore());
            assert!(!endpoints.candidates("target.example:4001").is_empty());
            endpoints
                .resolver
                .0
                .networks
                .publish(inventory(2, 2))
                .unwrap();
            assert!(!snapshot.is_current());
            assert!(!snapshot.restore());
            assert!(endpoints.candidates("target.example:4001").is_empty());
        }
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }
}
