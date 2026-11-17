use super::super::{
    NetworkResolver, Networks,
    tests::{answer, inventory},
};
use super::*;
use crate::runtime::physical_network::android::{PlatformDnsQuery, SocketBinder};
use hickory_proto::{op::Message, rr::Name};
use libp2p::dns::Resolver as _;
use std::{
    os::{
        fd::{AsRawFd, BorrowedFd, RawFd},
        unix::net::UnixDatagram,
    },
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

#[derive(Clone, Copy, Debug)]
enum Mode {
    Reply,
    Negative,
    WrongQuestion,
    Malformed,
    Unsupported,
    Pending,
}

#[derive(Debug)]
struct State {
    mode: Mode,
    calls: Mutex<Vec<(u64, Vec<u8>)>>,
    binds: AtomicUsize,
    finished: AtomicUsize,
    canceled: AtomicUsize,
    pending: Mutex<Vec<UnixDatagram>>,
}

#[derive(Debug)]
struct Binder {
    state: Arc<State>,
    available: bool,
}

impl SocketBinder for Binder {
    fn bind(&self, _: u64, _: BorrowedFd<'_>) -> io::Result<()> {
        self.state.binds.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Plaintext DNS forbidden in fixture",
        ))
    }
    fn supports_platform_dns(&self) -> bool {
        self.available
    }
    fn start_dns_query(
        &self,
        network: u64,
        message: &[u8],
    ) -> io::Result<Box<dyn PlatformDnsQuery>> {
        self.state
            .calls
            .lock()
            .unwrap()
            .push((network, message.to_vec()));
        if matches!(self.state.mode, Mode::Unsupported) {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let (socket, peer) = UnixDatagram::pair()?;
        socket.set_nonblocking(true)?;
        match self.state.mode {
            Mode::Pending => self.state.pending.lock().unwrap().push(peer),
            Mode::Malformed => {
                peer.send(b"invalid")?;
            }
            mode => {
                let mut bytes = answer(message, matches!(mode, Mode::Negative), false);
                if matches!(mode, Mode::WrongQuestion) {
                    let mut response = Message::from_vec(&bytes).unwrap();
                    response.queries_mut()[0].set_name(Name::from_ascii("other.example.").unwrap());
                    bytes = response.to_vec().unwrap();
                }
                peer.send(&bytes)?;
            }
        }
        Ok(Box::new(Query {
            socket,
            state: Arc::clone(&self.state),
            finished: false,
        }))
    }
}

#[derive(Debug)]
struct Query {
    socket: UnixDatagram,
    state: Arc<State>,
    finished: bool,
}

impl AsRawFd for Query {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

impl PlatformDnsQuery for Query {
    fn finish(mut self: Box<Self>) -> io::Result<Vec<u8>> {
        self.finished = true;
        self.state.finished.fetch_add(1, Ordering::SeqCst);
        let mut bytes = vec![0; MAX_DNS_PACKET];
        let length = self.socket.recv(&mut bytes)?;
        bytes.truncate(length);
        Ok(bytes)
    }
}

impl Drop for Query {
    fn drop(&mut self) {
        if !self.finished {
            self.state.canceled.fetch_add(1, Ordering::SeqCst);
        }
    }
}

fn fixture(mode: Mode, available: bool) -> (NetworkResolver, Arc<State>) {
    let networks = Arc::new(Networks::default());
    let mut initial = inventory(1, 1);
    for record in &mut initial.networks {
        record.private_dns_active = true;
        // Native DNS must work without guessing servers or leaking the internal dispatch key.
        record.dns_servers.clear();
    }
    networks.publish(initial).unwrap();
    let state = Arc::new(State {
        mode,
        calls: Mutex::new(Vec::new()),
        binds: AtomicUsize::new(0),
        finished: AtomicUsize::new(0),
        canceled: AtomicUsize::new(0),
        pending: Mutex::new(Vec::new()),
    });
    networks
        .binder
        .set(Arc::new(Binder {
            state: Arc::clone(&state),
            available,
        }))
        .unwrap();
    (NetworkResolver::with_networks(networks), state)
}

async fn started(state: &State) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while state.calls.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

async fn canceled(state: &State) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while state.canceled.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn private_dns_uses_exact_network_native_records_and_cache_without_plaintext() {
    let (resolver, state) = fixture(Mode::Reply, true);
    let a = resolver
        .ipv4_lookup("target.example.".into())
        .await
        .unwrap();
    assert_eq!(a.iter().next().unwrap().0.to_string(), "192.0.2.99");
    let count = state.calls.lock().unwrap().len();
    resolver
        .ipv4_lookup("target.example.".into())
        .await
        .unwrap();
    assert_eq!(state.calls.lock().unwrap().len(), count);
    assert!(
        resolver
            .ipv6_lookup("target.example.".into())
            .await
            .unwrap()
            .iter()
            .next()
            .is_some()
    );
    assert!(
        resolver
            .txt_lookup("_dnsaddr.target.example.".into())
            .await
            .unwrap()
            .iter()
            .next()
            .is_some()
    );
    assert!(
        state
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|(network, _)| *network == 1)
    );
    assert_eq!(state.binds.load(Ordering::SeqCst), 0);
    assert_eq!(state.finished.load(Ordering::SeqCst), 3);
    assert_eq!(state.canceled.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unsupported_private_dns_never_downgrades_to_raw_sockets() {
    for available in [false, true] {
        let (resolver, state) = fixture(Mode::Unsupported, available);
        assert!(
            resolver
                .ipv4_lookup("target.example.".into())
                .await
                .is_err()
        );
        assert_eq!(state.binds.load(Ordering::SeqCst), 0);
        assert_eq!(state.finished.load(Ordering::SeqCst), 0);
        if !available {
            assert!(state.calls.lock().unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn negative_native_answers_do_not_fallback_or_leak_a_descriptor() {
    let (resolver, state) = fixture(Mode::Negative, true);
    assert!(
        resolver
            .ipv4_lookup("missing.example.".into())
            .await
            .unwrap_err()
            .is_nx_domain()
    );
    assert_eq!(state.calls.lock().unwrap().len(), 1);
    assert_eq!(state.finished.load(Ordering::SeqCst), 1);
    assert_eq!(state.canceled.load(Ordering::SeqCst), 0);
    assert_eq!(state.binds.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn invalid_native_response_cannot_enter_the_dns_cache() {
    for mode in [Mode::WrongQuestion, Mode::Malformed] {
        let (resolver, state) = fixture(mode, true);
        assert!(
            resolver
                .ipv4_lookup("target.example.".into())
                .await
                .is_err()
        );
        assert_eq!(state.binds.load(Ordering::SeqCst), 0);
        assert_eq!(state.finished.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn canceled_native_wait_cancels_its_owned_descriptor_without_finishing() {
    let (resolver, state) = fixture(Mode::Pending, true);
    let query = tokio::spawn(async move { resolver.ipv4_lookup("target.example.".into()).await });
    started(&state).await;
    query.abort();
    assert!(query.await.unwrap_err().is_cancelled());
    canceled(&state).await;
    assert_eq!(state.canceled.load(Ordering::SeqCst), 1);
    assert_eq!(state.finished.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn inventory_change_interrupts_native_wait_and_rejects_late_result() {
    let (resolver, state) = fixture(Mode::Pending, true);
    let task = {
        let resolver = resolver.clone();
        tokio::spawn(async move { resolver.ipv4_lookup("target.example.".into()).await })
    };
    started(&state).await;
    let mut next = inventory(2, 2);
    for record in &mut next.networks {
        record.revision = 2;
        record.private_dns_active = true;
        record.dns_servers.clear();
    }
    resolver.0.networks.publish(next).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    canceled(&state).await;
    assert_eq!(state.canceled.load(Ordering::SeqCst), 1);
    assert_eq!(state.finished.load(Ordering::SeqCst), 0);
}
