//! Thread-scoped, real zero-TTL DNS for Linux packet-negotiation tests.

use super::super::tests::{fixture, local_resolvers};
use super::{Endpoints, authority};
use hickory_proto::{
    op::{Message, MessageType},
    rr::{
        RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use std::{
    cell::RefCell,
    collections::BTreeSet,
    marker::PhantomData,
    net::{IpAddr, SocketAddr},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, sync::watch, task::JoinHandle};

thread_local! {
    static OVERRIDE: RefCell<Option<Arc<Endpoints>>> = const { RefCell::new(None) };
}

pub(crate) fn lookup(candidate: &str) -> Option<Vec<SocketAddr>> {
    let endpoints = OVERRIDE.with_borrow(Clone::clone)?;
    Some(endpoints.candidates(candidate))
}

pub(crate) fn subscribe() -> Option<watch::Receiver<()>> {
    OVERRIDE.with_borrow(|endpoints| {
        endpoints
            .as_ref()
            .map(|endpoints| endpoints.changed.subscribe())
    })
}

pub(crate) fn pending(candidate: &str) -> Option<bool> {
    OVERRIDE.with_borrow(|endpoints| {
        endpoints
            .as_ref()
            .map(|endpoints| endpoints.pending(candidate))
    })
}

struct OverrideGuard {
    previous: Option<Arc<Endpoints>>,
    _thread: PhantomData<Rc<()>>,
}

impl Drop for OverrideGuard {
    fn drop(&mut self) {
        OVERRIDE.with_borrow_mut(|endpoints| *endpoints = self.previous.take());
    }
}

pub(crate) struct EndpointFixture {
    endpoints: Arc<Endpoints>,
    server: Option<JoinHandle<()>>,
    requests: Arc<AtomicUsize>,
    _override: OverrideGuard,
}

impl EndpointFixture {
    pub(crate) async fn install(ip: IpAddr) -> Self {
        assert!(ip.is_loopback(), "endpoint fixture requires loopback");
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let (resolver, _) = fixture();
        local_resolvers(&resolver, &[(1, address)]);
        let endpoints = Arc::new(Endpoints::new(resolver));
        let requests = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&requests);
        let server = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            loop {
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                let request = Message::from_vec(&buffer[..length]).unwrap();
                let mut response = Message::new();
                response
                    .set_id(request.id())
                    .set_message_type(MessageType::Response)
                    .set_op_code(request.op_code())
                    .set_recursion_desired(request.recursion_desired())
                    .set_recursion_available(true)
                    .set_authoritative(true);
                for query in request.queries() {
                    response.add_query(query.clone());
                    let data = match (query.query_type(), ip) {
                        (RecordType::A, IpAddr::V4(ip)) => RData::A(A(ip)),
                        (RecordType::AAAA, IpAddr::V6(ip)) => RData::AAAA(AAAA(ip)),
                        _ => continue,
                    };
                    response.add_answer(Record::from_rdata(query.name().clone(), 0, data));
                }
                socket
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        let previous = OVERRIDE.with_borrow_mut(|active| active.replace(Arc::clone(&endpoints)));
        Self {
            endpoints,
            server: Some(server),
            requests,
            _override: OverrideGuard {
                previous,
                _thread: PhantomData,
            },
        }
    }

    pub(crate) fn updates(&self) -> watch::Receiver<()> {
        self.endpoints.changed.subscribe()
    }

    pub(crate) fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    pub(crate) fn invalidate(&self) {
        self.endpoints
            .resolver
            .0
            .networks
            .publish(super::super::tests::inventory(2, 1))
            .unwrap();
    }

    pub(crate) async fn ready(&self, candidates: &[&str]) {
        let mut changed = self.updates();
        let mut hosts = BTreeSet::new();
        for candidate in candidates {
            let (hostname, _) = authority(candidate).expect("hostname endpoint fixture candidate");
            if hosts.insert(hostname.clone())
                && !self
                    .endpoints
                    .entries
                    .lock()
                    .unwrap()
                    .contains_key(&hostname)
            {
                assert!(self.endpoints.candidates(candidate).is_empty());
            }
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let ready = {
                    let entries = self.endpoints.entries.lock().unwrap();
                    hosts.iter().all(|host| {
                        entries.get(host).is_some_and(|entry| {
                            !entry.addresses.is_empty() && entry.epoch.is_current()
                        })
                    })
                };
                if ready {
                    break;
                }
                changed.changed().await.unwrap();
            }
        })
        .await
        .expect("real zero-TTL endpoint DNS completed");
        let entries = self.endpoints.entries.lock().unwrap();
        for host in hosts {
            let entry = &entries[&host];
            assert!(
                entry.expires <= Instant::now(),
                "DNS answer must have zero TTL"
            );
            assert!(
                entry.delivery_until.is_some(),
                "readiness must not consume the handoff"
            );
        }
        assert!(self.requests() > 0, "fixture must use the UDP DNS backend");
    }

    pub(crate) async fn shutdown(mut self) {
        let server = self.server.take().unwrap();
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }
}

impl Drop for EndpointFixture {
    fn drop(&mut self) {
        if let Some(server) = &self.server {
            server.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn override_is_opt_in_and_ready_preserves_real_zero_ttl_handoff() {
        let candidate = "fixture-zero-ttl.example:4012";
        for ip in ["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()] {
            assert!(lookup(candidate).is_none());
            assert!(pending(candidate).is_none());
            assert!(subscribe().is_none());
            let fixture = EndpointFixture::install(ip).await;
            assert_eq!(pending(candidate), Some(false));
            assert!(fixture.endpoints.entries.lock().unwrap().is_empty());
            assert!(subscribe().is_some());
            fixture.ready(&[candidate]).await;
            assert_eq!(pending(candidate), Some(false));
            assert_eq!(lookup(candidate), Some(vec![SocketAddr::new(ip, 4012)]));
            assert!(fixture.endpoints.entries.lock().unwrap().is_empty());
            fixture.shutdown().await;
            assert!(lookup(candidate).is_none());
            assert!(pending(candidate).is_none());
            assert!(subscribe().is_none());
        }
    }
}
