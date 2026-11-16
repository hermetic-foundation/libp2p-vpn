//! Native Linux loopback UDP/TLS evidence, not Android Network/netd proof.

#![cfg(target_os = "linux")]

use futures::{
    FutureExt,
    future::{BoxFuture, poll_fn},
    io::{AsyncReadExt, AsyncWriteExt},
};
use libp2p::{
    Multiaddr, PeerId, Transport,
    core::{
        Endpoint,
        muxing::StreamMuxer,
        transport::{DialOpts, ListenerId, PortUse, TransportEvent},
    },
    identity::Keypair,
    multiaddr::Protocol,
    quic::{self, ConnectionOwner, DialOperation, Selection, SocketContext, SocketPolicy},
};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

type NativeTransport = quic::tokio::Transport;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(300);
const DIAL_BUDGET: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, Eq, PartialEq)]
enum Event {
    Selected(usize),
    BeforeHandshake(usize),
    Authenticated(usize, PeerId),
    Admitted(usize, usize),
    Failed(usize),
    Dropped(usize),
}

type Events = Arc<Mutex<Vec<Event>>>;

#[derive(Debug)]
struct Owner {
    attempt: usize,
    events: Events,
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Event::Dropped(self.attempt));
    }
}

impl ConnectionOwner for Owner {
    fn before_handshake(&self) -> io::Result<()> {
        self.events
            .lock()
            .unwrap()
            .push(Event::BeforeHandshake(self.attempt));
        Ok(())
    }

    fn authenticated(&mut self, peer: PeerId) -> io::Result<()> {
        self.events
            .lock()
            .unwrap()
            .push(Event::Authenticated(self.attempt, peer));
        Ok(())
    }

    fn admitted(&mut self, connection_id: usize) -> io::Result<()> {
        self.events
            .lock()
            .unwrap()
            .push(Event::Admitted(self.attempt, connection_id));
        Ok(())
    }
}

fn selection(
    source: Ipv4Addr,
    interface: NonZeroU32,
    attempt: usize,
    events: &Events,
) -> Selection {
    events.lock().unwrap().push(Event::Selected(attempt));
    Selection {
        source: source.into(),
        interface,
        owner: Box::new(Owner {
            attempt,
            events: Arc::clone(events),
        }),
    }
}

#[derive(Debug)]
struct LegacyPolicy {
    preparations: Arc<AtomicUsize>,
    fail_preparation: bool,
    events: Events,
}

impl SocketPolicy for LegacyPolicy {
    fn prepare(&self, _context: SocketContext) -> BoxFuture<'static, io::Result<Selection>> {
        self.preparations.fetch_add(1, Ordering::SeqCst);
        let fail = self.fail_preparation;
        let events = Arc::clone(&self.events);
        async move {
            if fail {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "legacy preparation denied",
                ))
            } else {
                Ok(selection(
                    Ipv4Addr::LOCALHOST,
                    NonZeroU32::new(1).unwrap(),
                    0,
                    &events,
                ))
            }
        }
        .boxed()
    }
}

fn mock_context() -> SocketContext {
    SocketContext {
        local: "0.0.0.0:41000".parse().unwrap(),
        remote: "127.0.0.1:41001".parse().unwrap(),
        role: Endpoint::Dialer,
        mark: 0,
    }
}

#[tokio::test]
async fn existing_policy_default_dial_prepares_and_calls_operation_once() {
    let preparations = Arc::new(AtomicUsize::new(0));
    let operations = Arc::new(AtomicUsize::new(0));
    let events = Events::default();
    let policy = LegacyPolicy {
        preparations: Arc::clone(&preparations),
        fail_preparation: false,
        events: Arc::clone(&events),
    };
    let context = mock_context();
    assert_eq!(
        policy.dial_timeout(context, None, HANDSHAKE_TIMEOUT),
        HANDSHAKE_TIMEOUT
    );
    let calls = Arc::clone(&operations);
    let operation: DialOperation = Box::new(move |selected| {
        calls.fetch_add(1, Ordering::SeqCst);
        async move {
            let _selected = selected;
            tokio::time::sleep(Duration::from_millis(10)).await;
            Err(quic::Error::HandshakeTimedOut)
        }
        .boxed()
    });
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        policy.dial(context, None, HANDSHAKE_TIMEOUT, operation),
    )
    .await
    .unwrap();
    assert!(matches!(result, Err(quic::Error::HandshakeTimedOut)));
    assert_eq!(preparations.load(Ordering::SeqCst), 1);
    assert_eq!(operations.load(Ordering::SeqCst), 1);
    assert_eq!(
        *events.lock().unwrap(),
        [Event::Selected(0), Event::Dropped(0)]
    );
}

#[tokio::test]
async fn existing_policy_preparation_failure_never_calls_operation() {
    let preparations = Arc::new(AtomicUsize::new(0));
    let operations = Arc::new(AtomicUsize::new(0));
    let events = Events::default();
    let policy = LegacyPolicy {
        preparations: Arc::clone(&preparations),
        fail_preparation: true,
        events: Arc::clone(&events),
    };
    let calls = Arc::clone(&operations);
    let operation: DialOperation = Box::new(move |_selected| {
        calls.fetch_add(1, Ordering::SeqCst);
        async { Err(quic::Error::HandshakeTimedOut) }.boxed()
    });
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        policy.dial(mock_context(), None, HANDSHAKE_TIMEOUT, operation),
    )
    .await
    .unwrap();
    assert!(matches!(result, Err(quic::Error::Io(ref error))
        if error.kind() == io::ErrorKind::PermissionDenied
            && error.to_string() == "legacy preparation denied"));
    assert_eq!(preparations.load(Ordering::SeqCst), 1);
    assert_eq!(operations.load(Ordering::SeqCst), 0);
    assert!(events.lock().unwrap().is_empty());
}

#[derive(Debug)]
struct RetryPolicy {
    events: Events,
    contexts: Arc<Mutex<Vec<SocketContext>>>,
    interface: NonZeroU32,
    expected_peer: PeerId,
    timeout_calls: AtomicUsize,
}

impl SocketPolicy for RetryPolicy {
    fn prepare(&self, _context: SocketContext) -> BoxFuture<'static, io::Result<Selection>> {
        panic!("outgoing retry must use the dial hook, not hidden one-shot preparation")
    }

    fn dial(
        &self,
        context: SocketContext,
        peer: Option<PeerId>,
        handshake_timeout: Duration,
        mut operation: DialOperation,
    ) -> BoxFuture<'static, Result<(PeerId, quic::Connection), quic::Error>> {
        assert_eq!(peer, Some(self.expected_peer));
        assert_eq!(handshake_timeout, HANDSHAKE_TIMEOUT);
        assert!(
            context.local.ip().is_unspecified(),
            "source selection needs a wildcard socket"
        );
        assert_eq!(context.role, Endpoint::Dialer);
        assert_eq!(context.mark, 0);
        self.contexts.lock().unwrap().push(context);
        let events = Arc::clone(&self.events);
        let interface = self.interface;
        async move {
            for (attempt, source) in [(1, Ipv4Addr::new(127, 0, 0, 2)), (2, Ipv4Addr::LOCALHOST)] {
                if attempt == 2 {
                    assert!(
                        events.lock().unwrap().contains(&Event::Dropped(1)),
                        "failed native owner must drop before selecting the next attempt"
                    );
                }
                match operation(selection(source, interface, attempt, &events)).await {
                    Ok(connection) => return Ok(connection),
                    Err(error) => {
                        assert!(
                            matches!(error, quic::Error::HandshakeTimedOut),
                            "the blocked attempt must reach native handshake timeout: {error}"
                        );
                        events.lock().unwrap().push(Event::Failed(attempt));
                        if attempt == 2 {
                            return Err(error);
                        }
                    }
                }
            }
            unreachable!("the bounded retry loop returns on its second attempt")
        }
        .boxed()
    }

    fn dial_timeout(
        &self,
        _context: SocketContext,
        peer: Option<PeerId>,
        configured: Duration,
    ) -> Duration {
        assert_eq!(peer, Some(self.expected_peer));
        assert_eq!(configured, HANDSHAKE_TIMEOUT);
        self.timeout_calls.fetch_add(1, Ordering::SeqCst);
        DIAL_BUDGET
    }
}

#[derive(Debug, Default)]
struct ProxyStats {
    dropped: AtomicUsize,
    forwarded: AtomicUsize,
    replies: AtomicUsize,
    first_drop: tokio::sync::Notify,
    clients: Mutex<Vec<SocketAddr>>,
}

struct Proxy {
    address: SocketAddr,
    stats: Arc<ProxyStats>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

impl Proxy {
    async fn new(server: SocketAddr) -> Self {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let stats = Arc::new(ProxyStats::default());
        let observed = Arc::clone(&stats);
        let task = tokio::spawn(async move {
            let mut packet = vec![0_u8; 65_535];
            let mut client = None;
            loop {
                let (length, remote) = socket.recv_from(&mut packet).await.unwrap();
                if remote == server {
                    let client =
                        client.expect("only a forwarded handshake can cause a server reply");
                    socket.send_to(&packet[..length], client).await.unwrap();
                    observed.replies.fetch_add(1, Ordering::SeqCst);
                } else if remote.ip() == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)) {
                    observed.dropped.fetch_add(1, Ordering::SeqCst);
                    observed.first_drop.notify_one();
                } else {
                    assert_eq!(remote.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
                    client = Some(remote);
                    {
                        let mut clients = observed.clients.lock().unwrap();
                        if !clients.contains(&remote) {
                            clients.push(remote);
                        }
                    }
                    socket.send_to(&packet[..length], server).await.unwrap();
                    observed.forwarded.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        Self {
            address,
            stats,
            task: Some(task),
        }
    }

    async fn stop(mut self) {
        let task = self.task.take().unwrap();
        task.abort();
        assert!(
            task.await.unwrap_err().is_cancelled(),
            "UDP proxy must not fail internally"
        );
    }
}

fn loopback_interface() -> NonZeroU32 {
    NonZeroU32::new(
        std::fs::read_to_string("/sys/class/net/lo/ifindex")
            .expect("Linux loopback interface")
            .trim()
            .parse()
            .unwrap(),
    )
    .unwrap()
}

fn address(socket: SocketAddr, peer: PeerId) -> Multiaddr {
    Multiaddr::empty()
        .with(Protocol::Ip4(Ipv4Addr::LOCALHOST))
        .with(Protocol::Udp(socket.port()))
        .with(Protocol::QuicV1)
        .with(Protocol::P2p(peer))
}

async fn server() -> (NativeTransport, SocketAddr, PeerId) {
    let key = Keypair::generate_ed25519();
    let peer = key.public().to_peer_id();
    let mut transport = NativeTransport::new(quic::Config::new(&key));
    transport
        .listen_on(
            ListenerId::next(),
            "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        )
        .unwrap();
    let socket = match poll_fn(|cx| Pin::new(&mut transport).poll(cx)).await {
        TransportEvent::NewAddress { listen_addr, .. } => {
            let port = listen_addr
                .iter()
                .find_map(|part| match part {
                    Protocol::Udp(port) => Some(port),
                    _ => None,
                })
                .unwrap();
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
        }
        event => panic!("unexpected server startup event: {event:?}"),
    };
    (transport, socket, peer)
}

fn client(peer: PeerId) -> (NativeTransport, PeerId, Arc<RetryPolicy>) {
    let key = Keypair::generate_ed25519();
    let client_peer = key.public().to_peer_id();
    let policy = Arc::new(RetryPolicy {
        events: Events::default(),
        contexts: Arc::default(),
        interface: loopback_interface(),
        expected_peer: peer,
        timeout_calls: AtomicUsize::new(0),
    });
    let mut config = quic::Config::new(&key).with_socket_policy(policy.clone());
    config.handshake_timeout = HANDSHAKE_TIMEOUT;
    (NativeTransport::new(config), client_peer, policy)
}

#[tokio::test]
async fn native_tls_retries_after_source_specific_udp_drop_with_fresh_owner() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let (mut server, server_socket, server_peer) = server().await;
        let proxy = Proxy::new(server_socket).await;
        let (mut client, client_peer, policy) = client(server_peer);
        let dial = client
            .dial(
                address(proxy.address, server_peer),
                DialOpts {
                    role: Endpoint::Dialer,
                    port_use: PortUse::New,
                },
            )
            .unwrap();
        let accept = async {
            match poll_fn(|cx| Pin::new(&mut server).poll(cx)).await {
                TransportEvent::Incoming { upgrade, .. } => upgrade.await,
                event => panic!("unexpected native TLS listener event: {event:?}"),
            }
        };
        let (outgoing, incoming) = tokio::join!(dial, accept);
        let (authenticated_server, mut outgoing) = outgoing.unwrap();
        let (authenticated_client, mut incoming) = incoming.unwrap();
        assert_eq!(authenticated_server, server_peer);
        assert_eq!(authenticated_client, client_peer);
        assert!(proxy.stats.dropped.load(Ordering::SeqCst) > 0);
        assert!(proxy.stats.forwarded.load(Ordering::SeqCst) > 0);
        assert!(proxy.stats.replies.load(Ordering::SeqCst) > 0);
        assert_eq!(policy.timeout_calls.load(Ordering::SeqCst), 1);
        let contexts = policy.contexts.lock().unwrap().clone();
        assert_eq!(contexts.len(), 1);
        assert_eq!(contexts[0].remote, proxy.address);
        let events = policy.events.lock().unwrap().clone();
        let dropped = events
            .iter()
            .position(|event| *event == Event::Dropped(1))
            .unwrap();
        let selected = events
            .iter()
            .position(|event| *event == Event::Selected(2))
            .unwrap();
        assert!(dropped < selected);
        assert!(events.contains(&Event::Failed(1)));
        assert!(events.contains(&Event::BeforeHandshake(1)));
        assert!(events.contains(&Event::BeforeHandshake(2)));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::Authenticated(1, _)))
        );
        assert!(events.contains(&Event::Authenticated(2, server_peer)));

        // Exercise the public muxer admission hook; this raw-transport fixture
        // does not claim that the synthetic ID below came from a real Swarm.
        Pin::new(&mut outgoing).on_swarm_connection(700);
        assert!(
            policy
                .events
                .lock()
                .unwrap()
                .contains(&Event::Admitted(2, 700))
        );
        let payload = b"native TLS payload after exact-source retry";
        let send = async {
            let mut stream = poll_fn(|cx| Pin::new(&mut outgoing).poll_outbound(cx))
                .await
                .unwrap();
            stream.write_all(payload).await.unwrap();
            stream.flush().await.unwrap();
            let mut reply = vec![0_u8; payload.len()];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, payload);
        };
        let receive = async {
            let mut stream = poll_fn(|cx| Pin::new(&mut incoming).poll_inbound(cx))
                .await
                .unwrap();
            let mut received = vec![0_u8; payload.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, payload);
            stream.write_all(&received).await.unwrap();
            stream.flush().await.unwrap();
        };
        tokio::join!(send, receive);
        drop((outgoing, incoming, client, server));
        assert!(policy.events.lock().unwrap().contains(&Event::Dropped(2)));
        proxy.stop().await;
    })
    .await
    .expect("bounded real native UDP drop, TLS retry, payload and owner cleanup");
}

#[tokio::test]
async fn cancelling_blocked_native_handshake_drops_owner_and_never_retries() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (server, server_socket, server_peer) = server().await;
        let proxy = Proxy::new(server_socket).await;
        let (mut client, _, policy) = client(server_peer);
        let mut dial = client.dial(address(proxy.address, server_peer),
            DialOpts { role: Endpoint::Dialer, port_use: PortUse::New }).unwrap();
        tokio::select! {
            result = &mut dial => panic!("blocked native handshake completed before cancellation: {:?}", result.err()),
            () = proxy.stats.first_drop.notified() => {},
        }
        drop(dial);
        assert!(policy.events.lock().unwrap().contains(&Event::Dropped(1)));
        tokio::time::sleep(HANDSHAKE_TIMEOUT + Duration::from_millis(50)).await;
        let events = policy.events.lock().unwrap().clone();
        assert!(!events.contains(&Event::Selected(2)));
        assert!(!events.iter().any(|event| matches!(event, Event::Authenticated(_, _))));
        assert_eq!(proxy.stats.forwarded.load(Ordering::SeqCst), 0);
        assert!(proxy.stats.dropped.load(Ordering::SeqCst) > 0);
        drop((client, server));
        proxy.stop().await;
    }).await.expect("bounded native handshake cancellation without later retries");
}
