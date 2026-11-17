use super::*;
use crate::runtime::physical_network::{
    PhysicalNetworkKind,
    android::{Inventory, SocketBinder},
};
use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::{
        RData, Record, RecordType,
        rdata::{A, AAAA, TXT},
    },
};
use libp2p::dns::Resolver as _;
use std::os::fd::BorrowedFd;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(Debug, Default)]
pub(super) struct Binder {
    pub(super) calls: Mutex<Vec<u64>>,
    failed: Mutex<Vec<u64>>,
}

impl SocketBinder for Binder {
    fn bind(&self, network: u64, _: BorrowedFd<'_>) -> io::Result<()> {
        self.calls.lock().unwrap().push(network);
        if self.failed.lock().unwrap().contains(&network) {
            return Err(io::ErrorKind::NetworkUnreachable.into());
        }
        Ok(())
    }
}

pub(super) fn inventory(revision: u64, preferred: u64) -> Inventory {
    Inventory {
        revision,
        preferred_network: Some(preferred),
        networks: (1..=2)
            .map(|handle| NetworkRecord {
                network_handle: handle,
                incarnation: handle,
                revision: 1,
                kind: if handle == 1 {
                    PhysicalNetworkKind::Wifi
                } else {
                    PhysicalNetworkKind::Cellular
                },
                interface_name: format!("test{handle}"),
                interface_index: handle as u32,
                validated: true,
                addresses: [format!("192.0.2.{handle}").parse().unwrap()].into(),
                routes: Vec::new(),
                dns_servers: vec![format!("192.0.2.{}", handle + 50).parse().unwrap()],
                private_dns_active: false,
            })
            .collect(),
    }
}

pub(super) fn fixture() -> (NetworkResolver, Arc<Binder>) {
    let networks = Arc::new(Networks::default());
    networks.publish(inventory(1, 1)).unwrap();
    let binder = Arc::new(Binder::default());
    networks.binder.set(binder.clone()).unwrap();
    (NetworkResolver::with_networks(networks), binder)
}

pub(super) fn local_resolvers(resolver: &NetworkResolver, servers: &[(u64, SocketAddr)]) {
    let epoch = RouteEpoch::new(
        Arc::clone(&resolver.0.networks),
        resolver.0.networks.revision(),
    );
    // Only replace upstream server endpoints for loopback fixtures; use the real
    // scope, provider, cache, DNS parser, socket factory and epoch checks.
    let resolvers = servers
        .iter()
        .map(|(network, server)| {
            scoped_resolver(Scope {
                epoch: epoch.clone(),
                network: *network,
                incarnation: *network,
                servers: vec![*server],
                preparations: Arc::clone(&resolver.0.preparations),
                platform_dns: false,
            })
        })
        .collect();
    *resolver.0.cached.lock().unwrap() = Some(Cached { epoch, resolvers });
}

pub(super) fn answer(request: &[u8], negative: bool, truncated: bool) -> Vec<u8> {
    answer_with_ttl(request, negative, truncated, 60)
}

fn answer_with_ttl(request: &[u8], negative: bool, truncated: bool, ttl: u32) -> Vec<u8> {
    let request = Message::from_vec(request).unwrap();
    let mut answer = Message::new();
    answer
        .set_id(request.id())
        .set_message_type(MessageType::Response)
        .set_recursion_desired(request.recursion_desired())
        .set_recursion_available(true)
        .set_authoritative(true)
        .set_truncated(truncated);
    if negative {
        answer.set_response_code(ResponseCode::NXDomain);
    }
    for query in request.queries() {
        answer.add_query(query.clone());
        if negative || truncated {
            continue;
        }
        let data = match query.query_type() {
            RecordType::A => RData::A(A("192.0.2.99".parse().unwrap())),
            RecordType::AAAA => RData::AAAA(AAAA("2001:db8::99".parse().unwrap())),
            RecordType::TXT => RData::TXT(TXT::new(vec![
                "dnsaddr=/dns4/target.example/tcp/4001".to_owned(),
            ])),
            _ => continue,
        };
        answer.add_answer(Record::from_rdata(query.name().clone(), ttl, data));
    }
    answer.to_vec().unwrap()
}

pub(super) async fn server(negative: bool) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    server_ttl(negative, 60).await
}

pub(super) async fn server_ttl(
    negative: bool,
    ttl: u32,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        loop {
            let (length, remote) = socket.recv_from(&mut bytes).await.unwrap();
            socket
                .send_to(
                    &answer_with_ttl(&bytes[..length], negative, false, ttl),
                    remote,
                )
                .await
                .unwrap();
        }
    });
    (address, task)
}

#[test]
fn preference_dns_order_link_local_scope_and_epoch_are_preserved() {
    let (resolver, _) = fixture();
    let mut next = inventory(2, 2);
    next.networks[1].revision = 2;
    next.networks[1].dns_servers =
        vec!["fe80::53".parse().unwrap(), "2001:db8::53".parse().unwrap()];
    resolver.0.networks.publish(next).unwrap();
    let selected = resolver.resolvers().unwrap();
    assert_eq!(
        selected
            .iter()
            .map(|value| value.scope.network)
            .collect::<Vec<_>>(),
        vec![2, 1]
    );
    assert_eq!(
        selected[0].scope.servers,
        vec![
            "[fe80::53%2]:53".parse().unwrap(),
            "[2001:db8::53]:53".parse().unwrap()
        ]
    );
    let mut returned = inventory(3, 1);
    returned.networks[1].revision = 3;
    resolver.0.networks.publish(returned).unwrap();
    assert_eq!(
        selected[0].scope.check().unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(resolver.resolvers().unwrap()[0].scope.network, 1);
}

#[test]
fn absent_network_dns_never_uses_process_or_public_defaults() {
    let (resolver, binder) = fixture();
    let mut next = inventory(2, 1);
    for record in &mut next.networks {
        record.revision = 2;
        record.dns_servers.clear();
    }
    resolver.0.networks.publish(next).unwrap();
    assert_eq!(
        resolver.resolvers().err().unwrap().kind(),
        io::ErrorKind::NotConnected
    );
    assert!(binder.calls.lock().unwrap().is_empty());
}

#[test]
fn unresolved_names_use_default_dns_not_an_arbitrary_lan_destination() {
    let (resolver, _) = fixture();
    let mut next = inventory(2, 2);
    next.networks[0].revision = 2;
    next.networks[0].routes.push(super::super::NetworkRoute {
        destination: "0.0.0.0".parse().unwrap(),
        prefix_length: 8,
        gateway: None,
    });
    resolver.0.networks.publish(next).unwrap();
    assert_eq!(resolver.resolvers().unwrap()[0].scope.network, 2);
}

#[test]
fn private_dns_never_silently_falls_back_to_plaintext() {
    let (resolver, binder) = fixture();
    resolver.resolvers().unwrap();
    let mut next = inventory(2, 1);
    next.networks[0].revision = 2;
    next.networks[0].private_dns_active = true;
    resolver.0.networks.publish(next).unwrap();
    assert_eq!(
        resolver.resolvers().err().unwrap().kind(),
        io::ErrorKind::Unsupported
    );
    assert!(binder.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn real_dns_answers_and_cache_use_only_the_selected_network() {
    let (resolver, binder) = fixture();
    let (address, task) = server(false).await;
    local_resolvers(&resolver, &[(1, address)]);
    let a = resolver
        .ipv4_lookup("target.example.".into())
        .await
        .unwrap();
    assert_eq!(
        a.iter().next().unwrap().0,
        "192.0.2.99".parse::<std::net::Ipv4Addr>().unwrap()
    );
    let count = binder.calls.lock().unwrap().len();
    resolver
        .ipv4_lookup("target.example.".into())
        .await
        .unwrap();
    assert_eq!(binder.calls.lock().unwrap().len(), count);
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
    let ip = resolver.lookup_ip("target.example.".into()).await.unwrap();
    assert!(ip.iter().any(|address| address.is_ipv4()));
    assert!(
        binder
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|network| *network == 1)
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn connectivity_failure_can_fallback_but_authoritative_negative_cannot() {
    for negative in [false, true] {
        let (resolver, binder) = fixture();
        let (address, task) = server(negative).await;
        local_resolvers(&resolver, &[(1, address), (2, address)]);
        if !negative {
            binder.failed.lock().unwrap().push(1);
        }
        let result = resolver.ipv4_lookup("target.example.".into()).await;
        if negative {
            assert!(result.unwrap_err().is_nx_domain());
            assert!(
                binder
                    .calls
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|network| *network == 1)
            );
        } else {
            result.unwrap();
            assert_eq!(binder.calls.lock().unwrap().first(), Some(&1));
            assert_eq!(binder.calls.lock().unwrap().last(), Some(&2));
        }
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
}

#[tokio::test]
async fn stale_udp_scope_cannot_transmit_or_admit_a_new_socket() {
    let (resolver, binder) = fixture();
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = receiver.local_addr().unwrap();
    local_resolvers(&resolver, &[(1, server)]);
    let scope = resolver.resolvers().unwrap()[0].scope.clone();
    let runtime = NetworkRuntime {
        scope,
        handle: TokioHandle::default(),
    };
    let socket = runtime
        .bind_udp("0.0.0.0:0".parse().unwrap(), server)
        .await
        .unwrap();
    resolver.0.networks.publish(inventory(2, 2)).unwrap();
    assert_eq!(
        socket.send_to(b"stale", server).await.unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(
        runtime
            .bind_udp("0.0.0.0:0".parse().unwrap(), server)
            .await
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(*binder.calls.lock().unwrap(), vec![1]);
    let mut bytes = [0; 8];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), receiver.recv_from(&mut bytes))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_silent_first_server_does_not_consume_the_entire_network_budget() {
    let (resolver, binder) = fixture();
    let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (healthy, task) = server(false).await;
    local_resolvers(&resolver, &[(1, healthy)]);
    let mut scope = resolver.resolvers().unwrap()[0].scope.clone();
    scope.servers.insert(0, blackhole.local_addr().unwrap());
    resolver
        .0
        .cached
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .resolvers[0] = scoped_resolver(scope);
    resolver
        .ipv4_lookup("target.example.".into())
        .await
        .unwrap();
    let mut bytes = [0; 4096];
    assert!(blackhole.try_recv_from(&mut bytes).is_ok());
    assert!(
        binder
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|network| *network == 1)
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn response_received_after_epoch_change_cannot_escape_the_resolver() {
    let (resolver, _) = fixture();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    local_resolvers(&resolver, &[(1, socket.local_addr().unwrap())]);
    let query = {
        let resolver = resolver.clone();
        tokio::spawn(async move { resolver.ipv4_lookup("target.example.".into()).await })
    };
    let mut bytes = [0; 4096];
    let (length, remote) = socket.recv_from(&mut bytes).await.unwrap();
    resolver.0.networks.publish(inventory(2, 2)).unwrap();
    socket
        .send_to(&answer(&bytes[..length], false, false), remote)
        .await
        .unwrap();
    assert!(query.await.unwrap().is_err());
}

#[tokio::test]
async fn capacity_denial_and_wrong_server_do_not_transmit() {
    let (resolver, binder) = fixture();
    let permits = resolver
        .0
        .queries
        .acquire_many(MAX_QUERIES as u32)
        .await
        .unwrap();
    assert!(
        resolver
            .ipv4_lookup("target.example.".into())
            .await
            .is_err()
    );
    assert!(binder.calls.lock().unwrap().is_empty());
    drop(permits);
    let server: SocketAddr = "127.0.0.1:53".parse().unwrap();
    local_resolvers(&resolver, &[(1, server)]);
    let runtime = NetworkRuntime {
        scope: resolver.resolvers().unwrap()[0].scope.clone(),
        handle: TokioHandle::default(),
    };
    let other: SocketAddr = "127.0.0.1:54".parse().unwrap();
    assert_eq!(
        runtime
            .bind_udp("0.0.0.0:0".parse().unwrap(), other)
            .await
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    let socket = runtime
        .bind_udp("0.0.0.0:0".parse().unwrap(), server)
        .await
        .unwrap();
    assert_eq!(
        socket
            .send_to(b"unexpected", other)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[tokio::test]
async fn truncated_udp_response_falls_back_to_tcp_on_the_same_network() {
    let (resolver, binder) = fixture();
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = udp.local_addr().unwrap();
    let tcp = tokio::net::TcpListener::bind(address).await.unwrap();
    local_resolvers(&resolver, &[(1, address)]);
    let server = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        let (length, remote) = udp.recv_from(&mut bytes).await.unwrap();
        udp.send_to(&answer(&bytes[..length], false, true), remote)
            .await
            .unwrap();
        let (mut stream, _) = tcp.accept().await.unwrap();
        let length = stream.read_u16().await.unwrap() as usize;
        stream.read_exact(&mut bytes[..length]).await.unwrap();
        let response = answer(&bytes[..length], false, false);
        stream.write_u16(response.len() as u16).await.unwrap();
        stream.write_all(&response).await.unwrap();
    });
    resolver
        .ipv4_lookup("target.example.".into())
        .await
        .unwrap();
    server.await.unwrap();
    assert!(binder.calls.lock().unwrap().len() >= 2);
    assert!(
        binder
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|network| *network == 1)
    );
}

#[tokio::test]
async fn upstream_dns_transport_preserves_recursive_dnsaddr_and_family_resolution() {
    use libp2p::{
        Multiaddr, Transport as _,
        core::{
            Endpoint,
            transport::{DialOpts, ListenerId, PortUse, TransportError, TransportEvent},
        },
    };
    struct Echo;
    impl libp2p::Transport for Echo {
        type Output = Multiaddr;
        type Error = io::Error;
        type Dial = futures::future::Ready<io::Result<Multiaddr>>;
        type ListenerUpgrade = Self::Dial;
        fn listen_on(
            &mut self,
            _: ListenerId,
            address: Multiaddr,
        ) -> Result<(), TransportError<Self::Error>> {
            Err(TransportError::MultiaddrNotSupported(address))
        }
        fn remove_listener(&mut self, _: ListenerId) -> bool {
            false
        }
        fn dial(
            &mut self,
            address: Multiaddr,
            _: DialOpts,
        ) -> Result<Self::Dial, TransportError<Self::Error>> {
            if !address.iter().any(|protocol| {
                matches!(
                    protocol,
                    libp2p::multiaddr::Protocol::Ip4(_) | libp2p::multiaddr::Protocol::Ip6(_)
                )
            }) {
                return Err(TransportError::MultiaddrNotSupported(address));
            }
            Ok(futures::future::ready(Ok(address)))
        }
        fn poll(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
            Poll::Pending
        }
    }
    let (resolver, binder) = fixture();
    let (address, task) = server(false).await;
    local_resolvers(&resolver, &[(1, address)]);
    let mut transport = libp2p::dns::Transport::with_resolver(Echo, resolver);
    for (input, expected) in [
        ("/dnsaddr/root.example", "/ip4/192.0.2.99/tcp/4001"),
        ("/dns4/target.example/tcp/4001", "/ip4/192.0.2.99/tcp/4001"),
        (
            "/dns6/target.example/udp/4001/quic-v1",
            "/ip6/2001:db8::99/udp/4001/quic-v1",
        ),
    ] {
        let resolved = transport
            .dial(
                input.parse().unwrap(),
                DialOpts {
                    role: Endpoint::Dialer,
                    port_use: PortUse::New,
                },
            )
            .unwrap()
            .await
            .unwrap();
        assert_eq!(resolved.to_string(), expected);
    }
    assert!(
        binder
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|network| *network == 1)
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
}
