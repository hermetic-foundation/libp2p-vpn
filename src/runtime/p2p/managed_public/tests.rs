use super::*;
use futures::future::{Ready, ready};
use libp2p::{core::Endpoint, kad, swarm::NetworkBehaviour};
use std::task::Poll;

#[tokio::test]
async fn public_circuit_exemption_is_exact_to_configured_entrance_and_member() {
    use libp2p::relay::client::CircuitEntrancePolicy as _;

    let relay = PeerId::random();
    let member = PeerId::random();
    let other_member = PeerId::random();
    let explicit_reservation: Multiaddr = "/ip4/11.251.0.1/tcp/4001".parse().unwrap();
    let explicit_member: Multiaddr = "/ip4/11.251.0.2/tcp/4001".parse().unwrap();
    let alternate: Multiaddr = "/ip4/11.251.0.3/tcp/4001".parse().unwrap();
    let lan: Multiaddr = "/ip4/192.168.12.1/tcp/4001".parse().unwrap();
    let config = super::super::HostConfig {
        identity: crate::identity::NodeIdentity::generate_ed25519().unwrap(),
        network_name: "test".to_owned(),
        membership_tag: None,
        mtu: 1280,
        max_concurrent_control_streams: 8,
        max_concurrent_packet_streams: 8,
        listen_addresses: Vec::new(),
        external_addresses: Vec::new(),
        bootstrap_peers: Vec::new(),
        known_peers: vec![(
            member,
            format!("{explicit_member}/p2p/{relay}/p2p-circuit/p2p/{member}")
                .parse()
                .unwrap(),
        )],
        relay_reservations: vec![
            format!("{explicit_reservation}/p2p/{relay}/p2p-circuit")
                .parse()
                .unwrap(),
        ],
        relay_server: false,
        relay_resources: Default::default(),
        resources: Default::default(),
        discovery: Default::default(),
    };
    let policy = CircuitEntrancePolicy::new(Arc::new(ControlRoutes::new(8)), &config);
    assert!(!policy.requires_scope(relay, &explicit_reservation, other_member));
    assert!(!policy.requires_scope(relay, &explicit_member, member));
    assert!(policy.requires_scope(relay, &explicit_member, other_member));
    assert!(policy.requires_scope(relay, &alternate, member));
    assert!(!policy.requires_scope(relay, &lan, member));
    assert!(policy.requires_scope(PeerId::random(), &explicit_member, member));
}

#[derive(Default, Clone)]
struct Recorder(Arc<Mutex<Vec<(PortUse, bool)>>>);

impl Transport for Recorder {
    type Output = Output;
    type Error = io::Error;
    type Dial = Ready<io::Result<Output>>;
    type ListenerUpgrade = Self::Dial;

    fn listen_on(
        &mut self,
        _: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        Err(TransportError::MultiaddrNotSupported(addr))
    }

    fn remove_listener(&mut self, _: ListenerId) -> bool {
        false
    }

    fn dial(
        &mut self,
        _: Multiaddr,
        opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        self.0
            .lock()
            .unwrap()
            .push((opts.port_use, public_discovery::current().is_some()));
        Ok(ready(Err(io::ErrorKind::ConnectionRefused.into())))
    }

    fn poll(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Poll::Pending
    }
}

#[tokio::test]
async fn public_discovery_transport_scopes_only_exact_dials_and_stops_stale_attempts() {
    let routes = Arc::new(ControlRoutes::new(8));
    let recorder = Recorder::default();
    let resolved = ScopedTransport::new(recorder.clone().boxed(), None);
    let mut transport = ScopedTransport::new(resolved.boxed(), Some(Arc::clone(&routes))).boxed();
    let opts = DialOpts {
        port_use: PortUse::Reuse,
        role: Endpoint::Dialer,
    };
    let address: Multiaddr = "/ip4/203.0.113.9/tcp/1234".parse().unwrap();
    let scoped = ConnectionId::new_unchecked(41);
    routes.mark_public_discovery_dial(scoped).unwrap();
    assert!(
        transport
            .dial_with_connection_id(address.clone(), opts, 40)
            .unwrap()
            .await
            .is_err()
    );
    assert!(
        transport
            .dial_with_connection_id(address.clone(), opts, 41)
            .unwrap()
            .await
            .is_err()
    );
    assert_eq!(
        *recorder.0.lock().unwrap(),
        [(PortUse::Reuse, false), (PortUse::New, true)]
    );

    let in_flight = transport
        .dial_with_connection_id(address, opts, 41)
        .unwrap();
    routes.egress.retire_observer_for_test();
    let error = in_flight.await.unwrap_err();
    assert_eq!(
        error
            .get_ref()
            .and_then(|error| error.downcast_ref::<io::Error>())
            .map(io::Error::kind),
        Some(io::ErrorKind::Interrupted)
    );
    assert_eq!(recorder.0.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn public_discovery_tcp_revocation_shuts_down_established_io() {
    use crate::runtime::physical_network::public_discovery::{GuardedIo, Scope};
    use futures::io::AsyncWriteExt as _;
    use hickory_proto::runtime::iocompat::AsyncIoTokioAsStd;
    use tokio::io::AsyncReadExt as _;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socket = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (mut receiver, _) = listener.accept().await.unwrap();
    let owner = Arc::new(ControlRoutes::new(2));
    let scope = Scope::new(Arc::clone(&owner.egress)).unwrap();
    let shutdown = socket2::SockRef::from(&socket).try_clone().unwrap();
    let mut scoped = GuardedIo::new(AsyncIoTokioAsStd(socket), scope, shutdown).unwrap();
    scoped.write_all(b"allow").await.unwrap();
    let mut bytes = [0; 5];
    receiver.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"allow");
    owner.egress.retire_observer_for_test();
    assert_eq!(
        scoped.write_all(b"deny").await.unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    let read = tokio::time::timeout(std::time::Duration::from_secs(1), receiver.read(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read, 0);
}

#[tokio::test]
async fn public_discovery_resolved_transport_rejects_circuits_and_loopback() {
    let owner = Arc::new(ControlRoutes::new(2));
    let scope = super::public_discovery::Scope::new(Arc::clone(&owner.egress)).unwrap();
    let recorder = Recorder::default();
    let mut direct = ScopedTransport::new(recorder.clone().boxed(), None);
    let opts = DialOpts {
        port_use: PortUse::New,
        role: Endpoint::Dialer,
    };
    let circuit = format!(
        "/ip4/203.0.113.9/tcp/1234/p2p/{}/p2p-circuit/p2p/{}",
        PeerId::random(),
        PeerId::random()
    );
    DIAL.scope(scope, async {
        for address in [
            circuit.as_str(),
            "/ip4/127.0.0.1/tcp/1234",
            "/ip6/::ffff:127.0.0.1/tcp/1234",
        ] {
            assert!(matches!(
                direct.dial(address.parse().unwrap(), opts),
                Err(TransportError::Other(_))
            ));
        }
    })
    .await;
    assert!(recorder.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn public_discovery_kademlia_dials_around_an_unscoped_connection_and_cleans_failure() {
    use libp2p::{
        core::ConnectedPoint,
        swarm::{
            DialError, FromSwarm, ToSwarm,
            behaviour::{ConnectionEstablished, DialFailure},
        },
    };
    let local = PeerId::random();
    let remote = PeerId::random();
    let routes = Arc::new(ControlRoutes::new(4));
    let mut kad = kad::Behaviour::new(local, kad::store::MemoryStore::new(local));
    kad.set_outbound_discovery_policy(Arc::clone(&routes) as Arc<dyn kad::OutboundDiscoveryPolicy>);
    let address: Multiaddr = "/ip4/203.0.113.9/tcp/1234".parse().unwrap();
    kad.add_address(&remote, address.clone());
    let unscoped = ConnectionId::new_unchecked(41);
    let endpoint = ConnectedPoint::Dialer {
        address: address.clone(),
        role_override: Endpoint::Dialer,
        port_use: PortUse::Reuse,
    };
    let _handler = kad
        .handle_established_outbound_connection(
            unscoped,
            remote,
            &address,
            Endpoint::Dialer,
            PortUse::Reuse,
        )
        .unwrap();
    kad.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
        peer_id: remote,
        connection_id: unscoped,
        endpoint: &endpoint,
        failed_addresses: &[],
        other_established: 0,
    }));
    kad.get_closest_peers(remote);
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    let id = (0..8)
        .find_map(|_| match kad.poll(&mut cx) {
            Poll::Ready(ToSwarm::Dial { opts }) => Some(opts.connection_id()),
            Poll::Ready(ToSwarm::NotifyHandler { .. }) => {
                panic!("unscoped connection got a public RPC")
            }
            _ => None,
        })
        .expect("query should start a separate scoped dial");
    assert_ne!(id, unscoped);
    assert!(routes.public_discovery_dial(id).unwrap().is_some());
    kad.on_swarm_event(FromSwarm::DialFailure(DialFailure {
        peer_id: Some(remote),
        connection_id: id,
        error: &DialError::NoAddresses,
    }));
    assert!(routes.public_discovery_dial(id).unwrap().is_none());
}
