//! Host factory/borrowed-FD models; the ignored Linux namespace test performs
//! real UDP I/O but substitutes a fixture binder for Android Network/netd.

use super::*;
use std::os::fd::{AsRawFd, RawFd};

#[test]
fn stale_udp_lease_fails_before_binder_or_concrete_source_bind() {
    let (state, binder, owner) = owner();
    let lease = owner
        .lease(
            "0.0.0.0:0".parse().unwrap(),
            "203.0.113.9:443".parse().unwrap(),
            SocketProtocol::Udp,
            0,
            false,
        )
        .unwrap();
    state.publish(inventory(2, Some(2))).unwrap();
    assert!(!lease.is_current());
    assert!(lease.is_available());
    assert_eq!(
        Egress::udp_socket(lease).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert!(binder.calls.lock().unwrap().is_empty());
}

#[derive(Debug)]
struct BindObservation {
    handle: u64,
    fd: RawFd,
    before: SocketAddr,
}

#[derive(Debug)]
struct DatagramBinder {
    state: std::sync::Weak<Networks>,
    source: IpAddr,
    mark: Option<u32>,
    publish_during_bind: bool,
    calls: Mutex<Vec<BindObservation>>,
}

impl SocketBinder for DatagramBinder {
    fn bind(&self, handle: u64, fd: BorrowedFd<'_>) -> io::Result<()> {
        let socket = socket2::SockRef::from(&fd);
        self.calls.lock().unwrap().push(BindObservation {
            handle,
            fd: fd.as_raw_fd(),
            before: socket.local_addr()?.as_socket().unwrap(),
        });
        if let Some(mark) = self.mark {
            socket.set_mark(mark)?;
        }
        if self.publish_during_bind {
            let state = self.state.upgrade().unwrap();
            let mut next = state.state.read().unwrap().inventory.clone();
            next.revision += 1;
            state.publish(next).unwrap();
        }
        Ok(())
    }

    fn source_for(&self, handle: u64, destination: SocketAddr) -> io::Result<SocketAddr> {
        assert_eq!(handle, 1);
        assert_eq!(self.source.is_ipv4(), destination.is_ipv4());
        Ok(SocketAddr::new(self.source, 1234))
    }
}

fn datagram_owner(
    source: IpAddr,
    mark: Option<u32>,
    publish_during_bind: bool,
) -> (Arc<Networks>, Arc<DatagramBinder>, Egress) {
    let state = Arc::new(Networks::default());
    let mut network = record(1, 1, &source.to_string());
    network.interface_name = "lo".into();
    network.routes = vec![NetworkRoute {
        destination: if source.is_ipv4() { "0.0.0.0" } else { "::" }
            .parse()
            .unwrap(),
        prefix_length: 0,
        gateway: None,
    }];
    state
        .publish(Inventory {
            revision: 1,
            preferred_network: Some(1),
            networks: vec![network],
        })
        .unwrap();
    let binder = Arc::new(DatagramBinder {
        state: Arc::downgrade(&state),
        source,
        mark,
        publish_during_bind,
        calls: Mutex::new(Vec::new()),
    });
    state.binder.set(binder.clone()).unwrap();
    let owner = Egress::with_networks(Arc::clone(&state));
    (state, binder, owner)
}

#[test]
fn inventory_publication_inside_binder_rejects_socket_before_source_bind() {
    let (state, binder, owner) = datagram_owner("192.0.2.1".parse().unwrap(), None, true);
    let lease = owner
        .lease(
            "0.0.0.0:0".parse().unwrap(),
            "203.0.113.9:443".parse().unwrap(),
            SocketProtocol::Udp,
            0,
            false,
        )
        .unwrap();
    assert_eq!(
        Egress::udp_socket(lease).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(state.revision(), 2);
    let calls = binder.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].handle, 1);
    assert!(calls[0].before.ip().is_unspecified());
    assert_eq!(calls[0].before.port(), 0);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires isolated Linux user/network namespaces and iproute2; real IPv4/IPv6 UDP, fixture binder only; no Internet traffic"]
fn udp_factory_preserves_real_source_ephemeral_port_mark_and_borrowed_fd_in_namespace() {
    use crate::runtime::physical_network::linux::{isolated_namespace, test_ip as ip};

    const NAME: &str = "runtime::physical_network::android::tests::datagram::udp_factory_preserves_real_source_ephemeral_port_mark_and_borrowed_fd_in_namespace";
    if !isolated_namespace(NAME) {
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    for address in ["192.0.2.1/32", "192.0.2.2/32"] {
        ip(&["addr", "add", address, "dev", "lo"]);
    }
    for address in ["2001:db8:1::1/128", "2001:db8:1::2/128"] {
        ip(&["-6", "addr", "add", address, "dev", "lo", "nodad"]);
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                for (source, destination, wildcard) in [
                    ("192.0.2.1", "192.0.2.2:0", "0.0.0.0:0"),
                    ("2001:db8:1::1", "[2001:db8:1::2]:0", "[::]:0"),
                ] {
                    const MARK: u32 = 71;
                    let source: IpAddr = source.parse().unwrap();
                    let receiver = tokio::net::UdpSocket::bind(destination).await.unwrap();
                    let destination = receiver.local_addr().unwrap();
                    let (_, binder, owner) = datagram_owner(source, Some(MARK), false);
                    let lease = owner
                        .lease(
                            wildcard.parse().unwrap(),
                            destination,
                            SocketProtocol::Udp,
                            MARK,
                            false,
                        )
                        .unwrap();
                    let original_epoch = lease.epoch();
                    assert_eq!(lease.local_addr, SocketAddr::new(source, 0));
                    let (socket, lease) = Egress::udp_socket(lease).unwrap();
                    assert_eq!(lease.local_addr, socket.local_addr().unwrap());
                    assert_eq!(lease.local_addr.ip(), source);
                    assert_ne!(lease.local_addr.port(), 0);
                    assert_eq!(lease.context.source, lease.local_addr);
                    assert_eq!(lease.context.destination, destination);
                    assert_eq!(lease.context.protocol, SocketProtocol::Udp);
                    assert_eq!(lease.context.mark, MARK);
                    assert_eq!(socket2::SockRef::from(&socket).mark().unwrap(), MARK);
                    assert_eq!(lease.epoch(), original_epoch);
                    assert!(lease.is_current());
                    assert!(lease.preferred_dial);
                    assert!(!lease.source_fixed);
                    {
                        let calls = binder.calls.lock().unwrap();
                        assert_eq!(calls.len(), 1);
                        assert_eq!(calls[0].handle, 1);
                        assert_eq!(
                            calls[0].fd,
                            socket.as_raw_fd(),
                            "binder borrows the returned socket, not another descriptor"
                        );
                        assert!(calls[0].before.ip().is_unspecified());
                        assert_eq!(calls[0].before.port(), 0);
                        assert_eq!(calls[0].before.is_ipv4(), source.is_ipv4());
                    }
                    let sender = tokio::net::UdpSocket::from_std(socket).unwrap();
                    let payload = b"factory-selected-source";
                    sender.send_to(payload, destination).await.unwrap();
                    let mut received = [0_u8; 64];
                    let (length, observed_source) =
                        receiver.recv_from(&mut received).await.unwrap();
                    assert_eq!(&received[..length], payload);
                    assert_eq!(observed_source, lease.local_addr);
                    receiver.send_to(b"reply", observed_source).await.unwrap();
                    let (length, observed_remote) = sender.recv_from(&mut received).await.unwrap();
                    assert_eq!(&received[..length], b"reply");
                    assert_eq!(observed_remote, destination);
                }
            })
            .await
            .expect("bounded namespace UDP factory metadata and real source I/O");
        });
}
