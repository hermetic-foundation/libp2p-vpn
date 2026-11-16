use super::{LinuxEgress, SocketProtocol, index, ip, isolated_namespace};
use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, Type};
use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    num::NonZeroU32,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const TEST: &str = "runtime::physical_network::linux::egress::tcp::tests::asymmetric::accepted_asymmetric_tcp_preserves_os_routing";
const CLIENT: &str = "P2P_VPN_ASYMMETRIC_TCP_CLIENT";
const SERVER_NETNS: &str = "P2P_VPN_ASYMMETRIC_TCP_SERVER_NETNS";
const USERNS: &str = "P2P_VPN_ASYMMETRIC_TCP_USERNS";
const EVENT: &str = "asymmetric-tcp: ";
const STEP: Duration = Duration::from_secs(3);
const CONTROL: Duration = Duration::from_secs(5);
const SERVER: &str = "192.0.2.1:4001";
const BROKEN: &[u8] = b"device-bound-request";

#[test]
#[ignore = "requires isolated user/network namespaces, unshare, nsenter, iproute2 and raw TCP capture; no Internet or host network changes"]
fn accepted_asymmetric_tcp_preserves_os_routing() {
    if env::var_os(CLIENT).is_some() {
        client();
        return;
    }
    if !isolated_namespace(TEST) {
        return;
    }

    let mut child = ClientProcess::spawn();
    child.expect("ready");
    assert_ne!(
        fs::read_link(format!("/proc/{}/ns/net", child.id())).unwrap(),
        fs::read_link("/proc/self/ns/net").unwrap(),
        "client must have its own network namespace before moving interfaces"
    );
    assert_eq!(
        fs::read_link(format!("/proc/{}/ns/user", child.id())).unwrap(),
        fs::read_link("/proc/self/ns/user").unwrap(),
        "client must inherit the fixture's user namespace"
    );
    topology(&child);

    let listener = TcpListener::bind(SERVER).unwrap();
    listener.set_nonblocking(true).unwrap();
    child.send("connect");
    let mut streams = BTreeMap::new();
    for _ in 0..3 {
        let stream = accept(&listener);
        let port = stream.peer_addr().unwrap().port();
        assert!(matches!(port, 41001..=41003));
        assert!(streams.insert(port, stream).is_none());
    }
    let mut broken = streams.remove(&41001).unwrap();
    let mut sibling = streams.remove(&41002).unwrap();
    let prepared = streams.remove(&41003).unwrap();
    child.expect("connected");
    assert_unbound(&listener);
    assert_unbound(&sibling);
    assert_unbound(&prepared);

    child.send("baseline");
    exchange(&mut sibling, b"baseline-request", b"baseline-reply");
    child.expect("baseline-ok");

    // Only the reply route uses s_out; every client packet enters through s_in.
    SockRef::from(&broken)
        .bind_device_by_index_v4(NonZeroU32::new(index("s_out")))
        .unwrap();
    assert_eq!(
        SockRef::from(&broken).device().unwrap(),
        Some(b"s_out".to_vec())
    );
    let capture = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)).unwrap();
    capture.bind_device(Some(b"s_in")).unwrap();
    capture
        .bind(&SockAddr::from(
            "192.0.2.1:0".parse::<SocketAddr>().unwrap(),
        ))
        .unwrap();
    child.send("broken");
    capture_request(&capture);
    child.expect("broken-sent");
    broken
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let error = broken
        .read(&mut [0; 64])
        .expect_err("device-bound stream received a request from the other interface");
    assert!(
        matches!(
            error.kind(),
            io::ErrorKind::WouldBlock
                | io::ErrorKind::TimedOut
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
        ),
        "unexpected device-bound read failure: {error}"
    );
    drop(capture);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let owner = LinuxEgress::for_control();
    let original_local = prepared.local_addr().unwrap();
    let original_peer = prepared.peer_addr().unwrap();
    prepared.set_nonblocking(true).unwrap();
    let (mut prepared, lease) = runtime.block_on(async {
        let stream = tokio::net::TcpStream::from_std(prepared).unwrap();
        let lease = tokio::time::timeout(STEP, owner.prepare_tcp_stream(&stream))
            .await
            .expect("accepted route check timed out")
            .expect("accepted asymmetric route must remain eligible");
        (stream.into_std().unwrap(), lease)
    });
    prepared.set_nonblocking(false).unwrap();
    socket_timeouts(&prepared);
    assert_eq!(lease.route.interface_index, index("s_out"));
    assert_ne!(lease.route.interface_index, index("s_in"));
    assert_eq!(lease.context.interface_index, None);
    assert_eq!(lease.context.protocol, SocketProtocol::Tcp);
    assert_eq!(lease.context.mark, 0);
    assert_eq!(lease.context.source, original_local);
    assert_eq!(lease.local_addr, original_local);
    assert_eq!(lease.context.destination, original_peer);
    assert!(!lease.preferred_dial);
    assert!(lease.is_current());
    assert_unbound(&prepared);
    assert_unbound(&listener);
    assert_unbound(&sibling);

    child.send("prepared");
    exchange(&mut prepared, b"prepared-request", b"prepared-reply");
    child.expect("prepared-ok");
    child.send("sibling");
    exchange(&mut sibling, b"sibling-request", b"sibling-reply");
    child.expect("sibling-ok");
    child.send("fresh");
    let mut fresh = accept(&listener);
    assert_eq!(fresh.peer_addr().unwrap().port(), 41004);
    assert_unbound(&fresh);
    exchange(&mut fresh, b"fresh-request", b"fresh-reply");
    child.expect("fresh-ok");
    assert_unbound(&listener);
    assert_unbound(&sibling);
    assert_unbound(&prepared);
    assert_eq!(prepared.local_addr().unwrap(), original_local);
    assert_eq!(prepared.peer_addr().unwrap(), original_peer);
    assert!(lease.is_current());
    child.send("finish");
    child.expect("done");
    child.finish();
}

fn topology(child: &ClientProcess) {
    ip(&["link", "set", "lo", "up"]);
    child.ip(&["link", "set", "lo", "up"]);
    for (server, client, server_ip, client_ip, server_mac, client_mac) in [
        (
            "s_in",
            "c_in",
            "192.0.2.1",
            "192.0.2.2",
            "02:00:00:00:01:01",
            "02:00:00:00:01:02",
        ),
        (
            "s_out",
            "c_out",
            "198.51.100.1",
            "198.51.100.2",
            "02:00:00:00:02:01",
            "02:00:00:00:02:02",
        ),
    ] {
        ip(&[
            "link", "add", server, "type", "veth", "peer", "name", client,
        ]);
        for (name, mac) in [(server, server_mac), (client, client_mac)] {
            ip(&["link", "set", "dev", name, "address", mac]);
            ip(&["link", "set", "dev", name, "addrgenmode", "none"]);
        }
        ip(&["link", "set", client, "netns", &child.id().to_string()]);
        ip(&["addr", "add", &format!("{server_ip}/24"), "dev", server]);
        child.ip(&["addr", "add", &format!("{client_ip}/24"), "dev", client]);
        ip(&["link", "set", server, "up"]);
        child.ip(&["link", "set", client, "up"]);
        ip(&[
            "neigh",
            "replace",
            client_ip,
            "lladdr",
            client_mac,
            "nud",
            "permanent",
            "dev",
            server,
        ]);
        child.ip(&[
            "neigh",
            "replace",
            server_ip,
            "lladdr",
            server_mac,
            "nud",
            "permanent",
            "dev",
            client,
        ]);
    }
    disable_reverse_path_filter(&["s_in", "s_out"]);
    ip(&[
        "route",
        "replace",
        "192.0.2.2/32",
        "via",
        "198.51.100.2",
        "dev",
        "s_out",
        "src",
        "192.0.2.1",
    ]);
}

fn disable_reverse_path_filter(interfaces: &[&str]) {
    for interface in ["all", "default"]
        .into_iter()
        .chain(interfaces.iter().copied())
    {
        fs::write(
            format!("/proc/sys/net/ipv4/conf/{interface}/rp_filter"),
            "0\n",
        )
        .unwrap();
    }
}

fn socket_timeouts(stream: &TcpStream) {
    stream.set_read_timeout(Some(STEP)).unwrap();
    stream.set_write_timeout(Some(STEP)).unwrap();
    stream.set_nodelay(true).unwrap();
}

fn assert_unbound(socket: &impl std::os::fd::AsFd) {
    let socket = SockRef::from(socket);
    assert_eq!(socket.device().unwrap(), None);
    assert_eq!(socket.mark().unwrap(), 0);
}

fn accept(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + STEP;
    loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                assert_eq!(peer.ip(), std::net::Ipv4Addr::new(192, 0, 2, 2));
                assert_eq!(
                    stream.local_addr().unwrap(),
                    SERVER.parse::<SocketAddr>().unwrap()
                );
                socket_timeouts(&stream);
                return stream;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "accept timed out");
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept failed: {error}"),
        }
    }
}

fn exchange(stream: &mut TcpStream, request: &[u8], reply: &[u8]) {
    let mut received = vec![0; request.len()];
    stream
        .read_exact(&mut received)
        .expect("receive asymmetric request");
    assert_eq!(received, request);
    stream.write_all(reply).expect("send asymmetric reply");
}

fn capture_request(mut capture: &Socket) {
    let deadline = Instant::now() + STEP;
    let mut packet = [0; 1500];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "request never arrived on s_in");
        capture.set_read_timeout(Some(remaining)).unwrap();
        let count = capture.read(&mut packet).expect("capture request on s_in");
        if count < 40 || packet[0] >> 4 != 4 || packet[9] != 6 {
            continue;
        }
        let ip_length = usize::from(packet[0] & 0x0f) * 4;
        if ip_length < 20 || count < ip_length + 20 {
            continue;
        }
        let tcp = &packet[ip_length..count];
        let tcp_length = usize::from(tcp[12] >> 4) * 4;
        if packet[12..16] == [192, 0, 2, 2]
            && packet[16..20] == [192, 0, 2, 1]
            && u16::from_be_bytes([tcp[0], tcp[1]]) == 41001
            && u16::from_be_bytes([tcp[2], tcp[3]]) == 4001
            && tcp_length >= 20
            && tcp.get(tcp_length..) == Some(BROKEN)
        {
            return;
        }
    }
}

fn client() {
    assert_ne!(
        fs::read_link("/proc/self/ns/net").unwrap().into_os_string(),
        env::var_os(SERVER_NETNS).expect("server namespace"),
        "client must not configure the server namespace"
    );
    assert_eq!(
        fs::read_link("/proc/self/ns/user")
            .unwrap()
            .into_os_string(),
        env::var_os(USERNS).expect("fixture user namespace")
    );
    let (sender, control) = mpsc::channel();
    let _reader = lines(io::stdin(), sender);
    signal("ready");
    assert_eq!(
        control
            .recv_timeout(Duration::from_secs(15))
            .expect("topology setup deadline")
            .unwrap(),
        "connect"
    );
    disable_reverse_path_filter(&["c_in", "c_out"]);
    let mut broken = connect(41001);
    let mut sibling = connect(41002);
    let mut prepared = connect_managed(41003);
    signal("connected");
    command(&control, "baseline");
    request(&mut sibling, b"baseline-request", b"baseline-reply");
    signal("baseline-ok");
    command(&control, "broken");
    broken.write_all(BROKEN).expect("send device-bound request");
    signal("broken-sent");
    command(&control, "prepared");
    request(&mut prepared, b"prepared-request", b"prepared-reply");
    signal("prepared-ok");
    command(&control, "sibling");
    request(&mut sibling, b"sibling-request", b"sibling-reply");
    signal("sibling-ok");
    command(&control, "fresh");
    let mut fresh = connect(41004);
    request(&mut fresh, b"fresh-request", b"fresh-reply");
    signal("fresh-ok");
    command(&control, "finish");
    signal("done");
}

fn connect(port: u16) -> TcpStream {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
    socket
        .bind(&SockAddr::from(SocketAddr::from(([192, 0, 2, 2], port))))
        .unwrap();
    socket
        .connect_timeout(&SockAddr::from(SERVER.parse::<SocketAddr>().unwrap()), STEP)
        .unwrap();
    let stream = socket.into();
    socket_timeouts(&stream);
    stream
}

fn connect_managed(port: u16) -> TcpStream {
    let listener = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
    listener.set_reuse_address(true).unwrap();
    listener.set_reuse_port(true).unwrap();
    let source = SocketAddr::from(([192, 0, 2, 2], port));
    listener.bind(&SockAddr::from(source)).unwrap();
    listener.listen(4).unwrap();
    let stream = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let owner = LinuxEgress::for_control();
            let (socket, lease) = owner
                .prepare_tcp(SERVER.parse().unwrap(), true, &[source])
                .await
                .unwrap();
            assert_eq!(lease.local_addr, source);
            assert_eq!(lease.context.interface_index, None);
            assert_eq!(lease.route.interface_index, index("c_in"));
            assert_unbound(&socket);
            let stream = tokio::time::timeout(
                STEP,
                tokio::net::TcpSocket::from_std_stream(socket.into())
                    .connect(SERVER.parse().unwrap()),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(stream.local_addr().unwrap(), source);
            assert!(lease.is_current());
            stream.into_std().unwrap()
        });
    stream.set_nonblocking(false).unwrap();
    socket_timeouts(&stream);
    stream
}

fn request(stream: &mut TcpStream, request: &[u8], reply: &[u8]) {
    stream.write_all(request).expect("send asymmetric request");
    let mut received = vec![0; reply.len()];
    stream
        .read_exact(&mut received)
        .expect("receive asymmetric reply");
    assert_eq!(received, reply);
}

fn signal(event: &str) {
    println!("{EVENT}{event}");
    io::stdout().flush().unwrap();
}

fn lines(
    reader: impl Read + Send + 'static,
    sender: mpsc::Sender<io::Result<String>>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            if sender.send(line).is_err() {
                break;
            }
        }
    })
}

fn command(control: &Receiver<io::Result<String>>, expected: &str) {
    let line = control
        .recv_timeout(CONTROL)
        .expect("client control deadline")
        .unwrap();
    assert_eq!(line, expected);
}

struct ClientProcess {
    process: Option<Child>,
    input: Option<ChildStdin>,
    output: Receiver<io::Result<String>>,
    reader: Option<JoinHandle<()>>,
}

impl ClientProcess {
    fn spawn() -> Self {
        let (sender, output) = mpsc::channel();
        let process = Command::new("unshare")
            .arg("--net")
            .arg(env::current_exe().unwrap())
            .args([
                "--exact",
                TEST,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CLIENT, "1")
            .env(SERVER_NETNS, fs::read_link("/proc/self/ns/net").unwrap())
            .env(USERNS, fs::read_link("/proc/self/ns/user").unwrap())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn client in a child network namespace");
        let mut child = Self {
            process: Some(process),
            input: None,
            output,
            reader: None,
        };
        let process = child.process.as_mut().unwrap();
        child.input = process.stdin.take();
        let stdout = process.stdout.take().expect("piped client stdout");
        child.reader = Some(lines(stdout, sender));
        child
    }

    fn id(&self) -> u32 {
        self.process.as_ref().unwrap().id()
    }

    fn send(&mut self, message: &str) {
        let input = self.input.as_mut().unwrap();
        writeln!(input, "{message}").unwrap();
        input.flush().unwrap();
    }

    fn expect(&self, expected: &str) {
        let deadline = Instant::now() + CONTROL;
        loop {
            let line = self
                .output
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|error| panic!("waiting for client {expected}: {error}"))
                .expect("read client stdout");
            // The test harness can prefix the first uncaptured line with its test name.
            if let Some((_, event)) = line.split_once(EVENT) {
                assert_eq!(event, expected, "unexpected client event");
                return;
            }
        }
    }

    fn ip(&self, args: &[&str]) {
        let output = Command::new("timeout")
            .args(["--signal=KILL", "3", "nsenter", "--target"])
            .arg(self.id().to_string())
            .args(["--net", "--", "ip"])
            .args(args)
            .output()
            .expect("configure isolated client network");
        assert!(
            output.status.success(),
            "client ip {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn finish(&mut self) {
        self.input.take();
        let deadline = Instant::now() + STEP;
        loop {
            if let Some(status) = self.process.as_mut().unwrap().try_wait().unwrap() {
                assert!(status.success(), "client test failed: {status}");
                return;
            }
            assert!(Instant::now() < deadline, "client did not exit");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for ClientProcess {
    fn drop(&mut self) {
        self.input.take();
        let deadline = Instant::now() + STEP;
        if let Some(mut process) = self.process.take() {
            let _ = process.kill();
            let (sender, reaped) = mpsc::sync_channel(1);
            // The reaper keeps ownership even if the kernel outlives the cleanup deadline.
            thread::spawn(move || {
                let _ = sender.send(process.wait());
            });
            if !matches!(reaped.recv_timeout(STEP), Ok(Ok(_))) {
                eprintln!("asymmetric TCP client reaping failed or exceeded the cleanup deadline");
            }
        }
        if let Some(reader) = self.reader.take() {
            while !reader.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if reader.is_finished() {
                let _ = reader.join();
            } else {
                eprintln!("asymmetric TCP stdout reader exceeded the cleanup deadline");
            }
        }
    }
}
