//! Disposable browser/TUN qualification harness with loopback-only setup/control.
use std::{
    net::Ipv4Addr,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures::StreamExt;
use libp2p::{multiaddr::Protocol, swarm::SwarmEvent};
use p2p_vpn::{
    config::{Config, DiscoveryConfig, RouteConfig},
    identity::NodeIdentity,
    membership::{MembershipRecordOptions, MembershipRole, issue_membership_record_at},
    runtime::{
        forward::Forwarder,
        p2p::{HostConfig, build_node},
        packet_plane::PacketPlaneRuntime,
        runner::{OverlayMembership, ShutdownReason, run_node_until_with_packet_io},
        tun::{TunDevice, TunRuntimeConfig},
    },
};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};

const NATIVE_IP: &str = "10.203.0.1";
const BROWSER_IP: &str = "10.203.0.2";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Err(error) = run().await {
        eprintln!("browser fixture failed: {error}");
        std::process::exit(1);
    }
    Ok(())
}

fn error(e: impl std::fmt::Debug) -> std::io::Error {
    std::io::Error::other(format!("{e:?}"))
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .try_init();
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let web_root = if let Some(index) = arguments.iter().position(|arg| arg == "--web-root") {
        PathBuf::from(
            arguments
                .get(index + 1)
                .ok_or_else(|| error("--web-root requires a directory"))?,
        )
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("web")
    };
    let web_root = web_root.canonicalize()?;
    if !web_root.is_dir() {
        return Err(error("browser fixture web root must be a directory").into());
    }
    let export_client = arguments
        .windows(2)
        .find(|w| w[0] == "--export-client")
        .map(|w| PathBuf::from(&w[1]));
    if export_client.as_ref().is_some_and(|path| path.exists()) {
        return Err(error("client export directory already exists; use a fresh path").into());
    }
    let web_port: u16 = arguments
        .windows(2)
        .find(|w| w[0] == "--port")
        .map_or(Ok(8787), |w| w[1].parse())?;
    let webrtc_ip: Ipv4Addr =
        if let Some(value) = arguments.windows(2).find(|w| w[0] == "--webrtc-ip") {
            value[1].parse()?
        } else {
            // UDP connect selects a local route without sending any packet.
            let route = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
            route.connect((Ipv4Addr::new(192, 0, 2, 1), 9))?;
            let std::net::IpAddr::V4(ip) = route.local_addr()?.ip() else {
                return Err(error("no IPv4 underlay route").into());
            };
            ip
        };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, web_port)).await?;
    if std::net::TcpListener::bind((NATIVE_IP, 0)).is_ok() {
        return Err(error("test overlay address is already assigned; refusing to reuse it").into());
    }
    let native = NodeIdentity::generate_ed25519().map_err(error)?;
    let browser = NodeIdentity::generate_ed25519().map_err(error)?;
    let session_id = native.peer_id.clone();
    let native_host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))?
        .to_ascii_lowercase();
    let issued = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let network = format!("browser-qualification-{}", std::process::id());
    let mut records = Vec::new();
    for (member, ip) in [(&native, NATIVE_IP), (&browser, BROWSER_IP)] {
        records.push(
            issue_membership_record_at(
                &native,
                MembershipRecordOptions {
                    network_name: network.clone(),
                    member: member.clone(),
                    membership_epoch: 1,
                    sequence: 1,
                    roles: vec![
                        MembershipRole::OverlayMember,
                        MembershipRole::RouteAuthority,
                    ],
                    route_grants: vec![RouteConfig {
                        prefix: format!("{ip}/32"),
                        metric: 0,
                    }],
                    expires_at_unix_seconds: Some(issued + 3600),
                },
                issued,
            )
            .map_err(error)?,
        );
    }
    let discovery = DiscoveryConfig {
        mdns: false,
        kademlia: false,
        kademlia_provider_advertisement: false,
        dcutr: false,
        autonat: false,
        ..Default::default()
    };
    let config_for = |identity: &NodeIdentity, ip: &str| -> Result<Config, serde_json::Error> {
        serde_json::from_value(json!({
            "network": { "name": network, "local_peer": identity.peer_id,
                "private_key": identity.private_key, "vpn_ip": ip,
                "member_records": records, "listen_addresses": [],
                "discovery": discovery, "packet_plane": {"listen": [], "quic_listen": []} },
            "interface": {"name": format!("p2p-wasm-{}", std::process::id()), "mtu": 1280}
        }))
    };
    let native_config = config_for(&native, NATIVE_IP)?;
    let browser_config = config_for(&browser, BROWSER_IP)?;
    native_config.validate_runtime().map_err(error)?;
    let forwarder = Forwarder::from_config(&native_config).map_err(error)?;
    let browser_forwarder = Forwarder::from_config(&browser_config).map_err(error)?;
    if !forwarder.authorizes_advertised_routes(
        browser.peer_id.parse()?,
        &browser_forwarder.local_advertised_routes(),
    ) || !browser_forwarder.authorizes_advertised_routes(
        native.peer_id.parse()?,
        &forwarder.local_advertised_routes(),
    ) {
        return Err(error("fixture signed route authority is inconsistent").into());
    }
    let membership = OverlayMembership::from_config(&native_config).map_err(error)?;
    let mut node = build_node(&HostConfig {
        identity: native,
        network_name: network,
        membership_tag: None,
        mtu: 1280,
        max_concurrent_control_streams: 8,
        max_concurrent_packet_streams: 32,
        listen_addresses: vec![format!("/ip4/{webrtc_ip}/udp/0/webrtc-direct").parse()?],
        external_addresses: vec![],
        bootstrap_peers: vec![],
        known_peers: vec![],
        relay_reservations: vec![],
        relay_server: false,
        relay_resources: Default::default(),
        resources: native_config.resources,
        discovery,
    })
    .map_err(error)?;
    let address = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match node.swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => return Ok(address),
                SwarmEvent::ListenerError { error, .. } => return Err(error),
                _ => {}
            }
        }
    })
    .await??;
    let webrtc_port = address
        .iter()
        .find_map(|protocol| match protocol {
            Protocol::Udp(port) => Some(port),
            _ => None,
        })
        .ok_or_else(|| error("WebRTC listener has no UDP port"))?;
    let address = address.with(Protocol::P2p(node.local_peer_id)).to_string();
    let tun_config = TunRuntimeConfig::from_config(&native_config).map_err(error)?;
    let device = TunDevice::open(&tun_config).map_err(error)?;
    // Only this fresh test adapter receives host addresses/routes. Dropping the
    // device removes its routes; no existing interface is reconfigured.
    for command in tun_config.route_commands() {
        if !command.execute()?.success() {
            return Err(error("test TUN address/route setup failed").into());
        }
    }
    let overlay_http = TcpListener::bind((NATIVE_IP, 0)).await?;
    let overlay_port = overlay_http.local_addr()?.port();
    let proof_session = session_id.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, remote)) = overlay_http.accept().await {
            let session_id = proof_session.clone();
            tokio::spawn(async move {
                if let Ok(request) = read_request(&mut socket).await {
                    let path = request.split_whitespace().nth(1).unwrap_or("/");
                    println!(
                        "BROWSER_HTTP_PROOF {}",
                        json!({
                            "session_id": session_id, "path": path, "remote_ip": remote.ip().to_string()
                        })
                    );
                    let body = format!("p2p-vpn real TUN HTTP proof\n{path}\n");
                    let _ = response(&mut socket, "200 OK", "text/plain", body.as_bytes()).await;
                }
            });
        }
    });
    let token = rand::random::<[u8; 32]>()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let session = json!({"config": browser_config, "dial_address": address,
        "overlay_ip": NATIVE_IP, "overlay_port": overlay_port,
        "shutdown_token": token, "native_interface": tun_config.name,
        "session_id": session_id, "native_host": native_host,
        "webrtc_ip": webrtc_ip.to_string(), "webrtc_port": webrtc_port,
        "expires_at": issued + 3600, "qualification_mode": "local",
        "packet_device": "OS TUN", "test_credentials": "disposable; expires in one hour"});
    if let Some(destination) = export_client {
        export_client_bundle(&destination, &session, &web_root).await?;
        println!("BROWSER_CLIENT_EXPORTED {}", destination.display());
    }
    let session = session.to_string();
    let (stop, mut stopped) = watch::channel(false);
    let mut daemon_stop = stopped.clone();
    let runner = tokio::spawn(run_node_until_with_packet_io(
        node,
        forwarder,
        membership,
        vec![],
        device.into_packet_io(),
        1280,
        native_config.queue,
        native_config.resources,
        None,
        None,
        None,
        PacketPlaneRuntime::disabled(),
        None,
        vec![],
        Duration::from_secs(300),
        64,
        Default::default(),
        false,
        None,
        async move {
            let _ = daemon_stop.changed().await;
            ShutdownReason::Interrupt
        },
    ));
    println!(
        "BROWSER_FIXTURE_READY http://127.0.0.1:{web_port} interface={} overlay={NATIVE_IP}:{overlay_port}",
        tun_config.name
    );
    loop {
        tokio::select! {
            _ = stopped.changed() => break,
            _ = tokio::signal::ctrl_c() => { let _ = stop.send(true); break; }
            accepted = listener.accept() => {
                let (socket, _) = accepted?;
                let session = session.clone(); let root = web_root.clone(); let stop = stop.clone(); let token = token.clone();
                tokio::spawn(async move { let _ = serve(socket, session, root, web_port, token, stop).await; });
            }
        }
    }
    tokio::time::timeout(Duration::from_secs(15), runner)
        .await?
        .map_err(error)?
        .map_err(error)?;
    println!("BROWSER_FIXTURE_STOPPED");
    Ok(())
}

async fn export_client_bundle(
    destination: &std::path::Path,
    session: &serde_json::Value,
    web_root: &std::path::Path,
) -> std::io::Result<()> {
    // Copy only the browser's disposable identity. Native keys and loopback
    // shutdown authority never enter the portable bundle.
    let mut client_session = session.clone();
    let object = client_session
        .as_object_mut()
        .expect("fixture session object");
    object.remove("shutdown_token");
    object.insert("qualification_mode".into(), json!("split-lan"));
    tokio::fs::create_dir(destination).await?;
    tokio::fs::create_dir(destination.join("pkg")).await?;
    tokio::fs::create_dir(destination.join("tests")).await?;
    for file in [
        "index.html",
        "pkg/p2p_vpn_browser.js",
        "pkg/p2p_vpn_browser_bg.wasm",
    ] {
        tokio::fs::copy(web_root.join(file), destination.join(file)).await?;
    }
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for (source, target) in [
        ("tests/lan-client.mjs", "client.mjs"),
        ("tests/e2e.mjs", "tests/e2e.mjs"),
        ("package.json", "package.json"),
        ("package-lock.json", "package-lock.json"),
    ] {
        tokio::fs::copy(crate_root.join(source), destination.join(target)).await?;
    }
    tokio::fs::write(destination.join("session.json"), client_session.to_string()).await
}

// Avoid unbounded HTTP buffering in this local fixture server.
async fn read_request(socket: &mut TcpStream) -> std::io::Result<String> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut bytes = Vec::new();
        let mut chunk = [0; 1024];
        while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
            let count = socket.read(&mut chunk).await?;
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..count]);
            if bytes.len() > 16 * 1024 {
                return Err(error("HTTP header too large"));
            }
        }
        String::from_utf8(bytes).map_err(error)
    })
    .await
    .map_err(error)?
}

async fn serve(
    mut socket: TcpStream,
    session: String,
    root: PathBuf,
    port: u16,
    token: String,
    stop: watch::Sender<bool>,
) -> std::io::Result<()> {
    let request = read_request(&mut socket).await?;
    let expected_host = format!("host: 127.0.0.1:{port}");
    if !request
        .lines()
        .any(|line| line.to_ascii_lowercase() == expected_host)
    {
        return response(
            &mut socket,
            "403 Forbidden",
            "text/plain",
            b"invalid fixture host",
        )
        .await;
    }
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    if method == "POST" && path == "/shutdown" {
        if request.lines().any(|line| {
            line == format!("X-Fixture-Token: {token}")
                || line == format!("x-fixture-token: {token}")
        }) {
            response(&mut socket, "200 OK", "text/plain", b"stopping").await?;
            let _ = stop.send(true);
            return Ok(());
        }
    }
    if method != "GET" {
        return response(
            &mut socket,
            "405 Method Not Allowed",
            "text/plain",
            b"GET required",
        )
        .await;
    }
    if path == "/session.json" {
        return response(
            &mut socket,
            "200 OK",
            "application/json",
            session.as_bytes(),
        )
        .await;
    }
    let (file, mime) = match path {
        "/" | "/index.html" => ("index.html", "text/html"),
        "/pkg/p2p_vpn_browser.js" => ("pkg/p2p_vpn_browser.js", "text/javascript"),
        "/pkg/p2p_vpn_browser_bg.wasm" => ("pkg/p2p_vpn_browser_bg.wasm", "application/wasm"),
        _ => return response(&mut socket, "404 Not Found", "text/plain", b"not found").await,
    };
    match tokio::fs::read(root.join(file)).await {
        Ok(bytes) => response(&mut socket, "200 OK", mime, &bytes).await,
        Err(_) => {
            response(
                &mut socket,
                "404 Not Found",
                "text/plain",
                b"build the browser package first",
            )
            .await
        }
    }
}

async fn response(
    socket: &mut TcpStream,
    status: &str,
    mime: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    socket.write_all(head.as_bytes()).await?;
    socket.write_all(body).await?;
    socket.shutdown().await
}
