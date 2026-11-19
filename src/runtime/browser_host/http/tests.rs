use super::*;
use crate::config::PUBLIC_IPFS_KADEMLIA_PROTOCOL;
use libp2p::PeerId;
use serde_json::Value;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::task::JoinHandle;

struct TestAssets(PathBuf);

impl TestAssets {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "p2p-vpn-browser-host-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&dir).unwrap();
        let assets = Self(dir);
        std::fs::create_dir(assets.0.join("pkg")).unwrap();
        for &(name, _) in ASSETS {
            let body = if name == "/app.html" {
                "<!doctype html><html><head></head><body>Browser app</body></html>"
            } else {
                name
            };
            std::fs::write(assets.0.join(&name[1..]), body).unwrap();
        }
        std::fs::write(assets.0.join("private.json"), "private test file").unwrap();
        assets
    }
}

impl Drop for TestAssets {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub(crate) struct Fixture {
    state: Arc<State>,
    task: JoinHandle<io::Result<()>>,
}

impl Fixture {
    pub(crate) async fn start(protocol: StreamProtocol, bootstrap: Vec<Multiaddr>) -> Self {
        Self::start_excluding(protocol, bootstrap, None).await
    }

    pub(crate) async fn start_excluding(
        protocol: StreamProtocol,
        bootstrap: Vec<Multiaddr>,
        owned_interface: Option<String>,
    ) -> Self {
        let assets = TestAssets::new();
        let server = Server::bind(&assets.0, 0, protocol, bootstrap, owned_interface)
            .await
            .unwrap();
        assert_eq!(
            server.listener.local_addr().unwrap().ip(),
            Ipv4Addr::LOCALHOST
        );
        Self {
            state: Arc::clone(&server.state),
            task: tokio::spawn(server.run()),
        }
    }

    async fn exchange(&self, request: &str) -> String {
        let mut stream = TcpStream::connect(&self.state.host).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    pub(crate) async fn lookup(&self, network: &str, peer: PeerId) -> (u16, Value) {
        let bootstrap: Vec<_> = self
            .state
            .bootstrap
            .iter()
            .map(|(id, address)| {
                let mut address = address.clone();
                address.pop();
                serde_json::json!({"id": id.to_string(), "address": address.to_string()})
            })
            .collect();
        self.lookup_request(serde_json::json!({
            "network_name": network,
            "peer": peer.to_string(),
            "lan": false,
            "kademlia_protocol": self.state.protocol.as_ref(),
            "bootstrap": bootstrap,
        }))
        .await
    }

    pub(crate) async fn lookup_request(&self, request: Value) -> (u16, Value) {
        let response = self.post(&self.state.origin, &request.to_string()).await;
        Self::json_response(&response)
    }

    pub(crate) async fn lookup_pairing(&self, scoped: bool, locator: &str) -> (u16, Value) {
        let path = if scoped {
            SCOPED_PAIRING_PATH
        } else {
            PAIRING_PATH
        };
        let request = serde_json::json!({"locator":locator});
        let response = self
            .post_to(path, &self.state.origin, &request.to_string())
            .await;
        Self::json_response(&response)
    }

    fn json_response(response: &str) -> (u16, Value) {
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        (
            head.split_whitespace().nth(1).unwrap().parse().unwrap(),
            serde_json::from_str(body).unwrap(),
        )
    }

    async fn post(&self, origin: &str, request: &str) -> String {
        self.post_to(DISCOVERY_PATH, origin, request).await
    }

    async fn post_to(&self, path: &str, origin: &str, request: &str) -> String {
        self.exchange(&format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nOrigin: {origin}\r\n\
             Sec-Fetch-Site: same-origin\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n{request}",
            self.state.host,
            request.len(),
        ))
        .await
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn serves_only_allowlisted_assets_and_refuses_other_origins() {
    let fixture = Fixture::start(StreamProtocol::new(PUBLIC_IPFS_KADEMLIA_PROTOCOL), vec![]).await;
    let host = &fixture.state.host;
    let response = fixture
        .exchange(&format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"))
        .await;
    assert!(response.starts_with("HTTP/1.1 200 "));
    assert!(response.contains(&format!("<head>{MARKER}{PAIRING_MARKER}</head>")));
    let response = fixture
        .exchange(&format!(
            "GET /api/discovery HTTP/1.1\r\nHost: {host}\r\n\r\n"
        ))
        .await;
    assert!(response.starts_with("HTTP/1.1 200 "));
    assert!(response.ends_with(std::str::from_utf8(AVAILABILITY).unwrap()));
    for (request, status) in [
        (
            format!("GET / HTTP/1.1\r\nHost: rebind.example\r\n\r\n"),
            403,
        ),
        (
            format!("GET / HTTP/1.1\r\nHost: {host}\r\nHost: {host}\r\n\r\n"),
            400,
        ),
        (
            format!("GET /app.js HTTP/1.1\r\nHost: {host}\r\nSec-Fetch-Site: cross-site\r\n\r\n"),
            403,
        ),
        (
            format!("GET /private.json HTTP/1.1\r\nHost: {host}\r\n\r\n"),
            404,
        ),
        (
            format!("GET /pkg/../private.json HTTP/1.1\r\nHost: {host}\r\n\r\n"),
            404,
        ),
        (
            format!(
                "OPTIONS /api/discovery HTTP/1.1\r\nHost: {host}\r\nOrigin: https://other.invalid\r\n\r\n"
            ),
            403,
        ),
        (
            format!("POST /api/discovery HTTP/1.1\r\nHost: {host}\r\n\r\n"),
            403,
        ),
    ] {
        let response = fixture.exchange(&request).await;
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status} ")),
            "{response}"
        );
        assert!(
            !response
                .to_ascii_lowercase()
                .contains("access-control-allow")
        );
    }
    let response = fixture.post("https://other.invalid", "{}").await;
    assert!(response.starts_with("HTTP/1.1 403 "));
}

#[tokio::test]
async fn pairing_route_only_accepts_bounded_same_origin_locator_posts() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let fixture = Fixture::start(StreamProtocol::new(PUBLIC_IPFS_KADEMLIA_PROTOCOL), vec![]).await;
    let locator = URL_SAFE_NO_PAD.encode([0; 32]);
    let valid = serde_json::json!({"locator": &locator}).to_string();
    let foreign = fixture
        .post_to(PAIRING_PATH, "http://other.invalid", &valid)
        .await;
    assert!(foreign.starts_with("HTTP/1.1 403 "));
    assert!(
        !foreign
            .to_ascii_lowercase()
            .contains("access-control-allow")
    );

    let response = fixture.exchange(&format!(
        "POST {PAIRING_PATH} HTTP/1.1\r\nHost: {}\r\nOrigin: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        fixture.state.host, fixture.state.origin, MAX_PAIRING_BODY_BYTES + 1,
    )).await;
    assert!(response.starts_with("HTTP/1.1 413 "), "{response}");

    let _all_requests = fixture
        .state
        .lookups
        .try_acquire_many(u32::try_from(MAX_LOOKUPS).unwrap())
        .unwrap();
    for path in [PAIRING_PATH, SCOPED_PAIRING_PATH] {
        for body in [
            serde_json::json!({"locator":"1234-5678-ABCD-EFGH"}),
            serde_json::json!({"locator": &locator, "code": "not accepted"}),
            serde_json::json!({"locator": &locator, "private_key": "not accepted"}),
        ] {
            let response = fixture
                .post_to(path, &fixture.state.origin, &body.to_string())
                .await;
            assert!(response.starts_with("HTTP/1.1 400 "), "{response}");
        }
        let (status, response) = fixture
            .lookup_pairing(path == SCOPED_PAIRING_PATH, &locator)
            .await;
        assert_eq!(status, 429);
        assert_eq!(response, serde_json::json!({"error":"discovery_busy"}));
    }
}

#[tokio::test]
async fn private_member_seeds_are_not_pairing_bootstrap_contacts() {
    let seed = format!("/ip4/8.8.8.8/tcp/4001/p2p/{}", PeerId::random())
        .parse::<Multiaddr>()
        .unwrap();
    let fixture = Fixture::start(
        StreamProtocol::new("/p2p-vpn/test-private-kad/1"),
        vec![seed.clone()],
    )
    .await;
    assert!(public_pairing_bootstrap(&fixture.state).is_empty());
    let fixture = Fixture::start(
        StreamProtocol::new(PUBLIC_IPFS_KADEMLIA_PROTOCOL),
        vec![seed.clone()],
    )
    .await;
    assert_eq!(public_pairing_bootstrap(&fixture.state), [seed]);
}

#[tokio::test]
async fn bounds_request_size_and_lookup_concurrency() {
    let fixture = Fixture::start(StreamProtocol::new(PUBLIC_IPFS_KADEMLIA_PROTOCOL), vec![]).await;
    let response = fixture.exchange(&format!(
        "POST /api/discovery HTTP/1.1\r\nHost: {}\r\nOrigin: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        fixture.state.host, fixture.state.origin, MAX_BODY_BYTES + 1,
    )).await;
    assert!(response.starts_with("HTTP/1.1 413 "));
    let response = fixture
        .post(
            &fixture.state.origin,
            &serde_json::json!({
                "network_name": "n",
                "peer": PeerId::random().to_string(),
                "lan": false,
                "kademlia": false,
                "private_key": "not accepted",
            })
            .to_string(),
        )
        .await;
    assert!(response.starts_with("HTTP/1.1 400 "));
    let _all_requests = fixture
        .state
        .lookups
        .try_acquire_many(u32::try_from(MAX_LOOKUPS).unwrap())
        .unwrap();
    let (code, body) = fixture.lookup("n", PeerId::random()).await;
    assert_eq!(code, 429);
    assert_eq!(body, serde_json::json!({"error":"discovery_busy"}));
}

#[tokio::test]
async fn request_cannot_enable_dht_protocols_or_bootstrap_contacts() {
    let fixture = Fixture::start(StreamProtocol::new(PUBLIC_IPFS_KADEMLIA_PROTOCOL), vec![]).await;
    let peer = PeerId::random().to_string();
    for body in [
        serde_json::json!({"network_name":"n", "peer":peer, "lan":false, "kademlia_protocol":"/not-enabled"}),
        serde_json::json!({"network_name":"n", "peer":peer, "lan":false, "bootstrap":[{"id":peer, "address":"/ip4/8.8.8.8/tcp/4001"}]}),
    ] {
        let response = fixture.post(&fixture.state.origin, &body.to_string()).await;
        assert!(response.starts_with("HTTP/1.1 403 "), "{response}");
    }
    let body = serde_json::json!({"network_name":"n", "peer":peer, "kademlia":false, "lan":false});
    let response = fixture.post(&fixture.state.origin, &body.to_string()).await;
    let (status, reply) = Fixture::json_response(&response);
    assert_eq!(status, 200);
    assert_eq!(reply, serde_json::json!({"addresses":[], "source":null}));
}
