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
        Self::start_with_relays(protocol, bootstrap, owned_interface, Vec::new()).await
    }

    pub(crate) async fn start_with_relays(
        protocol: StreamProtocol,
        bootstrap: Vec<Multiaddr>,
        owned_interface: Option<String>,
        relays: Vec<Multiaddr>,
    ) -> Self {
        let assets = TestAssets::new();
        let server = Server::bind_with_approved_relays(
            &assets.0,
            0,
            protocol,
            bootstrap,
            owned_interface,
            relays,
        )
        .await
        .unwrap();
        Self::start_server(server)
    }

    pub(crate) async fn start_with_advertisement(
        permit: crate::runtime::browser_host::advertisement::Permit,
        bootstrap: Vec<Multiaddr>,
    ) -> Self {
        let assets = TestAssets::new();
        let mut server = Server::bind(&assets.0, 0, permit.protocol.clone(), bootstrap, None)
            .await
            .unwrap();
        server.enable_relay_advertisement(permit).unwrap();
        Self::start_server(server)
    }

    fn start_server(server: Server) -> Self {
        assert_eq!(
            server.listener.local_addr().unwrap().ip(),
            Ipv4Addr::LOCALHOST
        );
        Self {
            state: Arc::clone(&server.state),
            task: tokio::spawn(server.run()),
        }
    }

    pub(crate) async fn advertisement_challenge(&self) -> (u16, Value) {
        self.advertisement_post(relay_advertisement::CHALLENGE_PATH, "{}")
            .await
    }

    pub(crate) async fn advertisement_publish(&self, body: &str) -> (u16, Value) {
        self.advertisement_post(relay_advertisement::PUBLISH_PATH, body)
            .await
    }

    async fn advertisement_post(&self, path: &str, body: &str) -> (u16, Value) {
        Self::json_response(&self.post_to(path, &self.state.origin, body).await)
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

    pub(crate) async fn lookup_pairing_lan(&self) -> (u16, Value) {
        let response = self
            .post_to(PAIRING_LAN_PATH, &self.state.origin, "{}")
            .await;
        Self::json_response(&response)
    }

    async fn relay_control(&self, path: &str, lease_id: &str, relay_address: &str) -> (u16, Value) {
        let request = serde_json::json!({"lease_id": lease_id, "relay_address": relay_address});
        let response = self
            .post_to(path, &self.state.origin, &request.to_string())
            .await;
        Self::json_response(&response)
    }

    pub(crate) async fn activate_relay(&self, lease_id: &str, relay_address: &str) -> (u16, Value) {
        self.relay_control(RELAY_ACTIVATE_PATH, lease_id, relay_address)
            .await
    }

    pub(crate) async fn handoff_relay(&self, lease_id: &str, relay_address: &str) -> (u16, Value) {
        self.relay_control(RELAY_HANDOFF_PATH, lease_id, relay_address)
            .await
    }

    pub(crate) async fn stage_pairing_relay(&self, route: Multiaddr) -> io::Result<LeaseReply> {
        use crate::runtime::physical_network::{
            linux::egress::LinuxEgress, public_discovery::Scope,
        };

        let scope = Scope::new(Arc::new(LinuxEgress::for_control()))?;
        self.state
            .relay
            .lease_manager()
            .lease(
                scope,
                super::super::relay::AuthorizedCircuit::after_lookup(route),
            )
            .await?
            .publish()
    }

    pub(crate) async fn release_relay(&self, lease_id: &str) -> (u16, Value) {
        let request = serde_json::json!({"lease_id": lease_id});
        let response = self
            .post_to(RELAY_RELEASE_PATH, &self.state.origin, &request.to_string())
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
async fn activation_requires_exact_same_origin_and_bounded_json() {
    let fixture = Fixture::start(StreamProtocol::new(PUBLIC_IPFS_KADEMLIA_PROTOCOL), vec![]).await;
    let origin = &fixture.state.origin;
    let host = &fixture.state.host;
    let lease_id = "A".repeat(32);
    let candidate = format!(
        "/ip4/127.0.0.1/udp/4001/webrtc-direct/certhash/uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g/p2p/{}/p2p-circuit/p2p/{}",
        PeerId::random(),
        PeerId::random(),
    );
    let json = serde_json::json!({"lease_id": &lease_id, "relay_address": &candidate}).to_string();
    let request = format!("POST {RELAY_ACTIVATE_PATH} HTTP/1.1\r\nHost: {host}\r\n");
    let tail = format!(
        "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{json}",
        json.len()
    );
    for head in [
        format!("Sec-Fetch-Site: same-origin\r\n"),
        format!("Origin: {origin}\r\n"),
        format!("Origin: {origin}\r\nSec-Fetch-Site: same-site\r\n"),
        format!("Origin: {origin}\r\nSec-Fetch-Site: none\r\n"),
        "Origin: http://foreign.invalid\r\nSec-Fetch-Site: same-origin\r\n".to_owned(),
    ] {
        let response = fixture.exchange(&format!("{request}{head}{tail}")).await;
        assert_eq!(
            Fixture::json_response(&response),
            (403, serde_json::json!({"error":"wrong_origin"}))
        );
        assert!(
            !response
                .to_ascii_lowercase()
                .contains("access-control-allow")
        );
    }
    let admitted = format!("{request}Origin: {origin}\r\nSec-Fetch-Site: same-origin\r\n");
    for response in [
        fixture
            .exchange(&format!("{admitted}Origin: {origin}\r\n{tail}"))
            .await,
        fixture
            .exchange(&format!("{admitted}Sec-Fetch-Site: same-origin\r\n{tail}"))
            .await,
    ] {
        assert!(response.starts_with("HTTP/1.1 400 "), "{response}");
    }
    let response = fixture
        .exchange(&format!(
            "{admitted}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            MAX_RELAY_CONTROL_BODY_BYTES + 1
        ))
        .await;
    assert!(response.starts_with("HTTP/1.1 413 "), "{response}");
    for invalid in [
        serde_json::json!({"lease_id": "x", "relay_address": &candidate}),
        serde_json::json!({"lease_id": "*".repeat(32), "relay_address": &candidate}),
        serde_json::json!({"lease_id": &lease_id, "relay_address": "invalid"}),
        serde_json::json!({"lease_id": &lease_id, "relay_address": &candidate, "authorized": true}),
    ] {
        let response = fixture
            .post_to(RELAY_ACTIVATE_PATH, origin, &invalid.to_string())
            .await;
        assert!(response.starts_with("HTTP/1.1 400 "), "{response}");
    }
    assert_eq!(
        fixture.activate_relay(&lease_id, &candidate).await,
        (404, serde_json::json!({"error":"relay_lease_unavailable"}))
    );
    let foreign = fixture
        .post_to(RELAY_HANDOFF_PATH, "http://foreign.invalid", &json)
        .await;
    assert!(foreign.starts_with("HTTP/1.1 403 "), "{foreign}");
    assert_eq!(
        fixture.handoff_relay(&lease_id, &candidate).await,
        (404, serde_json::json!({"error":"relay_lease_unavailable"}))
    );
}

#[tokio::test]
async fn relay_advertisement_routes_are_opt_in_strict_and_bounded() {
    use crate::runtime::browser_host::advertisement::Permit;
    use relay_advertisement::{CHALLENGE_PATH, MARKER, MAX_CHALLENGE_BYTES, PUBLISH_PATH};

    let disabled = Fixture::start(StreamProtocol::new(PUBLIC_IPFS_KADEMLIA_PROTOCOL), vec![]).await;
    let page = |host: &str| format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
    assert!(
        !disabled
            .exchange(&page(&disabled.state.host))
            .await
            .contains(MARKER)
    );
    assert_eq!(disabled.advertisement_challenge().await.0, 404);
    assert_eq!(disabled.advertisement_publish("{}").await.0, 404);

    let browser_peer = PeerId::random();
    let relay = PeerId::random();
    let seed: Multiaddr = format!("/ip4/11.253.0.2/tcp/4001/p2p/{relay}")
        .parse()
        .unwrap();
    let fixture = Fixture::start_with_advertisement(
        Permit {
            network_name: "lab".into(),
            membership_tag: None,
            protocol: StreamProtocol::new("/browser-advertisement-test/kad/1"),
            browser_peer,
            destination: PeerId::random(),
            address: format!("{seed}/p2p-circuit/p2p/{browser_peer}")
                .parse()
                .unwrap(),
        },
        vec![seed],
    )
    .await;
    assert!(
        fixture
            .exchange(&page(&fixture.state.host))
            .await
            .contains(MARKER)
    );
    for (path, maximum) in [
        (CHALLENGE_PATH, MAX_CHALLENGE_BYTES),
        (
            PUBLISH_PATH,
            crate::peer_address_record::browser_advertisement::MAX_SUBMISSION_BYTES,
        ),
    ] {
        let wrong_origin = fixture.post_to(path, "https://other.invalid", "{}").await;
        assert_eq!(Fixture::json_response(&wrong_origin).0, 403);
        assert!(
            !wrong_origin
                .to_ascii_lowercase()
                .contains("access-control-allow")
        );
        let host = &fixture.state.host;
        let origin = &fixture.state.origin;
        for (headers, expected) in [
            (
                format!(
                    "Origin: {origin}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
                    maximum + 1
                ),
                413,
            ),
            (
                "Content-Type: application/json\r\nContent-Length: 2\r\n".into(),
                403,
            ),
            (
                format!("Origin: {origin}\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n"),
                415,
            ),
        ] {
            let response = fixture
                .exchange(&format!(
                    "POST {path} HTTP/1.1\r\nHost: {host}\r\n{headers}\r\n"
                ))
                .await;
            assert_eq!(Fixture::json_response(&response).0, expected);
        }
    }
    for field in ["private_key", "membership_key", "capability_secret"] {
        let plaintext = serde_json::json!({(field): "do-not-echo"});
        for path in [CHALLENGE_PATH, PUBLISH_PATH] {
            let response = fixture
                .post_to(path, &fixture.state.origin, &plaintext.to_string())
                .await;
            assert_eq!(Fixture::json_response(&response).0, 400);
            assert!(!response.contains("do-not-echo"));
        }
    }
    let (code, challenge) = fixture.advertisement_challenge().await;
    assert_eq!(code, 200);
    assert_eq!(challenge["browser_peer"], browser_peer.to_string());
    assert_eq!(fixture.advertisement_challenge().await.0, 429);
}

#[tokio::test]
async fn relay_advertisement_permit_file_denies_secrets_and_local_addresses() {
    let assets = TestAssets::new();
    let browser = PeerId::random();
    let member = PeerId::random();
    let relay = PeerId::random();
    let entrance = format!("/ip4/11.253.0.2/tcp/4001/p2p/{relay}");
    let mut server = Server::bind(
        &assets.0,
        0,
        StreamProtocol::new("/browser-advertisement-test/kad/1"),
        vec![entrance.parse().unwrap()],
        None,
    )
    .await
    .unwrap();
    let path = assets.0.join("permit.json");
    let mut permit = serde_json::json!({
        "network_name": "lab", "browser_peer": browser.to_string(),
        "destination": member.to_string(),
        "address": format!("/ip4/127.0.0.1/tcp/4001/p2p/{relay}/p2p-circuit/p2p/{browser}"),
    });
    std::fs::write(&path, permit.to_string()).unwrap();
    assert!(server.enable_relay_advertisement_file(&path).is_err());
    permit["address"] = format!("{entrance}/p2p-circuit/p2p/{browser}").into();
    permit["membership_key"] = "not public".into();
    std::fs::write(&path, permit.to_string()).unwrap();
    assert!(server.enable_relay_advertisement_file(&path).is_err());
    permit.as_object_mut().unwrap().remove("membership_key");
    std::fs::write(&path, permit.to_string()).unwrap();
    server.enable_relay_advertisement_file(&path).unwrap();
}

#[test]
fn file_inviter_assets_are_optional_and_allowlisted_as_a_pair() {
    let files = TestAssets::new();
    assert!(
        !load_assets(&files.0)
            .unwrap()
            .contains_key("/file-inviter.html")
    );
    std::fs::write(files.0.join("file-inviter.html"), "inviter page").unwrap();
    assert!(
        !load_assets(&files.0)
            .unwrap()
            .contains_key("/file-inviter.html")
    );
    std::fs::write(files.0.join("file-inviter.js"), "inviter script").unwrap();
    let assets = load_assets(&files.0).unwrap();
    assert_eq!(assets["/file-inviter.html"].bytes.as_ref(), b"inviter page");
    assert_eq!(
        assets["/file-inviter.js"].mime,
        "text/javascript; charset=utf-8"
    );
    assert!(!assets.contains_key("/private.json"));
}

#[test]
fn code_inviter_assets_are_optional_and_independent_of_file_inviter() {
    let files = TestAssets::new();
    let page = files.0.join("code-inviter.html");
    let script = files.0.join("code-inviter.js");
    std::fs::write(&script, "code inviter script").unwrap();
    assert!(
        !load_assets(&files.0)
            .unwrap()
            .contains_key("/code-inviter.js")
    );
    std::fs::write(&page, "code inviter page").unwrap();
    let assets = load_assets(&files.0).unwrap();
    assert_eq!(
        assets["/code-inviter.html"].mime,
        "text/html; charset=utf-8"
    );
    assert_eq!(
        assets["/code-inviter.js"].mime,
        "text/javascript; charset=utf-8"
    );
    assert!(!assets.contains_key("/file-inviter.html"));
    assert!(!assets.contains_key("/private.json"));
}

#[tokio::test]
async fn serves_only_allowlisted_assets_and_refuses_other_origins() {
    let fixture = Fixture::start(StreamProtocol::new(PUBLIC_IPFS_KADEMLIA_PROTOCOL), vec![]).await;
    let host = &fixture.state.host;
    let response = fixture
        .exchange(&format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"))
        .await;
    assert!(response.starts_with("HTTP/1.1 200 "));
    assert!(response.contains(&format!(
        "<head>{MARKER}{PAIRING_MARKER}{PAIRING_LAN_MARKER}</head>"
    )));
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
            serde_json::json!({"locator": &locator, "relay_address": "/ip4/8.8.8.8/udp/9"}),
            serde_json::json!({"locator": &locator, "relay_lease_id": "not accepted"}),
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
    let foreign = fixture
        .post_to(PAIRING_LAN_PATH, "http://other.invalid", "{}")
        .await;
    assert!(foreign.starts_with("HTTP/1.1 403 "), "{foreign}");
    for body in [
        serde_json::json!({"locator": locator}),
        serde_json::json!({"code": "not accepted"}),
        serde_json::json!([]),
        serde_json::Value::Null,
    ] {
        let response = fixture
            .post_to(PAIRING_LAN_PATH, &fixture.state.origin, &body.to_string())
            .await;
        assert!(response.starts_with("HTTP/1.1 400 "), "{response}");
    }
    let (status, response) = fixture.lookup_pairing_lan().await;
    assert_eq!(status, 429);
    assert_eq!(response, serde_json::json!({"error":"discovery_busy"}));
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
    let (status, reply) = fixture
        .lookup_request(serde_json::json!({
            "network_name":"n",
            "peer":peer,
            "lan":false,
            "relay_address":"/ip4/8.8.8.8/udp/4001",
        }))
        .await;
    assert_eq!(status, 400, "{reply}");
    let body = serde_json::json!({"network_name":"n", "peer":peer, "kademlia":false, "lan":false});
    let response = fixture.post(&fixture.state.origin, &body.to_string()).await;
    let (status, reply) = Fixture::json_response(&response);
    assert_eq!(status, 200);
    assert_eq!(reply, serde_json::json!({"addresses":[], "source":null}));
}
