use super::*;

pub(super) struct Live {
    state: Vec<String>,
    status: Vec<String>,
    paths: Vec<String>,
}

impl std::fmt::Debug for Live {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let counters = self
            .status
            .iter()
            .filter(|line| {
                [
                    "relay_reservations_accepted ",
                    "auto_relay_active_reservations ",
                    "path_healthy_relay_paths ",
                    "outbound_relay_stream_fallback_packets ",
                    "outbound_queue_blocked_no_supported_path_events ",
                    "inbound_packets ",
                ]
                .iter()
                .any(|prefix| line.starts_with(prefix))
            })
            .collect::<Vec<_>>();
        let circuits = self
            .state
            .iter()
            .filter(|line| {
                line.starts_with("physical circuit state: ")
                    || line.starts_with("connected_overlay_peers ")
            })
            .collect::<Vec<_>>();
        f.debug_struct("Live")
            .field("paths", &self.paths)
            .field("circuits", &circuits)
            .field("counters", &counters)
            .finish()
    }
}

impl Live {
    pub(super) async fn read(node: &Node) -> Self {
        tokio::time::timeout(Duration::from_secs(3), async {
            Self {
                state: node.control.state().await.unwrap(),
                status: node.control.status().await.unwrap(),
                paths: node.control.paths().await.unwrap(),
            }
        })
        .await
        .expect("runtime control must remain responsive")
    }

    pub(super) fn metric(&self, name: &str) -> u64 {
        self.status
            .iter()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(' ')?.parse().ok())
            .unwrap_or_else(|| panic!("missing {name} counter"))
    }

    pub(super) fn events<'a>(&'a self, event: &'a str) -> impl Iterator<Item = Multiaddr> + 'a {
        self.state.iter().filter_map(move |line| {
            (line.starts_with("transport event: ") && property(line, "event") == Some(event))
                .then(|| property(line, "address")?.parse().ok())
                .flatten()
        })
    }

    pub(super) fn relay_listen_addresses(&self) -> Vec<Multiaddr> {
        self.events("relay_listen_address_ready").collect()
    }

    pub(super) fn selected_circuit(
        &self,
        peer: libp2p::PeerId,
        entrance: &Multiaddr,
        role: &str,
    ) -> bool {
        let Some(Protocol::P2p(relay_peer)) = entrance.iter().last() else {
            return false;
        };
        let peer_overlay = PeerId::from_libp2p(peer);
        let relay_overlay = PeerId::from_libp2p(relay_peer).to_string();
        let prefix = format!("peer selected path: {peer_overlay} circuit_relay ");
        let peer = peer.to_string();
        let relay = relay_peer.to_string();
        let Some(path) = self.paths.iter().find(|line| line.starts_with(&prefix)) else {
            return false;
        };
        if value(path, "connection_role") != Some(role)
            || value(path, "relay_peer") != Some(&relay_overlay)
            || value(path, "established_as_relayed") != Some("true")
        {
            return false;
        }
        let Some(inner) = value(path, "connection_id") else {
            return false;
        };
        let matching_outer = self.state.iter().any(|line| {
            line.starts_with("physical circuit state: ")
                && property(line, "peer") == Some(&peer)
                && property(line, "connection_id") == Some(inner)
                && property(line, "relay") == Some(&relay)
                && property(line, "outer_usable") == Some("true")
                && property(line, "outer_retiring") == Some("false")
                && property(line, "outer_remote")
                    .and_then(|address| address.parse::<Multiaddr>().ok())
                    .and_then(|address| address.with_p2p(relay_peer).ok())
                    .as_ref()
                    == Some(entrance)
        });
        let metadata_prefix = format!("peer path: {peer_overlay} ");
        let no_alternate = self
            .paths
            .iter()
            .filter_map(|line| line.strip_prefix(&metadata_prefix))
            .all(|path| {
                path.starts_with("circuit_relay ")
                    && value(path, "relay_peer") == Some(&relay_overlay)
            });
        matching_outer && no_alternate
    }
}

pub(super) async fn wait_until(name: &str, node: &Node, condition: impl Fn(&Live) -> bool) -> Live {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let live = Live::read(node).await;
        if condition(&live) {
            return live;
        }
        assert!(
            Instant::now() < deadline,
            "{name} did not become ready: {live:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn property<'a>(line: &'a str, label: &str) -> Option<&'a str> {
    line.split_whitespace().find_map(|word| {
        let (key, value) = word.split_once('=')?;
        (key == label).then_some(value)
    })
}

fn value<'a>(line: &'a str, label: &str) -> Option<&'a str> {
    let mut words = line.split_whitespace();
    words.find(|word| *word == label)?;
    words.next()
}
