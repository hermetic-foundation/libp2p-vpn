use super::*;
use std::net::SocketAddr;

pub(super) const TEST_NAME: &str = "tun_namespace_minimal_tcp_follows_route_preference_and_returns";
pub(super) const ACCEPTOR_TEST_NAME: &str =
    "tun_namespace_minimal_tcp_acceptor_follows_route_preference_and_returns";
const DESTINATION: &str = "10.250.0.2:42102";

pub(super) fn is_test(name: &str) -> bool {
    matches!(name, TEST_NAME | ACCEPTOR_TEST_NAME)
}

pub(super) fn identities(test: &str) -> (NodeIdentity, NodeIdentity) {
    let a = NodeIdentity::generate_ed25519().unwrap();
    let b = NodeIdentity::generate_ed25519().unwrap();
    // TCP duplicate arbitration compares transport PeerIds, not overlay hashes.
    let rank = |identity: &NodeIdentity| {
        identity
            .peer_id
            .parse::<libp2p::PeerId>()
            .unwrap()
            .to_bytes()
    };
    if (rank(&a) < rank(&b)) == (test != ACCEPTOR_TEST_NAME) {
        (a, b)
    } else {
        (b, a)
    }
}

pub(super) fn configure_node(config: &mut Config, role: &str) {
    let listen = match role {
        "a" => "/ip4/10.250.0.1/tcp/42101",
        "b" => "/ip4/10.250.0.2/tcp/42102",
        other => panic!("unknown TCP failback role {other}"),
    };
    // Do not advertise either alternate gateway or any UDP/QUIC endpoint.
    config.network.listen_addresses = vec![listen.to_owned()];
    config.network.external_addresses = config.network.listen_addresses.clone();
    config.network.packet_plane.listen.clear();
    config.network.packet_plane.external_endpoints.clear();
    config.network.packet_plane.quic_listen.clear();
    config.network.packet_plane.quic_external_endpoints.clear();
    config.validate_runtime().expect("TCP-only failback config");
}

pub(super) fn configure_initial_direction(a: u32, b: u32, test: &str) {
    let (pid, source, destination, port) = if test == ACCEPTOR_TEST_NAME {
        (a, "10.250.0.1", "10.250.0.2", "42102")
    } else {
        (b, "10.250.0.2", "10.250.0.1", "42101")
    };
    // mDNS discovery is simultaneous; startup order alone cannot prove which
    // endpoint initiates. Only the intended direction may send its initial SYN.
    ns_command(
        pid,
        "iptables",
        &[
            "-I",
            "OUTPUT",
            "-p",
            "tcp",
            "--syn",
            "-s",
            source,
            "-d",
            destination,
            "--dport",
            port,
            "-j",
            "DROP",
        ],
    );
}

pub(super) fn capture(temp: &Path, a: u32, overlay_b: Ipv4Addr, test: &str) {
    let initial_role = if test == ACCEPTOR_TEST_NAME {
        "listener"
    } else {
        "dialer"
    };
    let initial = wait_for_daemon_state(
        temp,
        "a",
        // Startup duplicates may use the bounded 40-second migration grace;
        // allow its normal maintenance cleanup before checking the final role.
        scaled_wait_timeout(Duration::from_secs(60)),
        "initial TCP initiator role",
        |lines| selected_tcp(lines).is_some_and(|(_, role)| role == initial_role),
    );
    let mut old_connection = selected_tcp(&initial).unwrap().0.to_owned();
    let mut old_owner = route_owner(temp, &old_connection);
    assert_eq!(field(&old_owner, "role"), Some(initial_role));
    let mut old_source: SocketAddr = field(&old_owner, "source").unwrap().parse().unwrap();
    assert_eq!(old_source.ip().to_string(), "10.250.0.1");
    assert_tcp_traffic(temp, a, overlay_b, "before-route-change", &old_connection);

    for (stage, operation, interface, source) in [
        ("preferred-route-away", "del", "alt-a", "169.254.200.1"),
        ("preferred-route-return", "add", "veth-a", "10.250.0.1"),
    ] {
        assert_socket(temp, a, stage, old_source, None, true);
        // Hold only new connections; existing TCP data and ACKs remain usable.
        let syn_rule = [
            "OUTPUT",
            "-o",
            interface,
            "-p",
            "tcp",
            "--syn",
            "-d",
            "10.250.0.2",
            "--dport",
            "42102",
            "-j",
            "DROP",
        ];
        let mut command = vec!["-I"];
        command.extend(syn_rule);
        ns_command(a, "iptables", &command);
        if test == ACCEPTOR_TEST_NAME && operation == "add" {
            // The alternate-source migration is already complete. Remove the
            // startup-only constraint after the return-stage SYN guard is up.
            ns_command(
                a,
                "iptables",
                &[
                    "-D",
                    "OUTPUT",
                    "-p",
                    "tcp",
                    "--syn",
                    "-s",
                    "10.250.0.1",
                    "-d",
                    "10.250.0.2",
                    "--dport",
                    "42102",
                    "-j",
                    "DROP",
                ],
            );
        }
        let start = read_log(&temp.join("node-a.log")).len();
        ns_command(
            a,
            "ip",
            &[
                "route",
                operation,
                "10.250.0.2/32",
                "dev",
                "veth-a",
                "src",
                "10.250.0.1",
                "metric",
                "100",
            ],
        );
        let route = ns_command_output(a, "ip", &["-j", "route", "get", "10.250.0.2"]);
        assert!(route.status.success());
        let routes: serde_json::Value = serde_json::from_slice(&route.stdout).unwrap();
        assert_eq!(routes[0]["dev"], interface);
        assert_eq!(routes[0]["prefsrc"], source);
        fs::write(temp.join(format!("{stage}-route.json")), &route.stdout).unwrap();
        wait_event(temp, start, "control_tcp_replacement_dialing", |_| true);
        assert_tcp_traffic(
            temp,
            a,
            overlay_b,
            &format!("{stage}-during"),
            &old_connection,
        );
        let blocked = read_log(&temp.join("node-a.log"));
        assert!(
            !blocked[start..].lines().any(|line| {
                field(line, "event") == Some("control_tcp_replacement_promoted")
                    || (matches!(
                        field(line, "event"),
                        Some("connection_closed" | "control_tcp_fallback_retired")
                    ) && field(line, "connection_id") == Some(old_connection.as_str()))
            }),
            "{stage}: fallback must carry traffic before any replacement can promote\n{}",
            &blocked[start..]
        );
        assert_socket(temp, a, stage, old_source, None, true);
        // The old physical path is still up and its source is still assigned.
        let (old_interface, old_gateway) = if operation == "del" {
            ("veth-a", "10.250.0.2")
        } else {
            ("alt-a", "169.254.200.2")
        };
        ns_command(
            a,
            "ping",
            &["-c", "1", "-W", "2", "-I", old_interface, old_gateway],
        );
        let mut command = vec!["-D"];
        command.extend(syn_rule);
        ns_command(a, "iptables", &command);

        let promoted = wait_event(temp, start, "control_tcp_replacement_promoted", |_| true);
        let connection = field(&promoted, "connection_id").unwrap();
        let generation = field(&promoted, "generation").unwrap();
        assert_ne!(
            connection, old_connection,
            "replacement needs a new connection"
        );
        let owner = route_owner(temp, connection);
        let current: SocketAddr = field(&owner, "source").unwrap().parse().unwrap();
        assert_eq!(current.ip().to_string(), source);
        assert_ne!(current, old_source, "replacement must own the new source");
        assert_eq!(field(&owner, "role"), Some("dialer"));
        assert_eq!(field(&owner, "generation"), Some(generation));
        assert_eq!(field(&owner, "peer"), field(&old_owner, "peer"));
        assert_eq!(field(&owner, "peer"), field(&promoted, "peer"));
        assert_socket(temp, a, stage, current, Some(DESTINATION), true);
        wait_for_daemon_state(
            temp,
            "a",
            scaled_wait_timeout(Duration::from_secs(10)),
            "promoted TCP connection selected for payload",
            |lines| selected_tcp(lines).is_some_and(|(id, _)| id == connection),
        );
        let retired = wait_event(temp, start, "control_tcp_fallback_retired", |line| {
            field(line, "connection_id") == Some(old_connection.as_str())
                && field(line, "generation") == Some(generation)
                && field(line, "peer") == field(&promoted, "peer")
        });
        let closed = wait_event(temp, start, "connection_closed", |line| {
            field(line, "connection_id") == Some(old_connection.as_str())
                && field(line, "peer") == field(&promoted, "peer")
        });
        assert_socket(temp, a, stage, old_source, None, false);
        assert_tcp_traffic(
            temp,
            a,
            overlay_b,
            &format!("{stage}-after-retirement"),
            connection,
        );
        let log = read_log(&temp.join("node-a.log"));
        let transition = &log[start..];
        assert!(transition.find(&promoted).unwrap() < transition.find(&retired).unwrap());
        assert!(transition.find(&retired).unwrap() < transition.find(&closed).unwrap());
        fs::write(
            temp.join(format!("{stage}-ownership.txt")),
            format!("{old_owner}\n{owner}\n{promoted}\n{retired}\n{closed}\n"),
        )
        .unwrap();
        fs::write(temp.join(format!("{stage}-node-a.log")), transition).unwrap();
        old_connection = connection.to_owned();
        old_source = current;
        old_owner = owner;
    }
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace().find_map(|part| {
        let (name, value) = part.split_once('=')?;
        (name == key).then_some(value)
    })
}

fn wait_event(temp: &Path, start: usize, event: &str, predicate: impl Fn(&str) -> bool) -> String {
    let deadline = Instant::now() + scaled_wait_timeout(Duration::from_secs(60));
    loop {
        let log = read_log(&temp.join("node-a.log"));
        if let Some(line) = log[start..].split_inclusive('\n').find(|line| {
            line.ends_with('\n') && field(line, "event") == Some(event) && predicate(line)
        }) {
            return line.to_owned();
        }
        assert!(
            Instant::now() < deadline,
            "missing {event} after route transition\n{}",
            log_tail(&log, 100)
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn route_owner(temp: &Path, connection: &str) -> String {
    let log = read_log(&temp.join("node-a.log"));
    log.lines()
        .find(|line| {
            field(line, "event") == Some("control_tcp_route_owned")
                && field(line, "connection_id") == Some(connection)
        })
        .unwrap_or_else(|| panic!("no source ownership for TCP connection {connection}\n{log}"))
        .to_owned()
}

fn selected_tcp(lines: &[String]) -> Option<(&str, &str)> {
    lines.iter().find_map(|line| {
        let fields = line
            .strip_prefix("peer state: ")?
            .split_whitespace()
            .collect::<Vec<_>>();
        let value = |key| {
            fields
                .windows(2)
                .find_map(|pair| (pair[0] == key).then_some(pair[1]))
        };
        if value("selected_path")? != "direct_tcp_stream" {
            return None;
        }
        Some((
            value("selected_path_connection_id")?,
            value("selected_path_connection_role")?,
        ))
    })
}

fn assert_tcp_traffic(temp: &Path, a: u32, overlay_b: Ipv4Addr, stage: &str, connection: &str) {
    let before = ["a", "b"].map(|role| {
        let lines = wait_for_daemon_state(temp, role, Duration::from_secs(5), stage, |_| true);
        state_metric_count(&lines, "outbound_direct_tcp_stream_fallback_packets").unwrap()
    });
    let ping = ping_from_namespace(a, "hse2ea", overlay_b);
    fs::write(temp.join(format!("{stage}-ping.txt")), &ping.stdout).unwrap();
    assert!(
        ping.status.success()
            && recovery_soak::complete_ping(&String::from_utf8_lossy(&ping.stdout)),
        "{stage}: TCP overlay must deliver all five packets: {ping:?}"
    );
    for (role, before) in ["a", "b"].into_iter().zip(before) {
        let lines = wait_for_daemon_state(
            temp,
            role,
            scaled_wait_timeout(Duration::from_secs(5)),
            stage,
            |lines| {
                state_metric_count(lines, "outbound_direct_tcp_stream_fallback_packets")
                    .is_some_and(|count| count >= before + 5)
            },
        );
        assert!(
            selected_tcp(&lines).is_some(),
            "{stage}: node {role} must select TCP"
        );
        if role == "a" {
            assert_eq!(
                selected_tcp(&lines).unwrap().0,
                connection,
                "{stage}: payload must use the intended TCP connection"
            );
        }
        for metric in [
            "outbound_direct_quic_stream_fallback_packets",
            "outbound_owned_quic_datagram_packets",
            "outbound_owned_udp_datagram_packets",
            "outbound_relay_stream_fallback_packets",
            "packet_plane_listeners",
            "packet_plane_sessions",
            "packet_plane_quic_listeners",
            "packet_plane_quic_sessions",
        ] {
            assert_eq!(
                state_metric_count(&lines, metric),
                Some(0),
                "{stage}: node {role} {metric}"
            );
        }
        let peer = lines
            .iter()
            .find(|line| line.starts_with("peer state: "))
            .unwrap();
        for capability in [
            "quic_datagrams",
            "native_quic_datagrams",
            "owned_udp_packet_plane",
            "owned_quic_packet_plane",
        ] {
            assert!(
                peer.split_whitespace()
                    .collect::<Vec<_>>()
                    .windows(2)
                    .any(|pair| pair == [capability, "false"]),
                "{stage}: node {role} {capability}: {peer}"
            );
        }
        fs::write(
            temp.join(format!("{stage}-{role}-state.txt")),
            lines.join("\n"),
        )
        .unwrap();
    }
}

fn assert_socket(
    temp: &Path,
    a: u32,
    stage: &str,
    source: SocketAddr,
    destination: Option<&str>,
    present: bool,
) {
    let sockets = ns_command_output(a, "ss", &["-t", "-a", "-n", "-H"]);
    assert!(sockets.status.success());
    let output = String::from_utf8_lossy(&sockets.stdout);
    let found = output.lines().any(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields.first() == Some(&"ESTAB")
            && fields
                .get(3)
                .and_then(|value| value.parse::<SocketAddr>().ok())
                == Some(source)
            && destination.is_none_or(|remote| fields.get(4) == Some(&remote))
    });
    fs::write(
        temp.join(format!("{stage}-sockets-{present}.txt")),
        &sockets.stdout,
    )
    .unwrap();
    assert_eq!(
        found, present,
        "{stage}: established socket {source} destination {destination:?}\n{output}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_both_tcp_failback_test_names() {
        assert!(is_test(
            "tun_namespace_minimal_tcp_follows_route_preference_and_returns"
        ));
        assert!(is_test(
            "tun_namespace_minimal_tcp_acceptor_follows_route_preference_and_returns"
        ));
        assert!(!is_test(quic_route_failback::TEST_NAME));
        assert!(!is_test(
            "tun_namespace_minimal_tcp_follows_route_preference_and_returns_extra"
        ));
    }

    #[test]
    fn event_fields_do_not_match_other_events_or_connection_id_prefixes() {
        let line =
            "level=info event=control_tcp_fallback_retired peer=p connection_id=12 generation=4";
        assert_eq!(field(line, "event"), Some("control_tcp_fallback_retired"));
        assert_eq!(field(line, "connection_id"), Some("12"));
        assert_ne!(field(line, "connection_id"), Some("1"));
        assert_eq!(field(line, "source"), None);
        let owner =
            "event=control_tcp_route_owned connection_id=12 source=169.254.200.1:45678 role=dialer";
        assert_eq!(
            field(owner, "source")
                .unwrap()
                .parse::<SocketAddr>()
                .unwrap(),
            "169.254.200.1:45678".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn selected_tcp_requires_tcp_and_both_connection_fields() {
        for role in ["dialer", "listener"] {
            let lines = vec![format!(
                "peer state: p transport t validated true quic_datagrams false selected_path direct_tcp_stream selected_path_connection_id 12 selected_path_origin mdns selected_path_connection_role {role} selected_path_established_as_relayed false"
            )];
            assert_eq!(selected_tcp(&lines), Some(("12", role)));
        }
        for line in [
            "peer state: p selected_path direct_quic_stream selected_path_connection_id 12 selected_path_connection_role dialer",
            "peer state: p selected_path direct_tcp_stream selected_path_connection_id 12",
            "peer state: p selected_path direct_tcp_stream selected_path_connection_role dialer",
            "peer path state: p direct_tcp_stream connection_id 12 connection_role dialer",
        ] {
            assert_eq!(selected_tcp(&[line.to_owned()]), None);
        }
    }
}
