use super::*;
use std::net::SocketAddr;

pub(super) const TEST_NAME: &str =
    "tun_namespace_relay_circuit_follows_route_preference_and_returns";
pub(super) const ACCEPTOR_TEST_NAME: &str =
    "tun_namespace_incoming_relay_circuit_follows_route_preference_and_returns";

pub(super) fn is_test(name: &str) -> bool {
    matches!(name, TEST_NAME | ACCEPTOR_TEST_NAME)
}

pub(super) fn wait_for_reservation(temp: &Path) {
    wait_event(temp, "b", 0, "relay_listen_address_ready", |_| true);
}

fn target(a: u32, b: u32, test: &str) -> (u32, &'static str, &'static str, &'static str) {
    if test == ACCEPTOR_TEST_NAME {
        (b, "b", "veth-b", "10.251.0.2")
    } else {
        (a, "a", "veth-a", "10.251.0.1")
    }
}

pub(super) fn configure(relay: u32, a: u32, b: u32, test: &str) {
    let (node, _, interface, source) = target(a, b, test);
    run_command(
        "ip",
        &[
            "link",
            "add",
            "alt-node",
            "type",
            "veth",
            "peer",
            "name",
            "alt-relay",
        ],
    );
    for (pid, device, address) in [
        (node, "alt-node", "169.254.210.1/30"),
        (relay, "alt-relay", "169.254.210.2/30"),
    ] {
        run_command("ip", &["link", "set", device, "netns", &pid.to_string()]);
        ns_command(pid, "ip", &["addr", "add", address, "dev", device]);
        ns_command(pid, "ip", &["link", "set", device, "up"]);
    }
    ns_command(
        node,
        "ip",
        &[
            "route",
            "add",
            "10.251.0.254/32",
            "dev",
            interface,
            "src",
            source,
            "metric",
            "100",
        ],
    );
    ns_command(
        node,
        "ip",
        &[
            "route",
            "add",
            "10.251.0.254/32",
            "via",
            "169.254.210.2",
            "dev",
            "alt-node",
            "src",
            "169.254.210.1",
            "metric",
            "200",
        ],
    );
}

pub(super) fn capture(temp: &Path, a: u32, b: u32, overlay_b: Ipv4Addr, test: &str) {
    let (node, role, interface, original_source) = target(a, b, test);
    let initial = state(temp, role, "initial relay path");
    fs::write(
        temp.join(format!("initial-relay-{role}-state.txt")),
        initial.join("\n"),
    )
    .unwrap();
    let (peer, old, connection_role) = selected_relay(&initial).expect("relay-only initial path");
    assert_eq!(
        connection_role,
        if test == ACCEPTOR_TEST_NAME {
            "listener"
        } else {
            "dialer"
        },
        "fixture must move the intended circuit direction"
    );
    let peer = peer.to_owned();
    let mut old = old.to_owned();
    for (stage, operation, source) in [
        ("relay-route-away", "del", "169.254.210.1"),
        ("relay-route-return", "add", original_source),
    ] {
        let start = read_log(&temp.join(format!("node-{role}.log"))).len();
        ns_command(
            node,
            "ip",
            &[
                "route",
                operation,
                "10.251.0.254/32",
                "dev",
                interface,
                "src",
                original_source,
                "metric",
                "100",
            ],
        );
        assert_payload(temp, a, overlay_b, &format!("{stage}-during"));
        let admitted = wait_event(
            temp,
            role,
            start,
            "control_relay_handoff_admitted",
            |line| field(line, "peer") == Some(peer.as_str()),
        );
        let outer = field(&admitted, "replacement_outer").expect("replacement outer");
        let old_outer = field(&admitted, "old_outer").expect("old outer");
        assert_ne!(outer, old_outer);
        let owner = wait_event(temp, role, 0, "control_tcp_route_owned", |line| {
            field(line, "connection_id") == Some(outer)
        });
        let local: SocketAddr = field(&owner, "source").unwrap().parse().unwrap();
        assert_eq!(
            local.ip().to_string(),
            source,
            "replacement bypassed current kernel route"
        );
        let previous = wait_event(temp, role, 0, "control_tcp_route_owned", |line| {
            field(line, "connection_id") == Some(old_outer)
        });
        let previous: SocketAddr = field(&previous, "source").unwrap().parse().unwrap();
        let promoted = wait_event(
            temp,
            role,
            start,
            "control_relay_replacement_promoted",
            |line| field(line, "peer") == Some(peer.as_str()),
        );
        let replacement = field(&promoted, "connection_id").unwrap();
        assert_ne!(replacement, old);
        let selected = wait_for_daemon_state(
            temp,
            role,
            scaled_wait_timeout(Duration::from_secs(20)),
            stage,
            |lines| {
                selected_relay(lines)
                    .is_some_and(|(owner, id, _)| owner == peer && id == replacement)
            },
        );
        fs::write(
            temp.join(format!("{stage}-{role}-state.txt")),
            selected.join("\n"),
        )
        .unwrap();
        let deadline = Instant::now() + scaled_wait_timeout(Duration::from_secs(40));
        loop {
            let sockets = ns_command_output(
                node,
                "ss",
                &[
                    "-tnH",
                    "state",
                    "established",
                    "sport",
                    "=",
                    &format!(":{}", previous.port()),
                ],
            );
            assert!(sockets.status.success());
            if !String::from_utf8_lossy(&sockets.stdout).contains(&previous.to_string()) {
                fs::write(
                    temp.join(format!("{stage}-retired-socket.txt")),
                    &sockets.stdout,
                )
                .unwrap();
                break;
            }
            assert!(
                Instant::now() < deadline,
                "old relay socket {previous} remains after validated circuit migration\n{}",
                log_tail(&read_log(&temp.join(format!("node-{role}.log"))), 120)
            );
            thread::sleep(Duration::from_millis(100));
        }
        assert_payload(temp, a, overlay_b, &format!("{stage}-after"));
        old = replacement.to_owned();
    }
}

fn state(temp: &Path, role: &str, stage: &str) -> Vec<String> {
    wait_for_daemon_state(temp, role, Duration::from_secs(5), stage, |lines| {
        selected_relay(lines).is_some()
    })
}

fn selected_relay(lines: &[String]) -> Option<(&str, &str, &str)> {
    lines.iter().find_map(|line| {
        let mut words = line.strip_prefix("peer state: ")?.split_whitespace();
        words.next()?;
        let fields = words.collect::<Vec<_>>();
        let value = |key| {
            fields
                .windows(2)
                .find_map(|pair| (pair[0] == key).then_some(pair[1]))
        };
        if value("selected_path") != Some("circuit_relay") {
            return None;
        }
        Some((
            value("transport")?,
            value("selected_path_connection_id")?,
            value("selected_path_connection_role")?,
        ))
    })
}

fn assert_payload(temp: &Path, node: u32, overlay_b: Ipv4Addr, stage: &str) {
    let before = ["a", "b"].map(|role| {
        state_metric_count(
            &state(temp, role, stage),
            "outbound_relay_stream_fallback_packets",
        )
        .unwrap()
    });
    let ping = ping_from_namespace(node, "hse2ea", overlay_b);
    assert!(
        ping.status.success()
            && recovery_soak::complete_ping(&String::from_utf8_lossy(&ping.stdout)),
        "relayed traffic failed during {stage}: {ping:?}"
    );
    fs::write(temp.join(format!("{stage}-ping.txt")), &ping.stdout).unwrap();
    for (index, role) in ["a", "b"].into_iter().enumerate() {
        wait_for_daemon_state(temp, role, Duration::from_secs(5), stage, |lines| {
            state_metric_count(lines, "outbound_relay_stream_fallback_packets")
                .is_some_and(|count| count >= before[index] + 5)
                && state_metric_count(lines, "outbound_direct_tcp_stream_fallback_packets")
                    == Some(0)
                && state_metric_count(lines, "outbound_direct_quic_stream_fallback_packets")
                    == Some(0)
        });
    }
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace().find_map(|word| {
        word.split_once('=')
            .and_then(|(name, value)| (name == key).then_some(value))
    })
}

fn wait_event(
    temp: &Path,
    role: &str,
    start: usize,
    event: &str,
    predicate: impl Fn(&str) -> bool,
) -> String {
    let deadline = Instant::now() + scaled_wait_timeout(Duration::from_secs(60));
    loop {
        let log = read_log(&temp.join(format!("node-{role}.log")));
        if let Some(line) = log
            .get(start..)
            .unwrap_or_default()
            .split_inclusive('\n')
            .filter(|line| line.ends_with('\n') && field(line, "event") == Some(event))
            .find(|line| predicate(line))
        {
            return line.to_owned();
        }
        assert!(
            Instant::now() < deadline,
            "missing {event}\n{}",
            log_tail(&log, 120)
        );
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_circuit_uses_exact_named_fields_and_rejects_direct_paths() {
        let state = ["peer state: overlay-remote transport native-peer validated true selected_path circuit_relay selected_path_connection_id 72 selected_path_connection_role listener".to_owned()];
        assert_eq!(
            selected_relay(&state),
            Some(("native-peer", "72", "listener"))
        );
        let direct = [state[0].replace("circuit_relay", "direct_tcp_stream")];
        assert_eq!(selected_relay(&direct), None);
        assert!(is_test(TEST_NAME));
        assert!(is_test(ACCEPTOR_TEST_NAME));
        assert!(!is_test(&format!("{TEST_NAME}_suffix")));
    }
}
