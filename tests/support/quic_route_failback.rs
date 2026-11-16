use super::*;
use std::net::SocketAddr;

pub(super) const TEST_NAME: &str =
    "tun_namespace_minimal_quic_follows_route_preference_and_returns";

pub(super) fn identities() -> (NodeIdentity, NodeIdentity) {
    let a = NodeIdentity::generate_ed25519().unwrap();
    let b = NodeIdentity::generate_ed25519().unwrap();
    let rank = |identity: &NodeIdentity| {
        p2p_vpn::PeerId::from_libp2p(identity.peer_id.parse().unwrap()).as_bytes()
    };
    if rank(&a) < rank(&b) { (a, b) } else { (b, a) }
}

pub(super) fn configure(a: u32, b: u32) {
    run_command(
        "ip",
        &[
            "link", "add", "alt-a", "type", "veth", "peer", "name", "alt-b",
        ],
    );
    // Link-local gateway addresses are deliberately not advertised as peer
    // endpoints. The server's one advertised address stays reachable via both.
    for (pid, name, address) in [
        (a, "alt-a", "169.254.200.1/30"),
        (b, "alt-b", "169.254.200.2/30"),
    ] {
        run_command("ip", &["link", "set", name, "netns", &pid.to_string()]);
        ns_command(pid, "ip", &["addr", "add", address, "dev", name]);
        ns_command(pid, "ip", &["link", "set", name, "up"]);
    }
    ns_command(
        a,
        "ip",
        &[
            "route",
            "add",
            "10.250.0.2/32",
            "dev",
            "veth-a",
            "src",
            "10.250.0.1",
            "metric",
            "100",
        ],
    );
    ns_command(
        a,
        "ip",
        &[
            "route",
            "add",
            "10.250.0.2/32",
            "via",
            "169.254.200.2",
            "dev",
            "alt-a",
            "src",
            "169.254.200.1",
            "metric",
            "200",
        ],
    );
}

pub(super) fn capture(temp: &Path, a: u32, overlay_b: Ipv4Addr) {
    let destination = live_endpoint(&state(temp, "a"));
    assert_eq!(destination.ip().to_string(), "10.250.0.2");
    let mut old_source = live_endpoint(&state(temp, "b"));
    assert_eq!(old_source.ip().to_string(), "10.250.0.1");
    for (stage, operation, source) in [
        ("preferred-route-away", "del", "169.254.200.1"),
        ("preferred-route-return", "add", "10.250.0.1"),
    ] {
        let failure_start = read_log(&temp.join("node-a.log")).len();
        let port = destination.port().to_string();
        let drop_rule = [
            "OUTPUT", "-o", "alt-a", "-p", "udp", "--dport", &port, "-j", "DROP",
        ];
        if operation == "del" {
            let mut command = vec!["-I"];
            command.extend(drop_rule);
            ns_command(a, "iptables", &command);
        }
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
        // Both links and old source addresses remain usable. Validate service
        // immediately, before waiting for the preferred candidate to win.
        let ping = ping_from_namespace(a, "hse2ea", overlay_b);
        assert!(
            ping.status.success()
                && recovery_soak::complete_ping(&String::from_utf8_lossy(&ping.stdout)),
            "fallback service was lost during {stage}: {ping:?}"
        );
        if operation == "del" {
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                let log = read_log(&temp.join("node-a.log"));
                if log[failure_start..].lines().any(|line| {
                    line.contains("event=packet_plane_quic_connection_failed")
                        && line.contains("role=initiator")
                }) {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "preferred path was not attempted while blocked"
                );
                thread::sleep(Duration::from_millis(100));
            }
            assert_eq!(
                live_endpoint(&state(temp, "b")),
                old_source,
                "reverse fallback must not masquerade as preferred-path promotion"
            );
            let ping = ping_from_namespace(a, "hse2ea", overlay_b);
            assert!(
                ping.status.success()
                    && recovery_soak::complete_ping(&String::from_utf8_lossy(&ping.stdout)),
                "failed preferred validation disrupted fallback service"
            );
            let mut command = vec!["-D"];
            command.extend(drop_rule);
            ns_command(a, "iptables", &command);
            // No route event or manual reconnect follows removal of the block.
            // Only the outstanding intent's normal retry can promote this path.
        }
        let lines = wait_for_daemon_state(temp, "b", Duration::from_secs(60), stage, |lines| {
            live_endpoint_opt(lines).is_some_and(|endpoint| endpoint.ip().to_string() == source)
        });
        let current = live_endpoint(&lines);
        assert_ne!(old_source, current, "new source-owned connection required");
        fs::write(temp.join(format!("{stage}-b.txt")), lines.join("\n")).unwrap();
        assert_eq!(
            live_endpoint(&state(temp, "a")),
            destination,
            "peer endpoint must stay unchanged"
        );
        let lines = wait_for_daemon_state(temp, "a", Duration::from_secs(5), stage, |lines| {
            state_metric_count(lines, "outbound_owned_quic_datagram_packets")
                .is_some_and(|count| count > 0)
        });
        let before = state_metric_count(&lines, "outbound_owned_quic_datagram_packets").unwrap();
        let ping = ping_from_namespace(a, "hse2ea", overlay_b);
        assert!(
            ping.status.success()
                && recovery_soak::complete_ping(&String::from_utf8_lossy(&ping.stdout))
        );
        wait_for_daemon_state(
            temp,
            "a",
            Duration::from_secs(5),
            "payload on promoted QUIC",
            |lines| {
                state_metric_count(lines, "outbound_owned_quic_datagram_packets")
                    .is_some_and(|count| count >= before + 5)
            },
        );
        // Account for both application receive drain and Quinn protocol drain.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let sockets = ns_command_output(a, "ss", &["-u", "-a", "-n", "-H"]);
            assert!(sockets.status.success());
            let output = String::from_utf8_lossy(&sockets.stdout);
            if !output
                .lines()
                .any(|line| line.split_whitespace().nth(3) == Some(old_source.to_string().as_str()))
            {
                fs::write(temp.join(format!("{stage}-sockets.txt")), &sockets.stdout).unwrap();
                break;
            }
            assert!(
                Instant::now() < deadline,
                "old QUIC socket {old_source} retained after {stage}: {output}"
            );
            thread::sleep(Duration::from_millis(100));
        }
        old_source = current;
    }
    assert!(
        read_log(&temp.join("node-a.log"))
            .contains("event=packet_plane_quic_route_replacement_requested")
    );
}

fn state(temp: &Path, role: &str) -> Vec<String> {
    wait_for_daemon_state(
        temp,
        role,
        Duration::from_secs(5),
        "route failback state",
        |_| true,
    )
}

fn live_endpoint(lines: &[String]) -> SocketAddr {
    live_endpoint_opt(lines).expect("live QUIC endpoint")
}

fn live_endpoint_opt(lines: &[String]) -> Option<SocketAddr> {
    lines.iter().find_map(|line| {
        line.strip_prefix("packet_plane_quic_connection ")?
            .split_once(" endpoint ")?
            .1
            .parse()
            .ok()
    })
}
