//! Fixed-endpoint IPv4 TX handoff, not Android Network/default-source migration proof.
//! Replies may legitimately arrive on the old link; only the moving host's old
//! outbound raw-UDP tuple must become quiet. IPv4 keeps its shared base socket.
//! This is not full P6 RX/FD retirement evidence or IPv6 scope/device CLAT proof.

use super::*;
use std::net::SocketAddr;

pub(super) const TEST_NAME: &str = "tun_namespace_udp_follows_route_preference_and_returns";
pub(super) const RESPONDER_TEST_NAME: &str =
    "tun_namespace_udp_responder_follows_route_preference_and_returns";
const CHAIN: &str = "p2p-udp-out";
const A: &str = "10.250.0.1:43101";
const B: &str = "10.250.0.2:43102";
const QUIET_WINDOW: Duration = Duration::from_secs(6);
const FALLBACK_METRICS: &[&str] = &[
    "outbound_owned_quic_datagram_packets",
    "outbound_direct_tcp_stream_fallback_packets",
    "outbound_direct_quic_stream_fallback_packets",
    "outbound_relay_stream_fallback_packets",
];

pub(super) fn is_test(name: &str) -> bool {
    matches!(name, TEST_NAME | RESPONDER_TEST_NAME)
}

pub(super) fn identities(test: &str) -> (NodeIdentity, NodeIdentity) {
    quic_route_failback::identities(if test == RESPONDER_TEST_NAME {
        quic_route_failback::ACCEPTOR_TEST_NAME
    } else {
        quic_route_failback::TEST_NAME
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Session {
    endpoint: SocketAddr,
    local: u32,
    remote: u32,
    role: String,
}

type Sessions = [Session; 2];

#[derive(Debug, Default)]
struct Counters {
    primary: u64,
    alternate: u64,
    dropped: u64,
    unexpected: u64,
}

impl Counters {
    fn sent_on(&self, interface: &str) -> u64 {
        match interface {
            "veth-a" => self.primary,
            "alt-a" => self.alternate,
            other => panic!("unknown UDP underlay {other}"),
        }
    }
}

pub(super) fn capture(temp: &Path, a: u32, b: u32, overlay_b: Ipv4Addr, test: &str) {
    install_counters(a);
    let initial = settle_initial(temp, a, overlay_b);
    assert_eq!(
        initial[0].role,
        if test == RESPONDER_TEST_NAME {
            "responder"
        } else {
            "initiator"
        }
    );
    assert_fixed_pair(&initial);
    assert_route(temp, a, "10.250.0.2", "10.250.0.1", "veth-a", "initial-a");
    assert_payload(
        temp,
        a,
        overlay_b,
        Some(&initial),
        Some("veth-a"),
        "initial",
    );

    for (stage, operation, old_interface, new_interface) in [
        ("away", "del", "veth-a", "alt-a"),
        ("return", "add", "alt-a", "veth-a"),
    ] {
        wait_for_validation_settled(temp);
        let old = sessions(temp);
        let offsets = [
            read_log(&temp.join("node-a.log")).len(),
            read_log(&temp.join("node-b.log")).len(),
        ];
        ns_command(
            a,
            "iptables",
            &["-I", CHAIN, "1", "-o", new_interface, "-j", "DROP"],
        );
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
        assert_route(
            temp,
            a,
            "10.250.0.2",
            "10.250.0.1",
            new_interface,
            &format!("{stage}-a"),
        );
        // B's destination-specific route remains valid. Do not force its replies
        // onto A's new interface merely to make both directions look symmetric.
        assert_route(
            temp,
            b,
            "10.250.0.1",
            "10.250.0.2",
            "veth-b",
            &format!("{stage}-b"),
        );

        let deadline = Instant::now() + scaled_wait_timeout(Duration::from_secs(60));
        loop {
            assert_payload(
                temp,
                a,
                overlay_b,
                Some(&old),
                Some(old_interface),
                &format!("{stage}-blocked"),
            );
            for (role, offset) in ["a", "b"].into_iter().zip(offsets) {
                assert_eq!(
                    event_count(temp, role, offset, "packet_plane_udp_replacement_promoted"),
                    0,
                    "{stage}: blocked candidate replaced the working payload path"
                );
            }
            let staged = event_count(temp, "a", offsets[0], "packet_plane_udp_replacement_staged");
            let expired = event_count(temp, "a", offsets[0], "packet_plane_udp_validation_expired");
            if staged > 0
                && expired > 0
                && counters(temp, a, &format!("{stage}-blocked")).dropped > 0
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{stage}: blocked preferred candidate never attempted and timed out\n{}",
                log_tail(&read_log(&temp.join("node-a.log")), 80)
            );
        }
        assert_eq!(sessions(temp), old);
        let blocked = counters(temp, a, &format!("{stage}-timed-out"));
        assert!(
            blocked.dropped > 0,
            "{stage}: preferred UDP never reached the block"
        );
        ns_command(
            a,
            "iptables",
            &["-D", CHAIN, "-o", new_interface, "-j", "DROP"],
        );
        // Removing a packet filter emits no netlink route change. Production
        // retry, not another route event, a reset or a fixture Hello, must win.
        let promoted = wait_for_promoted(temp, a, overlay_b, &old, stage);
        assert!(
            event_count(temp, "a", offsets[0], "packet_plane_udp_replacement_staged") >= 2,
            "{stage}: promotion must follow a fresh attempt after candidate timeout"
        );
        for (role, offset) in ["a", "b"].into_iter().zip(offsets) {
            assert!(
                event_count(temp, role, offset, "packet_plane_udp_replacement_promoted") > 0,
                "{stage}: both directions need authenticated candidate promotion"
            );
        }
        wait_for_validation_settled(temp);
        let before = counters(temp, a, &format!("{stage}-tx-settled"));
        let probes_before =
            state_metric_count(&state(temp, "a"), "outbound_path_probes_sent").unwrap();
        let quiet_until = Instant::now() + QUIET_WINDOW;
        loop {
            assert_payload(
                temp,
                a,
                overlay_b,
                Some(&promoted),
                Some(new_interface),
                &format!("{stage}-promoted"),
            );
            let after = counters(temp, a, &format!("{stage}-quiet"));
            assert_eq!(
                after.sent_on(old_interface),
                before.sent_on(old_interface),
                "{stage}: moving host sent raw UDP on the old interface after TX validation settled"
            );
            if Instant::now() >= quiet_until {
                break;
            }
        }
        assert!(
            state_metric_count(&state(temp, "a"), "outbound_path_probes_sent")
                .is_some_and(|count| count > probes_before),
            "{stage}: quietness must include normal probes, not just payload"
        );
        let sockets = ns_command_output(a, "ss", &["-u", "-a", "-n", "-H"]);
        assert_output_success("shared UDP listener after handoff", &sockets);
        assert!(
            String::from_utf8_lossy(&sockets.stdout)
                .lines()
                .any(|line| line.split_whitespace().nth(3) == Some(A)),
            "{stage}: retirement closed the fixed shared UDP listener"
        );
        fs::write(
            temp.join(format!("udp-{stage}-sockets.txt")),
            &sockets.stdout,
        )
        .unwrap();
    }
    assert!(event_count(temp, "a", 0, "packet_plane_udp_route_replacement_requested") >= 2);
    for role in ["a", "b"] {
        assert_eq!(
            event_count(temp, role, 0, "runtime_network_changed"),
            0,
            "pure netlink handoff must not invoke the destructive global reset"
        );
    }
}

fn session(lines: &[String]) -> Session {
    let records = lines
        .iter()
        .filter_map(|line| line.strip_prefix("packet_plane_session "))
        .collect::<Vec<_>>();
    assert_eq!(
        records.len(),
        1,
        "fixture requires exactly one raw UDP peer"
    );
    let fields = records[0].split_whitespace().collect::<Vec<_>>();
    let field = |name: &str| fields.windows(2).find(|pair| pair[0] == name).unwrap()[1];
    Session {
        endpoint: field("endpoint").parse().unwrap(),
        local: field("local_session").parse().unwrap(),
        remote: field("remote_session").parse().unwrap(),
        role: field("role").to_owned(),
    }
}

fn state(temp: &Path, role: &str) -> Vec<String> {
    wait_for_daemon_state(
        temp,
        role,
        scaled_wait_timeout(Duration::from_secs(5)),
        "UDP failback state",
        |_| true,
    )
}

fn sessions(temp: &Path) -> Sessions {
    [session(&state(temp, "a")), session(&state(temp, "b"))]
}

fn assert_fixed_pair(pair: &Sessions) {
    assert_eq!(pair[0].endpoint, B.parse::<SocketAddr>().unwrap());
    assert_eq!(pair[1].endpoint, A.parse::<SocketAddr>().unwrap());
    assert_eq!(pair[0].local, pair[1].remote);
    assert_eq!(pair[0].remote, pair[1].local);
}

fn settle_initial(temp: &Path, a: u32, overlay_b: Ipv4Addr) -> Sessions {
    let deadline = Instant::now() + scaled_wait_timeout(Duration::from_secs(60));
    loop {
        let before = sessions(temp);
        // Startup can queue another Hello before the first probe ACK. Permit
        // those keys to settle here, never inside the blocked-route assertions.
        assert_payload(temp, a, overlay_b, None, Some("veth-a"), "startup");
        let states = [state(temp, "a"), state(temp, "b")];
        let current = [session(&states[0]), session(&states[1])];
        let ready = ["a", "b"].into_iter().enumerate().all(|(index, role)| {
            validation_settled(&states[index])
                && startup_confirmed(&read_log(&temp.join(format!("node-{role}.log"))))
        });
        if current == before && ready {
            assert_fixed_pair(&current);
            for (role, lines) in ["a", "b"].into_iter().zip(&states) {
                fs::write(
                    temp.join(format!("udp-startup-{role}-settled.txt")),
                    lines.join("\n"),
                )
                .unwrap();
            }
            return current;
        }
        assert!(
            Instant::now() < deadline,
            "initial UDP sessions never settled after confirmed probes\n{}",
            log_tail(&read_log(&temp.join("node-a.log")), 80)
        );
    }
}

fn startup_confirmed(log: &str) -> bool {
    let (mut hello, mut completed, mut installed) = (None, None, false);
    let (mut staged, mut promoted, mut transition, mut confirmed) = (None, None, None, None);
    for (index, line) in log.lines().enumerate() {
        let event = line
            .split_whitespace()
            .find_map(|field| field.strip_prefix("event="));
        match event {
            Some("packet_plane_hello_sent") => hello = Some(index),
            Some("packet_plane_session_established") => {
                completed = Some(index);
                installed = true;
            }
            Some("packet_plane_pending_hello_expired") => completed = Some(index),
            Some("packet_plane_udp_replacement_staged") => staged = Some(index),
            Some("packet_plane_udp_replacement_promoted") => promoted = Some(index),
            Some("packet_plane_udp_handoff_retired") => {}
            Some("path_probe_rtt_confirmed")
                if line
                    .split_whitespace()
                    .any(|field| field == "path=direct_udp_datagram") =>
            {
                confirmed = Some(index);
                continue;
            }
            _ => continue,
        }
        transition = Some(index);
    }
    installed
        && hello.is_none_or(|hello| completed.is_some_and(|completed| completed > hello))
        && staged.is_none_or(|staged| promoted.is_some_and(|promoted| promoted > staged))
        && confirmed
            .zip(transition)
            .is_some_and(|(confirmed, transition)| confirmed > transition)
}

fn wait_for_promoted(
    temp: &Path,
    a: u32,
    overlay_b: Ipv4Addr,
    old: &Sessions,
    stage: &str,
) -> Sessions {
    let deadline = Instant::now() + scaled_wait_timeout(Duration::from_secs(60));
    let promoted = loop {
        // Keep application demand alive, allowing either exact owner during the
        // transition but never substituting another payload transport.
        assert_payload(
            temp,
            a,
            overlay_b,
            None,
            None,
            &format!("{stage}-unblocked"),
        );
        let current = sessions(temp);
        if current
            .iter()
            .zip(old)
            .all(|(new, old)| new.local != old.local && new.remote != old.remote)
        {
            break current;
        }
        assert!(
            Instant::now() < deadline,
            "{stage}: normal retry never promoted after unblock\n{}",
            log_tail(&read_log(&temp.join("node-a.log")), 80)
        );
    };
    assert_fixed_pair(&promoted);
    for (role, current) in ["a", "b"].into_iter().zip(&promoted) {
        fs::write(
            temp.join(format!("udp-{stage}-{role}-promoted.txt")),
            format!("{current:?}\n"),
        )
        .unwrap();
    }
    promoted
}

fn validation_settled(lines: &[String]) -> bool {
    state_metric_count(lines, "packet_plane_udp_validation_pending") == Some(0)
        && state_metric_count(lines, "healthy_direct_udp_datagram_paths") == Some(1)
        && state_metric_count(lines, "packet_plane_udp_receive_only_sessions")
            .is_some_and(|count| count <= 64)
}

fn wait_for_validation_settled(temp: &Path) {
    for role in ["a", "b"] {
        wait_for_daemon_state(
            temp,
            role,
            scaled_wait_timeout(Duration::from_secs(15)),
            // RX keys may still be required by the other direction. This
            // fixture proves TX quietness, not premature RX-key destruction.
            "UDP TX validation settled with bounded RX retention",
            validation_settled,
        );
    }
}

fn assert_payload(
    temp: &Path,
    a: u32,
    overlay_b: Ipv4Addr,
    expected: Option<&Sessions>,
    interface: Option<&str>,
    stage: &str,
) {
    if let Some(expected) = expected {
        assert_eq!(
            &sessions(temp),
            expected,
            "{stage}: active ownership changed"
        );
    }
    let before_states = [state(temp, "a"), state(temp, "b")];
    let before = counters(temp, a, &format!("{stage}-before"));
    let ping = ping_from_namespace(a, "hse2ea", overlay_b);
    fs::write(temp.join(format!("udp-{stage}-ping.txt")), &ping.stdout).unwrap();
    assert!(
        ping.status.success()
            && recovery_soak::complete_ping(&String::from_utf8_lossy(&ping.stdout)),
        "{stage}: working raw UDP payload was interrupted: {ping:?}"
    );
    for (index, role) in ["a", "b"].into_iter().enumerate() {
        let baseline =
            state_metric_count(&before_states[index], "outbound_owned_udp_datagram_packets")
                .unwrap();
        let after = wait_for_daemon_state(
            temp,
            role,
            scaled_wait_timeout(Duration::from_secs(5)),
            "raw UDP payload without stream fallback",
            |lines| {
                state_metric_count(lines, "outbound_owned_udp_datagram_packets")
                    .is_some_and(|count| count >= baseline + 5)
            },
        );
        if let Some(expected) = expected {
            assert_eq!(
                session(&after),
                expected[index],
                "{stage}: payload changed active keys"
            );
        }
        for metric in FALLBACK_METRICS {
            let baseline = state_metric_count(&before_states[index], metric)
                .unwrap_or_else(|| panic!("missing fallback metric {metric}"));
            assert_eq!(
                state_metric_count(&after, metric),
                Some(baseline),
                "{stage}: {role} used {metric}"
            );
        }
        fs::write(
            temp.join(format!("udp-{stage}-{role}-state.txt")),
            after.join("\n"),
        )
        .unwrap();
    }
    let after = counters(temp, a, &format!("{stage}-after"));
    if let Some(interface) = interface {
        assert!(
            after.sent_on(interface) >= before.sent_on(interface) + 5,
            "{stage}: payload did not use selected send interface {interface}: {before:?} -> {after:?}"
        );
    }
}

fn event_count(temp: &Path, role: &str, offset: usize, event: &str) -> usize {
    read_log(&temp.join(format!("node-{role}.log")))[offset..]
        .lines()
        .filter(|line| {
            line.split_whitespace()
                .any(|field| field.strip_prefix("event=") == Some(event))
        })
        .count()
}

fn assert_route(
    temp: &Path,
    pid: u32,
    destination: &str,
    source: &str,
    interface: &str,
    stage: &str,
) {
    let route = ns_command_output(
        pid,
        "ip",
        &["-j", "route", "get", destination, "from", source],
    );
    assert_output_success("fixed-source UDP route", &route);
    let routes: serde_json::Value = serde_json::from_slice(&route.stdout).unwrap();
    assert_eq!(
        routes[0]["dev"], interface,
        "{stage}: kernel did not select requested underlay"
    );
    fs::write(temp.join(format!("udp-{stage}-route.json")), &route.stdout).unwrap();
}

fn install_counters(a: u32) {
    ns_command(a, "iptables", &["-N", CHAIN]);
    for interface in ["veth-a", "alt-a"] {
        ns_command(
            a,
            "iptables",
            &["-A", CHAIN, "-o", interface, "-j", "RETURN"],
        );
    }
    ns_command(a, "iptables", &["-A", CHAIN, "-j", "RETURN"]);
    ns_command(
        a,
        "iptables",
        &[
            "-I",
            "OUTPUT",
            "1",
            "-p",
            "udp",
            "-d",
            "10.250.0.2",
            "--sport",
            "43101",
            "--dport",
            "43102",
            "-j",
            CHAIN,
        ],
    );
}

fn counters(temp: &Path, a: u32, stage: &str) -> Counters {
    let output = ns_command_output(a, "iptables", &["-L", CHAIN, "-v", "-n", "-x"]);
    assert_output_success("raw UDP interface counters", &output);
    let text = String::from_utf8_lossy(&output.stdout);
    let mut result = Counters::default();
    let mut returns = 0;
    for line in text.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let Some(count) = fields.first().and_then(|field| field.parse::<u64>().ok()) else {
            continue;
        };
        assert!(fields.len() >= 9, "invalid iptables counter row: {line}");
        match (fields[2], fields[6]) {
            ("RETURN", "veth-a") => {
                result.primary = count;
                returns += 1;
            }
            ("RETURN", "alt-a") => {
                result.alternate = count;
                returns += 1;
            }
            ("RETURN", "*") => {
                result.unexpected = count;
                returns += 1;
            }
            ("DROP", _) => result.dropped += count,
            _ => panic!("unexpected raw UDP counter rule: {line}"),
        }
    }
    assert_eq!(returns, 3, "missing interface counter rules: {text}");
    assert_eq!(
        result.unexpected, 0,
        "raw UDP escaped both physical interfaces"
    );
    fs::write(
        temp.join(format!("udp-{stage}-counters.txt")),
        &output.stdout,
    )
    .unwrap();
    result
}

#[test]
fn tx_settle_gate_distinguishes_bounded_receive_state_from_pending_validation() {
    let lines = |pending, receiving| {
        vec![
            format!("packet_plane_udp_validation_pending {pending}"),
            format!("packet_plane_udp_receive_only_sessions {receiving}"),
            "healthy_direct_udp_datagram_paths 1".to_owned(),
        ]
    };
    assert!(validation_settled(&lines(0, 3)));
    assert!(!validation_settled(&lines(1, 3)));
    assert!(!validation_settled(&lines(0, 65)));
    assert!(!validation_settled(&[]));
}

#[test]
fn startup_gate_requires_fresh_confirmation_after_pending_hello_promotion_and_drain() {
    let initial = "event=packet_plane_hello_sent\nevent=packet_plane_session_established\nevent=path_probe_rtt_confirmed path=direct_udp_datagram\n";
    assert!(startup_confirmed(initial));
    let pending = format!(
        "{initial}event=packet_plane_hello_sent\nevent=path_probe_rtt_confirmed path=direct_udp_datagram\n"
    );
    assert!(
        !startup_confirmed(&pending),
        "the old ACK cannot complete the queued Hello"
    );
    let staged = format!(
        "{pending}event=packet_plane_udp_replacement_staged\nevent=packet_plane_session_established\nevent=path_probe_rtt_confirmed path=direct_udp_datagram\n"
    );
    assert!(
        !startup_confirmed(&staged),
        "a staged candidate has not promoted"
    );
    let draining = format!(
        "{staged}event=packet_plane_udp_replacement_promoted\nevent=path_probe_rtt_confirmed path=direct_udp_datagram\nevent=packet_plane_udp_handoff_retired\n"
    );
    assert!(
        !startup_confirmed(&draining),
        "require confirmation after the final transition"
    );
    assert!(!startup_confirmed(&format!(
        "{draining}event=path_probe_rtt_confirmed path=direct_tcp_stream\n"
    )));
    assert!(startup_confirmed(&format!(
        "{draining}event=path_probe_rtt_confirmed path=direct_udp_datagram\n"
    )));
}
