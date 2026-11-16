use super::*;
use std::net::IpAddr;

#[derive(Debug)]
struct Owner {
    inner: String,
    relay: String,
    outer: String,
    source: SocketAddr,
    interface: u32,
    generation: u64,
}

pub(super) fn capture(temp: &Path, a: u32, b: u32, overlay_b: Ipv4Addr, test: &str) {
    let (node, role, primary, original_source) = target(a, b, test);
    let initial = state(temp, role, "initial native QUIC circuit");
    let (peer, inner, direction) = selected_relay(&initial).expect("initial circuit binding");
    assert_eq!(
        direction,
        if acceptor(test) { "listener" } else { "dialer" }
    );
    let peer = peer.to_owned();
    let mut old = owner(temp, role, &peer, inner);
    assert_eq!(old.source.ip(), original_source.parse::<IpAddr>().unwrap());
    assert_eq!(old.interface, interface_index(node, primary));
    // The other endpoint's authenticated transport identity is this node's peer ID.
    let other_role = if role == "a" { "b" } else { "a" };
    let other = state(temp, other_role, "opposite circuit endpoint");
    let local_peer = selected_relay(&other).unwrap().0.to_owned();
    receiver_owner(temp, &local_peer, old.source, 0);
    fs::write(
        temp.join(format!("initial-native-quic-{role}-state.txt")),
        initial.join("\n"),
    )
    .unwrap();
    assert_payload(temp, a, overlay_b, "native-quic-initial-active-circuit");

    let alternate_source = if ipv6(test) {
        "fd00:210::1"
    } else {
        "169.254.210.1"
    };
    for (index, (stage, operation, source, preferred, old_interface)) in [
        (
            "native-quic-relay-away",
            "del",
            alternate_source,
            "alt-node",
            primary,
        ),
        (
            "native-quic-relay-return",
            "add",
            original_source,
            primary,
            "alt-node",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        assert_selected(temp, role, &peer, &old.inner, stage);
        let start = read_log(&temp.join(format!("node-{role}.log"))).len();
        let receiver_start = read_log(&temp.join("node-relay.log")).len();
        let mut traffic = Traffic::install(node, test, index, old.source, old_interface, preferred);
        primary_route(node, primary, original_source, test, operation);
        blocked_retry(
            temp, a, overlay_b, role, &peer, &old, start, stage, &traffic,
        );
        // No route change accompanies removal of the firewall rule. Recovery must retry.
        traffic.unblock();
        let admitted = wait_event_with_payload(
            temp,
            a,
            overlay_b,
            role,
            start,
            "control_relay_handoff_admitted",
            |line| {
                field(line, "peer") == Some(peer.as_str())
                    && field(line, "old_circuit") == Some(old.inner.as_str())
            },
        );
        assert_eq!(field(&admitted, "relay"), Some(old.relay.as_str()));
        assert_eq!(field(&admitted, "old_outer"), Some(old.outer.as_str()));
        let new_outer = field(&admitted, "replacement_outer").expect("exact admitted outer");
        assert_ne!(new_outer, old.outer);
        let promoted = wait_event_with_payload(
            temp,
            a,
            overlay_b,
            role,
            start,
            "control_relay_replacement_promoted",
            |line| field(line, "peer") == Some(peer.as_str()),
        );
        let new_inner = field(&promoted, "connection_id").expect("promoted inner CID");
        assert_ne!(new_inner, old.inner);
        let generation = field(&promoted, "generation").expect("promotion audit generation");
        let log = read_log(&temp.join(format!("node-{role}.log")));
        for event in [
            "control_relay_replacement_dialing",
            "control_relay_replacement_validating",
        ] {
            assert!(
                events(&log, start, event).any(|line| {
                    field(line, "peer") == Some(peer.as_str())
                        && field(line, "connection_id") == Some(new_inner)
                        && field(line, "generation") == Some(generation)
                }),
                "missing exact {event} for {new_inner}, generation {generation}\n{}",
                log_tail(&log, 120)
            );
        }
        let new = owner(temp, role, &peer, new_inner);
        assert_eq!(new.relay, old.relay);
        assert_eq!(new.outer, new_outer);
        assert_eq!(new.source.ip(), source.parse::<IpAddr>().unwrap());
        assert_eq!(new.interface, interface_index(node, preferred));
        assert_ne!(
            new.source, old.source,
            "fixture requires distinct measurable outer tuples"
        );
        let physical_promotion = wait_event(
            temp,
            role,
            start,
            "infrastructure_quic_replacement_promoted",
            |line| {
                field(line, "peer") == Some(new.relay.as_str())
                    && field(line, "connection_id") == Some(new.outer.as_str())
            },
        );
        assert!(field(&physical_promotion, "generation").is_some());
        receiver_owner(temp, &local_peer, new.source, receiver_start);
        let selected = wait_for_daemon_state(
            temp,
            role,
            scaled_wait_timeout(Duration::from_secs(20)),
            stage,
            |lines| selected_relay(lines).is_some_and(|(p, id, _)| p == peer && id == new.inner),
        );
        fs::write(
            temp.join(format!("{stage}-{role}-state.txt")),
            selected.join("\n"),
        )
        .unwrap();
        assert_payload(temp, a, overlay_b, &format!("{stage}-promoted"));

        wait_event_with_payload(
            temp,
            a,
            overlay_b,
            role,
            start,
            "control_relay_fallback_retired",
            |line| {
                field(line, "peer") == Some(peer.as_str())
                    && field(line, "connection_id") == Some(old.inner.as_str())
                    && field(line, "reason") == Some("transport_closed")
                    && field(line, "generation") == Some(generation)
            },
        );
        wait_event_with_payload(
            temp,
            a,
            overlay_b,
            role,
            start,
            "connection_closed",
            |line| {
                field(line, "peer") == Some(old.relay.as_str())
                    && field(line, "connection_id") == Some(old.outer.as_str())
                    && field(line, "relayed") == Some("false")
            },
        );
        retired_socket(temp, node, role, old.source, stage);
        quiet_after_drain(temp, a, overlay_b, role, &peer, &new, stage, &traffic);
        fs::write(temp.join(format!("{stage}-owners.txt")), format!(
            "old={old:?}\nnew={new:?}\npreferred_audit_generation={generation}\nphysical_promotion={physical_promotion}old_lease_generation={}\nnew_lease_generation={}\n",
            old.generation, new.generation,
        )).unwrap();
        traffic.remove();
        old = new;
    }
}

fn events<'a>(log: &'a str, start: usize, event: &'a str) -> impl Iterator<Item = &'a str> {
    log.get(start..)
        .unwrap_or_default()
        .split_inclusive('\n')
        .filter(move |line| line.ends_with('\n') && field(line, "event") == Some(event))
}

fn wait_event_with_payload(
    temp: &Path,
    a: u32,
    overlay_b: Ipv4Addr,
    role: &str,
    start: usize,
    event: &str,
    predicate: impl Fn(&str) -> bool,
) -> String {
    let deadline = Instant::now() + scaled_wait_timeout(Duration::from_secs(60));
    let mut sample = 0;
    loop {
        let log = read_log(&temp.join(format!("node-{role}.log")));
        if let Some(line) = events(&log, start, event).find(|line| predicate(line)) {
            return line.to_owned();
        }
        assert!(
            Instant::now() < deadline,
            "missing {event}\n{}",
            log_tail(&log, 120)
        );
        assert_payload(
            temp,
            a,
            overlay_b,
            &format!("{event}-{start}-pending-{sample}"),
        );
        sample += 1;
    }
}

fn owner(temp: &Path, role: &str, peer: &str, inner: &str) -> Owner {
    let binding = wait_event(temp, role, 0, "control_relay_circuit_owned", |line| {
        field(line, "peer") == Some(peer) && field(line, "connection_id") == Some(inner)
    });
    assert_eq!(field(&binding, "physical_transport"), Some("quic"));
    let relay = field(&binding, "relay").expect("relay peer").to_owned();
    let outer = field(&binding, "outer").expect("physical CID").to_owned();
    let physical = wait_event(temp, role, 0, "control_quic_route_owned", |line| {
        field(line, "peer") == Some(relay.as_str())
            && field(line, "connection_id") == Some(outer.as_str())
    });
    let source = socket_field(&physical, "source").expect("physical source socket");
    let interface = field(&physical, "interface")
        .unwrap()
        .parse::<u32>()
        .unwrap();
    let generation = field(&physical, "generation")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert_eq!(
        socket_field(&binding, "source").expect("circuit source socket"),
        source
    );
    assert_eq!(
        field(&binding, "interface")
            .unwrap()
            .parse::<u32>()
            .unwrap(),
        interface
    );
    assert_eq!(
        field(&binding, "generation")
            .unwrap()
            .parse::<u64>()
            .unwrap(),
        generation
    );
    Owner {
        inner: inner.to_owned(),
        relay,
        outer,
        source,
        interface,
        generation,
    }
}

fn socket_field(line: &str, key: &str) -> Option<SocketAddr> {
    let value = field(line, key)?;
    if value.starts_with('"') {
        serde_json::from_str(value).ok()
    } else {
        value.parse().ok()
    }
}

fn remote_tuple(address: &str) -> Option<SocketAddr> {
    let address: Multiaddr = address.parse().ok()?;
    let mut protocols = address.iter();
    let ip = match protocols.next()? {
        Protocol::Ip4(ip) => IpAddr::V4(ip),
        Protocol::Ip6(ip) => IpAddr::V6(ip),
        _ => return None,
    };
    let Protocol::Udp(port) = protocols.next()? else {
        return None;
    };
    if protocols.next()? != Protocol::QuicV1 {
        return None;
    }
    match protocols.next() {
        None => {}
        Some(Protocol::P2p(_)) if protocols.next().is_none() => {}
        _ => return None,
    }
    Some(SocketAddr::new(ip, port))
}

fn receiver_owner(temp: &Path, local_peer: &str, source: SocketAddr, start: usize) {
    let observed = wait_event(
        temp,
        "relay",
        start,
        "relay_fixture_connection_observed",
        |line| {
            field(line, "peer") == Some(local_peer)
                && field(line, "remote").and_then(remote_tuple) == Some(source)
                && field(line, "role") == Some("listener")
        },
    );
    // The receiver CID is local to the relay. It must not equal the client's CID by assumption.
    assert!(field(&observed, "connection_id").is_some());
    fs::write(
        temp.join(format!("receiver-{}-{}.txt", source.ip(), source.port())),
        observed,
    )
    .unwrap();
}

fn interface_index(node: u32, interface: &str) -> u32 {
    let output = ns_command_output(node, "ip", &["-j", "link", "show", "dev", interface]);
    assert!(output.status.success());
    let links: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    u32::try_from(links[0]["ifindex"].as_u64().unwrap()).unwrap()
}

fn assert_selected(temp: &Path, role: &str, peer: &str, inner: &str, stage: &str) {
    let current = state(temp, role, stage);
    assert!(
        selected_relay(&current).is_some_and(|(p, id, _)| p == peer && id == inner),
        "selected active circuit changed during {stage}: {current:?}"
    );
}

fn with_failure_diagnostics(action: impl FnOnce(), diagnostics: impl FnOnce()) {
    if let Err(original) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(diagnostics));
        std::panic::resume_unwind(original);
    }
}

fn diagnostic_command(node: u32, program: &str, args: &[&str]) -> String {
    let output = std::panic::catch_unwind(|| ns_command_output(node, program, args));
    let command = format!("namespace={node} command={program} {args:?}\n");
    match output {
        Ok(output) => format!(
            "{command}status={}\nstdout:\n{}\nstderr:\n{}\n",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ),
        Err(_) => format!("{command}command capture panicked\n"),
    }
}

fn assert_payload_with_counter_diag(
    temp: &Path,
    a: u32,
    overlay_b: Ipv4Addr,
    stage: &str,
    traffic: &Traffic,
    old: &Owner,
) {
    let before = traffic.diagnostic_snapshot();
    with_failure_diagnostics(
        || assert_payload(temp, a, overlay_b, stage),
        || {
            let after = traffic.diagnostic_snapshot();
            let counters =
                format!("old={old:?}\nbefore payload:\n{before}\nafter failure:\n{after}");
            if let Err(error) =
                fs::write(temp.join(format!("{stage}-failure-counters.txt")), counters)
            {
                eprintln!("failed to write {stage} counter diagnostics: {error}");
            }
            let mut network = String::new();
            for (family, destination) in [("-4", "10.251.0.254"), ("-6", "2001:db8:251::fe")] {
                for args in [
                    vec![family, "addr", "show"],
                    vec![family, "route", "show", "table", "all"],
                    vec![family, "rule", "show"],
                    vec![family, "route", "get", destination],
                    vec![
                        family,
                        "route",
                        "get",
                        destination,
                        "oif",
                        &traffic.old_interface,
                    ],
                ] {
                    network.push_str(&diagnostic_command(traffic.node, "ip", &args));
                }
                if old.source.is_ipv6() == (family == "-6") {
                    let source = old.source.ip().to_string();
                    network.push_str(&diagnostic_command(
                        traffic.node,
                        "ip",
                        &[family, "route", "get", destination, "from", &source],
                    ));
                    network.push_str(&diagnostic_command(
                        traffic.node,
                        "ip",
                        &[
                            family,
                            "route",
                            "get",
                            destination,
                            "from",
                            &source,
                            "oif",
                            &traffic.old_interface,
                        ],
                    ));
                }
            }
            network.push_str(&diagnostic_command(traffic.node, "ss", &["-uanie"]));
            if let Err(error) =
                fs::write(temp.join(format!("{stage}-failure-network.txt")), network)
            {
                eprintln!("failed to write {stage} network diagnostics: {error}");
            }
        },
    );
}

#[allow(clippy::too_many_arguments)]
fn blocked_retry(
    temp: &Path,
    a: u32,
    overlay_b: Ipv4Addr,
    role: &str,
    peer: &str,
    old: &Owner,
    start: usize,
    stage: &str,
    traffic: &Traffic,
) {
    let deadline = Instant::now() + scaled_wait_timeout(Duration::from_secs(80));
    let mut sample = 0;
    loop {
        assert_selected(temp, role, peer, &old.inner, stage);
        assert_payload_with_counter_diag(
            temp,
            a,
            overlay_b,
            &format!("{stage}-blocked-{sample}"),
            traffic,
            old,
        );
        assert_selected(temp, role, peer, &old.inner, stage);
        let log = read_log(&temp.join(format!("node-{role}.log")));
        assert!(
            !events(&log, start, "control_relay_replacement_promoted")
                .any(|line| field(line, "peer") == Some(peer)),
            "circuit promoted while preferred UDP was blocked\n{}",
            log_tail(&log, 100)
        );
        assert!(
            !events(&log, start, "connection_closed").any(|line| {
                (field(line, "peer") == Some(peer)
                    && field(line, "connection_id") == Some(old.inner.as_str()))
                    || (field(line, "peer") == Some(old.relay.as_str())
                        && field(line, "connection_id") == Some(old.outer.as_str()))
            }),
            "working fallback closed before preferred validation\n{}",
            log_tail(&log, 100)
        );
        let attempts = events(&log, start, "infrastructure_quic_replacement_dialing")
            .filter(|line| field(line, "peer") == Some(old.relay.as_str()))
            .filter_map(|line| field(line, "connection_id"))
            .collect::<std::collections::HashSet<_>>();
        let counters = traffic.counters();
        assert_eq!(
            counters.wrong_interface, 0,
            "old tuple leaked onto the new interface"
        );
        if attempts.len() >= 2 && counters.blocked > 0 && counters.old > 0 && counters.received > 0
        {
            fs::write(
                temp.join(format!("{stage}-blocked-retry.txt")),
                format!(
                    "replacement_attempts={attempts:?}\ncounters={counters:?}\n{}",
                    traffic.snapshot(),
                ),
            )
            .unwrap();
            return;
        }
        assert!(
            Instant::now() < deadline,
            "no bounded preferred retry with working old circuit during {stage}\n{}\n{}",
            traffic.snapshot(),
            log_tail(&log, 120)
        );
        sample += 1;
    }
}

fn retired_socket(temp: &Path, node: u32, role: &str, old: SocketAddr, stage: &str) {
    let shared_listener = old.port() == if role == "a" { 42201 } else { 42202 };
    let deadline = Instant::now() + scaled_wait_timeout(Duration::from_secs(30));
    loop {
        let output = ns_command_output(
            node,
            "ss",
            &["-uanH", "sport", "=", &format!(":{}", old.port())],
        );
        assert!(output.status.success());
        let open = !String::from_utf8_lossy(&output.stdout).trim().is_empty();
        if shared_listener || !open {
            if shared_listener {
                assert!(
                    open,
                    "retiring an owner closed the shared incoming listener"
                );
            }
            fs::write(
                temp.join(format!("{stage}-retired-udp-socket.txt")),
                &output.stdout,
            )
            .unwrap();
            return;
        }
        assert!(
            Instant::now() < deadline,
            "dedicated old outer UDP socket {old} was not released"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

#[allow(clippy::too_many_arguments)]
fn quiet_after_drain(
    temp: &Path,
    a: u32,
    overlay_b: Ipv4Addr,
    role: &str,
    peer: &str,
    new: &Owner,
    stage: &str,
    traffic: &Traffic,
) {
    // Swarm closure precedes QUIC's close-flight drain. Wait for a bounded stable
    // tuple, then require silence for more than three native 5-second keepalives.
    let deadline = Instant::now() + scaled_wait_timeout(Duration::from_secs(30));
    let mut last = traffic.counters().old_tuple();
    let mut stable_since = Instant::now();
    let mut sample = 0;
    loop {
        assert_payload(
            temp,
            a,
            overlay_b,
            &format!("{stage}-protocol-drain-{sample}"),
        );
        assert_selected(temp, role, peer, &new.inner, stage);
        let counters = traffic.counters();
        assert_eq!(counters.wrong_interface, 0);
        if counters.old_tuple() != last {
            last = counters.old_tuple();
            stable_since = Instant::now();
        }
        if stable_since.elapsed() >= Duration::from_secs(6) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "old tuple did not finish bounded protocol drain\n{}",
            traffic.snapshot()
        );
        sample += 1;
    }
    let before = traffic.snapshot();
    let quiet_start = Instant::now();
    sample = 0;
    while quiet_start.elapsed() < Duration::from_secs(16) {
        assert_payload(
            temp,
            a,
            overlay_b,
            &format!("{stage}-quiet-payload-{sample}"),
        );
        assert_selected(temp, role, peer, &new.inner, stage);
        let counters = traffic.counters();
        assert_eq!(counters.wrong_interface, 0);
        assert_eq!(
            counters.old_tuple(),
            last,
            "retired old native QUIC tuple kept transmitting during payload\n{}",
            traffic.snapshot()
        );
        sample += 1;
    }
    fs::write(temp.join(format!("{stage}-quiet-old-tuple.txt")), format!(
        "quiet_elapsed={:?}\nold_sent_received={last:?}\npayload_samples={sample}\nbefore:\n{before}\nafter:\n{}", quiet_start.elapsed(), traffic.snapshot(),
    )).unwrap();
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Counters {
    wrong_interface: u64,
    blocked: u64,
    old: u64,
    received: u64,
}

impl Counters {
    fn old_tuple(&self) -> (u64, u64) {
        (self.old, self.received)
    }
}

fn counters(snapshot: &str, blocked: bool) -> Counters {
    let rules = snapshot
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let number = words.next()?.parse::<u32>().ok()?;
            let packets = words.next()?.parse::<u64>().ok()?;
            words.next()?.parse::<u64>().ok()?;
            let target = words.next()?;
            Some((number, packets, target))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rules.len(),
        if blocked { 3 } else { 2 },
        "unexpected tuple counter rules: {snapshot}"
    );
    assert_eq!(rules[0].2, "DROP");
    assert_eq!(rules.last().unwrap().2, "RETURN");
    if blocked {
        assert_eq!(rules[1].2, "DROP");
    }
    Counters {
        wrong_interface: rules[0].1,
        blocked: if blocked { rules[1].1 } else { 0 },
        old: rules.last().unwrap().1,
        received: 0,
    }
}

struct Traffic {
    node: u32,
    program: &'static str,
    chain: String,
    incoming: String,
    old_interface: String,
    blocked: bool,
}

impl Traffic {
    fn install(
        node: u32,
        test: &str,
        stage: usize,
        old: SocketAddr,
        old_interface: &str,
        preferred: &str,
    ) -> Self {
        let traffic = Self {
            node,
            program: if ipv6(test) { "ip6tables" } else { "iptables" },
            chain: format!("P2P_RQ_{stage}"),
            incoming: format!("P2P_RQI_{stage}"),
            old_interface: old_interface.to_owned(),
            blocked: true,
        };
        traffic.command(&["-N", &traffic.chain]);
        traffic.command(&["-I", "OUTPUT", "1", "-j", &traffic.chain]);
        traffic.command(&["-N", &traffic.incoming]);
        traffic.command(&["-I", "INPUT", "1", "-j", &traffic.incoming]);
        let source = old.ip().to_string();
        let port = old.port().to_string();
        let destination = relay_destination(test);
        traffic.command(&[
            "-A",
            &traffic.chain,
            "-p",
            "udp",
            "-s",
            &source,
            "--sport",
            &port,
            "-d",
            destination,
            "--dport",
            "42200",
            "!",
            "-o",
            old_interface,
            "-j",
            "DROP",
        ]);
        traffic.command(&[
            "-A",
            &traffic.chain,
            "-p",
            "udp",
            "-d",
            destination,
            "--dport",
            "42200",
            "-o",
            preferred,
            "-j",
            "DROP",
        ]);
        traffic.command(&[
            "-A",
            &traffic.chain,
            "-p",
            "udp",
            "-s",
            &source,
            "--sport",
            &port,
            "-d",
            destination,
            "--dport",
            "42200",
            "-o",
            old_interface,
            "-j",
            "RETURN",
        ]);
        traffic.command(&[
            "-A",
            &traffic.incoming,
            "-p",
            "udp",
            "-s",
            destination,
            "--sport",
            "42200",
            "-d",
            &source,
            "--dport",
            &port,
            "-i",
            old_interface,
            "-j",
            "RETURN",
        ]);
        traffic
    }
    fn command(&self, args: &[&str]) {
        ns_command(self.node, self.program, args);
    }
    fn unblock(&mut self) {
        self.command(&["-D", &self.chain, "2"]);
        self.blocked = false;
    }
    fn snapshot(&self) -> String {
        format!(
            "outgoing:\n{}incoming:\n{}",
            self.chain_snapshot(&self.chain),
            self.chain_snapshot(&self.incoming)
        )
    }
    fn diagnostic_snapshot(&self) -> String {
        [&self.chain, &self.incoming]
            .into_iter()
            .map(|chain| {
                diagnostic_command(
                    self.node,
                    self.program,
                    &["-L", chain, "-v", "-n", "-x", "--line-numbers"],
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
    fn chain_snapshot(&self, chain: &str) -> String {
        let output = ns_command_output(
            self.node,
            self.program,
            &["-L", chain, "-v", "-n", "-x", "--line-numbers"],
        );
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap()
    }
    fn counters(&self) -> Counters {
        let mut result = counters(&self.chain_snapshot(&self.chain), self.blocked);
        result.received = incoming_packets(&self.chain_snapshot(&self.incoming));
        result
    }
    fn remove(self) {
        self.command(&["-D", "OUTPUT", "-j", &self.chain]);
        self.command(&["-F", &self.chain]);
        self.command(&["-X", &self.chain]);
        self.command(&["-D", "INPUT", "-j", &self.incoming]);
        self.command(&["-F", &self.incoming]);
        self.command(&["-X", &self.incoming]);
    }
}

fn incoming_packets(snapshot: &str) -> u64 {
    let packets = snapshot
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            words.next()?.parse::<u32>().ok()?;
            let packets = words.next()?.parse::<u64>().ok()?;
            words.next()?.parse::<u64>().ok()?;
            assert_eq!(words.next(), Some("RETURN"));
            Some(packets)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        packets.len(),
        1,
        "unexpected incoming tuple counter rules: {snapshot}"
    );
    packets[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_diagnostics_preserve_original_panic_even_if_capture_panics() {
        let called = std::cell::Cell::new(false);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_failure_diagnostics(
                || std::panic::panic_any(73_u32),
                || {
                    called.set(true);
                    panic!("diagnostic capture failed");
                },
            );
        }));
        assert!(called.get());
        assert_eq!(result.unwrap_err().downcast_ref::<u32>(), Some(&73));
        called.set(false);
        with_failure_diagnostics(|| {}, || called.set(true));
        assert!(
            !called.get(),
            "successful payload must not run failure capture"
        );
    }

    #[test]
    fn socket_fields_accept_runtime_quoted_ipv6_and_native_unquoted_addresses() {
        for (line, expected) in [
            ("source=10.251.0.1:42201 interface=5", "10.251.0.1:42201"),
            (
                "source=[2001:db8:251::1]:42201 interface=5",
                "[2001:db8:251::1]:42201",
            ),
            (
                "source=\"[2001:db8:251::1]:42201\" interface=5",
                "[2001:db8:251::1]:42201",
            ),
        ] {
            assert_eq!(
                socket_field(line, "source"),
                Some(expected.parse().unwrap())
            );
        }
        for line in [
            "source=\"[::1]:42",
            "source=\"not-a-socket\"",
            "interface=5",
        ] {
            assert_eq!(socket_field(line, "source"), None);
        }
    }

    #[test]
    fn receiver_tuple_requires_native_quic_not_tcp_or_circuit() {
        assert_eq!(
            remote_tuple("/ip4/10.251.0.1/udp/42201/quic-v1"),
            Some("10.251.0.1:42201".parse().unwrap())
        );
        assert_eq!(
            remote_tuple("/ip6/2001:db8:251::1/udp/42201/quic-v1"),
            Some("[2001:db8:251::1]:42201".parse().unwrap())
        );
        assert_eq!(remote_tuple("/ip4/10.251.0.1/tcp/42201"), None);
        assert_eq!(
            remote_tuple("/ip4/10.251.0.1/udp/42201/quic-v1/p2p-circuit"),
            None
        );
    }

    #[test]
    fn exact_old_tuple_counters_survive_removal_of_only_the_preferred_block() {
        let blocked = "Chain P2P_RQ_0 (1 references)\nnum pkts bytes target prot opt in out source destination\n1 0 0 DROP udp -- * !veth-a 10.251.0.1 10.251.0.254\n2 13 15600 DROP udp -- * alt-node 0.0.0.0/0 10.251.0.254\n3 42 8400 RETURN udp -- * veth-a 10.251.0.1 10.251.0.254\n";
        assert_eq!(
            counters(blocked, true),
            Counters {
                wrong_interface: 0,
                blocked: 13,
                old: 42,
                received: 0,
            }
        );
        let unblocked = "Chain P2P_RQ_1 (1 references)\nnum pkts bytes target prot opt in out source destination\n1 0 0 DROP udp -- * !alt-node fd00:210::1 2001:db8:251::fe\n2 42 8400 RETURN udp -- * alt-node fd00:210::1 2001:db8:251::fe\n";
        assert_eq!(
            counters(unblocked, false),
            Counters {
                wrong_interface: 0,
                blocked: 0,
                old: 42,
                received: 0,
            }
        );
        assert_eq!(
            incoming_packets("num pkts bytes target prot\n1 37 8900 RETURN udp\n"),
            37
        );
    }
}
