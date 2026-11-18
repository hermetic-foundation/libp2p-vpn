//! Two disjoint single-family links and one relay Peer ID. The namespaces have
//! no external network access; a private DHT carries the signed address record.
use super::*;
use p2p_vpn::config::BootstrapPeerConfig;

pub(super) const V4_RESERVES: &str = "tun_namespace_ipv4_member_reserves_cross_family_relay";
pub(super) const V6_RESERVES: &str = "tun_namespace_ipv6_member_reserves_cross_family_relay";
const V4_RELAY: &str = "11.251.0.254";
const V6_RELAY: &str = "2001:db9:251::fe";

fn v4_entrance() -> String {
    format!("/ip4/{V4_RELAY}/tcp/42200")
}

fn v6_entrance() -> String {
    format!("/ip6/{V6_RELAY}/tcp/42200")
}

pub(super) fn is_test(name: &str) -> bool {
    matches!(name, V4_RESERVES | V6_RESERVES)
}

pub(super) fn dispatch(test: &str) {
    match env::var(CHILD_ENV).as_deref() {
        Ok("orchestrator") => run(test),
        Ok("node") => run_node_child(),
        _ => reexec_orchestrator(test),
    }
}

fn overlay(identity: &NodeIdentity) -> Ipv4Addr {
    p2p_vpn::route::builtin_ipv4(identity.peer_id.parse().unwrap())
}

fn member_config(
    role: &str,
    local: &NodeIdentity,
    remote: &NodeIdentity,
    relay: &NodeIdentity,
    entrance: String,
    reserve: bool,
) -> Config {
    let mut config = direct_overlay_config(role, local, remote);
    config.network.listen_addresses.clear();
    config.network.external_addresses.clear();
    config.peers[0].addresses.clear();
    disable_owned_packet_planes(&mut config);
    config.network.discovery = dht_test_discovery();
    config.network.discovery.kademlia_provider_advertisement = reserve;
    config.network.relay.auto.max_candidates = usize::from(reserve);
    config.network.relay.auto.max_reservations = usize::from(reserve);
    config.network.bootstrap_peers = vec![BootstrapPeerConfig {
        id: relay.peer_id.clone(),
        address: entrance,
    }];
    config
}

fn run(test: &str) {
    let temp = init_namespace_temp_dir(&env::temp_dir().join("p2p-vpn-cross-family"), test);
    let relay = NodeIdentity::generate_ed25519().unwrap();
    let v4 = NodeIdentity::generate_ed25519().unwrap();
    let v6 = loop {
        let next = NodeIdentity::generate_ed25519().unwrap();
        if overlay(&next) != overlay(&v4) {
            break next;
        }
    };
    let v4_reserves = test == V4_RESERVES;
    let mut server = relay_config(&relay);
    server.network.discovery = dht_bootstrap_discovery();
    server.network.listen_addresses = vec![v4_entrance(), v6_entrance()];
    server.network.external_addresses = server.network.listen_addresses.clone();
    write_child_config(&temp, "relay", &server);
    write_child_config(
        &temp,
        "a",
        &member_config("a", &v4, &v6, &relay, v4_entrance(), v4_reserves),
    );
    write_child_config(
        &temp,
        "b",
        &member_config("b", &v6, &v4, &relay, v6_entrance(), !v4_reserves),
    );
    let mut children = [("relay", &relay), ("a", &v4), ("b", &v6)].map(|(role, node)| {
        spawn_node(
            test,
            role,
            node,
            None,
            None,
            &temp,
            &temp.join(format!("start-{role}")),
        )
    });
    let [relay_pid, v4_pid, v6_pid] = children.each_ref().map(NamespaceChild::id);
    for pid in [relay_pid, v4_pid, v6_pid] {
        wait_for_child_namespace(pid);
    }
    attach_link(
        v4_pid,
        relay_pid,
        "v4",
        "11.251.0.1/24",
        "11.251.0.254/24",
        false,
    );
    attach_link(
        v6_pid,
        relay_pid,
        "v6",
        "2001:db9:251::1/64",
        "2001:db9:251::fe/64",
        true,
    );
    ns_command(v4_pid, "ip", &["route", "add", "default", "via", V4_RELAY]);
    ns_command(
        v6_pid,
        "ip",
        &["-6", "route", "add", "default", "via", V6_RELAY],
    );
    assert!(
        !ns_command_output(v4_pid, "ip", &["-6", "route", "get", V6_RELAY])
            .status
            .success()
    );
    assert!(
        !ns_command_output(v6_pid, "ip", &["-4", "route", "get", V4_RELAY])
            .status
            .success()
    );

    let [reserver, caller] = if v4_reserves { ["a", "b"] } else { ["b", "a"] };
    for role in ["relay", reserver] {
        fs::write(temp.join(format!("start-{role}")), "start").unwrap();
        wait_for_file(&temp.join(format!("ready-{role}")));
    }
    wait_for_daemon_state(
        &temp,
        reserver,
        Duration::from_secs(15),
        "both entrances to one automatic reservation",
        |lines| {
            let address = |entrance: String| {
                let needle = format!(" address={entrance}/p2p/{}/p2p-circuit/", relay.peer_id);
                lines.iter().any(|line| {
                    line.contains("event=relay_listen_address_ready") && line.contains(&needle)
                })
            };
            address(v4_entrance()) && address(v6_entrance())
        },
    );
    let reserver_id = if v4_reserves {
        &v4.peer_id
    } else {
        &v6.peer_id
    };
    let put_record = format!("PutRecord {{ source: PeerId(\"{reserver_id}\")");
    // A scoped reservation can be invalidated by startup route notifications.
    // Allow the default 30-second reservation retry before expecting publication.
    let deadline = Instant::now() + Duration::from_secs(55);
    while !read_log(&temp.join("node-relay.log")).contains(&put_record) {
        assert!(
            Instant::now() < deadline,
            "reservation owner never published its signed address record:\n{}",
            log_tail(&read_log(&temp.join(format!("node-{reserver}.log"))), 50)
        );
        thread::sleep(Duration::from_millis(200));
    }
    fs::write(temp.join(format!("start-{caller}")), "start").unwrap();
    wait_for_file(&temp.join(format!("ready-{caller}")));
    let (caller_pid, caller_tun, target) = if v4_reserves {
        (v6_pid, "hse2eb", overlay(&v4))
    } else {
        (v4_pid, "hse2ea", overlay(&v6))
    };
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        // Live traffic requests a lookup for the member. Do not wait for a path
        // before giving the demand-driven recovery loop any work.
        if ns_command_output(
            caller_pid,
            "ping",
            &["-c", "1", "-W", "1", "-I", caller_tun, &target.to_string()],
        )
        .status
        .success()
        {
            break;
        }
        if Instant::now() >= deadline {
            capture_daemon_snapshots(&temp, &["a", "b"]);
            panic!(
                "caller never reached member through discovered relay:\n{}\n{}",
                daemon_snapshot_summary(&temp, &["a", "b"]),
                log_tail(&read_log(&temp.join(format!("node-{caller}.log"))), 60)
            );
        }
    }
    for role in ["a", "b"] {
        wait_for_selected_path(&temp, role, "circuit_relay");
    }
    assert_output_success(
        "v4 to v6 member over relay",
        &ping_from_namespace(v4_pid, "hse2ea", overlay(&v6)),
    );
    assert_output_success(
        "v6 to v4 member over relay",
        &ping_from_namespace(v6_pid, "hse2eb", overlay(&v4)),
    );
    for (role, entrance) in [("a", v4_entrance()), ("b", v6_entrance())] {
        wait_for_daemon_state(
            &temp,
            role,
            Duration::from_secs(5),
            "payload across family-specific relay entrance",
            |lines| {
                let exact = format!(" outer_remote={entrance}");
                lines.iter().any(|line| {
                    line.starts_with("physical circuit state:")
                        && line.contains(&format!(" relay={} ", relay.peer_id))
                        && line.contains(&exact)
                        && line.contains(" outer_usable=true ")
                }) && state_metric_count(lines, "outbound_relay_stream_fallback_packets")
                    .is_some_and(|count| count >= 5)
                    && state_metric_count(lines, "outbound_direct_tcp_stream_fallback_packets")
                        == Some(0)
                    && state_metric_count(lines, "outbound_direct_quic_stream_fallback_packets")
                        == Some(0)
            },
        );
    }
    for child in &mut children {
        stop_child(child);
    }
    cleanup_temp_dir(temp);
}

fn attach_link(member: u32, relay: u32, name: &str, local: &str, server: &str, ipv6: bool) {
    let member_if = format!("vpn-{name}");
    let relay_if = format!("relay-{name}");
    run_command(
        "ip",
        &[
            "link", "add", &member_if, "type", "veth", "peer", "name", &relay_if,
        ],
    );
    for (pid, interface, address) in [(member, &member_if, local), (relay, &relay_if, server)] {
        run_command("ip", &["link", "set", interface, "netns", &pid.to_string()]);
        ns_command(pid, "ip", &["link", "set", "lo", "up"]);
        if ipv6 {
            ns_command(
                pid,
                "ip",
                &["-6", "addr", "add", address, "dev", interface, "nodad"],
            );
        } else {
            ns_command(
                pid,
                "sysctl",
                &["-w", &format!("net.ipv6.conf.{interface}.disable_ipv6=1")],
            );
            ns_command(pid, "ip", &["-4", "addr", "add", address, "dev", interface]);
        }
        ns_command(pid, "ip", &["link", "set", interface, "up"]);
    }
}
