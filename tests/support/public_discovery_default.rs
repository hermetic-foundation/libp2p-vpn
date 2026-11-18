//! Real public-protocol bootstrap and direct member traffic on separate links.
use super::*;
use hickory_proto::{
    op::{Message, MessageType},
    rr::{RData, Record, RecordType, rdata::A},
};
use p2p_vpn::config::{BootstrapPeerConfig, PUBLIC_IPFS_KADEMLIA_PROTOCOL};
use std::net::UdpSocket;

pub(super) const TEST_NAME: &str = "tun_namespace_public_discovery_uses_default_not_secondary";
const PRIMARY: &str = "11.252.0.254";
const SECONDARY: &str = "11.253.0.254";
const PORT: &str = "42300";
const REFERRAL: &str = "11.253.0.253";
const REFERRAL_PORT: &str = "42301";
const CHAIN: &str = "p2p-public-scope";
const REFERRAL_CHAIN: &str = "p2p-public-referral";
const DNS_CHAIN: &str = "p2p-public-dns";
const DNS_PRIMARY: &str = "8.8.8.8";
const DNS_SECONDARY: &str = "8.8.4.4";
const SEED_NAME: &str = "seed.discovery.test";

pub(super) fn run() {
    let temp = init_namespace_temp_dir(&env::temp_dir().join("p2p-vpn-public-scope"), TEST_NAME);
    let a = NodeIdentity::generate_ed25519().unwrap();
    let b = loop {
        let candidate = NodeIdentity::generate_ed25519().unwrap();
        if overlay_addr(&candidate) != overlay_addr(&a) {
            break candidate;
        }
    };
    let seed = NodeIdentity::generate_ed25519().unwrap();
    let referral = NodeIdentity::generate_ed25519().unwrap();
    let addresses = [PRIMARY, SECONDARY].map(|ip| format!("/ip4/{ip}/tcp/{PORT}"));
    let referral_address = format!("/ip4/{REFERRAL}/tcp/{REFERRAL_PORT}");
    let mut referred_config = bootstrap_config(&referral);
    referred_config.network.discovery.kademlia_protocol = PUBLIC_IPFS_KADEMLIA_PROTOCOL.to_owned();
    referred_config.network.listen_addresses = vec![referral_address.clone()];
    referred_config.network.external_addresses = vec![referral_address.clone()];
    write_child_config(&temp, "referral", &referred_config);

    let mut seed_config = bootstrap_config(&seed);
    seed_config.network.discovery.kademlia_protocol = PUBLIC_IPFS_KADEMLIA_PROTOCOL.to_owned();
    seed_config.network.listen_addresses = addresses.to_vec();
    seed_config.network.external_addresses = addresses.to_vec();
    seed_config.network.relay.server = true;
    seed_config.network.bootstrap_peers = vec![BootstrapPeerConfig {
        id: referral.peer_id.clone(),
        address: referral_address,
    }];
    write_child_config(&temp, "bootstrap", &seed_config);

    let mut client = direct_overlay_config("a", &a, &b);
    disable_owned_packet_planes(&mut client);
    client.network.discovery = relay_test_discovery();
    client.network.discovery.kademlia = true;
    client.network.discovery.kademlia_protocol = PUBLIC_IPFS_KADEMLIA_PROTOCOL.to_owned();
    client.network.relay.auto.max_reservations = 1;
    client.network.bootstrap_peers = [
        format!("/dns4/{SEED_NAME}/tcp/{PORT}"),
        addresses[1].clone(),
    ]
    .into_iter()
    .map(|address| BootstrapPeerConfig {
        id: seed.peer_id.clone(),
        address,
    })
    .collect();
    client.network.listen_addresses = vec!["/ip4/11.253.0.1/tcp/42101".to_owned()];
    client.peers[0].addresses = vec!["/ip4/11.253.0.2/tcp/42102".to_owned()];
    // A separate member still needs discovery after the direct member becomes
    // healthy. Otherwise the production runtime intentionally goes quiet.
    let undiscovered = loop {
        let candidate = NodeIdentity::generate_ed25519().unwrap();
        let ip = overlay_addr(&candidate);
        if ip != overlay_addr(&a) && ip != overlay_addr(&b) {
            break candidate;
        }
    };
    let undiscovered_ip = overlay_addr(&undiscovered).to_string();
    client
        .peers
        .push(peer_config(&undiscovered, None, Vec::new()));
    write_child_config(&temp, "a", &client);
    let mut member = direct_overlay_config("b", &b, &a);
    disable_owned_packet_planes(&mut member);
    member.network.discovery = relay_test_discovery();
    member.network.listen_addresses = vec!["/ip4/11.253.0.2/tcp/42102".to_owned()];
    member.peers[0].addresses = vec!["/ip4/11.253.0.1/tcp/42101".to_owned()];
    write_child_config(&temp, "b", &member);

    let mut children = [
        ("referral", &referral),
        ("bootstrap", &seed),
        ("a", &a),
        ("b", &b),
    ]
    .map(|(role, identity)| {
        spawn_node(
            TEST_NAME,
            role,
            identity,
            None,
            None,
            &temp,
            &temp.join(format!("start-{role}")),
        )
    });
    let [referral_pid, seed_pid, a_pid, b_pid] = children.each_ref().map(NamespaceChild::id);
    for pid in [referral_pid, seed_pid, a_pid, b_pid] {
        wait_for_child_namespace(pid);
    }
    for (name, endpoint, client_ip, seed_ip) in [
        ("pub", PRIMARY, "11.252.0.1/24", "11.252.0.254/24"),
        ("alt", SECONDARY, "11.253.0.1/24", "11.253.0.254/24"),
    ] {
        let bridge = format!("br-{name}");
        run_command("ip", &["link", "add", &bridge, "type", "bridge"]);
        run_command("ip", &["link", "set", &bridge, "up"]);
        attach_veth_to_bridge(a_pid, name, client_ip, &bridge);
        attach_veth_to_bridge(seed_pid, &format!("{name}s"), seed_ip, &bridge);
        ns_command(a_pid, "ping", &["-c", "1", "-W", "2", endpoint]);
    }
    attach_veth_to_bridge(b_pid, "b", "11.253.0.2/24", "br-alt");
    attach_veth_to_bridge(referral_pid, "ref", "11.253.0.253/24", "br-alt");
    ns_command(a_pid, "ping", &["-c", "1", "-W", "2", REFERRAL]);
    ns_command(
        a_pid,
        "ip",
        &["route", "add", "default", "via", PRIMARY, "dev", "veth-pub"],
    );
    ns_command(
        a_pid,
        "ip",
        &[
            "route", "add", "default", "via", SECONDARY, "dev", "veth-alt", "metric", "200",
        ],
    );
    for resolver in [DNS_PRIMARY, DNS_SECONDARY] {
        ns_command(
            seed_pid,
            "ip",
            &["addr", "add", &format!("{resolver}/32"), "dev", "lo"],
        );
    }
    ns_command(
        a_pid,
        "ip",
        &[
            "route",
            "add",
            DNS_SECONDARY,
            "via",
            SECONDARY,
            "dev",
            "veth-alt",
        ],
    );
    install_counters(a_pid, CHAIN, PORT, &["tcp"]);
    install_counters(a_pid, REFERRAL_CHAIN, REFERRAL_PORT, &["tcp"]);
    install_counters(a_pid, DNS_CHAIN, "53", &["tcp", "udp"]);

    for role in ["referral", "bootstrap", "a", "b"] {
        fs::write(temp.join(format!("start-{role}")), "start").expect("release namespace child");
        wait_for_file(&temp.join(format!("ready-{role}")));
    }
    wait_for_daemon_running(&temp, "a");
    wait_for_peer_ready(&temp, "a");
    assert_output_success(
        "direct member on nondefault interface",
        &ping_from_namespace(a_pid, "hse2ea", overlay_addr(&b)),
    );
    wait_for_selected_path(&temp, "a", "direct_tcp_stream");

    // Include the production 60-second LAN-first startup holdoff.
    let deadline = Instant::now() + Duration::from_secs(110);
    let scoped_referral = format!("outgoing connection to {} failed", referral.peer_id);
    let seed_connection = format!(
        "ConnectionEstablished {{ peer_id: PeerId(\"{}\")",
        a.peer_id
    );
    let seed_to_referral = format!(
        "ConnectionEstablished {{ peer_id: PeerId(\"{}\")",
        referral.peer_id
    );
    loop {
        let bootstrap = counters(a_pid, CHAIN);
        let dns = counters(a_pid, DNS_CHAIN);
        assert_eq!(
            bootstrap[1], 0,
            "automatic public dials sent packets on the alternate link"
        );
        assert_eq!(dns[1], 0, "public DNS sent packets on the alternate link");
        assert_eq!(
            counters(a_pid, REFERRAL_CHAIN)[1],
            0,
            "a referred Kademlia peer received packets on the alternate link"
        );
        let client_log = read_log(&temp.join("node-a.log"));
        let seed_log = read_log(&temp.join("node-bootstrap.log"));
        let connected = bootstrap[0] > 0 && dns[0] > 0 && seed_log.contains(&seed_connection);
        if connected
            && seed_log.contains(&seed_to_referral)
            && seed_log.contains("request: FindNode { num_closer_peers:")
            && client_log.contains("event=relay_listen_address_ready")
            && client_log.contains(&scoped_referral)
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no authenticated default-link seed, automatic reservation, and scoped referral attempt"
        );
        if connected {
            // Generate demand after the holdoff and handshake, not before
            // the seed is eligible for the runtime's recovery query.
            let _ = ns_command_output(
                a_pid,
                "ping",
                &["-c", "1", "-W", "1", "-I", "hse2ea", &undiscovered_ip],
            );
        }
        thread::sleep(Duration::from_millis(250));
    }

    ns_command(
        a_pid,
        "ip",
        &["route", "del", "default", "via", PRIMARY, "dev", "veth-pub"],
    );
    let [old_interface, new_interface] = ["veth-pub", "veth-alt"].map(|device| {
        let output = ns_command_output(a_pid, "ip", &["-j", "link", "show", "dev", device]);
        assert_output_success("read physical interface", &output);
        let links: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
        format!("interface={}", links[0]["ifindex"].as_u64().unwrap())
    });
    wait_for_daemon_state(
        &temp,
        "a",
        Duration::from_secs(45),
        "public seed connection moves to the new default interface",
        |lines| {
            let seed_owner = format!("peer={}", seed.peer_id);
            let has_owner_on = |interface: &str| {
                lines.iter().any(|line| {
                    line.starts_with("physical control state:")
                        && line.split_whitespace().any(|field| field == seed_owner)
                        && line.split_whitespace().any(|field| field == interface)
                })
            };
            // The kernel may route the same seed IP via a different gateway.
            has_owner_on(&new_interface) && !has_owner_on(&old_interface)
        },
    );
    let cutover = counters(a_pid, CHAIN);
    let dns_cutover = counters(a_pid, DNS_CHAIN);
    let referral_cutover = counters(a_pid, REFERRAL_CHAIN);
    assert!(
        cutover[1] > 0,
        "new default never carried bootstrap traffic"
    );
    assert_output_success(
        "member traffic survives default change",
        &ping_from_namespace(a_pid, "hse2ea", overlay_addr(&b)),
    );
    assert_eq!(
        counters(a_pid, CHAIN)[0],
        cutover[0],
        "public discovery still transmitted on the old default after retirement"
    );
    assert_eq!(
        counters(a_pid, DNS_CHAIN)[0],
        dns_cutover[0],
        "public DNS still transmitted on the old default after retirement"
    );
    assert_eq!(
        counters(a_pid, REFERRAL_CHAIN)[0],
        referral_cutover[0],
        "Kademlia referral still transmitted on the old default after retirement"
    );
    for child in &mut children {
        stop_child(child);
    }
    cleanup_temp_dir(temp);
}

fn overlay_addr(node: &NodeIdentity) -> Ipv4Addr {
    p2p_vpn::route::builtin_ipv4(node.peer_id.parse().unwrap())
}

fn install_counters(pid: u32, chain: &str, port: &str, protocols: &[&str]) {
    ns_command(pid, "iptables", &["-N", chain]);
    for protocol in protocols {
        ns_command(
            pid,
            "iptables",
            &[
                "-I", "OUTPUT", "1", "-p", protocol, "--dport", port, "-j", chain,
            ],
        );
    }
    for device in ["veth-pub", "veth-alt"] {
        ns_command(
            pid,
            "iptables",
            &["-A", chain, "-o", device, "-j", "RETURN"],
        );
    }
}

pub(super) fn start_resolvers() {
    for server in [DNS_PRIMARY, DNS_SECONDARY] {
        let socket = UdpSocket::bind((server, 53)).expect("bind isolated fixture resolver");
        thread::spawn(move || {
            let mut buf = [0; 4096];
            while let Ok((size, client)) = socket.recv_from(&mut buf) {
                let Ok(request) = Message::from_vec(&buf[..size]) else {
                    continue;
                };
                let mut reply = Message::new();
                reply
                    .set_id(request.id())
                    .set_message_type(MessageType::Response)
                    .set_recursion_desired(request.recursion_desired())
                    .set_recursion_available(true);
                for query in request.queries() {
                    reply.add_query(query.clone());
                    if query.query_type() == RecordType::A
                        && query.name().to_utf8() == format!("{SEED_NAME}.")
                    {
                        reply.add_answer(Record::from_rdata(
                            query.name().clone(),
                            0,
                            RData::A(A(PRIMARY.parse().unwrap())),
                        ));
                    }
                }
                let reply = reply.to_vec().expect("encode fixture DNS answer");
                socket
                    .send_to(&reply, client)
                    .expect("send fixture DNS answer");
            }
        });
    }
}

fn counters(pid: u32, chain: &str) -> [u64; 2] {
    let output = ns_command_output(pid, "iptables", &["-L", chain, "-vxn"]);
    assert_output_success("read discovery interface counters", &output);
    let rows: Vec<u64> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            (fields.get(2) == Some(&"RETURN")).then(|| fields[0].parse::<u64>().unwrap())
        })
        .collect();
    rows.try_into()
        .expect("one counter per discovery interface")
}
