use super::*;
use crate::runtime::physical_network::linux::ownership::OVERLAY_MARKER;

fn runtime_config(name: &str, host: u8) -> TunRuntimeConfig {
    TunRuntimeConfig {
        name: name.to_owned(),
        mtu: 1280,
        addresses: TunAddresses {
            ipv4: Ipv4Addr::new(100, 64, 0, host),
            ipv6: Ipv6Addr::new(0xfd42, 0, 0, 0, 0, 0, 0, u16::from(host)),
        },
        additional_addresses: vec![
            IpCidr::new(Ipv4Addr::new(10, 42, 0, host).into(), 32).unwrap(),
            IpCidr::new(
                Ipv6Addr::new(0xfd43, 0, 0, 0, 0, 0, 0, u16::from(host)).into(),
                128,
            )
            .unwrap(),
        ],
        routes: vec![
            Route {
                owner: PeerId::from_bytes([host; 32]),
                prefix: IpCidr::new(Ipv4Addr::new(10, 44, host, 0).into(), 24).unwrap(),
                metric: 10,
            },
            Route {
                owner: PeerId::from_bytes([host; 32]),
                prefix: IpCidr::new(
                    Ipv6Addr::new(0xfd44, u16::from(host), 0, 0, 0, 0, 0, 0).into(),
                    64,
                )
                .unwrap(),
                metric: 10,
            },
        ],
    }
}

#[test]
fn startup_marks_overlay_before_addresses_and_routes() {
    assert_eq!(OVERLAY_MARKER, "p2p-vpn:overlay:v1");
    for name in ["custom42", "odd;name"] {
        let config = runtime_config(name, 1);
        let commands = config.route_commands();
        assert_eq!(
            commands[0].args(),
            ["link", "set", "dev", name, "alias", OVERLAY_MARKER]
        );
        assert_eq!(
            commands.iter().map(ToString::to_string).collect::<Vec<_>>(),
            [
                format!("ip link set dev {name} alias p2p-vpn:overlay:v1"),
                format!("ip -6 addr replace fd42::1/128 dev {name} nodad"),
                format!("ip addr replace 10.42.0.1/32 dev {name}"),
                format!("ip -6 addr replace fd43::1/128 dev {name} nodad"),
                format!(
                    "ip route replace 10.44.1.0/24 dev {name} src 10.42.0.1 metric 3000 mtu 1280 advmss 1240"
                ),
                format!(
                    "ip -6 route replace fd44:1::/64 dev {name} src fd43::1 metric 3000 mtu 1280 advmss 1220"
                ),
            ]
        );
    }
}

#[derive(Debug, serde::Deserialize)]
struct LinkMetadata {
    ifindex: u32,
    ifname: String,
    #[serde(default)]
    ifalias: Option<String>,
}

fn link_metadata() -> Vec<LinkMetadata> {
    let output = Command::new("ip")
        .args(["-j", "link", "show"])
        .output()
        .expect("query namespace link metadata");
    assert!(
        output.status.success(),
        "ip link query failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse namespace link metadata")
}

fn link(name: &str) -> LinkMetadata {
    link_metadata()
        .into_iter()
        .find(|link| link.ifname == name)
        .unwrap_or_else(|| panic!("missing namespace interface {name}"))
}

fn assert_owned_links(expected: &[(&str, u32)]) {
    let mut actual = link_metadata()
        .into_iter()
        .filter(|link| link.ifalias.as_deref() == Some(OVERLAY_MARKER))
        .map(|link| (link.ifname, link.ifindex))
        .collect::<Vec<_>>();
    let mut expected = expected
        .iter()
        .map(|(name, index)| ((*name).to_owned(), *index))
        .collect::<Vec<_>>();
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
}

fn assert_link_absent(name: &str) {
    assert!(
        link_metadata().iter().all(|link| link.ifname != name),
        "interface {name} survived its last TUN owner"
    );
}

fn open_configured(config: &TunRuntimeConfig) -> TunDevice {
    let device = TunDevice::open(config).expect("open real nonpersistent TUN");
    assert_eq!(device.name().unwrap(), config.name);
    assert_ne!(link(&config.name).ifalias.as_deref(), Some(OVERLAY_MARKER));
    for command in config.sysctl_commands() {
        command.execute().expect("configure TUN sysctl");
    }
    for command in config.route_commands() {
        let status = command.execute().expect("execute TUN startup command");
        assert!(status.success(), "`{command}` exited with {status}");
    }
    assert_eq!(link(&config.name).ifalias.as_deref(), Some(OVERLAY_MARKER));
    device
}

#[test]
#[ignore = "requires isolated Linux user/network namespaces, iproute2 and /dev/net/tun"]
fn overlay_marker_follows_real_tun_lifecycle() {
    const PARENT_NAMESPACE: &str = "P2P_VPN_TUN_OWNERSHIP_PARENT_NETNS";
    let namespace = fs::read_link("/proc/self/ns/net").expect("current network namespace");
    let Some(parent_namespace) = std::env::var_os(PARENT_NAMESPACE) else {
        let status = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net"])
            .arg(std::env::current_exe().expect("test executable"))
            .args([
                "--ignored",
                "--exact",
                "runtime::tun::ownership_tests::overlay_marker_follows_real_tun_lifecycle",
                "--nocapture",
            ])
            .env(PARENT_NAMESPACE, namespace)
            .status()
            .expect("launch isolated ownership test");
        assert!(status.success(), "isolated TUN ownership test failed");
        return;
    };
    assert_ne!(
        namespace,
        PathBuf::from(parent_namespace),
        "ownership test must not mutate its parent's network namespace"
    );

    let first_config = runtime_config("custom42", 1);
    let second_config = runtime_config("other17", 2);
    let first = open_configured(&first_config);
    let first_index = link(&first_config.name).ifindex;
    let second = open_configured(&second_config);
    let second_index = link(&second_config.name).ifindex;
    assert_ne!(first_index, second_index);
    assert_owned_links(&[("custom42", first_index), ("other17", second_index)]);

    for args in [
        vec!["link", "set", "dev", "custom42", "down"],
        vec!["link", "set", "dev", "custom42", "name", "renamed9"],
        vec!["link", "set", "dev", "renamed9", "up"],
    ] {
        let status = Command::new("ip").args(&args).status().unwrap();
        assert!(status.success(), "ip {args:?} exited with {status}");
    }
    assert_link_absent("custom42");
    assert_owned_links(&[("renamed9", first_index), ("other17", second_index)]);

    // A new TUN with the old name must not inherit the renamed device's marker.
    let replacement = TunDevice::open(&runtime_config("custom42", 3)).unwrap();
    assert_ne!(link("custom42").ifindex, first_index);
    assert_ne!(link("custom42").ifalias.as_deref(), Some(OVERLAY_MARKER));
    assert_owned_links(&[("renamed9", first_index), ("other17", second_index)]);
    drop(replacement);
    assert_link_absent("custom42");

    let (reader, writer) = first.split();
    drop(reader);
    assert_owned_links(&[("renamed9", first_index), ("other17", second_index)]);
    drop(writer);
    assert_link_absent("renamed9");
    assert_owned_links(&[("other17", second_index)]);

    // Name reuse after deletion must also start without ownership metadata.
    let replacement = TunDevice::open(&runtime_config("renamed9", 3)).unwrap();
    assert_ne!(link("renamed9").ifindex, first_index);
    assert_ne!(link("renamed9").ifalias.as_deref(), Some(OVERLAY_MARKER));
    assert_owned_links(&[("other17", second_index)]);
    drop(replacement);
    assert_link_absent("renamed9");

    drop(second);
    assert_link_absent("other17");
    assert_owned_links(&[]);
}
