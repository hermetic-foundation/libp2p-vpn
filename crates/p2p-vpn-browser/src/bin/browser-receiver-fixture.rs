//! Disposable direct or relayed receiver for Chromium tests. No TUN.
use std::{
    net::Ipv4Addr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, mdns,
    multiaddr::Protocol,
    noise, relay,
    request_response::{self, Message},
    swarm::{ConnectionId, NetworkBehaviour, SwarmEvent, behaviour::toggle::Toggle},
    tcp, yamux,
};
use p2p_vpn::{
    PathKind,
    config::{Config, RouteConfig},
    identity::NodeIdentity,
    membership::{
        MembershipRecordIssueOptions, MembershipRecordOptions, MembershipRecordSubject,
        MembershipRole, SignedMembershipRecord, issue_membership_record_at,
        issue_membership_record_for_subject_at,
    },
    runtime::{
        control::{
            self, ControlCapabilities, ControlRejectionReason, ControlRequest, ControlResponse,
            ControlRoute, MembershipRecordsRequest,
        },
        forward::Forwarder,
        packet::{self, PacketRejectionReason, PacketResponse},
        service::{self, ServiceRequest, ServiceResponse, ServiceStatusRequest},
    },
    wire::{Frame, PayloadType},
};
use serde_json::json;
use smoltcp::wire::{IpProtocol, Ipv4Packet};

const MTU: u16 = 1280;
const NATIVE_MTU: u16 = 1200;
const NATIVE_IP: Ipv4Addr = Ipv4Addr::new(10, 204, 0, 1);
const BROWSER_IP: Ipv4Addr = Ipv4Addr::new(10, 204, 0, 2);
const UNASSIGNED_IP: Ipv4Addr = Ipv4Addr::new(10, 204, 0, 3);
const FIXTURE_SCOPE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[path = "browser-receiver-fixture/demand.rs"]
mod demand;
#[path = "browser-receiver-fixture/gateway.rs"]
mod gateway;
#[path = "browser-receiver-fixture/incoming.rs"]
mod incoming;
#[path = "browser-receiver-fixture/shared_incoming.rs"]
mod shared_incoming;

#[derive(NetworkBehaviour)]
struct Behaviour {
    mdns: Toggle<mdns::tokio::Behaviour>,
    relay: Toggle<relay::client::Behaviour>,
    control: request_response::Behaviour<control::ControlCodec>,
    demand: Toggle<demand::Wire>,
    packet: request_response::Behaviour<packet::PacketCodec>,
    service: request_response::Behaviour<service::ServiceCodec>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let scenario = match args.next().as_deref() {
        Some("packets") => "packets",
        Some("wrong-network") => "wrong-network",
        Some("wrong-wire-version") => "wrong-wire-version",
        Some("wrong-packet-protocol") => "wrong-packet-protocol",
        Some("wrong-header-length") => "wrong-header-length",
        Some("zero-mtu") => "zero-mtu",
        Some("unknown-path") => "unknown-path",
        Some("ungranted-route") => "ungranted-route",
        Some("local-route-collision") => "local-route-collision",
        Some("wrong-membership-tag") => "wrong-membership-tag",
        Some("rotated-membership-tag") => "rotated-membership-tag",
        Some("membership") => "membership",
        Some("revocation") => "revocation",
        Some("recovery") => "recovery",
        Some("deny-capabilities") => "deny-capabilities",
        Some("incoming-relay") => "incoming-relay",
        Some("incoming-app") => "incoming-app",
        Some("incoming-demand") => "incoming-demand",
        Some("preferred-return") => "preferred-return",
        Some("relay-gateway") => "relay-gateway",
        Some("relay-gateway-cross-family") => "relay-gateway-cross-family",
        Some("relay-gateway-seed") => return gateway::serve_seed().await,
        Some("shared-incoming") => {
            let entrance = args.next().ok_or("missing relay entrance")?.parse()?;
            let verify_outbound = args.next().as_deref() == Some("--verify-outbound");
            return tokio::time::timeout(
                Duration::from_secs(40),
                shared_incoming::run(entrance, verify_outbound),
            )
            .await?;
        }
        _ => {
            return Err("unknown browser receiver fixture scenario".into());
        }
    };
    let relay = args
        .next()
        .map(|address| address.parse::<Multiaddr>())
        .transpose()?;
    let signed_entrance = if scenario == "relay-gateway-cross-family" {
        Some(
            args.next()
                .ok_or("missing signed circuit entrance")?
                .parse()?,
        )
    } else {
        None
    };
    let expect_relay = matches!(
        scenario,
        "incoming-relay" | "incoming-app" | "relay-gateway" | "relay-gateway-cross-family"
    ) || args.next().as_deref() == Some("relayed");
    let recover_direct = scenario == "recovery" && args.next().as_deref() == Some("direct");
    tokio::time::timeout(
        Duration::from_secs(if scenario == "incoming-demand" {
            90
        } else {
            60
        }),
        run(
            scenario,
            relay,
            expect_relay,
            recover_direct,
            signed_entrance,
        ),
    )
    .await?
}

async fn run(
    scenario: &str,
    relay_entrance: Option<Multiaddr>,
    expect_relay: bool,
    recover_direct: bool,
    signed_entrance: Option<Multiaddr>,
) -> Result<()> {
    let native = NodeIdentity::generate_ed25519().map_err(debug_error)?;
    let browser = NodeIdentity::generate_ed25519().map_err(debug_error)?;
    let network = format!("browser-receiver-{}", native.peer_id);
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let records = [(&native, NATIVE_IP), (&browser, BROWSER_IP)]
        .into_iter()
        .map(|(member, ip)| {
            issue_membership_record_at(
                &native,
                MembershipRecordOptions {
                    network_name: network.clone(),
                    member: member.clone(),
                    membership_epoch: 1,
                    sequence: 1,
                    roles: vec![
                        MembershipRole::OverlayMember,
                        MembershipRole::RouteAuthority,
                    ],
                    route_grants: vec![RouteConfig {
                        prefix: format!("{ip}/32"),
                        metric: 0,
                    }],
                    expires_at_unix_seconds: Some(now + 300),
                },
                now,
            )
            .map_err(debug_error)
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let config_for = |identity: &NodeIdentity, ip: Ipv4Addr| -> serde_json::Result<Config> {
        serde_json::from_value(json!({
            "network": {
                "name": network, "local_peer": identity.peer_id,
                "private_key": identity.private_key, "vpn_ip": ip,
                "member_records": records, "listen_addresses": [],
                "packet_plane": {"listen": [], "quic_listen": []},
            },
            "interface": {"name": "p2p-receiver", "mtu": MTU},
        }))
    };
    let mut native_config = config_for(&native, NATIVE_IP)?;
    let mut browser_config = config_for(&browser, BROWSER_IP)?;
    let previous_tag = p2p_vpn::config::membership_tag(&network, &[1; 32]);
    if matches!(scenario, "wrong-membership-tag" | "rotated-membership-tag") {
        native_config.network.membership_key = Some(FIXTURE_SCOPE_KEY.into());
        browser_config.network.membership_key = Some(FIXTURE_SCOPE_KEY.into());
        if scenario == "rotated-membership-tag" {
            browser_config
                .network
                .previous_membership_tags
                .push(previous_tag.clone());
        }
    }
    if matches!(scenario, "relay-gateway" | "relay-gateway-cross-family") {
        browser_config.network.discovery.mdns = false;
        browser_config.network.discovery.kademlia = true;
        browser_config.network.discovery.kademlia_protocol = gateway::DHT_PROTOCOL.into();
    }
    let mut records_to_serve = native_config.network.member_records.clone();
    if scenario == "membership" {
        for _ in 0..9 {
            records_to_serve.push(
                issue_membership_record_at(
                    &native,
                    MembershipRecordOptions {
                        network_name: network.clone(),
                        member: NodeIdentity::generate_ed25519().map_err(debug_error)?,
                        membership_epoch: 1,
                        sequence: 1,
                        roles: vec![MembershipRole::OverlayMember],
                        route_grants: vec![],
                        expires_at_unix_seconds: Some(now + 300),
                    },
                    now,
                )
                .map_err(debug_error)?,
            );
        }
    }
    if scenario == "revocation" {
        records_to_serve.push(
            issue_membership_record_for_subject_at(
                &native,
                MembershipRecordIssueOptions {
                    network_name: network.clone(),
                    member: MembershipRecordSubject::from_identity(&browser)
                        .map_err(debug_error)?,
                    membership_epoch: 1,
                    sequence: 2,
                    revoked: true,
                    roles: vec![],
                    route_grants: vec![],
                    expires_at_unix_seconds: None,
                },
                now,
            )
            .map_err(debug_error)?,
        );
    }
    let forwarder = Forwarder::from_config(&native_config).map_err(debug_error)?;
    let mut caps = ControlCapabilities::local(
        &network,
        native_config.membership_tag().map_err(debug_error)?,
        NATIVE_MTU,
    )
    .with_advertised_routes(forwarder.local_advertised_routes());
    let expected_path = if expect_relay {
        PathKind::CircuitRelay
    } else {
        PathKind::DirectWebRtcStream
    };
    caps.preferred_path = expected_path.wire_name().into();
    if matches!(scenario, "membership" | "revocation") {
        caps.supports_membership_record_pages = true;
        caps.membership_records_snapshot =
            Some(control::membership_records_snapshot(&records_to_serve));
        caps.membership_record_count = u16::try_from(records_to_serve.len())?;
    }

    let keys = native.keypair().map_err(debug_error)?;
    let lan_recovery = scenario == "recovery" && relay_entrance.is_some();
    let mdns = lan_recovery
        .then(|| mdns::tokio::Behaviour::new(mdns::Config::default(), keys.public().to_peer_id()))
        .transpose()?;
    let certificate = libp2p_webrtc::tokio::Certificate::generate(&mut rand::rngs::OsRng)?;
    let mut swarm = SwarmBuilder::with_existing_identity(keys)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_other_transport(|key| libp2p_webrtc::tokio::Transport::new(key.clone(), certificate))?
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|_, relay| Behaviour {
            mdns: mdns.into(),
            relay: relay_entrance.is_some().then_some(relay).into(),
            control: control::behaviour(8),
            demand: (scenario == "incoming-demand")
                .then(|| demand::behaviour(2))
                .into(),
            packet: packet::behaviour(MTU, 32),
            service: service::behaviour(8),
        })?
        .with_swarm_config(|config| config.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    let fixture_ip = match scenario {
        "relay-gateway" => gateway::MEMBER_IP,
        "relay-gateway-cross-family" => gateway::MEMBER_V6,
        _ if lan_recovery => "192.168.44.2",
        _ => "192.0.2.1",
    };
    let (original_listener, address) = direct_listener(&mut swarm, fixture_ip).await?;
    let member = *swarm.local_peer_id();
    let recovery_address = if scenario == "recovery" {
        let (_, replacement) = direct_listener(&mut swarm, fixture_ip).await?;
        assert_ne!(address, replacement);
        Some(replacement.with(Protocol::P2p(member)).to_string())
    } else {
        None
    };
    let relay_peer = relay_entrance
        .as_ref()
        .and_then(|entrance| match entrance.iter().last() {
            Some(Protocol::P2p(peer)) => Some(peer),
            _ => None,
        });
    let circuit = if let Some(entrance) = &relay_entrance {
        let reservation = entrance.clone().with(Protocol::P2pCircuit);
        if !matches!(
            scenario,
            "incoming-relay" | "incoming-app" | "incoming-demand"
        ) {
            let listener = swarm.listen_on(reservation.clone())?;
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr { listener_id, .. } if listener_id == listener => {
                        break;
                    }
                    SwarmEvent::ListenerClosed {
                        listener_id,
                        reason,
                        ..
                    } if listener_id == listener => {
                        reason?;
                        return Err("reservation unexpectedly closed".into());
                    }
                    SwarmEvent::OutgoingConnectionError { error, .. } => return Err(error.into()),
                    _ => {}
                }
            }
        }
        Some(reservation.with(Protocol::P2p(member)).to_string())
    } else {
        None
    };
    let direct = address.with(Protocol::P2p(member));
    let gateway_record = if scenario == "relay-gateway" {
        let circuit = circuit
            .as_deref()
            .ok_or("expected gateway relay entrance")?
            .parse()?;
        Some(gateway::publish(&network, &native, &direct, circuit, now).await?)
    } else {
        None
    };
    let signed_record = if let Some(entrance) = signed_entrance {
        if !matches!(
            entrance.iter().collect::<Vec<_>>().as_slice(),
            [Protocol::Ip4(_), Protocol::Tcp(_), Protocol::P2p(relay)] if Some(*relay) == relay_peer
        ) || circuit.is_none()
        {
            return Err("signed IPv4 entrance must pin the IPv6 reservation's relay".into());
        }
        Some(gateway::SignedRecord::new(
            &network,
            &native,
            vec![
                entrance
                    .with(Protocol::P2pCircuit)
                    .with(Protocol::P2p(member)),
            ],
            now,
        )?)
    } else {
        None
    };
    let peer = browser.peer_id.parse()?;
    println!(
        "{}",
        json!({
            "config": browser_config,
            "dial_address": direct.to_string(),
            "recovery_address": recovery_address,
            "relay_address": circuit,
            "native_peer_id": native.peer_id,
            "gateway_record": gateway_record,
            "signed_gateway_record": signed_record,
        })
    );
    let mut fixture = Fixture {
        swarm,
        peer,
        relay_peer,
        expected_path,
        forwarder,
        caps,
        records_to_serve,
        report_revocation: scenario == "revocation",
        membership_pages_served: 0,
        capture_recovery_probe: scenario == "recovery",
        recovery_probe: None,
        abandoned_probe: None,
    };
    let deny_capabilities = scenario == "deny-capabilities";
    if scenario == "incoming-demand" {
        return demand::exercise(
            &mut fixture,
            relay_entrance.ok_or("expected relay entrance")?,
        )
        .await;
    }
    if matches!(scenario, "incoming-relay" | "incoming-app") {
        incoming::dial_and_exchange(
            &mut fixture,
            relay_entrance.ok_or("expected relay entrance")?,
        )
        .await?;
    } else if scenario == "preferred-return" {
        let connection = fixture.exchange_capabilities(false).await?;
        fixture.preferred_return(connection).await?;
    } else {
        fixture.exchange_capabilities(deny_capabilities).await?;
    }
    if deny_capabilities {
        println!("{}", json!({ "denied": "WrongNetwork" }));
    } else if scenario == "incoming-app" {
        let status = fixture
            .send_status(ServiceStatusRequest::local(&network, None, 42))
            .await?;
        println!("{}", json!({ "status": status }));
    } else if scenario == "recovery" {
        let (request_id, probe) = loop {
            if let Some(probe) = fixture.recovery_probe.take() {
                break probe;
            }
            let event = fixture.next().await?;
            fixture.capture_packet_probe(event);
        };
        fixture.capture_recovery_probe = false;
        fixture.abandoned_probe = Some(request_id);
        fixture
            .swarm
            .disconnect_peer_id(peer)
            .map_err(|_| "initial path is not connected")?;
        assert!(fixture.swarm.remove_listener(original_listener));
        loop {
            if let SwarmEvent::ConnectionClosed {
                peer_id,
                num_established: 0,
                ..
            } = fixture.swarm.select_next_some().await
                && peer_id == peer
            {
                break;
            }
        }
        drop(probe);
        if recover_direct {
            fixture.expected_path = PathKind::DirectWebRtcStream;
            fixture.caps.preferred_path = fixture.expected_path.wire_name().into();
        }
        let selected = fixture.exchange_capabilities(false).await?;
        println!("{}", json!({ "reauthenticated": true }));
        if lan_recovery {
            loop {
                if let BehaviourEvent::Packet(request_response::Event::Message {
                    connection_id,
                    message:
                        Message::Request {
                            request, channel, ..
                        },
                    ..
                }) = fixture.next().await?
                {
                    assert_eq!(connection_id, selected);
                    assert_eq!(request.header.payload_type, PayloadType::Keepalive);
                    fixture
                        .swarm
                        .behaviour_mut()
                        .packet
                        .send_response(channel, PacketResponse::Accepted)
                        .map_err(debug_error)?;
                    println!("{}", json!({ "recovered_packet": true }));
                }
            }
        }
    } else if scenario == "revocation" {
        loop {
            fixture.next().await?;
        }
    } else if scenario == "membership" {
        let expected = fixture.caps.membership_records_snapshot.clone();
        let mut served = None;
        for _ in 0..8 {
            let response = fixture.request_membership_page(&network).await?;
            let ControlResponse::MembershipRecordsPage(page) = response else {
                return Err(debug_error(response).into());
            };
            if Some(&page.snapshot) == expected.as_ref() {
                served = Some(page);
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        let page = served.ok_or("browser did not serve the merged membership snapshot")?;
        println!(
            "{}",
            json!({
                "snapshot": page.snapshot,
                "total_records": page.total_records,
                "pages_sent": fixture.membership_pages_served,
            })
        );
    } else if let Some((bad_caps, reason)) =
        denied_advertisement(scenario, fixture.caps.clone(), &previous_tag)
    {
        let mut rotated = None;
        if scenario == "rotated-membership-tag" {
            let mut old_caps = fixture.caps.clone();
            old_caps.membership_tag = Some(previous_tag);
            let response = fixture.send_capabilities(old_caps).await?;
            assert!(matches!(response, ControlResponse::CapabilitiesAccepted(_)));
            rotated = Some(true);
        }
        let response = fixture.send_capabilities(bad_caps).await?;
        assert_eq!(response, ControlResponse::CapabilitiesRejected(reason));
        let label = if scenario == "wrong-network" {
            "wrong_network"
        } else {
            "rejection"
        };
        if let Some(rotated) = rotated {
            println!(
                "{}",
                json!({(label): response, "previous_tag_accepted": rotated})
            );
        } else {
            println!("{}", json!({(label): response}));
        }
    } else {
        let mut proof = serde_json::Map::new();
        let valid = Frame::packet(1, 3, ipv4_packet(NATIVE_IP, BROWSER_IP)).map_err(debug_error)?;
        let keepalive = Frame::keepalive(1, 4).map_err(debug_error)?;
        let probe =
            Frame::path_probe(1, 5, vec![0; usize::from(NATIVE_MTU)]).map_err(debug_error)?;
        for (label, frame, expected) in [
            (
                "bad_source",
                Frame::packet(1, 1, ipv4_packet(UNASSIGNED_IP, BROWSER_IP)).map_err(debug_error)?,
                PacketResponse::Rejected(PacketRejectionReason::UnauthorizedSource),
            ),
            (
                "wrong_destination",
                Frame::packet(1, 2, ipv4_packet(NATIVE_IP, UNASSIGNED_IP)).map_err(debug_error)?,
                PacketResponse::Rejected(PacketRejectionReason::UnauthorizedDestination),
            ),
            ("valid_ip", valid.clone(), PacketResponse::Accepted),
            ("identical_ip", valid, PacketResponse::Accepted),
            (
                "nonempty_keepalive",
                Frame::new(PayloadType::Keepalive, 1, 4, vec![1]).map_err(debug_error)?,
                PacketResponse::Rejected(PacketRejectionReason::UnexpectedPayload),
            ),
            ("keepalive", keepalive.clone(), PacketResponse::Accepted),
            (
                "identical_keepalive",
                keepalive,
                PacketResponse::Rejected(PacketRejectionReason::Replay),
            ),
            (
                "too_large",
                Frame::path_probe(1, 5, vec![0; usize::from(NATIVE_MTU) + 1])
                    .map_err(debug_error)?,
                PacketResponse::Rejected(PacketRejectionReason::PacketTooLarge),
            ),
            ("path_probe", probe.clone(), PacketResponse::Accepted),
        ] {
            let actual = fixture.send_packet(frame).await?;
            assert_eq!(actual, expected, "{label}");
            proof.insert(label.into(), json!(format!("{actual:?}")));
        }
        if scenario == "packets" {
            let malformed = Frame::packet(1, 6, vec![0x45]).map_err(debug_error)?;
            let actual = fixture.send_packet(malformed).await?;
            assert_eq!(
                actual,
                PacketResponse::Rejected(PacketRejectionReason::MalformedPacket)
            );
            proof.insert("malformed_ip".into(), json!(format!("{actual:?}")));
            let actual = fixture.send_packet(probe).await?;
            assert_eq!(
                actual,
                PacketResponse::Rejected(PacketRejectionReason::Replay)
            );
            proof.insert("identical_path_probe".into(), json!(format!("{actual:?}")));
        }
        let status = fixture
            .send_status(ServiceStatusRequest::local(&network, None, 42))
            .await?;
        let wrong_scope = fixture
            .send_status(ServiceStatusRequest::local(
                &network,
                Some("other".to_owned()),
                43,
            ))
            .await?;
        println!(
            "{}",
            json!({
                "packets": proof,
                "status": status,
                "wrong_scope": wrong_scope,
                "gateway_direct_attempted": gateway_record.as_ref().map(gateway::SignedFixture::saw_direct),
            })
        );
    }

    // Keep the transport alive until the driver has also checked the WASM result.
    // The driver terminates this process; the outer timeout bounds orphaned runs.
    loop {
        fixture.swarm.select_next_some().await;
    }
}

fn denied_advertisement(
    scenario: &str,
    mut caps: ControlCapabilities,
    previous_tag: &str,
) -> Option<(ControlCapabilities, ControlRejectionReason)> {
    use ControlRejectionReason as Reason;

    let reason = match scenario {
        "wrong-network" => {
            caps.network_name.push_str("-wrong");
            Reason::WrongNetwork
        }
        "wrong-wire-version" => {
            caps.wire_version += 1;
            Reason::UnsupportedWireVersion
        }
        "wrong-packet-protocol" => {
            caps.packet_protocol.push_str("-wrong");
            Reason::UnsupportedPacketProtocol
        }
        "wrong-header-length" => {
            caps.packet_header_len += 1;
            Reason::UnsupportedPacketHeaderLength
        }
        "zero-mtu" => {
            caps.effective_mtu = 0;
            Reason::InvalidEffectiveMtu
        }
        "unknown-path" => {
            caps.preferred_path = "unknown".into();
            Reason::UnsupportedPreferredPath
        }
        "ungranted-route" | "local-route-collision" => {
            let ip = if scenario == "ungranted-route" {
                UNASSIGNED_IP
            } else {
                BROWSER_IP
            };
            caps = caps.with_advertised_routes(vec![ControlRoute::new(format!("{ip}/32"), 0)]);
            Reason::UnauthorizedRouteAdvertisement
        }
        "wrong-membership-tag" => {
            caps.membership_tag = Some(previous_tag.into());
            Reason::MembershipMismatch
        }
        "rotated-membership-tag" => {
            caps.membership_tag = Some(p2p_vpn::config::membership_tag(
                &caps.network_name,
                &[2; 32],
            ));
            Reason::MembershipMismatch
        }
        _ => return None,
    };
    Some((caps, reason))
}

async fn direct_listener(
    swarm: &mut Swarm<Behaviour>,
    ip: &str,
) -> Result<(libp2p::core::transport::ListenerId, Multiaddr)> {
    let host = match ip.parse::<std::net::IpAddr>()? {
        std::net::IpAddr::V4(ip) => Protocol::Ip4(ip),
        std::net::IpAddr::V6(ip) => Protocol::Ip6(ip),
    };
    let expected = swarm.listen_on(
        Multiaddr::empty()
            .with(host)
            .with(Protocol::Udp(0))
            .with(Protocol::WebRTCDirect),
    )?;
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } if listener_id == expected => {
                return Ok((listener_id, address));
            }
            SwarmEvent::ListenerError { listener_id, error } if listener_id == expected => {
                return Err(error.into());
            }
            _ => {}
        }
    }
}

struct Fixture {
    swarm: Swarm<Behaviour>,
    peer: PeerId,
    relay_peer: Option<PeerId>,
    expected_path: PathKind,
    forwarder: Forwarder,
    caps: ControlCapabilities,
    records_to_serve: Vec<SignedMembershipRecord>,
    report_revocation: bool,
    membership_pages_served: usize,
    capture_recovery_probe: bool,
    recovery_probe: Option<(
        request_response::InboundRequestId,
        request_response::ResponseChannel<PacketResponse>,
    )>,
    abandoned_probe: Option<request_response::InboundRequestId>,
}

impl Fixture {
    async fn exchange_capabilities(&mut self, deny: bool) -> Result<ConnectionId> {
        let (connection, advertised) = loop {
            if let BehaviourEvent::Control(request_response::Event::Message {
                connection_id,
                message:
                    Message::Request {
                        request, channel, ..
                    },
                ..
            }) = self.next().await?
            {
                let ControlRequest::Capabilities(advertised) = request else {
                    return Err("first browser control request was not capabilities".into());
                };
                let reason = control::validate_capabilities(
                    &advertised,
                    &self.caps.network_name,
                    self.caps.membership_tag.as_deref(),
                    &[],
                );
                assert_eq!(reason, None);
                assert_eq!(advertised.preferred_path, self.expected_path.wire_name());
                assert!(
                    self.forwarder
                        .authorizes_advertised_routes(self.peer, &advertised.advertised_routes)
                );
                let response = if deny {
                    ControlResponse::CapabilitiesRejected(ControlRejectionReason::WrongNetwork)
                } else {
                    ControlResponse::CapabilitiesAccepted(self.caps.clone())
                };
                self.swarm
                    .behaviour_mut()
                    .control
                    .send_response(channel, response)
                    .map_err(debug_error)?;
                if deny {
                    return Ok(connection_id);
                }
                break (connection_id, advertised);
            }
        };
        // Do not begin the probes until the native-initiated exchange succeeds too.
        let response = self.send_capabilities(self.caps.clone()).await?;
        if self.caps.supports_membership_record_pages {
            assert!(matches!(response, ControlResponse::CapabilitiesAccepted(_)));
        } else {
            assert_eq!(response, ControlResponse::CapabilitiesAccepted(advertised));
        }
        Ok(connection)
    }

    async fn preferred_return(&mut self, relay: ConnectionId) -> Result<()> {
        let mut candidates = Vec::new();
        let mut relay_packets = 0;
        let mut direct_packets = 0;
        let mut obsolete_probe = None;
        let mut draining_packet = None;
        let mut confirmed = None;
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    connection_id,
                    endpoint,
                    ..
                } if peer_id == self.peer => {
                    assert!(!endpoint.is_relayed());
                    candidates.push(connection_id);
                }
                SwarmEvent::Behaviour(BehaviourEvent::Control(
                    request_response::Event::Message {
                        peer,
                        connection_id,
                        message:
                            Message::Request {
                                request: ControlRequest::Capabilities(caps),
                                channel,
                                ..
                            },
                    },
                )) if peer == self.peer => {
                    assert_eq!(Some(&connection_id), candidates.last());
                    assert_eq!(
                        control::validate_capabilities(
                            &caps,
                            &self.caps.network_name,
                            self.caps.membership_tag.as_deref(),
                            &[],
                        ),
                        None
                    );
                    assert!(
                        self.forwarder
                            .authorizes_advertised_routes(peer, &caps.advertised_routes)
                    );
                    assert_eq!(
                        caps.preferred_path,
                        PathKind::DirectWebRtcStream.wire_name()
                    );
                    let mut own = self.caps.clone();
                    if candidates.len() == 1 {
                        own.network_name = "wrong-network".into();
                    }
                    self.swarm
                        .behaviour_mut()
                        .control
                        .send_response(channel, ControlResponse::CapabilitiesAccepted(own))
                        .map_err(debug_error)?;
                }
                SwarmEvent::Behaviour(BehaviourEvent::Packet(
                    request_response::Event::Message {
                        peer,
                        connection_id,
                        message:
                            Message::Request {
                                request, channel, ..
                            },
                    },
                )) if peer == self.peer => {
                    self.forwarder
                        .accept_inbound_stream_frame(peer, &request)
                        .map_err(debug_error)?;
                    match request.header.payload_type {
                        PayloadType::PathProbe => {
                            assert_eq!(Some(&connection_id), candidates.last());
                            assert_eq!(request.payload.len(), usize::from(NATIVE_MTU));
                            assert!(request.payload.starts_with(b"path-probe-v1"));
                            match candidates.len() {
                                2 => {
                                    obsolete_probe = Some(channel);
                                }
                                3 => {
                                    confirmed = Some(connection_id);
                                    self.swarm
                                        .behaviour_mut()
                                        .packet
                                        .send_response(channel, PacketResponse::Accepted)
                                        .map_err(debug_error)?;
                                }
                                _ => return Err("unexpected candidate packet probe".into()),
                            }
                        }
                        PayloadType::IpPacket if connection_id == relay => {
                            relay_packets += 1;
                            if relay_packets == 4 {
                                // This legitimate request is still on the relay
                                // when the candidate becomes active.
                                draining_packet = Some(channel);
                            } else {
                                self.swarm
                                    .behaviour_mut()
                                    .packet
                                    .send_response(channel, PacketResponse::Accepted)
                                    .map_err(debug_error)?;
                            }
                        }
                        PayloadType::IpPacket => {
                            assert_eq!(confirmed, Some(connection_id));
                            direct_packets += 1;
                            let old = draining_packet
                                .take()
                                .expect("in-flight relay packet survived promotion");
                            self.swarm
                                .behaviour_mut()
                                .packet
                                .send_response(old, PacketResponse::Accepted)
                                .map_err(debug_error)?;
                            self.swarm
                                .behaviour_mut()
                                .packet
                                .send_response(channel, PacketResponse::Accepted)
                                .map_err(debug_error)?;
                        }
                        other => {
                            return Err(
                                format!("unexpected preferred return payload: {other:?}").into()
                            );
                        }
                    }
                }
                SwarmEvent::ConnectionClosed {
                    peer_id,
                    connection_id,
                    ..
                } if peer_id == self.peer && connection_id == relay => {
                    assert_eq!(candidates.len(), 3);
                    assert!(obsolete_probe.is_some());
                    assert!(confirmed.is_some());
                    assert_eq!(relay_packets, 4);
                    assert_eq!(direct_packets, 1);
                    println!(
                        "{}",
                        json!({
                            "obsolete_probe_held": true,
                            "relay_packets": relay_packets,
                            "direct_packets": direct_packets,
                            "relay_drained": true,
                        })
                    );
                    return Ok(());
                }
                _ => {}
            }
        }
    }

    async fn request_membership_page(&mut self, network: &str) -> Result<ControlResponse> {
        let expected = self.swarm.behaviour_mut().control.send_request(
            &self.peer,
            ControlRequest::MembershipRecords(MembershipRecordsRequest::first(network, None)),
        );
        loop {
            if let BehaviourEvent::Control(request_response::Event::Message {
                message:
                    Message::Response {
                        request_id,
                        response,
                    },
                ..
            }) = self.next().await?
            {
                assert_eq!(request_id, expected);
                return Ok(response);
            }
        }
    }

    fn capture_packet_probe(&mut self, event: BehaviourEvent) {
        if let BehaviourEvent::Packet(request_response::Event::Message {
            message:
                Message::Request {
                    request_id,
                    request,
                    channel,
                },
            ..
        }) = event
        {
            assert!(self.capture_recovery_probe && self.recovery_probe.is_none());
            assert_eq!(request.header.payload_type, PayloadType::Keepalive);
            self.recovery_probe = Some((request_id, channel));
        }
    }

    async fn send_capabilities(&mut self, caps: ControlCapabilities) -> Result<ControlResponse> {
        let expected = self
            .swarm
            .behaviour_mut()
            .control
            .send_request(&self.peer, ControlRequest::Capabilities(caps));
        loop {
            match self.next().await? {
                BehaviourEvent::Control(request_response::Event::Message {
                    message:
                        Message::Response {
                            request_id,
                            response,
                        },
                    ..
                }) => {
                    assert_eq!(request_id, expected);
                    return Ok(response);
                }
                event => self.capture_packet_probe(event),
            }
        }
    }

    async fn send_packet(&mut self, frame: Frame) -> Result<PacketResponse> {
        let expected = self
            .swarm
            .behaviour_mut()
            .packet
            .send_request(&self.peer, frame);
        loop {
            if let BehaviourEvent::Packet(request_response::Event::Message {
                message:
                    Message::Response {
                        request_id,
                        response,
                    },
                ..
            }) = self.next().await?
            {
                assert_eq!(request_id, expected);
                return Ok(response);
            }
        }
    }

    async fn send_status(&mut self, request: ServiceStatusRequest) -> Result<ServiceResponse> {
        let expected = self
            .swarm
            .behaviour_mut()
            .service
            .send_request(&self.peer, ServiceRequest::Status(request));
        loop {
            if let BehaviourEvent::Service(request_response::Event::Message {
                message:
                    Message::Response {
                        request_id,
                        response,
                    },
                ..
            }) = self.next().await?
            {
                assert_eq!(request_id, expected);
                return Ok(response);
            }
        }
    }

    async fn next(&mut self) -> Result<BehaviourEvent> {
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::Behaviour(BehaviourEvent::Control(
                    request_response::Event::Message {
                        peer,
                        message:
                            Message::Request {
                                request: ControlRequest::MembershipRecords(request),
                                channel,
                                ..
                            },
                        ..
                    },
                )) if self.caps.supports_membership_record_pages => {
                    assert_eq!(peer, self.peer);
                    let page = control::build_membership_records_page(
                        &request,
                        &self.records_to_serve,
                        &self.caps.network_name,
                        None,
                        &[],
                    )
                    .map_err(debug_error)?;
                    self.swarm
                        .behaviour_mut()
                        .control
                        .send_response(channel, ControlResponse::MembershipRecordsPage(page))
                        .map_err(debug_error)?;
                    self.membership_pages_served += 1;
                    if self.report_revocation && self.membership_pages_served == 1 {
                        println!("{}", json!({ "revocation_sent": true }));
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Packet(
                    request_response::Event::InboundFailure {
                        request_id,
                        error:
                            request_response::InboundFailure::ConnectionClosed
                            | request_response::InboundFailure::ResponseOmission,
                        ..
                    },
                )) if self.abandoned_probe == Some(request_id) => {
                    self.abandoned_probe = None;
                }
                SwarmEvent::Behaviour(event) => {
                    let peer = match &event {
                        BehaviourEvent::Control(request_response::Event::Message {
                            peer, ..
                        })
                        | BehaviourEvent::Packet(request_response::Event::Message {
                            peer, ..
                        })
                        | BehaviourEvent::Service(request_response::Event::Message {
                            peer, ..
                        }) => *peer,
                        BehaviourEvent::Control(request_response::Event::ResponseSent {
                            ..
                        })
                        | BehaviourEvent::Packet(request_response::Event::ResponseSent {
                            ..
                        })
                        | BehaviourEvent::Relay(_)
                        | BehaviourEvent::Mdns(_) => continue,
                        _ => return Err(debug_error(event).into()),
                    };
                    assert_eq!(peer, self.peer);
                    return Ok(event);
                }
                SwarmEvent::ConnectionEstablished {
                    peer_id, endpoint, ..
                } if Some(peer_id) != self.relay_peer => {
                    assert_eq!(peer_id, self.peer);
                    assert_eq!(
                        endpoint.is_relayed(),
                        self.expected_path == PathKind::CircuitRelay
                    );
                }
                SwarmEvent::IncomingConnectionError { error, .. } => return Err(error.into()),
                SwarmEvent::ConnectionClosed { peer_id, cause, .. }
                    if Some(peer_id) != self.relay_peer =>
                {
                    return Err(format!("connection to {peer_id} closed: {cause:?}").into());
                }
                _ => {}
            }
        }
    }
}

fn ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
    let mut bytes = vec![0; 28];
    let mut packet = Ipv4Packet::new_unchecked(bytes.as_mut_slice());
    packet.set_version(4);
    packet.set_header_len(20);
    packet.set_total_len(28);
    packet.set_hop_limit(64);
    packet.set_next_header(IpProtocol::Icmp);
    packet.set_src_addr(source);
    packet.set_dst_addr(destination);
    packet.fill_checksum();
    // ICMP echo request (type 8) with a valid checksum and no echo data.
    packet
        .payload_mut()
        .copy_from_slice(&[8, 0, 0xf7, 0xff, 0, 0, 0, 0]);
    bytes
}

fn debug_error(error: impl std::fmt::Debug) -> std::io::Error {
    std::io::Error::other(format!("{error:?}"))
}
