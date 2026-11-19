//! Disposable WebRTC Direct peer for tests/receiver.mjs. No TUN or discovery.
use std::{
    net::Ipv4Addr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures::StreamExt;
use libp2p::{
    PeerId, Swarm, SwarmBuilder,
    multiaddr::Protocol,
    request_response::{self, Message},
    swarm::{NetworkBehaviour, SwarmEvent},
};
use p2p_vpn::{
    PathKind,
    config::{Config, RouteConfig},
    identity::NodeIdentity,
    membership::{MembershipRecordOptions, MembershipRole, issue_membership_record_at},
    runtime::{
        control::{
            self, ControlCapabilities, ControlRejectionReason, ControlRequest, ControlResponse,
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

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(NetworkBehaviour)]
struct Behaviour {
    control: request_response::Behaviour<control::ControlCodec>,
    packet: request_response::Behaviour<packet::PacketCodec>,
    service: request_response::Behaviour<service::ServiceCodec>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let wrong_network = match std::env::args().nth(1).as_deref() {
        Some("packets") => false,
        Some("wrong-network") => true,
        _ => return Err("usage: browser-receiver-fixture packets|wrong-network".into()),
    };
    tokio::time::timeout(Duration::from_secs(45), run(wrong_network)).await?
}

async fn run(wrong_network: bool) -> Result<()> {
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
    let native_config = config_for(&native, NATIVE_IP)?;
    let browser_config = config_for(&browser, BROWSER_IP)?;
    let forwarder = Forwarder::from_config(&native_config).map_err(debug_error)?;
    let mut caps = ControlCapabilities::local(
        &network,
        native_config.membership_tag().map_err(debug_error)?,
        NATIVE_MTU,
    )
    .with_advertised_routes(forwarder.local_advertised_routes());
    caps.preferred_path = PathKind::DirectWebRtcStream.wire_name().into();

    let keys = native.keypair().map_err(debug_error)?;
    let certificate = libp2p_webrtc::tokio::Certificate::generate(&mut rand::rngs::OsRng)?;
    let mut swarm = SwarmBuilder::with_existing_identity(keys)
        .with_tokio()
        .with_other_transport(|key| libp2p_webrtc::tokio::Transport::new(key.clone(), certificate))?
        .with_behaviour(|_| Behaviour {
            control: control::behaviour(8),
            packet: packet::behaviour(MTU, 32),
            service: service::behaviour(8),
        })?
        .with_swarm_config(|config| config.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    swarm.listen_on("/ip4/192.0.2.1/udp/0/webrtc-direct".parse()?)?;
    let address = loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => break address,
            SwarmEvent::ListenerError { error, .. } => return Err(error.into()),
            _ => {}
        }
    };
    let peer = browser.peer_id.parse()?;
    println!(
        "{}",
        json!({
            "config": browser_config,
            "dial_address": address.with(Protocol::P2p(*swarm.local_peer_id())).to_string(),
            "native_peer_id": native.peer_id,
        })
    );
    let mut fixture = Fixture {
        swarm,
        peer,
        forwarder,
        caps,
    };
    fixture.exchange_capabilities().await?;
    if wrong_network {
        let mut bad_caps = fixture.caps.clone();
        bad_caps.network_name.push_str("-wrong");
        let response = fixture.send_capabilities(bad_caps).await?;
        assert_eq!(
            response,
            ControlResponse::CapabilitiesRejected(ControlRejectionReason::WrongNetwork)
        );
        println!("{}", json!({"wrong_network": response}));
    } else {
        let mut proof = serde_json::Map::new();
        let valid = Frame::packet(1, 3, ipv4_packet(NATIVE_IP, BROWSER_IP)).map_err(debug_error)?;
        let keepalive = Frame::keepalive(1, 4).map_err(debug_error)?;
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
            (
                "path_probe",
                Frame::path_probe(1, 5, vec![0; usize::from(NATIVE_MTU)]).map_err(debug_error)?,
                PacketResponse::Accepted,
            ),
        ] {
            let actual = fixture.send_packet(frame).await?;
            assert_eq!(actual, expected, "{label}");
            proof.insert(label.into(), json!(format!("{actual:?}")));
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
            json!({"packets": proof, "status": status, "wrong_scope": wrong_scope})
        );
    }

    // Keep the transport alive until the driver has also checked the WASM result.
    // The driver terminates this process; the outer timeout bounds orphaned runs.
    loop {
        fixture.swarm.select_next_some().await;
    }
}

struct Fixture {
    swarm: Swarm<Behaviour>,
    peer: PeerId,
    forwarder: Forwarder,
    caps: ControlCapabilities,
}

impl Fixture {
    async fn exchange_capabilities(&mut self) -> Result<()> {
        let advertised = loop {
            if let BehaviourEvent::Control(request_response::Event::Message {
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
                assert!(
                    self.forwarder
                        .authorizes_advertised_routes(self.peer, &advertised.advertised_routes)
                );
                self.swarm
                    .behaviour_mut()
                    .control
                    .send_response(
                        channel,
                        ControlResponse::CapabilitiesAccepted(self.caps.clone()),
                    )
                    .map_err(debug_error)?;
                break advertised;
            }
        };
        // Do not begin the probes until the native-initiated exchange succeeds too.
        let response = self.send_capabilities(self.caps.clone()).await?;
        assert_eq!(response, ControlResponse::CapabilitiesAccepted(advertised));
        Ok(())
    }

    async fn send_capabilities(&mut self, caps: ControlCapabilities) -> Result<ControlResponse> {
        let expected = self
            .swarm
            .behaviour_mut()
            .control
            .send_request(&self.peer, ControlRequest::Capabilities(caps));
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
                        }) => continue,
                        _ => return Err(debug_error(event).into()),
                    };
                    assert_eq!(peer, self.peer);
                    return Ok(event);
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => assert_eq!(peer_id, self.peer),
                SwarmEvent::IncomingConnectionError { error, .. } => return Err(error.into()),
                SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
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
