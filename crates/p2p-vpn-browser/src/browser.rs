use std::{collections::HashSet, net::Ipv4Addr, time::Duration};

use futures::{FutureExt, StreamExt};
use gloo_timers::future::TimeoutFuture;
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, identify, ping, request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use p2p_vpn::{
    PathKind,
    config::Config,
    queue::PeerQueues,
    route::builtin_ipv4,
    runtime::{
        control::{self, ControlCapabilities, ControlRequest, ControlResponse},
        forward::Forwarder,
        packet::{self, PacketRejectionReason, PacketResponse},
    },
    wire::PayloadType,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;
use web_time::Instant;

use crate::net::{HttpConnection, MTU};

#[derive(NetworkBehaviour)]
struct Behaviour {
    control: request_response::Behaviour<control::ControlCodec>,
    packet: request_response::Behaviour<packet::PacketCodec>,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
}

#[derive(Default, Serialize)]
struct Counters {
    connections: u64,
    outbound_ip_packets: u64,
    inbound_ip_packets: u64,
    outbound_ip_bytes: u64,
    inbound_ip_bytes: u64,
    rejected_inbound_packets: u64,
    accepted_outbound_packets: u64,
}

/// An actual p2p-vpn peer, driven by browser WebRTC and the browser event loop.
/// The foreground API permits one operation at a time and bounds each operation.
#[wasm_bindgen]
pub struct BrowserVpn {
    config: Config,
    dial_address: Multiaddr,
    peer: PeerId,
    swarm: Swarm<Behaviour>,
    forwarder: Forwarder,
    ready: bool,
    counters: Counters,
    pending: HashSet<request_response::OutboundRequestId>,
    #[cfg(feature = "test-hooks")]
    test_request: Option<request_response::OutboundRequestId>,
    #[cfg(feature = "test-hooks")]
    test_response: Option<PacketResponse>,
}

#[wasm_bindgen]
impl BrowserVpn {
    #[wasm_bindgen(constructor)]
    pub fn new(config_json: &str, dial_address: &str) -> Result<BrowserVpn, JsError> {
        console_error_panic_hook::set_once();
        let config: Config = serde_json::from_str(config_json)?;
        if usize::from(config.interface.mtu) != MTU {
            return Err(JsError::new("the browser milestone requires MTU 1280"));
        }
        config.membership_tag().map_err(debug_error)?;
        let identity = config.identity().map_err(debug_error)?;
        let keys = identity.keypair().map_err(debug_error)?;
        let address: Multiaddr = dial_address.parse().map_err(debug_error)?;
        let peer = address
            .iter()
            .find_map(|part| {
                if let libp2p::multiaddr::Protocol::P2p(peer) = part {
                    Some(peer)
                } else {
                    None
                }
            })
            .ok_or_else(|| JsError::new("dial address must pin the native peer ID"))?;
        if !address
            .iter()
            .any(|part| matches!(part, libp2p::multiaddr::Protocol::WebRTCDirect))
        {
            return Err(JsError::new("expected a WebRTC Direct address"));
        }
        let forwarder = Forwarder::from_config(&config).map_err(debug_error)?;
        if !forwarder.is_configured_transport_peer(peer) {
            return Err(JsError::new(
                "native peer is not authorized by this configuration",
            ));
        }
        let swarm = SwarmBuilder::with_existing_identity(keys.clone())
            .with_wasm_bindgen()
            .with_other_transport(|key| {
                libp2p::webrtc_websys::Transport::new(libp2p::webrtc_websys::Config::new(key))
            })
            .map_err(debug_error)?
            .with_behaviour(|_| Behaviour {
                control: control::behaviour(8),
                packet: packet::behaviour(MTU as u16, 32),
                identify: identify::Behaviour::new(identify::Config::new(
                    "/p2p-vpn/0.1.0".into(),
                    keys.public(),
                )),
                ping: ping::Behaviour::default(),
            })
            .map_err(debug_error)?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        Ok(Self {
            config,
            dial_address: address,
            peer,
            swarm,
            forwarder,
            ready: false,
            counters: Counters::default(),
            pending: HashSet::new(),
            #[cfg(feature = "test-hooks")]
            test_request: None,
            #[cfg(feature = "test-hooks")]
            test_response: None,
        })
    }

    pub fn local_peer_id(&self) -> String {
        self.swarm.local_peer_id().to_string()
    }

    pub fn snapshot(&self) -> String {
        serde_json::json!({
            "local_peer_id": self.local_peer_id(),
            "remote_peer_id": self.peer.to_string(),
            "transport": "webrtc-direct",
            "authorized": self.ready,
            "counters": self.counters,
        })
        .to_string()
    }

    /// Drop the old WebRTC connection and start a fresh VPN session with the same identity.
    pub async fn reset_connection(&mut self) -> Result<(), JsError> {
        if self.swarm.is_connected(&self.peer) {
            self.swarm
                .disconnect_peer_id(self.peer)
                .map_err(debug_error)?;
            let started = Instant::now();
            loop {
                if started.elapsed() > Duration::from_secs(5) {
                    return Err(JsError::new(
                        "old WebRTC connection did not close within five seconds",
                    ));
                }
                let event = {
                    let next = self.swarm.next().fuse();
                    let tick = TimeoutFuture::new(5).fuse();
                    futures::pin_mut!(next, tick);
                    futures::select! { event = next => event, _ = tick => None }
                };
                if matches!(event, Some(SwarmEvent::ConnectionClosed { peer_id, num_established: 0, .. }) if peer_id == self.peer)
                {
                    break;
                }
            }
        }
        let replacement = Self::new(
            &serde_json::to_string(&self.config)?,
            &self.dial_address.to_string(),
        )?;
        *self = replacement;
        Ok(())
    }

    pub async fn connect(&mut self) -> Result<String, JsError> {
        self.forwarder
            .merge_membership_records(&[], unix_seconds())
            .map_err(debug_error)?;
        if !self.forwarder.is_configured_transport_peer(self.peer) {
            return Err(JsError::new(
                "native peer membership has expired or been revoked",
            ));
        }
        if !self.swarm.is_connected(&self.peer) {
            self.ready = false;
            self.swarm
                .dial(self.dial_address.clone())
                .map_err(debug_error)?;
        }
        let start = Instant::now();
        while !self.ready {
            if start.elapsed() > Duration::from_secs(25) {
                return Err(JsError::new(
                    "WebRTC connection or VPN capability exchange timed out",
                ));
            }
            self.step(None).await?;
        }
        Ok(self.snapshot())
    }

    #[cfg(feature = "test-hooks")]
    pub async fn test_spoofed_source(&mut self, destination: &str) -> Result<String, JsError> {
        self.connect().await?;
        let destination: Ipv4Addr = destination.parse().map_err(debug_error)?;
        let mut bytes = vec![0; 20];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&20_u16.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&[192, 0, 2, 8]);
        bytes[16..20].copy_from_slice(&destination.octets());
        let frame = p2p_vpn::wire::Frame::packet(0xBAD, 0, bytes).map_err(debug_error)?;
        self.test_response = None;
        self.test_request = Some(
            self.swarm
                .behaviour_mut()
                .packet
                .send_request(&self.peer, frame),
        );
        let started = Instant::now();
        while self.test_response.is_none() {
            if started.elapsed() > Duration::from_secs(12) {
                return Err(JsError::new("spoof test timed out"));
            }
            self.step(None).await?;
        }
        Ok(format!("{:?}", self.test_response.take().unwrap()))
    }

    /// HTTP over TCP/IP packets inside the VPN. Does not use browser fetch or a proxy.
    pub async fn fetch_http(
        &mut self,
        address: &str,
        port: u16,
        path: &str,
    ) -> Result<String, JsError> {
        self.connect().await?;
        let remote: Ipv4Addr = address.parse().map_err(debug_error)?;
        let local = match self.config.network.vpn_ip.as_deref() {
            Some(ip) => ip.parse().map_err(debug_error)?,
            None => builtin_ipv4(self.config.local_peer_id().map_err(debug_error)?),
        };
        let mut tcp =
            HttpConnection::new(local, remote, port, path).map_err(|e| JsError::new(&e))?;
        let mut queues = PeerQueues::new(128, 128 * 1024);
        let started = Instant::now();
        let mut refresh = Instant::now();
        loop {
            if started.elapsed() > Duration::from_secs(30) {
                return Err(JsError::new("overlay HTTP operation exceeded 30 seconds"));
            }
            if refresh.elapsed() >= Duration::from_secs(1) {
                self.forwarder
                    .merge_membership_records(&[], unix_seconds())
                    .map_err(debug_error)?;
                refresh = Instant::now();
            }
            let response = tcp
                .poll(started.elapsed().as_millis() as i64)
                .map_err(|e| JsError::new(&e))?;
            while let Some(packet) = tcp.device.take_packet() {
                self.forwarder
                    .enqueue_tun_packet(&mut queues, packet)
                    .map_err(debug_error)?;
            }
            while self.pending.len() < 32 {
                let Some(packet) = queues.dequeue() else {
                    break;
                };
                let frame = self
                    .forwarder
                    .queued_packet_frame_with_mtu(&packet, MTU as u16)
                    .map_err(debug_error)?;
                let peer = self
                    .forwarder
                    .transport_peer_for_overlay(packet.peer())
                    .ok_or_else(|| JsError::new("queued peer lost authorization"))?;
                self.counters.outbound_ip_packets += 1;
                self.counters.outbound_ip_bytes += frame.payload.len() as u64;
                self.pending
                    .insert(self.swarm.behaviour_mut().packet.send_request(&peer, frame));
            }
            if let Some(response) = response {
                let flush = Instant::now();
                while !self.pending.is_empty() && flush.elapsed() < Duration::from_secs(2) {
                    self.step(Some(&mut tcp)).await?;
                }
                return Ok(response);
            }
            self.step(Some(&mut tcp)).await?;
        }
    }
}

fn unix_seconds() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

fn debug_error(error: impl std::fmt::Debug) -> JsError {
    JsError::new(&format!("{error:?}"))
}

impl BrowserVpn {
    fn capabilities(&self) -> ControlCapabilities {
        let mut caps = ControlCapabilities::local(
            &self.config.network.name,
            self.config
                .membership_tag()
                .expect("validated at construction"),
            MTU as u16,
        )
        .with_advertised_routes(self.forwarder.local_advertised_routes());
        // Retain the current wire protocol; WebRTC carries its reliable packet streams.
        caps.preferred_path = PathKind::DirectWebRtcStream.wire_name().into();
        caps
    }

    fn validate_capabilities(
        &self,
        peer: PeerId,
        caps: &ControlCapabilities,
    ) -> Result<(), JsError> {
        if peer != self.peer || !self.forwarder.is_configured_transport_peer(peer) {
            return Err(JsError::new("unauthorized capability sender"));
        }
        if caps.checkpoint.is_some() {
            return Err(JsError::new(
                "cooperative checkpoint enrollment is outside this browser milestone",
            ));
        }
        if let Some(reason) = control::validate_capabilities(
            caps,
            &self.config.network.name,
            self.config
                .membership_tag()
                .map_err(debug_error)?
                .as_deref(),
            &self.config.network.previous_membership_tags,
        ) {
            return Err(debug_error(reason));
        }
        if caps.effective_mtu < MTU as u16
            || !self
                .forwarder
                .authorizes_advertised_routes(peer, &caps.advertised_routes)
        {
            return Err(JsError::new(
                "native peer advertised an unauthorized route or incompatible MTU",
            ));
        }
        Ok(())
    }

    async fn step(&mut self, mut tcp: Option<&mut HttpConnection>) -> Result<(), JsError> {
        let event = {
            let next = self.swarm.next().fuse();
            let tick = TimeoutFuture::new(5).fuse();
            futures::pin_mut!(next, tick);
            futures::select! { event = next => event, _ = tick => None }
        };
        let Some(event) = event else { return Ok(()) };
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                if peer_id != self.peer {
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return Err(JsError::new("unexpected remote identity"));
                }
                self.counters.connections += 1;
                let caps = self.capabilities();
                self.swarm
                    .behaviour_mut()
                    .control
                    .send_request(&peer_id, ControlRequest::Capabilities(caps));
            }
            SwarmEvent::OutgoingConnectionError { error, .. } => return Err(debug_error(error)),
            SwarmEvent::ConnectionClosed {
                num_established: 0, ..
            } => {
                self.ready = false;
                return Err(JsError::new(
                    "WebRTC disconnected; reset the connection and retry",
                ));
            }
            SwarmEvent::Behaviour(BehaviourEvent::Control(request_response::Event::Message {
                peer,
                message,
                ..
            })) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    let response = match request {
                        ControlRequest::Capabilities(caps) => {
                            self.validate_capabilities(peer, &caps)?;
                            self.forwarder
                                .merge_membership_records(&caps.member_records, unix_seconds())
                                .map_err(debug_error)?;
                            self.ready = true;
                            ControlResponse::CapabilitiesAccepted(self.capabilities())
                        }
                        ControlRequest::PacketPlaneHello(_) => {
                            ControlResponse::PacketPlaneRejected(
                                control::ControlRejectionReason::UnsupportedPreferredPath,
                            )
                        }
                        ControlRequest::MembershipRecords(_) => {
                            ControlResponse::MembershipRecordsRejected(
                                control::MembershipRecordsRejectionReason::UnsupportedVersion,
                            )
                        }
                    };
                    self.swarm
                        .behaviour_mut()
                        .control
                        .send_response(channel, response)
                        .map_err(debug_error)?;
                }
                request_response::Message::Response { response, .. } => match response {
                    ControlResponse::CapabilitiesAccepted(caps) => {
                        self.validate_capabilities(peer, &caps)?;
                        self.forwarder
                            .merge_membership_records(&caps.member_records, unix_seconds())
                            .map_err(debug_error)?;
                        self.ready = true;
                    }
                    other => return Err(debug_error(other)),
                },
            },
            SwarmEvent::Behaviour(BehaviourEvent::Control(
                request_response::Event::OutboundFailure { error, .. },
            )) => return Err(debug_error(error)),
            SwarmEvent::Behaviour(BehaviourEvent::Packet(request_response::Event::Message {
                peer,
                message,
                ..
            })) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    let accepted = match request.header.payload_type {
                        PayloadType::IpPacket => self
                            .forwarder
                            .accept_inbound_packet(peer, &request)
                            .map_err(|e| format!("{e:?}"))
                            .and_then(|bytes| {
                                let Some(tcp) = tcp.as_mut() else {
                                    return Err("no active TCP socket".into());
                                };
                                tcp.device.receive_packet(bytes)?;
                                self.counters.inbound_ip_packets += 1;
                                self.counters.inbound_ip_bytes += bytes.len() as u64;
                                Ok(())
                            }),
                        kind => self
                            .forwarder
                            .accept_inbound_control_frame(peer, &request, kind)
                            .map_err(|e| format!("{e:?}")),
                    };
                    let response = if accepted.is_ok() {
                        PacketResponse::Accepted
                    } else {
                        self.counters.rejected_inbound_packets += 1;
                        PacketResponse::Rejected(PacketRejectionReason::MalformedPacket)
                    };
                    self.swarm
                        .behaviour_mut()
                        .packet
                        .send_response(channel, response)
                        .map_err(debug_error)?;
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    #[cfg(feature = "test-hooks")]
                    if self.test_request == Some(request_id) {
                        self.test_request = None;
                        self.test_response = Some(response);
                        return Ok(());
                    }
                    self.pending.remove(&request_id);
                    match response {
                        PacketResponse::Accepted => self.counters.accepted_outbound_packets += 1,
                        PacketResponse::Rejected(reason) => return Err(debug_error(reason)),
                    }
                }
            },
            SwarmEvent::Behaviour(BehaviourEvent::Packet(
                request_response::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                self.pending.remove(&request_id);
                return Err(debug_error(error));
            }
            _ => {}
        }
        Ok(())
    }
}
