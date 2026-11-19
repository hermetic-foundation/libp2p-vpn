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
        control::{
            self, ControlCapabilities, ControlRejectionReason, ControlRequest, ControlResponse,
        },
        forward::{Forwarder, InboundStreamFrame},
        packet::{self, PacketRejectionReason, PacketResponse},
        service::{self, ServiceRequest},
    },
};
use serde::Serialize;
use wasm_bindgen::prelude::*;
use web_time::Instant;

use crate::net::{HttpConnection, IpDevice, MIN_IPV4_MTU};

#[derive(NetworkBehaviour)]
struct Behaviour {
    control: request_response::Behaviour<control::ControlCodec>,
    packet: request_response::Behaviour<packet::PacketCodec>,
    service: request_response::Behaviour<service::ServiceCodec>,
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
    stream_mtu: Option<u16>,
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
        let local_mtu = config.effective_packet_mtu();
        if local_mtu < MIN_IPV4_MTU {
            return Err(JsError::new("browser IPv4 MTU must be at least 68"));
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
                packet: packet::behaviour(local_mtu, 32),
                service: service::inbound_behaviour(8),
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
            stream_mtu: None,
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
            "authorized": self.stream_mtu.is_some(),
            "stream_mtu": self.stream_mtu,
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
        let mut replacement = Self::new(
            &serde_json::to_string(&self.config)?,
            &self.dial_address.to_string(),
        )?;
        // Replacing the transport must not roll back learned membership or revocations.
        std::mem::swap(&mut replacement.forwarder, &mut self.forwarder);
        *self = replacement;
        Ok(())
    }

    pub async fn connect(&mut self) -> Result<String, JsError> {
        self.refresh_peer_authorization()?;
        if !self.swarm.is_connected(&self.peer) {
            self.stream_mtu = None;
            self.swarm
                .dial(self.dial_address.clone())
                .map_err(debug_error)?;
        }
        let start = Instant::now();
        while self.stream_mtu.is_none() {
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
        let mtu = self.stream_mtu.expect("connected stream");
        let remote: Ipv4Addr = address.parse().map_err(debug_error)?;
        let local = match self.config.network.vpn_ip.as_deref() {
            Some(ip) => ip.parse().map_err(debug_error)?,
            None => builtin_ipv4(self.config.local_peer_id().map_err(debug_error)?),
        };
        let mut tcp = HttpConnection::new_with_mtu(local, remote, port, path, mtu)
            .map_err(|e| JsError::new(&e))?;
        let mut queues = PeerQueues::new(128, 128 * 1024);
        let started = Instant::now();
        let mut refresh = Instant::now();
        loop {
            if started.elapsed() > Duration::from_secs(30) {
                return Err(JsError::new("overlay HTTP operation exceeded 30 seconds"));
            }
            if refresh.elapsed() >= Duration::from_secs(1) {
                self.refresh_peer_authorization()?;
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
                    .queued_packet_frame_with_mtu(&packet, mtu)
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
                    self.step(Some(&mut tcp.device)).await?;
                }
                return Ok(response);
            }
            self.step(Some(&mut tcp.device)).await?;
        }
    }

    #[cfg(feature = "test-hooks")]
    pub async fn test_drive_receiver(&mut self) -> Result<String, JsError> {
        self.connect().await?;
        let mut sink = IpDevice::new(self.stream_mtu.expect("connected stream"))
            .map_err(|e| JsError::new(&e))?;
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            self.step(Some(&mut sink)).await?;
        }
        Ok(self.snapshot())
    }
}

fn unix_seconds() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

fn debug_error(error: impl std::fmt::Debug) -> JsError {
    JsError::new(&format!("{error:?}"))
}

impl BrowserVpn {
    fn refresh_peer_authorization(&mut self) -> Result<(), JsError> {
        self.forwarder
            .merge_membership_records(&[], unix_seconds())
            .map_err(debug_error)?;
        if self.forwarder.is_configured_transport_peer(self.peer) {
            return Ok(());
        }
        self.stream_mtu = None;
        let _ = self.swarm.disconnect_peer_id(self.peer);
        Err(JsError::new(
            "native peer membership has expired or been revoked",
        ))
    }

    fn capabilities(&self) -> ControlCapabilities {
        let mut caps = ControlCapabilities::local(
            &self.config.network.name,
            self.config
                .membership_tag()
                .expect("validated at construction"),
            self.config.effective_packet_mtu(),
        )
        .with_advertised_routes(self.forwarder.local_advertised_routes());
        // Retain the current wire protocol; WebRTC carries its reliable packet streams.
        caps.preferred_path = PathKind::DirectWebRtcStream.wire_name().into();
        caps
    }

    fn admit_capabilities(
        &mut self,
        peer: PeerId,
        caps: &ControlCapabilities,
    ) -> Result<(), ControlRejectionReason> {
        if peer != self.peer {
            return Err(ControlRejectionReason::UnauthorizedPeer);
        }
        if let Some(reason) = control::validate_capabilities(
            caps,
            &self.config.network.name,
            self.config
                .membership_tag()
                .expect("validated at construction")
                .as_deref(),
            &self.config.network.previous_membership_tags,
        ) {
            return Err(reason);
        }
        if caps.checkpoint.is_some() {
            return Err(ControlRejectionReason::InvalidMembershipRecord);
        }
        let mtu = self.config.effective_packet_mtu().min(caps.effective_mtu);
        if mtu < MIN_IPV4_MTU {
            return Err(ControlRejectionReason::InvalidEffectiveMtu);
        }
        self.forwarder
            .merge_membership_records(&caps.member_records, unix_seconds())
            .map_err(|_| ControlRejectionReason::InvalidMembershipRecord)?;
        self.forwarder
            .merge_hostname_records(&caps.hostname_records)
            .map_err(|_| ControlRejectionReason::InvalidHostnameRecord)?;
        self.forwarder.authorize_peer_capabilities(peer, caps)?;
        self.stream_mtu = Some(mtu);
        Ok(())
    }

    async fn flush_capability_rejection(
        &mut self,
        peer: PeerId,
        id: request_response::InboundRequestId,
    ) {
        // Keep polling until the typed reply is sent, then close without admitting traffic.
        self.stream_mtu = None;
        {
            let drain = async {
                while let Some(event) = self.swarm.next().await {
                    if matches!(event, SwarmEvent::Behaviour(BehaviourEvent::Control(
                    request_response::Event::ResponseSent { request_id, .. }
                    | request_response::Event::InboundFailure { request_id, .. }
                )) if request_id == id)
                    {
                        break;
                    }
                }
            }
            .fuse();
            let deadline = TimeoutFuture::new(2_000).fuse();
            futures::pin_mut!(drain, deadline);
            futures::select! { () = drain => (), _ = deadline => () };
        }
        let _ = self.swarm.disconnect_peer_id(peer);
    }

    async fn step(&mut self, device: Option<&mut IpDevice>) -> Result<(), JsError> {
        let event = {
            let next = self.swarm.next().fuse();
            let tick = TimeoutFuture::new(5).fuse();
            futures::pin_mut!(next, tick);
            futures::select! { event = next => event, _ = tick => None }
        };
        let Some(event) = event else { return Ok(()) };
        let device_mtu = device.as_ref().map(|device| device.mtu());
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
                self.stream_mtu = None;
                return Err(JsError::new(
                    "WebRTC disconnected; reset the connection and retry",
                ));
            }
            SwarmEvent::Behaviour(BehaviourEvent::Service(request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request: ServiceRequest::Status(request),
                        channel,
                        ..
                    },
                ..
            })) => {
                let response = service::stream_status_response(
                    &request,
                    peer == self.peer && self.forwarder.is_configured_transport_peer(peer),
                    &self.config.network.name,
                    self.config
                        .membership_tag()
                        .expect("validated at construction"),
                    &self.config.network.previous_membership_tags,
                    self.config.effective_packet_mtu(),
                    self.stream_mtu
                        .map(|mtu| (PathKind::DirectWebRtcStream, mtu)),
                );
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .service
                    .send_response(channel, response);
            }
            SwarmEvent::Behaviour(BehaviourEvent::Control(request_response::Event::Message {
                peer,
                message,
                ..
            })) => match message {
                request_response::Message::Request {
                    request_id,
                    request,
                    channel,
                } => {
                    let response = match request {
                        ControlRequest::Capabilities(caps) => match self
                            .admit_capabilities(peer, &caps)
                        {
                            Ok(()) => ControlResponse::CapabilitiesAccepted(self.capabilities()),
                            Err(reason) => ControlResponse::CapabilitiesRejected(reason),
                        },
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
                    let rejected = match &response {
                        ControlResponse::CapabilitiesRejected(reason) => Some(*reason),
                        _ => None,
                    };
                    let sent = self
                        .swarm
                        .behaviour_mut()
                        .control
                        .send_response(channel, response);
                    if let Some(reason) = rejected {
                        if sent.is_ok() {
                            self.flush_capability_rejection(peer, request_id).await;
                        } else {
                            self.stream_mtu = None;
                            let _ = self.swarm.disconnect_peer_id(peer);
                        }
                        return Err(debug_error(reason));
                    }
                    sent.map_err(debug_error)?;
                }
                request_response::Message::Response { response, .. } => {
                    let result = match response {
                        ControlResponse::CapabilitiesAccepted(caps) => {
                            self.admit_capabilities(peer, &caps).map_err(debug_error)
                        }
                        other => Err(debug_error(other)),
                    };
                    if result.is_err() {
                        self.stream_mtu = None;
                        let _ = self.swarm.disconnect_peer_id(peer);
                    }
                    result?;
                }
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
                    let accepted = match self.stream_mtu.filter(|_| peer == self.peer) {
                        None => Err(PacketRejectionReason::UnauthorizedPeer),
                        Some(mtu) if request.payload.len() > usize::from(mtu) => {
                            Err(PacketRejectionReason::PacketTooLarge)
                        }
                        Some(_) => {
                            self.forwarder
                                .accept_inbound_stream_frame(peer, &request)
                                .map_err(|error| PacketRejectionReason::from_forward_error(&error))
                                .and_then(|frame| match frame {
                                    InboundStreamFrame::IpPacket(bytes) => {
                                        let device = device
                                            .ok_or(PacketRejectionReason::UnexpectedPayload)?;
                                        device
                                            .receive_packet(bytes)
                                            .map_err(|_| PacketRejectionReason::RateLimited)?;
                                        self.counters.inbound_ip_packets += 1;
                                        self.counters.inbound_ip_bytes += bytes.len() as u64;
                                        Ok(())
                                    }
                                    InboundStreamFrame::Keepalive
                                    | InboundStreamFrame::PathProbe => Ok(()),
                                })
                        }
                    };
                    let response = match accepted {
                        Ok(()) => PacketResponse::Accepted,
                        Err(reason) => {
                            self.counters.rejected_inbound_packets += 1;
                            PacketResponse::Rejected(reason)
                        }
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
        if device_mtu.is_some() && self.stream_mtu != device_mtu {
            return Err(JsError::new(
                "IPv4 stream MTU changed; retry the HTTP request",
            ));
        }
        Ok(())
    }
}
