#[cfg(feature = "test-hooks")]
use std::net::Ipv4Addr;
use std::{collections::HashSet, net::IpAddr, time::Duration};

use futures::{FutureExt, StreamExt};
use gloo_timers::future::TimeoutFuture;
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, identify,
    multiaddr::Protocol,
    ping, request_response,
    swarm::{NetworkBehaviour, SwarmEvent, dial_opts::DialOpts},
};
use p2p_vpn::{
    PathKind,
    config::Config,
    dns::{DnsRecordSet, DnsZone},
    membership::SignedMembershipRecord,
    queue::PeerQueues,
    route::{builtin_ipv4, builtin_ipv6},
    runtime::{
        control::{
            self, ControlCapabilities, ControlRejectionReason, ControlRequest, ControlResponse,
            MembershipRecordsRejectionReason, MembershipRecordsRequest, MembershipSnapshot,
        },
        forward::{Forwarder, InboundStreamFrame},
        packet::{self, PacketRejectionReason, PacketResponse},
        service::{self, ServiceRequest},
    },
};
use serde::Serialize;
use wasm_bindgen::prelude::*;
use web_time::Instant;

use crate::{
    membership_store::MembershipStore,
    net::{HttpConnection, IpDevice, MIN_IPV4_MTU},
};

const MAX_MEMBER_ENDPOINTS: usize = 8;

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

struct MembershipSync {
    request_id: request_response::OutboundRequestId,
    request: MembershipRecordsRequest,
    advertised_total: Option<u16>,
    pages: MembershipSnapshot,
    deadline: Instant,
    restarts: u8,
}

/// An actual p2p-vpn peer, driven by browser WebRTC and the browser event loop.
/// The foreground API permits one operation at a time and bounds each operation.
#[wasm_bindgen]
pub struct BrowserVpn {
    config: Config,
    dial_addresses: Vec<Multiaddr>,
    peer: PeerId,
    swarm: Swarm<Behaviour>,
    forwarder: Forwarder,
    stream_mtu: Option<u16>,
    path_recovery_needed: bool,
    membership_sync: Option<MembershipSync>,
    synced_snapshot: Option<String>,
    membership_store: Option<MembershipStore>,
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
        let (address, peer) = parse_member_endpoint(dial_address)?;
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
            dial_addresses: vec![address],
            peer,
            swarm,
            forwarder,
            stream_mtu: None,
            path_recovery_needed: false,
            membership_sync: None,
            synced_snapshot: None,
            membership_store: None,
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

    /// Serialize only the routing inputs a local discovery host needs. An empty
    /// peer selects the sole authorized member when there is exactly one.
    pub fn discovery_query(config_json: &str, peer: &str) -> Result<String, JsError> {
        let config: Config = serde_json::from_str(config_json)?;
        let forwarder = Forwarder::from_config(&config).map_err(debug_error)?;
        let peer = if peer.is_empty() {
            let mut members = forwarder.configured_transport_peers();
            let sole = members
                .next()
                .ok_or_else(|| JsError::new("No authorized overlay peers to discover"))?;
            if members.next().is_some() {
                return Err(JsError::new("Select a peer ID from this network"));
            }
            sole
        } else {
            peer.parse().map_err(debug_error)?
        };
        if !forwarder.is_configured_transport_peer(peer) {
            return Err(JsError::new(
                "Discovery target is not an authorized overlay peer",
            ));
        }
        let discovery = &config.network.discovery;
        Ok(serde_json::json!({
            "network_name": config.network.name,
            "membership_tag": config.membership_tag().map_err(debug_error)?,
            "peer": peer.to_string(),
            "kademlia_protocol": discovery.kademlia_protocol,
            "bootstrap": config.network.bootstrap_peers,
            "kademlia": discovery.kademlia,
            "lan": discovery.mdns,
        })
        .to_string())
    }

    /// Replace dial hints for the already pinned peer. Hints never grant authority.
    pub fn set_member_endpoints(&mut self, addresses_json: &str) -> Result<(), JsError> {
        if addresses_json.len() > MAX_MEMBER_ENDPOINTS * 1024 {
            return Err(JsError::new("Member endpoint list exceeds its byte limit"));
        }
        let values: Vec<String> = serde_json::from_str(addresses_json)?;
        if values.is_empty() || values.len() > MAX_MEMBER_ENDPOINTS {
            return Err(JsError::new(
                "Expected between one and eight member endpoints",
            ));
        }
        let mut addresses = Vec::with_capacity(values.len());
        for value in &values {
            let (address, peer) = parse_member_endpoint(value)?;
            if peer != self.peer {
                return Err(JsError::new(
                    "Member endpoint does not match the pinned peer",
                ));
            }
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        self.dial_addresses = addresses;
        Ok(())
    }

    pub fn snapshot(&self) -> String {
        serde_json::json!({
            "local_peer_id": self.local_peer_id(),
            "remote_peer_id": self.peer.to_string(),
            "transport": "webrtc-direct",
            "authorized": self.stream_mtu.is_some(),
            "stream_mtu": self.stream_mtu,
            "path_recovery_needed": self.path_recovery_needed,
            "membership_snapshot": self.synced_snapshot,
            "counters": self.counters,
        })
        .to_string()
    }

    /// Resolve only within the configured overlay. Never queries the browser's resolver.
    pub async fn resolve_overlay_name(&mut self, name: &str) -> Result<String, JsError> {
        self.open_membership_store().await?;
        self.refresh_peer_authorization()?;
        let records = self.overlay_dns_record(name)?;
        Ok(serde_json::json!({
            "name": records.fqdn,
            "peer_id": records.transport_peer,
            "ipv4": records.ipv4,
            "ipv6": records.ipv6,
        })
        .to_string())
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
            &self.dial_addresses[0].to_string(),
        )?;
        // Replacing the transport must not roll back learned membership or revocations.
        std::mem::swap(&mut replacement.forwarder, &mut self.forwarder);
        std::mem::swap(&mut replacement.dial_addresses, &mut self.dial_addresses);
        replacement.membership_store = self.membership_store.take();
        *self = replacement;
        Ok(())
    }

    pub async fn connect(&mut self) -> Result<String, JsError> {
        self.open_membership_store().await?;
        self.refresh_peer_authorization()?;
        if !self.swarm.is_connected(&self.peer) {
            self.clear_session();
            self.swarm
                .dial(
                    DialOpts::peer_id(self.peer)
                        .addresses(self.dial_addresses.clone())
                        .build(),
                )
                .map_err(|error| {
                    self.path_recovery_needed =
                        matches!(error, libp2p::swarm::DialError::Transport(_));
                    debug_error(error)
                })?;
        }
        let start = Instant::now();
        while self.stream_mtu.is_none() || self.membership_sync.is_some() {
            if start.elapsed() > Duration::from_secs(25) {
                self.clear_session();
                let _ = self.swarm.disconnect_peer_id(self.peer);
                return Err(JsError::new(
                    "WebRTC connection or VPN capability exchange timed out",
                ));
            }
            self.step(None).await?;
        }
        Ok(self.snapshot())
    }

    /// Close the session and wait for site storage to release the identity.
    pub async fn close(&mut self) -> Result<(), JsError> {
        let result = self.reset_connection().await;
        self.clear_session();
        if let Some(store) = self.membership_store.take() {
            store.close().await?;
        }
        result
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
        let remote: IpAddr = match address.parse() {
            Ok(ip) => ip,
            Err(_) => {
                let records = self.overlay_dns_record(address)?;
                records
                    .ipv4
                    .first()
                    .copied()
                    .map(IpAddr::V4)
                    .or_else(|| records.ipv6.first().copied().map(IpAddr::V6))
                    .ok_or_else(|| JsError::new("Overlay hostname has no address"))?
            }
        };
        let local_peer = self.config.local_peer_id().map_err(debug_error)?;
        let configured_ip = self
            .config
            .network
            .vpn_ip
            .as_deref()
            .map(str::parse::<IpAddr>)
            .transpose()
            .map_err(debug_error)?;
        let local = configured_ip
            .filter(|ip| ip.is_ipv4() == remote.is_ipv4())
            .unwrap_or_else(|| match remote {
                IpAddr::V4(_) => builtin_ipv4(local_peer).into(),
                IpAddr::V6(_) => builtin_ipv6(local_peer).into(),
            });
        let mut tcp = HttpConnection::new_ip_with_mtu(local, remote, port, path, mtu)
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
                if peer != self.peer {
                    return Err(JsError::new("Destination uses a different overlay peer"));
                }
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

fn parse_member_endpoint(value: &str) -> Result<(Multiaddr, PeerId), JsError> {
    if value.len() > 1024 {
        return Err(JsError::new("Member endpoint exceeds its byte limit"));
    }
    let address: Multiaddr = value.parse().map_err(debug_error)?;
    let mut parts = address.iter();
    if !matches!(parts.next(), Some(Protocol::Ip4(_) | Protocol::Ip6(_)))
        || !matches!(parts.next(), Some(Protocol::Udp(port)) if port > 0)
        || parts.next() != Some(Protocol::WebRTCDirect)
        || !matches!(parts.next(), Some(Protocol::Certhash(hash)) if hash.code() == 0x12 && hash.size() == 32)
    {
        return Err(JsError::new(
            "Expected an IP WebRTC Direct endpoint with a SHA-256 certificate hash",
        ));
    }
    let Some(Protocol::P2p(peer)) = parts.next() else {
        return Err(JsError::new("Dial address must pin the native peer ID"));
    };
    if parts.next().is_some() {
        return Err(JsError::new(
            "Unexpected protocols after the destination peer ID",
        ));
    }
    Ok((address, peer))
}

fn debug_error(error: impl std::fmt::Debug) -> JsError {
    JsError::new(&format!("{error:?}"))
}

impl BrowserVpn {
    fn overlay_dns_record(&self, name: &str) -> Result<DnsRecordSet, JsError> {
        if name.is_empty() || name.len() > 254 || !name.is_ascii() {
            return Err(JsError::new("Expected a p2p-vpn overlay hostname"));
        }
        let hostnames = self
            .forwarder
            .effective_hostname_records()
            .map_err(debug_error)?;
        let zone = DnsZone::from_config_with_effective_membership_at(
            &self.config,
            self.forwarder.member_records(),
            &hostnames,
            self.forwarder.effective_membership(),
            unix_seconds(),
        )
        .map_err(debug_error)?;
        if zone.conflict(name).is_some() {
            return Err(JsError::new("Overlay hostname has conflicting owners"));
        }
        zone.record(name)
            .cloned()
            .ok_or_else(|| JsError::new("Overlay hostname not found"))
    }

    async fn open_membership_store(&mut self) -> Result<(), JsError> {
        if self.membership_store.is_none() {
            let store =
                MembershipStore::open(&self.config.network.name, &self.local_peer_id()).await?;
            self.forwarder
                .merge_membership_records(&store.load()?, unix_seconds())
                .map_err(debug_error)?;
            self.membership_store = Some(store);
        }
        Ok(())
    }

    fn merge_membership_durably(
        &mut self,
        records: &[SignedMembershipRecord],
    ) -> Result<(), JsError> {
        if records
            .iter()
            .all(|record| self.forwarder.member_records().contains(record))
        {
            self.forwarder
                .merge_membership_records(records, unix_seconds())
                .map_err(debug_error)?;
            return Ok(());
        }
        let (update, _) = self
            .forwarder
            .prepare_legacy_membership_merge(records, unix_seconds())
            .map_err(debug_error)?;
        if update.member_records() != self.forwarder.member_records() {
            self.membership_store
                .as_ref()
                .ok_or_else(|| JsError::new("Membership store is not open"))?
                .save(update.member_records())?;
        }
        self.forwarder
            .try_commit_reconfigure(update)
            .map_err(debug_error)
    }

    fn clear_session(&mut self) {
        self.stream_mtu = None;
        self.membership_sync = None;
        self.path_recovery_needed = false;
    }

    fn lose_transport(&mut self) {
        self.clear_session();
        self.path_recovery_needed = true;
    }

    fn refresh_peer_authorization(&mut self) -> Result<(), JsError> {
        self.forwarder
            .merge_membership_records(&[], unix_seconds())
            .map_err(debug_error)?;
        if self.forwarder.is_configured_transport_peer(self.peer) {
            return Ok(());
        }
        self.clear_session();
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
        .with_advertised_routes(self.forwarder.local_advertised_routes())
        .with_member_records(self.forwarder.advertised_member_records_at(unix_seconds()));
        // Retain the current wire protocol; WebRTC carries its reliable packet streams.
        caps.preferred_path = PathKind::DirectWebRtcStream.wire_name().into();
        caps.supports_membership_record_pages = true;
        let records = self.forwarder.member_records();
        caps.membership_records_snapshot = Some(control::membership_records_snapshot(records));
        caps.membership_record_count = u16::try_from(records.len()).expect("bounded record count");
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
        self.merge_membership_durably(&caps.member_records)
            .map_err(|_| ControlRejectionReason::InvalidMembershipRecord)?;
        self.forwarder
            .merge_hostname_records(&caps.hostname_records)
            .map_err(|_| ControlRejectionReason::InvalidHostnameRecord)?;
        self.forwarder.authorize_peer_capabilities(peer, caps)?;
        self.stream_mtu = Some(mtu);
        self.start_membership_sync(caps);
        Ok(())
    }

    fn start_membership_sync(&mut self, caps: &ControlCapabilities) {
        let Some(snapshot) = caps.membership_records_snapshot.as_ref() else {
            return;
        };
        if !caps.supports_membership_record_pages
            || self.membership_sync.is_some()
            || self.synced_snapshot.as_ref() == Some(snapshot)
            || control::membership_records_snapshot(self.forwarder.member_records()) == *snapshot
        {
            return;
        }
        let request = self.membership_request().next(snapshot.clone(), 0);
        let request_id = self.send_membership_request(&request);
        self.membership_sync = Some(MembershipSync {
            request_id,
            request,
            advertised_total: Some(caps.membership_record_count),
            pages: MembershipSnapshot::default(),
            deadline: Instant::now() + Duration::from_secs(20),
            restarts: 0,
        });
    }

    fn membership_request(&self) -> MembershipRecordsRequest {
        MembershipRecordsRequest::first(
            &self.config.network.name,
            self.config
                .membership_tag()
                .expect("validated at construction"),
        )
    }

    fn send_membership_request(
        &mut self,
        request: &MembershipRecordsRequest,
    ) -> request_response::OutboundRequestId {
        self.swarm.behaviour_mut().control.send_request(
            &self.peer,
            ControlRequest::MembershipRecords(request.clone()),
        )
    }

    fn receive_membership_response(
        &mut self,
        peer: PeerId,
        response: ControlResponse,
        mut sync: MembershipSync,
    ) -> Result<(), JsError> {
        if peer != self.peer || !self.forwarder.authorizes_membership_sync(peer) {
            return Err(JsError::new("unauthorized membership response"));
        }
        let page = match response {
            ControlResponse::MembershipRecordsPage(page) => page,
            ControlResponse::MembershipRecordsRejected(
                MembershipRecordsRejectionReason::SnapshotChanged,
            ) if sync.restarts < 2 => {
                sync.request = self.membership_request();
                sync.advertised_total = None;
                sync.pages = MembershipSnapshot::default();
                sync.restarts += 1;
                sync.request_id = self.send_membership_request(&sync.request);
                self.membership_sync = Some(sync);
                return Ok(());
            }
            response => return Err(debug_error(response)),
        };
        control::validate_membership_records_page(
            &page,
            &sync.request,
            &self.config.network.name,
            self.config
                .membership_tag()
                .expect("validated at construction")
                .as_deref(),
            &self.config.network.previous_membership_tags,
        )
        .map_err(debug_error)?;
        let snapshot = page.snapshot.clone();
        let next = page.next_cursor;
        match sync
            .pages
            .append(page, sync.advertised_total)
            .map_err(debug_error)?
        {
            None => {
                sync.request = sync
                    .request
                    .next(snapshot, next.expect("page has continuation"));
                sync.request_id = self.send_membership_request(&sync.request);
                self.membership_sync = Some(sync);
            }
            Some(records) => {
                self.merge_membership_durably(&records)?;
                self.refresh_peer_authorization()?;
                self.synced_snapshot = Some(snapshot);
            }
        }
        Ok(())
    }

    async fn flush_capability_rejection(
        &mut self,
        peer: PeerId,
        id: request_response::InboundRequestId,
    ) {
        // Keep polling until the typed reply is sent, then close without admitting traffic.
        self.clear_session();
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
        if self
            .membership_sync
            .as_ref()
            .is_some_and(|sync| Instant::now() >= sync.deadline)
        {
            self.clear_session();
            let _ = self.swarm.disconnect_peer_id(self.peer);
            return Err(JsError::new("membership snapshot exchange timed out"));
        }
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
            SwarmEvent::OutgoingConnectionError { error, .. } => {
                if matches!(error, libp2p::swarm::DialError::Transport(_)) {
                    self.lose_transport();
                } else {
                    self.clear_session();
                }
                return Err(debug_error(error));
            }
            SwarmEvent::ConnectionClosed {
                num_established: 0, ..
            } => {
                self.lose_transport();
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
                        ControlRequest::MembershipRecords(request) => {
                            let result = if peer != self.peer
                                || !self.forwarder.authorizes_membership_sync(peer)
                            {
                                Err(MembershipRecordsRejectionReason::UnauthorizedPeer)
                            } else {
                                control::build_membership_records_page(
                                    &request,
                                    self.forwarder.member_records(),
                                    &self.config.network.name,
                                    self.config
                                        .membership_tag()
                                        .expect("validated at construction")
                                        .as_deref(),
                                    &self.config.network.previous_membership_tags,
                                )
                            };
                            match result {
                                Ok(page) => ControlResponse::MembershipRecordsPage(page),
                                Err(reason) => ControlResponse::MembershipRecordsRejected(reason),
                            }
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
                            self.clear_session();
                            let _ = self.swarm.disconnect_peer_id(peer);
                        }
                        return Err(debug_error(reason));
                    }
                    sent.map_err(debug_error)?;
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    let result = if self
                        .membership_sync
                        .as_ref()
                        .is_some_and(|sync| sync.request_id == request_id)
                    {
                        let sync = self.membership_sync.take().expect("matched request");
                        self.receive_membership_response(peer, response, sync)
                    } else {
                        match response {
                            ControlResponse::CapabilitiesAccepted(caps) => {
                                self.admit_capabilities(peer, &caps).map_err(debug_error)
                            }
                            other => Err(debug_error(other)),
                        }
                    };
                    if result.is_err() {
                        self.clear_session();
                        let _ = self.swarm.disconnect_peer_id(peer);
                    }
                    result?;
                }
            },
            SwarmEvent::Behaviour(BehaviourEvent::Control(
                request_response::Event::OutboundFailure { error, .. },
            )) => {
                if transport_failure(&error) {
                    self.lose_transport();
                } else {
                    self.clear_session();
                }
                let _ = self.swarm.disconnect_peer_id(self.peer);
                return Err(debug_error(error));
            }
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
                if transport_failure(&error) {
                    self.lose_transport();
                }
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

fn transport_failure(error: &request_response::OutboundFailure) -> bool {
    matches!(
        error,
        request_response::OutboundFailure::ConnectionClosed
            | request_response::OutboundFailure::DialFailure
    )
}
