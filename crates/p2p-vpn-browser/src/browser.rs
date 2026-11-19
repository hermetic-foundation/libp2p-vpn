#[cfg(feature = "test-hooks")]
use std::net::Ipv4Addr;
use std::{collections::HashSet, error::Error, io, net::IpAddr, time::Duration};

use futures::{FutureExt, StreamExt};
use gloo_timers::future::TimeoutFuture;
use libp2p::{
    Multiaddr, PeerId, Swarm,
    core::{ConnectedPoint, transport::TransportError},
    identify,
    multiaddr::Protocol,
    ping, request_response,
    swarm::{
        ConnectionId, DialError, NetworkBehaviour, SwarmEvent, behaviour::toggle::Toggle,
        dial_opts::DialOpts,
    },
};
use p2p_vpn::{
    PathKind,
    config::Config,
    dns::{DnsRecordSet, DnsZone},
    membership::{
        SignedMembershipRecord,
        checkpoint::{
            MembershipSyncState, NetworkAnchor, NetworkCapability, RetainedCheckpointState,
            SnapshotRank,
        },
    },
    queue::PeerQueues,
    route::{builtin_ipv4, builtin_ipv6},
    runtime::{
        control::{
            self, ControlCapabilities, ControlRejectionReason, ControlRequest, ControlResponse,
            MembershipRecordsRejectionReason, MembershipRecordsRequest, MembershipSnapshot,
            checkpoint as checkpoint_wire,
        },
        forward::{Forwarder, InboundStreamFrame},
        packet::{self, PacketRejectionReason, PacketResponse},
        service::{self, ServiceRequest},
    },
};
use serde::Serialize;
use wasm_bindgen::prelude::*;
use web_time::Instant;

#[cfg(feature = "relay-client")]
use crate::relay::{RelayRoute, build_transport};
use crate::{
    browser_pairing::BrowserCheckpointActivation,
    checkpoint::{CheckpointBehaviour, CheckpointDriver},
    checkpoint_bundle::{self, Credentials},
    membership_store::{CheckpointBootstrap, CheckpointStore, MembershipStore, StoredCheckpoint},
    net::{HttpConnection, IpDevice, MIN_IPV4_MTU},
};

const MAX_MEMBER_ENDPOINTS: usize = 8;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(25);
const CHECKPOINT_SYNC_TIMEOUT: Duration = Duration::from_secs(50);
#[cfg(feature = "relay-client")]
const CONNECT_WITH_FALLBACK_TIMEOUT: Duration = Duration::from_secs(40);

mod handoff;
#[cfg(feature = "relay-client")]
mod relay_listener;

#[derive(NetworkBehaviour)]
struct Behaviour {
    limits: handoff::CandidateLimits,
    #[cfg(feature = "relay-client")]
    relay: libp2p::swarm::behaviour::toggle::Toggle<libp2p::relay::client::Behaviour>,
    control: request_response::Behaviour<control::ControlCodec>,
    checkpoint: Toggle<CheckpointBehaviour>,
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

struct BrowserCheckpoint {
    driver: CheckpointDriver,
    store: Option<CheckpointStore>,
    secret: Vec<u8>,
    enrollment_floor: Option<SnapshotRank>,
    capability_request: Option<request_response::OutboundRequestId>,
    installed: bool,
    blocked: bool,
    last_error: Option<String>,
}

impl BrowserCheckpoint {
    fn restore_driver(
        config: &Config,
        peer: PeerId,
        anchor: NetworkAnchor,
        secret: &[u8],
        saved: &StoredCheckpoint,
    ) -> Result<CheckpointDriver, JsError> {
        CheckpointDriver::restore(
            config.identity().map_err(debug_error)?,
            peer,
            config.network.name.clone(),
            anchor,
            secret.into(),
            &serde_json::to_vec(&saved.retained)?,
            saved.enrollment_floor,
        )
        .map_err(|error| JsError::new(&error.to_string()))
    }
}

#[derive(Clone)]
struct MemberEndpoints {
    direct: Vec<Multiaddr>,
    #[cfg(feature = "relay-client")]
    relay: Option<RelayRoute>,
}

impl MemberEndpoints {
    fn relay_dial_addr(&self) -> Option<Multiaddr> {
        #[cfg(feature = "relay-client")]
        if let Some(route) = &self.relay {
            return Some(route.dial_addr());
        }
        None
    }

    fn is_relay_hop(&self, _peer: PeerId) -> bool {
        #[cfg(feature = "relay-client")]
        if let Some(route) = &self.relay {
            return route.relay_peer() == _peer;
        }
        false
    }
}

enum MemberDialError {
    Dial(DialError),
    Deadline,
}

/// An actual p2p-vpn peer, driven by browser WebRTC and the browser event loop.
/// The foreground API permits one operation at a time and bounds each operation.
#[wasm_bindgen]
pub struct BrowserVpn {
    config: Config,
    endpoints: MemberEndpoints,
    peer: PeerId,
    swarm: Swarm<Behaviour>,
    #[cfg(feature = "relay-client")]
    relay_reservation: Option<relay_listener::RelayReservation>,
    forwarder: Forwarder,
    stream_mtu: Option<u16>,
    member_connection: Option<ConnectionId>,
    member_path: Option<PathKind>,
    handoff: handoff::Handoff,
    path_recovery_needed: bool,
    membership_sync: Option<MembershipSync>,
    synced_snapshot: Option<String>,
    membership_store: Option<MembershipStore>,
    checkpoint: Option<BrowserCheckpoint>,
    counters: Counters,
    pending: HashSet<request_response::OutboundRequestId>,
    #[cfg(feature = "test-hooks")]
    test_request: Option<request_response::OutboundRequestId>,
    #[cfg(feature = "test-hooks")]
    test_response: Option<PacketResponse>,
}

impl BrowserVpn {
    fn from_endpoints(
        config: Config,
        peer: PeerId,
        endpoints: MemberEndpoints,
    ) -> Result<Self, JsError> {
        config.membership_tag().map_err(debug_error)?;
        let forwarder = Forwarder::from_config(&config).map_err(debug_error)?;
        if !forwarder.is_configured_transport_peer(peer) {
            return Err(JsError::new(
                "native peer is not authorized by this configuration",
            ));
        }
        Self::build(config, peer, endpoints, forwarder, false)
    }

    fn build(
        config: Config,
        peer: PeerId,
        endpoints: MemberEndpoints,
        forwarder: Forwarder,
        checkpoint_enabled: bool,
    ) -> Result<Self, JsError> {
        console_error_panic_hook::set_once();
        let local_mtu = config.effective_packet_mtu();
        if local_mtu < MIN_IPV4_MTU {
            return Err(JsError::new("browser IPv4 MTU must be at least 68"));
        }
        let keys = config
            .identity()
            .map_err(debug_error)?
            .keypair()
            .map_err(debug_error)?;
        let direct_transport = || {
            libp2p::webrtc_websys::Transport::new(libp2p::webrtc_websys::Config::new(&keys)).boxed()
        };
        #[cfg(feature = "relay-client")]
        let (transport, relay) = match &endpoints.relay {
            Some(route) => {
                let (transport, behaviour) = build_transport(&keys, route)?;
                (transport, Some(behaviour))
            }
            None => (direct_transport(), None),
        };
        #[cfg(not(feature = "relay-client"))]
        let transport = direct_transport();
        let swarm = Swarm::new(
            transport,
            Behaviour {
                limits: handoff::CandidateLimits::new(),
                #[cfg(feature = "relay-client")]
                relay: relay.into(),
                control: control::behaviour(8),
                checkpoint: Toggle::from(checkpoint_enabled.then(|| checkpoint_wire::behaviour(8))),
                packet: packet::behaviour(local_mtu, 32),
                service: service::inbound_behaviour(8),
                identify: identify::Behaviour::new(identify::Config::new(
                    "/p2p-vpn/0.1.0".into(),
                    keys.public(),
                )),
                ping: ping::Behaviour::default(),
            },
            keys.public().to_peer_id(),
            libp2p::swarm::Config::with_wasm_executor()
                .with_idle_connection_timeout(Duration::from_secs(60)),
        );
        Ok(Self {
            config,
            endpoints,
            peer,
            swarm,
            #[cfg(feature = "relay-client")]
            relay_reservation: None,
            forwarder,
            stream_mtu: None,
            member_connection: None,
            member_path: None,
            handoff: handoff::Handoff::default(),
            path_recovery_needed: false,
            membership_sync: None,
            synced_snapshot: None,
            membership_store: None,
            checkpoint: None,
            counters: Counters::default(),
            pending: HashSet::new(),
            #[cfg(feature = "test-hooks")]
            test_request: None,
            #[cfg(feature = "test-hooks")]
            test_response: None,
        })
    }

    async fn open_checkpoint_at(
        config: Config,
        peer: PeerId,
        endpoints: MemberEndpoints,
        bootstrap_json: &str,
        capability_secret: Vec<u8>,
    ) -> Result<Self, JsError> {
        if !config.network.member_records.is_empty()
            || config.network.membership_key.is_some()
            || !config.network.previous_membership_tags.is_empty()
        {
            return Err(JsError::new(
                "Checkpoint bootstrap cannot use legacy membership credentials",
            ));
        }
        let identity = config.identity().map_err(debug_error)?;
        let bootstrap = CheckpointBootstrap::parse(bootstrap_json)?;
        let invalid = || JsError::new("Invalid checkpoint bootstrap or saved state");
        let capability =
            NetworkCapability::from_secret(bootstrap.anchor.clone(), Some(&capability_secret))
                .map_err(|_| invalid())?;
        let seed =
            RetainedCheckpointState::decode(&serde_json::to_vec(&bootstrap.retained)?, &capability)
                .map_err(|_| invalid())?;
        let seed_rank = seed.snapshot.payload.rank().map_err(|_| invalid())?;
        if let Some(floor) = bootstrap.enrollment_floor {
            floor.validate().map_err(|_| invalid())?;
        }
        let store =
            CheckpointStore::open(&config.network.name, &identity.peer_id, &capability_secret)
                .await?;
        let mut saved = store.load().await?.unwrap_or(StoredCheckpoint {
            retained: seed,
            enrollment_floor: None,
        });
        if saved
            .retained
            .snapshot
            .payload
            .rank()
            .map_err(|_| invalid())?
            < seed_rank
        {
            return Err(JsError::new(
                "Saved checkpoint is older than the trusted bootstrap",
            ));
        }
        saved.enrollment_floor = saved.enrollment_floor.max(bootstrap.enrollment_floor);
        let driver = BrowserCheckpoint::restore_driver(
            &config,
            peer,
            bootstrap.anchor,
            &capability_secret,
            &saved,
        )?;
        let forwarder = Forwarder::from_checkpoint_config(
            &config,
            driver.state(),
            driver.anchor(),
            unix_seconds(),
        )
        .map_err(debug_error)?;
        let mut vpn = Self::build(config, peer, endpoints, forwarder, true)?;
        let enrollment_floor = saved.enrollment_floor;
        store.save(saved).await?;
        vpn.checkpoint = Some(BrowserCheckpoint {
            driver,
            store: Some(store),
            secret: capability_secret,
            enrollment_floor,
            capability_request: None,
            installed: false,
            blocked: false,
            last_error: None,
        });
        Ok(vpn)
    }

    async fn dial_member(
        &mut self,
        addresses: Vec<Multiaddr>,
        deadline: Instant,
    ) -> Result<(ConnectionId, ConnectedPoint), MemberDialError> {
        let opts = DialOpts::peer_id(self.peer).addresses(addresses).build();
        let dial_id = opts.connection_id();
        self.swarm.dial(opts).map_err(MemberDialError::Dial)?;
        let wait = async {
            loop {
                match self.swarm.select_next_some().await {
                    SwarmEvent::ConnectionEstablished {
                        connection_id,
                        endpoint,
                        ..
                    } if connection_id == dial_id => return Ok((connection_id, endpoint)),
                    SwarmEvent::OutgoingConnectionError {
                        connection_id,
                        error,
                        ..
                    } if connection_id == dial_id => return Err(MemberDialError::Dial(error)),
                    event => {
                        // Retire any stale preferred dial even during recovery.
                        let _ = self.on_handoff_event(&event);
                    }
                }
            }
        }
        .fuse();
        let timeout = TimeoutFuture::new(
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis() as u32,
        )
        .fuse();
        futures::pin_mut!(wait, timeout);
        futures::select! { result = wait => result, _ = timeout => Err(MemberDialError::Deadline) }
    }

    fn member_connected(
        &mut self,
        connection: ConnectionId,
        endpoint: &ConnectedPoint,
    ) -> Result<(), JsError> {
        self.member_connection = Some(connection);
        self.member_path = Some(if endpoint.is_relayed() {
            PathKind::CircuitRelay
        } else {
            PathKind::DirectWebRtcStream
        });
        self.counters.connections += 1;
        self.send_capabilities()
    }

    fn member_dial_error(&mut self, error: DialError) -> JsError {
        if matches!(&error, DialError::Transport(errors) if !errors.iter().any(|(_, error)| {
            transport_error_causes(error).any(identity_or_policy_denial)
        })) {
            self.lose_transport();
        } else {
            self.clear_session();
        }
        debug_error(error)
    }

    fn connection_timeout(&mut self) -> JsError {
        if self.swarm.is_connected(&self.peer) {
            self.clear_session();
        } else {
            self.lose_transport();
        }
        let _ = self.swarm.disconnect_peer_id(self.peer);
        if let Some(checkpoint) = &self.checkpoint {
            let reason = checkpoint
                .last_error
                .as_deref()
                .unwrap_or("no acceptable authenticated snapshot");
            return JsError::new(&format!(
                "Checkpoint connection or synchronization timed out: {reason}"
            ));
        }
        JsError::new("WebRTC connection or VPN capability exchange timed out")
    }
}

#[wasm_bindgen]
impl BrowserVpn {
    #[wasm_bindgen(constructor)]
    pub fn new(config_json: &str, dial_address: &str) -> Result<BrowserVpn, JsError> {
        let config: Config = serde_json::from_str(config_json)?;
        let (address, peer) = parse_member_endpoint(dial_address)?;
        Self::from_endpoints(
            config,
            peer,
            MemberEndpoints {
                direct: vec![address],
                #[cfg(feature = "relay-client")]
                relay: None,
            },
        )
    }

    /// Use one explicit user- or host-selected relay. An empty direct address is relay-only.
    #[cfg(feature = "relay-client")]
    pub fn with_relay(
        config_json: &str,
        direct_address: &str,
        relay_address: &str,
    ) -> Result<BrowserVpn, JsError> {
        let config = serde_json::from_str(config_json)?;
        let (peer, endpoints) = parse_relay_endpoints(direct_address, relay_address)?;
        Self::from_endpoints(config, peer, endpoints)
    }

    pub fn local_peer_id(&self) -> String {
        self.swarm.local_peer_id().to_string()
    }

    /// Open a WebRTC Direct peer from trusted, locally provisioned checkpoint material.
    pub async fn open_checkpoint(
        config_json: &str,
        dial_address: &str,
        bootstrap_json: &str,
        capability_secret: Vec<u8>,
    ) -> Result<Self, JsError> {
        let (address, peer) = parse_member_endpoint(dial_address)?;
        Self::open_checkpoint_at(
            serde_json::from_str(config_json)?,
            peer,
            MemberEndpoints {
                direct: vec![address],
                #[cfg(feature = "relay-client")]
                relay: None,
            },
            bootstrap_json,
            capability_secret,
        )
        .await
    }

    /// Consume the approved pairing handle and open a gated checkpoint peer.
    /// Call `connect` to fetch and commit the authenticated snapshot.
    pub async fn open_checkpoint_activation(
        activation: BrowserCheckpointActivation,
    ) -> Result<Self, JsError> {
        let inputs = activation.into_inputs()?;
        #[cfg(feature = "relay-client")]
        if inputs.dial_address.contains("/p2p-circuit/") {
            return Self::open_checkpoint_with_relay(
                &inputs.config_json,
                "",
                &inputs.dial_address,
                &inputs.bootstrap_json,
                inputs.capability_secret,
            )
            .await;
        }
        Self::open_checkpoint(
            &inputs.config_json,
            &inputs.dial_address,
            &inputs.bootstrap_json,
            inputs.capability_secret,
        )
        .await
    }

    /// Produce a passphrase-encrypted file for explicit download. Never export
    /// a pending, excluded, closed, or uncommitted checkpoint.
    pub async fn export_checkpoint_credentials(&self, passphrase: &str) -> Result<String, JsError> {
        let unavailable =
            || JsError::new("Connect an authorized checkpoint peer before exporting credentials");
        let checkpoint = self.checkpoint.as_ref().ok_or_else(unavailable)?;
        let state = checkpoint.driver.state();
        if self.stream_mtu.is_none()
            || !checkpoint.installed
            || checkpoint.blocked
            || self.forwarder.checkpoint_sync_state() != Some(MembershipSyncState::Participating)
            || !state
                .snapshot()
                .payload
                .member(&self.peer.to_string())
                .is_some_and(|member| member.active_at(unix_seconds()))
        {
            return Err(unavailable());
        }
        let store = checkpoint.store.as_ref().ok_or_else(unavailable)?;
        let saved = store.load().await?.ok_or_else(unavailable)?;
        if saved.enrollment_floor.is_some() || saved.retained != state.retained() {
            return Err(JsError::new(
                "Saved checkpoint does not match the authorized state",
            ));
        }
        let floor = saved
            .retained
            .snapshot
            .payload
            .rank()
            .map_err(debug_error)?;
        checkpoint_bundle::seal(
            &Credentials {
                config: self.config.clone(),
                bootstrap: CheckpointBootstrap {
                    anchor: checkpoint.driver.anchor().clone(),
                    retained: saved.retained,
                    enrollment_floor: Some(floor),
                },
                capability_secret: checkpoint.secret.clone(),
                direct_addresses: self
                    .endpoints
                    .direct
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                relay_address: self
                    .endpoints
                    .relay_dial_addr()
                    .map(|address| address.to_string()),
            },
            passphrase,
        )
        .await
    }

    /// Open a user-selected encrypted checkpoint bundle. This does not dial or
    /// grant packets. Call `connect` while holding the original identity lock.
    pub async fn import_checkpoint_credentials(
        bundle_json: &str,
        passphrase: &str,
    ) -> Result<Self, JsError> {
        let credentials = checkpoint_bundle::unseal(bundle_json, passphrase).await?;
        let (peer, endpoints) = parse_credential_endpoints(
            &credentials.direct_addresses,
            credentials.relay_address.as_deref(),
        )?;
        if credentials.bootstrap.enrollment_floor.is_none() {
            return Err(JsError::new(
                "Checkpoint credential bundle is missing its authority floor",
            ));
        }
        Self::open_checkpoint_at(
            credentials.config,
            peer,
            endpoints,
            &serde_json::to_string(&credentials.bootstrap)?,
            credentials.capability_secret,
        )
        .await
    }

    /// Explicit relay fallback for checkpoint mode. An empty direct address is relay-only.
    #[cfg(feature = "relay-client")]
    pub async fn open_checkpoint_with_relay(
        config_json: &str,
        direct_address: &str,
        relay_address: &str,
        bootstrap_json: &str,
        capability_secret: Vec<u8>,
    ) -> Result<Self, JsError> {
        let (peer, endpoints) = parse_relay_endpoints(direct_address, relay_address)?;
        Self::open_checkpoint_at(
            serde_json::from_str(config_json)?,
            peer,
            endpoints,
            bootstrap_json,
            capability_secret,
        )
        .await
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
        Ok(discovery_query_for(
            &config,
            peer,
            config.membership_tag().map_err(debug_error)?,
        ))
    }

    /// Reuse the authorized member and its current scope after enrollment or a restore.
    pub fn member_discovery_query(&self) -> Option<String> {
        let discovery = &self.config.network.discovery;
        ((discovery.mdns || discovery.kademlia)
            && self.forwarder.is_configured_transport_peer(self.peer))
        .then(|| discovery_query_for(&self.config, self.peer, self.membership_tag()))
    }

    /// Replace dial hints for the already pinned peer. Hints never grant authority.
    pub fn set_member_endpoints(&mut self, addresses_json: &str) -> Result<(), JsError> {
        let addresses = parse_member_endpoints(addresses_json, self.peer)?;
        if addresses.is_empty() {
            return Err(JsError::new(
                "Expected between one and eight member endpoints",
            ));
        }
        self.endpoints.direct = addresses;
        Ok(())
    }

    /// Replace all hints after path loss without replacing the retained authority.
    #[cfg(feature = "relay-client")]
    pub async fn replace_discovered_paths(
        &mut self,
        addresses_json: &str,
        relay_address: Option<String>,
    ) -> Result<(), JsError> {
        let direct = parse_member_endpoints(addresses_json, self.peer)?;
        let relay = relay_address
            .as_deref()
            .map(|address| {
                let (peer, endpoints) = parse_relay_endpoints("", address)?;
                if peer != self.peer {
                    return Err(JsError::new(
                        "Relay endpoint does not match the pinned peer",
                    ));
                }
                Ok(endpoints.relay.expect("validated relay endpoint"))
            })
            .transpose()?;
        if direct.is_empty() && relay.is_none() {
            return Err(JsError::new("No usable member endpoints"));
        }
        self.endpoints = MemberEndpoints { direct, relay };
        self.reset_connection().await
    }

    pub fn snapshot(&self) -> String {
        serde_json::json!({
            "local_peer_id": self.local_peer_id(),
            "remote_peer_id": self.peer.to_string(),
            "transport": match self.member_path {
                Some(PathKind::CircuitRelay) => "circuit-relay",
                None if self.endpoints.direct.is_empty() => "circuit-relay",
                _ => "webrtc-direct",
            },
            "authorized": self.stream_mtu.is_some(),
            "ready": self.stream_mtu.is_some() && self.membership_sync.is_none(),
            "stream_mtu": self.stream_mtu,
            "path_recovery_needed": self.path_recovery_needed,
            "membership_snapshot": self.synced_snapshot,
            "checkpoint": self.checkpoint.as_ref().and_then(|_| self.capabilities().ok()?.checkpoint),
            "counters": self.counters,
        })
        .to_string()
    }

    /// Resolve only within the configured overlay. Never queries the browser's resolver.
    pub async fn resolve_overlay_name(&mut self, name: &str) -> Result<String, JsError> {
        self.open_membership_store().await?;
        self.refresh_peer_authorization()?;
        if self.checkpoint.is_some() && self.stream_mtu.is_none() {
            return Err(JsError::new(
                "Checkpoint packet authority has not been established",
            ));
        }
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
        #[cfg(feature = "relay-client")]
        self.release_relay();
        if self.checkpoint.is_some() {
            self.clear_session();
        }
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
        if self.checkpoint.is_some() {
            return self.reset_checkpoint().await;
        }
        let mut replacement =
            Self::from_endpoints(self.config.clone(), self.peer, self.endpoints.clone())?;
        // Replacing the transport must not roll back learned membership or revocations.
        std::mem::swap(&mut replacement.forwarder, &mut self.forwarder);
        replacement.membership_store = self.membership_store.take();
        replacement.handoff.generation = self.handoff.generation;
        *self = replacement;
        Ok(())
    }

    pub async fn connect(&mut self) -> Result<String, JsError> {
        #[cfg(feature = "relay-client")]
        if self.relay_reservation.is_some() {
            return self.accept_relay().await;
        }
        self.open_membership_store().await?;
        self.refresh_peer_authorization()?;
        let relay_address = self.endpoints.relay_dial_addr();
        let budget = CONNECT_TIMEOUT;
        #[cfg(feature = "relay-client")]
        let budget = if relay_address.is_some() && !self.endpoints.direct.is_empty() {
            CONNECT_WITH_FALLBACK_TIMEOUT
        } else {
            budget
        };
        let mut deadline = Instant::now() + budget;
        if !self.swarm.is_connected(&self.peer) {
            self.clear_session();
            let addresses = if self.endpoints.direct.is_empty() {
                relay_address.iter().cloned().collect()
            } else {
                self.endpoints.direct.clone()
            };
            let dial = self.dial_member(addresses, deadline).await;
            #[cfg(feature = "relay-client")]
            let dial = if !self.endpoints.direct.is_empty()
                && matches!(&dial, Err(MemberDialError::Dial(error)) if direct_unavailable(error))
                && let Some(relay_address) = relay_address
            {
                self.refresh_peer_authorization()?;
                self.dial_member(vec![relay_address], deadline).await
            } else {
                dial
            };
            match dial {
                Ok((connection, endpoint)) => self.member_connected(connection, &endpoint)?,
                Err(MemberDialError::Dial(error)) => return Err(self.member_dial_error(error)),
                Err(MemberDialError::Deadline) => return Err(self.connection_timeout()),
            }
        }
        if self.checkpoint.is_some() {
            // Transport fallback keeps the parent's dial budget. Snapshot
            // synchronization gets its own foreground budget after the dial.
            deadline = Instant::now() + CHECKPOINT_SYNC_TIMEOUT;
        }
        while self.stream_mtu.is_none() || self.membership_sync.is_some() {
            if Instant::now() >= deadline {
                return Err(self.connection_timeout());
            }
            self.step(None).await?;
        }
        Ok(self.snapshot())
    }

    /// Drive the foreground peer while the app is not performing another operation.
    pub async fn poll_foreground(&mut self) -> Result<(), JsError> {
        self.wait_for_event(None, 100).await
    }

    /// Close the session and wait for site storage to release the identity.
    pub async fn close(&mut self) -> Result<(), JsError> {
        if self
            .checkpoint
            .as_ref()
            .is_some_and(|checkpoint| checkpoint.store.is_none())
        {
            return Ok(());
        }
        let result = self.reset_connection().await;
        self.clear_session();
        if let Some(store) = self.membership_store.take() {
            store.close().await?;
        }
        if let Some(checkpoint) = &mut self.checkpoint
            && let Some(store) = checkpoint.store.take()
        {
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
        self.test_request = Some(self.send_member_packet(frame)?);
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
            .effective_config()
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
                let id = self.send_member_packet(frame)?;
                self.pending.insert(id);
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

    #[cfg(feature = "test-hooks")]
    pub async fn test_drive_transport_probe(&mut self) -> Result<String, JsError> {
        self.connect().await?;
        let frame = p2p_vpn::wire::Frame::keepalive(1, 1).map_err(debug_error)?;
        let id = self.send_member_packet(frame)?;
        self.pending.insert(id);
        let start = Instant::now();
        while self.pending.contains(&id) {
            if start.elapsed() >= Duration::from_secs(15) {
                return Err(JsError::new("transport probe did not complete"));
            }
            self.step(None).await?;
        }
        Ok(self.snapshot())
    }
}

fn unix_seconds() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

fn discovery_query_for(config: &Config, peer: PeerId, tag: Option<String>) -> String {
    let discovery = &config.network.discovery;
    serde_json::json!({
        "network_name": config.network.name,
        "membership_tag": tag,
        "peer": peer.to_string(),
        "kademlia_protocol": discovery.kademlia_protocol,
        "bootstrap": config.network.bootstrap_peers,
        "kademlia": discovery.kademlia,
        "lan": discovery.mdns,
    })
    .to_string()
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

fn parse_member_endpoints(input: &str, expected_peer: PeerId) -> Result<Vec<Multiaddr>, JsError> {
    if input.len() > MAX_MEMBER_ENDPOINTS * 1024 {
        return Err(JsError::new("Member endpoint list exceeds its byte limit"));
    }
    let values: Vec<String> = serde_json::from_str(input)?;
    parse_member_endpoint_list(&values, expected_peer)
}

fn parse_member_endpoint_list(
    values: &[String],
    expected_peer: PeerId,
) -> Result<Vec<Multiaddr>, JsError> {
    if values.len() > MAX_MEMBER_ENDPOINTS {
        return Err(JsError::new("Member endpoint list exceeds its count limit"));
    }
    let mut addresses = Vec::with_capacity(values.len());
    for value in values {
        let (address, peer) = parse_member_endpoint(value)?;
        if peer != expected_peer {
            return Err(JsError::new(
                "Member endpoint does not match the pinned peer",
            ));
        }
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    Ok(addresses)
}

fn parse_credential_endpoints(
    direct: &[String],
    relay: Option<&str>,
) -> Result<(PeerId, MemberEndpoints), JsError> {
    let first = direct.first().map_or("", String::as_str);
    let (peer, mut endpoints) = if let Some(_relay) = relay {
        #[cfg(not(feature = "relay-client"))]
        return Err(JsError::new(
            "Checkpoint credentials require relay support in this build",
        ));
        #[cfg(feature = "relay-client")]
        parse_relay_endpoints(first, _relay)?
    } else {
        let (address, peer) = parse_member_endpoint(first)?;
        (
            peer,
            MemberEndpoints {
                direct: vec![address],
                #[cfg(feature = "relay-client")]
                relay: None,
            },
        )
    };
    endpoints.direct = parse_member_endpoint_list(direct, peer)?;
    Ok((peer, endpoints))
}

#[cfg(feature = "relay-client")]
fn parse_relay_endpoints(
    direct_address: &str,
    relay_address: &str,
) -> Result<(PeerId, MemberEndpoints), JsError> {
    if relay_address.len() > 1024 {
        return Err(JsError::new("Relay endpoint exceeds its byte limit"));
    }
    let route = RelayRoute::from_dial_addr(&relay_address.parse().map_err(debug_error)?)?;
    let peer = route.destination();
    let direct = if direct_address.is_empty() {
        Vec::new()
    } else {
        let (address, direct_peer) = parse_member_endpoint(direct_address)?;
        if direct_peer != peer {
            return Err(JsError::new(
                "Direct and relay endpoints must pin the same peer",
            ));
        }
        vec![address]
    };
    Ok((
        peer,
        MemberEndpoints {
            direct,
            relay: Some(route),
        },
    ))
}

fn debug_error(error: impl std::fmt::Debug) -> JsError {
    JsError::new(&format!("{error:?}"))
}

impl BrowserVpn {
    async fn reset_checkpoint(&mut self) -> Result<(), JsError> {
        let checkpoint = self.checkpoint.as_ref().expect("checkpoint mode");
        let mut saved = checkpoint
            .store
            .as_ref()
            .ok_or_else(|| JsError::new("Checkpoint session is closed"))?
            .load()
            .await?
            .ok_or_else(|| JsError::new("Saved checkpoint state is missing"))?;
        let saved_rank = saved
            .retained
            .snapshot
            .payload
            .rank()
            .map_err(debug_error)?;
        let current_rank = checkpoint
            .driver
            .state()
            .snapshot()
            .payload
            .rank()
            .map_err(debug_error)?;
        if saved_rank < current_rank {
            return Err(JsError::new(
                "Saved checkpoint would roll back installed authority",
            ));
        }
        saved.enrollment_floor = saved.enrollment_floor.max(checkpoint.enrollment_floor);
        let driver = BrowserCheckpoint::restore_driver(
            &self.config,
            self.peer,
            checkpoint.driver.anchor().clone(),
            &checkpoint.secret,
            &saved,
        )?;
        let forwarder = Forwarder::from_checkpoint_config(
            &self.config,
            driver.state(),
            driver.anchor(),
            unix_seconds(),
        )
        .map_err(debug_error)?;
        let mut replacement = Self::build(
            self.config.clone(),
            self.peer,
            self.endpoints.clone(),
            forwarder,
            true,
        )?;
        let mut checkpoint = self.checkpoint.take().expect("checkpoint mode");
        checkpoint.driver = driver;
        checkpoint.enrollment_floor = saved.enrollment_floor;
        checkpoint.capability_request = None;
        checkpoint.installed = false;
        checkpoint.blocked = false;
        checkpoint.last_error = None;
        replacement.checkpoint = Some(checkpoint);
        replacement.handoff.generation = self.handoff.generation;
        *self = replacement;
        Ok(())
    }

    fn send_capabilities(&mut self) -> Result<(), JsError> {
        let caps = self.capabilities()?;
        let id = self
            .swarm
            .behaviour_mut()
            .control
            .send_request(&self.peer, ControlRequest::Capabilities(caps));
        if let Some(checkpoint) = &mut self.checkpoint {
            checkpoint.capability_request = Some(id);
        }
        Ok(())
    }

    async fn tick_checkpoint(&mut self) -> Result<(), JsError> {
        let Some(checkpoint) = &mut self.checkpoint else {
            return Ok(());
        };
        if checkpoint.blocked {
            return Err(JsError::new(
                "Checkpoint installation failed; reset the connection before retrying",
            ));
        }
        let now = Instant::now();
        let wall_now = unix_seconds();
        let anchor = checkpoint.driver.anchor().clone();
        let install = checkpoint
            .driver
            .finish_due(now, wall_now)
            .map_err(debug_error)?;
        if let Some(install) = install {
            // Gate old packet authority while saving and confirming the new projection.
            self.stream_mtu = None;
            checkpoint.blocked = true;
            let update = self
                .forwarder
                .prepare_checkpoint_reconfigure(
                    self.config.clone(),
                    install.state(),
                    &anchor,
                    wall_now,
                )
                .map_err(debug_error)?;
            checkpoint
                .store
                .as_ref()
                .ok_or_else(|| JsError::new("Checkpoint session is closed"))?
                .save(StoredCheckpoint {
                    retained: install.state().retained(),
                    enrollment_floor: None,
                })
                .await?;
            self.forwarder
                .commit_checkpoint_update(update)
                .map_err(debug_error)?;
            let selection = install.commit();
            checkpoint.enrollment_floor = None;
            checkpoint.blocked = false;
            checkpoint.installed = true;
            checkpoint.last_error = None;
            if !self.forwarder.is_configured_transport_peer(self.peer) {
                return Err(JsError::new(&format!(
                    "Selected checkpoint does not authorize this connection ({:?})",
                    selection.sync_state
                )));
            }
            // The native peer must acknowledge the post-install descriptor before
            // sending packets, not just acknowledge the original control-only dial.
            return self.send_capabilities();
        }
        let wire = self
            .swarm
            .behaviour_mut()
            .checkpoint
            .as_mut()
            .expect("checkpoint behaviour");
        checkpoint.driver.drive_sync(wire, now).map_err(debug_error)
    }

    fn overlay_dns_record(&self, name: &str) -> Result<DnsRecordSet, JsError> {
        if name.is_empty() || name.len() > 254 || !name.is_ascii() {
            return Err(JsError::new("Expected a p2p-vpn overlay hostname"));
        }
        let hostnames = self
            .forwarder
            .effective_hostname_records()
            .map_err(debug_error)?;
        let zone = DnsZone::from_config_with_effective_membership_at(
            self.effective_config(),
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
        if let Some(checkpoint) = &self.checkpoint {
            return checkpoint
                .store
                .as_ref()
                .map(|_| ())
                .ok_or_else(|| JsError::new("Checkpoint session is closed"));
        }
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

    fn effective_config(&self) -> &Config {
        if self.checkpoint.is_some() {
            self.forwarder.config()
        } else {
            &self.config
        }
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
        self.clear_handoff();
        self.member_connection = None;
        self.stream_mtu = None;
        self.member_path = None;
        self.membership_sync = None;
        self.path_recovery_needed = false;
        if let Some(checkpoint) = &mut self.checkpoint {
            checkpoint.capability_request = None;
            checkpoint.installed = false;
            checkpoint.driver.disconnected(Instant::now());
        }
    }

    fn lose_transport(&mut self) {
        self.clear_session();
        self.path_recovery_needed = true;
    }

    fn refresh_peer_authorization(&mut self) -> Result<(), JsError> {
        self.forwarder
            .merge_membership_records(&[], unix_seconds())
            .map_err(debug_error)?;
        if let Some(checkpoint) = &self.checkpoint {
            if checkpoint.blocked {
                return Err(JsError::new(
                    "Checkpoint installation failed; reset the connection before retrying",
                ));
            }
            if self.stream_mtu.is_none() {
                return Ok(());
            }
        }
        if self.forwarder.is_configured_transport_peer(self.peer) {
            return Ok(());
        }
        self.clear_session();
        let _ = self.swarm.disconnect_peer_id(self.peer);
        Err(JsError::new(
            "native peer membership has expired or been revoked",
        ))
    }

    fn membership_tag(&self) -> Option<String> {
        self.checkpoint.as_ref().map_or_else(
            || {
                self.config
                    .membership_tag()
                    .expect("validated at construction")
            },
            |checkpoint| Some(checkpoint.driver.membership_tag().into()),
        )
    }

    fn capabilities(&self) -> Result<ControlCapabilities, JsError> {
        let mut caps = ControlCapabilities::local(
            &self.config.network.name,
            self.membership_tag(),
            self.config.effective_packet_mtu(),
        )
        .with_advertised_routes(self.forwarder.local_advertised_routes())
        .with_member_records(self.forwarder.advertised_member_records_at(unix_seconds()));
        caps.preferred_path = self
            .member_path
            .unwrap_or(PathKind::DirectWebRtcStream)
            .wire_name()
            .into();
        if let Some(checkpoint) = &self.checkpoint {
            return checkpoint
                .driver
                .decorate_capabilities(caps, unix_seconds())
                .map_err(debug_error);
        }
        caps.supports_membership_record_pages = true;
        let records = self.forwarder.member_records();
        caps.membership_records_snapshot = Some(control::membership_records_snapshot(records));
        caps.membership_record_count = u16::try_from(records.len()).expect("bounded record count");
        Ok(caps)
    }

    fn admit_capabilities(
        &mut self,
        peer: PeerId,
        caps: &ControlCapabilities,
    ) -> Result<(), ControlRejectionReason> {
        if peer != self.peer {
            return Err(ControlRejectionReason::UnauthorizedPeer);
        }
        if let Some(checkpoint) = &mut self.checkpoint {
            if caps.effective_mtu < MIN_IPV4_MTU {
                return Err(ControlRejectionReason::InvalidEffectiveMtu);
            }
            return checkpoint.driver.observe_capabilities(peer, caps);
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
        self.wait_for_event(device, 5).await
    }

    async fn wait_for_event(
        &mut self,
        device: Option<&mut IpDevice>,
        timeout_ms: u32,
    ) -> Result<(), JsError> {
        self.tick_checkpoint().await?;
        let device_mtu = device.as_ref().map(|device| device.mtu());
        if self.checkpoint.is_some() && device_mtu.is_some() && self.stream_mtu != device_mtu {
            return Err(JsError::new(
                "Stream authority or MTU changed; retry the HTTP request",
            ));
        }
        if self
            .membership_sync
            .as_ref()
            .is_some_and(|sync| Instant::now() >= sync.deadline)
        {
            self.clear_session();
            let _ = self.swarm.disconnect_peer_id(self.peer);
            return Err(JsError::new("membership snapshot exchange timed out"));
        }
        self.drive_handoff()?;
        let event = {
            let next = self.swarm.next().fuse();
            let tick = TimeoutFuture::new(timeout_ms).fuse();
            futures::pin_mut!(next, tick);
            futures::select! { event = next => event, _ = tick => None }
        };
        let Some(event) = event else { return Ok(()) };
        #[cfg(feature = "relay-client")]
        self.observe_relay_listener(&event)?;
        if self.on_handoff_event(&event)? {
            return Ok(());
        }
        if let SwarmEvent::Behaviour(event) = &event {
            let source = match event {
                BehaviourEvent::Control(event) => Some(wire_source(event)),
                BehaviourEvent::Checkpoint(event) => Some(wire_source(event)),
                BehaviourEvent::Packet(event) => Some(wire_source(event)),
                BehaviourEvent::Service(event) => Some(wire_source(event)),
                _ => None,
            };
            if let Some((peer, id)) = source
                && (peer != self.peer
                    || (Some(id) != self.member_connection && !self.admits_handoff_wire(id, event)))
            {
                return Ok(());
            }
        }
        match event {
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } => {
                if self.endpoints.is_relay_hop(peer_id) {
                    return Ok(());
                }
                if peer_id != self.peer {
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return Err(JsError::new("unexpected remote identity"));
                }
                if self.member_connection.is_some() {
                    self.swarm.close_connection(connection_id);
                    return Ok(());
                }
                if endpoint.is_listener() {
                    #[cfg(feature = "relay-client")]
                    if !self.claim_incoming_circuit(peer_id, connection_id, &endpoint)? {
                        return Ok(());
                    }
                    #[cfg(not(feature = "relay-client"))]
                    {
                        self.swarm.close_connection(connection_id);
                        return Ok(());
                    }
                }
                self.member_connected(connection_id, &endpoint)?;
            }
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer),
                error,
                ..
            } if peer == self.peer && self.member_connection.is_none() => {
                return Err(self.member_dial_error(error));
            }
            SwarmEvent::ConnectionClosed { connection_id, .. }
                if Some(connection_id) == self.member_connection =>
            {
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
                    peer == self.peer
                        && self.forwarder.is_configured_transport_peer(peer)
                        && (self.checkpoint.is_none() || self.stream_mtu.is_some()),
                    &self.config.network.name,
                    self.membership_tag(),
                    &self.config.network.previous_membership_tags,
                    self.config.effective_packet_mtu(),
                    self.member_path.zip(self.stream_mtu),
                );
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .service
                    .send_response(channel, response);
            }
            SwarmEvent::Behaviour(BehaviourEvent::Control(request_response::Event::Message {
                peer,
                connection_id,
                message,
                ..
            })) => match message {
                request_response::Message::Request {
                    request_id,
                    request,
                    channel,
                } => {
                    if self.member_connection != Some(connection_id) {
                        self.answer_candidate_control(peer, connection_id, request, channel);
                        return Ok(());
                    }
                    let response = match request {
                        ControlRequest::Capabilities(caps) => match self
                            .admit_capabilities(peer, &caps)
                        {
                            Ok(()) => ControlResponse::CapabilitiesAccepted(self.capabilities()?),
                            Err(reason) => ControlResponse::CapabilitiesRejected(reason),
                        },
                        ControlRequest::PacketPlaneHello(_) => {
                            ControlResponse::PacketPlaneRejected(
                                control::ControlRejectionReason::UnsupportedPreferredPath,
                            )
                        }
                        ControlRequest::MembershipRecords(request) => {
                            let result = if self.checkpoint.is_some() {
                                Err(MembershipRecordsRejectionReason::UnsupportedVersion)
                            } else if peer != self.peer
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
                    let result = if let Some(checkpoint) = &mut self.checkpoint {
                        if peer != self.peer || checkpoint.capability_request != Some(request_id) {
                            return Ok(());
                        }
                        checkpoint.capability_request = None;
                        let installed = checkpoint.installed;
                        match response {
                            ControlResponse::CapabilitiesAccepted(caps) => self
                                .admit_capabilities(peer, &caps)
                                .and_then(|()| {
                                    if installed {
                                        self.forwarder.authorize_peer_capabilities(peer, &caps)?;
                                        self.stream_mtu = Some(
                                            self.config
                                                .effective_packet_mtu()
                                                .min(caps.effective_mtu),
                                        );
                                    }
                                    Ok(())
                                })
                                .map_err(debug_error),
                            other => Err(debug_error(other)),
                        }
                    } else if self
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
                request_response::Event::OutboundFailure {
                    error,
                    peer,
                    request_id,
                    ..
                },
            )) => {
                if self.checkpoint.as_ref().is_some_and(|checkpoint| {
                    peer != self.peer || checkpoint.capability_request != Some(request_id)
                }) {
                    return Ok(());
                }
                if transport_failure(&error) {
                    self.lose_transport();
                } else {
                    self.clear_session();
                }
                let _ = self.swarm.disconnect_peer_id(self.peer);
                return Err(debug_error(error));
            }
            SwarmEvent::Behaviour(BehaviourEvent::Checkpoint(event)) => {
                let checkpoint = self.checkpoint.as_mut().expect("checkpoint behaviour");
                let wire = self
                    .swarm
                    .behaviour_mut()
                    .checkpoint
                    .as_mut()
                    .expect("checkpoint behaviour");
                if let Err(error) =
                    checkpoint
                        .driver
                        .handle_event(wire, event, Instant::now(), unix_seconds())
                {
                    checkpoint.last_error = Some(error.to_string());
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Packet(request_response::Event::Message {
                peer,
                connection_id,
                message,
                ..
            })) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    let accepted =
                        match self.stream_mtu.filter(|_| {
                            peer == self.peer && self.admits_member_packet(connection_id)
                        }) {
                            None => Err(PacketRejectionReason::UnauthorizedPeer),
                            Some(mtu) if request.payload.len() > usize::from(mtu) => {
                                Err(PacketRejectionReason::PacketTooLarge)
                            }
                            Some(_) => self
                                .forwarder
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
                                }),
                        };
                    let response = match accepted {
                        Ok(()) => PacketResponse::Accepted,
                        Err(reason) => {
                            self.counters.rejected_inbound_packets += 1;
                            PacketResponse::Rejected(reason)
                        }
                    };
                    let sent = self
                        .swarm
                        .behaviour_mut()
                        .packet
                        .send_response(channel, response);
                    if self.member_connection == Some(connection_id) {
                        sent.map_err(debug_error)?;
                    }
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
                    if !self.admits_member_packet(connection_id) {
                        return Ok(());
                    }
                    match response {
                        PacketResponse::Accepted => self.counters.accepted_outbound_packets += 1,
                        PacketResponse::Rejected(_)
                            if self.member_connection != Some(connection_id) => {}
                        PacketResponse::Rejected(reason) => return Err(debug_error(reason)),
                    }
                }
            },
            SwarmEvent::Behaviour(BehaviourEvent::Packet(
                request_response::Event::OutboundFailure {
                    request_id,
                    error,
                    connection_id,
                    ..
                },
            )) => {
                self.pending.remove(&request_id);
                if self.member_connection != Some(connection_id) {
                    return Ok(());
                }
                if transport_failure(&error)
                    || matches!(error, request_response::OutboundFailure::Timeout)
                {
                    self.lose_transport();
                    let _ = self.swarm.disconnect_peer_id(self.peer);
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
    match error {
        request_response::OutboundFailure::ConnectionClosed
        | request_response::OutboundFailure::DialFailure => true,
        request_response::OutboundFailure::Io(error) => matches!(
            error.kind(),
            io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::NotConnected
                | io::ErrorKind::UnexpectedEof
        ),
        _ => false,
    }
}

fn wire_source<T, U>(event: &request_response::Event<T, U>) -> (PeerId, ConnectionId) {
    use request_response::Event;

    match *event {
        Event::Message {
            peer,
            connection_id,
            ..
        }
        | Event::OutboundFailure {
            peer,
            connection_id,
            ..
        }
        | Event::InboundFailure {
            peer,
            connection_id,
            ..
        }
        | Event::ResponseSent {
            peer,
            connection_id,
            ..
        } => (peer, connection_id),
    }
}

fn transport_error_causes(
    error: &TransportError<io::Error>,
) -> impl Iterator<Item = &(dyn Error + 'static)> {
    let TransportError::Other(error) = error else {
        return std::iter::successors(None, next_cause);
    };
    std::iter::successors(Some(error as &dyn Error), next_cause)
}

fn next_cause<'a>(cause: &&'a (dyn Error + 'static)) -> Option<&'a (dyn Error + 'static)> {
    // Boxed transports can wrap an io::Error inside another io::Error.
    let cause = *cause;
    cause
        .downcast_ref::<io::Error>()
        .and_then(io::Error::get_ref)
        .map(|error| error as &dyn Error)
        .or_else(|| cause.source())
}

fn identity_or_policy_denial(cause: &(dyn Error + 'static)) -> bool {
    use libp2p::webrtc_websys;

    matches!(
        cause.downcast_ref::<webrtc_websys::Error>(),
        Some(webrtc_websys::Error::Authentication(_) | webrtc_websys::Error::UnknownRemotePeerId)
    ) || cause
        .downcast_ref::<io::Error>()
        .is_some_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
}

#[cfg(feature = "relay-client")]
fn direct_unavailable(error: &DialError) -> bool {
    use libp2p::{core::transport::timeout::TransportTimeoutError, webrtc_websys};

    matches!(error, DialError::Transport(errors) if !errors.is_empty()
    && errors.iter().all(|(_, error)| {
        transport_error_causes(error).any(|cause| {
            matches!(cause.downcast_ref::<TransportTimeoutError<webrtc_websys::Error>>(),
                Some(TransportTimeoutError::Timeout
                    | TransportTimeoutError::Other(webrtc_websys::Error::Connection(_))))
        })
    }))
}
