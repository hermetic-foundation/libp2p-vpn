//! Native fixture for the real Chromium checkpoint issuer circuit test.

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::{
        io,
        net::Ipv4Addr,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use futures::StreamExt as _;
    use libp2p::{
        Multiaddr, PeerId, Swarm, SwarmBuilder,
        multiaddr::Protocol,
        noise, relay, request_response as rr,
        swarm::{ConnectionId, NetworkBehaviour, SwarmEvent, dial_opts::DialOpts},
        tcp, yamux,
    };
    use p2p_vpn::{
        config::{Config, membership_tag},
        identity::NodeIdentity,
        membership::checkpoint::{
            CheckpointMember, CooperativeMembershipState, MembershipSyncState, NetworkAnchor,
            NetworkCapability, SnapshotPolicy,
        },
        pairing::{
            PairingOffer, PairingRequestOptions, PairingResponse, build_named_pairing_request_at,
            checkpoint_grant::VerifiedCheckpointEnrollment,
        },
        route::builtin_ipv4,
        runtime::{
            control::{
                self, ControlCapabilities, ControlRequest, ControlResponse,
                checkpoint::{
                    self, CheckpointCodec, CheckpointProgress, CheckpointSync,
                    CheckpointSyncIndicator,
                },
                checkpoint_mutation::{
                    self, CheckpointMutationCodec, CheckpointMutationResponse, MutationOutcome,
                },
            },
            forward::Forwarder,
            packet::{self, PacketCodec, PacketRejectionReason, PacketResponse},
        },
        wire::Frame,
    };
    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, BufReader};

    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
    const SECRET: [u8; 32] = [219; 32];
    const NETWORK: &str = "checkpoint-relay-issuance";
    const MTU: u16 = 1280;

    #[derive(NetworkBehaviour)]
    struct Wire {
        relay: relay::client::Behaviour,
        control: rr::Behaviour<control::ControlCodec>,
        pages: rr::Behaviour<CheckpointCodec>,
        mutation: rr::Behaviour<CheckpointMutationCodec>,
        packet: rr::Behaviour<PacketCodec>,
    }

    struct Member {
        swarm: Swarm<Wire>,
        identity: NodeIdentity,
        peer: PeerId,
        connection: ConnectionId,
        state: CooperativeMembershipState,
        sync: CheckpointSync,
        controls_answered: usize,
    }

    impl Member {
        async fn dial(
            identity: NodeIdentity,
            peer: PeerId,
            address: Multiaddr,
            state: CooperativeMembershipState,
        ) -> Result<Self> {
            let key = identity.keypair().map_err(error)?;
            let cert = libp2p_webrtc::tokio::Certificate::generate(&mut rand::rngs::OsRng)?;
            let mut swarm = SwarmBuilder::with_existing_identity(key)
                .with_tokio()
                .with_tcp(
                    tcp::Config::default(),
                    noise::Config::new,
                    yamux::Config::default,
                )?
                .with_other_transport(|key| {
                    libp2p_webrtc::tokio::Transport::new(key.clone(), cert)
                })?
                .with_relay_client(noise::Config::new, yamux::Config::default)?
                .with_behaviour(|_, relay| Wire {
                    relay,
                    control: control::behaviour(8),
                    pages: checkpoint::behaviour(8),
                    mutation: checkpoint_mutation::behaviour(4),
                    packet: packet::behaviour(MTU, 8),
                })?
                .with_swarm_config(|config| {
                    config.with_idle_connection_timeout(Duration::from_secs(65))
                })
                .build();
            let listener = swarm.listen_on("/ip4/11.250.0.2/udp/0/webrtc-direct".parse()?)?;
            loop {
                if matches!(swarm.select_next_some().await,
                    SwarmEvent::NewListenAddr { listener_id, .. } if listener_id == listener)
                {
                    break;
                }
            }
            let opts = DialOpts::peer_id(peer).addresses(vec![address]).build();
            let connection = opts.connection_id();
            swarm.dial(opts)?;
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::ConnectionEstablished {
                        peer_id,
                        connection_id,
                        endpoint,
                        ..
                    } if connection_id == connection => {
                        assert_eq!(peer_id, peer);
                        assert!(endpoint.is_relayed());
                        break;
                    }
                    SwarmEvent::OutgoingConnectionError {
                        connection_id,
                        error: failure,
                        ..
                    } if connection_id == connection => return Err(failure.into()),
                    _ => {}
                }
            }
            let sync = CheckpointSync::new(
                *swarm.local_peer_id(),
                state.snapshot().payload.anchor.clone(),
                Default::default(),
            )
            .map_err(error)?;
            Ok(Self {
                swarm,
                identity,
                peer,
                connection,
                state,
                sync,
                controls_answered: 0,
            })
        }

        fn caps(&self) -> Result<ControlCapabilities> {
            let mut caps =
                ControlCapabilities::local(NETWORK, Some(membership_tag(NETWORK, &SECRET)), MTU)
                    .with_checkpoint(&self.state)
                    .map_err(error)?;
            caps.preferred_path = p2p_vpn::PathKind::CircuitRelay.wire_name().into();
            Ok(caps)
        }

        async fn next(&mut self) -> Result<WireEvent> {
            loop {
                match self.swarm.select_next_some().await {
                    SwarmEvent::Behaviour(WireEvent::Control(rr::Event::Message {
                        peer,
                        connection_id,
                        message:
                            rr::Message::Request {
                                request, channel, ..
                            },
                    })) => {
                        assert_eq!((peer, connection_id), (self.peer, self.connection));
                        let ControlRequest::Capabilities(remote) = request else {
                            return Err("unexpected control request".into());
                        };
                        assert_eq!(
                            remote.membership_tag.as_deref(),
                            Some(membership_tag(NETWORK, &SECRET).as_str())
                        );
                        let response = ControlResponse::CapabilitiesAccepted(self.caps()?);
                        self.swarm
                            .behaviour_mut()
                            .control
                            .send_response(channel, response)
                            .map_err(error)?;
                        self.controls_answered += 1;
                    }
                    SwarmEvent::Behaviour(WireEvent::Pages(rr::Event::Message {
                        peer,
                        connection_id,
                        message:
                            rr::Message::Request {
                                request, channel, ..
                            },
                    })) => {
                        assert_eq!((peer, connection_id), (self.peer, self.connection));
                        let response = self
                            .sync
                            .respond_at(
                                peer,
                                &request,
                                &self.state,
                                &self.identity,
                                &SECRET,
                                Instant::now(),
                                now()?,
                            )
                            .map_err(error)?;
                        self.swarm
                            .behaviour_mut()
                            .pages
                            .send_response(channel, response)
                            .map_err(error)?;
                    }
                    SwarmEvent::Behaviour(WireEvent::Mutation(rr::Event::Message {
                        peer,
                        connection_id,
                        message:
                            rr::Message::Request {
                                request, channel, ..
                            },
                    })) => {
                        assert_eq!((peer, connection_id), (self.peer, self.connection));
                        let candidate = request
                            .prepare_at(peer, &self.state, now()?)
                            .map_err(error)?;
                        let boundary = candidate.snapshot().payload.boundary().map_err(error)?;
                        let response = CheckpointMutationResponse::for_request(
                            &request,
                            MutationOutcome::Applied(boundary),
                        )
                        .map_err(error)?;
                        self.state = candidate;
                        self.swarm
                            .behaviour_mut()
                            .mutation
                            .send_response(channel, response)
                            .map_err(error)?;
                        println!(
                            "{}",
                            json!({"incumbent_applied": boundary.authority_revision})
                        );
                    }
                    SwarmEvent::ConnectionClosed {
                        connection_id,
                        cause,
                        ..
                    } if connection_id == self.connection => return Err(error(cause).into()),
                    SwarmEvent::Behaviour(event) => return Ok(event),
                    _ => {}
                }
            }
        }

        async fn advertise(&mut self) -> Result<ControlCapabilities> {
            self.exchange(self.caps()?).await
        }

        async fn exchange(&mut self, caps: ControlCapabilities) -> Result<ControlCapabilities> {
            let request = ControlRequest::Capabilities(caps);
            let id = self
                .swarm
                .behaviour_mut()
                .control
                .send_request_on_connection_with_deadline(
                    &self.peer,
                    self.connection,
                    request,
                    limit(),
                )
                .map_err(error)?;
            loop {
                match self.next().await? {
                    WireEvent::Control(rr::Event::Message {
                        peer,
                        connection_id,
                        message:
                            rr::Message::Response {
                                request_id,
                                response,
                            },
                        ..
                    }) if id == request_id => {
                        assert_eq!((peer, connection_id), (self.peer, self.connection));
                        let ControlResponse::CapabilitiesAccepted(caps) = response else {
                            return Err(error(response).into());
                        };
                        return Ok(caps);
                    }
                    WireEvent::Control(rr::Event::OutboundFailure {
                        request_id,
                        error: failure,
                        ..
                    }) if request_id == id => return Err(failure.into()),
                    _ => {}
                }
            }
        }

        async fn fetch(&mut self) -> Result<()> {
            let start = Instant::now();
            let window = Duration::from_secs(4);
            let end = start + window;
            let challenge = self.state.begin_resync(start, window).map_err(error)?;
            let mut page = self
                .sync
                .start_request(self.peer, challenge, &SECRET, start, end)
                .map_err(error)?;
            loop {
                let id = self
                    .swarm
                    .behaviour_mut()
                    .pages
                    .send_request_on_connection_with_deadline(
                        &self.peer,
                        self.connection,
                        page.clone(),
                        end,
                    )
                    .map_err(error)?;
                let response = loop {
                    match self.next().await? {
                        WireEvent::Pages(rr::Event::Message {
                            peer,
                            connection_id,
                            message:
                                rr::Message::Response {
                                    request_id,
                                    response,
                                },
                            ..
                        }) if request_id == id => {
                            assert_eq!((peer, connection_id), (self.peer, self.connection));
                            break response;
                        }
                        WireEvent::Pages(rr::Event::OutboundFailure {
                            request_id,
                            error: failure,
                            ..
                        }) if request_id == id => return Err(failure.into()),
                        _ => {}
                    }
                };
                match self
                    .sync
                    .accept_response(self.peer, &page, response, &SECRET, Instant::now())
                    .map_err(error)?
                {
                    CheckpointProgress::More(next) => page = next,
                    CheckpointProgress::Complete(offer) => {
                        self.state
                            .collect_offer(&offer, self.peer, Instant::now())
                            .map_err(error)?;
                        break;
                    }
                }
            }
            while let Ok(event) = tokio::time::timeout_at(end.into(), self.next()).await {
                event?;
            }
            let selection = self
                .state
                .finish_resync(Instant::now(), now()?)
                .map_err(error)?;
            assert!(selection.observed_remote_offer);
            assert_eq!(selection.sync_state, MembershipSyncState::Participating);
            Ok(())
        }

        async fn send_probe(&mut self, sequence: u64, source: Ipv4Addr) -> Result<PacketResponse> {
            let packet = Frame::packet(
                1,
                sequence,
                ip_packet(
                    source,
                    builtin_ipv4(p2p_vpn::PeerId::from_libp2p(self.peer)),
                ),
            )
            .map_err(error)?;
            let id = self
                .swarm
                .behaviour_mut()
                .packet
                .send_request_on_connection_with_deadline(
                    &self.peer,
                    self.connection,
                    packet,
                    limit(),
                )
                .map_err(error)?;
            loop {
                match self.next().await? {
                    WireEvent::Packet(rr::Event::Message {
                        peer,
                        connection_id,
                        message:
                            rr::Message::Response {
                                request_id,
                                response,
                            },
                        ..
                    }) if request_id == id => {
                        assert_eq!((peer, connection_id), (self.peer, self.connection));
                        return Ok(response);
                    }
                    WireEvent::Packet(rr::Event::OutboundFailure {
                        request_id,
                        error: failure,
                        ..
                    }) if request_id == id => return Err(failure.into()),
                    _ => {}
                }
            }
        }
    }

    fn ip_packet(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
        let mut bytes = vec![0u8; 28];
        let mut packet = smoltcp::wire::Ipv4Packet::new_unchecked(bytes.as_mut_slice());
        packet.set_version(4);
        packet.set_header_len(20);
        packet.set_total_len(28);
        packet.set_hop_limit(64);
        packet.set_next_header(smoltcp::wire::IpProtocol::Icmp);
        packet.set_src_addr(source);
        packet.set_dst_addr(destination);
        packet.fill_checksum();
        packet
            .payload_mut()
            .copy_from_slice(&[8, 0, 0xf7, 0xff, 0, 0, 0, 0]);
        bytes
    }

    fn config(identity: &NodeIdentity) -> Result<Config> {
        Ok(serde_json::from_value(json!({
            "network": {"name": NETWORK, "private_key": identity.private_key, "listen_addresses": []},
        }))?)
    }

    fn error(value: impl std::fmt::Debug) -> io::Error {
        io::Error::other(format!("{value:?}"))
    }
    fn limit() -> Instant {
        Instant::now() + Duration::from_secs(8)
    }
    fn now() -> Result<u64> {
        Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
    }
    fn ip(identity: &NodeIdentity) -> Ipv4Addr {
        builtin_ipv4(identity.peer_id.parse().unwrap())
    }

    #[tokio::main]
    pub(super) async fn run() -> Result<()> {
        tokio::time::timeout(Duration::from_secs(90), scenario()).await?
    }

    async fn scenario() -> Result<()> {
        let entrance: Multiaddr = std::env::args()
            .nth(1)
            .ok_or("missing relay entrance")?
            .parse()?;
        let (browser, first, second) = loop {
            let make = || NodeIdentity::generate_ed25519().map_err(error);
            let (a, b, c) = (make()?, make()?, make()?);
            if ip(&a) != ip(&b) && ip(&a) != ip(&c) && ip(&b) != ip(&c) {
                break (a, b, c);
            }
        };
        let browser_id: PeerId = browser.peer_id.parse()?;
        let first_id: PeerId = first.peer_id.parse()?;
        let circuit = |peer| {
            entrance
                .clone()
                .with(Protocol::P2pCircuit)
                .with(Protocol::P2p(peer))
        };
        let anchor = NetworkAnchor::new([128; 32]).map_err(error)?;
        let capability =
            NetworkCapability::from_secret(anchor.clone(), Some(&SECRET)).map_err(error)?;
        let state = CooperativeMembershipState::bootstrap_at(
            capability.clone(),
            first.peer_id.clone(),
            vec![
                CheckpointMember::new(&first).map_err(error)?,
                CheckpointMember::new(&browser).map_err(error)?,
            ],
            SnapshotPolicy::default(),
            now()?,
        )
        .map_err(error)?;
        let reservation = circuit(browser_id);
        println!(
            "{}",
            json!({
                "config": config(&browser)?, "secret": SECRET, "first_route": circuit(first_id).to_string(),
                "reservation": reservation.to_string(), "joiner_ip": ip(&second),
                "bootstrap": {"anchor": anchor, "retained": state.retained(), "enrollment_floor": null},
            })
        );
        let mut input = BufReader::new(tokio::io::stdin()).lines();
        assert_eq!(
            input.next_line().await?.as_deref(),
            Some(reservation.to_string().as_str())
        );
        let mut incumbent = Member::dial(first, browser_id, reservation.clone(), state).await?;
        tokio::select! {
            result = async {
                incumbent.advertise().await?;
                loop { incumbent.next().await?; }
            } => result,
            result = async {
                let offer: PairingOffer = serde_json::from_str(&input.next_line().await?.ok_or("missing offer")?)?;
                assert_eq!(offer.payload.inviter_addresses, [reservation.to_string()]);
                let request = build_named_pairing_request_at(&offer, PairingRequestOptions {
                    identity: second.clone(), requested_vpn_ip: None, requested_routes: Vec::new(),
                }, None, now()?).map_err(error)?;
                println!("{}", json!({"request": request}));
                let response: PairingResponse = serde_json::from_str(&input.next_line().await?.ok_or("missing response")?)?;
                let verified = VerifiedCheckpointEnrollment::verify_at(&offer, &response, &second, now()?)
                    .map_err(error)?.ok_or("expected checkpoint grant")?;
                let pending = verified.into_pending_seed().map_err(error)?;
                let state = CooperativeMembershipState::restore(capability, second.peer_id.clone(), pending.retained).map_err(error)?;
                assert_eq!(state.sync_state(), MembershipSyncState::ResyncRequired);
                let local_ip = ip(&second);
                let mut joiner = Member::dial(second, browser_id, reservation, state).await?;
                let advertised = joiner.advertise().await?.checkpoint.ok_or("missing issuer descriptor")?;
                assert!(matches!(advertised.sync,
                    CheckpointSyncIndicator::Participating | CheckpointSyncIndicator::Resyncing));
                assert_eq!(advertised.boundary.authority_revision, pending.enrollment_floor.authority_revision);
                // Even claiming the exact current rank cannot substitute for a transfer.
                let mut early = joiner.caps()?;
                early.checkpoint = Some(advertised.clone());
                early.checkpoint.as_mut().unwrap().sync = CheckpointSyncIndicator::Participating;
                joiner.exchange(early).await?;
                assert_eq!(joiner.send_probe(1, local_ip).await?, PacketResponse::Rejected(PacketRejectionReason::UnauthorizedPeer));
                joiner.fetch().await?;
                assert_eq!(joiner.state.snapshot().payload.rank().map_err(error)?, pending.enrollment_floor);
                let projection = Forwarder::from_checkpoint_config(
                    &config(&joiner.identity)?, &joiner.state, &anchor, now()?,
                ).map_err(error)?;
                assert!(projection.is_configured_transport_peer(browser_id));
                let exchanges = joiner.controls_answered;
                assert_eq!(joiner.advertise().await?.checkpoint.unwrap().boundary, advertised.boundary);
                while joiner.controls_answered == exchanges { joiner.next().await?; }
                // Give the browser's exact response event precedence over the probe.
                let _ = tokio::time::timeout(Duration::from_millis(100), joiner.next()).await;
                assert_eq!(joiner.send_probe(2, local_ip).await?, PacketResponse::Accepted);
                println!("{}", json!({"activated_rank": pending.enrollment_floor, "packet_accepted": true}));
                Ok(())
            } => result,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    native::run()
}

#[cfg(target_arch = "wasm32")]
fn main() {}
