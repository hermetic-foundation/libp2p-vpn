//! Foreground transport for pairing on a VPN swarm before member admission.

use std::time::Duration;

use futures::{FutureExt as _, StreamExt as _};
use gloo_timers::future::TimeoutFuture;
use libp2p::{
    PeerId, StreamProtocol,
    request_response::{self, ProtocolSupport},
    swarm::{ConnectionId, SwarmEvent},
};
use p2p_vpn::{
    config::Config,
    runtime::pairing_code::{
        PAIRING_CODE_V2_PROTOCOL, PairingCodeV2Codec, PairingCodeV2Request, PairingCodeV2Response,
    },
};
use wasm_bindgen::prelude::*;
use web_time::Instant;

use super::{BehaviourEvent, BrowserVpn, Forwarder, MemberEndpoints, debug_error};
use crate::{membership_store::MembershipStore, relay::RelayRoute};

pub(super) type Wire = request_response::Behaviour<PairingCodeV2Codec>;

pub(crate) enum Event {
    Request {
        peer: PeerId,
        id: request_response::InboundRequestId,
        request: PairingCodeV2Request,
        channel: request_response::ResponseChannel<PairingCodeV2Response>,
    },
    ResponseSent(request_response::InboundRequestId),
}

pub(crate) struct InvitationTransport {
    vpn: BrowserVpn,
    reserved_outer: Option<ConnectionId>,
    pairing_connection: Option<ConnectionId>,
}

impl InvitationTransport {
    pub(crate) fn new(config: Config, route: RelayRoute) -> Result<Self, JsError> {
        let forwarder = Forwarder::from_config(&config).map_err(debug_error)?;
        let mut vpn = BrowserVpn::build(
            config,
            route.destination(),
            MemberEndpoints {
                direct: Vec::new(),
                relay: Some(route),
            },
            forwarder,
            false,
        )?;
        vpn.swarm.behaviour_mut().code_invitation = Some(Wire::new(
            [(
                StreamProtocol::new(PAIRING_CODE_V2_PROTOCOL),
                ProtocolSupport::Inbound,
            )],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(10))
                .with_max_concurrent_streams(2),
        ))
        .into();
        Ok(Self {
            vpn,
            reserved_outer: None,
            pairing_connection: None,
        })
    }

    pub(crate) fn start_reservation(&mut self) -> Result<(), JsError> {
        if self.reserved_outer.is_some() && self.outer().is_none() {
            return Err(JsError::new("Invitation reservation is no longer live"));
        }
        if self.vpn.relay_reservation.is_none() {
            self.vpn.start_relay_reservation()?;
        }
        Ok(())
    }

    pub(crate) fn has_reservation(&self) -> bool {
        self.vpn.relay_reservation.is_some()
    }

    pub(crate) fn release_reservation(&mut self) {
        self.vpn.release_relay();
    }

    pub(crate) fn confirmed_address(&self) -> Option<String> {
        self.outer()?;
        self.vpn.relay_reservation_address()
    }

    fn outer(&self) -> Option<ConnectionId> {
        let (_, outer) = self.vpn.confirmed_reservation()?;
        (self.reserved_outer == Some(outer)).then_some(outer)
    }

    fn owns_circuit(&self, peer: PeerId, inner: ConnectionId) -> bool {
        peer == self.vpn.peer
            && self.outer().is_some_and(|outer| {
                let Some(route) = self.vpn.endpoints.relay.as_ref() else {
                    return false;
                };
                self.vpn
                    .swarm
                    .behaviour()
                    .relay
                    .as_ref()
                    .is_some_and(|relay| {
                        relay.circuit_connection_owner(peer, inner)
                            == Some((route.relay_peer(), outer))
                    })
            })
    }

    pub(crate) async fn next(&mut self, timeout_ms: u32) -> Result<Option<Event>, JsError> {
        let event = {
            let next = self.vpn.swarm.next().fuse();
            let timeout = TimeoutFuture::new(timeout_ms).fuse();
            futures::pin_mut!(next, timeout);
            futures::select! { event = next => event, _ = timeout => None }
        };
        let Some(event) = event else { return Ok(None) };
        self.vpn.observe_relay_listener(&event)?;
        if self.reserved_outer.is_none() {
            self.reserved_outer = self.vpn.confirmed_reservation().map(|(_, outer)| outer);
        } else if self.outer().is_none() {
            return Err(JsError::new("Invitation reservation is no longer live"));
        }
        // Do not run the VPN's event dispatcher until the approved config has
        // been installed. Unhandled data/control requests drop their channels.
        match event {
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } if endpoint.is_listener() => {
                if self.pairing_connection.is_none() && self.owns_circuit(peer_id, connection_id) {
                    self.pairing_connection = Some(connection_id);
                } else {
                    self.vpn.swarm.close_connection(connection_id);
                }
            }
            SwarmEvent::ConnectionClosed { connection_id, .. }
                if Some(connection_id) == self.pairing_connection =>
            {
                self.pairing_connection = None;
            }
            SwarmEvent::Behaviour(BehaviourEvent::CodeInvitation(
                request_response::Event::Message {
                    peer,
                    connection_id,
                    message:
                        request_response::Message::Request {
                            request_id,
                            request,
                            channel,
                        },
                },
            )) if Some(connection_id) == self.pairing_connection
                && self.owns_circuit(peer, connection_id) =>
            {
                return Ok(Some(Event::Request {
                    peer,
                    id: request_id,
                    request,
                    channel,
                }));
            }
            SwarmEvent::Behaviour(BehaviourEvent::CodeInvitation(
                request_response::Event::ResponseSent { request_id, .. },
            )) => return Ok(Some(Event::ResponseSent(request_id))),
            _ => {}
        }
        Ok(None)
    }

    pub(crate) fn respond(
        &mut self,
        channel: request_response::ResponseChannel<PairingCodeV2Response>,
        response: PairingCodeV2Response,
    ) -> bool {
        self.vpn
            .swarm
            .behaviour_mut()
            .code_invitation
            .as_mut()
            .is_some_and(|wire| wire.send_response(channel, response).is_ok())
    }

    pub(crate) async fn activate(
        mut self,
        config: Config,
        store: Option<MembershipStore>,
    ) -> Result<BrowserVpn, JsError> {
        let outer = self
            .outer()
            .ok_or_else(|| JsError::new("Invitation reservation is no longer live"))?;
        let forwarder = Forwarder::from_config(&config).map_err(debug_error)?;
        if config.local_peer().map_err(debug_error)? != self.vpn.local_peer_id()
            || !forwarder.is_configured_transport_peer(self.vpn.peer)
        {
            return Err(JsError::new("Approved pairing does not authorize this VPN"));
        }

        // Retire only the end-to-end PAKE circuit. Keep the HOP connection and
        // listener owner; the enrolled peer starts a separate VPN circuit.
        if let Some(inner) = self.pairing_connection {
            self.vpn.swarm.close_connection(inner);
            let deadline = Instant::now() + Duration::from_secs(2);
            while self.pairing_connection.is_some() {
                if Instant::now() >= deadline || self.outer() != Some(outer) {
                    return Err(JsError::new(
                        "Could not retire pairing circuit on its reservation",
                    ));
                }
                self.next(50).await?;
            }
        }
        if self.outer() != Some(outer) {
            return Err(JsError::new(
                "Invitation reservation changed before VPN activation",
            ));
        }
        self.vpn.config = config;
        self.vpn.forwarder = forwarder;
        self.vpn.membership_store = store;
        Ok(self.vpn)
    }
}
