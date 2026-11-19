use std::time::Duration;

use libp2p::{
    Multiaddr, PeerId,
    core::{ConnectedPoint, transport::ListenerId},
    multiaddr::Protocol,
    swarm::{ConnectionId, SwarmEvent},
};
use smoltcp::phy::{Device, RxToken};
use wasm_bindgen::prelude::*;
use web_time::Instant;

use super::{
    BehaviourEvent, Binding, BrowserVpn, CHECKPOINT_SYNC_TIMEOUT, CONNECT_TIMEOUT, IpDevice,
    PacketTarget, debug_error,
};

const MAX_RECEIVE_WAIT_MS: u32 = 5_000;

pub(super) struct RelayReservation {
    listener: ListenerId,
    relay: PeerId,
    address: Multiaddr,
    advertised: bool,
    publication_addresses: Vec<Multiaddr>,
    member: Option<ConnectionId>,
    additional: Option<PeerId>,
}

#[wasm_bindgen]
impl BrowserVpn {
    pub(super) fn owns_incoming_relay(&self, connection: ConnectionId) -> bool {
        self.confirmed_reservation()
            .is_some_and(|(reservation, outer)| {
                reservation.member == Some(connection)
                    && self.swarm.behaviour().relay.as_ref().is_some_and(|client| {
                        client.circuit_connection_owner(self.peer, connection)
                            == Some((reservation.relay, outer))
                    })
            })
    }

    /// Reserve using the already selected relay. Only call after explicit authorization
    /// by the user or host. Returns the browser's pinned circuit address once accepted.
    pub async fn reserve_relay(&mut self) -> Result<String, JsError> {
        self.open_membership_store().await?;
        self.refresh_relay_authorization()?;
        if let Some(address) = self.relay_reservation_address() {
            return Ok(address);
        }
        if self.relay_reservation.is_some() || self.swarm.is_connected(&self.peer) {
            return Err(JsError::new(
                "Release the old reservation or close the current VPN session first",
            ));
        }
        self.start_relay_reservation()?;

        let deadline = Instant::now() + CONNECT_TIMEOUT;
        loop {
            if let Some(address) = self.relay_reservation_address() {
                return Ok(address);
            }
            if Instant::now() >= deadline {
                self.release_relay();
                return Err(JsError::new("Explicit relay reservation timed out"));
            }
            if let Err(error) = self.step(None).await {
                self.release_relay();
                return Err(error);
            }
        }
    }

    /// Return the exact advertised circuit while its selected reservation is live.
    pub fn relay_reservation_address(&self) -> Option<String> {
        self.confirmed_reservation()
            .map(|(reservation, _)| reservation.address.to_string())
    }

    /// Opt in to one additional legacy member on the existing reservation.
    /// The exact peer must already be authorized by the committed membership.
    pub async fn allow_incoming_relay_member(&mut self, peer: &str) -> Result<(), JsError> {
        if self.checkpoint.is_some() {
            return Err(JsError::new(
                "Shared incoming circuits require legacy membership",
            ));
        }
        let peer = peer.parse::<PeerId>().map_err(debug_error)?;
        self.open_membership_store().await?;
        self.refresh_relay_authorization()?;
        let (reservation, _) = self
            .confirmed_reservation()
            .ok_or_else(|| JsError::new("No confirmed explicit relay reservation"))?;
        if peer == self.peer
            || peer == reservation.relay
            || peer == *self.swarm.local_peer_id()
            || reservation
                .additional
                .is_some_and(|current| current != peer)
            || !self.forwarder.is_configured_transport_peer(peer)
            || !self
                .forwarder
                .effective_membership()
                .overlay_members()
                .any(|member| member.transport_peer == peer)
        {
            return Err(JsError::new(
                "Additional incoming member is not authorized or the slot is occupied",
            ));
        }
        self.relay_reservation
            .as_mut()
            .expect("confirmed reservation")
            .additional = Some(peer);
        self.sessions.set_limit(2);
        self.additional_inbound.set(Some(peer));
        Ok(())
    }

    #[cfg(feature = "test-hooks")]
    pub fn test_authorized_incoming_members(&self) -> String {
        let peers: Vec<_> = std::iter::once(self.peer)
            .chain(self.additional_relay_peer())
            .filter_map(|peer| self.sessions.outbound(peer))
            .filter(|selected| self.owns_shared_relay_binding(selected.binding))
            .map(|selected| selected.binding.peer.to_string())
            .collect();
        serde_json::json!(peers).to_string()
    }

    #[cfg(feature = "test-hooks")]
    pub fn test_close_incoming_member(&mut self, peer: &str) -> Result<bool, JsError> {
        let peer = peer.parse::<PeerId>().map_err(debug_error)?;
        let binding = self
            .sessions
            .outbound(peer)
            .map(|selected| selected.binding)
            .filter(|binding| self.owns_shared_relay_binding(*binding));
        Ok(binding.is_some_and(|binding| self.swarm.close_connection(binding.connection)))
    }

    /// Stop listening and close the inbound VPN session, if this reservation owns it.
    pub fn release_relay(&mut self) -> bool {
        let Some(reservation) = self.relay_reservation.take() else {
            return false;
        };
        self.additional_inbound.set(None);
        self.swarm.remove_listener(reservation.listener);
        if let Some(peer) = reservation.additional {
            for binding in self.sessions.revoke(peer) {
                self.swarm.close_connection(binding.connection);
            }
            self.sessions.set_limit(1);
        }
        if let Some(connection) = reservation.member {
            self.swarm.close_connection(connection);
            self.clear_session();
        }
        true
    }

    /// Wait for the pinned member to dial the active reservation, then authorize its session.
    /// This never dials the member and does not create or renew a removed reservation.
    pub async fn accept_relay(&mut self) -> Result<String, JsError> {
        self.open_membership_store().await?;
        self.refresh_relay_authorization()?;
        let timeout = if self.checkpoint.is_some() {
            CHECKPOINT_SYNC_TIMEOUT
        } else {
            CONNECT_TIMEOUT
        };
        let deadline = Instant::now() + timeout;
        loop {
            let Some((reservation, _)) = self.confirmed_reservation() else {
                return Err(JsError::new("No confirmed explicit relay reservation"));
            };
            if reservation.member.is_some()
                && self.stream_mtu().is_some()
                && self.membership_sync.is_none()
            {
                return Ok(self.snapshot());
            }
            if Instant::now() >= deadline {
                if let Some(connection) = reservation.member {
                    self.swarm.close_connection(connection);
                    self.clear_session();
                }
                return Err(JsError::new(
                    "Incoming VPN circuit or authorization timed out",
                ));
            }
            self.step(None).await?;
        }
    }

    /// Drive the accepted incoming member and return one authorized IP packet, if available.
    /// Calls are bounded; keep polling while the application wants to receive or serve control.
    pub async fn receive_relay_packet(
        &mut self,
        timeout_ms: u32,
    ) -> Result<Option<Vec<u8>>, JsError> {
        if !(1..=MAX_RECEIVE_WAIT_MS).contains(&timeout_ms) {
            return Err(JsError::new(
                "Relay receive timeout must be between 1 and 5000 ms",
            ));
        }
        self.refresh_relay_authorization()?;
        let shared = self.shared_relay();
        let mtu = if shared && self.confirmed_reservation().is_some() {
            Some(self.config.effective_packet_mtu())
        } else {
            self.stream_mtu().filter(|_| {
                self.confirmed_reservation()
                    .is_some_and(|(reservation, _)| reservation.member.is_some())
            })
        };
        let Some(mtu) = mtu else {
            return Err(JsError::new("No authorized incoming VPN circuit"));
        };
        let mut device = IpDevice::new(mtu).map_err(|error| JsError::new(&error))?;
        let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
        while Instant::now() < deadline {
            if shared {
                self.wait_for_event(Some(PacketTarget::Reservation(&mut device)), 5)
                    .await?;
            } else {
                self.step(Some(&mut device)).await?;
            }
            if let Some((packet, _)) = device.receive(smoltcp::time::Instant::from_millis(0)) {
                return Ok(Some(packet.consume(<[u8]>::to_vec)));
            }
        }
        Ok(None)
    }
}

impl BrowserVpn {
    // Callers must authorize the purpose of the reservation. Starting the
    // listener does not admit a VPN member.
    pub(super) fn start_relay_reservation(&mut self) -> Result<(), JsError> {
        let route = self
            .endpoints
            .relay
            .as_ref()
            .ok_or_else(|| JsError::new("No explicit relay route selected"))?;
        let reservation_addr = route.reservation_addr();
        let listener = self
            .swarm
            .listen_on(reservation_addr.clone())
            .map_err(debug_error)?;
        self.relay_reservation = Some(RelayReservation {
            listener,
            relay: route.relay_peer(),
            address: reservation_addr.with(Protocol::P2p(*self.swarm.local_peer_id())),
            advertised: false,
            publication_addresses: Vec::new(),
            member: None,
            additional: None,
        });
        Ok(())
    }

    fn additional_relay_peer(&self) -> Option<PeerId> {
        self.relay_reservation.as_ref()?.additional
    }

    pub(super) fn shared_relay(&self) -> bool {
        self.additional_relay_peer().is_some()
    }

    pub(super) fn owns_shared_relay_binding(&self, binding: Binding) -> bool {
        self.shared_relay()
            && self
                .sessions
                .primary(binding.peer)
                .is_some_and(|(primary, _)| primary == binding)
            && self.owns_reservation_circuit(binding)
    }

    fn owns_reservation_circuit(&self, binding: Binding) -> bool {
        self.confirmed_reservation()
            .is_some_and(|(reservation, outer)| {
                (binding.peer == self.peer || reservation.additional == Some(binding.peer))
                    && self.swarm.behaviour().relay.as_ref().is_some_and(|client| {
                        client.circuit_connection_owner(binding.peer, binding.connection)
                            == Some((reservation.relay, outer))
                    })
            })
    }

    /// Retirement of one inner circuit must not release the reservation.
    pub(super) fn retire_shared_relay_member(&mut self, binding: Binding) -> bool {
        if !self.shared_relay()
            || !self
                .sessions
                .primary(binding.peer)
                .is_some_and(|(current, _)| current == binding)
        {
            return false;
        }
        if binding.peer == self.peer {
            if let Some(reservation) = &mut self.relay_reservation {
                reservation.member = None;
            }
            self.clear_session();
        } else {
            self.sessions.closed(binding);
            self.swarm.close_connection(binding.connection);
        }
        true
    }

    pub(super) fn refresh_shared_relay(&mut self) -> Result<(), JsError> {
        let Some(additional) = self.additional_relay_peer() else {
            return Ok(());
        };
        self.forwarder
            .merge_membership_records(&[], super::unix_seconds())
            .map_err(debug_error)?;
        let local = p2p_vpn::PeerId::from_libp2p(*self.swarm.local_peer_id());
        if !self
            .forwarder
            .effective_membership()
            .authorizes_configured_peer(local)
        {
            self.release_relay();
            return Err(JsError::new("Local membership has expired or been revoked"));
        }
        let permits_additional = self.forwarder.is_configured_transport_peer(additional);
        self.additional_inbound
            .set(permits_additional.then_some(additional));
        for (peer, permitted) in [
            (
                self.peer,
                self.forwarder.is_configured_transport_peer(self.peer),
            ),
            (additional, permits_additional),
        ] {
            if !permitted && let Some((binding, _)) = self.sessions.primary(peer) {
                self.retire_shared_relay_member(binding);
            }
        }
        Ok(())
    }

    fn refresh_relay_authorization(&mut self) -> Result<(), JsError> {
        if self.shared_relay() {
            return self.refresh_shared_relay();
        }
        if let Err(error) = self.refresh_peer_authorization() {
            self.release_relay();
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn confirmed_reservation(&self) -> Option<(&RelayReservation, ConnectionId)> {
        let reservation = self
            .relay_reservation
            .as_ref()
            .filter(|entry| entry.advertised)?;
        let client = self.swarm.behaviour().relay.as_ref()?;
        let outer =
            client.reservation_listener_connection(reservation.relay, reservation.listener)?;
        client
            .confirmed_reservation_connections(reservation.relay)
            .any(|connection| connection == outer)
            .then_some((reservation, outer))
    }

    pub(super) fn reservation_confirms_address(&self, address: &Multiaddr) -> bool {
        self.confirmed_reservation()
            .is_some_and(|(reservation, _)| reservation.publication_addresses.contains(address))
    }

    pub(super) fn observe_relay_listener(
        &mut self,
        event: &SwarmEvent<BehaviourEvent>,
    ) -> Result<(), JsError> {
        let Some(reservation) = self.relay_reservation.as_mut() else {
            return Ok(());
        };
        match event {
            SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } if *listener_id == reservation.listener => {
                if address == &reservation.address {
                    reservation.advertised = true;
                }
                // The relay emits up to four new entrances before expiring the old set.
                if reservation.publication_addresses.len() < 8
                    && !reservation.publication_addresses.contains(address)
                    && p2p_vpn::peer_address_record::browser_advertisement::circuit_relay(
                        address,
                        *self.swarm.local_peer_id(),
                    ) == Some(reservation.relay)
                {
                    reservation.publication_addresses.push(address.clone());
                }
            }
            SwarmEvent::ExpiredListenAddr {
                listener_id,
                address,
            } if *listener_id == reservation.listener => {
                if address == &reservation.address {
                    reservation.advertised = false;
                }
                reservation
                    .publication_addresses
                    .retain(|entry| entry != address);
            }
            SwarmEvent::ListenerClosed {
                listener_id,
                reason,
                ..
            } if *listener_id == reservation.listener => {
                self.release_relay();
                return Err(match reason {
                    Ok(()) => JsError::new("Explicit relay reservation closed"),
                    Err(error) => debug_error(error),
                });
            }
            SwarmEvent::ConnectionClosed { connection_id, .. }
                if Some(*connection_id) == reservation.member =>
            {
                reservation.member = None;
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn claim_incoming_circuit(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
        endpoint: &ConnectedPoint,
    ) -> Result<bool, JsError> {
        let owned = endpoint.is_relayed()
            && self.sessions.primary(peer).is_none()
            && self.owns_reservation_circuit(Binding { peer, connection });
        if !owned {
            self.swarm.close_connection(connection);
            return Ok(false);
        }
        if let Err(error) = self.refresh_relay_authorization() {
            self.swarm.close_connection(connection);
            return Err(error);
        }
        if self.shared_relay() && !self.forwarder.is_configured_transport_peer(peer) {
            self.swarm.close_connection(connection);
            return Ok(false);
        }
        if peer == self.peer {
            self.relay_reservation
                .as_mut()
                .expect("confirmed reservation")
                .member = Some(connection);
        }
        Ok(true)
    }
}
