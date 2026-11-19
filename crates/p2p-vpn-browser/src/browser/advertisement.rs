use std::time::Duration;

use libp2p::Multiaddr;
use p2p_vpn::{
    config::PUBLIC_IPFS_KADEMLIA_PROTOCOL,
    peer_address_record::browser_advertisement::{Challenge, MAX_CIRCUIT_BYTES, Submission},
};
use wasm_bindgen::prelude::*;
use web_time::Instant;

use super::{BrowserVpn, debug_error, unix_seconds};

#[wasm_bindgen]
impl BrowserVpn {
    /// Sign one explicitly named public circuit for a local publication challenge.
    /// This does not reserve, renew, dial, or publish anything.
    pub async fn sign_relay_advertisement(
        &mut self,
        address: &str,
        challenge: &str,
    ) -> Result<String, JsError> {
        let challenge = Challenge::parse(challenge).map_err(debug_error)?;
        if address.len() > MAX_CIRCUIT_BYTES || address != challenge.address {
            return Err(JsError::new(
                "Publication requires the exact approved circuit",
            ));
        }
        let address: Multiaddr = address.parse().map_err(debug_error)?;
        self.open_membership_store().await?;
        self.check_publication_scope(&challenge)?;
        let unconfirmed =
            || JsError::new("Public circuit is not confirmed on the current reservation");
        let deadline = Instant::now() + Duration::from_millis(250);
        // RESERVE can report the native entrance after the WebRTC ingress that
        // made reserve_relay return. Drive only the already-confirmed listener.
        loop {
            if self.relay_reservation_address().is_none() || Instant::now() >= deadline {
                return Err(unconfirmed());
            }
            self.step(None).await?;
            if self.reservation_confirms_address(&address) {
                break;
            }
        }
        self.check_publication_scope(&challenge)?;
        let identity = self.effective_config().identity().map_err(debug_error)?;
        Submission::sign(&challenge, &identity, unix_seconds()).map_err(debug_error)
    }
}

impl BrowserVpn {
    fn check_publication_scope(&mut self, challenge: &Challenge) -> Result<(), JsError> {
        self.refresh_peer_authorization()?;
        let config = self.effective_config();
        let discovery = &config.network.discovery;
        if !discovery.kademlia
            || discovery.kademlia_protocol == PUBLIC_IPFS_KADEMLIA_PROTOCOL
            || challenge.kademlia_protocol != discovery.kademlia_protocol
            || challenge.network_name != config.network.name
            || challenge.membership_tag != self.membership_tag()
            || challenge.browser_peer != self.local_peer_id()
            || challenge.destination != self.peer.to_string()
            || !self.forwarder.is_configured_transport_peer(self.peer)
            || self
                .checkpoint
                .as_ref()
                .is_some_and(|checkpoint| checkpoint.enrollment_floor.is_some())
        {
            return Err(JsError::new(
                "Browser publication scope or destination is not authorized",
            ));
        }
        Ok(())
    }
}
