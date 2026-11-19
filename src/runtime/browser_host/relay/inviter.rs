//! Reservation egress only for an operator-pinned pair of relay addresses.

use std::{
    collections::{HashMap, hash_map::Entry},
    io,
    sync::Mutex,
    time::{Duration, Instant},
};

use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use serde::Serialize;

use super::{Gateway, MAX_APPROVED_ENTRANCES, probe};
use crate::runtime::browser_host::with_default_path;

const PREPARE_BUDGET: Duration = Duration::from_secs(5);
const PROBE_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Default)]
pub(super) struct Policy {
    aliases: HashMap<PeerId, Multiaddr>,
    next_probe: Mutex<Option<Instant>>,
}

#[derive(Serialize)]
pub(in crate::runtime::browser_host) struct ReservationReply {
    pub(in crate::runtime::browser_host) relay_entrance: String,
    pub(in crate::runtime::browser_host) native_alias: String,
    pub(in crate::runtime::browser_host) relay_lease_id: String,
}

impl Policy {
    pub(super) fn new(gateway: &Gateway, addresses: Vec<Multiaddr>) -> io::Result<Self> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "each inviter native alias must match one pinned WebRTC relay ID and public IP",
            )
        };
        if addresses.len() > MAX_APPROVED_ENTRANCES {
            return Err(invalid());
        }
        let mut policy = Self::default();
        for address in addresses {
            let Some(Protocol::P2p(relay)) = address.iter().last() else {
                return Err(invalid());
            };
            let entrance = gateway.pinned_entrance(relay).ok_or_else(invalid)?;
            let address = probe::native_contact(relay, address).ok_or_else(invalid)?;
            if probe::numeric_host(&address) != probe::numeric_host(entrance) {
                return Err(invalid());
            }
            let Entry::Vacant(alias) = policy.aliases.entry(relay) else {
                return Err(invalid());
            };
            alias.insert(address);
        }
        Ok(policy)
    }

    pub(super) async fn reserve(
        &self,
        gateway: &Gateway,
        relay: PeerId,
        owned_interface: Option<&str>,
    ) -> io::Result<ReservationReply> {
        let unavailable = || io::Error::new(io::ErrorKind::NotFound, "inviter relay not approved");
        let native = self.aliases.get(&relay).ok_or_else(unavailable)?;
        let webrtc = gateway.pinned_entrance(relay).ok_or_else(unavailable)?;
        let manager = gateway.lease_manager();
        let slot = manager.reserve()?;
        {
            let mut next = self
                .next_probe
                .lock()
                .map_err(|_| io::Error::other("inviter relay policy poisoned"))?;
            let now = Instant::now();
            if next.is_some_and(|next| now < next) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "inviter relay probe limit",
                ));
            }
            *next = Some(now + PROBE_INTERVAL);
        }
        let prepared = with_default_path(owned_interface, PREPARE_BUDGET, |path| async move {
            probe::verify_pinned_pair(&path, relay, native, webrtc).await?;
            manager.prepare_inviter(path.scope, webrtc, slot).await
        })
        .await?;
        let lease = prepared.publish()?;
        Ok(ReservationReply {
            relay_entrance: lease.relay_address,
            native_alias: native.to_string(),
            relay_lease_id: lease.relay_lease_id,
        })
    }
}
