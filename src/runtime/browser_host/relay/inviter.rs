//! Reservation egress for a pinned pair or an independently verified public relay.

#[cfg(feature = "webrtc")]
mod automatic;

use std::{
    collections::{HashMap, hash_map::Entry},
    io,
    sync::Mutex,
    time::{Duration, Instant},
};

use libp2p::{Multiaddr, PeerId, StreamProtocol, multiaddr::Protocol};
use serde::Serialize;

use super::{Gateway, MAX_APPROVED_ENTRANCES, probe};
use crate::runtime::browser_host::with_default_path;

const PREPARE_BUDGET: Duration = Duration::from_secs(5);
const PROBE_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Default)]
pub(super) struct Policy {
    aliases: HashMap<PeerId, Multiaddr>,
    default_relay: Option<PeerId>,
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
            policy.default_relay.get_or_insert(relay);
        }
        Ok(policy)
    }

    pub(super) async fn reserve(
        &self,
        gateway: &Gateway,
        relay: Option<PeerId>,
        protocol: &StreamProtocol,
        bootstrap: &[(PeerId, Multiaddr)],
        owned_interface: Option<&str>,
    ) -> io::Result<ReservationReply> {
        let unavailable = || io::Error::new(io::ErrorKind::NotFound, "inviter relay not approved");
        let pinned = match relay.or(self.default_relay) {
            Some(relay) => Some((
                relay,
                self.aliases.get(&relay).ok_or_else(unavailable)?,
                gateway.pinned_entrance(relay).ok_or_else(unavailable)?,
            )),
            None if gateway.entrances.is_empty() => None,
            None => return Err(unavailable()),
        };
        #[cfg(not(feature = "webrtc"))]
        if pinned.is_none() {
            return Err(unavailable());
        }
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
        let (native, prepared) = match pinned {
            Some((relay, native, webrtc)) => {
                let prepared =
                    with_default_path(owned_interface, PREPARE_BUDGET, |path| async move {
                        probe::verify_pinned_pair(&path, relay, native, webrtc).await?;
                        manager.prepare_inviter(path.scope, webrtc, slot).await
                    })
                    .await?;
                (native.clone(), prepared)
            }
            #[cfg(feature = "webrtc")]
            None => {
                with_default_path(owned_interface, automatic::BUDGET, |path| async move {
                    let (native, entrance, proof) =
                        automatic::select(&path, protocol, bootstrap).await?;
                    // Keep both stopped probe sockets bound until both lease sockets exist.
                    let prepared = manager.prepare_inviter(path.scope, &entrance, slot).await?;
                    drop(proof);
                    Ok((native, prepared))
                })
                .await?
            }
            #[cfg(not(feature = "webrtc"))]
            None => {
                let _ = (protocol, bootstrap);
                return Err(unavailable());
            }
        };
        let lease = prepared.publish()?;
        Ok(ReservationReply {
            relay_entrance: lease.relay_address,
            native_alias: native.to_string(),
            relay_lease_id: lease.relay_lease_id,
        })
    }
}
