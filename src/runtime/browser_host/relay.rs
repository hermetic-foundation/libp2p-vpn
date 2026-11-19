//! Prepare an approved relay without exposing its upstream address.

use std::{
    collections::{HashMap, HashSet},
    io,
    sync::{Arc, Mutex},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use rand_core::{OsRng, RngCore as _};
use serde::Serialize;
use tokio::{sync::Semaphore, task::JoinHandle};

use crate::runtime::browser_relay_egress;

use super::{
    DiscoveryRequest, browser_address, lookup, validate_scope, verified_addresses,
    with_default_dht_scope,
};

const MAX_APPROVED_ENTRANCES: usize = 8;
const MAX_LIVE_LEASES: usize = 2;
const LEASE_ID_BYTES: usize = 24;

pub(super) struct Gateway {
    entrances: HashMap<PeerId, Multiaddr>,
    slots: Arc<Semaphore>,
    leases: Mutex<HashMap<String, LeaseTask>>,
}

struct LeaseTask(JoinHandle<()>);

impl Drop for LeaseTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Serialize)]
pub(super) struct LeaseReply {
    pub(super) relay_address: String,
    pub(super) relay_lease_id: String,
}

pub(super) struct Resolution {
    pub(super) addresses: Vec<Multiaddr>,
    pub(super) relay: Option<LeaseReply>,
}

struct Candidates {
    direct: Vec<Multiaddr>,
    circuit: Option<Multiaddr>,
}

impl Gateway {
    pub(super) fn new(entrances: Vec<Multiaddr>) -> io::Result<Self> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected up to eight public WebRTC Direct entrances, one per pinned relay peer",
            )
        };
        if entrances.len() > MAX_APPROVED_ENTRANCES {
            return Err(invalid());
        }
        let mut approved = HashMap::new();
        for address in entrances {
            let Some(Protocol::P2p(peer)) = address.iter().last() else {
                return Err(invalid());
            };
            let address = browser_address(peer, address).ok_or_else(invalid)?;
            if approved.insert(peer, address).is_some() {
                return Err(invalid());
            }
        }
        Ok(Self {
            entrances: approved,
            slots: Arc::new(Semaphore::new(MAX_LIVE_LEASES)),
            leases: Mutex::new(HashMap::new()),
        })
    }

    pub(super) fn enabled(&self) -> bool {
        !self.entrances.is_empty()
    }

    pub(super) async fn resolve(&self, request: DiscoveryRequest<'_>) -> io::Result<Resolution> {
        validate_scope(request.network_name, request.membership_tag)?;
        let (addresses, prepared) = with_default_dht_scope(
            &request.protocol,
            &request.bootstrap,
            request.owned_interface,
            |swarm, scope| async {
                let Candidates {
                    direct: addresses,
                    circuit,
                } = lookup(&request, swarm, |value| {
                    self.candidates(request.peer, verified_addresses(&request, value))
                })
                .await?;
                let Some(route) = circuit else {
                    return Ok((addresses, None));
                };
                let attempt = async {
                    let permit = Arc::clone(&self.slots).try_acquire_owned().map_err(|_| {
                        io::Error::new(io::ErrorKind::WouldBlock, "browser relay lease limit")
                    })?;
                    let (address, pump) = browser_relay_egress::prepare(scope, &route).await?;
                    Ok::<_, io::Error>((address, pump, permit))
                }
                .await;
                match attempt {
                    Ok(prepared) => Ok((addresses, Some(prepared))),
                    Err(_) if !addresses.is_empty() => Ok((addresses, None)),
                    Err(error) => Err(error),
                }
            },
        )
        .await?;
        let Some((address, pump, permit)) = prepared else {
            return Ok(Resolution {
                addresses,
                relay: None,
            });
        };
        let mut bytes = [0; LEASE_ID_BYTES];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let lease_id = URL_SAFE_NO_PAD.encode(bytes);
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| io::Error::other("relay lease owner poisoned"))?;
        leases.retain(|_, task| !task.0.is_finished());
        leases.insert(
            lease_id.clone(),
            LeaseTask(tokio::spawn(async move {
                let _permit = permit;
                let _ = pump.await;
            })),
        );
        Ok(Resolution {
            addresses,
            relay: Some(LeaseReply {
                relay_address: address.to_string(),
                relay_lease_id: lease_id,
            }),
        })
    }

    pub(super) fn release(&self, lease_id: &str) -> io::Result<bool> {
        let lease = self
            .leases
            .lock()
            .map_err(|_| io::Error::other("relay lease owner poisoned"))?
            .remove(lease_id);
        Ok(lease.is_some())
    }

    fn candidates(&self, peer: PeerId, advertised: Vec<Multiaddr>) -> Option<Candidates> {
        let mut seen = HashSet::new();
        let mut direct = Vec::new();
        let mut relay = None;
        for address in advertised {
            if is_circuit(&address) {
                if relay.is_none() {
                    relay = self.approved_route(peer, address);
                }
            } else if let Some(address) = browser_address(peer, address)
                && seen.insert(address.clone())
            {
                direct.push(address);
            }
        }
        (!direct.is_empty() || relay.is_some()).then_some(Candidates {
            direct,
            circuit: relay,
        })
    }

    fn approved_route(&self, peer: PeerId, mut route: Multiaddr) -> Option<Multiaddr> {
        if route.pop()? != Protocol::P2p(peer) || route.pop()? != Protocol::P2pCircuit {
            return None;
        }
        let Protocol::P2p(relay) = route.pop()? else {
            return None;
        };
        if relay == peer
            || route.is_empty()
            || route
                .iter()
                .any(|part| matches!(part, Protocol::P2p(_) | Protocol::P2pCircuit))
        {
            return None;
        }
        // A signed native TCP/QUIC route can use our approved WebRTC entrance
        // into the same relay reservation. Never dial the advertised entrance.
        Some(
            self.entrances
                .get(&relay)?
                .clone()
                .with(Protocol::P2pCircuit)
                .with(Protocol::P2p(peer)),
        )
    }
}

fn is_circuit(address: &Multiaddr) -> bool {
    address
        .iter()
        .any(|protocol| protocol == Protocol::P2pCircuit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_requires_an_approved_identity_and_exact_destination() {
        let relay = PeerId::random();
        let destination = PeerId::random();
        let addr: Multiaddr = format!(
            "/ip4/8.8.8.8/udp/4001/webrtc-direct/certhash/uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g/p2p/{relay}"
        ).parse().unwrap();
        let gateway = Gateway::new(vec![addr.clone()]).unwrap();
        let route = |relay, peer| {
            format!("/ip4/8.8.4.4/tcp/4001/p2p/{relay}/p2p-circuit/p2p/{peer}")
                .parse()
                .unwrap()
        };
        assert_eq!(
            gateway.approved_route(destination, route(relay, destination)),
            Some(
                addr.with(Protocol::P2pCircuit)
                    .with(Protocol::P2p(destination))
            )
        );
        assert!(
            gateway
                .approved_route(destination, route(PeerId::random(), destination))
                .is_none()
        );
        assert!(
            gateway
                .approved_route(destination, route(relay, PeerId::random()))
                .is_none()
        );
        assert!(gateway.approved_route(relay, route(relay, relay)).is_none());
    }
}
