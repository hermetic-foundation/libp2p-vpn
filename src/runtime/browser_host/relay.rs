//! Prepare bounded gateway leases through approved or authenticated relay contacts.

mod inviter;
mod lease;
mod probe;

use std::{
    collections::{HashMap, HashSet},
    io,
};

use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};

pub(super) use inviter::ReservationReply;
pub(super) use lease::{AuthorizedCircuit, LeaseManager, LeaseReply};

use super::{
    DiscoveryRequest, browser_address, lookup, validate_scope, verified_addresses,
    with_default_dht_scope,
};

const MAX_APPROVED_ENTRANCES: usize = 8;

pub(super) struct Gateway {
    entrances: HashMap<PeerId, Multiaddr>,
    leases: LeaseManager,
    inviter: inviter::Policy,
}

pub(super) struct Resolution {
    pub(super) addresses: Vec<Multiaddr>,
    pub(super) relay: Option<LeaseReply>,
}

struct Candidates {
    direct: Vec<Multiaddr>,
    circuit: Option<Circuit>,
}

enum Circuit {
    Override(Multiaddr),
    Identify {
        relay: PeerId,
        contact: probe::Contact,
    },
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
            leases: LeaseManager::new(),
            inviter: inviter::Policy::default(),
        })
    }

    pub(super) fn lease_manager(&self) -> &LeaseManager {
        &self.leases
    }

    pub(super) fn pinned_entrance(&self, relay: PeerId) -> Option<&Multiaddr> {
        self.entrances.get(&relay)
    }

    pub(super) fn set_inviter_aliases(&mut self, aliases: Vec<Multiaddr>) -> io::Result<()> {
        self.inviter = inviter::Policy::new(self, aliases)?;
        Ok(())
    }

    pub(super) async fn reserve_inviter(
        &self,
        relay: Option<PeerId>,
        protocol: &libp2p::StreamProtocol,
        bootstrap: &[(PeerId, Multiaddr)],
        owned_interface: Option<&str>,
    ) -> io::Result<ReservationReply> {
        self.inviter
            .reserve(self, relay, protocol, bootstrap, owned_interface)
            .await
    }

    pub(super) async fn resolve(&self, request: DiscoveryRequest<'_>) -> io::Result<Resolution> {
        validate_scope(request.network_name, request.membership_tag)?;
        let request = &request;
        let (addresses, prepared) = with_default_dht_scope(
            &request.protocol,
            &request.bootstrap,
            request.owned_interface,
            |mut swarm, path| async move {
                let Candidates {
                    direct: addresses,
                    circuit,
                } = lookup(request, &mut swarm, |value| {
                    self.candidates(request.peer, verified_addresses(request, value))
                })
                .await?;
                let Some(circuit) = circuit else {
                    return Ok((addresses, None));
                };
                let attempt = async {
                    let route = match circuit {
                        Circuit::Override(route) => route,
                        Circuit::Identify { relay, contact } => circuit_address(
                            contact.verify(relay, &mut swarm, &path).await?,
                            request.peer,
                        ),
                    };
                    self.lease_manager()
                        .lease_member(path.scope, AuthorizedCircuit::after_lookup(route))
                        .await
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
        let relay = prepared.map(lease::PreparedLease::publish).transpose()?;
        Ok(Resolution { addresses, relay })
    }

    pub(super) fn release(&self, lease_id: &str) -> io::Result<bool> {
        self.lease_manager().release(lease_id)
    }

    fn candidates(&self, peer: PeerId, advertised: Vec<Multiaddr>) -> Option<Candidates> {
        let mut seen = HashSet::new();
        let mut direct = Vec::new();
        let mut manual = None;
        let mut automatic = None;
        for address in advertised {
            if is_circuit(&address) {
                let Some((relay, entrance)) = signed_entrance(peer, address) else {
                    continue;
                };
                if let Some(approved) = self.entrances.get(&relay) {
                    manual.get_or_insert_with(|| {
                        Circuit::Override(circuit_address(approved.clone(), peer))
                    });
                } else if automatic.is_none()
                    && let Some(contact) = probe::Contact::from_signed(relay, entrance)
                {
                    automatic = Some(Circuit::Identify { relay, contact });
                }
            } else if let Some(address) = browser_address(peer, address)
                && seen.insert(address.clone())
            {
                direct.push(address);
            }
        }
        let circuit = manual.or(automatic);
        (!direct.is_empty() || circuit.is_some()).then_some(Candidates { direct, circuit })
    }
}

fn signed_entrance(peer: PeerId, mut route: Multiaddr) -> Option<(PeerId, Multiaddr)> {
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
    Some((relay, route.with(Protocol::P2p(relay))))
}

fn circuit_address(entrance: Multiaddr, destination: PeerId) -> Multiaddr {
    entrance
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(destination))
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
    fn configured_override_wins_and_signed_destination_must_match() {
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
        let other = PeerId::random();
        let selected = gateway
            .candidates(
                destination,
                vec![route(other, destination), route(relay, destination)],
            )
            .unwrap();
        let Some(Circuit::Override(selected)) = selected.circuit else {
            panic!("operator override must win");
        };
        assert_eq!(selected, circuit_address(addr, destination));
        assert!(
            gateway
                .candidates(destination, vec![route(relay, other)])
                .is_none()
        );
        assert!(
            gateway
                .candidates(relay, vec![route(relay, relay)])
                .is_none()
        );
    }
}
