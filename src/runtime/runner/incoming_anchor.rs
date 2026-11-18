//! Automatic relay acquisition uses actual authenticated connections, not advertised transports.
use super::*;

pub(super) const MAX_CANDIDATE_ADDRESSES: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Family {
    V4 = 0,
    V6 = 1,
}

fn address_family(address: &Multiaddr) -> Option<Family> {
    address.iter().find_map(|protocol| match protocol {
        Protocol::Ip4(_) | Protocol::Dns4(_) => Some(Family::V4),
        Protocol::Ip6(ip) if ip.to_ipv4_mapped().is_some() => Some(Family::V4),
        Protocol::Ip6(_) | Protocol::Dns6(_) => Some(Family::V6),
        _ => None,
    })
}

/// The caller must supply only addresses from one authenticated HOP owner.
pub(super) fn dual_family_candidate(addresses: &[Multiaddr]) -> bool {
    let has_family = |family| {
        addresses
            .iter()
            .any(|address| address_family(address) == Some(family))
    };
    has_family(Family::V4) && has_family(Family::V6)
}

/// Reserve room for both entrances of one actual, publicly dialable relay in
/// an otherwise best-effort, bounded signed address record.
pub(super) fn public_relay_publication_pair<'a>(
    listeners: impl IntoIterator<Item = &'a Multiaddr>,
    local_peer: Libp2pPeerId,
) -> [Option<&'a Multiaddr>; 2] {
    let mut by_relay = HashMap::<_, [Option<_>; 2]>::new();
    for address in listeners {
        let Some(relay) = relayed_address_relay_peer(address) else {
            continue;
        };
        let Some(family) = address_family(address) else {
            continue;
        };
        if discovered_address_target(address) != Some(local_peer)
            || !kademlia_peer_address_is_advertisable(address)
        {
            continue;
        }
        let pair = by_relay.entry(relay).or_default();
        pair[family as usize].get_or_insert(address);
        if pair.iter().all(Option::is_some) {
            return *pair;
        }
    }
    [None, None]
}

pub(super) fn authenticated_dial_address(
    peer: Libp2pPeerId,
    connection: ConnectionId,
    epochs: &ConnectionEpochs,
    connections: &HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
) -> Option<Multiaddr> {
    if !epochs.is_usable(connection) || !epochs.established.contains_key(&connection) {
        return None;
    }
    let ConnectedPoint::Dialer { address, .. } = connections.get(&(peer, connection))? else {
        return None;
    };
    // An actual outbound destination is not a remote-supplied listen address.
    // Inbound ephemeral ports and nested circuit endpoints are not candidates.
    auto_relay_candidate_address(peer, address)
}

pub(super) fn candidate_addresses(
    peer: Libp2pPeerId,
    advertised: &[Multiaddr],
    known: Option<&Multiaddr>,
    networks: &[LocalInterfaceNetwork],
    source: DiscoveredPeerAddressSource,
) -> Vec<Multiaddr> {
    // Validate remote advertisements before adding the already retained route.
    // A public Identify response cannot introduce a private address this way.
    let advertised = advertised.iter().filter(|address| {
        !source.requires_public_transport() || discovered_address_uses_public_transport(address)
    });
    let mut groups: [[Vec<Multiaddr>; 2]; 4] = Default::default();
    let mut best_family = [None, None];
    for address in advertised.chain(known) {
        if address.iter().any(|protocol| match protocol {
            Protocol::P2p(owner) => owner != peer,
            Protocol::P2pCircuit | Protocol::Tcp(0) | Protocol::Udp(0) => true,
            Protocol::Ip4(ip) => ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast(),
            Protocol::Ip6(ip) => {
                ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.to_ipv4_mapped().is_some_and(|ip| {
                        ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast()
                    })
            }
            _ => false,
        }) {
            continue;
        }
        let Some(address) = auto_relay_candidate_address(peer, address) else {
            continue;
        };
        let locality = auto_relay_candidate_address_rank(&address, networks) as usize;
        let transport = match transport_kind(&address) {
            Some(PathKind::DirectTcpStream) => 0,
            Some(PathKind::DirectQuicStream) => 1,
            _ => continue,
        };
        if let Some(family) = address_family(&address) {
            let best = &mut best_family[family as usize];
            if best
                .as_ref()
                .is_none_or(|(rank, _)| (locality, transport) < *rank)
            {
                *best = Some(((locality, transport), address.clone()));
            }
        }
        let group = &mut groups[locality][transport];
        if group.len() < MAX_CANDIDATE_ADDRESSES && !group.contains(&address) {
            group.push(address);
        }
    }
    let mut result = Vec::with_capacity(MAX_CANDIDATE_ADDRESSES);
    for [tcp, quic] in groups {
        let mut tcp = tcp.into_iter();
        let mut quic = quic.into_iter();
        while result.len() < MAX_CANDIDATE_ADDRESSES {
            let pair = [tcp.next(), quic.next()];
            if pair.iter().all(Option::is_none) {
                break;
            }
            let remaining = MAX_CANDIDATE_ADDRESSES - result.len();
            result.extend(pair.into_iter().flatten().take(remaining));
        }
    }
    if best_family.iter().all(Option::is_some) && !dual_family_candidate(&result) {
        // Preserve the preferred route even when reserving room for both families.
        let mut replacement = result.len();
        for (family, (_, address)) in [Family::V4, Family::V6]
            .into_iter()
            .zip(best_family.into_iter().flatten())
        {
            if !result
                .iter()
                .any(|address| address_family(address) == Some(family))
            {
                replacement -= 1;
                result[replacement] = address;
            }
        }
    }
    result
}

#[cfg(test)]
pub(super) fn attempt_at(
    swarm: &mut Swarm<Behaviour>,
    state: &mut AutoRelayState,
    metrics: &RuntimeMetrics,
    epochs: &mut ConnectionEpochs,
    connections: &HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
    now: Instant,
) {
    attempt_with_configured_at(swarm, state, metrics, epochs, connections, &[], now);
}

pub(super) fn attempt_with_configured_at(
    swarm: &mut Swarm<Behaviour>,
    state: &mut AutoRelayState,
    metrics: &RuntimeMetrics,
    epochs: &mut ConnectionEpochs,
    connections: &HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
    configured_relays: &[(Libp2pPeerId, Multiaddr)],
    now: Instant,
) {
    state.exclude_configured_relays(configured_relays);
    expire_pending_auto_relay_reservations(swarm, state, metrics, epochs, now);
    let retention = &swarm.behaviour().connection_retention;
    for (peer, address) in state.next_reservation_targets_excluding(
        now,
        |peer| {
            retention.relay_handoff_owns_peer(peer)
                || configured_relays
                    .iter()
                    .any(|(configured, _)| *configured == peer)
        },
        |peer| {
            connections.iter().any(|((owner, id), endpoint)| {
                *owner == peer
                    && !endpoint.is_relayed()
                    && epochs.is_usable(*id)
                    && epochs.established.contains_key(id)
                    && retention
                        .services(peer, *id)
                        .is_some_and(|services| services.relay)
            })
        },
    ) {
        metrics.record_auto_relay_reservation_attempt();
        log_runtime_event(
            LogLevel::Info,
            "auto_relay_reservation_attempt",
            &[
                ("relay", &peer.to_string()),
                ("address", &address.to_string()),
            ],
        );
    }
    let pending = state
        .pending_reservations
        .iter()
        .filter(|(peer, _)| {
            !state.reservation_listeners.contains_key(peer)
                && !swarm
                    .behaviour()
                    .connection_retention
                    .relay_handoff_owns_peer(**peer)
        })
        .map(|(peer, pending)| (*peer, pending.clone()))
        .collect::<Vec<_>>();
    for (peer, mut pending) in pending {
        let scoped_platform = cfg!(any(target_os = "linux", target_os = "android"));
        let public = relay_transport_is_publicly_dialable(&pending.address);
        let eligible = |id| {
            if !scoped_platform {
                true
            } else if public {
                public_connection_available(swarm, peer, id)
            } else {
                connections.get(&(peer, id)).is_some_and(|endpoint| {
                    !relay_transport_is_publicly_dialable(endpoint.get_remote_address())
                })
            }
        };
        if pending.owned_dial.is_none()
            && state
                .reservation_failures
                .get(&peer)
                .is_some_and(|failures| *failures > 0)
            && transport_kind(&pending.address) == Some(PathKind::DirectTcpStream)
            && let Some(address) = quic_fallback(peer, epochs, connections, eligible)
        {
            pending.address = address.clone();
            state
                .pending_reservations
                .get_mut(&peer)
                .expect("pending attempt")
                .address = address;
            log_runtime_event(
                LogLevel::Info,
                "auto_relay_reservation_quic_fallback",
                &[("relay", &peer.to_string())],
            );
        }
        if auto_relay_candidate_address(peer, &pending.address).is_none() {
            failed(
                state,
                metrics,
                peer,
                now,
                "unsupported_or_mismatched_address",
            );
            continue;
        }
        if let Some(id) = matching_connection_where(peer, &pending, epochs, connections, eligible) {
            if !swarm
                .behaviour_mut()
                .relay
                .prefer_relay_connection(peer, id)
            {
                failed(state, metrics, peer, now, "connection_no_longer_owned");
                continue;
            }
            if let Some(unused) = pending.owned_dial
                && unused != id
                && !epochs.established.contains_key(&unused)
            {
                epochs.mark_retiring(unused);
                swarm.close_connection(unused);
            }
            if pending.owned_dial == Some(id) {
                // Native address fallback shares one token. Publish its successful route,
                // not the first (possibly refused) address in the dial options.
                pending.address = auto_relay_candidate_address(
                    peer,
                    connections[&(peer, id)].get_remote_address(),
                )
                .expect("selected direct transport is supported");
                state
                    .pending_reservations
                    .get_mut(&peer)
                    .expect("pending attempt")
                    .address = pending.address.clone();
            }
            let address = pending.address.with(Protocol::P2pCircuit);
            match swarm.listen_on(address) {
                Ok(listener)
                    if swarm
                        .behaviour_mut()
                        .relay
                        .pin_reservation_listener(peer, listener, id)
                        && state.record_reservation_listener(peer, listener, id) =>
                {
                    log_runtime_event(
                        LogLevel::Info,
                        "auto_relay_reservation_connection_selected",
                        &[
                            ("relay", &peer.to_string()),
                            ("connection_id", &id.to_string()),
                        ],
                    );
                }
                Ok(listener) => {
                    swarm.remove_listener(listener);
                    failed(state, metrics, peer, now, "listener_ownership_conflict");
                }
                Err(error) => failed(state, metrics, peer, now, &format!("{error:?}")),
            }
        } else if let Some(id) = pending.owned_dial {
            // Admission has one token and deadline, including repeated driver ticks.
            if !epochs.is_usable(id) {
                failed(state, metrics, peer, now, "setup_connection_failed");
            }
        } else {
            let addresses = state
                .candidate_addresses(peer)
                .iter()
                .filter(|address| {
                    !scoped_platform || relay_transport_is_publicly_dialable(address) == public
                })
                .cloned();
            let opts = known_peer_dial_options(peer, addresses, PeerCondition::Always);
            let id = opts.connection_id();
            let result = if public {
                epochs.dial_public(swarm, opts)
            } else {
                epochs.dial(swarm, opts)
            };
            match result {
                Ok(()) => {
                    state
                        .pending_reservations
                        .get_mut(&peer)
                        .expect("pending attempt")
                        .owned_dial = Some(id);
                    log_runtime_event(
                        LogLevel::Info,
                        "auto_relay_reservation_transport_connecting",
                        &[
                            ("relay", &peer.to_string()),
                            ("connection_id", &id.to_string()),
                        ],
                    );
                }
                Err(error) => failed(state, metrics, peer, now, &error.to_string()),
            }
        }
    }
}

fn failed(
    state: &mut AutoRelayState,
    metrics: &RuntimeMetrics,
    peer: Libp2pPeerId,
    now: Instant,
    reason: &str,
) {
    state.release_reservation_for_retry_after(peer, now);
    let evicted = state.record_reservation_failure(peer);
    metrics.record_auto_relay_reservation_failure();
    log_runtime_event(
        LogLevel::Warn,
        "auto_relay_reservation_failed",
        &[
            ("relay", &peer.to_string()),
            ("error", reason),
            ("evicted", &evicted.to_string()),
        ],
    );
}

fn public_connection_available(
    swarm: &Swarm<Behaviour>,
    peer: Libp2pPeerId,
    id: ConnectionId,
) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        swarm
            .behaviour()
            .connection_retention
            .physical_routes()
            .is_some_and(|routes| routes.public_discovery_connection_available(peer, id))
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = (swarm, peer, id);
        true
    }
}

fn quic_fallback(
    peer: Libp2pPeerId,
    epochs: &ConnectionEpochs,
    connections: &HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
    eligible: impl Fn(ConnectionId) -> bool,
) -> Option<Multiaddr> {
    let networks = local_interface_networks("");
    connections
        .iter()
        .filter_map(|((owner, id), endpoint)| {
            if *owner != peer
                || !epochs.is_usable(*id)
                || !epochs.established.contains_key(id)
                || !eligible(*id)
                || endpoint.is_relayed()
                || transport_kind(endpoint.get_remote_address()) != Some(PathKind::DirectQuicStream)
            {
                return None;
            }
            let address = auto_relay_candidate_address(peer, endpoint.get_remote_address())?;
            Some((
                auto_relay_candidate_address_rank(&address, &networks),
                *id,
                address,
            ))
        })
        .min_by_key(|(rank, id, _)| (*rank, *id))
        .map(|(_, _, address)| address)
}

#[cfg(test)]
fn matching_connection(
    peer: Libp2pPeerId,
    pending: &PendingAutoRelayReservation,
    epochs: &ConnectionEpochs,
    connections: &HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
) -> Option<ConnectionId> {
    matching_connection_where(peer, pending, epochs, connections, |_| true)
}

fn matching_connection_where(
    peer: Libp2pPeerId,
    pending: &PendingAutoRelayReservation,
    epochs: &ConnectionEpochs,
    connections: &HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
    eligible: impl Fn(ConnectionId) -> bool,
) -> Option<ConnectionId> {
    let desired = transport_kind(&pending.address)?;
    connections
        .iter()
        .filter_map(|((owner, id), endpoint)| {
            let address = endpoint.get_remote_address();
            (*owner == peer
                && epochs.is_usable(*id)
                && epochs.established.contains_key(id)
                && eligible(*id)
                && !endpoint.is_relayed()
                && transport_kind(address).is_some()
                && (pending.owned_dial == Some(*id)
                    || (transport_kind(address) == Some(desired)
                        && (first_ip_in_multiaddr(address).is_some_and(|ip| {
                            first_ip_in_multiaddr(&pending.address) == Some(ip)
                        }) || address
                            .iter()
                            .filter(|p| !matches!(p, Protocol::P2p(_)))
                            .eq(pending
                                .address
                                .iter()
                                .filter(|p| !matches!(p, Protocol::P2p(_))))))))
            .then_some(*id)
        })
        .min()
}

fn transport_kind(address: &Multiaddr) -> Option<PathKind> {
    if !supports_auto_relay_candidate_transport(address)
        || address.iter().any(|p| p == Protocol::P2pCircuit)
    {
        return None;
    }
    if address.iter().any(|p| matches!(p, Protocol::Tcp(_))) {
        Some(PathKind::DirectTcpStream)
    } else if address
        .iter()
        .any(|p| matches!(p, Protocol::Quic | Protocol::QuicV1))
    {
        Some(PathKind::DirectQuicStream)
    } else {
        None
    }
}

pub(super) fn confirmed_connection(
    swarm: &Swarm<Behaviour>,
    epochs: &ConnectionEpochs,
    connections: &HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
    peer: Libp2pPeerId,
    expected: ConnectionId,
) -> Option<(ConnectionId, PathKind)> {
    swarm
        .behaviour()
        .relay
        .confirmed_reservation_connections(peer)
        .filter(|id| *id == expected)
        .filter_map(|id| {
            if !epochs.is_usable(id) || !epochs.established.contains_key(&id) {
                return None;
            }
            let endpoint = connections.get(&(peer, id))?;
            if endpoint.is_relayed() {
                return None;
            }
            Some((id, transport_kind(endpoint.get_remote_address())?))
        })
        .min_by_key(|(id, _)| *id)
}

pub(super) fn confirm_if_ready(
    swarm: &Swarm<Behaviour>,
    epochs: &ConnectionEpochs,
    connections: &HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
    state: &mut AutoRelayState,
    readiness: &RelayReadiness,
    peer: Libp2pPeerId,
) {
    if state
        .pending_reservations
        .get(&peer)
        .is_none_or(|pending| Instant::now() >= pending.expires_at)
        || !readiness.relay_ready(peer)
    {
        return;
    }
    let Some(listener) = state.reservation_listeners.get(&peer) else {
        return;
    };
    if !readiness
        .relayed_listen_addresses
        .get(&peer)
        .is_some_and(|addresses| addresses.iter().any(|(owner, _)| *owner == listener.id))
    {
        return;
    }
    let Some((id, kind)) =
        confirmed_connection(swarm, epochs, connections, peer, listener.connection)
    else {
        return;
    };
    state.record_reservation_accepted(peer);
    log_runtime_event(
        LogLevel::Info,
        "auto_relay_incoming_anchor_ready",
        &[
            ("relay", &peer.to_string()),
            ("connection_id", &id.to_string()),
            ("transport", &format!("{kind:?}")),
        ],
    );
}

#[cfg(test)]
mod tests;
