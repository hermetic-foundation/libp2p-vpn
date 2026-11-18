use super::*;
use crate::handler::ConnectionResources;
use libp2p_swarm::dial_opts::{DialOpts, PeerCondition};

pub(super) struct DiscoveryDial {
    id: ConnectionId,
    policy: std::sync::Arc<dyn OutboundDiscoveryPolicy>,
}

impl Drop for DiscoveryDial {
    fn drop(&mut self) {
        self.policy.finish_dial(self.id);
    }
}

pub(super) struct Connection {
    pub(super) peer: PeerId,
    pub(super) outbound_enabled: bool,
    pub(super) protocol_supported: bool,
    pub(super) resources: ConnectionResources,
}

impl Connection {
    pub(super) fn new(
        peer: PeerId,
        cleanup: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            peer,
            outbound_enabled: true,
            protocol_supported: false,
            resources: ConnectionResources::with_cleanup(cleanup),
        }
    }
}

impl<TStore: RecordStore + Send + 'static> Behaviour<TStore> {
    /// Restrict automatic outbound work to exact policy-approved connections.
    /// Install before polling the behaviour; previously dispatched work is not recalled.
    pub fn set_outbound_discovery_policy(
        &mut self,
        policy: std::sync::Arc<dyn OutboundDiscoveryPolicy>,
    ) {
        self.discovery_dials.clear();
        self.outbound_discovery_policy = Some(policy);
    }

    pub(super) fn finish_discovery_dial(&mut self, peer: PeerId, id: ConnectionId) -> bool {
        if self.discovery_dials.get(&peer).is_some_and(|dial| dial.id == id) {
            self.discovery_dials.remove(&peer);
            return true;
        }
        false
    }

    pub(super) fn connection_allows_outbound(&self, peer: PeerId, id: ConnectionId) -> bool {
        self.connections.get(&id).is_some_and(|connection| {
            connection.peer == peer && connection.outbound_enabled && connection.resources.live()
                && self.outbound_discovery_policy.as_ref().is_none_or(|policy| policy.allows_connection(peer, id))
        })
    }

    pub(super) fn has_protocol_connection(&self, peer: PeerId) -> bool {
        self.connections.values().any(|connection| {
            connection.peer == peer && connection.protocol_supported && connection.resources.live()
        })
    }

    /// Include or exclude an established connection from future outbound RPCs.
    ///
    /// Existing handler work, pinned replies, and queued actions keep their
    /// owners. All connections start enabled; new RPCs select the enabled
    /// connection with the smallest ID. An unknown or mismatched owner
    /// returns false without allocating, polling, or dialing.
    /// When every connection to a connected peer is disabled, new RPCs wait
    /// in the existing bounded pending-RPC queue until enabled or timed out.
    pub fn set_connection_outbound_enabled(
        &mut self,
        peer: &PeerId,
        id: ConnectionId,
        enabled: bool,
    ) -> bool {
        let Some(connection) = self
            .connections
            .get_mut(&id)
            .filter(|connection| connection.peer == *peer && connection.resources.live())
        else {
            return false;
        };
        connection.outbound_enabled = enabled;
        if enabled && self.connection_allows_outbound(*peer, id) {
            self.enqueue_pending_rpcs(*peer, id);
        }
        true
    }

    pub(super) fn enqueue_pending_rpcs(&mut self, peer: PeerId, id: ConnectionId) {
        let timeout = self.queries.config().timeout;
        for query in self.queries.iter_mut() {
            if query.is_finished() || query.has_expired(timeout) {
                continue;
            }
            if let Some(event) = query.pending_rpcs.remove_peer(&peer) {
                let provider = matches!(event, HandlerIn::AddProvider { .. });
                if !self.queued_events.push_back(ToSwarm::NotifyHandler {
                    peer_id: peer,
                    handler: NotifyHandler::One(id),
                    event,
                }) {
                    query.on_failure(&peer);
                } else if provider && self.outbound_discovery_policy.is_none() {
                    query.on_success(&peer, vec![]);
                }
            }
        }
        if let Some(waker) = self.no_events_waker.take() {
            waker.wake();
        }
    }

    /// Whether this connection owns queued or native handler work.
    ///
    /// Includes codec/substream work, rejection notifications, dispatches not
    /// yet delivered to the handler, and handler notifications awaiting the
    /// behaviour. Pinned replies and mode updates remain drain work even when
    /// outbound RPC selection is disabled. Peer-level unassigned RPCs and
    /// completed query metadata are excluded. Closed or dropped records return
    /// false once discarded by the behaviour; this method does not perform I/O.
    pub fn has_pending_requests_on_connection(&self, peer: &PeerId, id: ConnectionId) -> bool {
        self.connections.get(&id).is_some_and(|connection| {
            connection.peer == *peer && (connection.resources.busy()
                || (self.mode_updates_pending && self.mode_update_cursor.is_none_or(|cursor| id > cursor))
                || self.queued_events.iter().any(|event| matches!(event,
                ToSwarm::NotifyHandler { peer_id, handler: NotifyHandler::One(owner), .. } if peer_id == peer && *owner == id)))
        })
    }

    pub(super) fn prepare_dispatch(
        &mut self,
        event: ToSwarm<Event, HandlerIn>,
    ) -> Option<ToSwarm<Event, HandlerIn>> {
        if let Some(policy) = self.outbound_discovery_policy.clone() {
            match &event {
                ToSwarm::Dial { opts } => {
                    let peer = opts.get_peer_id()?;
                    if self.discovery_dials.contains_key(&peer)
                        || self.connections.keys().any(|id| self.connection_allows_outbound(peer, *id))
                    {
                        return None;
                    }
                    let addresses = self.addresses_of_peer(peer);
                    if !addresses.is_empty() {
                        // A connected member, or a dial belonging to another
                        // behaviour, does not satisfy this scoped Kademlia RPC.
                        let opts = DialOpts::peer_id(peer)
                            .condition(PeerCondition::Always)
                            .addresses(addresses)
                            .allocate_new_port()
                            .build();
                        let id = opts.connection_id();
                        if policy.start_dial(id) {
                            self.discovery_dials.insert(peer, DiscoveryDial { id, policy });
                            return Some(ToSwarm::Dial { opts });
                        }
                    }
                    for query in self.queries.iter_mut() {
                        query.on_failure(&peer);
                    }
                    return None;
                }
                ToSwarm::NotifyHandler { peer_id, handler: NotifyHandler::One(id), event } => {
                    if let HandlerIn::FindNodeReq { query_id, .. }
                        | HandlerIn::GetProvidersReq { query_id, .. }
                        | HandlerIn::AddProvider { query_id, .. }
                        | HandlerIn::GetRecord { query_id, .. }
                        | HandlerIn::PutRecord { query_id, .. } = event
                    {
                        let allowed = self.connection_allows_outbound(*peer_id, *id);
                        if let Some(query) = self.queries.get_mut(query_id) {
                            if !allowed {
                                query.on_failure(peer_id);
                            } else if matches!(event, HandlerIn::AddProvider { .. }) {
                                query.on_success(peer_id, vec![]);
                            }
                        }
                        if !allowed {
                            return None;
                        }
                    }
                }
                _ => {}
            }
        }
        if let ToSwarm::NotifyHandler {
            peer_id,
            handler: NotifyHandler::One(id),
            ..
        } = &event
        {
            if let Some(connection) = self
                .connections
                .get(id)
                .filter(|connection| connection.peer == *peer_id)
            {
                connection.resources.dispatched();
            }
        }
        Some(event)
    }
}
