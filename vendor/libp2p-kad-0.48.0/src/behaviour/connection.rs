use super::*;
use crate::handler::ConnectionResources;

pub(super) struct Connection {
    pub(super) peer: PeerId,
    pub(super) outbound_enabled: bool,
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
            resources: ConnectionResources::with_cleanup(cleanup),
        }
    }
}

impl<TStore: RecordStore + Send + 'static> Behaviour<TStore> {
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
        if enabled {
            let timeout = self.queries.config().timeout;
            for query in self.queries.iter_mut() {
                if query.is_finished() || query.has_expired(timeout) {
                    continue;
                }
                if let Some(event) = query.pending_rpcs.remove_peer(peer) {
                    let provider = matches!(event, HandlerIn::AddProvider { .. });
                    if !self.queued_events.push_back(ToSwarm::NotifyHandler {
                        peer_id: *peer,
                        handler: NotifyHandler::One(id),
                        event,
                    }) {
                        query.on_failure(peer);
                    } else if provider {
                        query.on_success(peer, vec![]);
                    }
                }
            }
            if let Some(waker) = self.no_events_waker.take() {
                waker.wake();
            }
        }
        true
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
        &self,
        event: ToSwarm<Event, HandlerIn>,
    ) -> ToSwarm<Event, HandlerIn> {
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
        event
    }
}
