use std::task::{Context, Poll};

use libp2p::{
    Multiaddr, PeerId, connection_limits,
    core::{Endpoint, transport::PortUse},
    swarm::{
        ConnectionDenied, ConnectionId, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm, behaviour::FromSwarm,
    },
};

pub(in super::super) struct CandidateLimits {
    inner: connection_limits::Behaviour,
    candidate: Option<(PeerId, ConnectionId)>,
}

impl CandidateLimits {
    pub(in super::super) fn new() -> Self {
        Self {
            inner: connection_limits::Behaviour::new(
                connection_limits::ConnectionLimits::default()
                    .with_max_pending_incoming(Some(4))
                    .with_max_established_per_peer(Some(1)),
            ),
            candidate: None,
        }
    }

    pub(super) fn allow_candidate(&mut self, peer: PeerId, connection: ConnectionId) {
        self.candidate = Some((peer, connection));
    }

    pub(super) fn revoke_candidate(&mut self, connection: ConnectionId) {
        if self.candidate.is_some_and(|(_, id)| id == connection) {
            self.candidate = None;
        }
    }
}

impl NetworkBehaviour for CandidateLimits {
    type ConnectionHandler = <connection_limits::Behaviour as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = <connection_limits::Behaviour as NetworkBehaviour>::ToSwarm;

    fn handle_pending_inbound_connection(
        &mut self,
        id: ConnectionId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.inner
            .handle_pending_inbound_connection(id, local, remote)
    }

    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner
            .handle_established_inbound_connection(id, peer, local, remote)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: Option<PeerId>,
        addresses: &[Multiaddr],
        role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        self.inner
            .handle_pending_outbound_connection(id, peer, addresses, role)
    }

    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        address: &Multiaddr,
        role: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if self.candidate != Some((peer, id)) || role != Endpoint::Dialer {
            return self
                .inner
                .handle_established_outbound_connection(id, peer, address, role, port_use);
        }

        // Relax the per-peer bound only for this synchronous check. Every
        // incoming or unrelated connection still observes the normal limit.
        self.candidate = None;
        let limits = self.inner.limits_mut().clone();
        *self.inner.limits_mut() = limits.clone().with_max_established_per_peer(Some(2));
        let result = self
            .inner
            .handle_established_outbound_connection(id, peer, address, role, port_use);
        *self.inner.limits_mut() = limits;
        result
    }

    fn on_swarm_event(&mut self, event: FromSwarm<'_>) {
        if let FromSwarm::DialFailure(failure) = &event {
            self.revoke_candidate(failure.connection_id);
        }
        self.inner.on_swarm_event(event);
    }

    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.inner.on_connection_handler_event(peer, id, event);
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.inner.poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::{core::ConnectedPoint, swarm::behaviour::ConnectionEstablished};

    #[test]
    fn only_the_exact_outbound_candidate_can_exceed_the_normal_per_peer_limit() {
        let mut limits = CandidateLimits::new();
        let peer = PeerId::random();
        let address: Multiaddr = "/memory/1".parse().unwrap();
        let fallback = ConnectionId::new_unchecked(1);
        let candidate = ConnectionId::new_unchecked(2);
        let unrelated = ConnectionId::new_unchecked(3);
        let cancelled = ConnectionId::new_unchecked(4);
        let endpoint = ConnectedPoint::Dialer {
            address: address.clone(),
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        };
        limits.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
            peer_id: peer,
            connection_id: fallback,
            endpoint: &endpoint,
            failed_addresses: &[],
            other_established: 0,
        }));
        let outbound = |limits: &mut CandidateLimits, id| {
            limits.handle_established_outbound_connection(
                id,
                peer,
                &address,
                Endpoint::Dialer,
                PortUse::New,
            )
        };
        limits.allow_candidate(peer, candidate);
        assert!(
            limits
                .handle_established_inbound_connection(unrelated, peer, &address, &address)
                .is_err()
        );
        assert!(outbound(&mut limits, unrelated).is_err());
        assert!(outbound(&mut limits, candidate).is_ok());
        assert!(outbound(&mut limits, unrelated).is_err());
        assert!(outbound(&mut limits, candidate).is_err());

        limits.allow_candidate(peer, cancelled);
        limits.revoke_candidate(cancelled);
        assert!(outbound(&mut limits, cancelled).is_err());
    }
}
