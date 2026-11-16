use std::{
    collections::BTreeMap,
    convert::Infallible,
    task::{Context, Poll},
};

use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse, upgrade::DeniedUpgrade},
    swarm::{
        ConnectionDenied, ConnectionHandler, ConnectionHandlerEvent, ConnectionId, FromSwarm,
        NetworkBehaviour, NotifyHandler, SubstreamProtocol, ToSwarm, handler::ConnectionEvent,
    },
};

#[derive(Default)]
pub struct Behaviour {
    connections: BTreeMap<ConnectionId, Retention>,
    #[cfg(target_os = "linux")]
    physical_routes: Option<std::sync::Arc<super::physical_network::linux::control::ControlRoutes>>,
    #[cfg(target_os = "linux")]
    physical_reconciler: Option<super::physical_network::linux::control::reconcile::Reconciler>,
    #[cfg(target_os = "linux")]
    pub(crate) physical_handoff: super::runner::physical_control_handoff::State,
    #[cfg(target_os = "linux")]
    pub(crate) infrastructure_handoff: super::runner::physical_infrastructure_handoff::State,
}

struct Retention {
    peer: PeerId,
    desired: bool,
    notified: bool,
    services: Option<IdentifiedServices>,
}

/// Service reports belong to an authenticated live connection, not a peer cache.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct IdentifiedServices {
    pub primary_dht: bool,
    pub public_dht: bool,
    pub autonat: bool,
    pub relay: bool,
}

impl IdentifiedServices {
    pub(crate) fn include(&mut self, other: Self) {
        self.primary_dht |= other.primary_dht;
        self.public_dht |= other.public_dht;
        self.autonat |= other.autonat;
        self.relay |= other.relay;
    }
    pub(crate) fn routing(self) -> bool {
        self.primary_dht || self.public_dht
    }

    pub(crate) fn infrastructure(self) -> bool {
        self.routing() || self.relay
    }

    pub(crate) fn covers(self, required: Self) -> bool {
        (!required.primary_dht || self.primary_dht)
            && (!required.public_dht || self.public_dht)
            && (!required.autonat || self.autonat)
            && (!required.relay || self.relay)
    }
}

impl Behaviour {
    pub(crate) fn relay_handoff_owns_peer(&self, peer: PeerId) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.infrastructure_handoff.owns_relay_peer(peer)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = peer;
            false
        }
    }

    pub(crate) fn relay_handoff_owns_listener(
        &self,
        peer: PeerId,
        listener: libp2p::core::transport::ListenerId,
    ) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.infrastructure_handoff
                .owns_relay_listener(peer, listener)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (peer, listener);
            false
        }
    }

    pub(crate) fn relay_handoff_listener_closed(
        &mut self,
        listener: libp2p::core::transport::ListenerId,
    ) {
        #[cfg(target_os = "linux")]
        self.infrastructure_handoff.relay_listener_closed(listener);
        #[cfg(not(target_os = "linux"))]
        let _ = listener;
    }

    pub(crate) fn record_services(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        services: IdentifiedServices,
    ) -> bool {
        let Some(owner) = self
            .connections
            .get_mut(&id)
            .filter(|owner| owner.peer == peer)
        else {
            return false;
        };
        owner.services = Some(services);
        true
    }

    pub(crate) fn clear_services(&mut self, peer: PeerId, id: ConnectionId) {
        if let Some(owner) = self
            .connections
            .get_mut(&id)
            .filter(|owner| owner.peer == peer)
        {
            owner.services = None;
        }
    }

    pub(crate) fn services(&self, peer: PeerId, id: ConnectionId) -> Option<IdentifiedServices> {
        self.connections
            .get(&id)
            .filter(|owner| owner.peer == peer)?
            .services
    }

    pub(crate) fn sibling_services(
        &self,
        peer: PeerId,
        id: ConnectionId,
        usable: impl Fn(ConnectionId) -> bool,
    ) -> IdentifiedServices {
        let mut services = IdentifiedServices::default();
        for (_, owner) in self
            .connections
            .iter()
            .filter(|(other, owner)| **other != id && owner.peer == peer && usable(**other))
        {
            if let Some(other) = owner.services {
                services.include(other);
            }
        }
        services
    }

    pub(crate) fn owns_physical_validation(
        &self,
        id: libp2p::request_response::OutboundRequestId,
    ) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.physical_handoff.owns_request(id)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = id;
            false
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn with_physical_routes(
        routes: std::sync::Arc<super::physical_network::linux::control::ControlRoutes>,
    ) -> Self {
        Self {
            physical_routes: Some(routes),
            ..Self::default()
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn physical_routes(
        &self,
    ) -> Option<&std::sync::Arc<super::physical_network::linux::control::ControlRoutes>> {
        self.physical_routes.as_ref()
    }

    /// Coalesce policy changes in the existing connection owner, never a queue.
    pub(crate) fn retain_connections(
        &mut self,
        mut retain: impl FnMut(PeerId, ConnectionId) -> bool,
    ) {
        for (id, state) in &mut self.connections {
            state.desired = retain(state.peer, *id);
            #[cfg(target_os = "linux")]
            if self
                .physical_handoff
                .protects(state.peer, std::time::Instant::now())
            {
                state.desired = true;
            }
            #[cfg(target_os = "linux")]
            if self.infrastructure_handoff.protects(state.peer, *id) {
                state.desired = true;
            }
        }
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Handler;
    type ToSwarm = Infallible;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<Handler, ConnectionDenied> {
        Ok(Handler::default())
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<Handler, ConnectionDenied> {
        Ok(Handler::default())
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(event) => {
                self.connections.insert(
                    event.connection_id,
                    Retention {
                        peer: event.peer_id,
                        desired: false,
                        notified: false,
                        services: None,
                    },
                );
            }
            FromSwarm::ConnectionClosed(event) => {
                if self
                    .connections
                    .get(&event.connection_id)
                    .is_some_and(|state| state.peer == event.peer_id)
                {
                    self.connections.remove(&event.connection_id);
                }
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(&mut self, _: PeerId, _: ConnectionId, event: Infallible) {
        match event {}
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<ToSwarm<Infallible, bool>> {
        #[cfg(target_os = "linux")]
        if self.physical_reconciler.is_none()
            && let Some(routes) = &self.physical_routes
        {
            self.physical_reconciler = Some(
                super::physical_network::linux::control::reconcile::Reconciler::new(
                    std::sync::Arc::clone(routes),
                ),
            );
        }
        #[cfg(target_os = "linux")]
        if let Some(reconciler) = self.physical_reconciler.as_mut() {
            reconciler.poll(cx);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = cx;
        for (id, state) in &mut self.connections {
            if state.desired != state.notified {
                state.notified = state.desired;
                return Poll::Ready(ToSwarm::NotifyHandler {
                    peer_id: state.peer,
                    handler: NotifyHandler::One(*id),
                    event: state.desired,
                });
            }
        }
        Poll::Pending
    }
}

#[derive(Default)]
pub struct Handler {
    retained: bool,
}

impl ConnectionHandler for Handler {
    type FromBehaviour = bool;
    type ToBehaviour = Infallible;
    type InboundProtocol = DeniedUpgrade;
    type OutboundProtocol = DeniedUpgrade;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<DeniedUpgrade> {
        SubstreamProtocol::new(DeniedUpgrade, ())
    }

    fn connection_keep_alive(&self) -> bool {
        self.retained
    }

    fn on_behaviour_event(&mut self, retained: bool) {
        self.retained = retained;
    }

    fn poll(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<ConnectionHandlerEvent<DeniedUpgrade, (), Infallible>> {
        Poll::Pending
    }

    fn on_connection_event(&mut self, _: ConnectionEvent<DeniedUpgrade, DeniedUpgrade, (), ()>) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt as _;
    use std::time::Duration;

    fn swarm() -> libp2p::Swarm<Behaviour> {
        libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .unwrap()
            .with_quic()
            .with_behaviour(|_| Behaviour::default())
            .unwrap()
            .with_swarm_config(|config| {
                config.with_idle_connection_timeout(Duration::from_millis(200))
            })
            .build()
    }

    #[tokio::test]
    async fn retained_tcp_and_quic_connections_survive_idle_then_close_on_release() {
        for address in ["/ip4/127.0.0.1/tcp/0", "/ip4/127.0.0.1/udp/0/quic-v1"] {
            tokio::time::timeout(Duration::from_secs(5), async {
                let mut a = swarm();
                let mut b = swarm();
                a.listen_on(address.parse().unwrap()).unwrap();
                let address = loop {
                    if let libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } = a.select_next_some().await { break address; }
                };
                b.dial(address).unwrap();
                let mut established = [false; 2];
                while !established.iter().all(|connected| *connected) {
                    tokio::select! {
                        event = a.select_next_some() => if matches!(event, libp2p::swarm::SwarmEvent::ConnectionEstablished { .. }) {
                            a.behaviour_mut().retain_connections(|_, _| true);
                            established[0] = true;
                        },
                        event = b.select_next_some() => if matches!(event, libp2p::swarm::SwarmEvent::ConnectionEstablished { .. }) {
                            b.behaviour_mut().retain_connections(|_, _| true);
                            established[1] = true;
                        },
                    }
                }
                let dwell = tokio::time::sleep(Duration::from_secs(1));
                tokio::pin!(dwell);
                loop {
                    tokio::select! {
                        () = &mut dwell => break,
                        event = a.select_next_some() => assert!(!matches!(event, libp2p::swarm::SwarmEvent::ConnectionClosed { .. }), "retained connection closed: {event:?}"),
                        event = b.select_next_some() => assert!(!matches!(event, libp2p::swarm::SwarmEvent::ConnectionClosed { .. }), "retained connection closed: {event:?}"),
                    }
                }
                a.behaviour_mut().retain_connections(|_, _| false);
                b.behaviour_mut().retain_connections(|_, _| false);
                let mut closed = [false; 2];
                while !closed.iter().all(|closed| *closed) {
                    tokio::select! {
                        event = a.select_next_some() => if matches!(event, libp2p::swarm::SwarmEvent::ConnectionClosed { .. }) { closed[0] = true; },
                        event = b.select_next_some() => if matches!(event, libp2p::swarm::SwarmEvent::ConnectionClosed { .. }) { closed[1] = true; },
                    }
                }
                assert!(a.behaviour().connections.is_empty());
                assert!(b.behaviour().connections.is_empty());
            }).await.unwrap_or_else(|_| panic!("idle retention case timed out: {address}"));
        }
    }

    #[test]
    fn retention_updates_coalesce_and_release_without_protocol_work() {
        let peer = PeerId::random();
        let id = ConnectionId::new_unchecked(1);
        let mut behaviour = Behaviour::default();
        behaviour.connections.insert(
            id,
            Retention {
                peer,
                desired: false,
                notified: false,
                services: None,
            },
        );
        let mut handler = Handler::default();
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(!handler.connection_keep_alive());
        for _ in 0..10_000 {
            behaviour.retain_connections(|_, _| true);
            behaviour.retain_connections(|_, _| false);
        }
        assert!(behaviour.poll(&mut cx).is_pending());
        assert_eq!(behaviour.connections.len(), 1);
        behaviour.retain_connections(|p, c| p == peer && c == id);
        let Poll::Ready(ToSwarm::NotifyHandler {
            peer_id,
            handler: NotifyHandler::One(connection),
            event,
        }) = behaviour.poll(&mut cx)
        else {
            panic!("missing retention notification")
        };
        assert_eq!((peer_id, connection, event), (peer, id, true));
        handler.on_behaviour_event(event);
        assert!(handler.connection_keep_alive());
        assert!(handler.poll(&mut cx).is_pending());
        assert!(behaviour.poll(&mut cx).is_pending());
        behaviour.retain_connections(|_, _| false);
        let Poll::Ready(ToSwarm::NotifyHandler { event, .. }) = behaviour.poll(&mut cx) else {
            panic!("missing release notification")
        };
        handler.on_behaviour_event(event);
        assert!(!handler.connection_keep_alive());
    }

    #[tokio::test]
    async fn unretained_tcp_and_quic_connections_expire_without_application_traffic() {
        for address in ["/ip4/127.0.0.1/tcp/0", "/ip4/127.0.0.1/udp/0/quic-v1"] {
            tokio::time::timeout(Duration::from_secs(5), async {
                let mut a = swarm();
                let mut b = swarm();
                a.listen_on(address.parse().unwrap()).unwrap();
                let address = loop {
                    if let libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } =
                        a.select_next_some().await
                    {
                        break address;
                    }
                };
                b.dial(address).unwrap();
                let mut established = [false; 2];
                let mut closed = [false; 2];
                while !closed.iter().all(|closed| *closed) {
                    let (index, event) = tokio::select! {
                        event = a.select_next_some() => (0, event),
                        event = b.select_next_some() => (1, event),
                    };
                    match event {
                        libp2p::swarm::SwarmEvent::ConnectionEstablished { .. } => {
                            established[index] = true
                        }
                        libp2p::swarm::SwarmEvent::ConnectionClosed { .. } => {
                            assert!(established[index]);
                            closed[index] = true;
                        }
                        _ => {}
                    }
                }
                assert!(a.behaviour().connections.is_empty());
                assert!(b.behaviour().connections.is_empty());
            })
            .await
            .unwrap_or_else(|_| panic!("unretained idle case timed out: {address}"));
        }
    }

    #[test]
    fn policy_updates_cannot_create_connection_owners() {
        let mut behaviour = Behaviour::default();
        behaviour.retain_connections(|_, _| panic!("no live connection"));
        assert!(behaviour.connections.is_empty());
    }

    #[test]
    fn service_reports_are_exact_and_do_not_create_or_retain_connections() {
        let peer = PeerId::random();
        let other = PeerId::random();
        let id = ConnectionId::new_unchecked(1);
        let services = IdentifiedServices {
            primary_dht: true,
            ..Default::default()
        };
        let mut behaviour = Behaviour::default();
        assert!(!behaviour.record_services(peer, id, services));
        assert!(behaviour.connections.is_empty());
        behaviour.connections.insert(
            id,
            Retention {
                peer,
                desired: false,
                notified: false,
                services: None,
            },
        );
        assert!(!behaviour.record_services(other, id, services));
        assert!(behaviour.record_services(peer, id, services));
        behaviour.clear_services(other, id);
        assert_eq!(behaviour.services(peer, id), Some(services));
        assert_eq!(behaviour.services(other, id), None);
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(
            behaviour.poll(&mut cx).is_pending(),
            "recording support creates no wire or retention work"
        );
        behaviour.clear_services(peer, id);
        assert_eq!(behaviour.services(peer, id), None);
    }

    #[test]
    fn sibling_support_excludes_wrong_peers_failed_owner_and_unusable_generations() {
        let peer = PeerId::random();
        let failed = ConnectionId::new_unchecked(1);
        let usable = ConnectionId::new_unchecked(2);
        let stale = ConnectionId::new_unchecked(3);
        let mut behaviour = Behaviour::default();
        for (id, owner, services) in [
            (
                failed,
                peer,
                IdentifiedServices {
                    primary_dht: true,
                    ..Default::default()
                },
            ),
            (
                usable,
                peer,
                IdentifiedServices {
                    public_dht: true,
                    ..Default::default()
                },
            ),
            (
                stale,
                peer,
                IdentifiedServices {
                    relay: true,
                    ..Default::default()
                },
            ),
            (
                ConnectionId::new_unchecked(4),
                PeerId::random(),
                IdentifiedServices {
                    autonat: true,
                    ..Default::default()
                },
            ),
        ] {
            behaviour.connections.insert(
                id,
                Retention {
                    peer: owner,
                    desired: false,
                    notified: false,
                    services: Some(services),
                },
            );
        }
        assert_eq!(
            behaviour.sibling_services(peer, failed, |id| id != stale),
            IdentifiedServices {
                public_dht: true,
                ..Default::default()
            }
        );
        assert_eq!(
            behaviour.sibling_services(peer, failed, |_| false),
            IdentifiedServices::default()
        );
    }

    #[test]
    fn replacement_requires_all_services_on_one_connection() {
        let required = IdentifiedServices {
            primary_dht: true,
            public_dht: true,
            autonat: true,
            relay: true,
        };
        assert!(required.covers(required));
        for missing in [
            IdentifiedServices {
                primary_dht: false,
                ..required
            },
            IdentifiedServices {
                public_dht: false,
                ..required
            },
            IdentifiedServices {
                autonat: false,
                ..required
            },
            IdentifiedServices {
                relay: false,
                ..required
            },
        ] {
            assert!(!missing.covers(required));
        }
        assert!(required.covers(IdentifiedServices::default()));
        assert!(!IdentifiedServices::default().infrastructure());
    }

    #[test]
    fn closing_exact_owner_retires_unsent_retention() {
        let peer = PeerId::random();
        let id = ConnectionId::new_unchecked(1);
        let endpoint = libp2p::core::ConnectedPoint::Listener {
            local_addr: "/memory/1".parse().unwrap(),
            send_back_addr: "/memory/2".parse().unwrap(),
        };
        let mut behaviour = Behaviour::default();
        behaviour.on_swarm_event(FromSwarm::ConnectionEstablished(
            libp2p::swarm::behaviour::ConnectionEstablished {
                peer_id: peer,
                connection_id: id,
                endpoint: &endpoint,
                failed_addresses: &[],
                other_established: 0,
            },
        ));
        behaviour.retain_connections(|_, _| true);
        for (closing_peer, connection_id, remaining) in [
            (PeerId::random(), id, 1),
            (peer, ConnectionId::new_unchecked(2), 1),
            (peer, id, 0),
        ] {
            behaviour.on_swarm_event(FromSwarm::ConnectionClosed(
                libp2p::swarm::behaviour::ConnectionClosed {
                    peer_id: closing_peer,
                    connection_id,
                    endpoint: &endpoint,
                    cause: None,
                    remaining_established: 0,
                },
            ));
            assert_eq!(behaviour.connections.len(), remaining);
        }
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(behaviour.poll(&mut cx).is_pending());
    }
}
