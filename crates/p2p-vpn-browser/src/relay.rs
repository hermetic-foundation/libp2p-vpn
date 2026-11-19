//! Explicit Circuit Relay v2 routes. No relay discovery or service runs in the browser.

use std::{
    io,
    net::Ipv4Addr,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};

use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};

#[derive(Clone, Debug)]
pub(crate) struct RelayRoute {
    relay_entrance: Multiaddr,
    relay_peer: PeerId,
    destination: Destination,
    public_alias: Option<Multiaddr>,
}

#[derive(Clone, Debug)]
enum Destination {
    Pinned(PeerId),
    Invitation(Arc<IncomingInvitation>),
}

#[derive(Debug)]
struct IncomingInvitation {
    selected: OnceLock<PeerId>,
    remaining: AtomicU8,
    activated: AtomicBool,
}

const INVITATION_CIRCUIT_ATTEMPTS: u8 = 8;

impl RelayRoute {
    /// Both the WebRTC Direct relay and the end-to-end destination must be pinned.
    pub(crate) fn from_dial_addr(addr: &Multiaddr) -> io::Result<Self> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected a pinned WebRTC Direct relay address followed by /p2p-circuit/p2p/<destination>",
            )
        };
        let mut entrance = addr.clone();
        let Some(Protocol::P2p(destination)) = entrance.pop() else {
            return Err(invalid());
        };
        if entrance.pop() != Some(Protocol::P2pCircuit) {
            return Err(invalid());
        }
        let relay_peer = Self::parse_entrance(&entrance).ok_or_else(invalid)?;
        if relay_peer == destination {
            return Err(invalid());
        }
        Ok(Self {
            relay_entrance: entrance,
            relay_peer,
            destination: Destination::Pinned(destination),
            public_alias: None,
        })
    }

    /// Only the inviter's private PAKE dispatcher may use a route without a
    /// destination. Its selected identity is shared with the transport.
    #[cfg(feature = "test-hooks")]
    pub(crate) fn for_invitation(entrance: Multiaddr) -> io::Result<Self> {
        Self::incoming_invitation(entrance, None)
    }

    pub(crate) fn for_scoped_invitation(
        relay: PeerId,
        ingress: Multiaddr,
        public_alias: Multiaddr,
    ) -> io::Result<Self> {
        if ingress.iter().next() != Some(Protocol::Ip4(Ipv4Addr::LOCALHOST))
            || Self::parse_entrance(&ingress) != Some(relay)
            || public_alias.iter().last() != Some(Protocol::P2p(relay))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "gateway addresses do not match the pinned relay",
            ));
        }
        Self::incoming_invitation(ingress, Some(public_alias))
    }

    fn incoming_invitation(
        entrance: Multiaddr,
        public_alias: Option<Multiaddr>,
    ) -> io::Result<Self> {
        let relay_peer = Self::parse_entrance(&entrance).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected a pinned WebRTC Direct relay entrance",
            )
        })?;
        Ok(Self {
            relay_entrance: entrance,
            relay_peer,
            public_alias,
            destination: Destination::Invitation(Arc::new(IncomingInvitation {
                selected: OnceLock::new(),
                remaining: AtomicU8::new(INVITATION_CIRCUIT_ATTEMPTS),
                activated: AtomicBool::new(false),
            })),
        })
    }

    fn parse_entrance(entrance: &Multiaddr) -> Option<PeerId> {
        let mut parts = entrance.iter();
        match parts.next() {
            Some(Protocol::Ip4(ip)) if !ip.is_unspecified() => {}
            Some(Protocol::Ip6(ip)) if !ip.is_unspecified() => {}
            _ => return None,
        };
        let (
            Some(Protocol::Udp(port)),
            Some(Protocol::WebRTCDirect),
            Some(Protocol::Certhash(hash)),
            Some(Protocol::P2p(relay_peer)),
            None,
        ) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        )
        else {
            return None;
        };
        // WebRTC Direct supports SHA-256 certificate fingerprints.
        (port != 0 && hash.code() == 0x12 && hash.size() == 32).then_some(relay_peer)
    }

    pub(crate) fn relay_peer(&self) -> PeerId {
        self.relay_peer
    }

    pub(crate) fn destination(&self) -> PeerId {
        self.selected_peer()
            .expect("a VPN route must have a selected peer")
    }

    pub(crate) fn selected_peer(&self) -> Option<PeerId> {
        match &self.destination {
            Destination::Pinned(peer) => Some(*peer),
            Destination::Invitation(admission) => admission.selected.get().copied(),
        }
    }

    pub(crate) fn select_invitee(&self, peer: PeerId) -> bool {
        if peer == self.relay_peer {
            return false;
        }
        match &self.destination {
            Destination::Pinned(expected) => *expected == peer,
            Destination::Invitation(admission) => *admission.selected.get_or_init(|| peer) == peer,
        }
    }

    pub(crate) fn activate_invitee(&self, peer: PeerId) -> bool {
        if self.selected_peer() != Some(peer) {
            return false;
        }
        if let Destination::Invitation(admission) = &self.destination {
            admission.activated.store(true, Ordering::Release);
        }
        true
    }

    pub(crate) fn cancel_invitation(&self) {
        if let Destination::Invitation(admission) = &self.destination {
            admission.remaining.store(0, Ordering::Relaxed);
        }
    }

    fn dial_peer(&self) -> Option<PeerId> {
        match &self.destination {
            Destination::Invitation(_) if self.public_alias.is_some() => None,
            Destination::Invitation(admission) if !admission.activated.load(Ordering::Acquire) => {
                None
            }
            _ => self.selected_peer(),
        }
    }

    fn begin_circuit(&self, incoming: bool) -> bool {
        if let Destination::Invitation(admission) = &self.destination {
            return admission.activated.load(Ordering::Acquire)
                || (incoming
                    && admission
                        .remaining
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                            remaining.checked_sub(1)
                        })
                        .is_ok());
        }
        true
    }

    pub(crate) fn dial_addr(&self) -> Multiaddr {
        self.reservation_addr()
            .with(Protocol::P2p(self.destination()))
    }

    /// Pass to `Swarm::listen_on` only when the caller explicitly requests a reservation.
    pub(crate) fn reservation_addr(&self) -> Multiaddr {
        self.relay_entrance.clone().with(Protocol::P2pCircuit)
    }

    pub(crate) fn advertised_reservation_addr(&self, owner: PeerId) -> Multiaddr {
        self.public_reservation_addr(owner)
            .unwrap_or_else(|| self.reservation_addr().with(Protocol::P2p(owner)))
    }

    pub(crate) fn public_reservation_addr(&self, owner: PeerId) -> Option<Multiaddr> {
        Some(
            self.public_alias
                .clone()?
                .with(Protocol::P2pCircuit)
                .with(Protocol::P2p(owner)),
        )
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) use transport::{
    AdditionalInboundMember, build_transport, build_transport_with_inbound,
};

#[cfg(target_arch = "wasm32")]
mod transport {
    use std::{
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
        time::Duration,
    };

    use libp2p::{
        Transport,
        core::{
            muxing::StreamMuxerBox,
            transport::{
                Boxed, DialOpts, ListenerId, TransportError, TransportEvent,
                timeout::TransportTimeout,
            },
            upgrade::{self, Version},
        },
        identity, noise, relay, webrtc_websys, yamux,
    };

    use super::*;

    const DIRECT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
    const CIRCUIT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
    const MAX_CIRCUIT_STREAMS: usize = 128;

    type BrowserTransport = Boxed<(PeerId, StreamMuxerBox)>;

    #[derive(Clone, Default)]
    pub(crate) struct AdditionalInboundMember(
        Arc<Mutex<Option<PeerId>>>,
        Arc<Mutex<Option<(web_time::Instant, u8)>>>,
    );

    impl AdditionalInboundMember {
        pub(crate) fn set(&self, peer: Option<PeerId>) {
            if let Ok(mut current) = self.0.lock() {
                *current = peer;
            }
        }

        fn admits(&self, peer: PeerId) -> bool {
            self.0.lock().is_ok_and(|current| *current == Some(peer))
        }

        pub(crate) fn pairing(&self, deadline: Option<web_time::Instant>) {
            *self.1.lock().expect("pairing circuit budget") =
                deadline.map(|end| (end, INVITATION_CIRCUIT_ATTEMPTS));
        }

        fn try_pairing(&self) -> bool {
            let mut budget = self.1.lock().expect("pairing circuit budget");
            let Some((end, remaining)) = budget.as_mut() else {
                return false;
            };
            if web_time::Instant::now() >= *end || *remaining == 0 {
                return false;
            }
            *remaining -= 1;
            true
        }
    }

    /// Admit one explicit relay route, alongside WebRTC Direct hints for that member.
    /// Neither a reservation nor a dial occurs at construction.
    pub(crate) fn build_transport(
        keys: &identity::Keypair,
        route: &RelayRoute,
    ) -> io::Result<(BrowserTransport, relay::client::Behaviour)> {
        build_transport_with_inbound(keys, route, AdditionalInboundMember::default())
    }

    pub(crate) fn build_transport_with_inbound(
        keys: &identity::Keypair,
        route: &RelayRoute,
        additional: AdditionalInboundMember,
    ) -> io::Result<(BrowserTransport, relay::client::Behaviour)> {
        let local_peer = keys.public().to_peer_id();
        if local_peer == route.relay_peer() || route.selected_peer() == Some(local_peer) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "relay, local, and remote peers must be distinct",
            ));
        }

        let direct = TransportTimeout::new(
            webrtc_websys::Transport::new(webrtc_websys::Config::new(keys)),
            DIRECT_HANDSHAKE_TIMEOUT,
        )
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed();
        let (transport, behaviour) = relay::client::new(local_peer);
        let noise = noise::Config::new(keys).map_err(io::Error::other)?;
        let mut yamux = yamux::Config::default();
        yamux.set_max_num_streams(MAX_CIRCUIT_STREAMS);
        let circuit_route = route.clone();
        let circuit = transport.and_then(move |stream, endpoint| {
            let binding = stream.circuit_binding();
            let noise = noise.clone();
            let yamux = yamux.clone();
            let additional = additional.clone();
            let route = circuit_route.clone();
            let incoming = endpoint.is_listener();
            async move {
                if !route.begin_circuit(incoming) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "invitation circuit budget exhausted",
                    ));
                }
                let (peer, secured) =
                    upgrade::apply(stream, noise, endpoint.clone(), Version::V1Lazy)
                        .await
                        .map_err(io::Error::other)?;
                // STOP carries a relay-supplied source ID. Trust the end-to-end
                // Noise identity instead, including on inbound reservations.
                let permitted_additional = incoming
                    && matches!(route.destination, Destination::Pinned(_))
                    && (additional.admits(peer)
                        || (route.selected_peer() != Some(peer)
                            && peer != local_peer
                            && peer != route.relay_peer()
                            && additional.try_pairing()));
                if peer == local_peer
                    || peer == route.relay_peer()
                    || (route
                        .selected_peer()
                        .map_or(!incoming, |expected| peer != expected)
                        && !permitted_additional)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "circuit Noise identity does not match the pinned VPN peer",
                    ));
                }
                let muxer = upgrade::apply(secured, yamux, endpoint, Version::V1Lazy)
                    .await
                    .map_err(io::Error::other)?;
                Ok((peer, StreamMuxerBox::new(binding.wrap_muxer(peer, muxer))))
            }
        });
        let transport = ExplicitTransport {
            direct,
            circuit: TransportTimeout::new(circuit, CIRCUIT_HANDSHAKE_TIMEOUT).boxed(),
            route: route.clone(),
            reservation_addr: route.reservation_addr(),
            listener: None,
        };
        Ok((transport.boxed(), behaviour))
    }

    struct ExplicitTransport {
        direct: BrowserTransport,
        circuit: BrowserTransport,
        route: RelayRoute,
        reservation_addr: Multiaddr,
        listener: Option<ListenerId>,
    }

    impl ExplicitTransport {
        fn for_dial(&mut self, addr: &Multiaddr) -> Option<&mut BrowserTransport> {
            // Select the leg explicitly. WebRTC Direct can accept trailing protocols
            // after a /p2p component, and must never consume a circuit address.
            let selected = self.route.dial_peer();
            if selected.is_some() && addr == &self.route.dial_addr() {
                return Some(&mut self.circuit);
            }
            (addr == &self.route.relay_entrance
                || selected.is_some_and(|peer| {
                    addr.iter().count() == 5 && addr.iter().last() == Some(Protocol::P2p(peer))
                }))
            .then_some(&mut self.direct)
        }
    }

    impl Transport for ExplicitTransport {
        type Output = <BrowserTransport as Transport>::Output;
        type Error = io::Error;
        type ListenerUpgrade = <BrowserTransport as Transport>::ListenerUpgrade;
        type Dial = <BrowserTransport as Transport>::Dial;

        fn listen_on(
            &mut self,
            id: ListenerId,
            addr: Multiaddr,
        ) -> Result<(), TransportError<Self::Error>> {
            if addr != self.reservation_addr {
                return Err(TransportError::MultiaddrNotSupported(addr));
            }
            if self.listener.is_some() {
                return Err(TransportError::Other(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "relay reservation already requested",
                )));
            }
            self.circuit.listen_on(id, addr)?;
            self.listener = Some(id);
            Ok(())
        }

        fn remove_listener(&mut self, id: ListenerId) -> bool {
            let removed = self.circuit.remove_listener(id);
            if removed && self.listener == Some(id) {
                self.listener = None;
            }
            removed
        }

        fn dial(
            &mut self,
            addr: Multiaddr,
            opts: DialOpts,
        ) -> Result<Self::Dial, TransportError<Self::Error>> {
            match self.for_dial(&addr) {
                Some(transport) => transport.dial(addr, opts),
                None => Err(TransportError::MultiaddrNotSupported(addr)),
            }
        }

        fn dial_with_connection_id(
            &mut self,
            addr: Multiaddr,
            opts: DialOpts,
            id: usize,
        ) -> Result<Self::Dial, TransportError<Self::Error>> {
            match self.for_dial(&addr) {
                Some(transport) => transport.dial_with_connection_id(addr, opts, id),
                None => Err(TransportError::MultiaddrNotSupported(addr)),
            }
        }

        fn poll(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
            let this = self.get_mut();
            let event = Pin::new(&mut this.circuit).poll(cx);
            if let Poll::Ready(TransportEvent::ListenerClosed { listener_id, .. }) = &event
                && this.listener == Some(*listener_id)
            {
                this.listener = None;
            }
            if event.is_ready() {
                return event;
            }
            Pin::new(&mut this.direct).poll(cx)
        }
    }
}

#[cfg(test)]
mod tests {
    use libp2p::core::multihash::Multihash;

    use super::*;

    #[test]
    fn requires_an_exact_webrtc_relay_entrance_and_a_distinct_destination() {
        let relay = PeerId::random();
        let destination = PeerId::random();
        let fingerprint = Multihash::wrap(0x12, &[7; 32]).unwrap();
        let base = "/ip6/::1/udp/12345/webrtc-direct"
            .parse::<Multiaddr>()
            .unwrap();
        let entrance = base
            .clone()
            .with(Protocol::Certhash(fingerprint))
            .with(Protocol::P2p(relay));
        let reservation = entrance.clone().with(Protocol::P2pCircuit);
        let dial = reservation.clone().with(Protocol::P2p(destination));

        let route = RelayRoute::from_dial_addr(&dial).unwrap();
        assert_eq!(route.relay_peer(), relay);
        assert_eq!(route.destination(), destination);
        assert_eq!(route.dial_addr(), dial);
        assert_eq!(route.reservation_addr(), reservation);

        for invalid in [
            entrance,
            reservation.clone(),
            reservation.clone().with(Protocol::P2p(relay)),
            base.clone()
                .with(Protocol::P2p(relay))
                .with(Protocol::P2pCircuit)
                .with(Protocol::P2p(destination)),
            base.with(Protocol::Certhash(fingerprint))
                .with(Protocol::P2pCircuit)
                .with(Protocol::P2p(destination)),
            dial.clone().with(Protocol::P2pCircuit),
            dial.with(Protocol::Tcp(4001)),
        ] {
            assert!(
                RelayRoute::from_dial_addr(&invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }
}
