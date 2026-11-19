//! Explicit Circuit Relay v2 routes. No relay discovery or service runs in the browser.

use std::io;

use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};

#[derive(Clone, Debug)]
pub(crate) struct RelayRoute {
    relay_entrance: Multiaddr,
    relay_peer: PeerId,
    destination: PeerId,
}

impl RelayRoute {
    /// Both the WebRTC Direct relay and the end-to-end destination must be pinned.
    pub(crate) fn from_dial_addr(addr: &Multiaddr) -> io::Result<Self> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected a pinned WebRTC Direct relay address followed by /p2p-circuit/p2p/<destination>",
            )
        };
        let mut parts = addr.iter();
        let ip = match parts.next() {
            Some(Protocol::Ip4(ip)) if !ip.is_unspecified() => Protocol::Ip4(ip),
            Some(Protocol::Ip6(ip)) if !ip.is_unspecified() => Protocol::Ip6(ip),
            _ => return Err(invalid()),
        };
        let (
            Some(Protocol::Udp(port)),
            Some(Protocol::WebRTCDirect),
            Some(Protocol::Certhash(hash)),
            Some(Protocol::P2p(relay_peer)),
            Some(Protocol::P2pCircuit),
            Some(Protocol::P2p(destination)),
            None,
        ) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        )
        else {
            return Err(invalid());
        };
        // WebRTC Direct supports SHA-256 certificate fingerprints.
        if port == 0 || hash.code() != 0x12 || hash.size() != 32 || relay_peer == destination {
            return Err(invalid());
        }
        let relay_entrance = Multiaddr::empty()
            .with(ip)
            .with(Protocol::Udp(port))
            .with(Protocol::WebRTCDirect)
            .with(Protocol::Certhash(hash))
            .with(Protocol::P2p(relay_peer));
        Ok(Self {
            relay_entrance,
            relay_peer,
            destination,
        })
    }

    pub(crate) fn relay_peer(&self) -> PeerId {
        self.relay_peer
    }

    pub(crate) fn destination(&self) -> PeerId {
        self.destination
    }

    pub(crate) fn dial_addr(&self) -> Multiaddr {
        self.reservation_addr()
            .with(Protocol::P2p(self.destination))
    }

    /// Pass to `Swarm::listen_on` only when the caller explicitly requests a reservation.
    pub(crate) fn reservation_addr(&self) -> Multiaddr {
        self.relay_entrance.clone().with(Protocol::P2pCircuit)
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) use transport::build_transport;

#[cfg(target_arch = "wasm32")]
mod transport {
    use std::{
        pin::Pin,
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
        identity, noise, relay,
        swarm::behaviour::toggle::Toggle,
        webrtc_websys, yamux,
    };

    use super::*;

    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
    const MAX_CIRCUIT_STREAMS: usize = 128;

    type BrowserTransport = Boxed<(PeerId, StreamMuxerBox)>;

    /// The direct address (if any) and the relay route must be selected by the host/user,
    /// not taken from a discovery or Identify event. No reservation occurs at construction.
    pub(crate) fn build_transport(
        keys: &identity::Keypair,
        direct_addr: Option<&Multiaddr>,
        route: Option<&RelayRoute>,
    ) -> io::Result<(BrowserTransport, Toggle<relay::client::Behaviour>)> {
        if direct_addr.is_some_and(|addr| addr.iter().any(|p| p == Protocol::P2pCircuit)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the direct endpoint must not contain /p2p-circuit",
            ));
        }

        let direct = webrtc_websys::Transport::new(webrtc_websys::Config::new(keys)).boxed();
        let (circuit, behaviour) = if let Some(route) = route {
            let local_peer = keys.public().to_peer_id();
            let expected = route.destination();
            if local_peer == route.relay_peer()
                || local_peer == expected
                || direct_addr
                    .is_some_and(|addr| addr.iter().last() != Some(Protocol::P2p(expected)))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "relay, local, and remote peers must be distinct; direct and relayed endpoints must pin the same remote peer",
                ));
            }
            let (transport, behaviour) = relay::client::new(local_peer);
            let noise = noise::Config::new(keys).map_err(io::Error::other)?;
            let mut yamux = yamux::Config::default();
            yamux.set_max_num_streams(MAX_CIRCUIT_STREAMS);
            let transport = transport
                .and_then(move |stream, endpoint| {
                    let binding = stream.circuit_binding();
                    let noise = noise.clone();
                    let yamux = yamux.clone();
                    async move {
                        let (peer, secured) =
                            upgrade::apply(stream, noise, endpoint.clone(), Version::V1Lazy)
                                .await
                                .map_err(io::Error::other)?;
                        // STOP carries a relay-supplied source ID. Trust the end-to-end
                        // Noise identity instead, including on inbound reservations.
                        if peer != expected {
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
                })
                .boxed();
            (
                Some(CircuitTransport {
                    transport,
                    dial_addr: route.dial_addr(),
                    reservation_addr: route.reservation_addr(),
                    relay_entrance: route.relay_entrance.clone(),
                    listener: None,
                }),
                Some(behaviour),
            )
        } else {
            (None, None)
        };
        let transport = ExplicitTransport {
            direct,
            direct_addr: direct_addr.cloned(),
            circuit,
        };
        Ok((
            TransportTimeout::new(transport, HANDSHAKE_TIMEOUT).boxed(),
            Toggle::from(behaviour),
        ))
    }

    struct CircuitTransport {
        transport: BrowserTransport,
        dial_addr: Multiaddr,
        reservation_addr: Multiaddr,
        relay_entrance: Multiaddr,
        listener: Option<ListenerId>,
    }

    struct ExplicitTransport {
        direct: BrowserTransport,
        direct_addr: Option<Multiaddr>,
        circuit: Option<CircuitTransport>,
    }

    impl ExplicitTransport {
        fn for_dial(&mut self, addr: &Multiaddr) -> Option<&mut BrowserTransport> {
            // Select the leg explicitly. WebRTC Direct can accept trailing protocols
            // after a /p2p component, and must never consume a circuit address.
            if let Some(circuit) = &mut self.circuit {
                if addr == &circuit.dial_addr {
                    return Some(&mut circuit.transport);
                }
                if addr == &circuit.relay_entrance {
                    return Some(&mut self.direct);
                }
            }
            (self.direct_addr.as_ref() == Some(addr)).then_some(&mut self.direct)
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
            let Some(circuit) = self.circuit.as_mut().filter(|c| addr == c.reservation_addr) else {
                return Err(TransportError::MultiaddrNotSupported(addr));
            };
            if circuit.listener.is_some() {
                return Err(TransportError::Other(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "relay reservation already requested",
                )));
            }
            circuit.transport.listen_on(id, addr)?;
            circuit.listener = Some(id);
            Ok(())
        }

        fn remove_listener(&mut self, id: ListenerId) -> bool {
            self.circuit
                .as_mut()
                .is_some_and(|c| c.transport.remove_listener(id))
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
            if let Some(circuit) = &mut this.circuit {
                let event = Pin::new(&mut circuit.transport).poll(cx);
                if let Poll::Ready(TransportEvent::ListenerClosed { listener_id, .. }) = &event
                    && circuit.listener == Some(*listener_id)
                {
                    circuit.listener = None;
                }
                if event.is_ready() {
                    return event;
                }
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
