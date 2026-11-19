use std::future::Future;

use futures::{StreamExt, future};
use gloo_timers::future::TimeoutFuture;
use libp2p::{
    Multiaddr, PeerId, Swarm, Transport,
    core::{
        Endpoint,
        transport::{DialOpts as TransportDialOpts, PortUse, TransportError},
    },
    identity::Keypair,
    multiaddr::Protocol,
    ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent, behaviour::toggle::Toggle, dial_opts::DialOpts},
};
use wasm_bindgen::prelude::*;

use crate::relay_transport::{RelayRoute, build_transport};

#[derive(NetworkBehaviour)]
struct Behaviour {
    relay: Toggle<relay::client::Behaviour>,
    ping: ping::Behaviour,
}

#[wasm_bindgen]
pub struct RelayProbe {
    keys: Keypair,
    session: Option<Session>,
}

struct Session {
    route: RelayRoute,
    swarm: Swarm<Behaviour>,
}

#[wasm_bindgen]
impl RelayProbe {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        console_error_panic_hook::set_once();
        Self {
            keys: Keypair::generate_ed25519(),
            session: None,
        }
    }

    pub fn peer_id(&self) -> String {
        self.keys.public().to_peer_id().to_string()
    }

    pub fn configure(&mut self, entrance: &str, destination: &str) -> Result<(), JsError> {
        let destination: PeerId = destination.parse()?;
        let address = entrance
            .parse::<Multiaddr>()?
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(destination));
        let route = RelayRoute::from_dial_addr(&address)?;
        let (mut transport, relay) = build_transport(&self.keys, &route)?;
        let alternate = route
            .reservation_addr()
            .with(Protocol::P2p(PeerId::random()));
        if !matches!(
            transport.dial(
                alternate,
                TransportDialOpts {
                    role: Endpoint::Dialer,
                    port_use: PortUse::Reuse,
                }
            ),
            Err(TransportError::MultiaddrNotSupported(_))
        ) {
            return Err(JsError::new("unconfigured relay destination was accepted"));
        }
        let swarm = Swarm::new(
            transport,
            Behaviour {
                relay: Toggle::from(Some(relay)),
                ping: ping::Behaviour::default(),
            },
            self.keys.public().to_peer_id(),
            libp2p::swarm::Config::with_wasm_executor()
                .with_idle_connection_timeout(std::time::Duration::from_secs(30)),
        );
        self.session = Some(Session { route, swarm });
        Ok(())
    }

    pub async fn reserve(&mut self) -> Result<(), JsError> {
        let session = self.session()?;
        let address = session.route.reservation_addr();
        let id = session.swarm.listen_on(address.clone())?;
        if session.swarm.listen_on(address).is_ok() {
            return Err(JsError::new("duplicate reservation unexpectedly accepted"));
        }
        bounded(async {
            loop {
                match session.swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr { listener_id, .. } if listener_id == id => {
                        return Ok(());
                    }
                    SwarmEvent::ListenerClosed {
                        listener_id,
                        reason,
                        ..
                    } if listener_id == id => {
                        reason?;
                        return Err(JsError::new("reservation listener closed"));
                    }
                    SwarmEvent::OutgoingConnectionError { error, .. } => return Err(error.into()),
                    _ => {}
                }
            }
        })
        .await
    }

    pub async fn dial_and_ping(&mut self) -> Result<String, JsError> {
        let session = self.session()?;
        session.swarm.dial(
            DialOpts::peer_id(session.route.destination())
                .addresses(vec![session.route.dial_addr()])
                .build(),
        )?;
        self.await_ping().await
    }

    pub async fn await_ping(&mut self) -> Result<String, JsError> {
        let session = self.session()?;
        let expected = session.route.destination();
        bounded(async {
            let mut authenticated = None;
            loop {
                match session.swarm.select_next_some().await {
                    SwarmEvent::ConnectionEstablished {
                        peer_id,
                        connection_id,
                        endpoint,
                        ..
                    } if peer_id == expected && endpoint.is_relayed() => {
                        authenticated = Some(connection_id);
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Ping(event))
                        if event.peer == expected && Some(event.connection) == authenticated =>
                    {
                        event.result?;
                        return Ok(event.peer.to_string());
                    }
                    SwarmEvent::OutgoingConnectionError { error, .. } => return Err(error.into()),
                    SwarmEvent::IncomingConnectionError { error, .. } => return Err(error.into()),
                    SwarmEvent::ConnectionClosed {
                        peer_id,
                        connection_id,
                        cause,
                        ..
                    } if peer_id == expected && Some(connection_id) == authenticated => {
                        return Err(JsError::new(&format!(
                            "circuit closed before ping: {cause:?}"
                        )));
                    }
                    _ => {}
                }
            }
        })
        .await
    }

    pub async fn await_rejected_peer(&mut self) -> Result<String, JsError> {
        let session = self.session()?;
        bounded(async {
            loop {
                match session.swarm.select_next_some().await {
                    SwarmEvent::IncomingConnectionError { error, .. } => {
                        return Ok(format!("{error:?}"));
                    }
                    SwarmEvent::ConnectionEstablished {
                        peer_id, endpoint, ..
                    } if endpoint.is_relayed() && peer_id != session.route.destination() => {
                        return Err(JsError::new("unpinned peer established a circuit"));
                    }
                    _ => {}
                }
            }
        })
        .await
    }
}

impl RelayProbe {
    fn session(&mut self) -> Result<&mut Session, JsError> {
        self.session
            .as_mut()
            .ok_or_else(|| JsError::new("configure the probe first"))
    }
}

async fn bounded<T>(operation: impl Future<Output = Result<T, JsError>>) -> Result<T, JsError> {
    let timeout = TimeoutFuture::new(25_000);
    futures::pin_mut!(operation, timeout);
    match future::select(operation, timeout).await {
        future::Either::Left((result, _)) => result,
        future::Either::Right(_) => Err(JsError::new("relay probe timed out")),
    }
}
