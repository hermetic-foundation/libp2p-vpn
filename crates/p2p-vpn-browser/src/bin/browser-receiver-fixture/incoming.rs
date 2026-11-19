use std::io::BufRead;

use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};

use super::*;

pub(super) async fn dial_and_exchange(
    fixture: &mut Fixture,
    entrance: Multiaddr,
) -> Result<ConnectionId> {
    // The fixture never reserves. The browser must finish its own reservation
    // and publish that exact local address before the native peer can dial.
    let address = entrance
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(fixture.peer));
    let offered = std::io::stdin()
        .lock()
        .lines()
        .next()
        .ok_or("expected the browser's reservation address")??;
    assert_eq!(offered, address.to_string());
    let connection = exchange_on_reservation(fixture, address.clone()).await?;
    let duplicate = DialOpts::peer_id(fixture.peer)
        .condition(PeerCondition::Always)
        .addresses(vec![address])
        .build();
    let duplicate_id = duplicate.connection_id();
    fixture.swarm.dial(duplicate)?;
    loop {
        match fixture.swarm.select_next_some().await {
            SwarmEvent::ConnectionClosed {
                connection_id,
                num_established: 1,
                ..
            }
            | SwarmEvent::OutgoingConnectionError { connection_id, .. }
                if connection_id == duplicate_id =>
            {
                break;
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } if peer_id == fixture.peer => {
                return Err("the original circuit did not retain ownership".into());
            }
            _ => {}
        }
    }
    Ok(connection)
}

pub(super) async fn exchange_on_reservation(
    fixture: &mut Fixture,
    address: Multiaddr,
) -> Result<ConnectionId> {
    fixture.swarm.dial(
        DialOpts::peer_id(fixture.peer)
            .addresses(vec![address])
            .build(),
    )?;
    let connection = loop {
        match fixture.swarm.select_next_some().await {
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                connection_id,
                ..
            } if peer_id == fixture.peer => {
                assert!(endpoint.is_dialer() && endpoint.is_relayed());
                break connection_id;
            }
            SwarmEvent::OutgoingConnectionError { error, .. } => return Err(error.into()),
            _ => {}
        }
    };

    let request = fixture.swarm.behaviour_mut().control.send_request(
        &fixture.peer,
        ControlRequest::Capabilities(fixture.caps.clone()),
    );
    let mut answered = false;
    let mut accepted = false;
    while !(answered && accepted) {
        let BehaviourEvent::Control(request_response::Event::Message { message, .. }) =
            fixture.next().await?
        else {
            continue;
        };
        match message {
            Message::Request {
                request: ControlRequest::Capabilities(caps),
                channel,
                ..
            } => {
                check_browser_capabilities(fixture, &caps);
                fixture
                    .swarm
                    .behaviour_mut()
                    .control
                    .send_response(
                        channel,
                        ControlResponse::CapabilitiesAccepted(fixture.caps.clone()),
                    )
                    .map_err(debug_error)?;
                answered = true;
            }
            Message::Response {
                request_id,
                response: ControlResponse::CapabilitiesAccepted(caps),
            } => {
                assert_eq!(request_id, request);
                check_browser_capabilities(fixture, &caps);
                accepted = true;
            }
            _ => {
                return Err(
                    "expected bidirectional capability exchange on incoming circuit".into(),
                );
            }
        }
    }

    Ok(connection)
}

fn check_browser_capabilities(fixture: &Fixture, caps: &ControlCapabilities) {
    if fixture.caps.demand_lifecycle_epoch().is_some() {
        assert!(
            caps.demand_lifecycle_epoch().is_none(),
            "initial browser caps enabled Demand"
        );
    }
    assert_eq!(caps.preferred_path, PathKind::CircuitRelay.wire_name());
    assert_eq!(
        control::validate_capabilities(
            caps,
            &fixture.caps.network_name,
            fixture.caps.membership_tag.as_deref(),
            &[],
        ),
        None
    );
    assert!(
        fixture
            .forwarder
            .authorizes_advertised_routes(fixture.peer, &caps.advertised_routes)
    );
}
