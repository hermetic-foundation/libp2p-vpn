use std::time::Instant;

use libp2p::request_response::Event;
use p2p_vpn::runtime::lifecycle::{
    Epoch, IDLE_AFTER, PeerLifecycle, Phase, Readiness,
    protocol::{
        LifecycleCodec, Reply, Request, Response, Scope, Session, ValidatedRequest,
        ValidatedResponse,
    },
};

use super::*;

pub(super) type Wire = request_response::Behaviour<LifecycleCodec>;
pub(super) use p2p_vpn::runtime::lifecycle::protocol::behaviour;

const READY: Readiness = Readiness {
    incoming_path_available: true,
    outstanding_work: false,
};

pub(super) async fn exercise(fixture: &mut Fixture, entrance: Multiaddr) -> Result<()> {
    let local = Epoch::new([1; 16]).unwrap();
    fixture.caps = fixture.caps.clone().with_demand_lifecycle_epoch(local);
    let direct = fixture.exchange_capabilities(false).await?;
    legacy(fixture, direct).await?;
    if fixture.swarm.close_connection(direct) {
        loop {
            if let SwarmEvent::ConnectionClosed { connection_id, .. } =
                fixture.swarm.select_next_some().await
                && connection_id == direct
            {
                break;
            }
        }
    }
    println!("{}", json!({"stage": "direct-legacy"}));

    fixture.expected_path = PathKind::CircuitRelay;
    fixture.caps.preferred_path = PathKind::CircuitRelay.wire_name().into();
    let circuit = incoming::dial_and_exchange(fixture, entrance).await?;
    legacy(fixture, circuit).await?;
    println!("{}", json!({"stage": "hidden-legacy"}));
    let remote = wait_for_epoch_update(fixture, circuit)
        .await?
        .ok_or("visible browser did not advertise Demand")?;
    println!("{}", json!({"stage": "negotiated"}));

    let peer = fixture.peer;
    let scope = Scope {
        network_name: fixture.caps.network_name.clone(),
        membership_tag: fixture.caps.membership_tag.clone(),
    };
    let session = Session {
        peer,
        local_epoch: local,
        remote_epoch: remote,
        network_name: &scope.network_name,
        membership_tag: scope.membership_tag.as_deref(),
        previous_membership_tags: &[],
    };
    let mut policy = PeerLifecycle::new(local, remote, true, Instant::now() - IDLE_AFTER);
    loop {
        let event = fixture.swarm.select_next_some().await;
        if let SwarmEvent::Behaviour(BehaviourEvent::Demand(Event::Message {
            peer: actual,
            connection_id,
            message:
                Message::Request {
                    request_id,
                    request,
                    channel,
                },
        })) = event
        {
            assert_eq!((actual, connection_id), (peer, circuit));
            let ValidatedRequest::Idle(offer) = session
                .validate_request(peer, |_| true, &request)
                .map_err(debug_error)?
            else {
                return Err("first lifecycle request was not Idle".into());
            };
            let ack = policy
                .receive_idle(offer, Instant::now(), READY)
                .map_err(debug_error)?;
            let response = Response::for_request(
                &request,
                Reply::IdleAccepted {
                    responder_revision: ack.responder_revision,
                },
            );
            wire(fixture)
                .send_response(channel, response)
                .map_err(debug_error)?;
            loop {
                let sent = fixture.swarm.select_next_some().await;
                if let SwarmEvent::Behaviour(BehaviourEvent::Demand(Event::ResponseSent {
                    peer: actual,
                    connection_id,
                    request_id: id,
                })) = sent
                    && id == request_id
                {
                    assert_eq!((actual, connection_id), (peer, circuit));
                    break;
                }
                ensure_open(&sent, circuit)?;
            }
            policy
                .idle_reply_sent(ack, Instant::now(), READY)
                .map_err(debug_error)?;
            assert_eq!(policy.phase(), Phase::Dormant);
            break;
        }
        ensure_open(&event, circuit)?;
    }

    let wake = policy.wake(Instant::now(), true).map_err(debug_error)?;
    let request = Request::wake(scope.clone(), wake);
    let id = wire(fixture)
        .send_request_on_connection_with_deadline(
            &peer,
            circuit,
            request.clone(),
            Instant::now() + Duration::from_secs(5),
        )
        .map_err(debug_error)?;
    loop {
        let event = fixture.swarm.select_next_some().await;
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::Demand(Event::Message {
                peer: actual,
                connection_id,
                message:
                    Message::Response {
                        request_id,
                        response,
                    },
            })) if request_id == id => {
                assert_eq!((actual, connection_id), (peer, circuit));
                assert_eq!(
                    session
                        .validate_response(peer, |_| true, &request, &response)
                        .map_err(debug_error)?,
                    ValidatedResponse::WakeAccepted
                );
                break;
            }
            SwarmEvent::Behaviour(BehaviourEvent::Demand(Event::OutboundFailure {
                request_id,
                error,
                ..
            })) if request_id == id => return Err(error.into()),
            _ => ensure_open(&event, circuit)?,
        }
    }
    println!("{}", json!({"stage": "idle-and-wake-accepted"}));
    assert!(
        wait_for_epoch_update(fixture, circuit).await?.is_none(),
        "hidden browser did not withdraw Demand"
    );
    println!("{}", json!({"stage": "hidden-withdrawal"}));
    Ok(())
}

fn wire(fixture: &mut Fixture) -> &mut Wire {
    fixture
        .swarm
        .behaviour_mut()
        .demand
        .as_mut()
        .expect("Demand fixture wire")
}

fn ensure_open(event: &SwarmEvent<BehaviourEvent>, connection: ConnectionId) -> Result<()> {
    if matches!(event, SwarmEvent::ConnectionClosed { connection_id, .. } if *connection_id == connection)
    {
        return Err("test connection closed before exchange completed".into());
    }
    Ok(())
}

async fn legacy(fixture: &mut Fixture, connection: ConnectionId) -> Result<()> {
    let expected = fixture
        .swarm
        .behaviour_mut()
        .control
        .send_request_on_connection_with_deadline(
            &fixture.peer,
            connection,
            ControlRequest::Capabilities(fixture.caps.clone()),
            Instant::now() + Duration::from_secs(5),
        )
        .map_err(debug_error)?;
    let until = Instant::now() + Duration::from_secs(1);
    let mut replied = false;
    loop {
        let Ok(event) =
            tokio::time::timeout_at(until.into(), fixture.swarm.select_next_some()).await
        else {
            break;
        };
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::Control(Event::Message {
                peer,
                connection_id,
                message:
                    Message::Response {
                        request_id,
                        response: ControlResponse::CapabilitiesAccepted(caps),
                    },
            })) if request_id == expected => {
                assert_eq!((peer, connection_id), (fixture.peer, connection));
                assert!(caps.demand_lifecycle_epoch().is_none());
                replied = true;
            }
            SwarmEvent::Behaviour(BehaviourEvent::Control(Event::Message {
                message:
                    Message::Request {
                        request: ControlRequest::Capabilities(caps),
                        ..
                    },
                ..
            })) => assert!(
                caps.demand_lifecycle_epoch().is_none(),
                "ineligible Demand advertisement"
            ),
            SwarmEvent::Behaviour(BehaviourEvent::Demand(_)) => {
                return Err("ineligible connection used Demand wire".into());
            }
            _ => ensure_open(&event, connection)?,
        }
    }
    assert!(replied, "legacy control probe did not complete");
    Ok(())
}

async fn wait_for_epoch_update(
    fixture: &mut Fixture,
    connection: ConnectionId,
) -> Result<Option<Epoch>> {
    loop {
        let event = fixture.swarm.select_next_some().await;
        if let SwarmEvent::Behaviour(BehaviourEvent::Control(Event::Message {
            peer,
            connection_id,
            message:
                Message::Request {
                    request: ControlRequest::Capabilities(caps),
                    channel,
                    ..
                },
        })) = event
        {
            assert_eq!((peer, connection_id), (fixture.peer, connection));
            fixture
                .swarm
                .behaviour_mut()
                .control
                .send_response(
                    channel,
                    ControlResponse::CapabilitiesAccepted(fixture.caps.clone()),
                )
                .map_err(debug_error)?;
            return Ok(caps.demand_lifecycle_epoch());
        }
        ensure_open(&event, connection)?;
    }
}
