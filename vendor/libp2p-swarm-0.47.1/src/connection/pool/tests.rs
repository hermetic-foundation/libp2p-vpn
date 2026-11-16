use std::{
    io,
    sync::{Arc, Mutex},
};

use futures::task::noop_waker_ref;
use libp2p_core::{muxing::StreamMuxerEvent, transport::dummy::DummyTransport, Transport};

use super::*;
use crate::{
    behaviour::FromSwarm, dummy, Config, ConnectionDenied, NetworkBehaviour, Swarm, SwarmEvent,
    THandlerInEvent, THandlerOutEvent, ToSwarm,
};

#[derive(Default)]
struct Recording {
    admissions: Vec<ConnectionId>,
    hook_ids: Vec<usize>,
    driver_polls: usize,
    closes: usize,
    drops: usize,
}

struct RecordingMuxer(Arc<Mutex<Recording>>);

impl StreamMuxer for RecordingMuxer {
    type Substream = futures::io::Cursor<Vec<u8>>;
    type Error = io::Error;

    fn on_swarm_connection(self: Pin<&mut Self>, connection_id: usize) {
        let mut recording = self.0.lock().unwrap();
        assert_eq!(
            recording.admissions,
            [ConnectionId::new_unchecked(connection_id)]
        );
        assert!(recording.hook_ids.is_empty());
        assert_eq!(recording.driver_polls, 0);
        recording.hook_ids.push(connection_id);
    }

    fn poll_inbound(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        Poll::Pending
    }

    fn poll_outbound(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        Poll::Pending
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.lock().unwrap().closes += 1;
        Poll::Ready(Ok(()))
    }

    fn poll(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Result<StreamMuxerEvent, Self::Error>> {
        let mut recording = self.0.lock().unwrap();
        assert_eq!(recording.hook_ids.len(), 1);
        recording.driver_polls += 1;
        Poll::Pending
    }
}

impl Drop for RecordingMuxer {
    fn drop(&mut self) {
        self.0.lock().unwrap().drops += 1;
    }
}

struct AdmissionBehaviour {
    recording: Arc<Mutex<Recording>>,
    deny: bool,
}

impl AdmissionBehaviour {
    fn admit(&self, id: ConnectionId) -> Result<dummy::ConnectionHandler, ConnectionDenied> {
        let mut recording = self.recording.lock().unwrap();
        assert!(recording.hook_ids.is_empty());
        recording.admissions.push(id);
        if self.deny {
            Err(ConnectionDenied::new(io::Error::other("test denial")))
        } else {
            Ok(dummy::ConnectionHandler)
        }
    }
}

impl NetworkBehaviour for AdmissionBehaviour {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<Self::ConnectionHandler, ConnectionDenied> {
        self.admit(id)
    }

    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<Self::ConnectionHandler, ConnectionDenied> {
        self.admit(id)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        if let FromSwarm::ConnectionEstablished(event) = event {
            assert_eq!(
                self.recording.lock().unwrap().hook_ids,
                [event.connection_id.0]
            );
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        libp2p_core::util::unreachable(event)
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

fn new_swarm(deny: bool) -> (Swarm<AdmissionBehaviour>, Arc<Mutex<Recording>>) {
    let recording = Arc::new(Mutex::new(Recording::default()));
    let swarm = Swarm::new(
        DummyTransport::new().boxed(),
        AdmissionBehaviour {
            recording: recording.clone(),
            deny,
        },
        PeerId::random(),
        Config::without_executor().with_idle_connection_timeout(Duration::from_secs(60)),
    );
    (swarm, recording)
}

fn add_pending(
    swarm: &mut Swarm<AdmissionBehaviour>,
    recording: &Arc<Mutex<Recording>>,
    id: ConnectionId,
    obtained: PeerId,
    expected: Option<PeerId>,
    inbound: bool,
) {
    let muxer = StreamMuxerBox::new(RecordingMuxer(recording.clone()));
    let address: Multiaddr = "/memory/1".parse().unwrap();
    if inbound {
        swarm.pool.add_incoming(
            futures::future::ready(Ok((obtained, muxer))),
            IncomingInfo {
                local_addr: &address,
                send_back_addr: &address,
            },
            id,
        );
    } else {
        swarm.pool.add_outgoing(
            vec![futures::future::ready((address, Ok((obtained, muxer)))).boxed()],
            expected,
            Endpoint::Dialer,
            PortUse::Reuse,
            None,
            id,
        );
    }
}

fn next_pool_event(swarm: &mut Swarm<AdmissionBehaviour>) -> PoolEvent<Infallible> {
    let mut cx = Context::from_waker(noop_waker_ref());
    // The local executor is advanced at the end of Pool::poll; its event arrives next poll.
    for _ in 0..4 {
        if let Poll::Ready(event) = swarm.pool.poll(&mut cx) {
            return event;
        }
    }
    panic!("pending setup did not produce a pool event");
}

fn advance_pool(swarm: &mut Swarm<AdmissionBehaviour>) {
    let mut cx = Context::from_waker(noop_waker_ref());
    for _ in 0..4 {
        assert!(swarm.pool.poll(&mut cx).is_pending());
    }
}

#[test]
fn swarm_connection_hook_runs_once_after_admission_before_driver() {
    for inbound in [false, true] {
        let (mut swarm, recording) = new_swarm(false);
        let id = ConnectionId::new_unchecked(usize::MAX);
        let peer = PeerId::random();
        add_pending(&mut swarm, &recording, id, peer, Some(peer), inbound);
        let event = next_pool_event(&mut swarm);
        assert!(
            matches!(&event, PoolEvent::ConnectionEstablished { id: event_id, .. } if *event_id == id)
        );
        assert!(recording.lock().unwrap().hook_ids.is_empty());

        swarm.handle_pool_event(event);
        assert_eq!(recording.lock().unwrap().hook_ids, [id.0]);
        advance_pool(&mut swarm);
        let recording = recording.lock().unwrap();
        assert_eq!(recording.hook_ids, [id.0]);
        assert!(recording.driver_polls > 0);
        assert_eq!(recording.closes, 0);
    }
}

#[test]
fn swarm_connection_hook_does_not_run_when_behaviour_denies() {
    for inbound in [false, true] {
        let (mut swarm, recording) = new_swarm(true);
        let id = ConnectionId::new_unchecked(41);
        let peer = PeerId::random();
        add_pending(&mut swarm, &recording, id, peer, Some(peer), inbound);
        let event = next_pool_event(&mut swarm);
        swarm.handle_pool_event(event);
        assert!(matches!(
            swarm.pending_swarm_events.front(),
            Some(SwarmEvent::IncomingConnectionError {
                error: crate::ListenError::Denied { .. },
                ..
            }) | Some(SwarmEvent::OutgoingConnectionError {
                error: crate::DialError::Denied { .. },
                ..
            })
        ));

        advance_pool(&mut swarm);
        let recording = recording.lock().unwrap();
        assert_eq!(recording.admissions, [id]);
        assert!(recording.hook_ids.is_empty());
        assert_eq!(recording.closes, 1);
        assert_eq!(recording.drops, 1);
    }
}

#[test]
fn swarm_connection_hook_does_not_run_for_wrong_or_local_peer() {
    for local_peer in [false, true] {
        let (mut swarm, recording) = new_swarm(false);
        let obtained = if local_peer {
            *swarm.local_peer_id()
        } else {
            PeerId::random()
        };
        let expected = if local_peer {
            obtained
        } else {
            PeerId::random()
        };
        add_pending(
            &mut swarm,
            &recording,
            ConnectionId::new_unchecked(42),
            obtained,
            Some(expected),
            false,
        );
        let event = next_pool_event(&mut swarm);
        if local_peer {
            assert!(matches!(
                event,
                PoolEvent::PendingOutboundConnectionError {
                    error: PendingOutboundConnectionError::LocalPeerId { .. },
                    ..
                }
            ));
        } else {
            assert!(matches!(
                event,
                PoolEvent::PendingOutboundConnectionError {
                    error: PendingOutboundConnectionError::WrongPeerId { .. },
                    ..
                }
            ));
        }

        advance_pool(&mut swarm);
        let recording = recording.lock().unwrap();
        assert!(recording.admissions.is_empty());
        assert!(recording.hook_ids.is_empty());
        assert_eq!(recording.closes, 1);
        assert_eq!(recording.drops, 1);
    }
}

#[test]
fn swarm_connection_hook_does_not_run_for_cancelled_setup() {
    let (mut swarm, recording) = new_swarm(false);
    let id = ConnectionId::new_unchecked(43);
    let peer = PeerId::random();
    add_pending(&mut swarm, &recording, id, peer, Some(peer), false);
    swarm.pool.pending.get_mut(&id).unwrap().abort();

    assert!(matches!(
        next_pool_event(&mut swarm),
        PoolEvent::PendingOutboundConnectionError {
            error: PendingOutboundConnectionError::Aborted,
            ..
        }
    ));
    advance_pool(&mut swarm);
    let recording = recording.lock().unwrap();
    assert!(recording.admissions.is_empty());
    assert!(recording.hook_ids.is_empty());
    assert_eq!(recording.drops, 1);
}

#[test]
fn swarm_connection_hook_does_not_run_for_dropped_new_connection() {
    let (mut swarm, recording) = new_swarm(false);
    let peer = PeerId::random();
    add_pending(
        &mut swarm,
        &recording,
        ConnectionId::new_unchecked(44),
        peer,
        Some(peer),
        false,
    );
    let event = next_pool_event(&mut swarm);
    assert!(matches!(&event, PoolEvent::ConnectionEstablished { .. }));
    drop(event);

    advance_pool(&mut swarm);
    let recording = recording.lock().unwrap();
    assert!(recording.admissions.is_empty());
    assert!(recording.hook_ids.is_empty());
    assert_eq!(recording.closes, 1);
    assert_eq!(recording.drops, 1);
}
