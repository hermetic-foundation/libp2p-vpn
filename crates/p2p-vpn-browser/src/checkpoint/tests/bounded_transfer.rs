use libp2p::swarm::{ConnectionId, NetworkBehaviour};
use p2p_vpn::membership::checkpoint::MAX_SNAPSHOT_OFFER_BYTES;
use p2p_vpn::runtime::control::checkpoint;

use super::tests::{Fixture, SECRET, WALL_NOW, fixture};
use super::*;

#[test]
fn declared_transfer_bounds() {
    let defaults = CheckpointSyncLimits::default();
    assert_eq!(checkpoint::MAX_PAGE_BYTES, 8 * 1024);
    assert_eq!(checkpoint::MAX_PAGE_MESSAGE_BYTES, 12 * 1024);
    assert_eq!(MAX_SNAPSHOT_OFFER_BYTES, 4 * 1024 * 1024);
    assert_eq!(MAX_TRANSFER_SESSIONS, 32);
    assert_eq!(checkpoint::MAX_TRANSFERS_PER_PEER, 4);
    assert_eq!(checkpoint::MAX_TRANSFER_BUFFER_BYTES, 16 * 1024 * 1024);
    assert_eq!(defaults.max_sessions, 16);
    assert_eq!(defaults.max_sessions_per_peer, 4);
    assert_eq!(defaults.max_buffered_bytes, 16 * 1024 * 1024);
    assert_eq!(defaults.session_timeout, Duration::from_secs(60));
    assert_eq!(RESYNC_WINDOW, Duration::from_secs(15));
}

#[test]
fn partial_transfer_retires_and_retries_under_a_fresh_challenge() {
    for already_retired in [false, true] {
        let Fixture {
            mut client,
            publisher,
            publisher_state,
            ..
        } = fixture(false, false, false);
        let floor = publisher_state.snapshot().payload.rank().unwrap();
        client.enrollment_floor = Some(floor);
        let retained = client.state().retained();
        let peer = client.peer;
        let local = client.identity.peer_id.parse().unwrap();
        let mut source = CheckpointSync::new(
            peer,
            client.anchor().clone(),
            CheckpointSyncLimits::default(),
        )
        .unwrap();
        let mut wire = checkpoint::behaviour(4);
        let connection_id = ConnectionId::new_unchecked(1);
        let addr = "/memory/1".parse().unwrap();
        // Register a connection in the behavior without opening or polling a transport.
        let _handler = wire
            .handle_established_inbound_connection(connection_id, peer, &addr, &addr)
            .unwrap();
        let caps = ControlCapabilities::local("lab", Some(client.membership_tag().into()), 1280)
            .with_checkpoint(&publisher_state)
            .unwrap();
        client.observe_capabilities(peer, &caps).unwrap();

        let respond =
            |client: &mut CheckpointDriver, wire: &mut CheckpointBehaviour, response, now| {
                let request_id = client.outbound.as_ref().unwrap().id;
                client.handle_event(
                    wire,
                    rr::Event::Message {
                        peer,
                        connection_id,
                        message: rr::Message::Response {
                            request_id,
                            response,
                        },
                    },
                    now,
                    WALL_NOW,
                )
            };
        let start = Instant::now();
        let deadline = start + RESYNC_WINDOW;
        client.drive_sync(&mut wire, start).unwrap();
        let initial = client.outbound.as_ref().unwrap().request.clone();
        let page = source
            .respond_at(
                local,
                &initial,
                &publisher_state,
                &publisher,
                &SECRET,
                start,
                WALL_NOW,
            )
            .unwrap();
        let CheckpointPageResponse::Page(first) = &page else {
            panic!("expected an initial page");
        };
        assert_eq!(first.bytes.len(), checkpoint::MAX_PAGE_BYTES);
        let reserved_bytes = first.total_bytes as usize;
        assert!(reserved_bytes > checkpoint::MAX_PAGE_BYTES);
        let first_arrival = start + Duration::from_secs(1);
        respond(&mut client, &mut wire, page, first_arrival).unwrap();
        let continuation = client.outbound.as_ref().unwrap().request.clone();
        assert_eq!(continuation.challenge, initial.challenge);
        assert_eq!(continuation.cursor as usize, checkpoint::MAX_PAGE_BYTES);
        assert!(continuation.offer_digest.is_some());
        assert_eq!(client.round.as_ref().unwrap().deadline, deadline);
        assert_eq!(client.transfer.stats().assembler_sessions, 1);
        assert_eq!(client.transfer.stats().buffered_bytes, reserved_bytes);
        assert_eq!(client.state().retained(), retained);

        let before_deadline = deadline - Duration::from_millis(1);
        if already_retired {
            assert!(
                client
                    .finish_due(before_deadline, WALL_NOW)
                    .unwrap()
                    .is_none()
            );
            assert!(client.finish_due(deadline, WALL_NOW).unwrap().is_none());
            assert_eq!(client.transfer.stats().buffered_bytes, 0);
            // The request still owns its terminal notification, but no longer owns a round.
            let request_id = client.outbound.as_ref().unwrap().id;
            client.drive_sync(&mut wire, deadline).unwrap();
            assert_eq!(client.outbound.as_ref().unwrap().id, request_id);
            client
                .handle_event(
                    &mut wire,
                    rr::Event::OutboundFailure {
                        peer,
                        connection_id,
                        request_id,
                        error: rr::OutboundFailure::Timeout,
                    },
                    deadline,
                    WALL_NOW,
                )
                .unwrap();
        } else {
            let busy = CheckpointPageResponse::rejected(&continuation, CheckpointRejection::Busy);
            let rejected_at = first_arrival + Duration::from_secs(1);
            assert!(matches!(
                respond(&mut client, &mut wire, busy, rejected_at),
                Err(CheckpointSyncError::Rejected)
            ));
            assert_eq!(client.transfer.stats().retired_sessions, 1);
            client.drive_sync(&mut wire, before_deadline).unwrap();
        }
        assert!(client.round.is_none());
        assert!(client.outbound.is_none());
        assert!(client.finish_due(deadline, WALL_NOW).unwrap().is_none());
        assert_eq!(client.transfer.stats().assembler_sessions, 0);
        assert_eq!(client.transfer.stats().buffered_bytes, 0);
        assert_eq!(client.state().retained(), retained);
        assert_eq!(
            client.state().sync_state(),
            MembershipSyncState::ResyncRequired
        );
        assert_eq!(client.enrollment_floor, Some(floor));
        source.cancel(local, &initial.challenge, deadline);
        assert_eq!(source.stats().buffered_bytes, 0);

        client.drive_sync(&mut wire, deadline).unwrap();
        assert_eq!(client.transfer.stats().retired_sessions, 0);
        let restart = &client.outbound.as_ref().unwrap().request;
        assert_ne!(restart.challenge, initial.challenge);
        assert_eq!(restart.cursor, 0);
        assert_eq!(restart.offer_digest, None);
        let retry_deadline = deadline + RESYNC_WINDOW;
        assert_eq!(client.round.as_ref().unwrap().deadline, retry_deadline);
        let mut pages = 0;
        while let Some(outbound) = &client.outbound {
            pages += 1;
            assert!(pages <= MAX_SNAPSHOT_OFFER_BYTES / checkpoint::MAX_PAGE_BYTES);
            let page = source
                .respond_at(
                    local,
                    &outbound.request,
                    &publisher_state,
                    &publisher,
                    &SECRET,
                    deadline,
                    WALL_NOW,
                )
                .unwrap();
            let arrival = deadline + Duration::from_millis(pages as u64);
            respond(&mut client, &mut wire, page, arrival).unwrap();
            assert_eq!(client.state().retained(), retained);
            assert_eq!(client.enrollment_floor, Some(floor));
            assert_eq!(client.round.as_ref().unwrap().deadline, retry_deadline);
        }
        assert!(pages > 1);
        assert_eq!(source.stats().buffered_bytes, 0);
        assert_eq!(client.transfer.stats().buffered_bytes, 0);
        assert_eq!(client.transfer.stats().assembler_sessions, 0);
        assert!(
            client
                .finish_due(retry_deadline - Duration::from_millis(1), WALL_NOW)
                .unwrap()
                .is_none()
        );
        let install = client
            .finish_due(retry_deadline, WALL_NOW)
            .unwrap()
            .unwrap();
        assert_eq!(install.state().retained(), publisher_state.retained());
        assert!(install.commit().observed_remote_offer);
        assert_eq!(client.state().retained(), publisher_state.retained());
        assert_eq!(
            client.state().sync_state(),
            MembershipSyncState::Participating
        );
        assert_eq!(client.enrollment_floor, None);
        assert!(client.round.is_none());
    }
}
