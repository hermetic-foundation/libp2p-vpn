use super::*;
use libp2p::request_response::Behaviour;
use p2p_vpn::{
    runtime::{
        control::{self, ControlCapabilities, ControlCodec, ControlRequest},
        packet::{self, PacketCodec},
    },
    wire::Frame,
};

struct Fixture {
    sessions: MemberSessions,
    control: Behaviour<ControlCodec>,
    packet: Behaviour<PacketCodec>,
    now: Instant,
}

impl Fixture {
    fn new() -> Self {
        Self {
            sessions: MemberSessions::new(2),
            control: control::behaviour(4),
            packet: packet::behaviour(1500, 4),
            now: Instant::now(),
        }
    }

    fn request_capabilities(&mut self, binding: Binding) -> OutboundRequestId {
        let request = self.control.send_request(
            &binding.peer,
            ControlRequest::Capabilities(ControlCapabilities::local("mesh-test", None, 1500)),
        );
        assert!(self.sessions.expect_capabilities(binding, request));
        request
    }

    fn authorize(&mut self, binding: Binding, mtu: u16) -> OutboundRequestId {
        let request = self.request_capabilities(binding);
        assert!(self.sessions.finish_capabilities(
            binding,
            request,
            StreamMtu::negotiate(1500, mtu),
            self.now,
        ));
        request
    }

    fn probe_request(&mut self, binding: Binding) -> OutboundRequestId {
        self.packet
            .send_request(&binding.peer, Frame::keepalive(1, 1).unwrap())
    }
}

fn binding(peer: PeerId, connection: usize) -> Binding {
    Binding {
        peer,
        connection: ConnectionId::new_unchecked(connection),
    }
}

fn endpoints() -> (Binding, Binding, Binding) {
    let a = PeerId::random();
    let b = PeerId::random();
    (binding(a, 1), binding(a, 2), binding(b, 3))
}

#[test]
fn authorization_is_exact_and_two_members_keep_independent_mtu_and_capacity() {
    let mut f = Fixture::new();
    let (a, extra_a, b) = endpoints();
    let hop = binding(b.peer, 4);
    assert!(!f.sessions.attach(hop, Established::RelayHop));
    assert!(f.sessions.attach(a, Established::CircuitMember));
    assert!(f.sessions.attach(b, Established::DirectMember));
    assert!(!f.sessions.attach(extra_a, Established::DirectMember));
    assert!(
        !f.sessions
            .attach(binding(PeerId::random(), 5), Established::DirectMember)
    );
    assert!(
        !f.sessions
            .attach(binding(PeerId::random(), 1), Established::DirectMember)
    );

    let request_a = f.request_capabilities(a);
    let request_b = f.request_capabilities(b);
    let impostor = Binding { peer: b.peer, ..a };
    let mtu_a = StreamMtu::negotiate(1500, 1300);
    assert!(
        !f.sessions
            .finish_capabilities(impostor, request_a, mtu_a, f.now)
    );
    assert!(!f.sessions.finish_capabilities(a, request_b, mtu_a, f.now));
    assert!(!f.sessions.finish_capabilities(hop, request_b, mtu_a, f.now));
    assert!(f.sessions.outbound(a.peer).is_none());
    assert!(f.sessions.outbound(b.peer).is_none());
    assert!(f.sessions.awaits_capabilities(a, request_a, f.now));
    assert!(f.sessions.awaits_capabilities(b, request_b, f.now));
    assert!(f.sessions.finish_capabilities(a, request_a, mtu_a, f.now));
    assert!(!f.sessions.finish_capabilities(a, request_a, mtu_a, f.now));
    assert!(
        f.sessions
            .finish_capabilities(b, request_b, StreamMtu::negotiate(1500, 1420), f.now)
    );
    assert_eq!(f.sessions.outbound(a.peer).unwrap().mtu.get(), 1300);
    assert_eq!(f.sessions.outbound(b.peer).unwrap().mtu.get(), 1420);
    assert_eq!(f.sessions.inbound_mtu(a, f.now), mtu_a);
    assert!(f.sessions.inbound_mtu(hop, f.now).is_none());
    assert!(f.sessions.inbound_mtu(impostor, f.now).is_none());
    assert!(StreamMtu::negotiate(1500, MIN_IPV4_MTU - 1).is_none());
}

#[test]
fn reauthorization_gates_one_peer_and_retires_its_alternate_proofs() {
    let mut f = Fixture::new();
    let (a, candidate, b) = endpoints();
    assert!(f.sessions.attach(a, Established::CircuitMember));
    assert!(f.sessions.attach(b, Established::DirectMember));
    let stale = f.authorize(a, 1300);
    f.authorize(b, 1420);
    let b_before = f.sessions.outbound(b.peer);
    assert!(f.sessions.stage_direct(
        candidate,
        Established::DirectMember,
        a,
        f.now + Duration::from_secs(5)
    ));
    let candidate_request = f.request_capabilities(candidate);

    assert_eq!(f.sessions.require_reauthorization(a.peer), vec![candidate]);
    assert!(f.sessions.outbound(a.peer).is_none());
    assert!(f.sessions.inbound_mtu(a, f.now).is_none());
    assert_eq!(f.sessions.outbound(b.peer), b_before);
    let first_retry = f.request_capabilities(a);
    let retry = f.request_capabilities(a);
    let mtu = StreamMtu::negotiate(1500, 1200);
    assert!(
        !f.sessions
            .finish_capabilities(candidate, candidate_request, mtu, f.now)
    );
    assert!(!f.sessions.finish_capabilities(a, stale, mtu, f.now));
    assert!(!f.sessions.finish_capabilities(a, first_retry, mtu, f.now));
    assert!(f.sessions.finish_capabilities(a, retry, None, f.now));
    assert!(f.sessions.outbound(a.peer).is_none());
    assert!(!f.sessions.finish_capabilities(a, retry, mtu, f.now));
    f.authorize(a, 1200);
    assert_eq!(f.sessions.outbound(a.peer).unwrap().mtu, mtu.unwrap());
    assert_eq!(f.sessions.outbound(b.peer), b_before);
}

#[test]
fn handoff_promotes_only_the_exact_probed_candidate_and_drains_only_its_fallback() {
    let mut f = Fixture::new();
    let (a, candidate, b) = endpoints();
    assert!(f.sessions.attach(a, Established::CircuitMember));
    assert!(f.sessions.attach(b, Established::DirectMember));
    f.authorize(a, 1300);
    f.authorize(b, 1420);
    let b_before = f.sessions.outbound(b.peer);
    let deadline = f.now + Duration::from_secs(5);
    assert!(
        !f.sessions
            .stage_direct(candidate, Established::RelayHop, a, deadline)
    );
    assert!(
        !f.sessions
            .stage_direct(b, Established::DirectMember, a, deadline)
    );
    assert!(
        f.sessions
            .stage_direct(candidate, Established::DirectMember, a, deadline)
    );
    assert!(
        !f.sessions
            .stage_direct(binding(a.peer, 4), Established::DirectMember, a, deadline)
    );
    let probe = f.probe_request(candidate);
    assert!(!f.sessions.expect_probe(candidate, probe, f.now));
    f.authorize(candidate, 1300);
    assert!(f.sessions.expect_probe(candidate, probe, f.now));
    assert_eq!(f.sessions.outbound(a.peer).unwrap().binding, a);
    assert!(f.sessions.inbound_mtu(candidate, f.now).is_none());

    let wrong_request = f.probe_request(candidate);
    assert_eq!(
        f.sessions
            .finish_probe(candidate, wrong_request, true, f.now),
        ProbeOutcome::Ignored
    );
    assert_eq!(
        f.sessions.finish_probe(b, probe, true, f.now),
        ProbeOutcome::Ignored
    );
    assert_eq!(
        f.sessions.finish_probe(a, probe, true, f.now),
        ProbeOutcome::Ignored
    );
    assert_eq!(
        f.sessions.finish_probe(candidate, probe, true, f.now),
        ProbeOutcome::Promoted {
            draining: a,
            until: f.now + DRAIN_LIMIT
        }
    );
    assert_eq!(f.sessions.outbound(a.peer).unwrap().binding, candidate);
    assert_eq!(
        f.sessions.outbound(a.peer).unwrap().path,
        Established::DirectMember
    );
    assert_eq!(
        f.sessions.inbound_mtu(a, f.now),
        StreamMtu::negotiate(1500, 1300)
    );
    assert!(f.sessions.inbound_mtu(a, f.now + DRAIN_LIMIT).is_none());
    assert!(f.sessions.closed(a).is_empty());
    assert_eq!(f.sessions.outbound(a.peer).unwrap().binding, candidate);
    assert_eq!(f.sessions.outbound(b.peer), b_before);
}

#[test]
fn expired_or_rejected_probe_preserves_the_authorized_fallback() {
    for expired in [false, true] {
        let mut f = Fixture::new();
        let (a, candidate, _) = endpoints();
        assert!(f.sessions.attach(a, Established::CircuitMember));
        f.authorize(a, 1300);
        let deadline = f.now + Duration::from_secs(5);
        assert!(
            f.sessions
                .stage_direct(candidate, Established::DirectMember, a, deadline)
        );
        let request = f.request_capabilities(candidate);
        let mtu = StreamMtu::negotiate(1500, 1300);
        assert!(
            !f.sessions
                .finish_capabilities(candidate, request, mtu, deadline)
        );
        assert!(
            f.sessions
                .finish_capabilities(candidate, request, mtu, f.now)
        );
        let probe = f.probe_request(candidate);
        assert!(f.sessions.expect_probe(candidate, probe, f.now));
        let now = if expired { deadline } else { f.now };
        assert_eq!(
            f.sessions.finish_probe(candidate, probe, expired, now),
            ProbeOutcome::CloseCandidate(candidate)
        );
        assert_eq!(f.sessions.outbound(a.peer).unwrap().binding, a);
        assert!(f.sessions.inbound_mtu(candidate, now).is_none());
    }
}

#[test]
fn revocation_retires_only_the_matching_member_and_its_alternate() {
    for promoted in [false, true] {
        let mut f = Fixture::new();
        let (a, candidate, b) = endpoints();
        assert!(f.sessions.attach(a, Established::CircuitMember));
        assert!(f.sessions.attach(b, Established::DirectMember));
        f.authorize(a, 1300);
        f.authorize(b, 1420);
        let b_before = f.sessions.outbound(b.peer);
        assert!(f.sessions.stage_direct(
            candidate,
            Established::DirectMember,
            a,
            f.now + Duration::from_secs(5)
        ));
        f.authorize(candidate, 1300);
        let probe = f.probe_request(candidate);
        assert!(f.sessions.expect_probe(candidate, probe, f.now));
        if promoted {
            assert_eq!(
                f.sessions.finish_probe(candidate, probe, true, f.now),
                ProbeOutcome::Promoted {
                    draining: a,
                    until: f.now + DRAIN_LIMIT
                }
            );
        }
        assert!(f.sessions.closed(Binding { peer: b.peer, ..a }).is_empty());
        let mut removed = f.sessions.revoke(a.peer);
        removed.sort_unstable_by_key(|binding| binding.connection);
        assert_eq!(removed, [a, candidate]);
        assert!(f.sessions.outbound(a.peer).is_none());
        assert!(f.sessions.inbound_mtu(a, f.now).is_none());
        assert!(f.sessions.inbound_mtu(candidate, f.now).is_none());
        assert_eq!(
            f.sessions.finish_probe(candidate, probe, true, f.now),
            ProbeOutcome::Ignored
        );
        assert_eq!(f.sessions.outbound(b.peer), b_before);
        assert!(f.sessions.closed(b).is_empty());
        assert!(f.sessions.outbound(b.peer).is_none());
    }
}

#[test]
fn primary_close_discards_only_its_candidate_and_stale_events_cannot_touch_a_replacement() {
    let mut f = Fixture::new();
    let (a, candidate, b) = endpoints();
    assert!(f.sessions.attach(a, Established::CircuitMember));
    assert!(f.sessions.attach(b, Established::DirectMember));
    let stale = f.authorize(a, 1300);
    f.authorize(b, 1420);
    let sibling = f.sessions.outbound(b.peer);
    assert!(f.sessions.stage_direct(
        candidate,
        Established::DirectMember,
        a,
        f.now + Duration::from_secs(5)
    ));
    f.authorize(candidate, 1400);
    let probe = f.probe_request(candidate);
    assert!(!f.sessions.expect_probe(candidate, probe, f.now));
    assert_eq!(f.sessions.closed(a), vec![candidate]);

    let fresh = binding(a.peer, 5);
    assert!(f.sessions.attach(fresh, Established::DirectMember));
    let request = f.request_capabilities(fresh);
    let mtu = StreamMtu::negotiate(1500, 1250);
    assert!(!f.sessions.finish_capabilities(fresh, stale, mtu, f.now));
    assert!(f.sessions.closed(a).is_empty());
    assert!(f.sessions.finish_capabilities(fresh, request, mtu, f.now));
    assert_eq!(f.sessions.outbound(a.peer).unwrap().binding, fresh);
    assert_eq!(f.sessions.outbound(b.peer), sibling);
}
