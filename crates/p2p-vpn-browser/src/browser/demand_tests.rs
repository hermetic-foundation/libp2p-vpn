use super::*;
use p2p_vpn::runtime::lifecycle::IDLE_AFTER;

#[test]
fn visibility_and_a_continuous_foreground_pump_are_required() {
    let start = Instant::now();
    let mut pump = Foreground::default();
    pump.poll(start, true);
    assert!(!pump.live(start, true));
    let next = start + Duration::from_millis(100);
    pump.poll(next, true);
    assert!(pump.live(next, true));
    assert!(!pump.live(next, false));
    let after_sleep = next + FOREGROUND_LEASE;
    assert!(!pump.live(after_sleep, true));
    pump.poll(after_sleep, true);
    assert!(!pump.live(after_sleep, true));
    pump.poll(after_sleep, false);
    pump.poll(after_sleep, true);
    assert!(!pump.live(after_sleep, true));
}

#[test]
fn admitted_idle_and_wake_are_versioned_and_bound_to_one_connection() {
    let now = Instant::now();
    let connection = ConnectionId::new_unchecked(1);
    let local = Epoch::new([1; 16]).unwrap();
    let remote = Epoch::new([2; 16]).unwrap();
    let peer = libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id();
    let scope = Scope {
        network_name: "demand-test".into(),
        membership_tag: None,
    };
    let ready = Readiness {
        incoming_path_available: true,
        outstanding_work: false,
    };
    let mut session = Negotiation {
        connection,
        scope: scope.clone(),
        local,
        remote,
        policy: PeerLifecycle::new(local, remote, true, now),
        advertised: true,
        confirmed: true,
        blocked: false,
        control: None,
        outbound: None,
        inbound: None,
        wake: None,
        offered: false,
        requests: [None; 4],
    };
    assert!(session.enabled_on(connection));
    assert!(!session.enabled_on(ConnectionId::new_unchecked(2)));

    let idle_at = now + IDLE_AFTER;
    let mut other = PeerLifecycle::new(remote, local, true, now);
    let offer = other.offer_idle(idle_at, ready).unwrap();
    let request = Request::idle(scope.clone(), offer);
    let (reply, ack) = session.receive(peer, &[], &request, ready, idle_at);
    assert!(matches!(reply, Reply::IdleAccepted { .. }));
    assert_ne!(session.policy.phase(), Phase::Dormant);
    session
        .policy
        .idle_reply_sent(ack.unwrap(), idle_at, ready)
        .unwrap();
    assert_eq!(session.policy.phase(), Phase::Dormant);
    session.application_demand(idle_at);
    let wake = session.wake.take().expect("local payload queues a wake");
    other.receive_wake(wake, idle_at, true).unwrap();
    assert_eq!(session.policy.phase(), Phase::Active);

    let reply = session.receive(peer, &[], &request, ready, idle_at).0;
    assert!(matches!(reply, Reply::Rejected { .. }));
    let remote_wake = Request::wake(scope, other.wake(idle_at, true).unwrap());
    assert!(matches!(
        session.receive(peer, &[], &remote_wake, ready, idle_at).0,
        Reply::WakeAccepted {}
    ));
    assert!(matches!(
        session.receive(peer, &[], &remote_wake, ready, idle_at).0,
        Reply::Rejected { .. }
    ));
    session.suspend(idle_at);
    assert!(!session.enabled_on(connection));
}
