use super::*;

async fn fixture() -> (PacketPlaneRuntime, SocketAddr, PeerId) {
    let mut runtime = PacketPlaneRuntime::bind(vec!["127.0.0.1:0".parse().unwrap()])
        .await
        .unwrap();
    runtime.follow_physical_routes("absent-pv".into());
    let destination = "127.0.0.1:45000".parse().unwrap();
    (
        runtime,
        destination,
        PeerId::from_libp2p(Libp2pPeerId::random()),
    )
}

#[tokio::test]
async fn repeated_requests_keep_one_preparation_and_ready_owner() {
    let (runtime, destination, peer) = fixture().await;
    let mut queue = Preparations::default();
    assert!(
        queue
            .get_or_start(peer, Role::Initiator, destination, || runtime
                .udp_preparation(peer, destination, false))
            .unwrap()
            .is_none()
    );
    for _ in 0..8 {
        assert!(
            queue
                .get_or_start(peer, Role::Initiator, destination, || panic!(
                    "must not start another source lookup"
                ))
                .unwrap()
                .is_none()
        );
    }
    let completion = queue.tasks.join_next().await.unwrap().unwrap();
    assert!(queue.finish(completion).unwrap().result.is_ok());
    let ready = queue
        .get_or_start(peer, Role::Initiator, destination, || {
            panic!("must reuse completed preparation")
        })
        .unwrap()
        .unwrap();
    assert!(ready.is_current());
    assert_eq!(queue.entries.len(), 1);
    assert!(queue.tasks.is_empty());
    queue.expire(Instant::now() + PACKET_PLANE_PENDING_HELLO_TIMEOUT);
    assert!(!ready.is_current());
    assert!(queue.entries.is_empty());
}

#[tokio::test]
async fn stale_completions_cannot_replace_a_new_generation_or_outlive_cancellation() {
    let (runtime, destination, peer) = fixture().await;
    let mut queue = Preparations::default();
    queue
        .get_or_start(peer, Role::Initiator, destination, || {
            runtime.udp_preparation(peer, destination, false)
        })
        .unwrap();
    let old = queue.tasks.join_next().await.unwrap().unwrap();
    queue.cancel_peer(peer);
    queue
        .get_or_start(peer, Role::Initiator, destination, || {
            runtime.udp_preparation(peer, destination, false)
        })
        .unwrap();
    assert!(queue.finish(old).is_none());
    assert!(queue.entries[&(peer, Role::Initiator)].ready.is_none());
    let fresh = queue.tasks.join_next().await.unwrap().unwrap();
    queue
        .entries
        .get_mut(&(peer, Role::Initiator))
        .unwrap()
        .started -= PACKET_PLANE_PENDING_HELLO_TIMEOUT;
    assert!(queue.finish(fresh).unwrap().result.is_err());
    assert!(queue.entries.is_empty());
}

#[tokio::test]
async fn global_preparation_bound_is_checked_before_invoking_a_new_factory() {
    let (runtime, destination, _) = fixture().await;
    let mut queue = Preparations::default();
    for _ in 0..CAPACITY {
        let peer = PeerId::from_libp2p(Libp2pPeerId::random());
        queue
            .get_or_start(peer, Role::Initiator, destination, || {
                runtime.udp_preparation(peer, destination, false)
            })
            .unwrap();
    }
    assert_eq!(
        queue
            .get_or_start(
                PeerId::from_libp2p(Libp2pPeerId::random()),
                Role::Responder,
                destination,
                || panic!("capacity rejection must precede socket work")
            )
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    queue.clear();
    while queue.tasks.join_next().await.is_some() {}
    assert!(queue.entries.is_empty());
}

#[test]
fn signed_destination_retargeting_is_bounded_and_does_not_cycle() {
    let mut queue = Preparations::default();
    let peer = PeerId::from_libp2p(Libp2pPeerId::random());
    let endpoints: Vec<SocketAddr> = (1..=4)
        .map(|port| SocketAddr::new("127.0.0.1".parse().unwrap(), port))
        .collect();
    assert!(queue.retarget(peer, endpoints[0], endpoints[1]));
    let deadline = queue.destinations[&peer].deadline;
    assert!(queue.retarget(peer, endpoints[1], endpoints[2]));
    assert!(!queue.retarget(peer, endpoints[2], endpoints[0]));
    assert!(!queue.retarget(peer, endpoints[2], endpoints[3]));
    assert_eq!(queue.destination(peer), Some(endpoints[2]));
    assert_eq!(queue.destinations[&peer].deadline, deadline);
    queue.forget(peer);
    assert_eq!(queue.destination(peer), None);
}

#[tokio::test]
async fn crossed_hello_transfers_work_without_revocation_or_deadline_renewal() {
    let (runtime, destination, peer) = fixture().await;
    let mut queue = Preparations::default();
    queue
        .get_or_start(peer, Role::Initiator, destination, || {
            runtime.udp_preparation(peer, destination, false)
        })
        .unwrap();
    let old_completion = queue.tasks.join_next().await.unwrap().unwrap();
    let (work, started) = queue.take_initiator(peer, destination).unwrap();
    let observer = work.clone();
    assert!(observer.is_current());
    assert!(!queue.contains_current(peer, Role::Initiator));
    queue
        .get_or_start(peer, Role::Responder, destination, || Ok(work))
        .unwrap();
    queue.inherit_started(peer, Role::Responder, started);
    assert!(queue.finish(old_completion).is_none());
    let completion = queue.tasks.join_next().await.unwrap().unwrap();
    assert!(queue.finish(completion).unwrap().result.is_ok());
    assert!(observer.is_current());
    assert_eq!(queue.entries[&(peer, Role::Responder)].started, started);
    queue.expire(started + PACKET_PLANE_PENDING_HELLO_TIMEOUT);
    assert!(!observer.is_current());
    assert!(queue.entries.is_empty());
}

#[test]
fn dns_waits_are_bounded_and_repeated_requests_do_not_extend_the_deadline() {
    let mut negotiator = PacketPlaneNegotiator::default();
    let peer = PeerId::from_libp2p(Libp2pPeerId::random());
    assert!(negotiator.wait_for_dns(peer));
    let started = negotiator.dns_waiters[&peer].started;
    assert!(negotiator.wait_for_dns(peer));
    assert_eq!(negotiator.dns_waiters[&peer].started, started);
    for _ in 1..PACKET_DNS_WAIT_CAPACITY {
        assert!(negotiator.wait_for_dns(PeerId::from_libp2p(Libp2pPeerId::random())));
    }
    assert!(!negotiator.wait_for_dns(PeerId::from_libp2p(Libp2pPeerId::random())));
    assert_eq!(negotiator.dns_waiters.len(), PACKET_DNS_WAIT_CAPACITY);
    negotiator.expire_dns(Instant::now() + PACKET_PLANE_PENDING_HELLO_TIMEOUT);
    assert!(negotiator.dns_waiters.is_empty());
    assert!(negotiator.wait_for_dns(peer));
    negotiator.cancel_pending_for_peer(peer);
    assert!(negotiator.dns_waiters.is_empty());
}

#[tokio::test]
async fn dns_to_source_transition_preserves_original_deadline_and_revocation_cleans_dns_only_peer()
{
    let (mut runtime, destination, peer) = fixture().await;
    let mut negotiator = PacketPlaneNegotiator::default();
    assert!(negotiator.wait_for_dns(peer));
    let started = negotiator.dns_waiters[&peer].started;
    negotiator
        .udp_preparations
        .get_or_start(peer, Role::Responder, destination, || {
            runtime.udp_preparation(peer, destination, false)
        })
        .unwrap();
    negotiator.finish_dns_wait(peer);
    assert!(negotiator.dns_waiters.is_empty());
    assert_eq!(
        negotiator
            .udp_preparations
            .started_at(peer, Role::Responder),
        Some(started)
    );
    assert!(negotiator.wait_for_dns(peer));
    assert_eq!(negotiator.dns_waiters[&peer].started, started);
    negotiator.cancel_pending_for_peer(peer);
    while negotiator
        .udp_preparations
        .tasks
        .join_next()
        .await
        .is_some()
    {}
    assert!(negotiator.udp_preparations.entries.is_empty());

    assert!(negotiator.wait_for_dns(peer));
    let identity = NodeIdentity::generate_ed25519().unwrap();
    let mut config = super::super::tests::config_with_peer(&identity, Libp2pPeerId::random());
    config.peers.clear();
    let forwarder = Forwarder::from_config(&config).unwrap();
    assert_eq!(
        reconcile_packet_plane_authorization(
            &forwarder,
            &mut runtime,
            None,
            &mut negotiator,
            &mut PathSet::default(),
            &mut PathProbeTracker::default(),
        ),
        1
    );
    assert!(negotiator.dns_waiters.is_empty());
}
