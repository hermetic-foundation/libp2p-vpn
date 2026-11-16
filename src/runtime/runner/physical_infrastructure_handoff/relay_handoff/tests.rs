use super::*;
use crate::runtime::physical_network::linux::control::ControlRoutes;
use std::sync::Arc;

async fn candidate(peer: Libp2pPeerId, id: ConnectionId) -> Candidate {
    let owners = Arc::new(ControlRoutes::new(4));
    let (_, lease) = owners
        .egress
        .prepare_tcp("127.0.0.1:4001".parse().unwrap(), false, &[])
        .await
        .unwrap();
    Candidate {
        peer,
        id,
        epoch: lease.epoch(),
    }
}

#[tokio::test]
async fn reservation_attempts_are_bounded_across_candidate_replacement() {
    let peer = Libp2pPeerId::random();
    let mut candidate = candidate(peer, ConnectionId::new_unchecked(1)).await;
    let mut state = State::default();
    let address: Multiaddr = "/ip4/192.0.2.1/tcp/4001".parse().unwrap();
    let mut now = Instant::now();
    for index in 0..MAX_ATTEMPTS {
        candidate.id = ConnectionId::new_unchecked(usize::from(index) + 1);
        assert!(state.admit(&candidate, std::slice::from_ref(&address), now));
        state.failed(peer, now);
        assert!(!state.admit(&candidate, std::slice::from_ref(&address), now));
        now += Duration::from_secs(300);
    }
    now += Duration::from_secs(86400);
    assert!(!state.admit(&candidate, std::slice::from_ref(&address), now));
    let new_address = "/ip4/192.0.2.2/tcp/4001".parse().unwrap();
    assert!(state.admit(&candidate, &[address, new_address], now));
    assert_eq!(state.budgets.len(), 1);
}

#[tokio::test]
async fn exhausted_peer_budgets_have_a_fixed_admission_bound() {
    let mut candidate = candidate(Libp2pPeerId::random(), ConnectionId::new_unchecked(1)).await;
    let mut state = State::default();
    let now = Instant::now();
    let addresses = ["/ip4/192.0.2.1/tcp/4001".parse().unwrap()];
    for _ in 0..MAX_PEERS {
        candidate.peer = Libp2pPeerId::random();
        assert!(state.admit(&candidate, &addresses, now));
        state.failed(candidate.peer, now);
    }
    candidate.peer = Libp2pPeerId::random();
    assert!(!state.admit(&candidate, &addresses, now + Duration::from_secs(86400)));
    assert_eq!(state.budgets.len(), MAX_PEERS);
}

#[tokio::test]
async fn listener_loss_is_exact_and_preserves_pending_native_owner() {
    let peer = Libp2pPeerId::random();
    let other = Libp2pPeerId::random();
    let candidate = candidate(peer, ConnectionId::new_unchecked(2)).await;
    let old = Anchor {
        peer,
        connection: ConnectionId::new_unchecked(1),
        listener: ListenerId::next(),
    };
    let listener = ListenerId::next();
    let mut state = State::default();
    state.anchors.insert(peer, old.clone());
    state.moves.insert(
        peer,
        Move {
            candidate: candidate.clone(),
            listener,
            old: vec![old.clone()],
            required: IdentifiedServices {
                relay: true,
                ..Default::default()
            },
            configured: true,
            automatic: false,
            deadline: Instant::now(),
            failed: false,
        },
    );
    assert!(state.owns_listener(peer, listener));
    assert!(!state.owns_listener(other, listener));
    assert!(state.protects(peer, old.connection));
    assert!(state.protects(peer, candidate.id));
    assert!(!state.protects(other, candidate.id));
    state.listener_closed(ListenerId::next());
    assert!(!state.moves[&peer].failed);
    state.listener_closed(listener);
    assert!(state.moves[&peer].failed);
    assert!(
        state.protects(peer, candidate.id),
        "failure observation is not cancellation of native I/O"
    );
    assert_eq!(state.anchors[&peer].listener, old.listener);
    state.listener_closed(old.listener);
    assert!(!state.anchors.contains_key(&peer));
}
