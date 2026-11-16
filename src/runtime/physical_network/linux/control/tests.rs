use super::*;

async fn lease(routes: &ControlRoutes) -> RouteLease {
    let (_, lease) = routes
        .egress
        .prepare_tcp("127.0.0.1:4001".parse().unwrap(), false, &[])
        .await
        .unwrap();
    lease
}

#[tokio::test]
async fn registrations_are_exact_bounded_and_snapshots_do_not_retain_liveness() {
    let routes = Arc::new(ControlRoutes::new(1));
    let peer = PeerId::random();
    let lease = lease(&routes).await;
    let first = routes.register(peer, lease.clone()).unwrap();
    let snapshot = routes.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].peer, peer);
    assert_eq!(snapshot[0].id, 1);
    assert!(snapshot[0].is_live());
    assert!(!snapshot[0].is_adopted());
    first.adopt().unwrap();
    assert!(snapshot[0].is_adopted());
    assert_eq!(
        routes.register(peer, lease.clone()).err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    drop(first);
    assert!(!snapshot[0].is_live());
    assert!(!snapshot[0].is_adopted());
    assert!(routes.snapshot().is_empty());
    let second = routes.register(peer, lease).unwrap();
    assert_eq!(routes.snapshot()[0].id, 2);
    drop(second);
    assert!(routes.snapshot().is_empty());
}

#[tokio::test]
async fn stale_routes_and_identifier_exhaustion_never_register() {
    let routes = Arc::new(ControlRoutes::new(1));
    let peer = PeerId::random();
    let mut stale = lease(&routes).await;
    let current = stale.clone();
    stale.route.generation = 0;
    assert_eq!(
        routes.register(peer, stale).err().unwrap().kind(),
        io::ErrorKind::Interrupted
    );
    routes.state.lock().unwrap().next = u64::MAX;
    assert!(routes.register(peer, current).is_err());
    assert!(routes.snapshot().is_empty());
    assert_eq!(routes.state.lock().unwrap().next, u64::MAX);
}

#[tokio::test]
async fn route_changed_after_authentication_cannot_be_adopted() {
    let routes = Arc::new(ControlRoutes::new(1));
    let registration = routes
        .register(PeerId::random(), lease(&routes).await)
        .unwrap();
    let snapshot = routes.snapshot();
    routes
        .state
        .lock()
        .unwrap()
        .routes
        .get_mut(&registration.id)
        .unwrap()
        .lease
        .route
        .generation = 0;
    assert_eq!(
        registration.adopt().unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert!(!snapshot[0].is_adopted());
    drop(registration);
    assert!(!snapshot[0].is_live());
    assert!(routes.snapshot().is_empty());
}
