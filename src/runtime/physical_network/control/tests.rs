//! Registry regressions using the Linux route backend.

use super::*;

#[test]
fn preferred_validation_suppresses_extra_attempts_and_scopes_do_not_clear_each_other() {
    let routes = ControlRoutes::new(16);
    let peer = PeerId::random();
    routes.set_network_fallback_peers([peer]);
    routes.mark_preferred_validation(PreferredValidation::Overlay, peer);
    assert!(!routes.network_fallback_allowed(Some(peer)));
    routes.mark_preferred_validation(PreferredValidation::Infrastructure, peer);
    routes.set_preferred_validation(PreferredValidation::Overlay, []);
    assert!(!routes.network_fallback_allowed(Some(peer)));
    routes.set_preferred_validation(PreferredValidation::Infrastructure, []);
    assert!(routes.network_fallback_allowed(Some(peer)));
    routes.set_preferred_validation(PreferredValidation::Overlay, [peer]);
    assert!(!routes.network_fallback_allowed(Some(peer)));
    routes.set_preferred_validation(PreferredValidation::Overlay, []);
    assert!(routes.network_fallback_allowed(Some(peer)));
}

#[test]
fn network_fallback_permission_is_explicit_replaced_and_instance_local() {
    let routes = ControlRoutes::new(16);
    let other = ControlRoutes::new(16);
    let peer = PeerId::random();
    let relay = PeerId::random();
    assert!(!routes.network_fallback_allowed(None));
    assert!(!routes.network_fallback_allowed(Some(peer)));
    routes.set_network_fallback_peers([peer]);
    assert!(routes.network_fallback_allowed(Some(peer)));
    assert!(!routes.network_fallback_allowed(Some(relay)));
    assert!(!other.network_fallback_allowed(Some(peer)));
    routes.allow_network_fallback_peer(relay);
    assert!(routes.network_fallback_allowed(Some(relay)));
    routes.set_network_fallback_peers([relay]);
    assert!(!routes.network_fallback_allowed(Some(peer)));
    routes.set_network_fallback_peers([]);
    assert!(!routes.network_fallback_allowed(Some(relay)));
    assert!(
        routes.snapshot().is_empty(),
        "eligibility creates no connection ownership"
    );
}

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
    let connection = ConnectionId::new_unchecked(23);
    assert!(routes.connection(peer, connection).is_none());
    first.bind_connection(connection).unwrap();
    first.adopt().unwrap();
    assert_eq!(routes.connection(peer, connection).unwrap().id, 1);
    assert!(routes.connection(PeerId::random(), connection).is_none());
    assert!(snapshot[0].is_adopted());
    assert_eq!(
        routes.register(peer, lease.clone()).err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    drop(first);
    assert!(!snapshot[0].is_live());
    assert!(!snapshot[0].is_adopted());
    assert!(routes.snapshot().is_empty());
    assert!(routes.connection(peer, connection).is_none());
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
    registration
        .bind_connection(ConnectionId::new_unchecked(23))
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

#[tokio::test]
async fn association_is_exact_nontransferable_and_required_before_adoption() {
    let routes = Arc::new(ControlRoutes::new(2));
    let peer = PeerId::random();
    let lease = lease(&routes).await;
    let first = routes.register(peer, lease.clone()).unwrap();
    let second = routes.register(peer, lease.clone()).unwrap();
    let a = ConnectionId::new_unchecked(17);
    let b = ConnectionId::new_unchecked(19);
    assert_eq!(
        first.adopt().unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    first.bind_connection(a).unwrap();
    first.bind_connection(a).unwrap();
    assert_eq!(
        first.bind_connection(b).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        second.bind_connection(a).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    first.adopt().unwrap();
    second.bind_connection(b).unwrap();
    second.adopt().unwrap();
    assert_ne!(
        routes.connection(peer, a).unwrap().id,
        routes.connection(peer, b).unwrap().id
    );
    let snapshot = routes.connection(peer, a).unwrap();
    drop(first);
    assert!(!snapshot.is_live());
    assert!(routes.connection(peer, a).is_none());
    assert!(routes.connection(peer, b).is_some());
    assert_eq!(snapshot.connection_id, Some(a));
    drop(second);
    assert!(routes.snapshot().is_empty());
}
