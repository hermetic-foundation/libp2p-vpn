use super::*;

#[test]
fn unmanaged_runtime_has_no_route_observer() {
    let runtime = PacketPlaneRuntime::disabled();
    assert!(Reconciler::new(&runtime).is_none());
    assert!(!runtime.route_refresh_needed(PeerId::from_libp2p(libp2p::PeerId::random())));
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    async fn fixture(prepared: usize) -> (PacketPlaneRuntime, PeerId) {
        let mut runtime = PacketPlaneRuntime::bind(vec!["127.0.0.1:0".parse().unwrap(); 2])
            .await
            .unwrap();
        runtime.follow_physical_routes("absent-pv".into());
        let local_identity = NodeIdentity::generate_ed25519().unwrap();
        let remote_identity = NodeIdentity::generate_ed25519().unwrap();
        let secret = PacketPlaneEphemeralSecret::generate();
        let remote_secret = PacketPlaneEphemeralSecret::generate();
        let handshake =
            |kind, identity: &NodeIdentity, secret: &PacketPlaneEphemeralSecret, id, endpoint| {
                PacketPlaneHandshake::signed(
                    kind,
                    identity,
                    PacketPlaneHandshakeParams {
                        network_name: "lab".into(),
                        session_id: id,
                        nonce: u64::from(id),
                        mtu: 1280,
                        ephemeral_public_key: secret.public_key(),
                        endpoint,
                    },
                )
                .unwrap()
                .verify("lab", None)
                .unwrap()
            };
        let hello = handshake(
            PacketPlaneHandshakeKind::Hello,
            &local_identity,
            &secret,
            1,
            runtime.primary_listener().unwrap(),
        );
        let accept = handshake(
            PacketPlaneHandshakeKind::Accept,
            &remote_identity,
            &remote_secret,
            2,
            "127.0.0.1:49001".parse().unwrap(),
        );
        runtime
            .establish_session(PacketPlaneSessionRole::Initiator, &secret, &hello, &accept)
            .unwrap();
        let routes = &runtime.udp_routes[&accept.peer];
        for listener in 0..prepared {
            let path = udp_path::Route::prepare(
                &runtime.sockets[listener],
                runtime.udp_owner.as_ref().unwrap(),
                accept.endpoint,
                None,
            )
            .await
            .unwrap();
            routes.sockets[listener].path.set(path).unwrap();
        }
        (runtime, accept.peer)
    }

    async fn decisions(
        reconciler: &mut Reconciler,
        runtime: &mut PacketPlaneRuntime,
    ) -> Vec<reconcile::Decision> {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                match reconciler.next().await.unwrap() {
                    Event::Snapshot => {
                        assert!(reconciler.apply(Event::Snapshot, runtime).is_empty());
                    }
                    Event::Checked(decisions) => return decisions,
                    Event::Unavailable => panic!("route observer unavailable"),
                }
            }
        })
        .await
        .expect("bounded local UDP route audit")
    }

    #[tokio::test]
    async fn only_prepared_active_session_slots_enter_route_audits() {
        let (mut runtime, peer) = fixture(1).await;
        let routes = Arc::clone(&runtime.udp_routes[&peer]);
        let targets = runtime.udp_route_targets();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].peer, peer);
        assert_eq!(targets[0].connection_id, 0);
        assert!(Arc::ptr_eq(&targets[0].token, &routes.token));
        assert_eq!(
            targets[0].destination,
            routes.sockets[0]
                .path
                .get()
                .unwrap()
                .lease
                .context
                .destination
        );
        let mut reconciler = Reconciler::new(&runtime).unwrap();
        let mut checked = decisions(&mut reconciler, &mut runtime).await;
        assert_eq!(checked.len(), 1);
        let mut decision = checked.pop().unwrap();
        decision.replace = true;
        for mismatch in 0..4 {
            let mut wrong = decision.clone();
            match mismatch {
                0 => wrong.connection_id = 1,
                1 => wrong.connection_id = usize::MAX,
                2 => wrong.token = Arc::new(()),
                _ => wrong.destination.set_port(49002),
            }
            assert!(
                reconciler
                    .apply(Event::Checked(vec![wrong]), &mut runtime)
                    .is_empty()
            );
            assert!(runtime.udp_route_refresh.is_empty());
        }
        runtime.sessions.remove(&peer);
        assert!(runtime.udp_route_targets().is_empty());
        assert!(
            reconciler
                .apply(Event::Checked(vec![decision]), &mut runtime)
                .is_empty()
        );
        assert!(runtime.udp_route_refresh.is_empty());
    }

    #[tokio::test]
    async fn sibling_listener_results_cannot_clear_another_listener_refresh() {
        let (mut runtime, peer) = fixture(2).await;
        let mut reconciler = Reconciler::new(&runtime).unwrap();
        let mut checked = decisions(&mut reconciler, &mut runtime).await;
        checked.sort_by_key(|decision| decision.connection_id);
        assert_eq!(checked.len(), 2);
        checked[0].replace = true;
        checked[1].replace = false;
        assert_eq!(
            reconciler.apply(Event::Checked(checked.clone()), &mut runtime),
            vec![peer]
        );
        assert!(runtime.route_refresh_needed(peer));
        assert!(runtime.udp_route_refresh.contains_key(&(peer, 0)));
        assert!(!runtime.udp_route_refresh.contains_key(&(peer, 1)));
        assert!(
            reconciler
                .apply(Event::Checked(checked.clone()), &mut runtime)
                .is_empty()
        );
        checked[1].replace = true;
        assert_eq!(
            reconciler.apply(Event::Checked(checked.clone()), &mut runtime),
            vec![peer]
        );
        checked[0].replace = false;
        assert!(
            reconciler
                .apply(Event::Checked(checked.clone()), &mut runtime)
                .is_empty()
        );
        assert!(runtime.route_refresh_needed(peer));
        assert!(!runtime.udp_route_refresh.contains_key(&(peer, 0)));
        assert!(runtime.udp_route_refresh.contains_key(&(peer, 1)));
        assert!(
            reconciler
                .apply(Event::Unavailable, &mut runtime)
                .is_empty()
        );
        assert!(runtime.route_refresh_needed(peer));
        checked[1].replace = false;
        assert!(
            reconciler
                .apply(Event::Checked(checked.clone()), &mut runtime)
                .is_empty()
        );
        assert!(!runtime.route_refresh_needed(peer));
        for decision in &mut checked {
            decision.replace = true;
        }
        assert_eq!(
            reconciler.apply(Event::Checked(checked), &mut runtime),
            vec![peer],
            "one peer notification per audit batch"
        );
        assert_eq!(runtime.udp_route_refresh.len(), 2);
    }

    #[tokio::test]
    async fn renewing_session_token_fences_old_checks_and_refresh_flags() {
        let (mut runtime, peer) = fixture(1).await;
        let mut reconciler = Reconciler::new(&runtime).unwrap();
        let mut checked = decisions(&mut reconciler, &mut runtime).await;
        let mut decision = checked.pop().unwrap();
        decision.replace = true;
        assert_eq!(
            reconciler.apply(Event::Checked(vec![decision.clone()]), &mut runtime),
            vec![peer]
        );
        let old = runtime
            .udp_routes
            .insert(peer, udp_path::Routes::new(2))
            .unwrap();
        assert!(!runtime.route_refresh_needed(peer));
        assert!(
            reconciler
                .apply(Event::Checked(vec![decision]), &mut runtime)
                .is_empty()
        );
        assert!(!runtime.route_refresh_needed(peer));
        assert!(reconciler.apply(Event::Snapshot, &mut runtime).is_empty());
        assert!(runtime.udp_route_refresh.is_empty());
        assert!(
            old.sockets[0].path.get().is_some(),
            "audit must not mutate old owners"
        );
    }

    #[tokio::test]
    async fn stale_observer_decision_cannot_request_session_refresh() {
        let (mut runtime, peer) = fixture(1).await;
        let mut reconciler = Reconciler::new(&runtime).unwrap();
        let mut checked = decisions(&mut reconciler, &mut runtime).await;
        let mut decision = checked.pop().unwrap();
        decision.replace = true;
        runtime
            .udp_owner
            .as_ref()
            .unwrap()
            .retire_observer_for_test();
        assert!(!decision.is_current());
        assert!(
            reconciler
                .apply(Event::Checked(vec![decision]), &mut runtime)
                .is_empty()
        );
        assert!(!runtime.route_refresh_needed(peer));
        assert!(runtime.udp_route_refresh.is_empty());
    }
}
