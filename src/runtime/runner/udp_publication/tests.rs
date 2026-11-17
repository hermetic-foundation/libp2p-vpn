use super::*;

fn capabilities(endpoints: &[&str]) -> ControlCapabilities {
    ControlCapabilities::local("sources", None, 1280)
        .with_packet_endpoint_candidates(
            endpoints
                .iter()
                .map(|endpoint| (*endpoint).to_owned())
                .collect(),
        )
        .with_owned_udp_packet_plane(!endpoints.is_empty())
}

#[test]
fn publication_is_idempotent_and_withdraws_only_generated_sources() {
    let mut owner = Sources::default();
    let mut local = capabilities(&["203.0.113.1:4002", "configured.example:4002"]);
    let source = "192.0.2.1:4002".parse().unwrap();
    assert!(owner.reconcile(&mut local, [source], &[], &[], true, &[]));
    assert!(
        local
            .packet_endpoint_candidates
            .contains(&source.to_string())
    );
    for _ in 0..5 {
        assert!(
            !owner.reconcile(&mut local, [source], &[], &[], true, &[]),
            "unchanged sources must not reset capability ACKs"
        );
    }
    assert!(owner.reconcile(&mut local, [], &[], &[], true, &[]));
    assert_eq!(
        local.packet_endpoint_candidates,
        ["203.0.113.1:4002", "configured.example:4002"]
    );
    assert!(owner.injected.is_empty());
}

#[test]
fn concurrent_sources_and_explicit_overrides_do_not_overwrite_one_another() {
    let mut owner = Sources::default();
    let mut local = capabilities(&[]);
    let a: SocketAddr = "192.0.2.1:4002".parse().unwrap();
    let b = "[2001:db8::1]:4002".parse().unwrap();
    owner.reconcile(&mut local, [a, b, a], &[], &[], true, &[]);
    assert_eq!(owner.injected.len(), 2);
    owner.reconcile(&mut local, [b], &[a.to_string()], &[], true, &[]);
    assert!(local.packet_endpoint_candidates.contains(&a.to_string()));
    assert!(local.packet_endpoint_candidates.contains(&b.to_string()));
    owner.reconcile(&mut local, [], &[a.to_string()], &[], true, &[]);
    assert_eq!(local.packet_endpoint_candidates, [a.to_string()]);
}

#[test]
fn generated_sources_exclude_overlay_unspecified_multicast_and_nonportable_link_local() {
    let mut owner = Sources::default();
    let mut local = capabilities(&[]);
    let sources = [
        "0.0.0.0:4002",
        "224.0.0.251:4002",
        "[::]:4002",
        "[ff02::fb]:4002",
        "[fe80::1%2]:4002",
        "10.42.0.1:4002",
        "127.0.0.1:0",
    ];
    assert!(!owner.reconcile(
        &mut local,
        sources.map(|source| source.parse().unwrap()),
        &[],
        &[IpCidr::new("10.42.0.0".parse().unwrap(), 24).unwrap()],
        true,
        &[]
    ));
    assert!(local.packet_endpoint_candidates.is_empty());
    assert!(!local.supports_owned_udp_packet_plane);
}

#[test]
fn source_bound_and_iteration_order_do_not_churn_publication() {
    let mut owner = Sources::default();
    let mut local = capabilities(&[]);
    let sources = (1..=96)
        .map(|port| SocketAddr::from(([192, 0, 2, 1], port)))
        .collect::<Vec<_>>();
    assert!(owner.reconcile(&mut local, sources.iter().copied(), &[], &[], true, &[]));
    assert_eq!(owner.injected.len(), MAX_GENERATED_SOURCES);
    let published = local.clone();
    assert!(!owner.reconcile(&mut local, sources.into_iter().rev(), &[], &[], true, &[]));
    assert_eq!(published, local);
    owner.reconcile(&mut local, [], &[], &[], false, &[]);
    assert!(!local.supports_owned_udp_packet_plane);
    assert!(owner.injected.is_empty());
}

#[test]
fn surviving_fallback_retains_only_existing_alias_until_its_original_owner_expires() {
    let mut owner = Sources::default();
    let mut local = capabilities(&[]);
    let old: SocketAddr = "192.0.2.1:4002".parse().unwrap();
    let preferred = "[2001:db8::1]:4002".parse().unwrap();
    owner.reconcile(&mut local, [old], &[], &[], true, &[]);
    let before = local.clone();
    assert!(!owner.reconcile(&mut local, [], &[], &[], true, &[old]));
    assert_eq!(
        local, before,
        "preference churn must not withdraw usable fallback"
    );
    owner.reconcile(&mut local, [preferred], &[], &[], true, &[old]);
    assert!(local.packet_endpoint_candidates.contains(&old.to_string()));
    owner.reconcile(&mut local, [preferred], &[], &[], true, &[]);
    assert_eq!(local.packet_endpoint_candidates, [preferred.to_string()]);
    let unknown: SocketAddr = "192.0.2.9:4002".parse().unwrap();
    assert!(!owner.reconcile(&mut local, [preferred], &[], &[], true, &[unknown]));
    assert!(
        !local
            .packet_endpoint_candidates
            .contains(&unknown.to_string()),
        "retained evidence cannot publish a new source"
    );
}

#[test]
fn retained_fallbacks_share_the_existing_hard_publication_bound() {
    let mut owner = Sources::default();
    let mut local = capabilities(&[]);
    let retained = (1..=32)
        .map(|port| SocketAddr::from(([192, 0, 2, 1], port)))
        .collect::<Vec<_>>();
    owner.reconcile(&mut local, retained.iter().copied(), &[], &[], true, &[]);
    let extra = (33..=96).map(|port| SocketAddr::from(([192, 0, 2, 1], port)));
    owner.reconcile(&mut local, extra, &[], &[], true, &retained);
    assert_eq!(owner.injected.len(), MAX_GENERATED_SOURCES);
    assert_eq!(
        local.packet_endpoint_candidates.len(),
        MAX_GENERATED_SOURCES
    );
}
