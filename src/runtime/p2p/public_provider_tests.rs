//! Loopback protocol evidence, not certification against a deployed Go DHT.

use super::*;
use futures::StreamExt as _;
use libp2p::{kad::store::RecordStore as _, swarm::SwarmEvent};

type TestSwarm = Swarm<kad::Behaviour<kad::store::MemoryStore>>;

fn node(server: bool) -> TestSwarm {
    SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|key: &Keypair| {
            let peer = key.public().to_peer_id();
            let mut config =
                controlled_kademlia_config(StreamProtocol::new(PUBLIC_IPFS_KADEMLIA_PROTOCOL));
            config.set_record_filtering(kad::StoreInserts::FilterBoth);
            let mut kad =
                kad::Behaviour::with_config(peer, kad::store::MemoryStore::new(peer), config);
            kad.set_mode(Some(if server {
                kad::Mode::Server
            } else {
                kad::Mode::Client
            }));
            kad
        })
        .unwrap()
        .build()
}

async fn listen(swarm: &mut TestSwarm) -> Multiaddr {
    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            swarm.add_external_address(address.clone());
            return address;
        }
    }
}

#[tokio::test]
async fn provider_publication_withdraws_relay_aliases_without_losing_direct_address() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut server = node(true);
        let mut publisher = node(false);
        let server_address = listen(&mut server).await;
        let direct = listen(&mut publisher).await;
        let member = *publisher.local_peer_id();
        let relay = PeerId::random();
        let [v4, v6] = ["/ip4/11.251.0.254/tcp/42200", "/ip6/2001:db9::fe/tcp/42200"].map(|addr| {
            format!("{addr}/p2p/{relay}/p2p-circuit/p2p/{member}")
                .parse::<Multiaddr>()
                .unwrap()
        });
        // Keep the old external entry to model a stale swarm address.
        publisher.add_external_address(v4.clone());
        publisher
            .behaviour_mut()
            .add_address(server.local_peer_id(), server_address);
        for (index, live) in [vec![v4.clone(), v6.clone()], vec![v6], vec![]]
            .into_iter()
            .enumerate()
        {
            let key = kad::RecordKey::new(&[u8::try_from(index).unwrap()]);
            let mut entries = live.clone();
            entries.extend(live.first().cloned());
            entries.push(direct.clone());
            publisher
                .behaviour_mut()
                .set_live_provider_relay_addresses(entries);
            publisher
                .behaviour_mut()
                .start_providing(key.clone())
                .unwrap();
            let advertised = loop {
                tokio::select! {
                    _ = publisher.select_next_some() => {},
                    event = server.select_next_some() => {
                        if let SwarmEvent::Behaviour(kad::Event::InboundRequest {
                            request: kad::InboundRequest::AddProvider { record: Some(record) },
                        }) = event {
                            assert_eq!(record.key, key);
                            assert_eq!(record.provider, member);
                            break record.addresses;
                        }
                    }
                }
            };
            let mut expected = live;
            expected.push(direct.clone().with_p2p(member).unwrap());
            assert_eq!(advertised, expected);
        }
    })
    .await
    .expect("provider alias publication fixture exceeded 10 seconds");
}

#[tokio::test]
async fn public_server_rejects_oversized_provider_and_serves_bounded_replacement() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut server = node(true);
        let mut publisher = node(false);
        let mut seeker = node(false);
        let server_address = listen(&mut server).await;
        let publisher_address = listen(&mut publisher).await;
        let server_peer = *server.local_peer_id();
        let publisher_peer = *publisher.local_peer_id();
        publisher.behaviour_mut().add_address(&server_peer, server_address.clone());
        seeker.behaviour_mut().add_address(&server_peer, server_address);

        let tag = crate::config::membership_tag("personal-devices", b"fixture");
        let legacy = kademlia_rendezvous_key("personal-devices", Some(&tag));
        let bounded = kademlia_provider_wire_key(publisher.behaviour(), &legacy);
        assert_eq!(legacy.as_ref().len(), 90);
        assert_eq!(bounded.as_ref().len(), 34);

        for key in [&legacy, &bounded] {
            publisher.behaviour_mut().try_start_providing(key.clone()).unwrap().unwrap();
            loop {
                tokio::select! {
                    _ = publisher.select_next_some() => {},
                    event = server.select_next_some() => {
                        if let SwarmEvent::Behaviour(kad::Event::InboundRequest {
                            request: kad::InboundRequest::AddProvider { record: Some(record) },
                        }) = event {
                            assert_eq!(&record.key, key);
                            assert_eq!(record.provider, publisher_peer);
                            // Mirror Go's provider-key limit at storage admission.
                            if !record.key.as_ref().is_empty() && record.key.as_ref().len() <= 80 {
                                server.behaviour_mut().store_mut().add_provider(record).unwrap();
                            }
                            break;
                        }
                    }
                }
            }
        }
        assert!(server.behaviour_mut().store_mut().providers(&legacy).is_empty());
        assert_eq!(server.behaviour_mut().store_mut().providers(&bounded).len(), 1);

        let lookup = seeker.behaviour_mut().try_get_providers(bounded.clone()).unwrap();
        loop {
            tokio::select! {
                _ = publisher.select_next_some() => {},
                _ = server.select_next_some() => {},
                event = seeker.select_next_some() => {
                    if let SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders { key, providers })),
                        ..
                    }) = event {
                        assert_eq!(id, lookup);
                        assert_eq!(key, bounded);
                        assert!(providers.contains(&publisher_peer));
                        break;
                    }
                }
            }
        }
        let expected_address = publisher_address.with_p2p(publisher_peer).unwrap();
        assert!(server.behaviour_mut().store_mut().providers(&bounded)[0].addresses.contains(&expected_address));
    }).await.expect("provider interoperability fixture exceeded 20 seconds");
}
