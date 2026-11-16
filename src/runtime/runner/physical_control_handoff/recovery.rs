//! Renew bounded attempts only for new inputs, never for elapsed time alone.

use super::*;
use crate::runtime::lifecycle::activity::DemandVersion;

pub(super) const MAX_ADDRESSES: usize = 16;

#[derive(Default)]
pub(in crate::runtime::runner) struct Recovery {
    addresses: Vec<Multiaddr>,
    demand: Option<DemandVersion>,
    retry_at: Option<Instant>,
    rounds: u8,
    cursor: usize,
}

impl Recovery {
    pub(in crate::runtime::runner) fn ready(&self, now: Instant) -> bool {
        self.retry_at.is_some_and(|at| now >= at)
    }

    pub(in crate::runtime::runner) fn exhaust(&mut self, now: Instant) -> Duration {
        let delay = Duration::from_secs((60_u64 << self.rounds.min(3)).min(300));
        self.retry_at = Some(now + delay);
        delay
    }

    pub(in crate::runtime::runner) fn rearm(
        &mut self,
        addresses: &[Multiaddr],
        demand: Option<DemandVersion>,
        now: Instant,
    ) -> Option<&'static str> {
        if !self.ready(now) || addresses.is_empty() {
            return None;
        }
        let new_address = addresses
            .iter()
            .position(|address| !self.addresses.contains(address));
        let reason = if demand.is_some() && demand != self.demand {
            "application_demand"
        } else if new_address.is_some() {
            "new_address"
        } else {
            return None;
        };
        if let Some(index) = new_address {
            self.cursor = index;
        }
        self.retry_at = None;
        self.rounds = self.rounds.saturating_add(1).min(3);
        Some(reason)
    }

    pub(in crate::runtime::runner) fn attempt(
        &mut self,
        mut addresses: Vec<Multiaddr>,
        demand: Option<DemandVersion>,
    ) -> Option<Multiaddr> {
        addresses.truncate(MAX_ADDRESSES);
        let index = self.cursor % addresses.len().max(1);
        let selected = addresses.get(index).cloned();
        self.cursor = (index + 1) % addresses.len().max(1);
        self.addresses = addresses;
        self.demand = demand;
        selected
    }
}

pub(super) fn demand(forwarder: &Forwarder, peer: Libp2pPeerId) -> Option<DemandVersion> {
    forwarder
        .application_demand(PeerId::from_libp2p(peer))
        .filter(|snapshot| snapshot.last_demand.is_some())
        .and_then(|snapshot| snapshot.version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::lifecycle::activity::ApplicationDemand;

    fn addresses(count: u16) -> Vec<Multiaddr> {
        (0..count)
            .map(|index| {
                format!("/ip4/192.0.2.1/tcp/{}", 4000 + index)
                    .parse()
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn elapsed_time_removals_and_reordering_cannot_rearm_idle_work() {
        let mut recovery = Recovery::default();
        let now = Instant::now();
        let addresses = addresses(3);
        recovery.attempt(addresses.clone(), None);
        assert_eq!(recovery.exhaust(now), Duration::from_secs(60));
        assert!(!recovery.ready(now));
        assert!(
            recovery
                .rearm(&addresses, None, now + Duration::from_secs(59))
                .is_none()
        );
        let later = now + Duration::from_secs(86400);
        assert!(recovery.ready(later));
        assert!(recovery.rearm(&addresses, None, later).is_none());
        assert!(recovery.rearm(&addresses[..1], None, later).is_none());
        let mut reordered = addresses;
        reordered.reverse();
        assert!(recovery.rearm(&reordered, None, later).is_none());
    }

    #[test]
    fn fresh_application_demand_is_coalesced_and_cooldown_grows_to_a_bound() {
        let peer = PeerId::from_libp2p(Libp2pPeerId::random());
        let mut now = Instant::now();
        let demand = ApplicationDemand::new([peer], now);
        let mut recovery = Recovery::default();
        let addresses = addresses(1);
        recovery.attempt(addresses.clone(), None);
        for seconds in [60, 120, 240, 300, 300] {
            let delay = recovery.exhaust(now);
            assert_eq!(delay, Duration::from_secs(seconds));
            demand.record(peer, now);
            let version = demand.snapshot(peer).unwrap().version;
            assert!(version.is_some());
            assert!(recovery.rearm(&addresses, version, now).is_none());
            now += delay;
            assert_eq!(
                recovery.rearm(&addresses, version, now),
                Some("application_demand")
            );
            assert!(!recovery.ready(now));
            recovery.attempt(addresses.clone(), version);
            let ready = now + recovery.exhaust(now);
            assert!(
                recovery.rearm(&addresses, version, ready).is_none(),
                "consumed demand is not new work"
            );
        }
    }

    #[test]
    fn genuinely_new_addresses_rearm_and_are_tried_before_old_failures() {
        let mut recovery = Recovery::default();
        let now = Instant::now();
        let old = addresses(3);
        recovery.attempt(old.clone(), None);
        let ready = now + recovery.exhaust(now);
        let new = addresses(4);
        assert!(recovery.rearm(&new, None, now).is_none());
        assert_eq!(recovery.rearm(&new, None, ready), Some("new_address"));
        assert_eq!(recovery.attempt(new.clone(), None), Some(new[3].clone()));
        let ready = ready + recovery.exhaust(ready);
        assert!(recovery.rearm(&new, None, ready).is_none());
    }

    #[test]
    fn address_rotation_crosses_round_boundaries_and_storage_is_bounded() {
        let mut recovery = Recovery::default();
        let now = Instant::now();
        let peer = PeerId::from_libp2p(Libp2pPeerId::random());
        let demand = ApplicationDemand::new([peer], now);
        let addresses = addresses(20);
        for index in 0..32 {
            if index % 3 == 0 && index != 0 {
                let ready = now + recovery.exhaust(now);
                demand.record(peer, ready);
                assert_eq!(
                    recovery.rearm(
                        &addresses[..MAX_ADDRESSES],
                        demand.snapshot(peer).unwrap().version,
                        ready
                    ),
                    Some("application_demand")
                );
            }
            assert_eq!(
                recovery.attempt(addresses.clone(), demand.snapshot(peer).unwrap().version),
                Some(addresses[index % MAX_ADDRESSES].clone())
            );
            assert_eq!(recovery.addresses.len(), MAX_ADDRESSES);
            assert!(recovery.cursor < MAX_ADDRESSES);
        }
    }

    #[test]
    fn empty_candidates_do_not_spend_fresh_demand_and_success_does_not_arm_a_timer() {
        let peer = Libp2pPeerId::random();
        let forwarder = super::super::tests::forwarder(peer);
        let now = Instant::now();
        assert_eq!(demand(&forwarder, peer), None);
        forwarder.record_application_demand(PeerId::from_libp2p(peer), now);
        let version = demand(&forwarder, peer);
        assert!(version.is_some());
        let mut recovery = Recovery::default();
        let addresses = addresses(1);
        assert!(recovery.rearm(&addresses, version, now).is_none());
        let ready = now + recovery.exhaust(now);
        assert!(recovery.rearm(&[], version, ready).is_none());
        assert_eq!(
            recovery.rearm(&addresses, version, ready),
            Some("application_demand")
        );
        recovery.attempt(addresses, version);
        assert!(!recovery.ready(ready + Duration::from_secs(86400)));
    }
}
