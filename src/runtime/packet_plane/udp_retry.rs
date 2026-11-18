//! ACK-driven Android retry operations, retained across Hello transcripts.
#![cfg(any(target_os = "android", all(test, target_os = "linux")))]

use super::udp_retry_runtime::UdpRecoveryIntent;
use super::{Arc, Duration, Instant, Mutex, PeerId, SocketAddr, io};
use crate::runtime::lifecycle::activity::DemandVersion;
use crate::runtime::physical_network::android::{
    SocketProtocol,
    egress::{
        Egress, NetworkAttempt, NetworkAttempts, RouteEpoch, RouteLease, canonical_socket_address,
    },
};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicBool, Ordering},
};

const MAX_PEERS: usize = 4096;
const RENEWAL_COOLDOWN: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub(super) struct Registry {
    peers: HashMap<PeerId, Stored>,
    limit: usize,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            peers: HashMap::new(),
            limit: MAX_PEERS,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Context {
    epoch: RouteEpoch,
    local: SocketAddr,
    destination: SocketAddr,
    mark: u32,
}

#[derive(Debug)]
struct Stored {
    context: Context,
    failed_owner: Option<Arc<()>>,
    valid: Arc<AtomicBool>,
    entry: Arc<tokio::sync::Mutex<Entry>>,
}

impl Drop for Stored {
    fn drop(&mut self) {
        // Archived RX routes can retain Entry, but not its authority to work.
        self.valid.store(false, Ordering::Release);
    }
}

#[derive(Debug)]
struct Entry {
    cursor: NetworkAttempts,
    selected: Option<NetworkAttempt>,
    attempted: bool,
    established: bool,
    preferred_only: bool,
    cooldown_until: Option<Instant>,
    current_candidate: Option<Arc<CandidateState>>,
    last_demand: Option<DemandVersion>,
    retry_at: Option<Instant>,
    preferred_at: Option<Instant>,
    active_anchor: Option<Arc<()>>,
    round: u8,
}

#[derive(Debug)]
struct CandidateState {
    candidate_token: Arc<()>,
    // Updated only while holding Entry, so prepared routes can check the tag
    // without acquiring the async lock (including during source lookup).
    current: AtomicBool,
    confirmed: AtomicBool,
    failure: Mutex<Option<(io::ErrorKind, Instant)>>,
    delivered: Mutex<Option<NetworkAttempt>>,
}

#[derive(Clone, Debug)]
pub(super) struct Candidate {
    entry: Arc<tokio::sync::Mutex<Entry>>,
    valid: Arc<AtomicBool>,
    epoch: RouteEpoch,
    state: Arc<CandidateState>,
}

impl Registry {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn admit(
        &mut self,
        owner: Arc<Egress>,
        peer: PeerId,
        local: SocketAddr,
        destination: SocketAddr,
        mark: u32,
        failed_owner: Option<Arc<()>>,
        preferred_only: bool,
        renewal: bool,
        intent: UdpRecoveryIntent,
        active: Option<Arc<()>>,
        now: Instant,
    ) -> io::Result<bool> {
        let (preferred_restart, round, last_demand) = {
            let stored = self.refresh(
                Arc::clone(&owner),
                peer,
                local,
                destination,
                mark,
                failed_owner.clone(),
                preferred_only,
            )?;
            let Ok(mut entry) = stored.entry.try_lock() else {
                return Ok(false);
            };
            entry.resolve_failure();
            if !stored.valid.load(Ordering::Acquire) || !stored.context.epoch.is_current() {
                return Ok(false);
            }
            if entry.preferred_only
                && !entry.attempted
                && !entry.established
                && entry.cursor.can_prepare()
                && entry.active_anchor.is_none()
            {
                // An epoch-triggered preferred probe also needs to remember
                // the surviving fallback when the first probe is blocked.
                entry.active_anchor = active.clone();
            }
            // A new transcript may supersede a candidate on the same ticket,
            // but neither it nor application packets can reset that cursor.
            if entry.has_live_candidate() {
                return Ok(intent.active(now)
                    && matches!(intent, UdpRecoveryIntent::AuthenticatedControl(_)));
            }
            let preferred = entry.preferred_due(active.as_ref(), intent, now);
            let fresh = active.is_none() && entry.fresh_work(intent, now);
            if !preferred && !fresh {
                let ready = if entry.established {
                    renewal && entry.cooled_down(now)
                } else {
                    entry.cursor.can_prepare()
                };
                if ready && !entry.attempted && !entry.established {
                    entry.last_demand = intent.demand(now);
                }
                return Ok(ready);
            }
            (
                preferred,
                entry.round.saturating_add(1).min(4),
                intent.demand(now).or(entry.last_demand),
            )
        };
        let cursor = NetworkAttempts::new(&owner, local, destination, SocketProtocol::Udp, mark)?;
        let epoch = cursor.epoch().clone();
        if !epoch.is_current()
            || self
                .peers
                .get(&peer)
                .is_none_or(|stored| stored.context.epoch != epoch)
        {
            return Err(stale());
        }
        self.peers.insert(
            peer,
            Stored {
                context: Context {
                    epoch,
                    local: canonical_socket_address(local),
                    destination: canonical_socket_address(destination),
                    mark,
                },
                failed_owner,
                valid: Arc::new(AtomicBool::new(true)),
                entry: Arc::new(tokio::sync::Mutex::new(Entry {
                    cursor,
                    selected: None,
                    attempted: false,
                    established: false,
                    preferred_only: preferred_restart || preferred_only,
                    cooldown_until: None,
                    current_candidate: None,
                    last_demand,
                    retry_at: None,
                    preferred_at: None,
                    active_anchor: if preferred_restart { active } else { None },
                    round,
                })),
            },
        );
        eprintln!(
            "level=info event=packet_plane_udp_recovery_rearmed peer={peer} kind={} round={round}",
            if preferred_restart {
                "preferred_validation"
            } else {
                "fresh_work"
            }
        );
        Ok(true)
    }

    pub(super) fn due(
        &self,
        peer: PeerId,
        failed_owner: Option<&Arc<()>>,
        active: Option<&Arc<()>>,
        intent: UdpRecoveryIntent,
        now: Instant,
    ) -> bool {
        let Some(stored) = self.peers.get(&peer) else {
            return intent.demand(now).is_some();
        };
        if !stored.valid.load(Ordering::Acquire) || !stored.context.epoch.is_current() {
            return intent.demand(now).is_some();
        }
        if failed_owner.is_some_and(|new| {
            stored
                .failed_owner
                .as_ref()
                .is_none_or(|old| !Arc::ptr_eq(new, old))
        }) {
            return true;
        }
        let Ok(mut entry) = stored.entry.try_lock() else {
            return false;
        };
        entry.resolve_failure();
        entry.preferred_due(active, intent, now)
            || (active.is_none() && entry.fresh_work(intent, now))
            || (entry.attempted
                && !entry.established
                && entry.cursor.can_prepare()
                && !entry.has_live_candidate())
    }

    pub(super) fn preferred_due(
        &self,
        peer: PeerId,
        active: Option<&Arc<()>>,
        intent: UdpRecoveryIntent,
        now: Instant,
    ) -> bool {
        let Some(stored) = self.peers.get(&peer) else {
            return false;
        };
        if !stored.valid.load(Ordering::Acquire) || !stored.context.epoch.is_current() {
            return false;
        }
        let Ok(mut entry) = stored.entry.try_lock() else {
            return false;
        };
        entry.resolve_failure();
        entry.preferred_due(active, intent, now)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn attach(
        &mut self,
        owner: Arc<Egress>,
        peer: PeerId,
        local: SocketAddr,
        destination: SocketAddr,
        mark: u32,
        failed_owner: Option<Arc<()>>,
        preferred_only: bool,
        candidate_token: Arc<()>,
        now: Instant,
    ) -> io::Result<Candidate> {
        let stored = self.refresh(
            owner,
            peer,
            local,
            destination,
            mark,
            failed_owner,
            preferred_only,
        )?;
        let mut entry = stored.entry.try_lock().map_err(|_| busy())?;
        entry.resolve_failure();
        if !stored.valid.load(Ordering::Acquire) || !stored.context.epoch.is_current() {
            return Err(stale());
        }
        if entry.established && !entry.cooled_down(now) {
            return Err(busy());
        }
        if entry.selected.is_none() && !entry.cursor.can_prepare() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "UDP Network retry operation exhausted or unfinished",
            ));
        }
        let state = match &entry.current_candidate {
            Some(current) if Arc::ptr_eq(&current.candidate_token, &candidate_token) => {
                Arc::clone(current)
            }
            _ => {
                entry.clear_candidate();
                let state = Arc::new(CandidateState {
                    candidate_token,
                    current: AtomicBool::new(true),
                    confirmed: AtomicBool::new(false),
                    failure: Mutex::new(None),
                    delivered: Mutex::new(None),
                });
                entry.current_candidate = Some(Arc::clone(&state));
                state
            }
        };
        Ok(Candidate {
            entry: Arc::clone(&stored.entry),
            valid: Arc::clone(&stored.valid),
            epoch: stored.context.epoch.clone(),
            state,
        })
    }

    #[cfg(test)]
    pub(super) fn pending(&self, peer: PeerId) -> bool {
        self.due(
            peer,
            None,
            None,
            UdpRecoveryIntent::Maintenance,
            Instant::now(),
        )
    }

    pub(super) fn forget(&mut self, peer: PeerId) {
        self.peers.remove(&peer);
    }

    pub(super) fn clear(&mut self) {
        self.peers.clear();
    }

    #[allow(clippy::too_many_arguments)]
    fn refresh(
        &mut self,
        owner: Arc<Egress>,
        peer: PeerId,
        local: SocketAddr,
        destination: SocketAddr,
        mark: u32,
        failed_owner: Option<Arc<()>>,
        preferred_only: bool,
    ) -> io::Result<&Stored> {
        self.peers
            .retain(|_, stored| stored.context.epoch.is_current());
        let context = Context {
            epoch: owner.current_epoch()?,
            local: canonical_socket_address(local),
            destination: canonical_socket_address(destination),
            mark,
        };
        self.peers
            .retain(|_, stored| stored.context.epoch == context.epoch);
        let replace = self.peers.get(&peer).is_none_or(|stored| {
            stored.context != context
                || failed_owner.as_ref().is_some_and(|new| {
                    stored
                        .failed_owner
                        .as_ref()
                        .is_none_or(|old| !Arc::ptr_eq(old, new))
                })
        });
        if replace {
            if !self.peers.contains_key(&peer) && self.peers.len() >= self.limit {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "UDP Network retry peer limit",
                ));
            }
            let cursor = NetworkAttempts::new(
                &owner,
                context.local,
                context.destination,
                SocketProtocol::Udp,
                context.mark,
            )?;
            if cursor.epoch() != &context.epoch || !context.epoch.is_current() {
                return Err(stale());
            }
            self.peers.insert(
                peer,
                Stored {
                    context,
                    failed_owner,
                    valid: Arc::new(AtomicBool::new(true)),
                    entry: Arc::new(tokio::sync::Mutex::new(Entry {
                        cursor,
                        selected: None,
                        attempted: false,
                        established: false,
                        // Policy belongs to this operation, not its Hello nonce.
                        preferred_only,
                        cooldown_until: None,
                        current_candidate: None,
                        last_demand: None,
                        retry_at: None,
                        preferred_at: None,
                        active_anchor: None,
                        round: 0,
                    })),
                },
            );
        }
        Ok(self.peers.get(&peer).expect("retry record inserted"))
    }
}

impl Entry {
    fn fresh_work(&self, intent: UdpRecoveryIntent, now: Instant) -> bool {
        !self.established
            && !self.cursor.can_prepare()
            && !self.has_live_candidate()
            && self.retry_at.is_some_and(|at| {
                now >= at
                    && (intent
                        .demand(now)
                        .is_some_and(|version| Some(version) != self.last_demand)
                        || intent.control(at, now))
            })
    }

    fn preferred_due(
        &self,
        active: Option<&Arc<()>>,
        intent: UdpRecoveryIntent,
        now: Instant,
    ) -> bool {
        !self.has_live_candidate()
            && self.cooled_down(now)
            && self.preferred_at.is_some_and(|at| {
                now >= at && (intent.demand(now).is_some() || intent.control(at, now))
            })
            && self
                .active_anchor
                .as_ref()
                .zip(active)
                .is_some_and(|(expected, actual)| Arc::ptr_eq(expected, actual))
    }

    fn retry_delay(&self) -> Duration {
        Duration::from_secs((30_u64 << self.round.min(4)).min(300))
    }
    fn has_live_candidate(&self) -> bool {
        self.current_candidate
            .as_ref()
            .is_some_and(|state| !state.confirmed.load(Ordering::Acquire))
    }

    fn cooled_down(&self, now: Instant) -> bool {
        self.cooldown_until.is_none_or(|until| now >= until)
    }

    fn clear_candidate(&mut self) {
        if let Some(state) = self.current_candidate.take() {
            state.current.store(false, Ordering::Release);
        }
    }

    fn matches(&self, state: &Arc<CandidateState>) -> bool {
        self.current_candidate
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, state))
    }

    fn resolve_failure(&mut self) {
        let Some(state) = self.current_candidate.as_ref() else {
            return;
        };
        let failure = *state
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some((kind, now)) = failure else {
            return;
        };
        if self.established {
            self.cooldown_until = Some(now + RENEWAL_COOLDOWN);
        } else if let Some(selected) = self.selected.take() {
            // Even a terminal/stale error cannot authorize another owner.
            let _ = self.cursor.failed(&selected, kind, !self.preferred_only);
        }
        self.clear_candidate();
        if !self.established && !self.cursor.can_prepare() {
            let at = now + self.retry_delay();
            self.retry_at = Some(at);
            if self.active_anchor.is_some() {
                self.preferred_at = Some(at);
            }
        }
    }
}

impl Candidate {
    pub(super) async fn prepare(&self, owner: &Egress) -> io::Result<RouteLease> {
        let mut entry = self.entry.lock().await;
        entry.resolve_failure();
        self.check(&entry)?;
        if owner.current_epoch()? != self.epoch {
            return Err(stale());
        }
        if entry.selected.is_none() {
            let preferred_only = entry.preferred_only;
            let prepared = entry
                .cursor
                .prepare(owner, || {
                    self.valid.load(Ordering::Acquire)
                        && self.epoch.is_current()
                        && self.state.current.load(Ordering::Acquire)
                        && !preferred_only
                })
                .await;
            if let Ok(selected) = &prepared {
                // Save before resolving a failure delivered during source lookup.
                entry.selected = Some(selected.clone());
                entry.attempted = true;
            }
            entry.resolve_failure();
            self.check(&entry)?;
            prepared?;
        }
        let selected = entry.selected.as_ref().ok_or_else(stale)?;
        if !selected.lease().is_current() {
            return Err(stale());
        }
        if entry.preferred_only && !selected.is_preferred() {
            return Err(io::Error::new(
                io::ErrorKind::NetworkUnreachable,
                "UDP preferred Network is unavailable",
            ));
        }
        // Synchronize delivery with failed(), independently of Entry's lock.
        let failure = self
            .state
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if failure.is_some() {
            drop(failure);
            entry.resolve_failure();
            return Err(stale());
        }
        self.check_identity(&entry)?;
        *self
            .state
            .delivered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(selected.clone());
        Ok(selected.lease().clone())
    }

    /// The parent has already authenticated the exact ACK and its deadline.
    #[cfg(test)]
    pub(super) async fn confirm(&self, deadline: Instant) -> io::Result<()> {
        self.confirm_with(deadline, || ()).await
    }

    /// Promotion must be infallible and must not reenter this retry ledger.
    pub(super) async fn confirm_with(
        &self,
        deadline: Instant,
        promote: impl FnOnce(),
    ) -> io::Result<()> {
        let mut entry = self.entry.lock().await;
        entry.resolve_failure();
        self.check(&entry)?;
        let failure = self
            .state
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if failure.is_some() {
            drop(failure);
            entry.resolve_failure();
            return Err(stale());
        }
        self.check_identity(&entry)?;
        let delivered = self
            .state
            .delivered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let selected = entry.selected.as_ref().ok_or_else(stale)?;
        if !delivered
            .as_ref()
            .is_some_and(|attempt| attempt.same_attempt(selected))
            || !selected.lease().is_current()
            || (entry.preferred_only && !selected.is_preferred())
        {
            return Err(stale());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "UDP Network ACK proof deadline expired",
            ));
        }
        let preferred = selected.is_preferred();
        if self.state.confirmed.load(Ordering::Acquire) {
            return Ok(());
        }
        if !entry.established {
            let selected = selected.clone();
            let permitted = !entry.preferred_only;
            entry.cursor.confirm(&selected, permitted)?;
        }
        // Keep both locks through the parent's synchronous ownership move.
        // There is no fallible step or await after cursor completion.
        promote();
        if preferred {
            entry.preferred_at = None;
            entry.active_anchor = None;
            entry.retry_at = None;
            entry.round = 0;
        } else {
            if !entry.established {
                entry.preferred_at = Some(Instant::now() + RENEWAL_COOLDOWN);
                entry.round = 0;
            }
            entry.active_anchor = Some(Arc::clone(&self.state.candidate_token));
        }
        entry.established = true;
        entry.cooldown_until = None;
        self.state.confirmed.store(true, Ordering::Release);
        Ok(())
    }

    pub(super) fn failed(&self, kind: io::ErrorKind, now: Instant) {
        let mut failure = self
            .state
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        failure.get_or_insert((kind, now));
        drop(failure);
        if let Ok(mut entry) = self.entry.try_lock() {
            entry.resolve_failure();
        }
    }

    pub(super) fn is_current(&self) -> bool {
        self.valid.load(Ordering::Acquire)
            && self.epoch.is_current()
            && self.state.current.load(Ordering::Acquire)
            && self
                .state
                .failure
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_none()
    }

    fn check(&self, entry: &Entry) -> io::Result<()> {
        if !self.is_current() {
            return Err(stale());
        }
        self.check_identity(entry)
    }

    fn check_identity(&self, entry: &Entry) -> io::Result<()> {
        if !self.valid.load(Ordering::Acquire)
            || !self.epoch.is_current()
            || !self.state.current.load(Ordering::Acquire)
            || !entry.matches(&self.state)
        {
            return Err(stale());
        }
        Ok(())
    }
}

fn stale() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "UDP Network retry candidate changed",
    )
}

fn busy() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "UDP Network retry entry is busy")
}

#[cfg(test)]
mod tests;
