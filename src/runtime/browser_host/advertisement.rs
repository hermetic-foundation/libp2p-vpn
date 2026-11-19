//! Explicit browser-owned peer-address publication on the OS-default physical link.

use std::{
    io,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::StreamExt as _;
use libp2p::{Multiaddr, PeerId, StreamProtocol, kad, swarm::SwarmEvent};
use rand_core::{OsRng, RngCore as _};
use tokio::sync::watch;

use crate::{
    config::PUBLIC_IPFS_KADEMLIA_PROTOCOL,
    peer_address_record::browser_advertisement::{CHALLENGE_LIFETIME, Challenge, Submission},
};

use super::{DhtSwarm, LOOKUP_BUDGET, kademlia_peer_addresses_key, with_default_dht};

const COOLDOWN: Duration = Duration::from_secs(30);

/// Trusted companion policy, not data obtained from a browser HTTP request.
/// The caller is responsible for keeping this authorization current.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Permit {
    pub network_name: String,
    pub membership_tag: Option<String>,
    pub protocol: StreamProtocol,
    pub browser_peer: PeerId,
    pub destination: PeerId,
    pub address: Multiaddr,
}

impl Permit {
    fn challenge(&self, nonce: String, issued_at_unix_seconds: u64) -> Challenge {
        Challenge {
            nonce,
            network_name: self.network_name.clone(),
            membership_tag: self.membership_tag.clone(),
            kademlia_protocol: self.protocol.to_string(),
            browser_peer: self.browser_peer.to_string(),
            destination: self.destination.to_string(),
            address: self.address.to_string(),
            issued_at_unix_seconds,
        }
    }

    fn validate(&self) -> io::Result<()> {
        if self.protocol.as_ref() == PUBLIC_IPFS_KADEMLIA_PROTOCOL {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "browser relay address values require a cooperating DHT",
            ));
        }
        self.challenge("a".repeat(32), 0)
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
    }
}

/// One explicitly authorized browser and circuit per loopback server.
pub struct Publisher {
    state: Mutex<State>,
    changed: watch::Sender<()>,
}

struct State {
    permit: Option<Permit>,
    pending: Option<(Challenge, Instant)>,
    next_challenge: Instant,
}

impl Publisher {
    /// `None` disables issuing challenges and writing to the DHT.
    pub fn new(permit: Option<Permit>) -> io::Result<Self> {
        if let Some(permit) = &permit {
            permit.validate()?;
        }
        Ok(Self {
            state: Mutex::new(State {
                permit,
                pending: None,
                next_challenge: Instant::now(),
            }),
            changed: watch::channel(()).0,
        })
    }

    /// Changing scope, recipient, circuit or permission invalidates existing work.
    pub fn replace_permit(&self, permit: Option<Permit>) -> io::Result<()> {
        if let Some(permit) = &permit {
            permit.validate()?;
        }
        let mut state = self.lock()?;
        if state.permit != permit {
            state.permit = permit;
            state.pending = None;
            self.changed.send_replace(());
        }
        Ok(())
    }

    /// Requires an explicit request; issuances (even unused ones) are rate limited.
    pub fn challenge(&self) -> io::Result<Challenge> {
        let mut state = self.lock()?;
        let permit = state.permit.as_ref().ok_or_else(not_permitted)?;
        let now = Instant::now();
        if now < state.next_challenge {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "browser advertisement is rate limited",
            ));
        }
        let mut nonce = [0; 24];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let challenge = permit.challenge(URL_SAFE_NO_PAD.encode(nonce), unix_seconds()?);
        state.next_challenge = now + COOLDOWN;
        state.pending = Some((
            challenge.clone(),
            now + Duration::from_secs(CHALLENGE_LIFETIME),
        ));
        Ok(challenge)
    }

    /// Validate and consume the challenge before opening any DHT transport.
    /// Bootstrap addresses and interface exclusions must come from host policy.
    pub async fn publish(
        &self,
        body: &[u8],
        bootstrap: &[Multiaddr],
        owned_interface: Option<&str>,
    ) -> io::Result<()> {
        let (permit, challenge, submission, mut changed) = self.consume(body)?;
        let now = unix_seconds()?;
        let (value, expires_at) = submission.verify(&challenge, now)?;
        let lifetime = Duration::from_secs(expires_at.saturating_sub(now));
        if lifetime <= LOOKUP_BUDGET + Duration::from_secs(1) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "browser advertisement expired",
            ));
        }
        let record = kad::Record {
            key: kademlia_peer_addresses_key(
                &permit.network_name,
                permit.membership_tag.as_deref(),
                permit.browser_peer,
            ),
            value,
            publisher: None,
            expires: Some(Instant::now() + lifetime),
        };
        tokio::select! {
            biased;
            _ = changed.changed() => Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "browser advertisement permission changed",
            )),
            result = with_default_dht(&permit.protocol, bootstrap, owned_interface, |swarm| {
                put_record(swarm, record)
            }) => result,
        }
    }

    fn consume(
        &self,
        body: &[u8],
    ) -> io::Result<(Permit, Challenge, Submission, watch::Receiver<()>)> {
        let mut state = self.lock()?;
        let permit = state.permit.as_ref().ok_or_else(not_permitted)?;
        let submission = Submission::parse(body)?;
        let (challenge, deadline) = state.pending.as_ref().ok_or_else(not_permitted)?;
        if submission.nonce != challenge.nonce || Instant::now() >= *deadline {
            return Err(not_permitted());
        }
        let permit = permit.clone();
        let (challenge, _) = state.pending.take().expect("validated pending challenge");
        Ok((permit, challenge, submission, self.changed.subscribe()))
    }

    fn lock(&self) -> io::Result<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("browser advertisement state unavailable"))
    }
}

async fn put_record(mut swarm: DhtSwarm, record: kad::Record) -> io::Result<()> {
    let query = swarm
        .behaviour_mut()
        .try_put_record(record, kad::Quorum::One)
        .map_err(io::Error::other)?
        .map_err(io::Error::other)?;
    loop {
        if let SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
            id,
            result: kad::QueryResult::PutRecord(result),
            ..
        }) = swarm.select_next_some().await
            && id == query
        {
            return result.map(|_| ()).map_err(io::Error::other);
        }
    }
}

fn unix_seconds() -> io::Result<u64> {
    UNIX_EPOCH
        .elapsed()
        .map(|time| time.as_secs())
        .map_err(io::Error::other)
}

fn not_permitted() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "no current browser advertisement permission",
    )
}

#[cfg(test)]
mod tests;
