//! Unregistered, short-lived ingress for a native WebRTC proof.

use super::*;

const PROBE_LIMITS: Limits = Limits {
    idle: Duration::from_secs(4),
    pending: Duration::from_secs(4),
    active: Duration::ZERO,
    traffic: Budget {
        bytes: 128 * 1024,
        packets: 256,
    },
};

pub(crate) struct Ingress {
    pub(crate) address: Multiaddr,
    pump: Pump,
}

impl Ingress {
    pub(crate) async fn prepare(
        scope: Scope,
        entrance: &Multiaddr,
        source: SocketAddr,
    ) -> io::Result<Self> {
        if !source.ip().is_loopback() || source.port() == 0 {
            return Err(unauthorized());
        }
        let upstream = pinned_relay_route(entrance, EntranceKind::Reservation)?;
        let (address, pump) = prepare_upstream(scope, upstream, PROBE_LIMITS, None).await?;
        pump.shared.lock()?.client = Some(source);
        Ok(Self { address, pump })
    }

    pub(crate) async fn while_driving<T>(
        &self,
        proof: impl Future<Output = io::Result<T>>,
    ) -> io::Result<T> {
        tokio::select! {
            biased;
            error = self.pump.run_borrowed() => Err(error.err().unwrap_or_else(closed)),
            result = proof => {
                self.pump.shared.scope.check()?;
                result
            }
        }
    }
}
