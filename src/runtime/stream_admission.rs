//! Reliable stream admission after transport authentication. The runtime owns
//! the binding lookup, exchange deadline, and current membership validation.

use super::packet::PacketRejectionReason;

pub const MIN_IPV4_MTU: u16 = 68;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamMtu(u16);

impl StreamMtu {
    /// Native IPv6-capable interfaces may impose a higher configuration floor.
    #[must_use]
    pub fn negotiate(local: u16, remote: u16) -> Option<Self> {
        let mtu = local.min(remote);
        (mtu >= MIN_IPV4_MTU).then_some(Self(mtu))
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Apply the grant of the exact binding before inspecting packet content.
    pub fn check_payload(
        grant: Option<Self>,
        payload_len: usize,
    ) -> Result<(), PacketRejectionReason> {
        let mtu = grant.ok_or(PacketRejectionReason::UnauthorizedPeer)?;
        if payload_len > usize::from(mtu.get()) {
            return Err(PacketRejectionReason::PacketTooLarge);
        }
        Ok(())
    }
}

/// Authority for exactly one binding. A caller must select this state using
/// the authenticated peer and connection from the transport event.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StreamAdmission<Request> {
    #[default]
    Unverified,
    Waiting(Request),
    Authorized(StreamMtu),
}

impl<Request: PartialEq> StreamAdmission<Request> {
    pub fn expect(&mut self, request: Request) -> bool {
        if matches!(self, Self::Authorized(_)) {
            return false;
        }
        *self = Self::Waiting(request);
        true
    }

    #[must_use]
    pub fn awaits(&self, request: &Request) -> bool {
        matches!(self, Self::Waiting(pending) if pending == request)
    }

    /// An unmatched completion cannot change or consume a pending request.
    pub fn finish(&mut self, request: &Request, mtu: Option<StreamMtu>) -> bool {
        if !self.awaits(request) {
            return false;
        }
        *self = mtu.map_or(Self::Unverified, Self::Authorized);
        true
    }

    /// Inbound updates may change a grant but cannot complete an outbound exchange.
    pub fn refresh(&mut self, mtu: StreamMtu) {
        if let Self::Authorized(current) = self {
            *current = mtu;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_completion_cannot_create_or_consume_a_grant() {
        let mut admission = StreamAdmission::default();
        let mtu = StreamMtu::negotiate(1500, 1280).unwrap();
        assert!(admission.expect(1));
        assert!(admission.expect(2));
        admission.refresh(mtu);
        assert!(!admission.finish(&1, Some(mtu)));
        assert!(admission.awaits(&2));
        assert!(admission.finish(&2, Some(mtu)));
        assert!(!admission.finish(&2, None));
        assert_eq!(admission, StreamAdmission::Authorized(mtu));
    }

    #[test]
    fn packet_limit_requires_a_grant_and_uses_the_lower_offer() {
        use PacketRejectionReason::{PacketTooLarge, UnauthorizedPeer};

        assert_eq!(StreamMtu::check_payload(None, 20), Err(UnauthorizedPeer));
        for (local, remote) in [(1500, 1280), (1280, 1500)] {
            let grant = StreamMtu::negotiate(local, remote);
            assert_eq!(StreamMtu::check_payload(grant, 1280), Ok(()));
            assert_eq!(StreamMtu::check_payload(grant, 1281), Err(PacketTooLarge));
        }
        assert!(StreamMtu::negotiate(1500, MIN_IPV4_MTU - 1).is_none());
    }
}
