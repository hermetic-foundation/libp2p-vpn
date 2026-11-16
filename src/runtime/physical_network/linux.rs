//! Kernel route observations, not a synthesized global default interface.

use futures::{StreamExt, TryStreamExt};
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    route::{RouteAddress, RouteAttribute, RouteFlags, RouteMessage, RouteProtocol, RouteType},
};
use rtnetlink::{Handle, MulticastGroup, RouteMessageBuilder};
use std::{
    collections::HashSet,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use tokio::{
    sync::{Semaphore, watch},
    task::JoinHandle,
    time::{Instant, sleep_until, timeout},
};

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
const EVENT_QUIET: Duration = Duration::from_millis(50);
const EVENT_MAX_WAIT: Duration = Duration::from_millis(250);
const GROUPS: &[MulticastGroup] = &[
    MulticastGroup::Link,
    MulticastGroup::Ipv4Ifaddr,
    MulticastGroup::Ipv6Ifaddr,
    MulticastGroup::Ipv4Route,
    MulticastGroup::Ipv6Route,
    MulticastGroup::Ipv4Rule,
    MulticastGroup::Ipv6Rule,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Revision {
    generation: u64,
    available: bool,
}

/// A destination's kernel-selected route for a locally originated, unbound,
/// unmarked socket owned by the current effective UID. No packets are sent.
/// Transport/port-, mark-, source-, or device-bound policy needs a matching
/// socket-context lookup before this can authorize that transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedRoute {
    pub generation: u64,
    pub destination: IpAddr,
    pub interface_index: u32,
    pub preferred_source: Option<IpAddr>,
    pub gateway: Option<IpAddr>,
    pub table: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteLookupError {
    MonitorUnavailable,
    Busy,
    Timeout,
    Kernel(Option<i32>),
    UnsupportedRoute,
    OwnOverlay,
    StaleGeneration,
    InvalidDestination,
}

impl std::fmt::Display for RouteLookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MonitorUnavailable => f.write_str("Linux route monitor is unavailable"),
            Self::Busy => f.write_str("Linux route lookup concurrency limit reached"),
            Self::Timeout => f.write_str("Linux route lookup timed out"),
            Self::Kernel(code) => write!(f, "Linux route lookup failed (errno {code:?})"),
            Self::UnsupportedRoute => f.write_str("Linux route is not a resolved unicast path"),
            Self::OwnOverlay => {
                f.write_str("Linux underlay route points into an owned VPN interface")
            }
            Self::StaleGeneration => f.write_str("Linux route changed during lookup"),
            Self::InvalidDestination => f.write_str("invalid Linux underlay destination"),
        }
    }
}

impl std::error::Error for RouteLookupError {}

/// One subscribed socket, one abort-on-drop driver, and a latest-value revision.
/// Callers re-evaluate affected destinations; notifications do not disconnect peers.
pub struct LinuxRouteMonitor {
    handle: Handle,
    revision: watch::Receiver<Revision>,
    lookups: Semaphore,
    driver: Option<JoinHandle<()>>,
}

// The Netlink library retains requests until a reply arrives. If a caller
// cancels or times out, retire this observer rather than accumulate orphans.
struct PendingLookup<'a> {
    monitor: &'a LinuxRouteMonitor,
    complete: bool,
}

impl PendingLookup<'_> {
    fn response_error(&mut self, error: rtnetlink::Error) -> RouteLookupError {
        if matches!(error, rtnetlink::Error::NetlinkError(_)) {
            self.complete = true;
        }
        lookup_error(error)
    }
}

impl Drop for PendingLookup<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.monitor.lookups.close();
            if let Some(driver) = &self.monitor.driver {
                driver.abort();
            }
        }
    }
}

impl LinuxRouteMonitor {
    /// Must be called inside a Tokio runtime. Subscribe before the first lookup
    /// so route-only and policy-rule changes cannot depend on address polling.
    pub fn new() -> io::Result<Self> {
        let (mut connection, handle, mut messages) = rtnetlink::new_multicast_connection(GROUPS)?;
        let (revision, receiver) = watch::channel(Revision {
            generation: 1,
            available: true,
        });
        let driver = tokio::spawn(async move {
            let mut batch = 0;
            loop {
                tokio::select! {
                    () = &mut connection => break,
                    message = messages.next() => {
                        let Some((message, source)) = message else { break };
                        // Only the kernel may invalidate routing state.
                        if source.port_number() != 0 {
                            continue;
                        }
                        match message.payload {
                            NetlinkPayload::InnerMessage(message) if invalidates_routes(&message) => {
                                if !advance_revision(&revision) {
                                    break;
                                }
                            }
                            NetlinkPayload::Overrun(_) | NetlinkPayload::Error(_) => break,
                            _ => {}
                        }
                        batch += 1;
                        if batch == 64 {
                            batch = 0;
                            tokio::task::yield_now().await;
                        }
                    }
                }
            }
            revision.send_modify(|state| state.available = false);
        });
        Ok(Self {
            handle,
            revision: receiver,
            lookups: Semaphore::new(4),
            driver: Some(driver),
        })
    }

    pub fn generation(&self) -> Result<u64, RouteLookupError> {
        if self.lookups.is_closed() {
            return Err(RouteLookupError::MonitorUnavailable);
        }
        current_generation(&self.revision)
    }

    pub fn validate_generation(&self, route: &ResolvedRoute) -> Result<(), RouteLookupError> {
        self.generation()?;
        check_generation(&self.revision, route.generation)
    }

    /// Coalesce bursts without polling and without indefinitely delaying a
    /// continuously flapping network. An unavailable monitor fails closed.
    pub async fn changed(&mut self) -> Result<u64, RouteLookupError> {
        self.generation()?;
        coalesced_change(&mut self.revision).await
    }

    pub async fn route_to(
        &self,
        destination: IpAddr,
        owned_interfaces: &HashSet<u32>,
    ) -> Result<ResolvedRoute, RouteLookupError> {
        if destination.is_unspecified()
            || destination.is_loopback()
            || destination.is_multicast()
            || matches!(destination, IpAddr::V6(ip) if ip.is_unicast_link_local())
        {
            return Err(RouteLookupError::InvalidDestination);
        }
        let generation = self.generation()?;
        let _permit = self
            .lookups
            .try_acquire()
            .map_err(|_| RouteLookupError::Busy)?;
        let request = route_request(destination, rustix::process::geteuid().as_raw());
        let mut routes = self.handle.route().get(request).execute();
        let mut pending = PendingLookup {
            monitor: self,
            complete: false,
        };
        let result = timeout(LOOKUP_TIMEOUT, async {
            let route = routes
                .try_next()
                .await
                .map_err(|error| pending.response_error(error))?
                .ok_or(RouteLookupError::UnsupportedRoute)?;
            if routes
                .try_next()
                .await
                .map_err(|error| pending.response_error(error))?
                .is_some()
            {
                return Err(RouteLookupError::UnsupportedRoute);
            }
            pending.complete = true;
            decode_route(route, generation, destination, owned_interfaces)
        })
        .await
        .map_err(|_| RouteLookupError::Timeout)?;
        self.generation()?;
        check_generation(&self.revision, generation)?;
        result
    }

    /// Await this when a caller needs proof that the owned driver has exited.
    pub async fn shutdown(mut self) {
        if let Some(driver) = self.driver.take() {
            driver.abort();
            let _ = driver.await;
        }
    }
}

impl Drop for LinuxRouteMonitor {
    fn drop(&mut self) {
        if let Some(driver) = &self.driver {
            driver.abort();
        }
    }
}

fn advance_revision(sender: &watch::Sender<Revision>) -> bool {
    sender.send_modify(|state| {
        if let Some(next) = state.generation.checked_add(1) {
            state.generation = next;
        } else {
            state.available = false;
        }
    });
    sender.borrow().available
}

fn current_generation(receiver: &watch::Receiver<Revision>) -> Result<u64, RouteLookupError> {
    let revision = *receiver.borrow();
    if receiver.has_changed().is_err() || !revision.available {
        return Err(RouteLookupError::MonitorUnavailable);
    }
    Ok(revision.generation)
}

fn check_generation(
    receiver: &watch::Receiver<Revision>,
    generation: u64,
) -> Result<(), RouteLookupError> {
    if current_generation(receiver)? == generation {
        Ok(())
    } else {
        Err(RouteLookupError::StaleGeneration)
    }
}

async fn coalesced_change(
    receiver: &mut watch::Receiver<Revision>,
) -> Result<u64, RouteLookupError> {
    receiver
        .changed()
        .await
        .map_err(|_| RouteLookupError::MonitorUnavailable)?;
    let maximum = Instant::now() + EVENT_MAX_WAIT;
    loop {
        current_generation(receiver)?;
        let deadline = maximum.min(Instant::now() + EVENT_QUIET);
        tokio::select! {
            () = sleep_until(deadline) => {
                receiver.borrow_and_update();
                return current_generation(receiver);
            }
            update = receiver.changed() => {
                update.map_err(|_| RouteLookupError::MonitorUnavailable)?;
                if Instant::now() >= maximum {
                    return current_generation(receiver);
                }
            }
        }
    }
}

fn invalidates_routes(message: &RouteNetlinkMessage) -> bool {
    matches!(
        message,
        RouteNetlinkMessage::NewLink(_)
            | RouteNetlinkMessage::DelLink(_)
            | RouteNetlinkMessage::NewAddress(_)
            | RouteNetlinkMessage::DelAddress(_)
            | RouteNetlinkMessage::NewRoute(_)
            | RouteNetlinkMessage::DelRoute(_)
            | RouteNetlinkMessage::NewRule(_)
            | RouteNetlinkMessage::DelRule(_)
    )
}

fn route_request(destination: IpAddr, uid: u32) -> RouteMessage {
    let mut message = match destination {
        IpAddr::V4(address) => RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(address, 32)
            .build(),
        IpAddr::V6(address) => RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(address, 128)
            .build(),
    };
    // Ask the routing policy database, not a main-table-only route dump.
    message.header.table = 0;
    message.header.protocol = RouteProtocol::Unspec;
    message.header.kind = RouteType::Unspec;
    message.header.flags.insert(RouteFlags::LookupTable);
    message.attributes.push(RouteAttribute::Uid(uid));
    message
}

fn lookup_error(error: rtnetlink::Error) -> RouteLookupError {
    match error {
        rtnetlink::Error::NetlinkError(error) => {
            RouteLookupError::Kernel(error.code.map(std::num::NonZeroI32::get))
        }
        _ => RouteLookupError::Kernel(None),
    }
}

fn decode_route(
    message: RouteMessage,
    generation: u64,
    destination: IpAddr,
    owned_interfaces: &HashSet<u32>,
) -> Result<ResolvedRoute, RouteLookupError> {
    let family = if destination.is_ipv4() {
        AddressFamily::Inet
    } else {
        AddressFamily::Inet6
    };
    if message.header.kind != RouteType::Unicast || message.header.address_family != family {
        return Err(RouteLookupError::UnsupportedRoute);
    }
    let mut route = ResolvedRoute {
        generation,
        destination,
        interface_index: 0,
        preferred_source: None,
        gateway: None,
        table: u32::from(message.header.table),
    };
    for attribute in message.attributes {
        match attribute {
            RouteAttribute::Oif(index) => route.interface_index = index,
            RouteAttribute::PrefSource(address) => {
                route.preferred_source = Some(ip_address(&address)?);
            }
            RouteAttribute::Gateway(address) => route.gateway = Some(ip_address(&address)?),
            RouteAttribute::Table(table) => route.table = table,
            // A resolved lookup must identify one actual egress; never choose
            // the first member of a multipath route ourselves.
            RouteAttribute::MultiPath(_) => return Err(RouteLookupError::UnsupportedRoute),
            _ => {}
        }
    }
    if route.interface_index == 0 {
        return Err(RouteLookupError::UnsupportedRoute);
    }
    if owned_interfaces.contains(&route.interface_index) {
        return Err(RouteLookupError::OwnOverlay);
    }
    Ok(route)
}

fn ip_address(address: &RouteAddress) -> Result<IpAddr, RouteLookupError> {
    match address {
        RouteAddress::Inet(ip) => Ok(IpAddr::V4(*ip)),
        RouteAddress::Inet6(ip) => Ok(IpAddr::V6(*ip)),
        _ => Err(RouteLookupError::UnsupportedRoute),
    }
}

#[cfg(test)]
mod tests;
