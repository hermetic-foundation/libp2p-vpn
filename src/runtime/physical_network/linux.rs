//! Kernel route observations, not a synthesized global default interface.

mod discovery;
pub use discovery::LinuxDiscovery;
pub(crate) mod control;
pub(crate) mod egress;
pub(crate) mod ownership;

use futures::{StreamExt, TryStreamExt};
use netlink_packet_core::{DefaultNla, NetlinkPayload};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    address::AddressAttribute,
    route::{RouteAddress, RouteAttribute, RouteFlags, RouteMessage, RouteProtocol, RouteType},
};
use rtnetlink::{Handle, MulticastGroup, RouteMessageBuilder};
use std::{
    collections::HashSet,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
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
const MDNS_DESTINATION: IpAddr = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251));
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
pub enum SocketProtocol {
    Tcp,
    Udp,
}

/// The actual socket tuple and routing selectors. Ports are in host byte order;
/// a wildcard source represents a socket that has not selected its source yet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketRouteContext {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub protocol: SocketProtocol,
    pub mark: u32,
    pub interface_index: Option<u32>,
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
    dumps: Semaphore,
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
            dumps: Semaphore::new(1),
            driver: Some(driver),
        })
    }

    pub fn generation(&self) -> Result<u64, RouteLookupError> {
        if self.lookups.is_closed() {
            return Err(RouteLookupError::MonitorUnavailable);
        }
        current_generation(&self.revision)
    }

    async fn dump_permit(&self) -> Result<tokio::sync::SemaphorePermit<'_>, RouteLookupError> {
        self.generation()?;
        // Linux permits only one in-progress dump on a Netlink socket, even
        // when ordinary single-object requests may proceed concurrently.
        let permit = timeout(LOOKUP_TIMEOUT, self.dumps.acquire())
            .await
            .map_err(|_| RouteLookupError::Timeout)?
            .map_err(|_| RouteLookupError::MonitorUnavailable)?;
        self.generation()?;
        Ok(permit)
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
        self.lookup_route(destination, owned_interfaces).await
    }

    pub async fn route_for_socket(
        &self,
        context: SocketRouteContext,
        owned_interfaces: &HashSet<u32>,
    ) -> Result<ResolvedRoute, RouteLookupError> {
        let request = socket_route_request(context, rustix::process::geteuid().as_raw())?;
        self.execute_lookup(request, context.destination.ip(), owned_interfaces)
            .await
    }

    async fn lookup_route(
        &self,
        destination: IpAddr,
        owned_interfaces: &HashSet<u32>,
    ) -> Result<ResolvedRoute, RouteLookupError> {
        self.lookup_route_on(destination, owned_interfaces, None)
            .await
    }

    async fn lookup_route_on(
        &self,
        destination: IpAddr,
        owned_interfaces: &HashSet<u32>,
        interface: Option<u32>,
    ) -> Result<ResolvedRoute, RouteLookupError> {
        let mut request = route_request(destination, rustix::process::geteuid().as_raw());
        if let Some(interface) = interface {
            request.attributes.push(RouteAttribute::Oif(interface));
        }
        self.execute_lookup(request, destination, owned_interfaces)
            .await
    }

    async fn execute_lookup(
        &self,
        request: RouteMessage,
        destination: IpAddr,
        owned_interfaces: &HashSet<u32>,
    ) -> Result<ResolvedRoute, RouteLookupError> {
        let generation = self.generation()?;
        let _permit = self
            .lookups
            .try_acquire()
            .map_err(|_| RouteLookupError::Busy)?;
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
            if route.header.kind == RouteType::Local && !destination.is_loopback() {
                self.require_local_underlay(destination, owned_interfaces, &mut pending)
                    .await?;
            }
            let route = decode_route(route, generation, destination, owned_interfaces)?;
            // Inspect the resolved interface, not a name prefix or cached index.
            // Reuse this lookup slot and deadline for the metadata request.
            pending.complete = false;
            let mut links = self
                .handle
                .link()
                .get()
                .match_index(route.interface_index)
                .execute();
            let link = links
                .try_next()
                .await
                .map_err(|error| pending.response_error(error))?;
            if links
                .try_next()
                .await
                .map_err(|error| pending.response_error(error))?
                .is_some()
            {
                return Err(RouteLookupError::UnsupportedRoute);
            }
            pending.complete = true;
            let link = link.ok_or(RouteLookupError::UnsupportedRoute)?;
            if link.header.index != route.interface_index {
                return Err(RouteLookupError::UnsupportedRoute);
            }
            if ownership::is_owned_link(&link) {
                return Err(RouteLookupError::OwnOverlay);
            }
            Ok(route)
        })
        .await
        .map_err(|_| RouteLookupError::Timeout)?;
        self.generation()?;
        check_generation(&self.revision, generation)?;
        result
    }

    // A local route uses loopback even when its address belongs to a TUN. Check
    // the address's actual owner before allowing same-host physical connections.
    async fn require_local_underlay(
        &self,
        destination: IpAddr,
        excluded: &HashSet<u32>,
        pending: &mut PendingLookup<'_>,
    ) -> Result<(), RouteLookupError> {
        let _dump = self.dump_permit().await?;
        pending.complete = false;
        let mut addresses = self.handle.address().get().execute();
        let mut owners = HashSet::new();
        let mut count = 0;
        while let Some(address) = addresses
            .try_next()
            .await
            .map_err(|error| pending.response_error(error))?
        {
            count += 1;
            if count > 4096 {
                return Err(RouteLookupError::UnsupportedRoute);
            }
            if address.attributes.iter().any(|attribute| matches!(attribute,
                AddressAttribute::Local(ip) | AddressAttribute::Address(ip) if *ip == destination
            )) {
                owners.insert(address.header.index);
            }
        }
        pending.complete = true;
        if owners.is_empty() {
            return Err(RouteLookupError::UnsupportedRoute);
        }
        for index in owners {
            if excluded.contains(&index) {
                return Err(RouteLookupError::OwnOverlay);
            }
            pending.complete = false;
            let mut links = self.handle.link().get().match_index(index).execute();
            let link = links
                .try_next()
                .await
                .map_err(|error| pending.response_error(error))?
                .ok_or(RouteLookupError::UnsupportedRoute)?;
            if links
                .try_next()
                .await
                .map_err(|error| pending.response_error(error))?
                .is_some()
            {
                return Err(RouteLookupError::UnsupportedRoute);
            }
            pending.complete = true;
            if ownership::is_owned_link(&link) {
                return Err(RouteLookupError::OwnOverlay);
            }
        }
        Ok(())
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

fn socket_route_request(
    context: SocketRouteContext,
    uid: u32,
) -> Result<RouteMessage, RouteLookupError> {
    let destination = context.destination.ip();
    let source = context.source.ip();
    if destination.is_unspecified()
        || destination.is_multicast()
        || source.is_multicast()
        || source.is_ipv4() != destination.is_ipv4()
        || context.interface_index == Some(0)
    {
        return Err(RouteLookupError::InvalidDestination);
    }
    let scope = match context.destination {
        SocketAddr::V6(address) if address.ip().is_unicast_link_local() => {
            if address.scope_id() == 0 {
                return Err(RouteLookupError::InvalidDestination);
            }
            Some(address.scope_id())
        }
        _ => None,
    };
    if scope
        .zip(context.interface_index)
        .is_some_and(|(a, b)| a != b)
    {
        return Err(RouteLookupError::InvalidDestination);
    }
    if let SocketAddr::V6(address) = context.source
        && address.ip().is_unicast_link_local()
        && (address.scope_id() == 0
            || Some(address.scope_id()) != context.interface_index.or(scope))
    {
        return Err(RouteLookupError::InvalidDestination);
    }
    let mut request = route_request(destination, uid);
    if !source.is_unspecified() {
        request.header.source_prefix_length = if source.is_ipv4() { 32 } else { 128 };
        request
            .attributes
            .push(RouteAttribute::Source(source.into()));
    }
    request.attributes.push(RouteAttribute::Mark(context.mark));
    if let Some(index) = context.interface_index.or(scope) {
        request.attributes.push(RouteAttribute::Oif(index));
    }
    // The pinned netlink crate represents these Linux UAPI attributes as
    // DefaultNla. RTA_IP_PROTO is a byte; RTA_{S,D}PORT use network byte order.
    for (kind, data) in [
        (
            27,
            vec![match context.protocol {
                SocketProtocol::Tcp => 6,
                SocketProtocol::Udp => 17,
            }],
        ),
        (28, context.source.port().to_be_bytes().to_vec()),
        (29, context.destination.port().to_be_bytes().to_vec()),
    ] {
        request
            .attributes
            .push(RouteAttribute::Other(DefaultNla::new(kind, data)));
    }
    Ok(request)
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
    let eligible_kind = matches!(message.header.kind, RouteType::Unicast | RouteType::Local)
        || (destination == MDNS_DESTINATION && message.header.kind == RouteType::Multicast);
    if !eligible_kind || message.header.address_family != family {
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
    let mut source = None;
    for attribute in message.attributes {
        match attribute {
            RouteAttribute::Oif(index) => route.interface_index = index,
            RouteAttribute::PrefSource(address) => {
                route.preferred_source = Some(ip_address(&address)?);
            }
            // IPv6 route-get replies may supply the selected source as RTA_SRC.
            RouteAttribute::Source(address) => source = Some(ip_address(&address)?),
            RouteAttribute::Gateway(address) => route.gateway = Some(ip_address(&address)?),
            RouteAttribute::Table(table) => route.table = table,
            // A resolved lookup must identify one actual egress; never choose
            // the first member of a multipath route ourselves.
            RouteAttribute::MultiPath(_) => return Err(RouteLookupError::UnsupportedRoute),
            _ => {}
        }
    }
    route.preferred_source = route.preferred_source.or(source);
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
#[cfg(test)]
pub(crate) use tests::{ip as test_ip, isolated_namespace};
