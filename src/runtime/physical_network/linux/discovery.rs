//! Linux's IPv4 mDNS route drives LAN admission; this does not pin unicast sockets.

use super::{LOOKUP_TIMEOUT, LinuxRouteMonitor, MDNS_DESTINATION, ResolvedRoute, RouteLookupError};
use crate::runtime::physical_network::{
    MAX_SOURCE_ADDRESSES, PhysicalNetworkKind, PhysicalNetworkPublisher, PhysicalNetworkSnapshot,
};
use futures::TryStreamExt;
use netlink_packet_route::{
    address::{AddressAttribute, AddressFlags, AddressHeaderFlags, AddressMessage},
    link::{InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkLayerType, LinkMessage},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    net::IpAddr,
    path::Path,
    time::Duration,
};
use tokio::{
    sync::{oneshot, watch},
    task::JoinHandle,
    time::{sleep, timeout},
};

const MAX_ADDRESS_RECORDS: usize = 4096;
const MAX_RETRY: Duration = Duration::from_secs(30);
const MAX_LINK_RECORDS: usize = 1024;
const MAX_LAN_CANDIDATES: usize = 16;

/// Native daemon integration. Initial admission is empty; selection updates do
/// not restart the VPN or install routes. Dropping this owner stops observation.
pub struct LinuxDiscovery {
    receiver: watch::Receiver<PhysicalNetworkSnapshot>,
    stop: Option<oneshot::Sender<()>>,
    driver: Option<JoinHandle<()>>,
}

impl LinuxDiscovery {
    #[must_use]
    pub fn start(owned_interface: Option<String>) -> Self {
        let publisher = PhysicalNetworkPublisher::default();
        let receiver = publisher.subscribe();
        let (stop, cancelled) = oneshot::channel();
        let driver = tokio::spawn(run(publisher, cancelled, owned_interface));
        Self {
            receiver,
            stop: Some(stop),
            driver: Some(driver),
        }
    }

    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<PhysicalNetworkSnapshot> {
        self.receiver.clone()
    }

    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(driver) = self.driver.take() {
            let _ = driver.await;
        }
    }
}

impl Drop for LinuxDiscovery {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(driver) = &self.driver {
            driver.abort();
        }
    }
}

struct Publications {
    publisher: PhysicalNetworkPublisher,
    last: PhysicalNetworkSnapshot,
}

impl Publications {
    fn update(&mut self, mut snapshot: PhysicalNetworkSnapshot) -> Result<(), &'static str> {
        snapshot.generation = self.last.generation;
        if snapshot == self.last {
            return Ok(());
        }
        snapshot.generation = self
            .last
            .generation
            .checked_add(1)
            .ok_or("generation_exhausted")?;
        self.publisher
            .publish(snapshot.clone())
            .map_err(|_| "invalid_snapshot")?;
        eprintln!(
            "level=info event=physical_network_linux_discovery generation={} interface={:?} kind={:?} source_count={}",
            snapshot.generation,
            snapshot.interface_name,
            snapshot.kind,
            snapshot.mdns_addresses().len()
        );
        self.last = snapshot;
        Ok(())
    }
}

#[derive(Default)]
struct Retry(u8);

impl Retry {
    fn next(&mut self) -> Duration {
        let delay = Duration::from_secs(1 << self.0.min(5)).min(MAX_RETRY);
        self.0 = self.0.saturating_add(1);
        delay
    }
}

async fn run(
    publisher: PhysicalNetworkPublisher,
    mut stop: oneshot::Receiver<()>,
    owned: Option<String>,
) {
    let mut publications = Publications {
        publisher,
        last: PhysicalNetworkSnapshot::default(),
    };
    let mut monitor: Option<LinuxRouteMonitor> = None;
    let mut retry = Retry::default();
    let mut delay = None;
    loop {
        if let Some(wait) = delay.take() {
            tokio::select! { biased; _ = &mut stop => break, () = sleep(wait) => {} }
        }
        if monitor.is_none() {
            match LinuxRouteMonitor::new() {
                Ok(created) => monitor = Some(created),
                Err(error) => {
                    eprintln!(
                        "level=warn event=physical_network_linux_monitor_unavailable errno={:?}",
                        error.raw_os_error()
                    );
                    delay = Some(retry.next());
                    continue;
                }
            }
        }
        let observer = monitor.as_mut().expect("monitor created");
        let result = tokio::select! {
            biased;
            _ = &mut stop => break,
            result = snapshot(observer, owned.as_deref()) => result,
        };
        match result {
            Ok(selection) => {
                if publications.update(selection).is_err() {
                    break;
                }
                retry = Retry::default();
            }
            Err(RouteLookupError::StaleGeneration) => {
                if publications
                    .update(PhysicalNetworkSnapshot::default())
                    .is_err()
                {
                    break;
                }
            }
            Err(error) => {
                if publications
                    .update(PhysicalNetworkSnapshot::default())
                    .is_err()
                {
                    break;
                }
                // Missing routes remain idle until an event. A broken observer
                // is replaced, never spun in a closed-channel select loop.
                if observer.generation().is_err()
                    || !matches!(
                        error,
                        RouteLookupError::UnsupportedRoute
                            | RouteLookupError::OwnOverlay
                            | RouteLookupError::Kernel(Some(-101 | -113 | -19 | -2))
                    )
                {
                    eprintln!(
                        "level=warn event=physical_network_linux_monitor_retry error={error}"
                    );
                    monitor.take().expect("monitor exists").shutdown().await;
                    delay = Some(retry.next());
                    continue;
                }
            }
        }
        let event = tokio::select! {
            biased;
            _ = &mut stop => break,
            changed = monitor.as_mut().expect("monitor exists").changed() => changed,
        };
        if event.is_err() {
            if publications
                .update(PhysicalNetworkSnapshot::default())
                .is_err()
            {
                break;
            }
            monitor.take().expect("monitor exists").shutdown().await;
            delay = Some(retry.next());
        }
    }
    if let Some(monitor) = monitor {
        monitor.shutdown().await;
    }
}

async fn snapshot(
    monitor: &LinuxRouteMonitor,
    owned: Option<&str>,
) -> Result<PhysicalNetworkSnapshot, RouteLookupError> {
    let (route, link) = timeout(LOOKUP_TIMEOUT, lan_route(monitor, owned))
        .await
        .map_err(|_| RouteLookupError::Timeout)??;
    let _dump = monitor.dump_permit().await?;
    let mut pending = monitor.request()?;
    let result = timeout(LOOKUP_TIMEOUT, async {
        let name = interface_name(&link).ok_or(RouteLookupError::UnsupportedRoute)?;
        let mut request = pending.handle()?.address().get();
        let message = request.message_mut();
        message.header.index = route.interface_index;
        let mut addresses = request.execute();
        let mut sources = BTreeSet::new();
        let mut records = 0;
        while let Some(address) = addresses
            .try_next()
            .await
            .map_err(|e| pending.response_error(e))?
        {
            records += 1;
            if records > MAX_ADDRESS_RECORDS {
                return Err(RouteLookupError::UnsupportedRoute);
            }
            if address.header.index == route.interface_index {
                collect_address(&address, &mut sources)?;
            }
        }
        pending.finish()?;
        if !route
            .preferred_source
            .is_some_and(|source| sources.contains(&source))
        {
            return Err(RouteLookupError::UnsupportedRoute);
        }
        let selection = PhysicalNetworkSnapshot {
            generation: 0,
            kind: PhysicalNetworkKind::Ethernet,
            interface_name: Some(name.to_owned()),
            network_handle: None,
            addresses: sources,
        };
        selection
            .validate()
            .map_err(|_| RouteLookupError::UnsupportedRoute)?;
        Ok(selection)
    })
    .await
    .map_err(|_| RouteLookupError::Timeout)?;
    monitor.validate_generation(&route)?;
    result
}

async fn lan_route(
    monitor: &LinuxRouteMonitor,
    owned: Option<&str>,
) -> Result<(ResolvedRoute, LinkMessage), RouteLookupError> {
    match monitor
        .lookup_route(MDNS_DESTINATION, &HashSet::new())
        .await
    {
        Ok(route) => {
            let mut pending = monitor.request()?;
            let mut links = pending
                .handle()?
                .link()
                .get()
                .match_index(route.interface_index)
                .execute();
            let link = timeout(LOOKUP_TIMEOUT, async {
                let link = links
                    .try_next()
                    .await
                    .map_err(|e| pending.response_error(e))?;
                if links
                    .try_next()
                    .await
                    .map_err(|e| pending.response_error(e))?
                    .is_some()
                {
                    return Err(RouteLookupError::UnsupportedRoute);
                }
                pending.finish()?;
                link.ok_or(RouteLookupError::UnsupportedRoute)
            })
            .await
            .map_err(|_| RouteLookupError::Timeout)??;
            monitor.validate_generation(&route)?;
            if link.header.index == route.interface_index && admitted_link(&link, owned) {
                return Ok((route, link));
            }
        }
        Err(
            RouteLookupError::OwnOverlay | RouteLookupError::Kernel(Some(-101 | -113 | -19 | -2)),
        ) => {}
        Err(error) => return Err(error),
    }
    // Link-local multicast needs no Internet gateway. When the unbound lookup
    // has no eligible LAN, match the interface-bound mDNS sender's socket
    // context instead of inventing a route or transmitting on every link.
    let generation = monitor.generation()?;
    let candidates = lan_candidates(monitor, owned).await?;
    let mut checked = 0;
    for (index, link) in candidates {
        if monitor.generation()? != generation {
            return Err(RouteLookupError::StaleGeneration);
        }
        checked += 1;
        match monitor
            .lookup_route_on(MDNS_DESTINATION, &HashSet::new(), Some(index))
            .await
        {
            Ok(route)
                if route.interface_index == index
                    && route.generation == generation
                    && route
                        .preferred_source
                        .is_some_and(|ip| ip.is_ipv4() && !ip.is_unspecified()) =>
            {
                return Ok((route, link));
            }
            Ok(route) if route.generation == generation && route.interface_index == index => {}
            Ok(_) | Err(RouteLookupError::StaleGeneration) => {
                return Err(RouteLookupError::StaleGeneration);
            }
            Err(
                RouteLookupError::Kernel(_)
                | RouteLookupError::UnsupportedRoute
                | RouteLookupError::OwnOverlay,
            ) => {}
            Err(error) => return Err(error),
        }
        if checked >= MAX_LAN_CANDIDATES {
            break;
        }
    }
    Err(RouteLookupError::UnsupportedRoute)
}

async fn lan_candidates(
    monitor: &LinuxRouteMonitor,
    owned: Option<&str>,
) -> Result<BTreeMap<u32, LinkMessage>, RouteLookupError> {
    let _dump = monitor.dump_permit().await?;
    let mut pending = monitor.request()?;
    let mut links = pending.handle()?.link().get().execute();
    timeout(LOOKUP_TIMEOUT, async {
        let mut candidates = BTreeMap::new();
        let mut records = 0;
        while let Some(link) = links
            .try_next()
            .await
            .map_err(|e| pending.response_error(e))?
        {
            records += 1;
            if records > MAX_LINK_RECORDS {
                return Err(RouteLookupError::UnsupportedRoute);
            }
            if admitted_link(&link, owned) {
                candidates.insert(link.header.index, link);
                if candidates.len() > MAX_LAN_CANDIDATES {
                    candidates.pop_last();
                }
            }
        }
        pending.finish()?;
        Ok(candidates)
    })
    .await
    .map_err(|_| RouteLookupError::Timeout)?
}

fn admitted_link(link: &LinkMessage, owned: Option<&str>) -> bool {
    !super::ownership::is_owned_link(link)
        && eligible_link(link, false)
        && interface_name(link).is_some_and(|name| owned != Some(name) && !cellular_device(name))
}

fn interface_name(link: &LinkMessage) -> Option<&str> {
    link.attributes.iter().find_map(|attr| match attr {
        LinkAttribute::IfName(name)
            if !name.is_empty()
                && name != "."
                && name != ".."
                && name.len() <= 64
                && !name.contains('/')
                && !name.chars().any(char::is_control) =>
        {
            Some(name.as_str())
        }
        _ => None,
    })
}

fn eligible_link(link: &LinkMessage, cellular: bool) -> bool {
    if cellular
        || link.header.link_layer_type != LinkLayerType::Ether
        || !link
            .header
            .flags
            .contains(LinkFlags::Up | LinkFlags::Multicast)
        || link
            .header
            .flags
            .intersects(LinkFlags::Loopback | LinkFlags::Pointopoint)
    {
        return false;
    }
    link.attributes
        .iter()
        .filter_map(|attr| match attr {
            LinkAttribute::LinkInfo(info) => Some(info),
            _ => None,
        })
        .flatten()
        .all(|info| match info {
            LinkInfo::Kind(kind) => matches!(
                kind,
                InfoKind::Bridge
                    | InfoKind::Veth
                    | InfoKind::Vlan
                    | InfoKind::Bond
                    | InfoKind::MacVlan
                    | InfoKind::MacVtap
                    | InfoKind::IpVlan
                    | InfoKind::IpVtap
            ),
            _ => true,
        })
}

fn cellular_device(name: &str) -> bool {
    let device = Path::new("/sys/class/net").join(name);
    // Hardware metadata, not interface prefixes or carrier address ranges.
    let driver = std::fs::read_link(device.join("device/driver")).ok();
    device.join("device/wwan").exists()
        || std::fs::read_link(device.join("device/subsystem"))
            .ok()
            .is_some_and(|path| path.file_name().is_some_and(|part| part == "wwan"))
        || driver
            .as_ref()
            .and_then(|path| path.file_name())
            .is_some_and(|part| {
                matches!(
                    part.to_str(),
                    Some("qmi_wwan" | "cdc_mbim" | "huawei_cdc_ncm" | "mhi_net" | "mhi_wwan_mbim")
                )
            })
}

fn collect_address(
    message: &AddressMessage,
    sources: &mut BTreeSet<IpAddr>,
) -> Result<(), RouteLookupError> {
    let unusable = AddressHeaderFlags::Tentative
        | AddressHeaderFlags::Dadfailed
        | AddressHeaderFlags::Deprecated;
    if message.header.flags.intersects(unusable) || message.attributes.iter().any(|attr|
        matches!(attr, AddressAttribute::Flags(flags) if flags.intersects(AddressFlags::Tentative | AddressFlags::Dadfailed | AddressFlags::Deprecated))
        || matches!(attr, AddressAttribute::CacheInfo(info) if info.ifa_valid == 0 || info.ifa_preferred == 0)) {
        return Ok(());
    }
    let local = message.attributes.iter().find_map(|attr| match attr {
        AddressAttribute::Local(ip) => Some(*ip),
        _ => None,
    });
    let address = local.or_else(|| {
        message.attributes.iter().find_map(|attr| match attr {
            AddressAttribute::Address(ip) => Some(*ip),
            _ => None,
        })
    });
    if let Some(ip) =
        address.filter(|ip| !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast())
    {
        sources.insert(ip);
        if sources.len() > MAX_SOURCE_ADDRESSES {
            return Err(RouteLookupError::UnsupportedRoute);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
