//! Kernel-scoped ownership shared by independently running native VPN instances.

use super::{LOOKUP_TIMEOUT, LinuxRouteMonitor, RouteLookupError};
use futures::TryStreamExt;
use netlink_packet_route::link::{InfoKind, LinkAttribute, LinkInfo, LinkMessage};
use std::collections::HashSet;
use tokio::time::timeout;

pub(crate) const OVERLAY_MARKER: &str = "p2p-vpn:overlay:v1";
const MAX_LINK_RECORDS: usize = 1024;

pub(super) fn is_owned_link(link: &LinkMessage) -> bool {
    link.attributes.iter().any(
        |attribute| matches!(attribute, LinkAttribute::IfAlias(alias) if alias == OVERLAY_MARKER),
    ) && link.attributes.iter().any(|attribute| {
        matches!(attribute, LinkAttribute::LinkInfo(info) if info.iter().any(|value| {
            matches!(value, LinkInfo::Kind(InfoKind::Tun))
        }))
    })
}

pub(super) async fn indices(monitor: &LinuxRouteMonitor) -> Result<HashSet<u32>, RouteLookupError> {
    let generation = monitor.generation()?;
    let _dump = monitor.dump_permit().await?;
    let _permit = monitor
        .lookups
        .try_acquire()
        .map_err(|_| RouteLookupError::Busy)?;
    let mut pending = monitor.request()?;
    let mut links = pending.handle()?.link().get().execute();
    let result = timeout(LOOKUP_TIMEOUT, async {
        let mut indices = HashSet::new();
        let mut records = 0;
        while let Some(link) = links
            .try_next()
            .await
            .map_err(|error| pending.response_error(error))?
        {
            records += 1;
            if records > MAX_LINK_RECORDS {
                return Err(RouteLookupError::UnsupportedRoute);
            }
            if is_owned_link(&link) {
                indices.insert(link.header.index);
            }
        }
        pending.finish()?;
        Ok(indices)
    })
    .await
    .map_err(|_| RouteLookupError::Timeout)?;
    if monitor.generation()? != generation {
        return Err(RouteLookupError::StaleGeneration);
    }
    result
}

#[cfg(test)]
mod tests;
