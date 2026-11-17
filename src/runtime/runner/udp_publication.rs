//! Publish actual prepared UDP sources without retaining their I/O owners.

use super::*;

const MAX_GENERATED_SOURCES: usize = 32;

#[derive(Default)]
pub(super) struct Sources {
    injected: HashSet<String>,
}

impl Sources {
    fn reconcile(
        &mut self,
        capabilities: &mut ControlCapabilities,
        sources: impl IntoIterator<Item = SocketAddr>,
        protected: &[String],
        overlay: &[IpCidr],
        listener: bool,
        retained: &[SocketAddr],
    ) -> bool {
        let before = capabilities.packet_endpoint_candidates.clone();
        let mut current = sources
            .into_iter()
            .filter(|source| {
                source.port() != 0
                    && is_usable_direct_packet_endpoint_ip(source.ip())
                    && !matches!(source.ip(), IpAddr::V6(ip) if ip.is_unicast_link_local())
                    && !overlay.iter().any(|prefix| prefix.contains(source.ip()))
            })
            .collect::<Vec<_>>();
        current.sort_unstable();
        current.dedup();
        current.truncate(MAX_GENERATED_SOURCES);
        let current = current
            .into_iter()
            .map(|source| source.to_string())
            .collect::<HashSet<_>>();
        let retained = retained
            .iter()
            .map(ToString::to_string)
            .collect::<HashSet<_>>();
        self.injected.retain(|endpoint| {
            if current.contains(endpoint) || retained.contains(endpoint) {
                return true;
            }
            if !protected.contains(endpoint) {
                capabilities
                    .packet_endpoint_candidates
                    .retain(|candidate| candidate != endpoint);
            }
            false
        });
        let mut additions = current.into_iter().collect::<Vec<_>>();
        additions.sort_unstable();
        for endpoint in additions {
            if self.injected.len() < MAX_GENERATED_SOURCES
                && !capabilities.packet_endpoint_candidates.contains(&endpoint)
            {
                capabilities
                    .packet_endpoint_candidates
                    .push(endpoint.clone());
                self.injected.insert(endpoint);
            }
        }
        let supported = listener && !capabilities.packet_endpoint_candidates.is_empty();
        let flags_changed = supported != capabilities.supports_owned_udp_packet_plane;
        if flags_changed {
            *capabilities = capabilities.clone().with_owned_udp_packet_plane(supported);
        }
        capabilities.packet_endpoint_candidates != before || flags_changed
    }
}

#[cfg(test)]
mod tests;
