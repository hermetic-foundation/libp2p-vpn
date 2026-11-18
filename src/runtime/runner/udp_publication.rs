//! Reconcile automatic packet aliases from their live owners, without owning I/O.

use super::*;

const MAX_GENERATED_SOURCES: usize = 32;
const MAX_NATIVE_OWNERS: usize = 64;

#[derive(Default)]
pub(super) struct State {
    base: Option<(Vec<String>, Vec<String>)>,
    udp: Sources,
    quic: Sources,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    native: HashMap<(Libp2pPeerId, ConnectionId), NativeClaim>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
struct NativeClaim {
    owner: super::super::physical_network::control::Snapshot,
    udp: Option<SocketAddr>,
    quic: Option<SocketAddr>,
}

impl State {
    pub(super) fn initialize_base(&mut self, udp: &[String], quic: &[String]) {
        self.base
            .get_or_insert_with(|| (udp.to_vec(), quic.to_vec()));
    }

    fn initialize(&mut self, local: &ControlCapabilities) {
        self.base.get_or_insert_with(|| {
            (
                local.packet_endpoint_candidates.clone(),
                local.owned_quic_packet_endpoint_candidates.clone(),
            )
        });
    }

    pub(super) fn forget_native(&mut self, peer: Libp2pPeerId, connection: ConnectionId) {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        self.native.remove(&(peer, connection));
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let _ = (peer, connection);
    }

    pub(super) fn forget_peer(&mut self, peer: PeerId) {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        self.native
            .retain(|(candidate, _), _| PeerId::from_libp2p(*candidate) != peer);
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let _ = peer;
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(super) fn record_native(
        &mut self,
        owner: super::super::physical_network::control::Snapshot,
        udp: Option<SocketAddr>,
        quic: Option<SocketAddr>,
    ) -> bool {
        self.prune_native(|_| true);
        let Some(connection) = owner.connection_id else {
            return false;
        };
        if !owner.is_live() || !owner.is_adopted() {
            return false;
        }
        let key = (owner.peer, connection);
        if udp.is_none() && quic.is_none() {
            return false;
        }
        if !self.native.contains_key(&key) && self.native.len() >= MAX_NATIVE_OWNERS {
            return false;
        }
        self.native.insert(key, NativeClaim { owner, udp, quic });
        true
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn prune_native(&mut self, authorized: impl Fn(Libp2pPeerId) -> bool) {
        self.native.retain(|(peer, _), claim| {
            if !authorized(*peer) || !claim.owner.is_live() || !claim.owner.is_adopted() {
                return false;
            }
            #[cfg(target_os = "android")]
            return claim.owner.lease.is_available();
            // Linux source audits close invalid owners asynchronously. Keep a
            // live fallback through an epoch change until that verdict arrives.
            #[cfg(not(target_os = "android"))]
            true
        });
    }

    fn render(
        &mut self,
        local: &mut ControlCapabilities,
        udp: Vec<SocketAddr>,
        quic: Vec<SocketAddr>,
        retained_udp: &[SocketAddr],
        retained_quic: &[SocketAddr],
        overlay: &[IpCidr],
        listener: bool,
        certificate: Option<Vec<u8>>,
    ) -> bool {
        self.initialize(local);
        let before = local.clone();
        let (base_udp, base_quic) = self.base.as_ref().expect("initialized aliases");
        let (udp, retained_udp) = if listener {
            (udp, retained_udp)
        } else {
            (Vec::new(), &[][..])
        };
        let (quic, retained_quic) = if certificate.is_some() {
            (quic, retained_quic)
        } else {
            (Vec::new(), &[][..])
        };
        self.udp
            .reconcile(local, udp, base_udp, overlay, listener, retained_udp);
        self.quic.reconcile_aliases(
            &mut local.owned_quic_packet_endpoint_candidates,
            quic,
            base_quic,
            overlay,
            retained_quic,
        );
        *local =
            match certificate.filter(|_| !local.owned_quic_packet_endpoint_candidates.is_empty()) {
                Some(certificate) => local
                    .clone()
                    .with_owned_quic_packet_plane_certificate(certificate),
                None => local.clone().with_owned_quic_packet_plane(false),
            };
        *local != before
    }
}

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
        let changed = self.reconcile_aliases(
            &mut capabilities.packet_endpoint_candidates,
            sources,
            protected,
            overlay,
            retained,
        );
        let supported = listener && !capabilities.packet_endpoint_candidates.is_empty();
        let flags_changed = supported != capabilities.supports_owned_udp_packet_plane;
        if flags_changed {
            *capabilities = capabilities.clone().with_owned_udp_packet_plane(supported);
        }
        changed || flags_changed
    }

    fn reconcile_aliases(
        &mut self,
        candidates: &mut Vec<String>,
        sources: impl IntoIterator<Item = SocketAddr>,
        protected: &[String],
        overlay: &[IpCidr],
        retained: &[SocketAddr],
    ) -> bool {
        let before = candidates.clone();
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
                candidates.retain(|candidate| candidate != endpoint);
            }
            false
        });
        let mut additions = current.into_iter().collect::<Vec<_>>();
        additions.sort_unstable();
        for endpoint in additions {
            if self.injected.len() < MAX_GENERATED_SOURCES && !candidates.contains(&endpoint) {
                candidates.push(endpoint.clone());
                self.injected.insert(endpoint);
            }
        }
        *candidates != before
    }
}

pub(super) fn reconcile(
    swarm: &mut Swarm<Behaviour>,
    forwarder: &Forwarder,
    runtime: &PacketPlaneRuntime,
    quic_runtime: Option<&PacketPlaneQuicRuntime>,
    negotiator: &mut PacketPlaneNegotiator,
    local: &mut ControlCapabilities,
    publication: &mut MembershipRecordSyncs,
    metrics: &RuntimeMetrics,
) {
    let overlay = forwarder
        .local_advertised_route_prefixes()
        .collect::<Vec<_>>();
    let mut sources = negotiator
        .udp_preparations
        .current_sources()
        .chain(negotiator.pending.values().filter_map(|pending| {
            if Instant::now().saturating_duration_since(pending.created_at)
                >= PACKET_PLANE_PENDING_HELLO_TIMEOUT
            {
                return None;
            }
            pending
                .udp_binding
                .as_ref()
                .filter(|binding| binding.is_current())
                .map(|binding| binding.source())
        }))
        .chain(runtime.udp_source_endpoints())
        .collect::<Vec<_>>();
    let snapshot = quic_runtime.map(PacketPlaneQuicRuntime::snapshot);
    let quic_listener = snapshot.as_ref().and_then(|snapshot| snapshot.listener);
    let certificate = snapshot.and_then(|snapshot| snapshot.certificate_der);
    let mut quic_sources = Vec::new();
    let state = &mut negotiator.udp_publication;
    state.initialize(local);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        state.prune_native(|peer| forwarder.is_configured_transport_peer(peer));
        sources.extend(state.native.values().filter_map(|claim| claim.udp));
        quic_sources.extend(state.native.values().filter_map(|claim| claim.quic));
    }
    for address in swarm.external_addresses() {
        let observed = observed_packet_plane_endpoints(
            address,
            runtime.primary_listener(),
            quic_listener,
            &overlay,
        );
        sources.extend(
            observed
                .udp
                .and_then(|endpoint| endpoint.parse::<SocketAddr>().ok()),
        );
        quic_sources.extend(
            observed
                .quic
                .and_then(|endpoint| endpoint.parse::<SocketAddr>().ok()),
        );
    }
    if state.render(
        local,
        sources,
        quic_sources,
        &runtime.udp_retained_source_endpoints(),
        &quic_runtime.map_or_else(Vec::new, PacketPlaneQuicRuntime::retained_source_aliases),
        &overlay,
        runtime.primary_listener().is_some(),
        certificate,
    ) {
        log_runtime_event(
            LogLevel::Info,
            "packet_plane_source_publication_changed",
            &[
                (
                    "udp_candidates",
                    &local.packet_endpoint_candidates.len().to_string(),
                ),
                (
                    "quic_candidates",
                    &local
                        .owned_quic_packet_endpoint_candidates
                        .len()
                        .to_string(),
                ),
            ],
        );
        broadcast_control_capabilities(swarm, forwarder, local, publication, metrics);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod ownership_tests;
#[cfg(test)]
mod tests;
