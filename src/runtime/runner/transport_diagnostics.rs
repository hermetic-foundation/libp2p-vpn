//! Read-only ownership evidence for explicit State requests, never health polling.

use super::*;

mod history;
pub(super) use history::{record, scope};

pub(super) fn record_relay_limit(event: &relay::client::Event) {
    let (role, peer, limit) = match event {
        relay::client::Event::ReservationReqAccepted {
            relay_peer_id,
            limit,
            ..
        } => ("reservation", relay_peer_id, limit),
        relay::client::Event::OutboundCircuitEstablished {
            relay_peer_id,
            limit,
        } => ("outbound_circuit", relay_peer_id, limit),
        relay::client::Event::InboundCircuitEstablished { src_peer_id, limit } => {
            ("inbound_circuit", src_peer_id, limit)
        }
    };
    log_runtime_event(
        LogLevel::Info,
        "relay_client_limit",
        &[
            ("role", role),
            ("peer", &peer.to_string()),
            (
                "duration_seconds",
                &limit.and_then(|limit| limit.duration()).map_or_else(
                    || "unknown".to_owned(),
                    |duration| duration.as_secs().to_string(),
                ),
            ),
            (
                "data_bytes",
                &limit
                    .and_then(|limit| limit.data_in_bytes())
                    .map_or_else(|| "unknown".to_owned(), |bytes| bytes.to_string()),
            ),
        ],
    );
}

pub(super) fn capture(
    behaviour: &Behaviour,
    connections: &HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
    epochs: &ConnectionEpochs,
) -> Vec<String> {
    let mut lines = Vec::new();
    #[cfg(any(target_os = "android", target_os = "linux"))]
    if let Some(registry) = behaviour.connection_retention.physical_routes() {
        for owner in registry.snapshot() {
            #[cfg(target_os = "android")]
            let network = {
                let [handle, incarnation, revision] = owner.lease.network_identity();
                format!(
                    " network_handle={handle} network_incarnation={incarnation} network_revision={revision} available={}",
                    owner.lease.is_available()
                )
            };
            #[cfg(not(target_os = "android"))]
            let network = "";
            lines.push(format!(
                "physical control state: peer={} route_id={} connection_id={} protocol={:?} source={} destination={} interface={} generation={} adopted={} lease_current={} cached_refresh_required={:?} role={}{}",
                owner.peer,
                owner.id,
                owner.connection_id.map_or_else(|| "none".to_owned(), |id| id.to_string()),
                owner.lease.context.protocol,
                owner.lease.local_addr,
                owner.lease.context.destination,
                owner.lease.route.interface_index,
                owner.lease.route.generation,
                owner.is_adopted(),
                owner.lease.is_current(),
                owner.refresh_required(),
                if owner.lease.preferred_dial { "dialer" } else { "listener" },
                network,
            ));
        }
    }
    for ((peer, inner), endpoint) in connections {
        if !endpoint.is_relayed() {
            continue;
        }
        let binding = behaviour.relay.circuit_connection_owner(*peer, *inner);
        let owner = binding.map_or_else(
            || "relay=unknown outer=unknown".to_owned(),
            |(relay, outer)| {
                let outer_remote = connections.get(&(relay, outer)).map_or_else(
                    || "unknown".to_owned(),
                    |endpoint| endpoint.get_remote_address().to_string(),
                );
                format!(
                    "relay={relay} outer={outer} outer_remote={outer_remote} {}",
                    epoch_line("outer", outer, epochs)
                )
            },
        );
        lines.push(format!(
            "physical circuit state: peer={peer} connection_id={inner} {owner} {}",
            epoch_line("inner", *inner, epochs),
        ));
    }
    lines.extend(history::snapshot());
    lines.sort_unstable();
    lines
}

fn epoch_line(label: &str, connection: ConnectionId, epochs: &ConnectionEpochs) -> String {
    format!(
        "{label}_epoch={} current_epoch={} {label}_usable={} {label}_retiring={}",
        epochs
            .connections
            .get(&connection)
            .map_or_else(|| "unknown".to_owned(), u64::to_string),
        epochs.current,
        epochs.is_usable(connection),
        epochs.retiring.contains(&connection),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn relay_limit_history_distinguishes_roles_and_missing_limits() {
        scope(async {
            let peer = Libp2pPeerId::random();
            for event in [
                relay::client::Event::ReservationReqAccepted {
                    relay_peer_id: peer,
                    renewal: false,
                    limit: None,
                },
                relay::client::Event::OutboundCircuitEstablished {
                    relay_peer_id: peer,
                    limit: None,
                },
                relay::client::Event::InboundCircuitEstablished {
                    src_peer_id: peer,
                    limit: None,
                },
            ] {
                record_relay_limit(&event);
            }
            let lines = history::snapshot();
            assert_eq!(lines.len(), 4);
            for role in ["reservation", "outbound_circuit", "inbound_circuit"] {
                assert!(
                    lines
                        .iter()
                        .any(|line| line.contains(&format!("role={role} "))
                            && line.contains("duration_seconds=unknown data_bytes=unknown"))
                );
            }
        })
        .await;
    }

    #[test]
    fn distinguishes_unknown_stale_retiring_and_usable_without_mutation() {
        let id = ConnectionId::new_unchecked(42);
        let mut epochs = ConnectionEpochs::default();
        assert!(epoch_line("inner", id, &epochs).contains("inner_epoch=unknown"));
        epochs.record_started(id);
        assert!(epoch_line("inner", id, &epochs).contains("inner_usable=true"));
        epochs.mark_retiring(id);
        let retiring = epoch_line("inner", id, &epochs);
        assert!(retiring.contains("inner_usable=false inner_retiring=true"));
        epochs.advance();
        let stale = epoch_line("outer", id, &epochs);
        assert!(stale.contains("outer_epoch=0 current_epoch=1 outer_usable=false"));
        assert_eq!(epochs.connections.get(&id), Some(&0));
        assert!(epochs.retiring.contains(&id));
    }
}
