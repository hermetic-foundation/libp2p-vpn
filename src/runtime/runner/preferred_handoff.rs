//! The route owner requests replacement; only packets on its current owner can commit.

use super::*;
use crate::runtime::{
    physical_network::platform::egress::RouteEpoch,
    preferred_handoff::{Command, Outcome, Request, Response, Scope},
};
use rand_core::{OsRng, RngCore};

const MAX_HANDOFFS: usize = 64;
const WINDOW: Duration = Duration::from_secs(25);

#[derive(Default)]
pub(crate) struct State {
    peers: HashMap<Libp2pPeerId, Ticket>,
}

struct Ticket {
    token: [u8; 16],
    relay: Libp2pPeerId,
    outer: ConnectionId,
    fallback: ConnectionId,
    epoch: RouteEpoch,
    deadline: Instant,
    candidate: Option<ConnectionId>,
    payload: bool,
}

fn current(swarm: &Swarm<Behaviour>, peer: Libp2pPeerId, ticket: &Ticket) -> bool {
    ticket.epoch.is_current()
        && Instant::now() < ticket.deadline
        && swarm
            .behaviour()
            .relay
            .circuit_connection_owner(peer, ticket.fallback)
            .is_some()
        && swarm
            .behaviour()
            .connection_retention
            .physical_routes()
            .and_then(|routes| routes.connection(ticket.relay, ticket.outer))
            .is_some_and(|route| {
                route.is_live() && route.is_adopted() && route.refresh_required() == Some(false)
            })
}

fn owns_candidate(
    swarm: &Swarm<Behaviour>,
    peer: Libp2pPeerId,
    id: ConnectionId,
    ticket: &Ticket,
) -> bool {
    id != ticket.fallback
        && swarm.behaviour().relay.circuit_connection_owner(peer, id)
            == Some((ticket.relay, ticket.outer))
}

pub(super) fn offer(
    swarm: &mut Swarm<Behaviour>,
    forwarder: &Forwarder,
    connections: &HashMap<(Libp2pPeerId, ConnectionId), ConnectedPoint>,
    relay: Libp2pPeerId,
    outer: ConnectionId,
    epoch: &RouteEpoch,
) {
    let now = Instant::now();
    swarm
        .behaviour_mut()
        .connection_retention
        .preferred_handoff
        .peers
        .retain(|_, ticket| ticket.deadline > now && ticket.epoch.is_current());
    let members = connections
        .keys()
        .filter(|(peer, id)| {
            forwarder.is_configured_transport_peer(*peer)
                && swarm
                    .behaviour()
                    .relay
                    .circuit_connection_owner(*peer, *id)
                    .is_some_and(|(owner, old)| owner == relay && old != outer)
        })
        .copied()
        .collect::<Vec<_>>();
    for (peer, fallback) in members {
        if swarm
            .behaviour()
            .connection_retention
            .preferred_handoff
            .peers
            .len()
            >= MAX_HANDOFFS
        {
            break;
        }
        let mut token = [0; 16];
        OsRng.fill_bytes(&mut token);
        let request = Request {
            scope: Scope {
                network_name: forwarder.config().network.name.clone(),
                membership_tag: forwarder.config().membership_tag().ok().flatten(),
            },
            token,
            command: Command::Offer,
        };
        if swarm
            .behaviour_mut()
            .preferred_handoff
            .send_request_on_connection_with_deadline(&peer, fallback, request, now + WINDOW)
            .is_ok()
        {
            swarm
                .behaviour_mut()
                .connection_retention
                .preferred_handoff
                .peers
                .insert(
                    peer,
                    Ticket {
                        token,
                        relay,
                        outer,
                        fallback,
                        epoch: epoch.clone(),
                        deadline: now + WINDOW,
                        candidate: None,
                        payload: false,
                    },
                );
            log_runtime_event(
                LogLevel::Info,
                "preferred_handoff_offer",
                &[
                    ("peer", &peer.to_string()),
                    ("fallback", &fallback.to_string()),
                    ("outer", &outer.to_string()),
                ],
            );
        }
    }
}

pub(super) fn handle_event(
    swarm: &mut Swarm<Behaviour>,
    forwarder: &Forwarder,
    epochs: &ConnectionEpochs,
    event: request_response::Event<Request, Response>,
) {
    let request_response::Event::Message {
        peer,
        connection_id,
        message: Message::Request {
            request, channel, ..
        },
    } = event
    else {
        return;
    };
    let mut outcome = Outcome::Rejected;
    let scope = request.scope.network_name == forwarder.config().network.name
        && crate::runtime::control::membership_tag_matches(
            request.scope.membership_tag.as_deref(),
            forwarder
                .config()
                .membership_tag()
                .ok()
                .flatten()
                .as_deref(),
            &forwarder.config().network.previous_membership_tags,
        );
    if epochs.is_usable(connection_id) && forwarder.is_configured_transport_peer(peer) && scope {
        let mut state =
            std::mem::take(&mut swarm.behaviour_mut().connection_retention.preferred_handoff);
        if let Some(ticket) = state.peers.get_mut(&peer)
            && ticket.token == request.token
            && current(swarm, peer, ticket)
            && owns_candidate(swarm, peer, connection_id, ticket)
        {
            match request.command {
                Command::Verify if ticket.candidate.is_none_or(|id| id == connection_id) => {
                    ticket.candidate = Some(connection_id);
                    outcome = Outcome::Verified;
                }
                Command::Commit if ticket.candidate == Some(connection_id) && ticket.payload => {
                    outcome = Outcome::Committed;
                    // The authenticated candidate has delivered an authorized IP packet to TUN.
                    // Closing only this member circuit releases its old relay dependency.
                    // The dialer promotes after receiving this reply, then closes the old
                    // member circuit. Closing here could race the commit acknowledgement.
                    log_runtime_event(
                        LogLevel::Info,
                        "preferred_handoff_committed",
                        &[
                            ("peer", &peer.to_string()),
                            ("connection_id", &connection_id.to_string()),
                            ("fallback", &ticket.fallback.to_string()),
                        ],
                    );
                }
                _ => {}
            }
        }
        if outcome == Outcome::Committed {
            state.peers.remove(&peer);
        }
        swarm.behaviour_mut().connection_retention.preferred_handoff = state;
    }
    let _ = swarm.behaviour_mut().preferred_handoff.send_response(
        channel,
        Response {
            token: request.token,
            outcome,
        },
    );
}

/// Called only after the ordinary IP authorization, replay checks and TUN write succeeded.
pub(super) fn payload(swarm: &mut Swarm<Behaviour>, peer: Libp2pPeerId, id: ConnectionId) {
    let mut state =
        std::mem::take(&mut swarm.behaviour_mut().connection_retention.preferred_handoff);
    if let Some(ticket) = state.peers.get_mut(&peer)
        && ticket.candidate == Some(id)
        && !ticket.payload
        && current(swarm, peer, ticket)
        && owns_candidate(swarm, peer, id, ticket)
    {
        ticket.payload = true;
        log_runtime_event(
            LogLevel::Info,
            "preferred_handoff_payload_verified",
            &[
                ("peer", &peer.to_string()),
                ("connection_id", &id.to_string()),
                ("outer", &ticket.outer.to_string()),
            ],
        );
    }
    swarm.behaviour_mut().connection_retention.preferred_handoff = state;
}
