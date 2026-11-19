use std::net::SocketAddr;

use libp2p_identity::{Keypair, PeerId};
use libp2p_webrtc_utils::{noise, Fingerprint};
use send_wrapper::SendWrapper;

use super::Error;
use crate::{connection::RtcPeerConnection, error::AuthenticationError, sdp, Connection};

/// Upgrades an outbound WebRTC connection by creating the data channel
/// and conducting a Noise handshake
pub(crate) async fn outbound(
    sock_addr: SocketAddr,
    remote_fingerprint: Fingerprint,
    id_keys: Keypair,
) -> Result<(PeerId, Connection), Error> {
    let fut = SendWrapper::new(outbound_inner(sock_addr, remote_fingerprint, id_keys));
    fut.await
}

/// Inner outbound function that is wrapped in [SendWrapper]
async fn outbound_inner(
    sock_addr: SocketAddr,
    remote_fingerprint: Fingerprint,
    id_keys: Keypair,
) -> Result<(PeerId, Connection), Error> {
    let rtc_peer_connection = RtcPeerConnection::new(remote_fingerprint.algorithm()).await?;

    // Create stream for Noise handshake
    // Must create data channel before Offer is created for it to be included in the SDP
    let (channel, listener) = rtc_peer_connection.new_handshake_stream();
    drop(listener);

    let offer = rtc_peer_connection.create_offer().await?;
    // WebRTC Direct r2: leave browser-generated local credentials untouched.
    let local_offer = web_sys::RtcSessionDescriptionInit::new(web_sys::RtcSdpType::Offer);
    local_offer.set_sdp(&offer);
    rtc_peer_connection
        .set_local_description(local_offer)
        .await?;

    let ufrag = format!("libp2p+webrtc+v2/{}", rtc_peer_connection.local_ice_password()?);
    let answer = sdp::answer(sock_addr, remote_fingerprint, &ufrag);
    rtc_peer_connection.set_remote_description(answer).await?;

    let local_fingerprint = rtc_peer_connection.local_fingerprint()?;

    tracing::trace!(?local_fingerprint);
    tracing::trace!(?remote_fingerprint);

    let peer_id = noise::outbound(id_keys, channel, remote_fingerprint, local_fingerprint)
        .await
        .map_err(AuthenticationError)?;

    tracing::debug!(peer=%peer_id, "Remote peer identified");

    Ok((peer_id, Connection::new(rtc_peer_connection)))
}
