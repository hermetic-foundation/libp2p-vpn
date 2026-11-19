//! WebRTC Direct r2 credential validation before allocating a peer connection.
//! https://github.com/libp2p/specs/blob/master/webrtc/webrtc-direct.md
pub(crate) struct IncomingIce<'a> {
    pub server_ufrag: &'a str,
    pub client_ufrag: &'a str,
    pub client_password: &'a str,
}

fn ice_chars(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

impl<'a> IncomingIce<'a> {
    pub(crate) fn parse(username: &'a str) -> Result<Self, &'static str> {
        let (server, client) = username
            .split_once(':')
            .ok_or("missing ICE username separator")?;
        if !ice_chars(server, 4, 256) || !ice_chars(client, 4, 256) {
            return Err("invalid ICE username fragment");
        }
        let password = if let Some(password) = server.strip_prefix("libp2p+webrtc+v2/") {
            if !ice_chars(password, 22, 256) {
                return Err("invalid v2 client password");
            }
            password
        } else if server.starts_with("libp2p+webrtc+v1/")
            && server == client
            && ice_chars(server, 22, 256)
        {
            server
        } else {
            return Err("unsupported WebRTC Direct version or mismatched v1 credentials");
        };
        Ok(Self {
            server_ufrag: server,
            client_ufrag: client,
            client_password: password,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_v2_password_and_separate_client_ufrag() {
        let parsed = IncomingIce::parse("libp2p+webrtc+v2/abcdefghijklmnopqrstuv:abcd").unwrap();
        assert_eq!(parsed.client_password, "abcdefghijklmnopqrstuv");
        assert_eq!(parsed.client_ufrag, "abcd");
        assert_eq!(
            parsed.server_ufrag,
            "libp2p+webrtc+v2/abcdefghijklmnopqrstuv"
        );
    }

    #[test]
    fn retains_v1_compatibility() {
        let frag = "libp2p+webrtc+v1/abcdefghijklmnopqrstuv";
        let username = format!("{frag}:{frag}");
        let parsed = IncomingIce::parse(&username).unwrap();
        assert_eq!(parsed.client_password, frag);
    }

    #[test]
    fn rejects_injection_unknown_versions_and_incomplete_credentials() {
        for username in [
            "libp2p+webrtc+v2/short:abcd",
            "libp2p+webrtc+v3/abcdefghijklmnopqrstuv:abcd",
            "abcdefghijklmnopqrstuv:abcd",
            "libp2p+webrtc+v2/abcdefghijklmnopqrstuv:abc\r\na=ice-lite",
            "libp2p+webrtc+v2/abcdefghijklmnopqrstuv:abcd:efgh",
            "libp2p+webrtc+v1/abcdefghijklmnopqrstuv:other",
        ] {
            assert!(IncomingIce::parse(username).is_err(), "{username:?}");
        }
        let oversized = format!("libp2p+webrtc+v2/{}:abcd", "a".repeat(256));
        assert!(IncomingIce::parse(&oversized).is_err());
    }
}
