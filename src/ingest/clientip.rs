//! Real client address behind (optional) reverse proxies.

use std::net::IpAddr;

use axum::http::HeaderMap;

/// `X-Forwarded-For` is only believed when the TCP peer is a configured
/// trusted proxy, and then only the right-most address that is not itself a
/// trusted proxy counts (anything to its left is attacker-controlled).
pub fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &[IpAddr]) -> IpAddr {
    let peer = peer.to_canonical();
    let is_trusted = |ip: IpAddr| trusted.iter().any(|t| t.to_canonical() == ip);

    if !is_trusted(peer) {
        return peer;
    }

    let hops: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .collect();

    for hop in hops.into_iter().rev() {
        match hop.parse::<IpAddr>() {
            Ok(ip) => {
                let ip = ip.to_canonical();
                if !is_trusted(ip) {
                    return ip;
                }
            }
            // Can't make sense of the chain; don't guess.
            Err(_) => return peer,
        }
    }
    peer
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn headers(xff: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in xff {
            h.append("x-forwarded-for", v.parse().unwrap());
        }
        h
    }

    #[test]
    fn untrusted_peer_cannot_spoof() {
        let h = headers(&["1.2.3.4"]);
        assert_eq!(
            client_ip(ip("9.9.9.9"), &h, &[ip("10.0.0.1")]),
            ip("9.9.9.9")
        );
        assert_eq!(client_ip(ip("9.9.9.9"), &h, &[]), ip("9.9.9.9"));
    }

    #[test]
    fn trusted_proxy_forwards_client() {
        let h = headers(&["1.2.3.4"]);
        assert_eq!(
            client_ip(ip("10.0.0.1"), &h, &[ip("10.0.0.1")]),
            ip("1.2.3.4")
        );
    }

    #[test]
    fn spoofed_left_entries_are_ignored() {
        // Client sent "6.6.6.6"; our proxy appended the real peer 1.2.3.4.
        let h = headers(&["6.6.6.6, 1.2.3.4"]);
        assert_eq!(
            client_ip(ip("10.0.0.1"), &h, &[ip("10.0.0.1")]),
            ip("1.2.3.4")
        );
    }

    #[test]
    fn skips_chained_trusted_proxies() {
        let h = headers(&["1.2.3.4", "10.0.0.2"]);
        let trusted = [ip("10.0.0.1"), ip("10.0.0.2")];
        assert_eq!(client_ip(ip("10.0.0.1"), &h, &trusted), ip("1.2.3.4"));
    }

    #[test]
    fn garbage_falls_back_to_peer() {
        let h = headers(&["not-an-ip"]);
        assert_eq!(
            client_ip(ip("10.0.0.1"), &h, &[ip("10.0.0.1")]),
            ip("10.0.0.1")
        );
        assert_eq!(
            client_ip(ip("10.0.0.1"), &HeaderMap::new(), &[ip("10.0.0.1")]),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn ipv4_mapped_addresses_are_canonicalized() {
        assert_eq!(
            client_ip(ip("::ffff:1.2.3.4"), &HeaderMap::new(), &[]),
            ip("1.2.3.4")
        );
    }
}
