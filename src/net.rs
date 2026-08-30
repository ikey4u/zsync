//! TCP transport. Daemon listens; `zsync connect host[:port]` dials.
//! `zsync://` URIs go through the encrypted relay (`zsyncd`).

use std::path::Path;

use anyhow::{bail, Context, Result};
use tokio::net::{TcpListener, TcpStream};

use crate::group::{self, GroupUri, GROUP_KEY_LEN};

pub const DEFAULT_PORT: u16 = 43721;

#[derive(Debug, Clone)]
pub struct RelayPeer {
    pub group_id: [u8; 16],
    pub key: Option<[u8; GROUP_KEY_LEN]>,
}

#[derive(Debug, Clone)]
pub struct PeerTarget {
    /// Canonical id in state.json. Relay URIs never include the key.
    pub uri: String,
    pub host: String,
    pub port: u16,
    pub relay: Option<RelayPeer>,
}

pub fn listen_port() -> u16 {
    std::env::var("ZSYNC_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&p| p != 0)
        .unwrap_or(DEFAULT_PORT)
}

pub async fn bind_listener(port: u16) -> Result<TcpListener> {
    TcpListener::bind(("0.0.0.0", port))
        .await
        .with_context(|| format!("bind 0.0.0.0:{port}"))
}

pub async fn connect_peer(target: &PeerTarget) -> Result<TcpStream> {
    let stream = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .with_context(|| format!("connect {}:{}", target.host, target.port))?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

pub fn parse_peer(raw: &str) -> Result<PeerTarget> {
    let raw: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    if raw.is_empty() {
        bail!("empty peer address");
    }
    if raw.starts_with("ssh://") {
        bail!("ssh:// is no longer supported; use `zsync connect <ip>`");
    }
    if raw.starts_with("iroh://") || raw.starts_with("endpoint") {
        bail!("iroh is gone; use `zsync connect <ip>`");
    }
    if raw.starts_with("zsync://") {
        let g = group::parse_group_uri(&raw)?;
        return Ok(peer_from_group(g));
    }
    let s = raw.strip_prefix("tcp://").unwrap_or(&raw);
    let (host, port) = split_host_port(s)?;
    if host.is_empty() {
        bail!("missing host");
    }
    Ok(PeerTarget {
        uri: format_host_port(&host, port),
        host,
        port,
        relay: None,
    })
}

fn peer_from_group(g: GroupUri) -> PeerTarget {
    PeerTarget {
        uri: g.redacted_uri(),
        host: g.host,
        port: g.port,
        relay: Some(RelayPeer {
            group_id: g.group_id,
            key: g.key,
        }),
    }
}

/// Persist a newly imported key, or load one for a redacted `zsync://` URI.
pub fn resolve_relay(zsync_dir: &Path, target: &mut PeerTarget) -> Result<()> {
    let Some(relay) = target.relay.as_mut() else {
        return Ok(());
    };
    if let Some(key) = relay.key {
        let g = GroupUri {
            group_id: relay.group_id,
            key: Some(key),
            host: target.host.clone(),
            port: target.port,
        };
        group::save_group_key(zsync_dir, &g)?;
    } else {
        relay.key = Some(group::load_group_key(zsync_dir, &relay.group_id)?);
    }
    Ok(())
}

pub fn display_uri(uri: &str) -> String {
    if let Ok(g) = group::parse_group_uri(uri) {
        g.redacted_uri()
    } else {
        uri.to_string()
    }
}

fn split_host_port(s: &str) -> Result<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, rest) =
            rest.split_once(']').context("unclosed '[' in address")?;
        if rest.is_empty() {
            return Ok((host.to_string(), DEFAULT_PORT));
        }
        let port = rest
            .strip_prefix(':')
            .context("expected :port after [...]")?;
        let port: u16 = port.parse().context("invalid port")?;
        return Ok((host.to_string(), port));
    }
    match s.rfind(':') {
        Some(i) if s[..i].contains(':') => Ok((s.to_string(), DEFAULT_PORT)),
        Some(i) => {
            let host = s[..i].to_string();
            let port: u16 = s[i + 1..].parse().context("invalid port")?;
            Ok((host, port))
        }
        None => Ok((s.to_string(), DEFAULT_PORT)),
    }
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage() {
        assert!(parse_peer("").is_err());
        assert!(parse_peer("ssh://box").is_err());
        assert!(parse_peer("iroh://abc").is_err());
    }

    #[test]
    fn parses_ip_default_port() {
        let t = parse_peer("192.168.1.5").unwrap();
        assert_eq!(t.host, "192.168.1.5");
        assert_eq!(t.port, DEFAULT_PORT);
        assert_eq!(t.uri, format!("192.168.1.5:{DEFAULT_PORT}"));
        assert!(t.relay.is_none());
    }

    #[test]
    fn parses_ip_port_and_tcp_prefix() {
        let a = parse_peer("10.0.0.2:9").unwrap();
        let b = parse_peer("tcp://10.0.0.2:9").unwrap();
        assert_eq!(a.uri, "10.0.0.2:9");
        assert_eq!(b.uri, "10.0.0.2:9");
    }

    #[test]
    fn parses_hostname_and_ipv6() {
        let h = parse_peer("box.lan").unwrap();
        assert_eq!(h.uri, format!("box.lan:{DEFAULT_PORT}"));
        let v6 = parse_peer("[::1]:43721").unwrap();
        assert_eq!(v6.host, "::1");
        assert_eq!(v6.port, 43721);
        assert_eq!(v6.uri, "[::1]:43721");
    }

    #[test]
    fn parses_zsync_uri_and_redacts_key() {
        let secret = crate::group::generate_secret();
        let gid = crate::group::group_id_from_secret(&secret);
        let g = crate::group::GroupUri {
            group_id: gid,
            key: Some(secret),
            host: "8.8.8.8".into(),
            port: 43721,
        };
        let full = g.to_uri().unwrap();
        let t = parse_peer(&full).unwrap();
        assert!(t.relay.is_some());
        assert_eq!(t.uri, g.redacted_uri());
        assert_eq!(t.host, "8.8.8.8");
        assert_eq!(t.relay.unwrap().key, Some(secret));
    }
}
