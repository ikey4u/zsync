//! P2P transport: iroh QUIC + hole punching, with encrypted relay fallback.
//!
//! Dial by ticket / endpoint id. Same-LAN and most home NATs go direct UDP.
//! Symmetric NAT keeps the session on a relay; relays only forward ciphertext.

use std::{path::Path, str::FromStr, time::Duration};

use anyhow::{bail, Context, Result};
use iroh::{endpoint::presets, Endpoint, EndpointAddr, EndpointId, SecretKey};
use iroh_tickets::endpoint::EndpointTicket;

pub const ALPN: &[u8] = b"zsync/1";

#[derive(Debug, Clone)]
pub struct PeerTarget {
    /// Canonical key used in state.json / peer map.
    pub uri: String,
    pub addr: EndpointAddr,
    pub endpoint_id: EndpointId,
}

pub fn load_or_create_secret(path: &Path) -> Result<SecretKey> {
    if let Ok(s) = std::fs::read_to_string(path) {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return trimmed
                .parse::<SecretKey>()
                .or_else(|_| secret_from_hex(trimmed))
                .context("parse zsync secret key");
        }
    }
    let key = SecretKey::generate();
    let encoded = hex32(&key.to_bytes());
    std::fs::write(path, format!("{encoded}\n"))
        .with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(0o600),
        );
    }
    Ok(key)
}

fn secret_from_hex(s: &str) -> Result<SecretKey> {
    let bytes = decode_hex32(s)?;
    Ok(SecretKey::from_bytes(&bytes))
}

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn decode_hex32(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("secret key must be 64 hex chars");
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}

pub fn endpoint_id_string(id: EndpointId) -> String {
    id.to_string()
}

pub fn iroh_uri(id: EndpointId) -> String {
    format!("iroh://{id}")
}

pub async fn bind_endpoint(secret: SecretKey) -> Result<Endpoint> {
    Endpoint::builder(presets::N0)
        .secret_key(secret)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .context("bind iroh endpoint")
}

pub async fn wait_online(ep: &Endpoint) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(8), ep.online())
        .await
        .context("waiting for iroh endpoint to come online")?;
    Ok(())
}

pub fn ticket_for(ep: &Endpoint) -> String {
    EndpointTicket::new(ep.addr()).to_string()
}

pub fn parse_peer(raw: &str) -> Result<PeerTarget> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("empty peer address");
    }
    if raw.starts_with("ssh://") {
        bail!("ssh:// is no longer supported; use `zsync pair` / `zsync connect <ticket>`");
    }
    if let Some(rest) = raw.strip_prefix("iroh://") {
        let id: EndpointId = rest
            .parse()
            .with_context(|| format!("bad iroh endpoint id: {rest}"))?;
        return Ok(PeerTarget {
            uri: iroh_uri(id),
            addr: EndpointAddr::from(id),
            endpoint_id: id,
        });
    }
    if let Ok(ticket) = EndpointTicket::from_str(raw) {
        let addr = ticket.endpoint_addr().clone();
        let id = addr.id;
        return Ok(PeerTarget {
            uri: raw.to_string(),
            addr,
            endpoint_id: id,
        });
    }
    if let Ok(id) = raw.parse::<EndpointId>() {
        return Ok(PeerTarget {
            uri: iroh_uri(id),
            addr: EndpointAddr::from(id),
            endpoint_id: id,
        });
    }
    bail!("peer must be an iroh ticket or iroh://<endpoint-id>");
}

pub fn should_dial(local_id: &str, remote: EndpointId, force: bool) -> bool {
    if force {
        return true;
    }
    local_id < endpoint_id_string(remote).as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage() {
        assert!(parse_peer("").is_err());
        assert!(parse_peer("http://example").is_err());
        assert!(parse_peer("ssh://box").is_err());
    }

    #[test]
    fn hex_roundtrip_secret() {
        let key = SecretKey::generate();
        let hex = hex32(&key.to_bytes());
        let back = secret_from_hex(&hex).unwrap();
        assert_eq!(key.public(), back.public());
    }
}
