//! Group credentials, zsync:// URIs, and AEAD for clip payloads.
//!
//! `zsyncd` creates the secret, prints a URI, then forgets the key.
//! Leaves import the URI; the relay only ever sees `group_id`.

use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::net::DEFAULT_PORT;

pub const GROUP_ID_LEN: usize = 16;
pub const GROUP_KEY_LEN: usize = 32;
pub const SENDER_LEN: usize = 16;
const HKDF_INFO: &[u8] = b"zsync-clip-v1";
const GID_SALT: &[u8] = b"zsync-gid";
const ENVELOPE_VER: u8 = 1;

#[derive(Debug, Clone)]
pub struct GroupUri {
    pub group_id: [u8; GROUP_ID_LEN],
    pub key: Option<[u8; GROUP_KEY_LEN]>,
    pub host: String,
    pub port: u16,
}

impl GroupUri {
    pub fn group_id_hex(&self) -> String {
        hex_encode(&self.group_id)
    }

    pub fn hub_addr(&self) -> String {
        format_host_port(&self.host, self.port)
    }

    pub fn redacted_uri(&self) -> String {
        format!(
            "zsync://{}@{}",
            hex_encode(&self.group_id),
            format_host_port(&self.host, self.port)
        )
    }

    pub fn to_uri(&self) -> Result<String> {
        let key = self.key.context("group key missing")?;
        let key = URL_SAFE_NO_PAD.encode(key);
        Ok(format!(
            "zsync://{}:{key}@{}",
            hex_encode(&self.group_id),
            format_host_port(&self.host, self.port)
        ))
    }
}

pub fn generate_secret() -> [u8; GROUP_KEY_LEN] {
    let mut key = [0u8; GROUP_KEY_LEN];
    getrandom::getrandom(&mut key).expect("getrandom");
    key
}

pub fn group_id_from_secret(
    secret: &[u8; GROUP_KEY_LEN],
) -> [u8; GROUP_ID_LEN] {
    let mut h = Sha256::new();
    h.update(GID_SALT);
    h.update(secret);
    let out = h.finalize();
    let mut id = [0u8; GROUP_ID_LEN];
    id.copy_from_slice(&out[..GROUP_ID_LEN]);
    id
}

pub fn parse_group_uri(raw: &str) -> Result<GroupUri> {
    let raw: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    let rest = raw
        .strip_prefix("zsync://")
        .context("expected zsync:// URI")?;
    let (creds, hostport) = rest
        .rsplit_once('@')
        .context("zsync:// URI missing @host")?;
    let (gid_hex, key) = if let Some((gid, key_b64)) = creds.split_once(':') {
        let key_bytes = URL_SAFE_NO_PAD
            .decode(key_b64)
            .context("decode group key")?;
        if key_bytes.len() != GROUP_KEY_LEN {
            bail!("group key must be {GROUP_KEY_LEN} bytes");
        }
        let mut key = [0u8; GROUP_KEY_LEN];
        key.copy_from_slice(&key_bytes);
        (gid, Some(key))
    } else {
        (creds, None)
    };
    let group_id = parse_group_id(gid_hex)?;
    let (host, port) = split_host_port(hostport)?;
    if host.is_empty() || host == "0.0.0.0" || host == "::" {
        bail!("zsync:// host cannot be unspecified ({host})");
    }
    Ok(GroupUri {
        group_id,
        key,
        host,
        port,
    })
}

pub fn parse_group_id(s: &str) -> Result<[u8; GROUP_ID_LEN]> {
    let s = s.trim();
    if s.len() != GROUP_ID_LEN * 2 || !s.bytes().all(|b| b.is_ascii_hexdigit())
    {
        bail!("group_id must be {} hex chars", GROUP_ID_LEN * 2);
    }
    let mut id = [0u8; GROUP_ID_LEN];
    for i in 0..GROUP_ID_LEN {
        id[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(id)
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

pub fn sender_from_node_id(node_id: &str) -> Result<[u8; SENDER_LEN]> {
    let s = node_id.trim();
    if s.len() < SENDER_LEN * 2 {
        bail!("node_id too short");
    }
    let mut id = [0u8; SENDER_LEN];
    for i in 0..SENDER_LEN {
        id[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(id)
}

#[derive(Debug, Serialize, Deserialize)]
struct GroupFile {
    key: String,
    host: String,
    port: u16,
}

pub fn groups_dir(zsync_dir: &Path) -> std::path::PathBuf {
    zsync_dir.join("groups")
}

pub fn save_group_key(zsync_dir: &Path, uri: &GroupUri) -> Result<()> {
    let key = uri.key.context("cannot save group without key")?;
    let dir = groups_dir(zsync_dir);
    fs::create_dir_all(&dir)
        .with_context(|| format!("mkdir {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    let path = dir.join(format!("{}.json", uri.group_id_hex()));
    let rec = GroupFile {
        key: URL_SAFE_NO_PAD.encode(key),
        host: uri.host.clone(),
        port: uri.port,
    };
    fs::write(&path, serde_json::to_vec_pretty(&rec)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn load_group_key(
    zsync_dir: &Path,
    group_id: &[u8; GROUP_ID_LEN],
) -> Result<[u8; GROUP_KEY_LEN]> {
    let path =
        groups_dir(zsync_dir).join(format!("{}.json", hex_encode(group_id)));
    let rec: GroupFile =
        serde_json::from_slice(&fs::read(&path).with_context(|| {
            format!(
                "missing group key {}; import the full zsync:// URI first",
                hex_encode(group_id)
            )
        })?)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(rec.key)
        .context("decode saved key")?;
    if bytes.len() != GROUP_KEY_LEN {
        bail!("saved group key has wrong length");
    }
    let mut key = [0u8; GROUP_KEY_LEN];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn aead_key(secret: &[u8; GROUP_KEY_LEN]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut out = [0u8; 32];
    hk.expand(HKDF_INFO, &mut out)
        .map_err(|_| anyhow::anyhow!("hkdf expand"))?;
    Ok(out)
}

pub fn seal(
    secret: &[u8; GROUP_KEY_LEN],
    group_id: &[u8; GROUP_ID_LEN],
    sender: &[u8; SENDER_LEN],
    counter: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new((&aead_key(secret)?).into());
    let mut nonce_bytes = [0u8; 24];
    getrandom::getrandom(&mut nonce_bytes).expect("getrandom");
    let nonce = XNonce::from(nonce_bytes);
    let mut ad = Vec::with_capacity(GROUP_ID_LEN + SENDER_LEN + 8);
    ad.extend_from_slice(group_id);
    ad.extend_from_slice(sender);
    ad.extend_from_slice(&counter.to_be_bytes());
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &ad,
            },
        )
        .map_err(|_| anyhow::anyhow!("encrypt clip"))?;
    let mut out = Vec::with_capacity(1 + SENDER_LEN + 8 + 24 + ct.len());
    out.push(ENVELOPE_VER);
    out.extend_from_slice(sender);
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub struct Opened {
    pub sender: [u8; SENDER_LEN],
    pub counter: u64,
    pub plaintext: Vec<u8>,
}

pub fn open(
    secret: &[u8; GROUP_KEY_LEN],
    group_id: &[u8; GROUP_ID_LEN],
    envelope: &[u8],
) -> Result<Opened> {
    if envelope.len() < 1 + SENDER_LEN + 8 + 24 + 16 {
        bail!("truncated envelope");
    }
    if envelope[0] != ENVELOPE_VER {
        bail!("unsupported envelope version {}", envelope[0]);
    }
    let mut sender = [0u8; SENDER_LEN];
    sender.copy_from_slice(&envelope[1..1 + SENDER_LEN]);
    let counter = u64::from_be_bytes(
        envelope[1 + SENDER_LEN..1 + SENDER_LEN + 8]
            .try_into()
            .unwrap(),
    );
    let nonce_off = 1 + SENDER_LEN + 8;
    let nonce = XNonce::from(
        <[u8; 24]>::try_from(&envelope[nonce_off..nonce_off + 24]).unwrap(),
    );
    let ct = &envelope[nonce_off + 24..];
    let cipher = XChaCha20Poly1305::new((&aead_key(secret)?).into());
    let mut ad = Vec::with_capacity(GROUP_ID_LEN + SENDER_LEN + 8);
    ad.extend_from_slice(group_id);
    ad.extend_from_slice(&sender);
    ad.extend_from_slice(&counter.to_be_bytes());
    let plaintext = cipher
        .decrypt(&nonce, Payload { msg: ct, aad: &ad })
        .map_err(|_| {
            anyhow::anyhow!("decrypt clip (wrong group or corrupt)")
        })?;
    Ok(Opened {
        sender,
        counter,
        plaintext,
    })
}

pub fn is_globally_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => is_public_v4(v),
        IpAddr::V6(v) => is_public_v6(v),
    }
}

fn is_public_v4(v: Ipv4Addr) -> bool {
    // CGNAT 100.64.0.0/10
    let cgnat = v.octets()[0] == 100 && (v.octets()[1] & 0xc0) == 64;
    !(v.is_unspecified()
        || v.is_loopback()
        || v.is_private()
        || v.is_link_local()
        || v.is_broadcast()
        || v.is_documentation()
        || cgnat)
}

fn is_public_v6(v: Ipv6Addr) -> bool {
    let segs = v.segments();
    if v.is_unspecified() || v.is_loopback() {
        return false;
    }
    if segs[0] & 0xffc0 == 0xfe80 {
        return false;
    }
    if segs[0] & 0xfe00 == 0xfc00 {
        return false;
    }
    true
}

pub fn warn_if_not_public(host: &str) {
    let Ok(ip) = host.parse::<IpAddr>() else {
        return;
    };
    if !is_globally_routable(ip) {
        eprintln!("warning: {host} 看起来不是公网地址，NAT 后的设备可能连不上");
    }
}

pub fn detect_advertise_ip() -> Option<IpAddr> {
    use std::net::UdpSocket;
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    let ip = sock.local_addr().ok()?.ip();
    if ip.is_unspecified() || ip.is_loopback() {
        None
    } else {
        Some(ip)
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
        Some(i) if !s[..i].contains(':') => {
            let host = s[..i].to_string();
            let port: u16 = s[i + 1..].parse().context("invalid port")?;
            Ok((host, port))
        }
        _ => Ok((s.to_string(), DEFAULT_PORT)),
    }
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_roundtrip() {
        let secret = generate_secret();
        let gid = group_id_from_secret(&secret);
        let g = GroupUri {
            group_id: gid,
            key: Some(secret),
            host: "8.8.8.8".into(),
            port: 43721,
        };
        let uri = g.to_uri().unwrap();
        assert!(uri.starts_with("zsync://"));
        let back = parse_group_uri(&uri).unwrap();
        assert_eq!(back.group_id, gid);
        assert_eq!(back.key, Some(secret));
        assert_eq!(back.host, "8.8.8.8");
        assert_eq!(back.port, 43721);
        let redacted = parse_group_uri(&g.redacted_uri()).unwrap();
        assert_eq!(redacted.group_id, gid);
        assert!(redacted.key.is_none());
    }

    #[test]
    fn uri_ipv6() {
        let secret = generate_secret();
        let g = GroupUri {
            group_id: group_id_from_secret(&secret),
            key: Some(secret),
            host: "2001:db8::1".into(),
            port: 43721,
        };
        let back = parse_group_uri(&g.to_uri().unwrap()).unwrap();
        assert_eq!(back.host, "2001:db8::1");
        assert_eq!(back.port, 43721);
    }

    #[test]
    fn seal_open() {
        let secret = generate_secret();
        let gid = group_id_from_secret(&secret);
        let sender = [7u8; 16];
        let env = seal(&secret, &gid, &sender, 3, b"hello").unwrap();
        let opened = open(&secret, &gid, &env).unwrap();
        assert_eq!(opened.sender, sender);
        assert_eq!(opened.counter, 3);
        assert_eq!(opened.plaintext, b"hello");
        let other = generate_secret();
        assert!(open(&other, &gid, &env).is_err());
    }

    #[test]
    fn rejects_unspecified_host() {
        let secret = generate_secret();
        let g = GroupUri {
            group_id: group_id_from_secret(&secret),
            key: Some(secret),
            host: "0.0.0.0".into(),
            port: 43721,
        };
        assert!(parse_group_uri(&g.to_uri().unwrap()).is_err());
    }

    #[test]
    fn private_ip_not_public() {
        assert!(!is_globally_routable("192.168.1.1".parse().unwrap()));
        assert!(!is_globally_routable("10.0.0.1".parse().unwrap()));
        assert!(!is_globally_routable("127.0.0.1".parse().unwrap()));
        assert!(!is_globally_routable("0.0.0.0".parse().unwrap()));
        assert!(!is_globally_routable("169.254.1.1".parse().unwrap()));
        assert!(!is_globally_routable("fe80::1".parse().unwrap()));
        assert!(!is_globally_routable("fc00::1".parse().unwrap()));
        assert!(is_globally_routable("8.8.8.8".parse().unwrap()));
    }
}
