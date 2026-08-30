use std::io;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAGIC: u32 = 0x5A53_594E; // "ZSYN"
pub const VERSION: u8 = 1;
pub const MAX_CLIP: usize = 10 * 1024 * 1024;
pub const MAX_FRAME: usize = MAX_CLIP + 64 * 1024;
pub const MAX_META: usize = 16 * 1024;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("bad magic")]
    BadMagic,
    #[error("unsupported protocol version {0}")]
    BadVersion(u8),
    #[error("frame exceeds 10MiB limit")]
    TooLarge,
    #[error("invalid clip meta")]
    BadMeta,
    #[error("clip size mismatch ({got} != {want})")]
    SizeMismatch { got: usize, want: usize },
    #[error("clip hash mismatch")]
    HashMismatch,
    #[error("unknown frame type {0}")]
    UnknownType(u8),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Hello = 1,
    HelloAck = 2,
    Ping = 3,
    Pong = 4,
    Clip = 5,
    ClipAck = 6,
    Error = 7,
    Bye = 8,
}

impl Type {
    pub fn from_u8(v: u8) -> Result<Self, ProtoError> {
        Ok(match v {
            1 => Self::Hello,
            2 => Self::HelloAck,
            3 => Self::Ping,
            4 => Self::Pong,
            5 => Self::Clip,
            6 => Self::ClipAck,
            7 => Self::Error,
            8 => Self::Bye,
            other => return Err(ProtoError::UnknownType(other)),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub node_id: String,
    pub hostname: String,
    pub os: String,
    pub headless: bool,
    pub version: String,
    pub max_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipMeta {
    pub origin_id: String,
    pub seq: u64,
    pub mime: String,
    pub hash: String,
    pub size: usize,
    /// Original filename when the clip is a copied file (basename only).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct Clip {
    pub meta: ClipMeta,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipAck {
    pub hash: String,
    pub ok: bool,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMsg {
    pub code: String,
    pub message: String,
}

pub fn hash(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex_encode(&h.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

pub fn new_node_id() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("getrandom");
    hex_encode(&b)
}

pub fn detect_mime(data: &[u8]) -> String {
    if data.len() >= 8 && data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return "image/png".into();
    }
    if data.len() >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff
    {
        return "image/jpeg".into();
    }
    if data.len() >= 4 && data.starts_with(b"GIF8") {
        return "image/gif".into();
    }
    if data.starts_with(b"%PDF") {
        return "application/pdf".into();
    }
    if data.is_empty()
        || (std::str::from_utf8(data).is_ok() && !data.contains(&0))
    {
        return "text/plain".into();
    }
    "application/octet-stream".into()
}

pub fn mime_from_filename(name: &str) -> Option<&'static str> {
    let ext = std::path::Path::new(name)
        .extension()?
        .to_str()?
        .to_ascii_lowercase();
    Some(match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "json" => "application/json",
        "txt" | "md" | "rs" | "toml" | "py" | "sh" | "c" | "h" | "go"
        | "ts" | "js" => "text/plain",
        "html" | "htm" => "text/html",
        "csv" => "text/csv",
        "mp4" => "video/mp4",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        _ => return None,
    })
}

pub fn ext_for_mime(mime: &str) -> &'static str {
    if mime.starts_with("image/png") {
        ".png"
    } else if mime.starts_with("image/jpeg") || mime.starts_with("image/jpg") {
        ".jpg"
    } else if mime.starts_with("image/gif") {
        ".gif"
    } else if mime.starts_with("image/webp") {
        ".webp"
    } else if mime.starts_with("application/pdf") {
        ".pdf"
    } else if mime.starts_with("application/zip") {
        ".zip"
    } else if mime.starts_with("text/plain") {
        ".txt"
    } else if mime.starts_with("text/html") {
        ".html"
    } else {
        ".bin"
    }
}

pub fn encode_frame(typ: Type, payload: &[u8]) -> Result<Vec<u8>, ProtoError> {
    if payload.len() > MAX_FRAME {
        return Err(ProtoError::TooLarge);
    }
    let mut buf = Vec::with_capacity(10 + payload.len());
    buf.extend_from_slice(&MAGIC.to_be_bytes());
    buf.push(VERSION);
    buf.push(typ as u8);
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    Ok(buf)
}

pub fn encode_json<T: Serialize>(
    typ: Type,
    v: &T,
) -> Result<Vec<u8>, ProtoError> {
    encode_frame(typ, &serde_json::to_vec(v)?)
}

/// Clip body only (meta + bytes), used as AEAD plaintext on the relay path.
pub fn encode_clip_body(clip: &Clip) -> Result<Vec<u8>, ProtoError> {
    if clip.data.len() > MAX_CLIP {
        return Err(ProtoError::TooLarge);
    }
    let mut meta = clip.meta.clone();
    meta.size = clip.data.len();
    let meta_bytes = serde_json::to_vec(&meta)?;
    if meta_bytes.len() > MAX_META {
        return Err(ProtoError::BadMeta);
    }
    let mut payload =
        Vec::with_capacity(2 + meta_bytes.len() + clip.data.len());
    payload.extend_from_slice(&(meta_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(&meta_bytes);
    payload.extend_from_slice(&clip.data);
    Ok(payload)
}

pub fn encode_clip(clip: &Clip) -> Result<Vec<u8>, ProtoError> {
    encode_frame(Type::Clip, &encode_clip_body(clip)?)
}

pub fn decode_frame(buf: &[u8]) -> Result<(Type, Vec<u8>), ProtoError> {
    if buf.len() < 10 {
        return Err(ProtoError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short frame header",
        )));
    }
    let magic = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    if magic != MAGIC {
        return Err(ProtoError::BadMagic);
    }
    if buf[4] != VERSION {
        return Err(ProtoError::BadVersion(buf[4]));
    }
    let typ = Type::from_u8(buf[5])?;
    let n = u32::from_be_bytes(buf[6..10].try_into().unwrap()) as usize;
    if n > MAX_FRAME {
        return Err(ProtoError::TooLarge);
    }
    if buf.len() < 10 + n {
        return Err(ProtoError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short frame payload",
        )));
    }
    Ok((typ, buf[10..10 + n].to_vec()))
}

pub fn decode_clip(payload: &[u8]) -> Result<Clip, ProtoError> {
    if payload.len() < 2 {
        return Err(ProtoError::BadMeta);
    }
    let meta_len =
        u16::from_be_bytes(payload[0..2].try_into().unwrap()) as usize;
    if meta_len == 0 || meta_len > MAX_META || 2 + meta_len > payload.len() {
        return Err(ProtoError::BadMeta);
    }
    let meta: ClipMeta = serde_json::from_slice(&payload[2..2 + meta_len])?;
    let data = payload[2 + meta_len..].to_vec();
    if meta.size != data.len() {
        return Err(ProtoError::SizeMismatch {
            got: data.len(),
            want: meta.size,
        });
    }
    if data.len() > MAX_CLIP {
        return Err(ProtoError::TooLarge);
    }
    Ok(Clip { meta, data })
}

/// Full payload, matching size and SHA-256. Call before writing the clipboard.
pub fn verify_clip(clip: &Clip) -> Result<(), ProtoError> {
    if clip.data.len() > MAX_CLIP || clip.meta.size > MAX_CLIP {
        return Err(ProtoError::TooLarge);
    }
    if clip.meta.size != clip.data.len() {
        return Err(ProtoError::SizeMismatch {
            got: clip.data.len(),
            want: clip.meta.size,
        });
    }
    if clip.meta.hash.is_empty() || hash(&clip.data) != clip.meta.hash {
        return Err(ProtoError::HashMismatch);
    }
    Ok(())
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    typ: Type,
    payload: &[u8],
) -> Result<(), ProtoError> {
    let buf = encode_frame(typ, payload)?;
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

pub async fn write_json<W: AsyncWrite + Unpin, T: Serialize>(
    w: &mut W,
    typ: Type,
    v: &T,
) -> Result<(), ProtoError> {
    write_frame(w, typ, &serde_json::to_vec(v)?).await
}

pub async fn write_clip<W: AsyncWrite + Unpin>(
    w: &mut W,
    clip: &Clip,
) -> Result<(), ProtoError> {
    let buf = encode_clip(clip)?;
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<(Type, Vec<u8>), ProtoError> {
    let mut hdr = [0u8; 10];
    r.read_exact(&mut hdr).await?;
    let magic = {
        let mut m = [0u8; 4];
        m.copy_from_slice(&hdr[0..4]);
        u32::from_be_bytes(m)
    };
    if magic != MAGIC {
        return Err(ProtoError::BadMagic);
    }
    if hdr[4] != VERSION {
        return Err(ProtoError::BadVersion(hdr[4]));
    }
    let typ = Type::from_u8(hdr[5])?;
    let n = {
        let mut m = [0u8; 4];
        m.copy_from_slice(&hdr[6..10]);
        u32::from_be_bytes(m) as usize
    };
    if n > MAX_FRAME {
        return Err(ProtoError::TooLarge);
    }
    let mut payload = vec![0u8; n];
    if n > 0 {
        r.read_exact(&mut payload).await?;
    }
    Ok((typ, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_hello() {
        let hello = Hello {
            node_id: "abc".into(),
            hostname: "box".into(),
            os: "linux".into(),
            headless: true,
            version: "0.1.0".into(),
            max_bytes: MAX_CLIP,
        };
        let buf = encode_json(Type::Hello, &hello).unwrap();
        let (typ, payload) = decode_frame(&buf).unwrap();
        assert_eq!(typ, Type::Hello);
        let back: Hello = serde_json::from_slice(&payload).unwrap();
        assert_eq!(back.node_id, "abc");
        assert!(back.headless);
    }

    #[test]
    fn roundtrip_clip() {
        let data = b"hello clipboard".to_vec();
        let clip = Clip {
            meta: ClipMeta {
                origin_id: "n1".into(),
                seq: 7,
                mime: "text/plain".into(),
                hash: hash(&data),
                size: data.len(),
                name: String::new(),
            },
            data,
        };
        let buf = encode_clip(&clip).unwrap();
        let (typ, payload) = decode_frame(&buf).unwrap();
        assert_eq!(typ, Type::Clip);
        let back = decode_clip(&payload).unwrap();
        assert_eq!(back.meta.seq, 7);
        assert_eq!(back.data, b"hello clipboard");
        assert_eq!(back.meta.hash, clip.meta.hash);
    }

    #[test]
    fn rejects_truncated_or_corrupt_clip() {
        let data = b"hello clipboard".to_vec();
        let clip = Clip {
            meta: ClipMeta {
                origin_id: "n1".into(),
                seq: 1,
                mime: "text/plain".into(),
                hash: hash(&data),
                size: data.len(),
                name: String::new(),
            },
            data: data.clone(),
        };
        let mut payload = encode_clip_body(&clip).unwrap();
        payload.pop();
        assert!(matches!(
            decode_clip(&payload),
            Err(ProtoError::SizeMismatch { .. })
        ));
        let mut bad = clip.clone();
        bad.data[0] ^= 0xff;
        assert!(matches!(verify_clip(&bad), Err(ProtoError::HashMismatch)));
        let mut short = clip;
        short.data.pop();
        assert!(verify_clip(&short).is_err());
    }

    #[test]
    fn rejects_too_large() {
        let data = vec![0u8; MAX_CLIP + 1];
        let clip = Clip {
            meta: ClipMeta {
                origin_id: "n".into(),
                seq: 1,
                mime: "application/octet-stream".into(),
                hash: hash(&data),
                size: data.len(),
                name: String::new(),
            },
            data,
        };
        assert!(matches!(encode_clip(&clip), Err(ProtoError::TooLarge)));
    }

    #[test]
    fn mime_sniff() {
        assert_eq!(detect_mime(b"hi"), "text/plain");
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&[0; 8]);
        assert_eq!(detect_mime(&png), "image/png");
    }
}
