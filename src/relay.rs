//! Framing between a leaf and `zsyncd` (inside TLS).
//! Distinct magic from the LAN ZSYN protocol so the two cannot be mixed up.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol::{ProtoError, MAX_FRAME};

pub const MAGIC: u32 = 0x5A53_5952; // "ZSYR"
pub const VERSION: u8 = 1;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Join = 1,
    JoinAck = 2,
    Data = 3,
    Ping = 4,
    Pong = 5,
    Error = 7,
    Bye = 8,
}

impl Type {
    pub fn from_u8(v: u8) -> Result<Self, ProtoError> {
        Ok(match v {
            1 => Self::Join,
            2 => Self::JoinAck,
            3 => Self::Data,
            4 => Self::Ping,
            5 => Self::Pong,
            7 => Self::Error,
            8 => Self::Bye,
            other => return Err(ProtoError::UnknownType(other)),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Join {
    pub group_id: String,
    pub device_id: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinAck {
    pub ok: bool,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMsg {
    pub code: String,
    pub message: String,
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    typ: Type,
    payload: &[u8],
) -> Result<(), ProtoError> {
    if payload.len() > MAX_FRAME {
        return Err(ProtoError::TooLarge);
    }
    let mut buf = Vec::with_capacity(10 + payload.len());
    buf.extend_from_slice(&MAGIC.to_be_bytes());
    buf.push(VERSION);
    buf.push(typ as u8);
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
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

pub async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<(Type, Vec<u8>), ProtoError> {
    let mut hdr = [0u8; 10];
    r.read_exact(&mut hdr).await?;
    let magic = u32::from_be_bytes(hdr[0..4].try_into().unwrap());
    if magic != MAGIC {
        return Err(ProtoError::BadMagic);
    }
    if hdr[4] != VERSION {
        return Err(ProtoError::BadVersion(hdr[4]));
    }
    let typ = Type::from_u8(hdr[5])?;
    let n = u32::from_be_bytes(hdr[6..10].try_into().unwrap()) as usize;
    if n > MAX_FRAME {
        return Err(ProtoError::TooLarge);
    }
    let mut payload = vec![0u8; n];
    if n > 0 {
        r.read_exact(&mut payload).await?;
    }
    Ok((typ, payload))
}

pub fn encode_error(code: &str, message: &str) -> Vec<u8> {
    serde_json::to_vec(&ErrorMsg {
        code: code.into(),
        message: message.into(),
    })
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_join() {
        let join = Join {
            group_id: "aa".repeat(16),
            device_id: "bb".repeat(16),
            hostname: "box".into(),
            version: "0.1".into(),
        };
        let mut buf = Vec::new();
        write_json(&mut buf, Type::Join, &join).await.unwrap();
        let (typ, payload) = read_frame(&mut buf.as_slice()).await.unwrap();
        assert_eq!(typ, Type::Join);
        let back: Join = serde_json::from_slice(&payload).unwrap();
        assert_eq!(back.group_id, join.group_id);
        assert_eq!(back.device_id, join.device_id);
    }
}
