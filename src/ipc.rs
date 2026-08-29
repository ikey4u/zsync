use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
#[cfg(unix)]
use tokio::net::UnixStream;

use crate::{config::Paths, protocol::MAX_CLIP};

#[cfg(unix)]
pub type IpcStream = UnixStream;
#[cfg(windows)]
pub type IpcStream = NamedPipeClient;

pub fn pipe_name() -> String {
    r"\\.\pipe\zsync".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Request {
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(default)]
    pub n: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(default)]
    pub n: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headless: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
    #[serde(skip)]
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatusPayload {
    pub daemon_pid: u32,
    pub node_id: String,
    pub clipboard: String,
    pub headless: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_mime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
    #[serde(default)]
    pub peers: Vec<PeerStatus>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerStatus {
    pub uri: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sync: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

pub struct Connection {
    pub stream: IpcStream,
}

impl Connection {
    pub async fn roundtrip(
        &mut self,
        req: &Request,
        body: &[u8],
    ) -> Result<Response> {
        write_msg(&mut self.stream, req, body).await?;
        read_response(&mut self.stream).await
    }
}

pub async fn connect(paths: &Paths) -> Result<Connection> {
    #[cfg(unix)]
    {
        let stream = UnixStream::connect(&paths.sock)
            .await
            .with_context(|| format!("connect {}", paths.sock.display()))?;
        Ok(Connection { stream })
    }
    #[cfg(windows)]
    {
        let _ = paths;
        let stream = ClientOptions::new()
            .open(pipe_name())
            .with_context(|| format!("connect {}", pipe_name()))?;
        Ok(Connection { stream })
    }
}

pub async fn write_msg<W: AsyncWriteExt + Unpin, T: Serialize>(
    w: &mut W,
    header: &T,
    body: &[u8],
) -> Result<()> {
    if body.len() > MAX_CLIP {
        bail!("payload exceeds 10MiB");
    }
    let mut value = serde_json::to_value(header)?;
    if let Some(obj) = value.as_object_mut() {
        obj.insert("n".into(), serde_json::json!(body.len()));
    }
    let line = serde_json::to_string(&value)?;
    w.write_all(line.as_bytes()).await?;
    w.write_all(b"\n").await?;
    if !body.is_empty() {
        w.write_all(body).await?;
    }
    w.flush().await?;
    Ok(())
}

pub async fn read_header_body<R: AsyncReadExt + Unpin>(
    r: &mut R,
) -> Result<(Request, Vec<u8>)> {
    let mut reader = BufReader::new(r);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        bail!("ipc: connection closed");
    }
    let req: Request =
        serde_json::from_str(line.trim()).context("ipc request json")?;
    if req.n > MAX_CLIP {
        bail!("ipc payload exceeds 10MiB");
    }
    let mut body = vec![0u8; req.n];
    if req.n > 0 {
        reader.read_exact(&mut body).await?;
    }
    // BufReader may have buffered extra bytes — we must not drop them.
    // For request/response with exact body length after a line, BufReader
    // is only safe if nothing follows that we need to write on the same
    // stream without consuming leftover. The protocol is request-then-body
    // then response, so leftover should be empty.
    let inner = reader.buffer().to_vec();
    if !inner.is_empty() {
        bail!("ipc: unexpected buffered bytes after request body");
    }
    Ok((req, body))
}

pub async fn read_response<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
) -> Result<Response> {
    let mut reader = BufReader::new(&mut *stream);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        bail!("ipc: connection closed");
    }
    let mut resp: Response =
        serde_json::from_str(line.trim()).context("ipc response json")?;
    if resp.n > MAX_CLIP {
        bail!("ipc payload exceeds 10MiB");
    }
    resp.body = vec![0u8; resp.n];
    if resp.n > 0 {
        reader.read_exact(&mut resp.body).await?;
    }
    if !reader.buffer().is_empty() {
        bail!("ipc: unexpected buffered bytes after response body");
    }
    Ok(resp)
}

/// Read a request from a stream without wrapping in BufReader leftover traps.
/// Uses a 1-byte loop for the header line (headers are tiny).
pub async fn read_line_json<
    T: for<'de> Deserialize<'de>,
    R: AsyncReadExt + Unpin,
>(
    r: &mut R,
) -> Result<(T, usize)> {
    let mut line = Vec::new();
    loop {
        let mut b = [0u8; 1];
        let n = r.read(&mut b).await?;
        if n == 0 {
            bail!("ipc: connection closed");
        }
        if b[0] == b'\n' {
            break;
        }
        line.push(b[0]);
        if line.len() > 64 * 1024 {
            bail!("ipc header too large");
        }
    }
    let v: serde_json::Value = serde_json::from_slice(&line)?;
    let n = v.get("n").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
    let parsed: T = serde_json::from_value(v)?;
    Ok((parsed, n))
}

pub async fn read_exact_body<R: AsyncReadExt + Unpin>(
    r: &mut R,
    n: usize,
) -> Result<Vec<u8>> {
    if n > MAX_CLIP {
        bail!("ipc payload exceeds 10MiB");
    }
    let mut body = vec![0u8; n];
    if n > 0 {
        r.read_exact(&mut body).await?;
    }
    Ok(body)
}
