use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::sync::broadcast;

use crate::{
    clipboard::{Backend, Item},
    config::StateFile,
    protocol::{self, hash, Clip, ClipAck, ClipMeta, Hello, MAX_CLIP},
    suppress::{SeenSeq, Suppress},
};

/// Peers subscribe here. `skip` is the ingress peer node_id that must not
/// receive this clip again (A → hub → A).
#[derive(Clone)]
pub struct Outbound {
    pub clip: Clip,
    pub skip: Option<String>,
}

/// Local-origin clips and forwarded remotes.
const BROADCAST_CAP: usize = 32;

#[derive(Clone)]
pub struct Hub {
    node_id: String,
    clipboard: Arc<dyn Backend>,
    suppress: Arc<Mutex<Suppress>>,
    seen: Arc<Mutex<SeenSeq>>,
    state: Arc<StateFile>,
    tx: broadcast::Sender<Outbound>,
}

impl Hub {
    pub fn new(
        node_id: String,
        clipboard: Arc<dyn Backend>,
        state: Arc<StateFile>,
        suppress_ttl: Duration,
    ) -> Self {
        let (tx, _) = broadcast::channel(BROADCAST_CAP);
        Self {
            node_id,
            clipboard,
            suppress: Arc::new(Mutex::new(Suppress::new(suppress_ttl, 64))),
            seen: Arc::new(Mutex::new(SeenSeq::default())),
            state,
            tx,
        }
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn clipboard(&self) -> Arc<dyn Backend> {
        Arc::clone(&self.clipboard)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Outbound> {
        self.tx.subscribe()
    }

    fn emit(&self, clip: Clip, skip: Option<String>) {
        let _ = self.tx.send(Outbound { clip, skip });
    }

    pub fn hello(&self) -> Hello {
        Hello {
            node_id: self.node_id.clone(),
            hostname: crate::config::hostname(),
            os: crate::config::this_os().into(),
            headless: self.clipboard.headless(),
            version: crate::config::crate_version().into(),
            max_bytes: MAX_CLIP,
        }
    }

    /// Watcher path: content is already on the clipboard.
    pub fn local_observed(&self, item: Item) -> Result<Option<Clip>> {
        if item.data.is_empty() {
            return Ok(None);
        }
        if item.data.len() > MAX_CLIP {
            tracing::warn!(
                bytes = item.data.len(),
                "local clip exceeds 10MiB, skip"
            );
            return Ok(None);
        }
        let h = if item.hash.is_empty() {
            hash(&item.data)
        } else {
            item.hash.clone()
        };
        if self.suppress.lock().unwrap().has(&h) {
            return Ok(None);
        }
        self.suppress.lock().unwrap().add(&h);
        let clip = self.pack(item.mime, item.name, item.data, h)?;
        self.emit(clip.clone(), None);
        Ok(Some(clip))
    }

    /// `zsync copy`: write local clipboard then broadcast as our origin.
    pub fn local_push(&self, item: Item) -> Result<Clip> {
        if item.data.len() > MAX_CLIP {
            anyhow::bail!("clipboard payload exceeds 10MiB");
        }
        let mut item = item;
        if item.hash.is_empty() {
            item.hash = hash(&item.data);
        }
        self.suppress.lock().unwrap().add(&item.hash);
        let stored = self.clipboard.set(&item)?;
        self.suppress.lock().unwrap().add(&stored.hash);
        let clip =
            self.pack(stored.mime, stored.name, stored.data, stored.hash)?;
        self.emit(clip.clone(), None);
        Ok(clip)
    }

    pub fn apply_remote(&self, clip: Clip) -> Result<ClipAck> {
        if let Err(e) = protocol::verify_clip(&clip) {
            tracing::warn!("drop incomplete clip: {e}");
            return Ok(ClipAck {
                hash: clip.meta.hash,
                ok: false,
                reason: match e {
                    protocol::ProtoError::TooLarge => "too-large".into(),
                    protocol::ProtoError::SizeMismatch { .. } => {
                        "truncated".into()
                    }
                    _ => "hash-mismatch".into(),
                },
            });
        }
        if clip.meta.origin_id == self.node_id {
            return Ok(ClipAck {
                hash: clip.meta.hash,
                ok: true,
                reason: "own-origin".into(),
            });
        }
        let actual_hash = clip.meta.hash.clone();
        if !self
            .seen
            .lock()
            .unwrap()
            .accept(&clip.meta.origin_id, clip.meta.seq)
        {
            return Ok(ClipAck {
                hash: clip.meta.hash,
                ok: true,
                reason: "duplicate".into(),
            });
        }
        if let Ok(Some(cur)) = self.clipboard.get() {
            if cur.hash == actual_hash {
                self.suppress.lock().unwrap().add(&actual_hash);
                return Ok(ClipAck {
                    hash: actual_hash,
                    ok: true,
                    reason: "already-present".into(),
                });
            }
        }
        self.suppress.lock().unwrap().add(&actual_hash);
        let item = Item {
            mime: clip.meta.mime.clone(),
            data: clip.data,
            hash: actual_hash.clone(),
            path: std::path::PathBuf::new(),
            name: clip.meta.name.clone(),
        };
        let stored = self.clipboard.set(&item)?;
        self.suppress.lock().unwrap().add(&stored.hash);
        Ok(ClipAck {
            hash: stored.hash,
            ok: true,
            reason: String::new(),
        })
    }

    /// Apply a clip that arrived from `from_peer`, then fan it out to every
    /// other peer. `from_peer` is the connecting client's node_id.
    pub fn apply_from(&self, clip: Clip, from_peer: &str) -> Result<ClipAck> {
        let out = clip.clone();
        let ack = self.apply_remote(clip)?;
        if ack.ok {
            self.emit(out, Some(from_peer.to_string()));
        }
        Ok(ack)
    }

    pub fn snapshot(&self) -> Result<Option<Item>> {
        self.clipboard.get()
    }

    fn pack(
        &self,
        mime: String,
        name: String,
        data: Vec<u8>,
        h: String,
    ) -> Result<Clip> {
        let seq = self.state.next_seq().context("persist seq")?;
        let mime = if mime.is_empty() {
            protocol::detect_mime(&data)
        } else {
            mime
        };
        Ok(Clip {
            meta: ClipMeta {
                origin_id: self.node_id.clone(),
                seq,
                mime,
                hash: h,
                size: data.len(),
                name,
            },
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        clipboard::Memory,
        config::{Paths, StateFile},
        protocol::{decode_clip, decode_frame, encode_clip, Type},
    };

    fn temp_state() -> Arc<StateFile> {
        let dir = std::env::temp_dir()
            .join(format!("zsync-hub-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let paths = Paths {
            sock: dir.join("daemon.sock"),
            pid: dir.join("daemon.pid"),
            log: dir.join("daemon.log"),
            node_id: dir.join("node_id"),
            secret: dir.join("secret"),
            state: dir.join("state.json"),
            dir,
        };
        Arc::new(StateFile::open(&paths).unwrap())
    }

    #[test]
    fn remote_apply_does_not_broadcast() {
        let mem = Arc::new(Memory::new());
        let hub = Hub::new(
            "node-b".into(),
            mem,
            temp_state(),
            Duration::from_secs(5),
        );
        let mut rx = hub.subscribe();
        let data = b"hello".to_vec();
        let clip = Clip {
            meta: ClipMeta {
                origin_id: "node-a".into(),
                seq: 1,
                mime: "text/plain".into(),
                hash: hash(&data),
                size: data.len(),
                name: String::new(),
            },
            data,
        };
        let ack = hub.apply_remote(clip).unwrap();
        assert!(ack.ok);
        assert!(rx.try_recv().is_err(), "apply_remote must not fan out");
        let got = hub.snapshot().unwrap().unwrap();
        assert_eq!(got.data, b"hello");
    }

    #[test]
    fn watcher_echo_suppressed() {
        let mem = Arc::new(Memory::new());
        let hub = Hub::new(
            "node-b".into(),
            Arc::clone(&mem) as Arc<dyn Backend>,
            temp_state(),
            Duration::from_secs(5),
        );
        let data = b"hello".to_vec();
        let clip = Clip {
            meta: ClipMeta {
                origin_id: "node-a".into(),
                seq: 1,
                mime: "text/plain".into(),
                hash: hash(&data),
                size: data.len(),
                name: String::new(),
            },
            data: data.clone(),
        };
        hub.apply_remote(clip).unwrap();
        let item = mem.get().unwrap().unwrap();
        let echoed = hub.local_observed(item).unwrap();
        assert!(echoed.is_none(), "watcher must drop hash in suppress");
    }

    #[test]
    fn two_hubs_one_clip_on_the_wire() {
        let a_mem = Arc::new(Memory::new());
        let b_mem = Arc::new(Memory::new());
        let hub_a = Hub::new(
            "a".into(),
            Arc::clone(&a_mem) as Arc<dyn Backend>,
            temp_state(),
            Duration::from_secs(5),
        );
        let hub_b = Hub::new(
            "b".into(),
            Arc::clone(&b_mem) as Arc<dyn Backend>,
            temp_state(),
            Duration::from_secs(5),
        );
        let clip = hub_a
            .local_push(Item::new("text/plain", b"ping".to_vec()))
            .unwrap();
        let buf = encode_clip(&clip).unwrap();
        let (typ, payload) = decode_frame(&buf).unwrap();
        assert_eq!(typ, Type::Clip);
        let decoded = decode_clip(&payload).unwrap();
        hub_b.apply_remote(decoded).unwrap();
        // B watcher would observe the same bytes
        let item = b_mem.get().unwrap().unwrap();
        assert!(hub_b.local_observed(item).unwrap().is_none());
        assert_eq!(b_mem.get().unwrap().unwrap().data, b"ping");
    }

    #[test]
    fn apply_from_fans_out_with_skip() {
        let mem = Arc::new(Memory::new());
        let hub =
            Hub::new("linux".into(), mem, temp_state(), Duration::from_secs(5));
        let mut rx = hub.subscribe();
        let data = b"from-mac".to_vec();
        let clip = Clip {
            meta: ClipMeta {
                origin_id: "mac".into(),
                seq: 1,
                mime: "text/plain".into(),
                hash: hash(&data),
                size: data.len(),
                name: String::new(),
            },
            data,
        };
        hub.apply_from(clip, "mac").unwrap();
        let out = rx.try_recv().expect("hub must fan out to other peers");
        assert_eq!(out.skip.as_deref(), Some("mac"));
        assert_eq!(out.clip.data, b"from-mac");
    }

    #[test]
    fn truncated_clip_never_hits_clipboard() {
        let mem = Arc::new(Memory::new());
        let hub = Hub::new(
            "b".into(),
            Arc::clone(&mem) as Arc<dyn Backend>,
            temp_state(),
            Duration::from_secs(5),
        );
        let mut rx = hub.subscribe();
        let data = b"complete-payload".to_vec();
        let mut clip = Clip {
            meta: ClipMeta {
                origin_id: "a".into(),
                seq: 1,
                mime: "text/plain".into(),
                hash: hash(&data),
                size: data.len(),
                name: String::new(),
            },
            data: data.clone(),
        };
        clip.data.pop();
        let ack = hub.apply_from(clip, "a").unwrap();
        assert!(!ack.ok);
        assert_eq!(ack.reason, "truncated");
        assert!(hub.snapshot().unwrap().is_none());
        assert!(rx.try_recv().is_err(), "must not fan out a truncated clip");

        let mut bad = Clip {
            meta: ClipMeta {
                origin_id: "a".into(),
                seq: 2,
                mime: "text/plain".into(),
                hash: hash(&data),
                size: data.len(),
                name: String::new(),
            },
            data,
        };
        bad.data[0] ^= 1;
        let ack = hub.apply_remote(bad).unwrap();
        assert!(!ack.ok);
        assert_eq!(ack.reason, "hash-mismatch");
        assert!(hub.snapshot().unwrap().is_none());
    }
}
