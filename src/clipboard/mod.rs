use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Result;

use crate::protocol::{detect_mime, hash};

mod file;
mod native;

pub use file::FileBackend;

#[derive(Debug, Clone)]
pub struct Item {
    pub mime: String,
    pub data: Vec<u8>,
    pub hash: String,
    pub path: PathBuf,
}

impl Item {
    pub fn new(mime: impl Into<String>, data: Vec<u8>) -> Self {
        let mime = {
            let m = mime.into();
            if m.is_empty() {
                detect_mime(&data)
            } else {
                m
            }
        };
        let hash = hash(&data);
        Self {
            mime,
            data,
            hash,
            path: PathBuf::new(),
        }
    }
}

pub trait Backend: Send + Sync {
    fn name(&self) -> &str;
    fn headless(&self) -> bool;
    fn get(&self) -> Result<Option<Item>>;
    fn set(&self, item: &Item) -> Result<Item>;
    fn current_path(&self) -> PathBuf;
}

pub fn open(dir: &Path) -> Result<Arc<dyn Backend>> {
    if let Some(n) = native::open(dir)? {
        return Ok(n);
    }
    Ok(Arc::new(FileBackend::open(dir)?))
}

/// In-memory clipboard for tests.
pub struct Memory {
    inner: std::sync::Mutex<Option<Item>>,
}

impl Memory {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(None),
        }
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for Memory {
    fn name(&self) -> &str {
        "memory"
    }
    fn headless(&self) -> bool {
        false
    }
    fn get(&self) -> Result<Option<Item>> {
        Ok(self.inner.lock().unwrap().clone())
    }
    fn set(&self, item: &Item) -> Result<Item> {
        let mut stored = item.clone();
        if stored.hash.is_empty() {
            stored.hash = hash(&stored.data);
        }
        *self.inner.lock().unwrap() = Some(stored.clone());
        Ok(stored)
    }
    fn current_path(&self) -> PathBuf {
        PathBuf::new()
    }
}
