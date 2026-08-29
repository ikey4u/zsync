use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use anyhow::{bail, Result};

use super::{Backend, Item};
use crate::protocol::{detect_mime, ext_for_mime, hash, MAX_CLIP};

pub struct FileBackend {
    dir: PathBuf,
    cur: Mutex<Current>,
}

#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
struct Current {
    #[serde(default)]
    hash: String,
    #[serde(default)]
    mime: String,
    #[serde(default)]
    size: usize,
    #[serde(default)]
    path: String,
}

impl FileBackend {
    pub fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir.join("clips").join("objects"))?;
        let b = Self {
            dir: dir.to_path_buf(),
            cur: Mutex::new(Current::default()),
        };
        if let Ok(bytes) = fs::read(b.meta_path()) {
            if let Ok(cur) = serde_json::from_slice::<Current>(&bytes) {
                *b.cur.lock().unwrap() = cur;
            }
        }
        Ok(b)
    }

    fn meta_path(&self) -> PathBuf {
        self.dir.join("clips").join("current.json")
    }

    fn objects(&self) -> PathBuf {
        self.dir.join("clips").join("objects")
    }
}

impl Backend for FileBackend {
    fn name(&self) -> &str {
        "file"
    }

    fn headless(&self) -> bool {
        true
    }

    fn current_path(&self) -> PathBuf {
        PathBuf::from(self.cur.lock().unwrap().path.clone())
    }

    fn get(&self) -> Result<Option<Item>> {
        let cur = self.cur.lock().unwrap().clone();
        if cur.hash.is_empty() {
            return Ok(None);
        }
        let obj = self.objects().join(&cur.hash);
        let data = match fs::read(&obj) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(e) => return Err(e.into()),
        };
        Ok(Some(Item {
            mime: cur.mime,
            hash: cur.hash,
            path: PathBuf::from(cur.path),
            data,
        }))
    }

    fn set(&self, item: &Item) -> Result<Item> {
        if item.data.len() > MAX_CLIP {
            bail!("clipboard payload exceeds 10MiB");
        }
        let mime = if item.mime.is_empty() {
            detect_mime(&item.data)
        } else {
            item.mime.clone()
        };
        let h = if item.hash.is_empty() {
            hash(&item.data)
        } else {
            item.hash.clone()
        };
        fs::write(self.objects().join(&h), &item.data)?;

        let ext = ext_for_mime(&mime);
        let stable = self.dir.join("clips").join(format!("current{ext}"));
        fs::write(&stable, &item.data)?;

        if let Ok(entries) = fs::read_dir(self.dir.join("clips")) {
            for e in entries.flatten() {
                let name = e.file_name();
                let name = name.to_string_lossy();
                if name.starts_with("current")
                    && name != format!("current{ext}")
                    && name != "current.json"
                {
                    let _ = fs::remove_file(e.path());
                }
            }
        }

        let abs = stable.canonicalize().unwrap_or(stable);
        let stored = Item {
            mime: mime.clone(),
            data: item.data.clone(),
            hash: h.clone(),
            path: abs.clone(),
        };
        let cur = Current {
            hash: h,
            mime,
            size: item.data.len(),
            path: abs.to_string_lossy().into_owned(),
        };
        fs::write(self.meta_path(), serde_json::to_vec_pretty(&cur)?)?;
        *self.cur.lock().unwrap() = cur;
        Ok(stored)
    }
}
