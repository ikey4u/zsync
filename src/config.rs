use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::protocol::MAX_CLIP;

pub const MAX_CLIP_BYTES: usize = MAX_CLIP;

#[derive(Debug, Clone)]
pub struct Config {
    pub max_clip_bytes: usize,
    pub poll_interval: std::time::Duration,
    pub suppress_ttl: std::time::Duration,
    pub debounce: std::time::Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_clip_bytes: MAX_CLIP_BYTES,
            poll_interval: std::time::Duration::from_millis(300),
            suppress_ttl: std::time::Duration::from_millis(5000),
            debounce: std::time::Duration::from_millis(200),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub peers: Vec<PeerState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerState {
    pub uri: String,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub dir: PathBuf,
    pub sock: PathBuf,
    pub pid: PathBuf,
    pub log: PathBuf,
    pub node_id: PathBuf,
    pub secret: PathBuf,
    pub state: PathBuf,
}

impl Paths {
    pub fn resolve() -> Result<Self> {
        let home = dirs_home().context("cannot resolve home directory")?;
        let dir = home.join(".zsync");
        fs::create_dir_all(&dir)
            .with_context(|| format!("mkdir {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
        Ok(Self {
            sock: dir.join("daemon.sock"),
            pid: dir.join("daemon.pid"),
            log: dir.join("daemon.log"),
            node_id: dir.join("node_id"),
            secret: dir.join("secret"),
            state: dir.join("state.json"),
            dir,
        })
    }
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
}

pub fn load_or_create_node_id(paths: &Paths) -> Result<String> {
    if let Ok(s) = fs::read_to_string(&paths.node_id) {
        let id = s.trim();
        if !id.is_empty() {
            return Ok(id.to_string());
        }
    }
    let id = crate::protocol::new_node_id();
    fs::write(&paths.node_id, format!("{id}\n"))?;
    Ok(id)
}

pub struct StateFile {
    path: PathBuf,
    inner: Mutex<State>,
}

impl StateFile {
    pub fn open(paths: &Paths) -> Result<Self> {
        let state = fs::read_to_string(&paths.state)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Ok(Self {
            path: paths.state.clone(),
            inner: Mutex::new(state),
        })
    }

    pub fn get(&self) -> State {
        self.inner.lock().unwrap().clone()
    }

    pub fn next_seq(&self) -> Result<u64> {
        let mut g = self.inner.lock().unwrap();
        g.seq += 1;
        let seq = g.seq;
        Self::save(&self.path, &g)?;
        Ok(seq)
    }

    pub fn upsert_peer(&self, uri: &str, enabled: bool) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        if let Some(p) = g.peers.iter_mut().find(|p| p.uri == uri) {
            p.enabled = enabled;
        } else {
            g.peers.push(PeerState {
                uri: uri.to_string(),
                enabled,
            });
        }
        Self::save(&self.path, &g)
    }

    pub fn remove_peer(&self, uri: Option<&str>) -> Result<Vec<String>> {
        let mut g = self.inner.lock().unwrap();
        let removed: Vec<String> = if let Some(uri) = uri {
            let before = g.peers.len();
            g.peers.retain(|p| p.uri != uri);
            if g.peers.len() == before {
                Vec::new()
            } else {
                vec![uri.to_string()]
            }
        } else {
            g.peers.drain(..).map(|p| p.uri).collect()
        };
        Self::save(&self.path, &g)?;
        Ok(removed)
    }

    fn save(path: &Path, state: &State) -> Result<()> {
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(state)?)?;
        fs::rename(tmp, path)?;
        Ok(())
    }
}

pub fn write_pid(path: &Path, pid: u32) -> Result<()> {
    fs::write(path, format!("{pid}\n"))?;
    Ok(())
}

pub fn read_pid(path: &Path) -> Option<u32> {
    let s = fs::read_to_string(path).ok()?;
    s.trim().parse().ok()
}

pub fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let rc = unsafe { libc::kill(pid as i32, 0) };
        if rc == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }
    #[cfg(not(unix))]
    {
        #[cfg(windows)]
        {
            use windows_sys::Win32::{
                Foundation::CloseHandle,
                System::Threading::{
                    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
                },
            };
            unsafe {
                let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                if h.is_null() {
                    return false;
                }
                CloseHandle(h);
                true
            }
        }
        #[cfg(not(windows))]
        {
            let _ = pid;
            false
        }
    }
}

pub fn kill_pid(pid: u32) -> Result<()> {
    #[cfg(unix)]
    {
        let rc = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
        if rc != 0
            && std::io::Error::last_os_error().raw_os_error()
                != Some(libc::ESRCH)
        {
            anyhow::bail!("kill {pid}: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        #[cfg(windows)]
        {
            use windows_sys::Win32::{
                Foundation::{CloseHandle, FALSE},
                System::Threading::{
                    OpenProcess, TerminateProcess, PROCESS_TERMINATE,
                },
            };
            unsafe {
                let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
                if h.is_null() {
                    anyhow::bail!("OpenProcess {pid} failed");
                }
                let ok = TerminateProcess(h, 1);
                CloseHandle(h);
                if ok == FALSE {
                    anyhow::bail!("TerminateProcess {pid} failed");
                }
            }
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = pid;
            anyhow::bail!("kill is only supported on unix and windows");
        }
    }
}

pub fn this_os() -> &'static str {
    std::env::consts::OS
}

pub fn hostname() -> String {
    hostname::get()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".into())
}

pub const ZSYNC_VERSION: &str = env!("ZSYNC_VERSION");

pub fn crate_version() -> &'static str {
    ZSYNC_VERSION
}
