//! Public-relay daemon: TLS, group allowlist, ciphertext fan-out.

use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    net::IpAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::{
    io::{split, AsyncWriteExt},
    net::TcpListener,
    sync::{mpsc, watch},
};
use tokio_rustls::TlsAcceptor;

use crate::{
    config::ZSYNC_VERSION,
    group::{
        self, generate_secret, group_id_from_secret, hex_encode, GroupUri,
    },
    net::DEFAULT_PORT,
    relay::{self, Join, JoinAck},
    tlsutil,
};

#[derive(Parser, Debug)]
#[command(
    name = "zsyncd",
    version = ZSYNC_VERSION,
    about = "Clipboard relay: TLS, group allowlist, ciphertext only",
    arg_required_else_help = true,
    subcommand_required = true
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Start or control the background daemon
    Daemon {
        #[command(subcommand)]
        action: Option<DaemonAction>,
        /// Run in the foreground (do not spawn)
        #[arg(long, short = 'f', global = true)]
        foreground: bool,
    },
    /// Manage groups (create prints a one-time zsync:// URI)
    Group {
        #[command(subcommand)]
        action: GroupCmd,
    },
    /// Show daemon, listen port, and online devices
    Status,
}

#[derive(Subcommand, Debug)]
enum DaemonAction {
    /// Stop a running daemon
    Stop,
    /// Show daemon and group status
    Status,
}

#[derive(Subcommand, Debug)]
enum GroupCmd {
    /// Create a group; prints zsync://gid:key@host:port once
    Create {
        /// Hostname or IP leaves should dial (not 0.0.0.0)
        #[arg(long)]
        domain: Option<String>,
        /// Optional label for `group ls`
        #[arg(long)]
        name: Option<String>,
    },
    Ls,
    Enable {
        group_id: String,
    },
    Disable {
        group_id: String,
    },
    /// Remove from the allowlist and drop connections
    Deny {
        group_id: String,
    },
    Kick {
        group_id: String,
        device_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GroupsFile {
    #[serde(default)]
    groups: Vec<GroupRec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GroupRec {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone)]
struct DaemonPaths {
    dir: PathBuf,
    groups: PathBuf,
    sock: PathBuf,
    pid: PathBuf,
    log: PathBuf,
}

impl DaemonPaths {
    fn resolve() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .context("cannot resolve home directory")?;
        let dir = home.join(".zsyncd");
        fs::create_dir_all(&dir)
            .with_context(|| format!("mkdir {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
        Ok(Self {
            groups: dir.join("groups.json"),
            sock: dir.join("admin.sock"),
            pid: dir.join("zsyncd.pid"),
            log: dir.join("zsyncd.log"),
            dir,
        })
    }
}

fn is_running(paths: &DaemonPaths) -> bool {
    match crate::config::read_pid(&paths.pid) {
        Some(pid) if crate::config::pid_alive(pid) => true,
        _ => false,
    }
}

fn cleanup_stale(paths: &DaemonPaths) {
    if let Some(pid) = crate::config::read_pid(&paths.pid) {
        if crate::config::pid_alive(pid) {
            return;
        }
    }
    let _ = fs::remove_file(&paths.sock);
    let _ = fs::remove_file(&paths.pid);
}

fn daemon_ready(paths: &DaemonPaths) -> bool {
    if !is_running(paths) {
        return false;
    }
    #[cfg(unix)]
    {
        paths.sock.exists()
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn start() -> Result<()> {
    let paths = DaemonPaths::resolve()?;
    if is_running(&paths) {
        println!(
            "zsyncd already running (pid {})",
            crate::config::read_pid(&paths.pid).unwrap_or(0)
        );
        return Ok(());
    }
    cleanup_stale(&paths);
    let exe = std::env::current_exe().context("current_exe")?;
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.log)
        .with_context(|| format!("open {}", paths.log.display()))?;
    let mut cmd = Command::new(exe);
    cmd.arg("daemon")
        .arg("--foreground")
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let child = cmd.spawn().context("spawn zsyncd")?;
    for _ in 0..80 {
        if daemon_ready(&paths) {
            println!("zsyncd started (pid {})", child.id());
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    bail!("zsyncd did not come up; see {}", paths.log.display());
}

fn stop() -> Result<()> {
    let paths = DaemonPaths::resolve()?;
    let Some(pid) = crate::config::read_pid(&paths.pid) else {
        println!("zsyncd is not running");
        return Ok(());
    };
    if !crate::config::pid_alive(pid) {
        cleanup_stale(&paths);
        println!("zsyncd is not running");
        return Ok(());
    }
    crate::config::kill_pid(pid)?;
    for _ in 0..40 {
        if !crate::config::pid_alive(pid) {
            cleanup_stale(&paths);
            println!("zsyncd stopped");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    bail!("zsyncd pid {pid} did not exit");
}

fn listen_port() -> u16 {
    std::env::var("ZSYNCD_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&p| p != 0)
        .unwrap_or(DEFAULT_PORT)
}

fn load_groups(path: &Path) -> GroupsFile {
    fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(GroupsFile { groups: Vec::new() })
}

fn save_groups(path: &Path, file: &GroupsFile) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(file)?)?;
    fs::rename(tmp, path)?;
    Ok(())
}

struct Allowlist {
    path: PathBuf,
    mtime: Option<std::time::SystemTime>,
    groups: HashMap<String, GroupRec>,
}

impl Allowlist {
    fn new(path: PathBuf) -> Self {
        let mut s = Self {
            path,
            mtime: None,
            groups: HashMap::new(),
        };
        s.refresh();
        s
    }

    fn refresh(&mut self) {
        let mtime = fs::metadata(&self.path).and_then(|m| m.modified()).ok();
        if mtime == self.mtime && !self.groups.is_empty() {
            return;
        }
        if mtime.is_none() && !self.path.exists() {
            self.groups.clear();
            self.mtime = None;
            return;
        }
        self.mtime = mtime;
        self.groups = load_groups(&self.path)
            .groups
            .into_iter()
            .map(|g| (g.id.clone(), g))
            .collect();
    }

    fn get(&mut self, id: &str) -> Option<GroupRec> {
        self.refresh();
        self.groups.get(id).cloned()
    }
}

struct Member {
    device_id: String,
    hostname: String,
    peer: String,
    tx: mpsc::Sender<Vec<u8>>,
    stop: watch::Sender<bool>,
}

struct Rooms {
    inner: HashMap<String, Vec<Member>>,
}

impl Rooms {
    fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    fn join(
        &mut self,
        group_id: &str,
        device_id: &str,
        hostname: String,
        peer: String,
        tx: mpsc::Sender<Vec<u8>>,
        stop: watch::Sender<bool>,
    ) {
        let members = self.inner.entry(group_id.to_string()).or_default();
        if let Some(old) = members.iter().position(|m| m.device_id == device_id)
        {
            let old = members.remove(old);
            let _ = old.stop.send(true);
        }
        members.push(Member {
            device_id: device_id.to_string(),
            hostname,
            peer,
            tx,
            stop,
        });
    }

    fn leave(&mut self, group_id: &str, device_id: &str) {
        if let Some(members) = self.inner.get_mut(group_id) {
            members.retain(|m| m.device_id != device_id);
            if members.is_empty() {
                self.inner.remove(group_id);
            }
        }
    }

    fn broadcast(&self, group_id: &str, from: &str, payload: Vec<u8>) {
        let Some(members) = self.inner.get(group_id) else {
            return;
        };
        for m in members {
            if m.device_id == from {
                continue;
            }
            let _ = m.tx.try_send(payload.clone());
        }
    }

    fn kick(&mut self, group_id: &str, device_id: &str) -> bool {
        let Some(members) = self.inner.get_mut(group_id) else {
            return false;
        };
        if let Some(i) = members.iter().position(|m| m.device_id == device_id) {
            let m = members.remove(i);
            let _ = m.stop.send(true);
            true
        } else {
            false
        }
    }

    fn kick_group(&mut self, group_id: &str) {
        if let Some(members) = self.inner.remove(group_id) {
            for m in members {
                let _ = m.stop.send(true);
            }
        }
    }

    fn snapshot(&self) -> HashMap<String, usize> {
        self.inner
            .iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect()
    }

    fn members(&self) -> HashMap<String, Vec<LiveDevice>> {
        self.inner
            .iter()
            .map(|(gid, members)| {
                (
                    gid.clone(),
                    members
                        .iter()
                        .map(|m| LiveDevice {
                            device_id: m.device_id.clone(),
                            hostname: m.hostname.clone(),
                            peer: m.peer.clone(),
                        })
                        .collect(),
                )
            })
            .collect()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AdminReq {
    action: String,
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    device_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct LiveDevice {
    device_id: String,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    peer: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct AdminResp {
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(default)]
    online: HashMap<String, usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(default)]
    members: HashMap<String, Vec<LiveDevice>>,
}

struct Server {
    allow: Mutex<Allowlist>,
    rooms: Mutex<Rooms>,
    probes: Mutex<ProbeTracker>,
    port: u16,
}

/// Failed Join / TLS from the same IP: after a few tries, drop new connections
/// before handshake so scanners burn less CPU and get no protocol banner.
struct ProbeTracker {
    inner: HashMap<IpAddr, ProbeState>,
}

struct ProbeState {
    fails: u32,
    window: Instant,
    banned_until: Option<Instant>,
}

const PROBE_WINDOW: Duration = Duration::from_secs(60);
const PROBE_MAX_FAILS: u32 = 8;
const PROBE_BAN: Duration = Duration::from_secs(10 * 60);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);

impl ProbeTracker {
    fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    fn is_banned(&mut self, ip: IpAddr) -> bool {
        self.gc();
        match self.inner.get(&ip) {
            Some(s) => {
                s.banned_until.map(|t| Instant::now() < t).unwrap_or(false)
            }
            None => false,
        }
    }

    fn fail(&mut self, ip: IpAddr) {
        let now = Instant::now();
        let s = self.inner.entry(ip).or_insert(ProbeState {
            fails: 0,
            window: now,
            banned_until: None,
        });
        if now.duration_since(s.window) > PROBE_WINDOW {
            s.fails = 0;
            s.window = now;
        }
        s.fails += 1;
        if s.fails >= PROBE_MAX_FAILS {
            s.banned_until = Some(now + PROBE_BAN);
            tracing::warn!(%ip, "probe ban {PROBE_BAN:?}");
        }
    }

    fn ok(&mut self, ip: IpAddr) {
        self.inner.remove(&ip);
    }

    fn gc(&mut self) {
        let now = Instant::now();
        self.inner.retain(|_, s| {
            s.banned_until.map(|t| now < t).unwrap_or(false)
                || now.duration_since(s.window) <= PROBE_WINDOW
        });
    }
}

pub async fn run() -> Result<()> {
    tlsutil::install_crypto_provider();
    let cli = Cli::parse();
    match cli.command {
        Cmd::Daemon { action, foreground } => match action {
            Some(DaemonAction::Stop) => stop(),
            Some(DaemonAction::Status) => cmd_status().await,
            None if foreground => run_server().await,
            None => start(),
        },
        Cmd::Group { action } => group_cmd(action).await,
        Cmd::Status => cmd_status().await,
    }
}

async fn group_cmd(action: GroupCmd) -> Result<()> {
    let paths = DaemonPaths::resolve()?;
    match action {
        GroupCmd::Create { domain, name } => cmd_create(&paths, domain, name)?,
        GroupCmd::Ls => cmd_ls(&paths).await?,
        GroupCmd::Enable { group_id } => {
            set_enabled(&paths, &group_id, true)?;
            println!("enabled {group_id}");
        }
        GroupCmd::Disable { group_id } => {
            set_enabled(&paths, &group_id, false)?;
            admin_kick_group(&paths, &group_id).await;
            println!("disabled {group_id}");
        }
        GroupCmd::Deny { group_id } => {
            remove_group(&paths, &group_id)?;
            admin_kick_group(&paths, &group_id).await;
            println!("denied {group_id}");
        }
        GroupCmd::Kick {
            group_id,
            device_id,
        } => {
            if !admin_kick(&paths, &group_id, &device_id).await? {
                bail!("kick failed; is zsyncd running?");
            }
            println!("kicked {device_id} from {group_id}");
        }
    }
    Ok(())
}

fn cmd_create(
    paths: &DaemonPaths,
    domain: Option<String>,
    name: Option<String>,
) -> Result<()> {
    let host = match domain {
        Some(h) => h,
        None => group::detect_advertise_ip()
            .map(|ip| ip.to_string())
            .context("could not detect address; pass --domain")?,
    };
    if host == "0.0.0.0" || host == "::" {
        bail!("--domain cannot be 0.0.0.0 / ::");
    }
    let port = listen_port();
    let secret = generate_secret();
    let gid = group_id_from_secret(&secret);
    let mut file = load_groups(&paths.groups);
    let id = hex_encode(&gid);
    if file.groups.iter().any(|g| g.id == id) {
        bail!("group {id} already exists");
    }
    file.groups.push(GroupRec {
        id: id.clone(),
        name: name.unwrap_or_default(),
        enabled: true,
    });
    save_groups(&paths.groups, &file)?;
    let uri = GroupUri {
        group_id: gid,
        key: Some(secret),
        host: host.clone(),
        port,
    };
    println!("{}", uri.to_uri()?);
    group::warn_if_not_public(&host);
    Ok(())
}

async fn cmd_ls(paths: &DaemonPaths) -> Result<()> {
    let file = load_groups(&paths.groups);
    let online = admin_ls(paths).await.unwrap_or_default();
    if file.groups.is_empty() {
        println!("(no groups)");
        return Ok(());
    }
    for g in file.groups {
        let n = online.get(&g.id).copied().unwrap_or(0);
        let st = if g.enabled { "enabled" } else { "disabled" };
        let name = if g.name.is_empty() { "-" } else { &g.name };
        println!("{id}  {name}  {st}  {n} online", id = g.id);
    }
    Ok(())
}

async fn cmd_status() -> Result<()> {
    let paths = DaemonPaths::resolve()?;
    if !is_running(&paths) {
        println!("daemon: not running");
        println!("hint:    zsyncd daemon");
        return Ok(());
    }
    let pid = crate::config::read_pid(&paths.pid).unwrap_or(0);
    let live = admin_status(&paths).await.ok();
    let port = live
        .as_ref()
        .and_then(|r| r.port)
        .unwrap_or_else(listen_port);
    println!("daemon:    running (pid {pid})");
    println!("listen:    0.0.0.0:{port}");
    let file = load_groups(&paths.groups);
    let members = live.as_ref().map(|r| r.members.clone()).unwrap_or_default();
    let online = live.as_ref().map(|r| r.online.clone()).unwrap_or_default();
    if file.groups.is_empty() && members.is_empty() {
        println!("groups:    none");
        return Ok(());
    }
    for g in &file.groups {
        let n = online.get(&g.id).copied().unwrap_or(0);
        let st = if g.enabled { "enabled" } else { "disabled" };
        let name = if g.name.is_empty() {
            "-"
        } else {
            g.name.as_str()
        };
        println!("group:     {}  {name}  {st}  {n} online", g.id);
        if let Some(devs) = members.get(&g.id) {
            for d in devs {
                let host = if d.hostname.is_empty() {
                    "-"
                } else {
                    d.hostname.as_str()
                };
                println!(
                    "           device {}  {host}  {}",
                    d.device_id, d.peer
                );
            }
        }
    }
    Ok(())
}

fn set_enabled(
    paths: &DaemonPaths,
    group_id: &str,
    enabled: bool,
) -> Result<()> {
    let id = hex_encode(&group::parse_group_id(group_id)?);
    let mut file = load_groups(&paths.groups);
    let Some(g) = file.groups.iter_mut().find(|g| g.id == id) else {
        bail!("unknown group {id}");
    };
    g.enabled = enabled;
    save_groups(&paths.groups, &file)
}

fn remove_group(paths: &DaemonPaths, group_id: &str) -> Result<()> {
    let id = hex_encode(&group::parse_group_id(group_id)?);
    let mut file = load_groups(&paths.groups);
    let before = file.groups.len();
    file.groups.retain(|g| g.id != id);
    if file.groups.len() == before {
        bail!("unknown group {id}");
    }
    save_groups(&paths.groups, &file)
}

async fn run_server() -> Result<()> {
    let paths = DaemonPaths::resolve()?;
    let port = listen_port();
    let (tls_cfg, _, _) = tlsutil::load_or_create_server(&paths.dir)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));
    let listener = TcpListener::bind(("0.0.0.0", port))
        .await
        .with_context(|| format!("bind 0.0.0.0:{port}"))?;
    let srv = Arc::new(Server {
        allow: Mutex::new(Allowlist::new(paths.groups.clone())),
        rooms: Mutex::new(Rooms::new()),
        probes: Mutex::new(ProbeTracker::new()),
        port,
    });
    crate::config::write_pid(&paths.pid, std::process::id())?;
    let _guard = PidGuard {
        pid: paths.pid.clone(),
        sock: paths.sock.clone(),
    };
    start_admin(paths.sock.clone(), Arc::clone(&srv))?;
    tracing::info!("zsyncd listening 0.0.0.0:{port}");
    loop {
        tokio::select! {
            _ = shutdown_signal() => break,
            acc = listener.accept() => {
                let (tcp, peer) = acc?;
                let _ = tcp.set_nodelay(true);
                if srv.probes.lock().unwrap().is_banned(peer.ip()) {
                    continue;
                }
                let acceptor = acceptor.clone();
                let srv = Arc::clone(&srv);
                tokio::spawn(async move {
                    if let Err(e) = serve_leaf(srv, acceptor, tcp, peer).await {
                        tracing::debug!("leaf {peer}: {e:#}");
                    }
                });
            }
        }
    }
    Ok(())
}

struct PidGuard {
    pid: PathBuf,
    sock: PathBuf,
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.pid);
        let _ = fs::remove_file(&self.sock);
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )
        .expect("sigterm");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn serve_leaf(
    srv: Arc<Server>,
    acceptor: TlsAcceptor,
    tcp: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
) -> Result<()> {
    let ip = peer.ip();
    let tls =
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp))
            .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(_)) | Err(_) => {
                srv.probes.lock().unwrap().fail(ip);
                return Ok(());
            }
        };
    let (mut reader, mut writer) = split(tls);
    let frame =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, relay::read_frame(&mut reader))
            .await;
    let Ok(Ok((typ, payload))) = frame else {
        srv.probes.lock().unwrap().fail(ip);
        let _ = writer.shutdown().await;
        return Ok(());
    };
    if typ != relay::Type::Join {
        srv.probes.lock().unwrap().fail(ip);
        let _ = writer.shutdown().await;
        return Ok(());
    }
    let join: Join = match serde_json::from_slice(&payload) {
        Ok(j) => j,
        Err(_) => {
            srv.probes.lock().unwrap().fail(ip);
            let _ = writer.shutdown().await;
            return Ok(());
        }
    };
    let gid = group::parse_group_id(&join.group_id).map(|id| hex_encode(&id));
    let allowed = match &gid {
        Ok(id) => srv
            .allow
            .lock()
            .unwrap()
            .get(id)
            .map(|g| g.enabled)
            .unwrap_or(false),
        Err(_) => false,
    };
    if !allowed {
        // Same silent close for unknown, disabled, and garbage — do not
        // confirm that a group_id exists.
        srv.probes.lock().unwrap().fail(ip);
        let _ = writer.shutdown().await;
        return Ok(());
    }
    let gid = gid.expect("allowed implies parsed group_id");
    srv.probes.lock().unwrap().ok(ip);
    let device = join.device_id.clone();
    tracing::info!(group = %gid, device = %device, %peer, "join");
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(16);
    let (stop_tx, mut stop_rx) = watch::channel(false);
    srv.rooms.lock().unwrap().join(
        &gid,
        &device,
        join.hostname.clone(),
        peer.to_string(),
        tx,
        stop_tx,
    );
    relay::write_json(
        &mut writer,
        relay::Type::JoinAck,
        &JoinAck {
            ok: true,
            message: String::new(),
        },
    )
    .await?;
    let mut ping = tokio::time::interval(Duration::from_secs(30));
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let result = loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    break Ok(());
                }
            }
            _ = ping.tick() => {
                let ok = srv
                    .allow
                    .lock()
                    .unwrap()
                    .get(&gid)
                    .map(|g| g.enabled)
                    .unwrap_or(false);
                if !ok {
                    break Ok(());
                }
                if let Err(e) = relay::write_frame(&mut writer, relay::Type::Ping, &[]).await {
                    break Err(e.into());
                }
            }
            msg = rx.recv() => {
                match msg {
                    Some(payload) => {
                        if let Err(e) = relay::write_frame(&mut writer, relay::Type::Data, &payload).await {
                            break Err(e.into());
                        }
                    }
                    None => break Ok(()),
                }
            }
            frame = relay::read_frame(&mut reader) => {
                let (typ, payload) = match frame {
                    Ok(v) => v,
                    Err(e) => break Err(e.into()),
                };
                match typ {
                    relay::Type::Data => {
                        let ok = srv
                            .allow
                            .lock()
                            .unwrap()
                            .get(&gid)
                            .map(|g| g.enabled)
                            .unwrap_or(false);
                        if !ok {
                            let _ = relay::write_frame(
                                &mut writer,
                                relay::Type::Error,
                                &relay::encode_error("disabled", "group disabled"),
                            )
                            .await;
                            break Ok(());
                        }
                        srv.rooms.lock().unwrap().broadcast(&gid, &device, payload);
                    }
                    relay::Type::Ping => {
                        if let Err(e) = relay::write_frame(&mut writer, relay::Type::Pong, &payload).await {
                            break Err(e.into());
                        }
                    }
                    relay::Type::Pong => {}
                    relay::Type::Bye | relay::Type::Error => break Ok(()),
                    relay::Type::Join | relay::Type::JoinAck => {}
                }
            }
        }
    };
    srv.rooms.lock().unwrap().leave(&gid, &device);
    let _ = writer.shutdown().await;
    result
}

fn start_admin(sock: PathBuf, srv: Arc<Server>) -> Result<()> {
    #[cfg(unix)]
    {
        let _ = fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock)
            .with_context(|| format!("bind {}", sock.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                fs::set_permissions(&sock, fs::Permissions::from_mode(0o600));
        }
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let srv = Arc::clone(&srv);
                        tokio::spawn(async move {
                            if let Err(e) = handle_admin(stream, srv).await {
                                tracing::debug!("admin: {e:#}");
                            }
                        });
                    }
                    Err(_) => break,
                }
            }
        });
    }
    #[cfg(not(unix))]
    {
        let _ = (sock, srv);
    }
    Ok(())
}

#[cfg(unix)]
async fn handle_admin(mut stream: UnixStream, srv: Arc<Server>) -> Result<()> {
    let (req, _) =
        crate::ipc::read_line_json::<AdminReq, _>(&mut stream).await?;
    let resp = dispatch_admin(&srv, req);
    let line = serde_json::to_string(&resp)?;
    use tokio::io::AsyncWriteExt;
    stream.write_all(line.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;
    Ok(())
}

fn dispatch_admin(srv: &Server, req: AdminReq) -> AdminResp {
    match req.action.as_str() {
        "ls" | "status" => {
            let rooms = srv.rooms.lock().unwrap();
            AdminResp {
                ok: true,
                online: rooms.snapshot(),
                pid: Some(std::process::id()),
                port: Some(srv.port),
                members: rooms.members(),
                ..AdminResp::default()
            }
        }
        "kick" => {
            let (Some(g), Some(d)) = (req.group_id, req.device_id) else {
                return AdminResp {
                    ok: false,
                    error: Some("missing group_id or device_id".into()),
                    ..AdminResp::default()
                };
            };
            let ok = srv.rooms.lock().unwrap().kick(&g, &d);
            AdminResp {
                ok,
                error: if ok {
                    None
                } else {
                    Some("not connected".into())
                },
                ..AdminResp::default()
            }
        }
        "kick_group" => {
            let Some(g) = req.group_id else {
                return AdminResp {
                    ok: false,
                    error: Some("missing group_id".into()),
                    ..AdminResp::default()
                };
            };
            srv.rooms.lock().unwrap().kick_group(&g);
            AdminResp {
                ok: true,
                ..AdminResp::default()
            }
        }
        other => AdminResp {
            ok: false,
            error: Some(format!("unknown action {other}")),
            ..AdminResp::default()
        },
    }
}

async fn admin_ls(paths: &DaemonPaths) -> Result<HashMap<String, usize>> {
    let resp = admin_roundtrip(
        paths,
        &AdminReq {
            action: "ls".into(),
            group_id: None,
            device_id: None,
        },
    )
    .await?;
    Ok(resp.online)
}

async fn admin_status(paths: &DaemonPaths) -> Result<AdminResp> {
    admin_roundtrip(
        paths,
        &AdminReq {
            action: "status".into(),
            group_id: None,
            device_id: None,
        },
    )
    .await
}

async fn admin_kick(
    paths: &DaemonPaths,
    group_id: &str,
    device_id: &str,
) -> Result<bool> {
    let resp = admin_roundtrip(
        paths,
        &AdminReq {
            action: "kick".into(),
            group_id: Some(hex_encode(&group::parse_group_id(group_id)?)),
            device_id: Some(device_id.to_string()),
        },
    )
    .await?;
    Ok(resp.ok)
}

async fn admin_kick_group(paths: &DaemonPaths, group_id: &str) {
    let Ok(id) = group::parse_group_id(group_id) else {
        return;
    };
    let _ = admin_roundtrip(
        paths,
        &AdminReq {
            action: "kick_group".into(),
            group_id: Some(hex_encode(&id)),
            device_id: None,
        },
    )
    .await;
}

async fn admin_roundtrip(
    paths: &DaemonPaths,
    req: &AdminReq,
) -> Result<AdminResp> {
    #[cfg(unix)]
    {
        let mut stream = UnixStream::connect(&paths.sock)
            .await
            .with_context(|| format!("connect {}", paths.sock.display()))?;
        let line = serde_json::to_string(req)?;
        stream.write_all(line.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;
        let (resp, _) =
            crate::ipc::read_line_json::<AdminResp, _>(&mut stream).await?;
        Ok(resp)
    }
    #[cfg(not(unix))]
    {
        let _ = (paths, req);
        bail!("admin socket is only available on unix");
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn probe_ban_after_repeated_fails() {
        let mut t = ProbeTracker::new();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        assert!(!t.is_banned(ip));
        for _ in 0..PROBE_MAX_FAILS {
            t.fail(ip);
        }
        assert!(t.is_banned(ip));
        t.ok(ip);
        assert!(!t.is_banned(ip));
    }
}
