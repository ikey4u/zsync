use std::{
    collections::{HashMap, HashSet},
    fs::OpenOptions,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{bail, Context, Result};
use iroh::endpoint::Connection as IrohConn;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::watch;

use crate::{
    clipboard::{self, Item},
    config::{
        self, kill_pid, pid_alive, read_pid, write_pid, Config, Paths,
        StateFile,
    },
    hub::Hub,
    ipc::{self, PeerStatus, Request, Response, StatusPayload},
    net::{self, ALPN},
    protocol::{self, Type},
};

struct Runtime {
    hub: Hub,
    state: Arc<StateFile>,
    peers: Mutex<HashMap<String, PeerEntry>>,
    live: Mutex<HashSet<String>>,
    endpoint: iroh::Endpoint,
    ticket: Mutex<Option<String>>,
    shutdown: watch::Sender<bool>,
}

struct PeerEntry {
    status: Arc<Mutex<PeerStatus>>,
    stop: watch::Sender<bool>,
}

pub fn is_running(paths: &Paths) -> bool {
    match read_pid(&paths.pid) {
        Some(pid) if pid_alive(pid) => true,
        _ => false,
    }
}

fn cleanup_stale(paths: &Paths) {
    if let Some(pid) = read_pid(&paths.pid) {
        if pid_alive(pid) {
            return;
        }
    }
    let _ = std::fs::remove_file(&paths.sock);
    let _ = std::fs::remove_file(&paths.pid);
}

pub fn start() -> Result<()> {
    let paths = Paths::resolve()?;
    if is_running(&paths) {
        println!(
            "daemon already running (pid {})",
            read_pid(&paths.pid).unwrap_or(0)
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
    let child = cmd.spawn().context("spawn daemon")?;
    for _ in 0..80 {
        if paths.sock.exists() && is_running(&paths) {
            println!("daemon started (pid {})", child.id());
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    bail!("daemon did not come up; see {}", paths.log.display());
}

pub fn stop() -> Result<()> {
    let paths = Paths::resolve()?;
    let Some(pid) = read_pid(&paths.pid) else {
        println!("daemon is not running");
        return Ok(());
    };
    if !pid_alive(pid) {
        cleanup_stale(&paths);
        println!("daemon is not running");
        return Ok(());
    }
    kill_pid(pid)?;
    for _ in 0..40 {
        if !pid_alive(pid) {
            cleanup_stale(&paths);
            println!("daemon stopped");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    bail!("daemon pid {pid} did not exit");
}

pub async fn run_foreground() -> Result<()> {
    run_agent().await
}

async fn run_agent() -> Result<()> {
    let paths = Paths::resolve()?;
    let cfg = Config::default();
    cleanup_stale(&paths);

    let node_id = config::load_or_create_node_id(&paths)?;
    let secret = net::load_or_create_secret(&paths.secret)?;
    let endpoint = net::bind_endpoint(secret).await?;
    let state = Arc::new(StateFile::open(&paths)?);
    let backend = clipboard::open(&paths.dir)?;
    let hub = Hub::new(node_id, backend, Arc::clone(&state), cfg.suppress_ttl);
    let (shutdown, sh_rx) = watch::channel(false);

    let rt = Arc::new(Runtime {
        hub,
        state: Arc::clone(&state),
        peers: Mutex::new(HashMap::new()),
        live: Mutex::new(HashSet::new()),
        endpoint,
        ticket: Mutex::new(None),
        shutdown,
    });

    start_ipc_listener(&paths, Arc::clone(&rt))?;
    write_pid(&paths.pid, std::process::id())?;
    let _guard = SockGuard {
        sock: paths.sock.clone(),
        pid: paths.pid.clone(),
    };

    let watch_hub = rt.hub.clone();
    let mut watch_stop = sh_rx.clone();
    tokio::spawn(async move {
        watch_clipboard(
            watch_hub,
            cfg.poll_interval,
            cfg.debounce,
            &mut watch_stop,
        )
        .await;
    });

    let accept_rt = Arc::clone(&rt);
    tokio::spawn(async move {
        accept_loop(accept_rt).await;
    });

    let ticket_rt = Arc::clone(&rt);
    tokio::spawn(async move {
        refresh_ticket(&ticket_rt).await;
    });

    for peer in state.get().peers {
        if peer.enabled {
            spawn_peer(&rt, &peer.uri, false);
        }
    }

    wait_shutdown(sh_rx).await;
    let _ = rt.shutdown.send(true);
    Ok(())
}

struct SockGuard {
    sock: std::path::PathBuf,
    pid: std::path::PathBuf,
}

fn start_ipc_listener(paths: &config::Paths, rt: Arc<Runtime>) -> Result<()> {
    #[cfg(unix)]
    {
        let listener = UnixListener::bind(&paths.sock)
            .with_context(|| format!("bind {}", paths.sock.display()))?;
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let rt = Arc::clone(&rt);
                        tokio::spawn(async move {
                            if let Err(e) = handle_ipc(stream, rt).await {
                                tracing::debug!("ipc: {e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("accept: {e}");
                        break;
                    }
                }
            }
        });
    }
    #[cfg(windows)]
    {
        std::fs::write(&paths.sock, b"named-pipe\n")?;
        let name = ipc::pipe_name();
        tokio::spawn(async move {
            use tokio::net::windows::named_pipe::ServerOptions;
            let mut server = match ServerOptions::new()
                .first_pipe_instance(true)
                .create(&name)
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("named pipe: {e}");
                    return;
                }
            };
            loop {
                if server.connect().await.is_err() {
                    break;
                }
                let connected = server;
                server = match ServerOptions::new().create(&name) {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let rt = Arc::clone(&rt);
                tokio::spawn(async move {
                    if let Err(e) = handle_ipc(connected, rt).await {
                        tracing::debug!("ipc: {e:#}");
                    }
                });
            }
        });
    }
    Ok(())
}

impl Drop for SockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.sock);
        let _ = std::fs::remove_file(&self.pid);
    }
}

async fn wait_shutdown(mut rx: watch::Receiver<bool>) {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )
        .expect("sigterm");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
            _ = rx.changed() => {}
        }
    }
    #[cfg(not(unix))]
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = rx.changed() => {}
        }
    }
}

async fn watch_clipboard(
    hub: Hub,
    interval: Duration,
    debounce: Duration,
    shutdown: &mut watch::Receiver<bool>,
) {
    let clip = hub.clipboard();
    let mut last = Vec::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            _ = tokio::time::sleep(interval) => {
                let backend = Arc::clone(&clip);
                let item = match tokio::task::spawn_blocking(move || backend.get()).await {
                    Ok(Ok(Some(i))) if !i.data.is_empty() => i,
                    _ => continue,
                };
                if item.data == last {
                    continue;
                }
                tokio::select! {
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() { break; }
                    }
                    _ = tokio::time::sleep(debounce) => {}
                }
                let backend = Arc::clone(&clip);
                let item = match tokio::task::spawn_blocking(move || backend.get()).await {
                    Ok(Ok(Some(i))) if !i.data.is_empty() => i,
                    _ => continue,
                };
                if item.data == last {
                    continue;
                }
                last = item.data.clone();
                if let Err(e) = hub.local_observed(item) {
                    tracing::debug!("local_observed: {e:#}");
                }
            }
        }
    }
}

fn spawn_peer(rt: &Arc<Runtime>, uri: &str, force_dial: bool) {
    let target = match net::parse_peer(uri) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(%uri, "bad peer: {e:#}");
            return;
        }
    };
    let key = net::iroh_uri(target.endpoint_id);
    let mut map = rt.peers.lock().unwrap();
    if let Some(existing) = map.get(&key) {
        if !*existing.stop.borrow() {
            if force_dial {
                let _ = existing.stop.send(true);
                map.remove(&key);
            } else {
                return;
            }
        }
    }
    let (stop_tx, stop_rx) = watch::channel(false);
    let status = Arc::new(Mutex::new(PeerStatus {
        uri: target.uri.clone(),
        state: "connecting".into(),
        ..PeerStatus::default()
    }));
    map.insert(
        key,
        PeerEntry {
            status: Arc::clone(&status),
            stop: stop_tx,
        },
    );
    drop(map);
    let rt = Arc::clone(rt);
    tokio::spawn(async move {
        maintain_p2p(
            rt,
            target.addr,
            target.endpoint_id,
            status,
            stop_rx,
            force_dial,
        )
        .await;
    });
}

fn stop_peer(rt: &Arc<Runtime>, uri: &str) {
    let key = net::parse_peer(uri)
        .ok()
        .map(|t| net::iroh_uri(t.endpoint_id))
        .unwrap_or_else(|| uri.to_string());
    if let Some(p) = rt.peers.lock().unwrap().remove(&key) {
        let _ = p.stop.send(true);
    }
}

fn short_err(e: &anyhow::Error) -> String {
    let s = format!("{e:#}");
    if s.len() > 200 {
        format!("{}…", &s[..200])
    } else {
        s
    }
}

async fn refresh_ticket(rt: &Runtime) {
    if net::wait_online(&rt.endpoint).await.is_ok() {
        let t = net::ticket_for(&rt.endpoint);
        *rt.ticket.lock().unwrap() = Some(t);
    } else {
        let t = net::ticket_for(&rt.endpoint);
        *rt.ticket.lock().unwrap() = Some(t);
    }
}

fn claim_live(rt: &Runtime, remote: &str) -> bool {
    rt.live.lock().unwrap().insert(remote.to_string())
}

fn release_live(rt: &Runtime, remote: &str) {
    rt.live.lock().unwrap().remove(remote);
}

fn remember_incoming(rt: &Arc<Runtime>, remote_id: iroh::EndpointId) {
    let uri = net::iroh_uri(remote_id);
    let _ = rt.state.upsert_peer(&uri, true);
    let mut map = rt.peers.lock().unwrap();
    map.entry(uri.clone()).or_insert_with(|| {
        let (stop_tx, _stop_rx) = watch::channel(false);
        PeerEntry {
            status: Arc::new(Mutex::new(PeerStatus {
                uri,
                state: "connected".into(),
                remote_node: Some(remote_id.to_string()),
                ..PeerStatus::default()
            })),
            stop: stop_tx,
        }
    });
}

async fn accept_loop(rt: Arc<Runtime>) {
    let ep = rt.endpoint.clone();
    loop {
        match ep.accept().await {
            None => break,
            Some(incoming) => {
                let rt = Arc::clone(&rt);
                tokio::spawn(async move {
                    if let Err(e) = run_incoming(rt, incoming).await {
                        tracing::warn!("incoming p2p: {e:#}");
                    }
                });
            }
        }
    }
}

async fn run_incoming(
    rt: Arc<Runtime>,
    incoming: iroh::endpoint::Incoming,
) -> Result<()> {
    let conn = incoming.await.context("accept iroh connection")?;
    let remote = conn.remote_id();
    let remote_s = remote.to_string();
    if !claim_live(&rt, &remote_s) {
        conn.close(0u32.into(), b"already connected");
        return Ok(());
    }
    remember_incoming(&rt, remote);
    let (status, stop) = {
        let map = rt.peers.lock().unwrap();
        let e = map
            .get(&net::iroh_uri(remote))
            .expect("incoming peer just inserted");
        (Arc::clone(&e.status), e.stop.subscribe())
    };
    let result = run_p2p_accept(&rt.hub, conn, Some(&status), stop).await;
    release_live(&rt, &remote_s);
    result
}

async fn run_p2p_accept(
    hub: &Hub,
    conn: IrohConn,
    status: Option<&Mutex<PeerStatus>>,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let (mut writer, mut reader) = conn.accept_bi().await?;
    let (typ, payload) = protocol::read_frame(&mut reader).await?;
    if typ != Type::Hello {
        bail!("p2p accept expected Hello, got {typ:?}");
    }
    let remote: protocol::Hello = serde_json::from_slice(&payload)?;
    protocol::write_json(&mut writer, Type::HelloAck, &hub.hello()).await?;
    if let Some(st) = status {
        let mut s = st.lock().unwrap();
        s.state = "connected".into();
        s.remote_node = Some(remote.node_id.clone());
        s.remote_host = Some(remote.hostname.clone());
        s.last_error = None;
    }
    framed_loop(
        hub,
        &mut reader,
        &mut writer,
        &mut stop,
        status,
        Some(remote.node_id),
    )
    .await
}

async fn maintain_p2p(
    rt: Arc<Runtime>,
    addr: iroh::EndpointAddr,
    endpoint_id: iroh::EndpointId,
    status: Arc<Mutex<PeerStatus>>,
    mut stop: watch::Receiver<bool>,
    force_dial: bool,
) {
    let remote_s = endpoint_id.to_string();
    if !net::should_dial(rt.hub.node_id(), endpoint_id, force_dial) {
        status.lock().unwrap().state = "waiting".into();
        let _ = stop.changed().await;
        return;
    }
    let mut delay = Duration::from_secs(1);
    loop {
        if *stop.borrow() {
            break;
        }
        if rt.live.lock().unwrap().contains(&remote_s) {
            status.lock().unwrap().state = "connected".into();
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                _ = stop.changed() => {
                    if *stop.borrow() {
                        break;
                    }
                }
            }
            continue;
        }
        status.lock().unwrap().state = "connecting".into();
        match run_p2p_dial(&rt, &addr, &remote_s, &status, &mut stop).await {
            Ok(()) => delay = Duration::from_secs(1),
            Err(e) => {
                tracing::warn!(peer = %remote_s, error = %e, "p2p session ended");
                status.lock().unwrap().last_error = Some(short_err(&e));
            }
        }
        if *stop.borrow() {
            break;
        }
        status.lock().unwrap().state = "reconnecting".into();
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = stop.changed() => {
                if *stop.borrow() {
                    break;
                }
            }
        }
        delay = (delay * 2).min(Duration::from_secs(30));
    }
    status.lock().unwrap().state = "disconnected".into();
}

async fn run_p2p_dial(
    rt: &Runtime,
    addr: &iroh::EndpointAddr,
    remote_s: &str,
    status: &Mutex<PeerStatus>,
    stop: &mut watch::Receiver<bool>,
) -> Result<()> {
    let conn = rt
        .endpoint
        .connect(addr.clone(), ALPN)
        .await
        .context("iroh connect")?;
    if !claim_live(rt, remote_s) {
        conn.close(0u32.into(), b"already connected");
        return Ok(());
    }
    let result = run_p2p_init(&rt.hub, conn, status, stop).await;
    release_live(rt, remote_s);
    result
}

async fn run_p2p_init(
    hub: &Hub,
    conn: IrohConn,
    status: &Mutex<PeerStatus>,
    stop: &mut watch::Receiver<bool>,
) -> Result<()> {
    let (mut writer, mut reader) = conn.open_bi().await?;
    protocol::write_json(&mut writer, Type::Hello, &hub.hello()).await?;
    let (typ, payload) = protocol::read_frame(&mut reader).await?;
    if typ != Type::HelloAck && typ != Type::Hello {
        bail!("expected HelloAck, got {typ:?}");
    }
    let remote: protocol::Hello = serde_json::from_slice(&payload)?;
    {
        let mut s = status.lock().unwrap();
        s.state = "connected".into();
        s.remote_node = Some(remote.node_id.clone());
        s.remote_host = Some(remote.hostname.clone());
        s.last_error = None;
    }
    if typ == Type::Hello {
        protocol::write_json(&mut writer, Type::HelloAck, &hub.hello()).await?;
    }
    framed_loop(
        hub,
        &mut reader,
        &mut writer,
        stop,
        Some(status),
        Some(remote.node_id),
    )
    .await
}

async fn framed_loop<R, W>(
    hub: &Hub,
    reader: &mut R,
    writer: &mut W,
    stop: &mut watch::Receiver<bool>,
    status: Option<&Mutex<PeerStatus>>,
    peer_id: Option<String>,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut rx = hub.subscribe();
    let mut ping = tokio::time::interval(Duration::from_secs(30));
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = stop.changed() => {
                if *stop.borrow() {
                    let _ = protocol::write_frame(writer, Type::Bye, &[]).await;
                    break;
                }
            }
            _ = ping.tick() => {
                protocol::write_frame(writer, Type::Ping, &[]).await?;
            }
            msg = rx.recv() => {
                match msg {
                    Ok(out) => {
                        if out.skip.is_some() && out.skip == peer_id {
                            continue;
                        }
                        protocol::write_clip(writer, &out.clip).await?;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
            frame = protocol::read_frame(reader) => {
                let (typ, payload) = frame?;
                match typ {
                    Type::Clip => {
                        let clip = protocol::decode_clip(&payload)?;
                        let ack = if let Some(id) = peer_id.as_deref() {
                            hub.apply_from(clip, id)?
                        } else {
                            hub.apply_remote(clip)?
                        };
                        protocol::write_json(writer, Type::ClipAck, &ack).await?;
                        if let Some(st) = status {
                            st.lock().unwrap().last_sync = Some(unix_now());
                        }
                    }
                    Type::Ping => {
                        protocol::write_frame(writer, Type::Pong, &payload).await?;
                    }
                    Type::Pong | Type::ClipAck => {}
                    Type::Bye | Type::Error => break,
                    Type::Hello => {
                        protocol::write_json(writer, Type::HelloAck, &hub.hello()).await?;
                    }
                    Type::HelloAck => {}
                }
            }
        }
    }
    Ok(())
}

fn unix_now() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into())
}

async fn handle_ipc<S>(mut stream: S, rt: Arc<Runtime>) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    loop {
        let (req, n) =
            match ipc::read_line_json::<Request, _>(&mut stream).await {
                Ok(v) => v,
                Err(_) => break,
            };
        let body = ipc::read_exact_body(&mut stream, n).await?;
        if req.action == "pair" {
            refresh_ticket(&rt).await;
            let ticket = rt.ticket.lock().unwrap().clone();
            let resp = if let Some(ticket) = ticket {
                Response {
                    ok: true,
                    ticket: Some(ticket),
                    ..Response::default()
                }
            } else {
                Response {
                    ok: false,
                    error: Some("no ticket yet; retry in a second".into()),
                    ..Response::default()
                }
            };
            ipc::write_msg(&mut stream, &resp, &[]).await?;
            continue;
        }
        let (mut resp, out) = dispatch(&rt, req, body);
        resp.n = out.len();
        ipc::write_msg(&mut stream, &resp, &out).await?;
    }
    Ok(())
}

fn dispatch(
    rt: &Arc<Runtime>,
    req: Request,
    body: Vec<u8>,
) -> (Response, Vec<u8>) {
    match req.action.as_str() {
        "status" => (
            Response {
                ok: true,
                status: Some(collect_status(rt)),
                ..Response::default()
            },
            Vec::new(),
        ),
        "connect" => match req.uri {
            None => err_resp("missing uri"),
            Some(uri) => {
                let target = match net::parse_peer(&uri) {
                    Ok(t) => t,
                    Err(e) => return err_resp(&e.to_string()),
                };
                let stored = target.uri.clone();
                if let Err(e) = rt.state.upsert_peer(&stored, true) {
                    return err_resp(&e.to_string());
                }
                spawn_peer(rt, &stored, true);
                (
                    Response {
                        ok: true,
                        ..Response::default()
                    },
                    Vec::new(),
                )
            }
        },
        "disconnect" => {
            let removed = match rt.state.remove_peer(req.uri.as_deref()) {
                Ok(v) => v,
                Err(e) => return err_resp(&e.to_string()),
            };
            if removed.is_empty() {
                let uris: Vec<String> =
                    rt.peers.lock().unwrap().keys().cloned().collect();
                for u in uris {
                    stop_peer(rt, &u);
                }
            } else {
                for u in &removed {
                    stop_peer(rt, u);
                }
            }
            (
                Response {
                    ok: true,
                    ..Response::default()
                },
                Vec::new(),
            )
        }
        "copy" => {
            let item = Item::new(req.mime.unwrap_or_default(), body);
            match rt.hub.local_push(item) {
                Ok(_) => (
                    Response {
                        ok: true,
                        ..Response::default()
                    },
                    Vec::new(),
                ),
                Err(e) => err_resp(&e.to_string()),
            }
        }
        "paste" => match rt.hub.snapshot() {
            Ok(Some(item)) => {
                let headless = rt.hub.clipboard().headless();
                let want_path = req.path_only.unwrap_or(false);
                let want_content = req.content_only.unwrap_or(false);
                let use_path = want_path || (headless && !want_content);
                let path = {
                    let p = rt.hub.clipboard().current_path();
                    if p.as_os_str().is_empty() {
                        None
                    } else {
                        Some(p.to_string_lossy().into_owned())
                    }
                };
                if use_path {
                    (
                        Response {
                            ok: true,
                            mime: Some(item.mime),
                            path,
                            headless: Some(headless),
                            ..Response::default()
                        },
                        Vec::new(),
                    )
                } else {
                    (
                        Response {
                            ok: true,
                            mime: Some(item.mime.clone()),
                            path,
                            headless: Some(headless),
                            n: item.data.len(),
                            ..Response::default()
                        },
                        item.data,
                    )
                }
            }
            Ok(None) => err_resp("clipboard is empty"),
            Err(e) => err_resp(&e.to_string()),
        },
        other => err_resp(&format!("unknown action {other}")),
    }
}

fn err_resp(msg: &str) -> (Response, Vec<u8>) {
    (
        Response {
            ok: false,
            error: Some(msg.into()),
            ..Response::default()
        },
        Vec::new(),
    )
}

fn collect_status(rt: &Runtime) -> StatusPayload {
    let clip = rt.hub.clipboard();
    let cur = clip.get().ok().flatten();
    let peers = rt
        .peers
        .lock()
        .unwrap()
        .values()
        .map(|p| p.status.lock().unwrap().clone())
        .collect();
    StatusPayload {
        daemon_pid: std::process::id(),
        node_id: rt.hub.node_id().to_string(),
        clipboard: clip.name().to_string(),
        headless: clip.headless(),
        current_mime: cur.as_ref().map(|c| c.mime.clone()),
        current_hash: cur.as_ref().map(|c| c.hash.clone()),
        current_bytes: cur.as_ref().map(|c| c.data.len()),
        current_path: {
            let p = clip.current_path();
            if p.as_os_str().is_empty() {
                None
            } else {
                Some(p.to_string_lossy().into_owned())
            }
        },
        ticket: rt.ticket.lock().unwrap().clone(),
        peers,
    }
}
