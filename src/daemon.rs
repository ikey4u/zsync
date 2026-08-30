use std::{
    collections::{HashMap, HashSet},
    fs::OpenOptions,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{bail, Context, Result};
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
};

use crate::{
    clipboard::{self, Item},
    config::{
        self, kill_pid, pid_alive, read_pid, write_pid, Config, Paths,
        StateFile,
    },
    group,
    hub::Hub,
    ipc::{self, PeerStatus, Request, Response, StatusPayload},
    net,
    protocol::{self, Type},
    relay, tlsutil,
};

struct Runtime {
    hub: Hub,
    state: Arc<StateFile>,
    peers: Mutex<HashMap<String, PeerEntry>>,
    live: Mutex<HashSet<String>>,
    zsync_dir: std::path::PathBuf,
    port: u16,
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
    let port = net::listen_port();
    let listener = net::bind_listener(port).await?;
    let port = listener.local_addr()?.port();
    let state = Arc::new(StateFile::open(&paths)?);
    let backend = clipboard::open(&paths.dir)?;
    let hub = Hub::new(node_id, backend, Arc::clone(&state), cfg.suppress_ttl);
    let (shutdown, sh_rx) = watch::channel(false);

    let rt = Arc::new(Runtime {
        hub,
        state: Arc::clone(&state),
        peers: Mutex::new(HashMap::new()),
        live: Mutex::new(HashSet::new()),
        zsync_dir: paths.dir.clone(),
        port,
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
        accept_loop(accept_rt, listener).await;
    });

    for peer in state.get().peers {
        if peer.enabled {
            let mut target = match net::parse_peer(&peer.uri) {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(uri = %net::display_uri(&peer.uri), "bad peer: {e:#}");
                    continue;
                }
            };
            if let Err(e) = net::resolve_relay(&paths.dir, &mut target) {
                tracing::warn!(uri = %target.uri, "relay key: {e:#}");
                continue;
            }
            if target.uri != peer.uri {
                let _ = state.remove_peer(Some(&peer.uri));
                let _ = state.upsert_peer(&target.uri, true);
            }
            spawn_peer(&rt, &target.uri, false);
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
    let mut target = match net::parse_peer(uri) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(uri = %net::display_uri(uri), "bad peer: {e:#}");
            return;
        }
    };
    if let Err(e) = net::resolve_relay(&rt.zsync_dir, &mut target) {
        tracing::warn!(uri = %target.uri, "relay key: {e:#}");
        return;
    }
    let key = target.uri.clone();
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
    let relay = target.relay.is_some();
    tokio::spawn(async move {
        if relay {
            maintain_relay(rt, target, status, stop_rx).await;
        } else {
            maintain_tcp(rt, target, status, stop_rx).await;
        }
    });
}

fn stop_peer(rt: &Arc<Runtime>, uri: &str) {
    let key = net::parse_peer(uri)
        .map(|t| t.uri)
        .unwrap_or_else(|_| net::display_uri(uri));
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

fn claim_live(rt: &Runtime, remote: &str) -> bool {
    rt.live.lock().unwrap().insert(remote.to_string())
}

fn release_live(rt: &Runtime, remote: &str) {
    rt.live.lock().unwrap().remove(remote);
}

fn remember_incoming(rt: &Arc<Runtime>, uri: String, hello: &protocol::Hello) {
    let mut map = rt.peers.lock().unwrap();
    map.entry(uri.clone()).or_insert_with(|| {
        let (stop_tx, _stop_rx) = watch::channel(false);
        PeerEntry {
            status: Arc::new(Mutex::new(PeerStatus {
                uri,
                state: "connected".into(),
                remote_node: Some(hello.node_id.clone()),
                remote_host: Some(hello.hostname.clone()),
                ..PeerStatus::default()
            })),
            stop: stop_tx,
        }
    });
}

async fn accept_loop(rt: Arc<Runtime>, listener: TcpListener) {
    tracing::info!("listening on 0.0.0.0:{}", rt.port);
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let rt = Arc::clone(&rt);
                tokio::spawn(async move {
                    if let Err(e) = run_incoming(rt, stream, peer).await {
                        tracing::warn!("incoming: {e:#}");
                    }
                });
            }
            Err(e) => {
                tracing::warn!("accept: {e}");
                break;
            }
        }
    }
}

async fn run_incoming(
    rt: Arc<Runtime>,
    stream: TcpStream,
    peer: std::net::SocketAddr,
) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let (mut reader, mut writer) = stream.into_split();
    let (typ, payload) = protocol::read_frame(&mut reader).await?;
    if typ != Type::Hello {
        bail!("expected Hello, got {typ:?}");
    }
    let remote: protocol::Hello = serde_json::from_slice(&payload)?;
    let live_key = remote.node_id.clone();
    if !claim_live(&rt, &live_key) {
        return Ok(());
    }
    remember_incoming(&rt, peer.to_string(), &remote);
    let status = {
        let map = rt.peers.lock().unwrap();
        Arc::clone(
            &map.get(&peer.to_string())
                .expect("incoming peer just inserted")
                .status,
        )
    };
    let mut stop = {
        let map = rt.peers.lock().unwrap();
        map.get(&peer.to_string())
            .expect("incoming peer just inserted")
            .stop
            .subscribe()
    };
    protocol::write_json(&mut writer, Type::HelloAck, &rt.hub.hello()).await?;
    {
        let mut s = status.lock().unwrap();
        s.state = "connected".into();
        s.remote_node = Some(remote.node_id.clone());
        s.remote_host = Some(remote.hostname.clone());
        s.last_error = None;
    }
    let result = framed_loop(
        &rt.hub,
        &mut reader,
        &mut writer,
        &mut stop,
        Some(&status),
        Some(remote.node_id),
    )
    .await;
    release_live(&rt, &live_key);
    result
}

async fn maintain_tcp(
    rt: Arc<Runtime>,
    target: net::PeerTarget,
    status: Arc<Mutex<PeerStatus>>,
    mut stop: watch::Receiver<bool>,
) {
    let live_key = target.uri.clone();
    let mut delay = Duration::from_secs(1);
    loop {
        if *stop.borrow() {
            break;
        }
        if rt.live.lock().unwrap().contains(&live_key) {
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
        match run_tcp_dial(&rt, &target, &live_key, &status, &mut stop).await {
            Ok(()) => delay = Duration::from_secs(1),
            Err(e) => {
                tracing::warn!(peer = %live_key, error = %e, "session ended");
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

async fn run_tcp_dial(
    rt: &Runtime,
    target: &net::PeerTarget,
    live_key: &str,
    status: &Mutex<PeerStatus>,
    stop: &mut watch::Receiver<bool>,
) -> Result<()> {
    let stream = net::connect_peer(target).await?;
    if !claim_live(rt, live_key) {
        return Ok(());
    }
    let result = run_tcp_init(&rt.hub, stream, status, stop).await;
    release_live(rt, live_key);
    result
}

async fn run_tcp_init(
    hub: &Hub,
    stream: TcpStream,
    status: &Mutex<PeerStatus>,
    stop: &mut watch::Receiver<bool>,
) -> Result<()> {
    let (mut reader, mut writer) = stream.into_split();
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

async fn maintain_relay(
    rt: Arc<Runtime>,
    target: net::PeerTarget,
    status: Arc<Mutex<PeerStatus>>,
    mut stop: watch::Receiver<bool>,
) {
    let live_key = target.uri.clone();
    let mut delay = Duration::from_secs(1);
    loop {
        if *stop.borrow() {
            break;
        }
        status.lock().unwrap().state = "connecting".into();
        match run_relay_dial(&rt, &target, &live_key, &status, &mut stop).await
        {
            Ok(()) => delay = Duration::from_secs(1),
            Err(e) => {
                tracing::warn!(peer = %live_key, error = %e, "relay session ended");
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

async fn run_relay_dial(
    rt: &Runtime,
    target: &net::PeerTarget,
    live_key: &str,
    status: &Mutex<PeerStatus>,
    stop: &mut watch::Receiver<bool>,
) -> Result<()> {
    if !claim_live(rt, live_key) {
        return Ok(());
    }
    let result = run_relay_session(rt, target, status, stop).await;
    release_live(rt, live_key);
    result
}

async fn run_relay_session(
    rt: &Runtime,
    target: &net::PeerTarget,
    status: &Mutex<PeerStatus>,
    stop: &mut watch::Receiver<bool>,
) -> Result<()> {
    let relay_peer = target.relay.as_ref().context("not a relay peer")?;
    let key = relay_peer.key.context("relay key not resolved")?;
    let hub_addr = if target.host.contains(':') {
        format!("[{}]:{}", target.host, target.port)
    } else {
        format!("{}:{}", target.host, target.port)
    };
    let tcp = net::connect_peer(target).await?;
    let pin = tlsutil::load_pin(&rt.zsync_dir, &hub_addr)?;
    let (cfg, handle) = tlsutil::client_config(pin)?;
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(cfg));
    let name = tlsutil::server_name(&target.host)?;
    let tls = connector
        .connect(name, tcp)
        .await
        .context("tls handshake with relay")?;
    if pin.is_none() {
        if let Some(got) = handle.observed() {
            tlsutil::save_pin(&rt.zsync_dir, &hub_addr, &got)?;
            tracing::info!(hub = %hub_addr, "pinned relay certificate");
        }
    }
    let (mut reader, mut writer) = tokio::io::split(tls);
    let join = relay::Join {
        group_id: group::hex_encode(&relay_peer.group_id),
        device_id: rt.hub.node_id().to_string(),
        hostname: config::hostname(),
        version: config::crate_version().into(),
    };
    relay::write_json(&mut writer, relay::Type::Join, &join).await?;
    let (typ, payload) = relay::read_frame(&mut reader).await?;
    match typ {
        relay::Type::JoinAck => {
            let ack: relay::JoinAck = serde_json::from_slice(&payload)?;
            if !ack.ok {
                bail!("join rejected: {}", ack.message);
            }
        }
        relay::Type::Error => {
            let err: relay::ErrorMsg = serde_json::from_slice(&payload)
                .unwrap_or(relay::ErrorMsg {
                    code: "error".into(),
                    message: String::from_utf8_lossy(&payload).into(),
                });
            bail!("join {}: {}", err.code, err.message);
        }
        other => bail!("expected JoinAck, got {other:?}"),
    }
    {
        let mut s = status.lock().unwrap();
        s.state = "connected".into();
        s.remote_host = Some(hub_addr);
        s.last_error = None;
    }
    let sender = group::sender_from_node_id(rt.hub.node_id())?;
    let mut counter = 0u64;
    let mut rx = rt.hub.subscribe();
    let mut ping = tokio::time::interval(Duration::from_secs(30));
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = stop.changed() => {
                if *stop.borrow() {
                    let _ = relay::write_frame(&mut writer, relay::Type::Bye, &[]).await;
                    break;
                }
            }
            _ = ping.tick() => {
                relay::write_frame(&mut writer, relay::Type::Ping, &[]).await?;
            }
            msg = rx.recv() => {
                match msg {
                    Ok(out) if out.skip.is_none() => {
                        counter = counter.wrapping_add(1);
                        let body = protocol::encode_clip_body(&out.clip)?;
                        let env = group::seal(
                            &key,
                            &relay_peer.group_id,
                            &sender,
                            counter,
                            &body,
                        )?;
                        relay::write_frame(&mut writer, relay::Type::Data, &env).await?;
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
            frame = relay::read_frame(&mut reader) => {
                let (typ, payload) = frame?;
                match typ {
                    relay::Type::Data => {
                        let opened = group::open(&key, &relay_peer.group_id, &payload)?;
                        let clip = protocol::decode_clip(&opened.plaintext)?;
                        if let Err(e) = protocol::verify_clip(&clip) {
                            tracing::warn!("drop incomplete clip: {e}");
                            continue;
                        }
                        let from = group::hex_encode(&opened.sender);
                        rt.hub.apply_from(clip, &from)?;
                        if let Ok(mut s) = status.lock() {
                            s.last_sync = Some(unix_now());
                        }
                    }
                    relay::Type::Ping => {
                        relay::write_frame(&mut writer, relay::Type::Pong, &payload).await?;
                    }
                    relay::Type::Pong | relay::Type::JoinAck => {}
                    relay::Type::Bye | relay::Type::Error => break,
                    relay::Type::Join => {}
                }
            }
        }
    }
    Ok(())
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
                        match protocol::decode_clip(&payload) {
                            Ok(clip) => {
                                let ack = if let Some(id) = peer_id.as_deref()
                                {
                                    hub.apply_from(clip, id)?
                                } else {
                                    hub.apply_remote(clip)?
                                };
                                protocol::write_json(
                                    writer,
                                    Type::ClipAck,
                                    &ack,
                                )
                                .await?;
                                if ack.ok {
                                    if let Some(st) = status {
                                        st.lock().unwrap().last_sync =
                                            Some(unix_now());
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("drop incomplete clip: {e}");
                                protocol::write_json(
                                    writer,
                                    Type::ClipAck,
                                    &protocol::ClipAck {
                                        hash: String::new(),
                                        ok: false,
                                        reason: "truncated".into(),
                                    },
                                )
                                .await?;
                            }
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
                let mut target = match net::parse_peer(&uri) {
                    Ok(t) => t,
                    Err(e) => return err_resp(&e.to_string()),
                };
                if let Err(e) = net::resolve_relay(&rt.zsync_dir, &mut target) {
                    return err_resp(&e.to_string());
                }
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
                let path = {
                    let p = rt.hub.clipboard().current_path();
                    if p.as_os_str().is_empty() {
                        None
                    } else {
                        Some(p.to_string_lossy().into_owned())
                    }
                };
                (
                    Response {
                        ok: true,
                        mime: Some(item.mime.clone()),
                        path,
                        headless: Some(headless),
                        n: item.data.len(),
                        name: if item.name.is_empty() {
                            None
                        } else {
                            Some(item.name.clone())
                        },
                        ..Response::default()
                    },
                    item.data,
                )
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
        port: rt.port,
        peers,
    }
}
