use std::{
    io::{self, Write},
    path::PathBuf,
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use tokio::io::AsyncReadExt;

use crate::{
    clipboard::{self, Item},
    config::{Paths, ZSYNC_VERSION},
    daemon,
    ipc::{self, Request},
    protocol::{detect_mime, MAX_CLIP},
};

const CLIPBOARD_HELP: &str = "\
Clipboard in editors
  Remote Linux has no X11 clipboard. Point the editor at zsync (daemon must
  be running). `zsync p` prints a file path; editors must use --content.

  Neovim  ~/.config/nvim/init.lua
    vim.g.clipboard = {
      name = \"zsync\",
      copy = { [\"+\"] = { \"zsync\", \"c\" }, [\"*\"] = { \"zsync\", \"c\" } },
      paste = {
        [\"+\"] = { \"zsync\", \"p\", \"--content\" },
        [\"*\"] = { \"zsync\", \"p\", \"--content\" },
      },
      cache_enabled = 0,
    }
    vim.opt.clipboard = \"unnamedplus\"

  Vim  ~/.vimrc  (no g:clipboard; map explicitly)
    vnoremap <silent> \"+y :w !zsync c<CR><CR>
    nnoremap <silent> \"+y :.w !zsync c<CR><CR>
    nnoremap <silent> \"+p :r !zsync p --content<CR>

  tmux  ~/.tmux.conf
    set -s copy-command \"zsync c\"
    bind-key -T copy-mode-vi y send-keys -X copy-pipe-and-cancel \"zsync c\"
    bind-key C-p run-shell \"zsync p --content | tmux load-buffer - && tmux paste-buffer\"

  zmux
    Copy mode yank and Prefix+] already call zsync when `zsync` is on PATH
    (also ~/.local/bin and ~/.cargo/bin). Pane OSC 52 is relayed and also
    copied into zsync. For Neovim inside a zmux pane, use the zsync provider
    above (not osc52). Both machines need `zsync daemon` and a one-time pair.

  Optional xclip shim
    ln -sf \"$(command -v zsync)\" ~/.local/bin/xclip
";

#[derive(Parser, Debug)]
#[command(
    name = "zsync",
    version = ZSYNC_VERSION,
    about = "Clipboard sync over QUIC (hole punching)",
    after_long_help = CLIPBOARD_HELP,
    disable_help_subcommand = false
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start or control the background daemon
    Daemon {
        #[command(subcommand)]
        action: Option<DaemonAction>,
        /// Run in the foreground (do not spawn)
        #[arg(long, short = 'f', global = true)]
        foreground: bool,
    },
    /// Print a ticket the other machine can `zsync connect`
    Pair,
    /// Connect to a peer (iroh ticket or iroh://id)
    Connect {
        /// Ticket from `zsync pair`, or iroh://endpoint-id
        uri: String,
    },
    /// Drop a saved peer
    Disconnect { uri: Option<String> },
    /// Show daemon and peer status
    Status,
    /// Copy data into the clipboard and sync it
    #[command(visible_alias = "c")]
    Copy {
        /// Text to copy. If omitted and stdin is a pipe, read stdin.
        text: Vec<String>,
    },
    /// Paste the current clip (content on GUI, path on headless)
    #[command(visible_alias = "p")]
    Paste {
        /// Always print the on-disk path
        #[arg(long)]
        path: bool,
        /// Always print the payload bytes
        #[arg(long)]
        content: bool,
    },
    /// xclip/xsel compatible CLI (also used when argv0 is xclip or xsel)
    Xclip {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
enum DaemonAction {
    /// Stop a running daemon
    Stop,
}

pub async fn run() -> Result<()> {
    let argv: Vec<String> = std::env::args().collect();
    if looks_like_xclip(&argv) {
        return xclip_compat(&xclip_args(&argv)).await;
    }
    let cli = Cli::parse();
    match cli.command {
        Commands::Daemon { action, foreground } => match action {
            Some(DaemonAction::Stop) => daemon::stop(),
            None if foreground => daemon::run_foreground().await,
            None => daemon::start(),
        },
        Commands::Pair => pair().await,
        Commands::Connect { uri } => connect(&uri).await,
        Commands::Disconnect { uri } => disconnect(uri.as_deref()).await,
        Commands::Status => status().await,
        Commands::Copy { text } => copy(text).await,
        Commands::Paste { path, content } => paste(path, content).await,
        Commands::Xclip { args } => xclip_compat(&args).await,
    }
}

async fn pair() -> Result<()> {
    let mut conn = ipc::connect(&Paths::resolve()?)
        .await
        .context("daemon is not running; start it with `zsync daemon`")?;
    let resp = conn
        .roundtrip(
            &Request {
                action: "pair".into(),
                ..Request::default()
            },
            &[],
        )
        .await?;
    if !resp.ok {
        bail!("{}", resp.error.unwrap_or_else(|| "pair failed".into()));
    }
    let ticket = resp.ticket.context("daemon returned no ticket")?;
    println!("{ticket}");
    eprintln!("on the other machine: zsync connect <this-ticket>");
    Ok(())
}

async fn connect(uri: &str) -> Result<()> {
    let target = crate::net::parse_peer(uri)?;
    let stored = target.uri.clone();
    let mut conn = ipc::connect(&Paths::resolve()?)
        .await
        .context("daemon is not running; start it with `zsync daemon`")?;
    let resp = conn
        .roundtrip(
            &Request {
                action: "connect".into(),
                uri: Some(stored.clone()),
                ..Request::default()
            },
            &[],
        )
        .await?;
    if !resp.ok {
        bail!("{}", resp.error.unwrap_or_else(|| "connect failed".into()));
    }
    println!("connecting {stored}");
    Ok(())
}

async fn disconnect(uri: Option<&str>) -> Result<()> {
    let mut conn = ipc::connect(&Paths::resolve()?)
        .await
        .context("daemon is not running")?;
    let resp = conn
        .roundtrip(
            &Request {
                action: "disconnect".into(),
                uri: uri.map(str::to_string),
                ..Request::default()
            },
            &[],
        )
        .await?;
    if !resp.ok {
        bail!(
            "{}",
            resp.error.unwrap_or_else(|| "disconnect failed".into())
        );
    }
    println!("disconnected");
    Ok(())
}

async fn status() -> Result<()> {
    let paths = Paths::resolve()?;
    if !daemon::is_running(&paths) {
        println!("daemon: not running");
        println!("hint:    zsync daemon");
        return Ok(());
    }
    let mut conn = ipc::connect(&paths).await?;
    let resp = conn
        .roundtrip(
            &Request {
                action: "status".into(),
                ..Request::default()
            },
            &[],
        )
        .await?;
    if !resp.ok {
        bail!("{}", resp.error.unwrap_or_else(|| "status failed".into()));
    }
    let Some(st) = resp.status else {
        bail!("daemon returned empty status");
    };
    println!("daemon:    running (pid {})", st.daemon_pid);
    println!("node:      {}", st.node_id);
    if let Some(t) = &st.ticket {
        println!("ticket:    {t}");
    }
    println!(
        "clipboard: {}{}",
        st.clipboard,
        if st.headless { " (headless)" } else { "" }
    );
    if let Some(mime) = &st.current_mime {
        println!(
            "current:   {mime}  {} bytes  {}",
            st.current_bytes.unwrap_or(0),
            st.current_hash
                .as_deref()
                .map(|h| &h[..h.len().min(12)])
                .unwrap_or("-")
        );
    }
    if let Some(path) = &st.current_path {
        println!("path:      {path}");
    }
    if st.peers.is_empty() {
        println!("peers:     none");
    }
    for p in st.peers {
        println!("peer:      {}", p.uri);
        println!("           state: {}", p.state);
        if let Some(n) = p.remote_node {
            println!("           remote: {n}");
        }
        if let Some(h) = p.remote_host {
            println!("           host:   {h}");
        }
        if let Some(s) = p.last_sync {
            println!("           last:   {s}");
        }
        if let Some(e) = p.last_error {
            println!("           error:  {e}");
        }
    }
    Ok(())
}

async fn copy(text: Vec<String>) -> Result<()> {
    let data = read_copy_payload(text).await?;
    put_clipboard(data).await
}

async fn put_clipboard(data: Vec<u8>) -> Result<()> {
    if data.len() > MAX_CLIP {
        bail!("clipboard payload exceeds 10MiB");
    }
    let mime = detect_mime(&data);
    let paths = Paths::resolve()?;
    if daemon::is_running(&paths) {
        let mut conn = ipc::connect(&paths).await?;
        let resp = conn
            .roundtrip(
                &Request {
                    action: "copy".into(),
                    mime: Some(mime.clone()),
                    ..Request::default()
                },
                &data,
            )
            .await?;
        if !resp.ok {
            bail!("{}", resp.error.unwrap_or_else(|| "copy failed".into()));
        }
        return Ok(());
    }
    let backend = clipboard::open(&paths.dir)?;
    let item = Item {
        mime,
        data,
        hash: String::new(),
        path: PathBuf::new(),
    };
    backend.set(&item)?;
    Ok(())
}

async fn read_copy_payload(text: Vec<String>) -> Result<Vec<u8>> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        let mut buf = Vec::new();
        tokio::io::stdin()
            .take((MAX_CLIP as u64) + 1)
            .read_to_end(&mut buf)
            .await?;
        if buf.len() > MAX_CLIP {
            bail!("clipboard payload exceeds 10MiB");
        }
        return Ok(buf);
    }
    if text.is_empty() {
        bail!("nothing to copy; pipe data or pass text: echo hi | zsync c");
    }
    Ok(text.join(" ").into_bytes())
}

async fn paste(want_path: bool, want_content: bool) -> Result<()> {
    if want_path && want_content {
        bail!("--path and --content are mutually exclusive");
    }
    let paths = Paths::resolve()?;
    if daemon::is_running(&paths) {
        let mut conn = ipc::connect(&paths).await?;
        let resp = conn
            .roundtrip(
                &Request {
                    action: "paste".into(),
                    path_only: Some(want_path),
                    content_only: Some(want_content),
                    ..Request::default()
                },
                &[],
            )
            .await?;
        if !resp.ok {
            bail!("{}", resp.error.unwrap_or_else(|| "paste failed".into()));
        }
        return write_paste(want_path, want_content, &resp);
    }
    let backend = clipboard::open(&paths.dir)?;
    let item = backend.get()?.context("clipboard is empty")?;
    let fake = ipc::Response {
        ok: true,
        mime: Some(item.mime),
        n: item.data.len(),
        path: {
            let p = backend.current_path();
            if p.as_os_str().is_empty() {
                None
            } else {
                Some(p.to_string_lossy().into_owned())
            }
        },
        headless: Some(backend.headless()),
        body: item.data,
        ..ipc::Response::default()
    };
    write_paste(want_path, want_content, &fake)
}

fn write_paste(
    want_path: bool,
    want_content: bool,
    resp: &ipc::Response,
) -> Result<()> {
    let headless = resp.headless.unwrap_or(false);
    let use_path = want_path || (headless && !want_content);
    if use_path {
        let path = resp.path.as_deref().context("no on-disk clip path")?;
        println!("{path}");
        return Ok(());
    }
    let mut out = io::stdout();
    if !resp.body.is_empty() {
        out.write_all(&resp.body)?;
    }
    out.flush()?;
    Ok(())
}

fn looks_like_xclip(argv: &[String]) -> bool {
    let Some(argv0) = argv.first() else {
        return false;
    };
    matches!(
        std::path::Path::new(argv0)
            .file_stem()
            .and_then(|s| s.to_str()),
        Some("xclip" | "xsel")
    )
}

fn xclip_args(argv: &[String]) -> Vec<String> {
    argv.iter().skip(1).cloned().collect()
}

struct XclipOpts {
    output: bool,
    filter: bool,
    drop_last_nl: bool,
    file: Option<PathBuf>,
}

fn parse_xclip_args(args: &[String]) -> Result<XclipOpts> {
    let mut output = false;
    let mut input = false;
    let mut filter = false;
    let mut drop_last_nl = false;
    let mut file = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-o" | "-out" | "--output" => output = true,
            "-i" | "-in" | "--input" => input = true,
            "-f" | "-filter" => filter = true,
            "-r" | "-rmlastnl" => drop_last_nl = true,
            "-selection" | "-d" | "-display" | "-t" | "-target" | "-loops"
            | "-l" => {
                i += 1;
            }
            "-silent" | "-quiet" | "-verbose" | "-noutf8" | "--clipboard"
            | "-b" | "--primary" | "-p" | "--secondary" | "-s"
            | "--nodetach" | "--detach" | "-n" | "--newline" => {}
            "-h" | "-help" | "--help" => {
                eprint_xclip_help();
                std::process::exit(0);
            }
            "-version" | "--version" => {
                println!("xclip (zsync {ZSYNC_VERSION})");
                std::process::exit(0);
            }
            s if s.starts_with('-') => {}
            s => file = Some(PathBuf::from(s)),
        }
        i += 1;
    }
    if output && input {
        bail!("xclip: -i and -o are mutually exclusive");
    }
    Ok(XclipOpts {
        output,
        filter,
        drop_last_nl,
        file,
    })
}

fn eprint_xclip_help() {
    eprintln!(
        "zsync xclip: drop-in for xclip/xsel using the zsync clipboard\n\
         -i / --input    copy stdin (or FILE) into zsync\n\
         -o / --output   paste zsync clipboard to stdout\n\
         -f / -filter    copy, then also write the bytes to stdout\n\
         selections (-selection / -b) are ignored; zsync has one clipboard"
    );
}

async fn xclip_compat(args: &[String]) -> Result<()> {
    let opts = parse_xclip_args(args)?;
    if opts.output {
        return paste(false, true).await;
    }
    let mut data = if let Some(path) = opts.file {
        tokio::fs::read(&path)
            .await
            .with_context(|| format!("read {}", path.display()))?
    } else {
        let mut buf = Vec::new();
        tokio::io::stdin()
            .take((MAX_CLIP as u64) + 1)
            .read_to_end(&mut buf)
            .await?;
        buf
    };
    if data.len() > MAX_CLIP {
        bail!("clipboard payload exceeds 10MiB");
    }
    if opts.drop_last_nl && data.last() == Some(&b'\n') {
        data.pop();
    }
    if opts.filter {
        io::stdout().write_all(&data)?;
        io::stdout().flush()?;
    }
    copy_bytes(data).await
}

async fn copy_bytes(data: Vec<u8>) -> Result<()> {
    put_clipboard(data).await
}
