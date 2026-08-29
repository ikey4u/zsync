#[tokio::main]
async fn main() {
    let daemon_fg = std::env::args().any(|a| a == "--foreground" || a == "-f")
        && std::env::args().any(|a| a == "daemon");
    let filter = if daemon_fg { "info" } else { "warn" };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();

    if let Err(e) = zsync::run().await {
        eprintln!("zsync: {e:#}");
        std::process::exit(1);
    }
}
