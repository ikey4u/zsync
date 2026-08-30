#[tokio::main]
async fn main() {
    tlsutil_install();
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();

    if let Err(e) = zsync::zsyncd::run().await {
        eprintln!("zsyncd: {e:#}");
        std::process::exit(1);
    }
}

fn tlsutil_install() {
    zsync::tlsutil::install_crypto_provider();
}
