pub mod clipboard;
pub mod config;
pub mod daemon;
pub mod group;
pub mod hub;
pub mod ipc;
pub mod net;
pub mod protocol;
pub mod relay;
pub mod suppress;
pub mod tlsutil;
pub mod zsyncd;

use anyhow::Result;

pub async fn run() -> Result<()> {
    crate::tlsutil::install_crypto_provider();
    crate::cli::run().await
}

mod cli;
