pub mod clipboard;
pub mod config;
pub mod daemon;
pub mod hub;
pub mod ipc;
pub mod net;
pub mod protocol;
pub mod suppress;

use anyhow::Result;

pub async fn run() -> Result<()> {
    crate::cli::run().await
}

mod cli;
