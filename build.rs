use std::process::Command;

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn git_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .map(|output| output.status.success() && !output.stdout.is_empty())
        .unwrap_or(false)
}

fn main() {
    let pkg_version =
        std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());

    let mut version = pkg_version.clone();
    if let Some(commit) = git_output(&["log", "-1", "--format=%h"]) {
        version = format!("{pkg_version}-{commit}");
        if git_dirty() {
            version.push_str("+dirty");
        }
    }

    println!("cargo:rustc-env=ZSYNC_VERSION={version}");
}
