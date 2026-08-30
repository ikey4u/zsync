#[cfg(not(target_os = "windows"))]
use std::{
    io::Write,
    process::{Command, Stdio},
};
use std::{path::Path, sync::Arc};

use anyhow::Result;
#[cfg(not(target_os = "windows"))]
use anyhow::{bail, Context};

use super::{Backend, FileBackend, Item};

struct Native {
    name: &'static str,
    file: FileBackend,
    getter: fn() -> Result<Option<Item>>,
    setter: fn(&Item) -> Result<()>,
}

impl Backend for Native {
    fn name(&self) -> &str {
        self.name
    }
    fn headless(&self) -> bool {
        false
    }
    fn current_path(&self) -> std::path::PathBuf {
        self.file.current_path()
    }
    fn get(&self) -> Result<Option<Item>> {
        let os = (self.getter)()?;
        let file = self.file.get().ok().flatten();
        match (os, file) {
            (Some(mut os), Some(stored)) if os.hash == stored.hash => {
                if os.name.is_empty() {
                    os.name = stored.name;
                }
                if os.mime.starts_with("text/")
                    && !stored.mime.starts_with("text/")
                {
                    os.mime = stored.mime;
                }
                Ok(Some(os))
            }
            (None, Some(stored)) => Ok(Some(stored)),
            (Some(os), _) => {
                if os.data.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(os))
                }
            }
            (None, None) => Ok(None),
        }
    }
    fn set(&self, item: &Item) -> Result<Item> {
        let stored = self.file.set(item)?;
        (self.setter)(&stored)?;
        Ok(stored)
    }
}

pub fn open(dir: &Path) -> Result<Option<Arc<dyn Backend>>> {
    #[cfg(target_os = "macos")]
    {
        if look("pbcopy").is_some() && look("pbpaste").is_some() {
            return Ok(Some(Arc::new(Native {
                name: "pboard",
                file: FileBackend::open(dir)?,
                getter: darwin_get,
                setter: darwin_set,
            })));
        }
    }
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("WAYLAND_DISPLAY").is_some()
            && look("wl-copy").is_some()
            && look("wl-paste").is_some()
        {
            return Ok(Some(Arc::new(Native {
                name: "wayland",
                file: FileBackend::open(dir)?,
                getter: wayland_get,
                setter: wayland_set,
            })));
        }
        if std::env::var_os("DISPLAY").is_some() {
            if look("xclip").is_some() {
                return Ok(Some(Arc::new(Native {
                    name: "xclip",
                    file: FileBackend::open(dir)?,
                    getter: xclip_get,
                    setter: xclip_set,
                })));
            }
            if look("xsel").is_some() {
                return Ok(Some(Arc::new(Native {
                    name: "xsel",
                    file: FileBackend::open(dir)?,
                    getter: xsel_get,
                    setter: xsel_set,
                })));
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        return Ok(Some(Arc::new(Native {
            name: "win32",
            file: FileBackend::open(dir)?,
            getter: windows_get,
            setter: windows_set,
        })));
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = dir;
        Ok(None)
    }
}

#[cfg(not(target_os = "windows"))]
fn look(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let p = dir.join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn run_out(bin: &str, args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new(bin).args(args).output()?;
    if !out.status.success() {
        bail!("{bin} exited {}", out.status);
    }
    Ok(out.stdout)
}

#[cfg(not(target_os = "windows"))]
fn run_in(bin: &str, args: &[&str], data: &[u8]) -> Result<()> {
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {bin}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(data)?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!("{bin} failed: {err}");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn darwin_get() -> Result<Option<Item>> {
    let text = run_out("pbpaste", &[]).unwrap_or_default();
    if let Some(item) = super::item_from_file_text(&text) {
        return Ok(Some(item));
    }
    // Finder copies put the basename on the text flavor and the real path
    // on «class furl». pbpaste alone would sync the name as text/plain.
    if super::looks_like_copied_filename(&text) {
        if let Some(item) = darwin_file_from_furl() {
            return Ok(Some(item));
        }
    }
    // Screenshots / "Copy Image": bitmap on PNGf, often a basename or HTML
    // on the text flavor. Prefer the bitmap when there is no real file.
    if let Ok(Some(png)) = darwin_png() {
        if png.starts_with(b"\x89PNG") {
            return Ok(Some(Item::new("image/png", png)));
        }
    }
    if !text.is_empty() {
        return Ok(Some(Item::new("text/plain", text)));
    }
    Ok(None)
}

#[cfg(target_os = "macos")]
fn darwin_file_from_furl() -> Option<Item> {
    let script = r#"
try
    POSIX path of (the clipboard as «class furl»)
on error
    return ""
end try
"#;
    let out = Command::new("osascript")
        .args(["-e", script])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&out.stdout);
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    super::item_from_file_text(path.as_bytes())
}

#[cfg(target_os = "macos")]
fn darwin_set(item: &Item) -> Result<()> {
    if !item.name.is_empty() && item.path.is_file() {
        return darwin_set_file(&item.path);
    }
    if item.mime.starts_with("image/") {
        let ext = if item.mime == "image/jpeg" {
            "jpg"
        } else {
            "png"
        };
        let path = std::env::temp_dir().join(format!("zsync-clip.{ext}"));
        std::fs::write(&path, &item.data)?;
        let posix = applescript_posix(&path);
        let script = if item.mime == "image/png" || ext == "png" {
            format!(
                r#"set the clipboard to (read (POSIX file "{posix}") as «class PNGf»)"#
            )
        } else {
            format!(
                r#"set the clipboard to (read (POSIX file "{posix}") as JPEG picture)"#
            )
        };
        let status =
            Command::new("osascript").args(["-e", &script]).status()?;
        let _ = std::fs::remove_file(&path);
        if !status.success() {
            bail!("osascript failed to set image clipboard");
        }
        return Ok(());
    }
    run_in("pbcopy", &[], &item.data)
}

#[cfg(target_os = "macos")]
fn darwin_set_file(path: &Path) -> Result<()> {
    let posix = applescript_posix(path);
    let script =
        format!(r#"set the clipboard to (POSIX file "{posix}" as alias)"#);
    let status = Command::new("osascript").args(["-e", &script]).status()?;
    if !status.success() {
        bail!("osascript failed to set file clipboard");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn applescript_posix(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

#[cfg(target_os = "macos")]
fn darwin_png() -> Result<Option<Vec<u8>>> {
    let dir =
        std::env::temp_dir().join(format!("zsync-png-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("clip.png");
    let posix = path.display().to_string();
    let script = format!(
        r#"
try
    set png_data to (the clipboard as «class PNGf»)
    set out to open for access POSIX file "{posix}" with write permission
    set eof of out to 0
    write png_data to out as «class PNGf»
    close access out
on error
    try
        close access POSIX file "{posix}"
    end try
end try
"#
    );
    let _ = Command::new("osascript").args(["-e", &script]).status();
    let data = std::fs::read(&path).ok();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(data)
}

#[cfg(target_os = "linux")]
fn wayland_get() -> Result<Option<Item>> {
    if let Ok(types) = run_out("wl-paste", &["--list-types"]) {
        let list = String::from_utf8_lossy(&types);
        if list.contains("text/uri-list") {
            if let Ok(b) =
                run_out("wl-paste", &["--no-newline", "-t", "text/uri-list"])
            {
                if let Some(item) = super::item_from_file_text(&b) {
                    return Ok(Some(item));
                }
            }
        }
        if list.contains("image/png") {
            if let Ok(b) =
                run_out("wl-paste", &["--no-newline", "-t", "image/png"])
            {
                if !b.is_empty() {
                    return Ok(Some(Item::new("image/png", b)));
                }
            }
        }
        for mime in ["application/pdf", "application/zip"] {
            if list.contains(mime) {
                if let Ok(b) =
                    run_out("wl-paste", &["--no-newline", "-t", mime])
                {
                    if !b.is_empty() {
                        return Ok(Some(Item::new(mime, b)));
                    }
                }
            }
        }
    }
    match run_out("wl-paste", &["--no-newline"]) {
        Ok(b) if !b.is_empty() => {
            if let Some(item) = super::item_from_file_text(&b) {
                return Ok(Some(item));
            }
            Ok(Some(Item::new("text/plain", b)))
        }
        _ => Ok(None),
    }
}

#[cfg(target_os = "linux")]
fn wayland_set(item: &Item) -> Result<()> {
    if !item.name.is_empty() && item.path.is_file() {
        let uri = super::file_uri(&item.path);
        return run_in("wl-copy", &["-t", "text/uri-list"], uri.as_bytes());
    }
    if !item.mime.is_empty() && !item.mime.starts_with("text/plain") {
        return run_in("wl-copy", &["-t", &item.mime], &item.data);
    }
    run_in("wl-copy", &[], &item.data)
}

#[cfg(target_os = "linux")]
fn xclip_get() -> Result<Option<Item>> {
    if let Ok(targets) =
        run_out("xclip", &["-selection", "clipboard", "-o", "-t", "TARGETS"])
    {
        let t = String::from_utf8_lossy(&targets);
        if t.contains("text/uri-list") {
            if let Ok(b) = run_out(
                "xclip",
                &["-selection", "clipboard", "-o", "-t", "text/uri-list"],
            ) {
                if let Some(item) = super::item_from_file_text(&b) {
                    return Ok(Some(item));
                }
            }
        }
        if t.contains("image/png") {
            if let Ok(b) = run_out(
                "xclip",
                &["-selection", "clipboard", "-o", "-t", "image/png"],
            ) {
                if !b.is_empty() {
                    return Ok(Some(Item::new("image/png", b)));
                }
            }
        }
        for mime in ["application/pdf", "application/zip"] {
            if t.contains(mime) {
                if let Ok(b) = run_out(
                    "xclip",
                    &["-selection", "clipboard", "-o", "-t", mime],
                ) {
                    if !b.is_empty() {
                        return Ok(Some(Item::new(mime, b)));
                    }
                }
            }
        }
    }
    match run_out("xclip", &["-selection", "clipboard", "-o"]) {
        Ok(b) if !b.is_empty() => {
            if let Some(item) = super::item_from_file_text(&b) {
                return Ok(Some(item));
            }
            Ok(Some(Item::new("text/plain", b)))
        }
        _ => Ok(None),
    }
}

#[cfg(target_os = "linux")]
fn xclip_set(item: &Item) -> Result<()> {
    if !item.name.is_empty() && item.path.is_file() {
        let uri = super::file_uri(&item.path);
        return run_in(
            "xclip",
            &["-selection", "clipboard", "-t", "text/uri-list"],
            uri.as_bytes(),
        );
    }
    if !item.mime.is_empty() && !item.mime.starts_with("text/plain") {
        return run_in(
            "xclip",
            &["-selection", "clipboard", "-t", &item.mime],
            &item.data,
        );
    }
    run_in("xclip", &["-selection", "clipboard"], &item.data)
}

#[cfg(target_os = "linux")]
fn xsel_get() -> Result<Option<Item>> {
    match run_out("xsel", &["--clipboard", "--output"]) {
        Ok(b) if !b.is_empty() => {
            if let Some(item) = super::item_from_file_text(&b) {
                return Ok(Some(item));
            }
            Ok(Some(Item::new("text/plain", b)))
        }
        _ => Ok(None),
    }
}

#[cfg(target_os = "linux")]
fn xsel_set(item: &Item) -> Result<()> {
    run_in("xsel", &["--clipboard", "--input"], &item.data)
}

#[cfg(target_os = "windows")]
fn windows_get() -> Result<Option<Item>> {
    match clipboard_win::get_clipboard_string() {
        Ok(s) if !s.is_empty() => {
            let bytes = s.into_bytes();
            if let Some(item) = super::item_from_file_text(&bytes) {
                return Ok(Some(item));
            }
            Ok(Some(Item::new("text/plain", bytes)))
        }
        _ => Ok(None),
    }
}

#[cfg(target_os = "windows")]
fn windows_set(item: &Item) -> Result<()> {
    if item.mime.starts_with("image/") || !item.name.is_empty() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&item.data);
    clipboard_win::set_clipboard_string(&text)
        .map_err(|e| anyhow::anyhow!("set clipboard: {e}"))
}
