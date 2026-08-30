use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};

use crate::protocol::{
    detect_mime, ext_for_mime, hash, mime_from_filename, MAX_CLIP,
};

mod file;
mod native;

pub use file::FileBackend;

#[derive(Debug, Clone)]
pub struct Item {
    pub mime: String,
    pub data: Vec<u8>,
    pub hash: String,
    pub path: PathBuf,
    /// Basename of a copied file; empty for ordinary text / screenshots.
    pub name: String,
}

impl Item {
    pub fn new(mime: impl Into<String>, data: Vec<u8>) -> Self {
        let mime = {
            let m = mime.into();
            if m.is_empty() {
                detect_mime(&data)
            } else {
                m
            }
        };
        let hash = hash(&data);
        Self {
            mime,
            data,
            hash,
            path: PathBuf::new(),
            name: String::new(),
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = sanitize_basename(&name.into()).unwrap_or_default();
        self
    }
}

pub fn is_image_mime(mime: &str) -> bool {
    mime.starts_with("image/")
}

/// Finder / file-manager copies often put only a basename on the text
/// flavor. True when that text is worth resolving as a real file path.
pub(crate) fn looks_like_copied_filename(text: &[u8]) -> bool {
    let s = std::str::from_utf8(text).unwrap_or("").trim();
    if s.is_empty() || s.len() > 1024 || s.contains('\n') || s.starts_with('<')
    {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return false;
    }
    if s.starts_with('/') || s.starts_with("file:") || s.starts_with('~') {
        return true;
    }
    Path::new(s)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| {
            !e.is_empty() && e.chars().all(|c| c.is_ascii_alphanumeric())
        })
}

/// `text/uri-list` body for a local file (trailing newline per RFC 2483).
pub(crate) fn file_uri(path: &Path) -> String {
    let abs = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let raw = abs.to_string_lossy();
    let mut out = String::from("file://");
    for b in raw.as_bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'/'
            | b'.'
            | b'-'
            | b'_'
            | b'~' => out.push(*b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out.push('\n');
    out
}

pub fn sanitize_basename(name: &str) -> Option<String> {
    let base = Path::new(name).file_name()?.to_str()?;
    if base.is_empty() || base == "." || base == ".." {
        return None;
    }
    let cleaned: String = base
        .chars()
        .filter(|c| *c != '/' && *c != '\\' && *c != '\0')
        .take(255)
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

/// True when paste should write a file into cwd instead of printing bytes.
pub fn should_write_file(name: &str, mime: &str, data: &[u8]) -> bool {
    if !name.is_empty() {
        return true;
    }
    if is_image_mime(mime) {
        return true;
    }
    if mime.starts_with("text/") || mime.is_empty() {
        let sniffed = detect_mime(data);
        return is_image_mime(&sniffed)
            || (!sniffed.starts_with("text/") && !data.is_empty());
    }
    true
}

/// Write a clip into `dir` and return the absolute path.
pub fn write_clip_file(
    dir: &Path,
    name: &str,
    mime: &str,
    data: &[u8],
) -> Result<PathBuf> {
    let mime = if mime.is_empty() {
        detect_mime(data)
    } else {
        mime.to_string()
    };
    let filename = sanitize_basename(name)
        .unwrap_or_else(|| format!("zsync-clip{}", ext_for_mime(&mime)));
    let dest = dir.join(filename);
    fs::write(&dest, data)
        .with_context(|| format!("write {}", dest.display()))?;
    Ok(dest.canonicalize().unwrap_or(dest))
}

pub fn write_image_file(
    dir: &Path,
    mime: &str,
    data: &[u8],
) -> Result<PathBuf> {
    write_clip_file(dir, "", mime, data)
}

/// Read a copied file path / `file://` URI list. Directories and oversized
/// files are skipped.
pub fn item_from_file_text(text: &[u8]) -> Option<Item> {
    let s = std::str::from_utf8(text).ok()?;
    let path = first_existing_file(s)?;
    read_file_item(&path)
}

fn first_existing_file(text: &str) -> Option<PathBuf> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let path = path_from_uri_or_path(line)?;
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

fn path_from_uri_or_path(s: &str) -> Option<PathBuf> {
    if let Some(rest) = s.strip_prefix("file://") {
        let decoded = percent_decode(rest);
        let path = decoded
            .strip_prefix("localhost")
            .unwrap_or(decoded.as_str());
        return Some(PathBuf::from(path));
    }
    let p = PathBuf::from(s);
    if p.is_file() {
        Some(p)
    } else {
        None
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(hex) = std::str::from_utf8(&b[i + 1..i + 3]) {
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn read_file_item(path: &Path) -> Option<Item> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() as usize > MAX_CLIP {
        return None;
    }
    let data = fs::read(path).ok()?;
    if data.len() > MAX_CLIP {
        return None;
    }
    let name = sanitize_basename(path.file_name()?.to_str()?)?;
    let mime = mime_from_filename(&name)
        .map(str::to_string)
        .unwrap_or_else(|| detect_mime(&data));
    Some(Item::new(mime, data).with_name(name))
}

pub trait Backend: Send + Sync {
    fn name(&self) -> &str;
    fn headless(&self) -> bool;
    fn get(&self) -> Result<Option<Item>>;
    fn set(&self, item: &Item) -> Result<Item>;
    fn current_path(&self) -> PathBuf;
}

pub fn open(dir: &Path) -> Result<Arc<dyn Backend>> {
    if let Some(n) = native::open(dir)? {
        return Ok(n);
    }
    Ok(Arc::new(FileBackend::open(dir)?))
}

/// In-memory clipboard for tests.
pub struct Memory {
    inner: std::sync::Mutex<Option<Item>>,
}

impl Memory {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(None),
        }
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for Memory {
    fn name(&self) -> &str {
        "memory"
    }
    fn headless(&self) -> bool {
        false
    }
    fn get(&self) -> Result<Option<Item>> {
        Ok(self.inner.lock().unwrap().clone())
    }
    fn set(&self, item: &Item) -> Result<Item> {
        let mut stored = item.clone();
        if stored.hash.is_empty() {
            stored.hash = hash(&stored.data);
        }
        *self.inner.lock().unwrap() = Some(stored.clone());
        Ok(stored)
    }
    fn current_path(&self) -> PathBuf {
        PathBuf::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_image_file_png() {
        let dir = std::env::temp_dir()
            .join(format!("zsync-img-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&[0; 16]);
        let path = write_image_file(&dir, "image/png", &png).unwrap();
        assert!(path.ends_with("zsync-clip.png"));
        assert_eq!(fs::read(&path).unwrap(), png);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_clip_keeps_basename() {
        let dir = std::env::temp_dir()
            .join(format!("zsync-file-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let dest =
            write_clip_file(&dir, "notes.pdf", "application/pdf", b"%PDF-1.4")
                .unwrap();
        assert!(dest.ends_with("notes.pdf"));
        assert_eq!(fs::read(&dest).unwrap(), b"%PDF-1.4");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn item_from_existing_file() {
        let dir = std::env::temp_dir()
            .join(format!("zsync-src-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let src = dir.join("hello.zip");
        fs::write(&src, b"PK\x03\x04hello").unwrap();
        let item =
            item_from_file_text(src.to_string_lossy().as_bytes()).unwrap();
        assert_eq!(item.name, "hello.zip");
        assert_eq!(item.mime, "application/zip");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sanitize_rejects_paths() {
        assert_eq!(
            sanitize_basename("../etc/passwd").as_deref(),
            Some("passwd")
        );
        assert_eq!(sanitize_basename(".").as_deref(), None);
        assert_eq!(
            sanitize_basename("foo/bar.txt").as_deref(),
            Some("bar.txt")
        );
    }

    #[test]
    fn screenshot_basename_is_not_a_file_clip() {
        // macOS pbpaste often returns just the screenshot filename, with the
        // bitmap living on PNGf. That name must not be treated as a file path.
        assert!(
            item_from_file_text(b"Screenshot 2026-08-07 at 00.00.30.png")
                .is_none()
        );
        assert!(looks_like_copied_filename(
            b"Screenshot 2026-08-07 at 00.00.30.png"
        ));
        assert!(looks_like_copied_filename(b"notes.pdf"));
        assert!(!looks_like_copied_filename(b"hello world"));
        assert!(!looks_like_copied_filename(b"<img src=\"x\">"));
        assert!(!looks_like_copied_filename(b"https://example.com/a.png"));
    }

    #[test]
    fn file_uri_encodes_spaces() {
        let dir = std::env::temp_dir()
            .join(format!("zsync-uri-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let src = dir.join("my file.pdf");
        fs::write(&src, b"%PDF-1.4").unwrap();
        let uri = file_uri(&src);
        assert!(uri.starts_with("file://"));
        assert!(uri.contains("my%20file.pdf"));
        assert!(uri.ends_with('\n'));
        let item = item_from_file_text(uri.as_bytes()).unwrap();
        assert_eq!(item.name, "my file.pdf");
        assert_eq!(item.data, b"%PDF-1.4");
        let _ = fs::remove_dir_all(&dir);
    }
}
