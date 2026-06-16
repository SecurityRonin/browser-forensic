//! Read-only, WAL-safe opening of browser SQLite evidence databases.
//!
//! Browser evidence DBs (`History`, `Cookies`, `places.sqlite`, …) must never be
//! mutated. A naive read-**write** [`rusqlite::Connection::open`] can checkpoint an
//! attached `-wal` on close, rewriting the main file — the cardinal sin for a
//! forensic tool. [`open_evidence_db`] is the single, secure-by-default way the
//! workspace opens such a file.
//!
//! ## WAL correctness
//!
//! SQLite's `immutable=1` URI flag makes a read-only open *ignore the `-wal`*,
//! silently dropping the newest uncheckpointed rows. We therefore use
//! `immutable=1` **only when there is no `-wal`**. When a non-empty `{path}-wal`
//! sidecar exists, we copy the `{db, -wal, -shm}` working set into a disposable
//! temp directory and open the **copy** `READ_ONLY` — the WAL is honored, and any
//! checkpoint that SQLite chooses to perform lands on the throw-away copy, never
//! the evidence.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

/// Provenance for an opened evidence database.
///
/// Surfaced additively alongside the connection so callers can record *how* the
/// evidence was accessed without altering the existing `BrowserEvent.source`
/// schema. When a WAL working-copy is made, `snapshot_path`, `sha256` (of the
/// original main DB), and `copied_at` are populated; for a copy-free open they
/// are `None`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceProvenance {
    /// The original evidence path the caller requested.
    pub original_path: PathBuf,
    /// Path to the disposable working copy actually opened, when one was made.
    pub snapshot_path: Option<PathBuf>,
    /// SHA-256 (lowercase hex) of the original main DB file, when a copy was made.
    pub sha256: Option<String>,
    /// When the working copy was taken.
    pub copied_at: Option<SystemTime>,
}

/// A read-only evidence SQLite connection plus its access provenance.
///
/// Holds an optional temp directory alive for the lifetime of the connection so
/// the working copy is not reaped while in use; it is cleaned up on drop.
#[derive(Debug)]
pub struct EvidenceDb {
    /// The read-only connection. Writes through it fail.
    pub conn: Connection,
    /// How the evidence was accessed (snapshot vs. in-place).
    pub provenance: EvidenceProvenance,
    /// Keeps the working-copy directory alive; `None` for a copy-free open.
    _snapshot_dir: Option<TempDir>,
}

/// Open a browser SQLite evidence database **read-only and WAL-safe**.
///
/// This is the only sanctioned way to open an evidence DB in the workspace:
/// the connection cannot write, and the original file is never checkpointed or
/// otherwise mutated.
///
/// # Errors
///
/// Returns an error if the file cannot be read, the working copy cannot be
/// written, or SQLite cannot open the (copy of the) database.
pub fn open_evidence_db(path: &Path) -> rusqlite::Result<EvidenceDb> {
    let wal = wal_sidecar(path);
    let has_wal = fs::metadata(&wal).is_ok_and(|m| m.len() > 0);

    if has_wal {
        open_with_wal_snapshot(path).map_err(to_sqlite_err)
    } else {
        open_immutable_in_place(path)
    }
}

/// No `-wal`: opening the original with `immutable=1` is safe and copy-free.
fn open_immutable_in_place(path: &Path) -> rusqlite::Result<EvidenceDb> {
    let uri = immutable_uri(path);
    let conn = Connection::open_with_flags(
        &uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )?;
    Ok(EvidenceDb {
        conn,
        provenance: EvidenceProvenance {
            original_path: path.to_path_buf(),
            snapshot_path: None,
            sha256: None,
            copied_at: None,
        },
        _snapshot_dir: None,
    })
}

/// `-wal` present: copy `{db, -wal, -shm}` to a temp working set and open the
/// copy `READ_ONLY` so the WAL is honored and any checkpoint hits the copy.
fn open_with_wal_snapshot(path: &Path) -> io::Result<EvidenceDb> {
    let dir = TempDir::new()?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "evidence path has no file name",
        )
    })?;
    let copy_db = dir.path().join(file_name);

    let sha256 = copy_and_hash(path, &copy_db)?;

    // Copy sidecars if present; missing -shm is fine (SQLite recreates it).
    copy_if_exists(&wal_sidecar(path), &sidecar(&copy_db, "-wal"))?;
    copy_if_exists(&shm_sidecar(path), &sidecar(&copy_db, "-shm"))?;

    let conn = Connection::open_with_flags(&copy_db, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(io::Error::other)?;

    Ok(EvidenceDb {
        conn,
        provenance: EvidenceProvenance {
            original_path: path.to_path_buf(),
            snapshot_path: Some(copy_db),
            sha256: Some(sha256),
            copied_at: Some(SystemTime::now()),
        },
        _snapshot_dir: Some(dir),
    })
}

/// Copy `src` to `dst` while computing the SHA-256 of the streamed bytes.
fn copy_and_hash(src: &Path, dst: &Path) -> io::Result<String> {
    let bytes = fs::read(src)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    fs::write(dst, &bytes)?;
    Ok(hex_lower(&hasher.finalize()))
}

fn copy_if_exists(src: &Path, dst: &Path) -> io::Result<()> {
    if src.exists() {
        fs::copy(src, dst)?;
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String is infallible.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Build a `file:` URI for `immutable=1` read-only open, percent-escaping the path.
fn immutable_uri(path: &Path) -> String {
    format!(
        "file:{}?immutable=1",
        encode_uri_path(&path.to_string_lossy())
    )
}

/// Minimal percent-encoding for a filesystem path used in a SQLite `file:` URI.
/// Encodes the characters SQLite's URI parser treats specially plus space.
fn encode_uri_path(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    for ch in p.chars() {
        match ch {
            '?' | '#' | '%' => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{:02X}", ch as u32);
            }
            ' ' => out.push_str("%20"),
            _ => out.push(ch),
        }
    }
    out
}

fn sidecar(db_path: &Path, suffix: &str) -> PathBuf {
    let mut s = db_path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

fn wal_sidecar(db_path: &Path) -> PathBuf {
    sidecar(db_path, "-wal")
}

fn shm_sidecar(db_path: &Path) -> PathBuf {
    sidecar(db_path, "-shm")
}

fn to_sqlite_err(e: io::Error) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN),
        Some(e.to_string()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immutable_uri_escapes_special_chars() {
        let p = Path::new("/tmp/some dir/Hi story?x");
        let uri = immutable_uri(p);
        assert!(uri.starts_with("file:/tmp/some%20dir/Hi%20story%3Fx"));
        assert!(uri.ends_with("?immutable=1"));
    }

    #[test]
    fn hex_lower_is_64_chars_for_sha256() {
        let h = Sha256::digest(b"hello");
        assert_eq!(hex_lower(&h).len(), 64);
    }

    #[test]
    fn sidecar_appends_suffix() {
        let p = Path::new("/x/History");
        assert_eq!(wal_sidecar(p), Path::new("/x/History-wal"));
        assert_eq!(shm_sidecar(p), Path::new("/x/History-shm"));
    }
}
