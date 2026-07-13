//! Layered PATH auto-detection with confidence + human basis (RFC 0001 D8).
//!
//! Magic bytes alone say "SQLite," never *which* artifact. Detection is layered:
//! (a) magic bytes (SQLite header, ESE signature, mozLz4, EWF/E01), (b) for a
//! SQLite database a **schema probe** that distinguishes Chromium History
//! (`urls`/`visits`) from Cookies, Firefox `places` (`moz_places`), and Safari
//! `History.db` (`history_items`), (c) directory markers (`Default/History` → a
//! Chromium profile, `places.sqlite` → Firefox), and (d) raw-disk / memory
//! flagged **explicitly low-confidence** unless a known header/container is
//! present. Every result carries a [`Confidence`] and a human `basis` string —
//! the audit trail written into the chain-of-custody manifest for court
//! defensibility (D8/D11). A `--type` override ([`DetectionKind`]) always exists
//! because the detector *will* guess wrong on carved / stomped data (Gemini).

use std::path::Path;

use browser_forensic_core::Confidence;
use browser_forensic_manifest::DetectionRecord;
use clap::ValueEnum;

/// One layered detection result: the artifact kind (human string), how confident
/// the call is, and the human-readable basis behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// The detected artifact kind, e.g. `Chromium History (SQLite)`.
    pub kind: String,
    /// Confidence in the classification (shares the finding-model axis).
    pub confidence: Confidence,
    /// The layered basis (magic → schema → directory markers) behind the call.
    pub basis: String,
}

impl Detection {
    fn new(kind: impl Into<String>, confidence: Confidence, basis: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            confidence,
            basis: basis.into(),
        }
    }

    /// Render the `Detected:/Basis:` header the examiner sees, matching the RFC
    /// D8 layout. Confidence is lower-cased (`high`/`medium`/`low`).
    #[must_use]
    pub fn header(&self) -> String {
        format!(
            "Detected: {}  Confidence: {}\nBasis:    {}",
            self.kind,
            self.confidence.to_string().to_lowercase(),
            self.basis
        )
    }
}

/// Build the chain-of-custody [`DetectionRecord`] for one detected input.
#[must_use]
pub fn to_record(path: &Path, d: &Detection) -> DetectionRecord {
    DetectionRecord {
        path: path.display().to_string(),
        detected_kind: d.kind.clone(),
        confidence: d.confidence,
        basis: d.basis.clone(),
    }
}

/// A forced artifact kind for `--type`, overriding auto-detection on carved /
/// stomped data the detector will guess wrong (RFC 0001 D8, Gemini's objection).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DetectionKind {
    /// Chromium `History` (SQLite `urls`/`visits`).
    ChromiumHistory,
    /// Chromium `Cookies` (SQLite).
    ChromiumCookies,
    /// Firefox `places.sqlite` (`moz_places`).
    FirefoxPlaces,
    /// Safari `History.db` (`history_items`).
    SafariHistory,
    /// A Chromium profile directory.
    ChromiumProfile,
    /// A Firefox profile directory.
    FirefoxProfile,
    /// An IE / Edge-Legacy `WebCacheV01.dat` (ESE).
    Webcache,
    /// A memory image.
    MemoryImage,
    /// A raw disk image.
    RawDisk,
}

impl DetectionKind {
    /// The human string for this forced kind (matches the auto-detector's names).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::ChromiumHistory => "Chromium History (SQLite)",
            Self::ChromiumCookies => "Chromium Cookies (SQLite)",
            Self::FirefoxPlaces => "Firefox places (SQLite)",
            Self::SafariHistory => "Safari History (SQLite)",
            Self::ChromiumProfile => "Chromium profile",
            Self::FirefoxProfile => "Firefox profile",
            Self::Webcache => "IE/Edge-Legacy WebCacheV01 (ESE)",
            Self::MemoryImage => "memory image",
            Self::RawDisk => "raw disk image",
        }
    }
}

/// The detection for a `--type <KIND>` override: the forced kind, high
/// confidence (the examiner asserted it), and a basis that records the override
/// so the manifest shows detection was skipped by hand.
#[must_use]
pub fn forced(kind: DetectionKind) -> Detection {
    Detection::new(
        kind.label(),
        Confidence::High,
        format!(
            "forced by --type {} (auto-detection skipped by the examiner)",
            kind.to_possible_value()
                .map_or_else(|| kind.label().to_string(), |v| v.get_name().to_string())
        ),
    )
}

/// The SQLite format-3 header magic.
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
/// The ESE (Extensible Storage Engine) file signature, at byte offset 4.
const ESE_SIGNATURE: [u8; 4] = [0xEF, 0xCD, 0xAB, 0x89];
/// The Firefox mozLz4 (`jsonlz4`) magic.
const MOZLZ4_MAGIC: &[u8; 8] = b"mozLz40\0";

/// Auto-detect the artifact at `path` with layered confidence + basis (D8).
///
/// A directory is classified by its browser-profile markers; a file by its magic
/// bytes and — for a SQLite database — a schema probe. Anything with no known
/// signature is reported **low-confidence** with its leading bytes shown, never
/// silently guessed (raw disk / memory images land here unless a container
/// header is present).
#[must_use]
pub fn detect(path: &Path) -> Detection {
    if path.is_dir() {
        detect_dir(path)
    } else {
        detect_file(path)
    }
}

/// Classify a directory by its browser-profile markers (layer c).
fn detect_dir(dir: &Path) -> Detection {
    if dir.join("History").is_file() || dir.join("Default").join("History").is_file() {
        return Detection::new(
            "Chromium profile",
            Confidence::High,
            "directory marker: History (Chromium profile layout)",
        );
    }
    if dir.join("places.sqlite").is_file() {
        return Detection::new(
            "Firefox profile",
            Confidence::High,
            "directory marker: places.sqlite (Firefox profile layout)",
        );
    }
    if dir.join("History.db").is_file() {
        return Detection::new(
            "Safari profile",
            Confidence::High,
            "directory marker: History.db (Safari profile layout)",
        );
    }
    // A home / mounted-image tree that leads to profiles but is not one itself.
    let lowered = dir.to_string_lossy().to_lowercase();
    if lowered.contains("/users/") || lowered.contains("appdata") || lowered.contains("/home/") {
        return Detection::new(
            "browser evidence directory (home/image layout)",
            Confidence::Medium,
            "directory with a Users/AppData/home layout; per-profile detection follows",
        );
    }
    Detection::new(
        "directory (no browser-profile markers)",
        Confidence::Low,
        "directory with no History/places.sqlite/History.db marker",
    )
}

/// Classify a file by magic bytes, then — for SQLite — a schema probe (layers a/b).
fn detect_file(path: &Path) -> Detection {
    let head = read_head(path);
    if head.len() >= SQLITE_MAGIC.len() && &head[..SQLITE_MAGIC.len()] == SQLITE_MAGIC.as_slice() {
        return detect_sqlite(path);
    }
    if head.len() >= 8 && head[4..8] == ESE_SIGNATURE {
        let is_webcache = file_name_eq(path, "webcachev01.dat");
        return Detection::new(
            if is_webcache {
                "IE/Edge-Legacy WebCacheV01 (ESE)"
            } else {
                "ESE database"
            },
            if is_webcache {
                Confidence::High
            } else {
                Confidence::Medium
            },
            "ESE signature 0xEF 0xCD 0xAB 0x89 at offset 4",
        );
    }
    if head.len() >= MOZLZ4_MAGIC.len() && &head[..MOZLZ4_MAGIC.len()] == MOZLZ4_MAGIC.as_slice() {
        return Detection::new(
            "Firefox mozLz4 (jsonlz4)",
            Confidence::High,
            "mozLz40 magic (Firefox jsonlz4 container)",
        );
    }
    if head.len() >= 3 && (&head[..3] == b"EVF" || &head[..3] == b"LVF") {
        return Detection::new(
            "EnCase/EWF disk image (E01)",
            Confidence::High,
            "EWF/EVF container signature",
        );
    }
    // No known signature. Raw disk / memory images land here — explicitly
    // low-confidence, and the leading bytes are SHOWN (fail-loud: never hide the
    // unrecognized value), so a human can identify what the tool could not.
    let hint = if file_name_hints_memory(path) {
        " — filename suggests a memory image"
    } else {
        ""
    };
    Detection::new(
        "unknown (possible raw disk or memory image)",
        Confidence::Low,
        format!(
            "no known file signature{hint}; leading bytes: {}",
            hex_prefix(&head)
        ),
    )
}

/// Probe a SQLite database's schema to distinguish the concrete artifact
/// (layer b). Table names come from `sqlite_master`; on a probe failure the
/// database is reported as generic SQLite (medium), never mis-classified.
fn detect_sqlite(path: &Path) -> Detection {
    let tables = match sqlite_tables(path) {
        Ok(t) => t,
        Err(_) => {
            return Detection::new(
                "SQLite database (schema probe failed)",
                Confidence::Medium,
                "SQLite header present; could not open for a schema probe",
            );
        }
    };
    let has = |name: &str| tables.iter().any(|t| t == name);
    let parent = parent_note(path);

    if has("urls") && has("visits") {
        return Detection::new(
            "Chromium History (SQLite)",
            Confidence::High,
            format!("SQLite header + urls/visits schema{parent}"),
        );
    }
    if has("cookies") {
        return Detection::new(
            "Chromium Cookies (SQLite)",
            Confidence::High,
            format!("SQLite header + cookies schema{parent}"),
        );
    }
    if has("moz_places") {
        return Detection::new(
            "Firefox places (SQLite)",
            Confidence::High,
            format!("SQLite header + moz_places schema{parent}"),
        );
    }
    if has("moz_cookies") {
        return Detection::new(
            "Firefox cookies (SQLite)",
            Confidence::High,
            format!("SQLite header + moz_cookies schema{parent}"),
        );
    }
    if has("history_items") && has("history_visits") {
        return Detection::new(
            "Safari History (SQLite)",
            Confidence::High,
            format!("SQLite header + history_items/history_visits schema{parent}"),
        );
    }
    // Unrecognized schema: show the tables that WERE there (fail-loud), medium.
    let mut sorted = tables.clone();
    sorted.sort();
    Detection::new(
        "SQLite database (unrecognized schema)",
        Confidence::Medium,
        format!(
            "SQLite header; unrecognized schema (tables: {})",
            if sorted.is_empty() {
                "<none>".to_string()
            } else {
                sorted.join(", ")
            }
        ),
    )
}

/// A `+ parent path .../<parent>/<file>` note when the parent directory looks
/// like a browser-profile layout (e.g. `.../Default/History`).
fn parent_note(path: &Path) -> String {
    let (Some(parent), Some(file)) = (path.parent().and_then(Path::file_name), path.file_name())
    else {
        return String::new();
    };
    format!(
        " + parent path .../{}/{}",
        parent.to_string_lossy(),
        file.to_string_lossy()
    )
}

/// The table names in a SQLite database, opened read-only.
fn sqlite_tables(path: &Path) -> rusqlite::Result<Vec<String>> {
    use rusqlite::OpenFlags;
    let conn = rusqlite::Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let mut stmt = conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table'")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Read up to the first 64 bytes of a file (enough for every signature we probe).
/// A read failure returns an empty buffer — detection degrades to low-confidence
/// "unknown", never a panic.
fn read_head(path: &Path) -> Vec<u8> {
    use std::io::Read as _;
    let Ok(mut f) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let mut buf = [0_u8; 64];
    let n = f.read(&mut buf).unwrap_or(0);
    buf[..n].to_vec()
}

/// Case-insensitive file-name equality.
fn file_name_eq(path: &Path, target_lower: &str) -> bool {
    path.file_name()
        .is_some_and(|n| n.to_string_lossy().to_lowercase() == target_lower)
}

/// Whether the file name carries a common memory-image extension.
fn file_name_hints_memory(path: &Path) -> bool {
    let Some(name) = path.file_name().map(|n| n.to_string_lossy().to_lowercase()) else {
        return false;
    };
    [".mem", ".raw", ".dmp", ".lime", ".vmem", ".dump"]
        .iter()
        .any(|ext| name.ends_with(ext))
}

/// A short, space-separated hex rendering of the leading bytes (for the
/// low-confidence basis — the evidence a human needs to identify the format).
fn hex_prefix(head: &[u8]) -> String {
    if head.is_empty() {
        return "<empty file>".to_string();
    }
    head.iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::TempDir;

    fn chrome_history(dir: &Path) -> std::path::PathBuf {
        let profile = dir.join("Default");
        std::fs::create_dir_all(&profile).unwrap();
        let history = profile.join("History");
        let conn = Connection::open(&history).unwrap();
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER);",
        )
        .unwrap();
        drop(conn);
        history
    }

    #[test]
    fn chrome_history_is_high_confidence_with_schema_in_basis() {
        let dir = TempDir::new().unwrap();
        let history = chrome_history(dir.path());
        let d = detect(&history);
        assert_eq!(d.kind, "Chromium History (SQLite)");
        assert_eq!(d.confidence, Confidence::High);
        assert!(d.basis.contains("urls/visits"), "{}", d.basis);
        assert!(d.basis.contains("parent path"), "{}", d.basis);
    }

    #[test]
    fn firefox_places_detected_via_moz_places() {
        let dir = TempDir::new().unwrap();
        let places = dir.path().join("places.sqlite");
        let conn = Connection::open(&places).unwrap();
        conn.execute_batch("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT);")
            .unwrap();
        drop(conn);
        let d = detect(&places);
        assert_eq!(d.kind, "Firefox places (SQLite)");
        assert_eq!(d.confidence, Confidence::High);
        assert!(d.basis.contains("moz_places"), "{}", d.basis);
    }

    #[test]
    fn cookies_are_not_mistaken_for_history() {
        let dir = TempDir::new().unwrap();
        let cookies = dir.path().join("Cookies");
        let conn = Connection::open(&cookies).unwrap();
        conn.execute_batch(
            "CREATE TABLE cookies (host_key TEXT, name TEXT, encrypted_value BLOB);",
        )
        .unwrap();
        drop(conn);
        let d = detect(&cookies);
        assert_eq!(d.kind, "Chromium Cookies (SQLite)");
    }

    #[test]
    fn unrecognized_sqlite_shows_its_tables() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("mystery.db");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch("CREATE TABLE widgets (id INTEGER PRIMARY KEY);")
            .unwrap();
        drop(conn);
        let d = detect(&db);
        assert_eq!(d.confidence, Confidence::Medium);
        assert!(
            d.basis.contains("widgets"),
            "shows the table names: {}",
            d.basis
        );
    }

    #[test]
    fn raw_bytes_are_explicitly_low_confidence_and_show_leading_bytes() {
        let dir = TempDir::new().unwrap();
        let raw = dir.path().join("dump.mem");
        std::fs::write(&raw, [0x00, 0x11, 0x22, 0x33, 0x44]).unwrap();
        let d = detect(&raw);
        assert_eq!(d.confidence, Confidence::Low);
        assert!(
            d.kind.to_lowercase().contains("raw disk") || d.kind.to_lowercase().contains("memory")
        );
        assert!(
            d.basis.contains("00 11 22 33"),
            "leading bytes shown: {}",
            d.basis
        );
        assert!(
            d.basis.contains("memory image"),
            "memory filename hint: {}",
            d.basis
        );
    }

    #[test]
    fn chromium_profile_directory_detected_by_marker() {
        let dir = TempDir::new().unwrap();
        let profile = dir.path().join("Default");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::write(profile.join("History"), b"x").unwrap();
        let d = detect(&profile);
        assert_eq!(d.kind, "Chromium profile");
        assert_eq!(d.confidence, Confidence::High);
    }

    #[test]
    fn forced_type_overrides_and_notes_it() {
        let d = forced(DetectionKind::FirefoxPlaces);
        assert_eq!(d.kind, "Firefox places (SQLite)");
        assert!(d.basis.contains("--type"), "{}", d.basis);
        assert!(d.basis.contains("firefox-places"), "{}", d.basis);
    }
}
