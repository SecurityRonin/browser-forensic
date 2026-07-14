#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Whole-image / physical-disk carving of browser artifacts.
//!
//! Recovers browser artifacts from the **raw unallocated space** of a full disk
//! or memory image — not just a single database's freelist/WAL. It streams the
//! image in bounded, overlapping windows over a [`forensic_vfs::ImageSource`],
//! locates artifact signatures, and hands page/entry-aligned slices to the
//! already-vetted per-format carvers rather than reimplementing any decode:
//!
//! * **SQLite records** — every `"SQLite format 3\0"` header found in unallocated
//!   space is a database (often a deleted whole DB) sitting in slack. The blob is
//!   opened with [`sqlite_core::Database`] and every page carved with its
//!   allocated-cell and free-region carvers, recovering rows that look like
//!   browser history (a URL plus a candidate visit time) or cookies.
//! * **Chromium SimpleCache entries** — each SimpleCache entry-header magic is
//!   parsed with `browser_forensic_cache`'s entry decoder, recovering the cached
//!   URL and response body.
//!
//! Honesty: a carved hit has **no filesystem context** — it is recovered from raw
//! bytes with no directory, inode, or allocation state to anchor it. Every
//! [`CarvedArtifact`] carries its absolute byte offset in the image and is framed
//! as *consistent with a deleted/evicted artifact*, never as a proven user action.
//!
//! This module owns **zero** record-decode logic; it is orchestration (windowing,
//! signature location, bounded reads, caps) over `sqlite-core` and
//! `browser-forensic-cache`.

use std::path::Path;

use forensic_vfs::adapters::FileSource;
use forensic_vfs::{ImageSource, VfsResult};

/// Which vetted carver recovered a [`CarvedArtifact`] from raw image bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarvedArtifactKind {
    /// A record carved from a SQLite database found in unallocated space (a URL
    /// plus, when present, a candidate visit time) — history- or cookie-shaped.
    SqliteRecord,
    /// A Chromium SimpleCache entry carved from its entry-header signature.
    CacheEntry,
}

impl CarvedArtifactKind {
    /// A stable machine token for output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CarvedArtifactKind::SqliteRecord => "sqlite_record",
            CarvedArtifactKind::CacheEntry => "cache_entry",
        }
    }
}

/// One artifact recovered from raw image bytes, with its absolute byte-offset
/// provenance. Carries no filesystem context: it is residue in unallocated space.
#[derive(Debug, Clone)]
pub struct CarvedArtifact {
    /// Which carver produced it.
    pub kind: CarvedArtifactKind,
    /// The recovered URL (the load-bearing datum for both record and cache hits).
    pub url: String,
    /// Absolute byte offset of the artifact within the image (its provenance).
    pub image_offset: u64,
    /// A candidate visit/last-used timestamp as the raw integer the record held,
    /// when one was present. Left uninterpreted — the epoch/units are not asserted.
    pub visit_time_raw: Option<i64>,
    /// A full-value detail string (recovered columns, or the cache mechanism note).
    /// Never ellipsized — a truncated value is destroyed evidence.
    pub detail: String,
}

/// Default streaming window (bytes) read from the image at once. Bounds memory
/// regardless of image size — a multi-GB image is never loaded whole.
pub const WINDOW: usize = 8 * 1024 * 1024;
/// Bytes carried from the end of one window into the next so a signature
/// straddling a window boundary is still located. Must exceed the longest
/// signature scanned for (the 16-byte SQLite magic).
pub const OVERLAP: usize = 64 * 1024;

/// Hard cap on the number of artifacts a single image carve may emit
/// (allocation-bomb guard against an image crafted to be all signatures).
const MAX_ARTIFACTS: usize = 5_000_000;

/// Carve every browser SQLite record and Chromium SimpleCache entry from the raw
/// unallocated space of an image, streaming it in bounded overlapping windows.
///
/// `source_path` labels the artifacts' provenance (the image path). Read-only,
/// bounded-memory, and panic-free on arbitrary bytes.
#[must_use]
pub fn carve_image(source: &dyn ImageSource, source_path: &Path) -> Vec<CarvedArtifact> {
    carve_image_with(source, source_path, WINDOW, OVERLAP)
}

/// Open `path` as a read-only positioned byte source and carve it (see
/// [`carve_image`]). Used when the evidence is a raw disk/memory image file
/// rather than an already-mounted container.
///
/// # Errors
/// [`VfsError`] if the path cannot be opened as a byte source.
pub fn carve_image_path(path: &Path) -> VfsResult<Vec<CarvedArtifact>> {
    let source = FileSource::open(path)?;
    Ok(carve_image(&source, path))
}

/// [`carve_image`] with explicit window/overlap sizing (the seam tests drive to
/// exercise window-boundary straddling with a small window).
#[must_use]
pub fn carve_image_with(
    _source: &dyn ImageSource,
    _source_path: &Path,
    _window: usize,
    _overlap: usize,
) -> Vec<CarvedArtifact> {
    // STUB (RED): no carving yet.
    let _ = MAX_ARTIFACTS;
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    /// A minimal in-memory [`ImageSource`] over a byte buffer (simulated image).
    struct MemSource(Vec<u8>);

    impl ImageSource for MemSource {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
            let start = usize::try_from(offset)
                .unwrap_or(usize::MAX)
                .min(self.0.len());
            let avail = &self.0[start..];
            let n = avail.len().min(buf.len());
            buf[..n].copy_from_slice(&avail[..n]);
            Ok(n)
        }
    }

    /// Build a Chromium-History-shaped SQLite DB carrying `url` in a `urls` row,
    /// returning the raw file bytes.
    fn build_history_db(url: &str, last_visit_time: i64) -> Vec<u8> {
        let f = NamedTempFile::new().unwrap();
        {
            let conn = Connection::open(f.path()).unwrap();
            conn.execute_batch(
                "PRAGMA auto_vacuum = NONE;
                 CREATE TABLE urls(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR,
                                   visit_count INTEGER, typed_count INTEGER,
                                   last_visit_time INTEGER, hidden INTEGER);",
            )
            .unwrap();
            // A few filler rows plus the known URL, so the row lands on a leaf page.
            for i in 0..8 {
                conn.execute(
                    "INSERT INTO urls VALUES (?1,?2,?3,?4,?5,?6,0)",
                    rusqlite::params![
                        i,
                        format!("https://filler{i}.example/path/to/page"),
                        format!("Filler {i}"),
                        i,
                        i,
                        last_visit_time + i as i64
                    ],
                )
                .unwrap();
            }
            conn.execute(
                "INSERT INTO urls VALUES (100,?1,?2,5,2,?3,0)",
                rusqlite::params![url, "Planted Secret", last_visit_time],
            )
            .unwrap();
        }
        std::fs::read(f.path()).unwrap()
    }

    /// Embed `payload` at `offset` inside a `total`-byte buffer of junk.
    fn plant(payload: &[u8], offset: usize, total: usize) -> Vec<u8> {
        let mut buf = vec![0u8; total];
        // fill with non-signature junk so nothing false-carves
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        buf[offset..offset + payload.len()].copy_from_slice(payload);
        buf
    }

    #[test]
    fn recovers_planted_sqlite_history_url_with_offset() {
        let url = "https://planted.example/deleted-secret";
        let db = build_history_db(url, 13_300_000_000_000_000);
        let db_off = 1_000_usize;
        let img = plant(&db, db_off, db_off + db.len() + 4096);
        let src = MemSource(img);

        let arts = carve_image(&src, Path::new("disk.dd"));
        let hit = arts
            .iter()
            .find(|a| a.url == url)
            .unwrap_or_else(|| panic!("planted URL not recovered: {arts:?}"));
        assert_eq!(hit.kind, CarvedArtifactKind::SqliteRecord);
        assert!(
            hit.image_offset >= db_off as u64 && hit.image_offset < (db_off + db.len()) as u64,
            "offset {} must fall within the planted DB [{}, {})",
            hit.image_offset,
            db_off,
            db_off + db.len()
        );
    }

    #[test]
    fn lying_sqlite_header_does_not_panic() {
        // valid magic, garbage everywhere else
        let mut db = b"SQLite format 3\0".to_vec();
        db.extend_from_slice(&[0xffu8; 512]);
        let img = plant(&db, 500, 8192);
        let src = MemSource(img);
        let _ = carve_image(&src, Path::new("junk.bin"));
    }

    #[test]
    fn empty_image_recovers_nothing() {
        let src = MemSource(Vec::new());
        assert!(carve_image(&src, Path::new("empty")).is_empty());
    }
}
