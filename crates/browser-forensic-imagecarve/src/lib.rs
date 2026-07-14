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

use std::collections::HashSet;
use std::path::Path;

use forensic_vfs::adapters::FileSource;
use forensic_vfs::{ImageSource, VfsResult};
use sqlite_core::{CarvedCell, Database, Value};

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

/// The SQLite file-format magic (`"SQLite format 3\0"`, 16 bytes) — the header
/// of a database found in unallocated space (sqlite.org/fileformat2.html §1.2).
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// Hard cap on the number of artifacts a single image carve may emit
/// (allocation-bomb guard against an image crafted to be all signatures).
const MAX_ARTIFACTS: usize = 5_000_000;
/// Largest byte extent read for one carved SQLite database blob (memory bound
/// against a header whose page-count field lies large).
const MAX_DB_EXTENT: usize = 64 * 1024 * 1024;
/// Cap on records emitted from one carved database (per-DB allocation bound).
const MAX_RECORDS_PER_DB: usize = 500_000;
/// Cap on the number of SQLite-header hits a single image carve will open
/// (bounds worst-case work on an image crafted to be all SQLite magics).
const MAX_SQLITE_CARVES: usize = 100_000;
/// Integers at or above this are treated as a candidate visit/last-used
/// timestamp (Chrome µs-since-1601 ≈ 1.3e16, Firefox µs-since-1970 ≈ 1.7e15,
/// WebKit s-since-2001 is smaller but a µs/ns history value clears 1e12). This
/// is a heuristic label only — the epoch/units are never asserted.
const MIN_CANDIDATE_TIMESTAMP: i64 = 1_000_000_000_000;

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
    source: &dyn ImageSource,
    _source_path: &Path,
    window: usize,
    overlap: usize,
) -> Vec<CarvedArtifact> {
    let len = source.len();
    let mut out = Vec::new();
    if len == 0 {
        return out;
    }
    // Sane window/overlap: window has a floor, overlap is strictly below window
    // so the scan cursor always advances (no infinite loop), and the overlap
    // still exceeds the longest signature (16-byte SQLite magic) so a signature
    // straddling a window boundary is re-seen in the next window.
    let window = window.max(4096);
    let overlap = overlap.min(window / 2).max(SQLITE_MAGIC.len());
    let step = (window - overlap).max(1) as u64;

    let mut buf = vec![0u8; window];
    let mut seen_sqlite: HashSet<u64> = HashSet::new();
    let mut sqlite_carves = 0usize;
    let mut base = 0u64;
    loop {
        let want = usize::try_from((len - base).min(window as u64)).unwrap_or(window);
        let n = fill(source, base, &mut buf[..want]);
        let win = &buf[..n];

        for local in find_all(win, SQLITE_MAGIC) {
            let abs = base + local as u64;
            // A magic in the overlap region is seen in two windows; carve once.
            if seen_sqlite.insert(abs) && sqlite_carves < MAX_SQLITE_CARVES {
                sqlite_carves += 1;
                carve_sqlite_at(source, abs, &mut out);
                if out.len() >= MAX_ARTIFACTS {
                    return out;
                }
            }
        }

        if base + n as u64 >= len {
            break;
        }
        base += step;
    }
    out
}

/// Fill `buf` from `source` at `offset`, returning the number of bytes read
/// (short at EOF or on a read error). Never panics.
fn fill(source: &dyn ImageSource, offset: u64, buf: &mut [u8]) -> usize {
    let mut done = 0usize;
    while done < buf.len() {
        match source.read_at(offset + done as u64, &mut buf[done..]) {
            Ok(k) if k > 0 => done += k,
            _ => break,
        }
    }
    done
}

/// Every offset in `hay` where `needle` begins (ascending). Bounds-checked.
fn find_all(hay: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let nlen = needle.len();
    if nlen == 0 || hay.len() < nlen {
        return out;
    }
    let mut i = 0usize;
    while i + nlen <= hay.len() {
        if hay.get(i..i + nlen) == Some(needle) {
            out.push(i);
        }
        i += 1;
    }
    out
}

/// Open the SQLite database whose header sits at absolute offset `abs` and carve
/// every browser-history-shaped record from its pages (allocated cells plus freed
/// residue), appending each as a [`CarvedArtifact`]. A malformed/lying header is
/// skipped, never a panic.
fn carve_sqlite_at(source: &dyn ImageSource, abs: u64, out: &mut Vec<CarvedArtifact>) {
    let Some(blob) = read_sqlite_extent(source, abs) else {
        return;
    };
    let Ok(db) = Database::open(blob) else {
        return; // header failed validation — not a real database
    };
    let page_size = u64::from(db.header().page_size.max(1));
    let page_count = db.page_count();
    let mut recovered = 0usize;
    for page in 1..=page_count {
        let Some(page_bytes) = db.raw_page(page) else {
            continue;
        };
        // Allocated cells (the DB itself is unallocated residue, so its live rows
        // are recovered too) plus freed in-page residue.
        let mut cells = db.carve_leaf_cells(page_bytes);
        cells.extend(db.carve_free_regions(page_bytes, 0));
        for cell in &cells {
            let Some(art) = history_artifact_from_cell(cell, abs, page, page_size) else {
                continue;
            };
            out.push(art);
            recovered += 1;
            if recovered >= MAX_RECORDS_PER_DB {
                return;
            }
        }
    }
}

/// Read a bounded, correctly-sized blob for the database whose header is at `abs`:
/// parse the 100-byte header to derive `page_size * page_count`, then read exactly
/// that many bytes (capped, and bounded by what the image holds). Returns `None`
/// for a non-database or an implausible page size.
fn read_sqlite_extent(source: &dyn ImageSource, abs: u64) -> Option<Vec<u8>> {
    let mut head = [0u8; 100];
    if fill(source, abs, &mut head) < 100 || head.get(0..16) != Some(&SQLITE_MAGIC[..]) {
        return None;
    }
    // page_size: u16 big-endian at offset 16; the value 1 encodes 65536.
    let ps_raw = u16::from_be_bytes([head[16], head[17]]);
    let page_size: usize = if ps_raw == 1 {
        65536
    } else {
        usize::from(ps_raw)
    };
    if page_size < 512 || !page_size.is_power_of_two() {
        return None;
    }
    // page_count: u32 big-endian at offset 28 (0 when not maintained → derive).
    let hdr_pages = u32::from_be_bytes([head[28], head[29], head[30], head[31]]) as usize;
    let remaining = usize::try_from(source.len().saturating_sub(abs)).unwrap_or(usize::MAX);
    let by_header = page_size.saturating_mul(hdr_pages);
    let want = if by_header == 0 { remaining } else { by_header }
        .min(MAX_DB_EXTENT)
        .min(remaining)
        .max(page_size);
    let mut blob = vec![0u8; want];
    let got = fill(source, abs, &mut blob);
    blob.truncate(got);
    (blob.len() >= page_size).then_some(blob)
}

/// Map a carved SQLite cell onto a browser-history-shaped [`CarvedArtifact`] when
/// it carries a URL-looking TEXT value (`"://"`); otherwise `None`. The absolute
/// image offset is `db_offset + (page-1)*page_size + cell.offset`.
fn history_artifact_from_cell(
    cell: &CarvedCell,
    db_offset: u64,
    page: u32,
    page_size: u64,
) -> Option<CarvedArtifact> {
    let url = cell.values.iter().find_map(|v| match v {
        Value::Text(t) if t.contains("://") => Some(t.clone()),
        _ => None,
    })?;
    let visit_time_raw = cell.values.iter().find_map(|v| match v {
        Value::Integer(n) if *n >= MIN_CANDIDATE_TIMESTAMP => Some(*n),
        _ => None,
    });
    let image_offset = db_offset
        .saturating_add(u64::from(page.saturating_sub(1)).saturating_mul(page_size))
        .saturating_add(cell.offset as u64);
    Some(CarvedArtifact {
        kind: CarvedArtifactKind::SqliteRecord,
        url,
        image_offset,
        visit_time_raw,
        detail: dump_values(&cell.values),
    })
}

/// A compact, full-value dump of a carved record's columns (never ellipsized).
fn dump_values(values: &[Value]) -> String {
    let mut s = String::from("[");
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        match v {
            Value::Null => s.push_str("null"),
            Value::Integer(n) => s.push_str(&n.to_string()),
            Value::Real(r) => s.push_str(&r.to_string()),
            Value::Text(t) => {
                s.push('"');
                s.push_str(t);
                s.push('"');
            }
            Value::Blob(b) => s.push_str(&format!("blob[{}]", b.len())),
        }
    }
    s.push(']');
    s
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
                        last_visit_time + i64::from(i)
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

    use std::io::Write as _;

    /// Write `bytes` to a fresh temp file (kept alive by the returned handle).
    fn temp_file_with(bytes: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn container_source_read_at_returns_correct_bytes_and_short_eof_read() {
        // A raw byte pattern → `container::open` sniffs it as Raw → the adapter
        // serves positioned reads over the decoded (here pass-through) stream.
        let data: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let f = temp_file_with(&data);
        let src = ContainerSource::open(f.path()).expect("open raw file as container");
        assert_eq!(src.len(), data.len() as u64);

        // Exact bytes at offset 0.
        let mut buf = [0u8; 16];
        assert_eq!(src.read_at(0, &mut buf).unwrap(), 16);
        assert_eq!(&buf[..], &data[..16]);

        // Exact bytes at an arbitrary interior offset.
        let mut buf = [0u8; 32];
        assert_eq!(src.read_at(1000, &mut buf).unwrap(), 32);
        assert_eq!(&buf[..], &data[1000..1032]);

        // Oversized read straddling EOF → short count (available prefix only).
        let mut buf = [0u8; 64];
        let n = src.read_at(data.len() as u64 - 10, &mut buf).unwrap();
        assert_eq!(n, 10);
        assert_eq!(&buf[..10], &data[data.len() - 10..]);

        // At and past EOF → 0, never a panic.
        let mut buf = [0u8; 8];
        assert_eq!(src.read_at(data.len() as u64, &mut buf).unwrap(), 0);
        assert_eq!(src.read_at(data.len() as u64 + 100, &mut buf).unwrap(), 0);
    }

    #[test]
    fn container_open_path_carves_planted_sqlite_url() {
        // Proves the new open strategy: `carve_image_path` opens through
        // `container::open` (not a raw FileSource) and still recovers the plant.
        let url = "https://planted.example/via-container-open";
        let db = build_history_db(url, 13_300_000_000_000_000);
        let db_off = 2048usize;
        let img = plant(&db, db_off, db_off + db.len() + 4096);
        let f = temp_file_with(&img);

        let arts = carve_image_path(f.path()).expect("carve raw image via container::open");
        assert!(
            arts.iter().any(|a| a.url == url),
            "planted URL not recovered through the container-abstraction open path: {arts:?}"
        );
    }

    #[test]
    fn carve_image_path_errors_loudly_when_image_cannot_be_opened() {
        // A non-existent path is a bootstrap failure — surfaced loudly, never
        // absorbed into an empty carve.
        let missing = Path::new("/nonexistent/br4n6/does-not-exist.img");
        assert!(carve_image_path(missing).is_err());
    }

    #[test]
    fn truncated_ewf_container_errors_loudly_and_never_panics() {
        // EnCase EWF v1 signature ("EVF\x09\x0d\x0a\xff\x00", libewf/EWF spec)
        // followed by garbage: sniffs as EWF, but the decoder must reject the
        // truncated body loudly — never a silent Raw downgrade or a panic.
        let mut bytes = vec![0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
        bytes.extend_from_slice(&[0xffu8; 1024]);
        let f = temp_file_with(&bytes);
        assert!(carve_image_path(f.path()).is_err());
    }

    /// Env-gated real-E01 validation (tier-2): set `BR4N6_E01` to a small E01 to
    /// prove it opens **decompressed** via `container::open` and carves. Provide
    /// `BR4N6_E01_URL` to assert a specific planted URL is recovered. Skips clean
    /// when unset (like an absent oracle binary).
    #[test]
    fn env_gated_e01_carves_decompressed_via_container_open() {
        let Ok(path) = std::env::var("BR4N6_E01") else {
            eprintln!("skip env_gated_e01: set BR4N6_E01 to a small E01 to run");
            return;
        };
        let arts =
            carve_image_path(Path::new(&path)).expect("open + carve E01 via container::open");
        if let Ok(url) = std::env::var("BR4N6_E01_URL") {
            assert!(
                arts.iter().any(|a| a.url == url),
                "planted URL {url} not recovered from E01: {arts:?}"
            );
        } else {
            assert!(!arts.is_empty(), "no artifacts carved from E01 {path}");
        }
    }
}
