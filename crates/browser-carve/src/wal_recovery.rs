//! WAL (Write-Ahead Log) recovery.

use std::path::Path;

use anyhow::{Context, Result};

use crate::{CarveResult, CarveStats, CarvedRecord, RecoveryMethod, RecoveryQuality};
use forensicnomicon::sqlite::{SQLITE_WAL_FRAME_HEADER_SIZE, SQLITE_WAL_HEADER_SIZE};

pub fn recover_from_wal(db_path: &Path) -> Result<CarveResult> {
    let wal_path_str = format!("{}-wal", db_path.display());
    let wal_path = Path::new(&wal_path_str);

    if !wal_path.exists() {
        // Also check that the db itself exists — return error for nonexistent db
        if !db_path.exists() {
            anyhow::bail!("database file does not exist: {}", db_path.display());
        }
        return Ok(CarveResult {
            records: Vec::new(),
            integrity: Vec::new(),
            stats: CarveStats::default(),
        });
    }

    let wal_data = std::fs::read(wal_path)
        .with_context(|| format!("failed to read WAL file: {}", wal_path.display()))?;

    if wal_data.len() < SQLITE_WAL_HEADER_SIZE {
        return Ok(CarveResult {
            records: Vec::new(),
            integrity: Vec::new(),
            stats: CarveStats {
                bytes_scanned: wal_data.len() as u64,
                ..Default::default()
            },
        });
    }

    let page_size = {
        let raw =
            u32::from_be_bytes([wal_data[8], wal_data[9], wal_data[10], wal_data[11]]) as usize;
        if raw == 0 {
            4096
        } else {
            raw
        }
    };

    let mut stats = CarveStats {
        bytes_scanned: wal_data.len() as u64,
        ..Default::default()
    };
    let mut records = Vec::new();

    let mut offset = SQLITE_WAL_HEADER_SIZE;
    while offset + SQLITE_WAL_FRAME_HEADER_SIZE + page_size <= wal_data.len() {
        stats.pages_scanned += 1;
        let page_data = &wal_data[offset + SQLITE_WAL_FRAME_HEADER_SIZE
            ..offset + SQLITE_WAL_FRAME_HEADER_SIZE + page_size];

        let recovered = scan_wal_page_for_urls(page_data, offset as u64);
        stats.records_recovered += recovered.len();
        records.extend(recovered);

        offset += SQLITE_WAL_FRAME_HEADER_SIZE + page_size;
    }

    Ok(CarveResult {
        records,
        integrity: Vec::new(),
        stats,
    })
}

fn scan_wal_page_for_urls(page_data: &[u8], frame_offset: u64) -> Vec<CarvedRecord> {
    let mut records = Vec::new();
    let needle = b"http";

    let mut i = 0;
    while i + needle.len() <= page_data.len() {
        if &page_data[i..i + needle.len()] != needle {
            i += 1;
            continue;
        }
        let end = page_data[i..]
            .iter()
            .position(|&b| !(0x20..=0x7e).contains(&b))
            .map_or(page_data.len(), |pos| i + pos);

        if end > i + 10 {
            if let Ok(url) = std::str::from_utf8(&page_data[i..end]) {
                if url.starts_with("http://") || url.starts_with("https://") {
                    let mut fields = std::collections::HashMap::new();
                    fields.insert("url".to_string(), serde_json::json!(url));
                    records.push(CarvedRecord {
                        offset: frame_offset + i as u64,
                        table: "unknown".to_string(),
                        fields,
                        method: RecoveryMethod::WalUncommitted,
                        quality: RecoveryQuality::Partial,
                    });
                }
            }
        }
        i += 1;
    }
    records
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    #[test]
    fn recover_from_wal_no_wal_returns_empty() {
        let f = NamedTempFile::new().expect("tempfile");
        {
            let conn = Connection::open(f.path()).expect("open");
            conn.execute_batch(
                "PRAGMA journal_mode = DELETE;
                 CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);",
            )
            .expect("create");
        }
        let result = recover_from_wal(f.path()).expect("recover");
        assert!(result.records.is_empty());
        assert_eq!(result.stats.records_recovered, 0);
    }

    #[test]
    fn recover_from_wal_nonexistent_returns_error() {
        let result = recover_from_wal(std::path::Path::new("/nonexistent/db"));
        assert!(result.is_err());
    }

    #[test]
    fn recover_from_wal_with_wal_file_scans_pages() {
        let f = NamedTempFile::new().expect("tempfile");
        {
            let conn = Connection::open(f.path()).expect("open");
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);
                 INSERT INTO urls VALUES (1, 'https://wal-test.example.com');",
            )
            .expect("setup");
        }
        // `.expect` above is the real assertion: recovery must not error on a
        // populated WAL. `bytes_scanned` is unsigned, so a `>= 0` bound is vacuous.
        let result = recover_from_wal(f.path()).expect("recover");
        let _ = result.stats.bytes_scanned;
    }

    /// Build a synthetic `<db>-wal` file: a 32-byte WAL header (page size in
    /// bytes 8..12, big-endian) followed by one frame = 24-byte frame header +
    /// `page` bytes. Returns the kept tempfile handles so the db path is stable.
    fn write_synthetic_wal(page: &[u8]) -> (NamedTempFile, std::path::PathBuf) {
        use std::io::Write;
        let db = NamedTempFile::new().expect("db tempfile");
        // The db file itself must exist for the non-error path.
        std::fs::write(db.path(), b"placeholder").expect("write db");
        let mut header = vec![0u8; SQLITE_WAL_HEADER_SIZE];
        let ps = (page.len() as u32).to_be_bytes();
        header[8..12].copy_from_slice(&ps);
        let mut wal = header;
        wal.extend_from_slice(&[0u8; SQLITE_WAL_FRAME_HEADER_SIZE]);
        wal.extend_from_slice(page);
        let wal_path = std::path::PathBuf::from(format!("{}-wal", db.path().display()));
        let mut fh = std::fs::File::create(&wal_path).expect("create wal");
        fh.write_all(&wal).expect("write wal");
        (db, wal_path)
    }

    #[test]
    fn recover_from_wal_carves_url_from_frame() {
        let mut page = vec![0u8; 256];
        let url = b"https://carved-from-wal.example.com/page";
        page[40..40 + url.len()].copy_from_slice(url);
        let (db, wal_path) = write_synthetic_wal(&page);
        let result = recover_from_wal(db.path()).expect("recover");
        std::fs::remove_file(&wal_path).ok();
        assert_eq!(result.stats.pages_scanned, 1, "one frame walked");
        assert_eq!(result.records.len(), 1, "one URL carved");
        assert!(matches!(
            result.records[0].method,
            RecoveryMethod::WalUncommitted
        ));
        assert!(matches!(
            result.records[0].quality,
            RecoveryQuality::Partial
        ));
        let carved = &result.records[0].fields["url"];
        assert_eq!(
            carved,
            &serde_json::json!(std::str::from_utf8(url).unwrap())
        );
    }

    #[test]
    fn recover_from_wal_ignores_non_http_and_short_matches() {
        let mut page = vec![0u8; 256];
        // "http" prefix but not a URL scheme -> rejected by the starts_with check.
        page[10..18].copy_from_slice(b"httpfoo!");
        // a too-short "http" run (< 10 printable bytes) -> rejected by the length gate.
        page[60..66].copy_from_slice(b"http\x00\x00");
        let (db, wal_path) = write_synthetic_wal(&page);
        let result = recover_from_wal(db.path()).expect("recover");
        std::fs::remove_file(&wal_path).ok();
        assert_eq!(result.stats.pages_scanned, 1);
        assert!(result.records.is_empty(), "no real URL present");
    }

    #[test]
    fn recover_from_wal_zero_page_size_header_defaults() {
        // page-size header bytes left at 0 -> code defaults page_size to 4096.
        use std::io::Write;
        let db = NamedTempFile::new().expect("db tempfile");
        std::fs::write(db.path(), b"placeholder").expect("write db");
        // Header only (32 bytes), no full frame -> loop body never runs, but the
        // page_size==0 default branch is taken.
        let wal_path = std::path::PathBuf::from(format!("{}-wal", db.path().display()));
        let mut fh = std::fs::File::create(&wal_path).expect("create wal");
        fh.write_all(&[0u8; SQLITE_WAL_HEADER_SIZE]).expect("write");
        let result = recover_from_wal(db.path()).expect("recover");
        std::fs::remove_file(&wal_path).ok();
        assert_eq!(result.stats.pages_scanned, 0, "no full frame to scan");
        assert_eq!(result.stats.bytes_scanned, SQLITE_WAL_HEADER_SIZE as u64);
    }

    #[test]
    fn recover_from_wal_truncated_below_header_returns_empty() {
        use std::io::Write;
        let db = NamedTempFile::new().expect("db tempfile");
        std::fs::write(db.path(), b"placeholder").expect("write db");
        let wal_path = std::path::PathBuf::from(format!("{}-wal", db.path().display()));
        let mut fh = std::fs::File::create(&wal_path).expect("create wal");
        fh.write_all(&[0u8; 8]).expect("write"); // < 32-byte header
        let result = recover_from_wal(db.path()).expect("recover");
        std::fs::remove_file(&wal_path).ok();
        assert!(result.records.is_empty());
        assert_eq!(result.stats.bytes_scanned, 8);
        assert_eq!(result.stats.pages_scanned, 0);
    }
}
