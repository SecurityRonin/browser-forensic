//! SQLite free-page carving for deleted record recovery.

use std::path::Path;

use anyhow::{Context, Result};

use crate::{CarveResult, CarveStats, CarvedRecord, RecoveryMethod, RecoveryQuality};

const SQLITE_HEADER_SIZE: usize = 100;
const PAGE_SIZE_OFFSET: usize = 16;
const FREELIST_TRUNK_OFFSET: usize = 32;

pub fn carve_sqlite_free_pages(path: &Path) -> Result<CarveResult> {
    let data = std::fs::read(path)
        .with_context(|| format!("failed to read SQLite file: {}", path.display()))?;

    if data.len() < SQLITE_HEADER_SIZE {
        anyhow::bail!("file too small to be a valid SQLite database");
    }

    if &data[0..16] != b"SQLite format 3\0" {
        anyhow::bail!("not a SQLite database (bad magic)");
    }

    let page_size = {
        let raw = u16::from_be_bytes([data[PAGE_SIZE_OFFSET], data[PAGE_SIZE_OFFSET + 1]]) as usize;
        if raw == 1 { 65536 } else { raw }
    };

    let freelist_trunk = u32::from_be_bytes([
        data[FREELIST_TRUNK_OFFSET], data[FREELIST_TRUNK_OFFSET+1],
        data[FREELIST_TRUNK_OFFSET+2], data[FREELIST_TRUNK_OFFSET+3],
    ]) as usize;

    let total_pages = data.len() / page_size;

    let mut stats = CarveStats {
        bytes_scanned: data.len() as u64,
        pages_scanned: total_pages as u32,
        free_pages_found: 0,
        records_recovered: 0,
        records_partial: 0,
    };

    let mut records = Vec::new();
    let free_pages = collect_free_pages(&data, freelist_trunk, page_size);
    stats.free_pages_found = free_pages.len() as u32;

    for &page_num in &free_pages {
        let page_offset = (page_num - 1) * page_size;
        if page_offset + page_size > data.len() {
            continue;
        }
        let page_data = &data[page_offset..page_offset + page_size];
        let recovered = scan_page_for_urls(page_data, page_offset as u64);
        stats.records_recovered += recovered.len();
        records.extend(recovered);
    }

    Ok(CarveResult { records, integrity: Vec::new(), stats })
}

fn collect_free_pages(data: &[u8], first_trunk: usize, page_size: usize) -> Vec<usize> {
    let mut free_pages = Vec::new();
    let mut trunk_page = first_trunk;

    while trunk_page > 0 {
        let offset = (trunk_page - 1) * page_size;
        if offset + page_size > data.len() {
            break;
        }
        free_pages.push(trunk_page);
        let trunk = &data[offset..offset + page_size];
        let next_trunk = u32::from_be_bytes([trunk[0], trunk[1], trunk[2], trunk[3]]) as usize;
        let leaf_count = u32::from_be_bytes([trunk[4], trunk[5], trunk[6], trunk[7]]) as usize;

        for i in 0..leaf_count {
            let leaf_offset = 8 + i * 4;
            if leaf_offset + 4 > page_size { break; }
            let leaf_page = u32::from_be_bytes([
                trunk[leaf_offset], trunk[leaf_offset+1],
                trunk[leaf_offset+2], trunk[leaf_offset+3],
            ]) as usize;
            if leaf_page > 0 { free_pages.push(leaf_page); }
        }

        trunk_page = next_trunk;
    }
    free_pages
}

fn scan_page_for_urls(page_data: &[u8], page_offset: u64) -> Vec<CarvedRecord> {
    let mut records = Vec::new();
    let needle = b"http";

    let mut i = 0;
    while i + needle.len() <= page_data.len() {
        if &page_data[i..i + needle.len()] != needle {
            i += 1;
            continue;
        }
        // Found "http" at byte index i — scan forward for end of printable ASCII
        let end = page_data[i..]
            .iter()
            .position(|&b| !(0x20..=0x7e).contains(&b))
            .map(|pos| i + pos)
            .unwrap_or(page_data.len());

        if end > i + 10 {
            if let Ok(url) = std::str::from_utf8(&page_data[i..end]) {
                if url.starts_with("http://") || url.starts_with("https://") {
                    let mut fields = std::collections::HashMap::new();
                    fields.insert("url".to_string(), serde_json::json!(url));
                    records.push(CarvedRecord {
                        offset: page_offset + i as u64,
                        table: "unknown".to_string(),
                        fields,
                        method: RecoveryMethod::FreePage,
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
    use tempfile::NamedTempFile;
    use rusqlite::Connection;

    #[test]
    fn carve_empty_db_returns_empty() {
        let f = NamedTempFile::new().expect("tempfile");
        {
            let conn = Connection::open(f.path()).expect("open");
            conn.execute_batch("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT);")
                .expect("create");
        }
        let result = carve_sqlite_free_pages(f.path()).expect("carve");
        assert_eq!(result.stats.records_recovered, 0);
        assert!(result.records.is_empty());
    }

    #[test]
    fn carve_db_with_deleted_rows_finds_free_pages() {
        let f = NamedTempFile::new().expect("tempfile");
        {
            let conn = Connection::open(f.path()).expect("open");
            conn.execute_batch(
                "PRAGMA auto_vacuum = NONE;
                 CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT);"
            ).expect("create");

            for i in 0..200_i32 {
                conn.execute(
                    "INSERT INTO urls VALUES (?1, ?2, ?3)",
                    rusqlite::params![i, format!("https://example{i}.com/page/with/long/path/to/fill/space"), format!("Title {i}")],
                ).expect("insert");
            }
            conn.execute("DELETE FROM urls", []).expect("delete");
        }

        let result = carve_sqlite_free_pages(f.path()).expect("carve");
        assert!(result.stats.pages_scanned > 0, "should have scanned pages");
        assert!(result.stats.free_pages_found > 0, "should have found free pages after deletion");
    }

    #[test]
    fn carve_nonexistent_file_returns_error() {
        let result = carve_sqlite_free_pages(std::path::Path::new("/nonexistent/db"));
        assert!(result.is_err());
    }

    #[test]
    fn carve_stats_populated() {
        let f = NamedTempFile::new().expect("tempfile");
        {
            let conn = Connection::open(f.path()).expect("open");
            conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, data TEXT);")
                .expect("create");
        }
        let result = carve_sqlite_free_pages(f.path()).expect("carve");
        assert!(result.stats.bytes_scanned > 0, "should report bytes scanned");
        assert!(result.stats.pages_scanned > 0, "should report pages scanned");
    }
}
