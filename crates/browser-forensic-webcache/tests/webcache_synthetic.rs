#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tier-2 end-to-end validation of the WebCache schema layer through the real
//! `ese_core` reader, using a synthetic ESE database.
//!
//! Ground truth is derivable from the documented ESE record construction (this
//! exercises `ese_core`'s genuine catalog + record decode path, not a mock), so
//! it proves the browser-forensic WebCache mapping — `Containers` →
//! `Container_#` → [`BrowserEvent`], container classification, and missing-table
//! degradation — is correct independently of any real-file quirks.
//!
//! Scope note: the fixture uses a single present `Container_#` data table.
//! `ese_core::catalog_entries` dedups catalog rows by `object_name`, so two
//! entry tables sharing WebCache's column names (`EntryId`, `Url`, …) would
//! collide in the synthetic simple-catalog format. Edge-vs-IE family detection
//! and the Cache/Cookies/Downloads/DOMStore classifications are covered by the
//! unit tests in `lib.rs`; this test proves the full ese-core traversal.
//!
//! Column *ids* here are synthetic-contiguous (1,2,3…) so `decode_record` reads
//! them cleanly; the mapping keys off column *names* (the real spec names).

use browser_forensic_core::{ArtifactKind, BrowserFamily};
use browser_forensic_webcache::parse_webcache;
use ese_core::{coltyp, CatalogEntry};
use ese_test_fixtures::{EseFileBuilder, PageBuilder, PAGE_SIZE};

/// 2023-01-01T00:00:00Z as a Windows FILETIME (100 ns ticks since 1601).
const FT_2023: i64 = (1_672_531_200 + 11_644_473_600) * 10_000_000;
const NS_2023: i64 = 1_672_531_200_000_000_000;

/// Build one ESE data record in the Vista+ layout `ese_core::decode_record`
/// expects: `[last_fixed_col, num_var_cols, var_data_offset(2)]`, packed fixed
/// data, then a cumulative 2-byte end-offset array, then variable payload.
fn record(last_fixed: u8, fixed: &[u8], vars: &[&[u8]]) -> Vec<u8> {
    let var_data_offset = u16::try_from(4 + fixed.len()).unwrap();
    let mut rec = vec![last_fixed, u8::try_from(vars.len()).unwrap()];
    rec.extend_from_slice(&var_data_offset.to_le_bytes());
    rec.extend_from_slice(fixed);
    let mut cum = 0u16;
    let mut payload = Vec::new();
    for v in vars {
        cum += u16::try_from(v.len()).unwrap();
        rec.extend_from_slice(&cum.to_le_bytes());
        payload.extend_from_slice(v);
    }
    rec.extend_from_slice(&payload);
    rec
}

fn tbl(object_id: u32, table_page: u32, name: &str) -> CatalogEntry {
    CatalogEntry {
        object_type: 1,
        object_id,
        parent_object_id: 1,
        table_page,
        object_name: name.to_owned(),
    }
}

fn col(parent: u32, column_id: u32, coltyp: u8, name: &str) -> CatalogEntry {
    CatalogEntry {
        object_type: 2,
        object_id: column_id,
        parent_object_id: parent,
        table_page: u32::from(coltyp),
        object_name: name.to_owned(),
    }
}

/// A `Containers` record: fixed ContainerId (i64), variable Name + Directory.
fn container_row(id: i64, name: &str, directory: &str) -> Vec<u8> {
    record(
        1,
        &id.to_le_bytes(),
        &[name.as_bytes(), directory.as_bytes()],
    )
}

/// A `Container_#` record: fixed EntryId(i64)+AccessedTime(i64)+AccessCount(u32),
/// variable Url + Filename.
fn entry_row(entry_id: i64, accessed: i64, count: u32, url: &str, filename: &str) -> Vec<u8> {
    let mut fixed = entry_id.to_le_bytes().to_vec();
    fixed.extend_from_slice(&accessed.to_le_bytes());
    fixed.extend_from_slice(&count.to_le_bytes());
    record(3, &fixed, &[url.as_bytes(), filename.as_bytes()])
}

/// Assemble a synthetic WebCacheV01.dat: a `Containers` table listing four
/// containers (IE History with a present `Container_1`, a skipped
/// BackgroundTransferApi, a History with no data table, and a Cookies with no
/// data table) plus the single present `Container_1` data table.
fn build_synthetic_webcache() -> tempfile::NamedTempFile {
    // Catalog (page 5): table + column entries. table_page = physical data page.
    let mut catalog = PageBuilder::new(PAGE_SIZE).leaf();
    catalog = catalog.add_record(&tbl(10, 6, "Containers").to_bytes());
    catalog = catalog.add_record(&col(10, 1, coltyp::LONG_LONG, "ContainerId").to_bytes());
    catalog = catalog.add_record(&col(10, 2, coltyp::TEXT, "Name").to_bytes());
    catalog = catalog.add_record(&col(10, 3, coltyp::TEXT, "Directory").to_bytes());
    catalog = catalog.add_record(&tbl(20, 7, "Container_1").to_bytes());
    catalog = catalog.add_record(&col(20, 1, coltyp::LONG_LONG, "EntryId").to_bytes());
    catalog = catalog.add_record(&col(20, 2, coltyp::LONG_LONG, "AccessedTime").to_bytes());
    catalog = catalog.add_record(&col(20, 3, coltyp::UNSIGNED_LONG, "AccessCount").to_bytes());
    catalog = catalog.add_record(&col(20, 4, coltyp::TEXT, "Url").to_bytes());
    catalog = catalog.add_record(&col(20, 5, coltyp::TEXT, "Filename").to_bytes());
    let catalog = catalog.build();

    // Containers data (page 6): 4 containers.
    let containers = PageBuilder::new(PAGE_SIZE)
        .leaf()
        .add_record(&container_row(
            1,
            "History",
            r"C:\Users\u\AppData\Local\Microsoft\Windows\INetCache\IE",
        ))
        .add_record(&container_row(
            2,
            "BackgroundTransferApi",
            r"C:\Users\u\AppData\Local\Microsoft\Windows\INetCache\BackgroundTransferApi",
        ))
        .add_record(&container_row(
            5,
            "History",
            r"C:\Users\u\AppData\Local\Microsoft\Windows\History.IE5",
        ))
        .add_record(&container_row(
            9,
            "Cookies",
            r"C:\Users\u\AppData\Local\Microsoft\Windows\INetCookies",
        ))
        .build();

    // Container_1 (History, IE): 2 entries.
    let container_1 = PageBuilder::new(PAGE_SIZE)
        .leaf()
        .add_record(&entry_row(
            1,
            FT_2023,
            4,
            "Visited: user@https://example.com/",
            "history.idx",
        ))
        .add_record(&entry_row(
            2,
            FT_2023,
            1,
            "Visited: user@https://rust-lang.org/",
            "history.idx",
        ))
        .build();

    let blank = vec![0u8; PAGE_SIZE];
    EseFileBuilder::new()
        .add_page(blank.clone()) // 1
        .add_page(blank.clone()) // 2
        .add_page(blank.clone()) // 3
        .add_page(blank) // 4
        .add_page(catalog) // 5 = catalog root
        .add_page(containers) // 6 = Containers data
        .add_page(container_1) // 7 = Container_1
        .write()
}

#[test]
fn parse_synthetic_webcache_end_to_end() {
    let tmp = build_synthetic_webcache();
    let events = parse_webcache(tmp.path()).expect("parse synthetic WebCache");

    // Container_1 has 2 History records. BackgroundTransferApi is skipped;
    // History@id5 and Cookies@id9 have no Container_# table → 0 events each.
    assert_eq!(
        events.len(),
        2,
        "expected 2 browsing events, got {events:?}"
    );

    for ev in &events {
        assert_eq!(ev.artifact, ArtifactKind::History);
        assert_eq!(ev.browser, BrowserFamily::InternetExplorer);
        assert_eq!(ev.timestamp_ns, NS_2023);
        assert_eq!(ev.attrs["container"], serde_json::json!("History"));
        assert!(ev.attrs.contains_key("url"));
        assert!(ev.attrs.contains_key("accessed_time_ns"));
    }
    assert!(events.iter().any(|e| e.description.contains("example.com")));
    assert!(events
        .iter()
        .any(|e| e.description.contains("rust-lang.org")));
    assert!(events
        .iter()
        .any(|e| e.attrs["access_count"] == serde_json::json!(4)));

    // Skipped / table-less containers produced nothing.
    assert!(events
        .iter()
        .all(|e| e.attrs["container"] != serde_json::json!("BackgroundTransferApi")));
    assert!(events
        .iter()
        .all(|e| e.attrs["container"] != serde_json::json!("Cookies")));
}
