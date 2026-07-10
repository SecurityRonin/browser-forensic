//! Export-format tests. SQLite output is verified by reading it back with
//! rusqlite; XLSX output by reading it back with calamine — real-oracle
//! round-trips rather than self-authored fixtures.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use browser_forensic_cli::export::{
    apply_interpretation, cell, compute_interpretation, render_timestamp, write_sqlite,
    write_stream, write_xlsx, ExportFormat,
};
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

// 2023-11-14T22:13:20Z
const TS_NS: i64 = 1_700_000_000_000_000_000;

fn search_event() -> BrowserEvent {
    BrowserEvent::new(
        TS_NS,
        BrowserFamily::Chromium,
        ArtifactKind::History,
        "/p/History",
        "Google search",
    )
    .with_attr(
        "url",
        json!("https://www.google.com/search?q=how+to+wipe+a+disk"),
    )
    .with_attr("title", json!("how to wipe a disk - Google Search"))
}

fn plain_event() -> BrowserEvent {
    BrowserEvent::new(
        TS_NS,
        BrowserFamily::Firefox,
        ArtifactKind::History,
        "/p/places.sqlite",
        "visit",
    )
    .with_attr("url", json!("https://example.com/page"))
}

#[test]
fn render_timestamp_utc_and_zoned() {
    assert_eq!(render_timestamp(TS_NS, None), "2023-11-14T22:13:20+00:00");
    let ny: chrono_tz::Tz = "America/New_York".parse().unwrap();
    // 22:13:20 UTC is 17:13:20 EST (-05:00) on 2023-11-14.
    assert_eq!(
        render_timestamp(TS_NS, Some(ny)),
        "2023-11-14T17:13:20-05:00"
    );
}

#[test]
fn interpretation_extracts_google_search() {
    let interp = compute_interpretation(&search_event()).unwrap();
    assert_eq!(interp, "Searched for \"how to wipe a disk\"");
}

#[test]
fn apply_interpretation_sets_attr() {
    let mut events = vec![search_event(), plain_event()];
    apply_interpretation(&mut events);
    assert_eq!(
        events[0]
            .attrs
            .get("interpretation")
            .and_then(|v| v.as_str()),
        Some("Searched for \"how to wipe a disk\"")
    );
    // A plain example.com URL has no query, so no interpretation.
    assert!(events[1].attrs.get("interpretation").is_none());
}

#[test]
fn cell_reads_columns_and_attrs() {
    let e = search_event();
    assert_eq!(cell(&e, "browser", None), "Chromium");
    assert_eq!(cell(&e, "artifact", None), "History");
    assert_eq!(
        cell(&e, "url", None),
        "https://www.google.com/search?q=how+to+wipe+a+disk"
    );
    assert_eq!(cell(&e, "timestamp", None), "2023-11-14T22:13:20+00:00");
}

#[test]
fn csv_stream_has_header_and_rows() {
    let events = vec![search_event()];
    let mut buf = Vec::new();
    write_stream(&events, ExportFormat::Csv, None, &mut buf).unwrap();
    let text = String::from_utf8(buf).unwrap();
    let mut lines = text.lines();
    assert_eq!(
        lines.next().unwrap(),
        "timestamp,browser,artifact,url,title,description,interpretation,source"
    );
    let row = lines.next().unwrap();
    assert!(row.contains("Chromium"));
    assert!(row.contains("google.com/search"));
}

#[test]
fn jsonl_stream_one_object_per_event() {
    let events = vec![search_event(), plain_event()];
    let mut buf = Vec::new();
    write_stream(&events, ExportFormat::Jsonl, None, &mut buf).unwrap();
    let text = String::from_utf8(buf).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2);
    let obj: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(obj["browser"], "Chromium");
    assert_eq!(obj["timestamp"], "2023-11-14T22:13:20+00:00");
}

#[test]
fn sqlite_export_roundtrips() {
    let mut events = vec![search_event(), plain_event()];
    apply_interpretation(&mut events);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out.sqlite");
    write_sqlite(&events, None, &path).unwrap();

    let conn = rusqlite::Connection::open(&path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM timeline", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 2);
    let interp: String = conn
        .query_row(
            "SELECT interpretation FROM timeline WHERE browser = 'Chromium'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(interp, "Searched for \"how to wipe a disk\"");
}

#[test]
fn xlsx_export_roundtrips() {
    use calamine::{Reader, Xlsx};
    let events = vec![search_event()];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out.xlsx");
    write_xlsx(&events, None, &path).unwrap();

    let mut wb: Xlsx<_> = calamine::open_workbook(&path).unwrap();
    let range = wb.worksheet_range("Timeline").unwrap();
    // Header row + one data row.
    assert_eq!(range.height(), 2);
    let header: Vec<String> = range
        .rows()
        .next()
        .unwrap()
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    assert_eq!(header[0], "timestamp");
    assert_eq!(header[1], "browser");
    let data: Vec<String> = range
        .rows()
        .nth(1)
        .unwrap()
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    assert_eq!(data[1], "Chromium");
}
