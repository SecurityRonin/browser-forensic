//! DFIR-interop serializer tests: TSK bodyfile (mactime 3.x), plaso `l2t_csv`,
//! and the HTML report. Machine formats are checked for exact field order and
//! delimiter faithfulness; the HTML report for escaping and structure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use browser_forensic_cli::report::{to_bodyfile, to_html_report, to_l2t_csv, ReportMeta};
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

const L2T_HEADER: &str = "date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra";

// 2023-11-14T22:13:20Z
const TS_NS: i64 = 1_700_000_000_000_000_000;
const TS_SECS: i64 = 1_700_000_000;

fn history_event() -> BrowserEvent {
    BrowserEvent::new(
        TS_NS,
        BrowserFamily::Chromium,
        ArtifactKind::History,
        "/p/History",
        "visit",
    )
    .with_attr("url", json!("https://example.com/page"))
    .with_attr("title", json!("Example"))
}

fn download_event() -> BrowserEvent {
    BrowserEvent::new(
        TS_NS,
        BrowserFamily::Chromium,
        ArtifactKind::Downloads,
        "/p/History",
        "file.zip (10 bytes)",
    )
    .with_attr("url", json!("https://example.com/file.zip"))
}

#[test]
fn bodyfile_has_eleven_pipe_fields() {
    let out = to_bodyfile(&[history_event()]);
    let line = out.lines().next().unwrap();
    let fields: Vec<&str> = line.split('|').collect();
    // MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
    assert_eq!(
        fields.len(),
        11,
        "TSK bodyfile 3.x has 11 pipe-delimited fields, got: {line}"
    );
}

#[test]
fn bodyfile_history_visit_in_atime_slot() {
    let out = to_bodyfile(&[history_event()]);
    let f: Vec<&str> = out.lines().next().unwrap().split('|').collect();
    assert_eq!(f[0], "0", "MD5");
    assert_eq!(f[2], "0", "inode");
    assert_eq!(f[3], "0", "mode");
    assert_eq!(f[6], "0", "size");
    assert_eq!(f[7], TS_SECS.to_string(), "atime = visit time");
    assert_eq!(f[8], "0", "mtime");
    assert_eq!(f[9], "0", "ctime");
    assert_eq!(f[10], "0", "crtime");
}

#[test]
fn bodyfile_name_is_descriptive() {
    let out = to_bodyfile(&[history_event()]);
    let f: Vec<&str> = out.lines().next().unwrap().split('|').collect();
    assert!(f[1].contains("[chromium history]"), "name: {}", f[1]);
    assert!(f[1].contains("https://example.com/page"), "name: {}", f[1]);
    assert!(f[1].contains("Last Visited Time"), "name: {}", f[1]);
}

#[test]
fn bodyfile_download_in_crtime_slot() {
    let out = to_bodyfile(&[download_event()]);
    let f: Vec<&str> = out.lines().next().unwrap().split('|').collect();
    assert_eq!(f[7], "0", "atime empty for a download creation time");
    assert_eq!(f[10], TS_SECS.to_string(), "crtime = download time");
}

#[test]
fn bodyfile_empty_events_is_empty_string() {
    assert_eq!(to_bodyfile(&[]), "");
}

#[test]
fn bodyfile_name_sanitizes_pipe_to_preserve_field_count() {
    let e = BrowserEvent::new(
        TS_NS,
        BrowserFamily::Firefox,
        ArtifactKind::History,
        "/p",
        "x",
    )
    .with_attr("url", json!("https://e.com/a|b"));
    let out = to_bodyfile(&[e]);
    let f: Vec<&str> = out.lines().next().unwrap().split('|').collect();
    assert_eq!(
        f.len(),
        11,
        "a pipe inside a value must not add a bodyfile field"
    );
}

// ---- l2t_csv (plaso / log2timeline) ----

#[test]
fn l2t_header_is_exact() {
    let out = to_l2t_csv(&[history_event()], None);
    assert_eq!(out.lines().next().unwrap(), L2T_HEADER);
}

#[test]
fn l2t_empty_events_header_only() {
    let out = to_l2t_csv(&[], None);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines, vec![L2T_HEADER]);
}

#[test]
fn l2t_row_has_seventeen_fields() {
    let out = to_l2t_csv(&[history_event()], None);
    let row = out.lines().nth(1).unwrap();
    // The history event has no commas in any value, so a naive split is safe.
    let fields: Vec<&str> = row.split(',').collect();
    assert_eq!(fields.len(), 17, "l2t_csv has 17 columns, row: {row}");
}

#[test]
fn l2t_date_time_timezone_utc() {
    let out = to_l2t_csv(&[history_event()], None);
    let f: Vec<&str> = out.lines().nth(1).unwrap().split(',').collect();
    assert_eq!(f[0], "11/14/2023", "date MM/DD/YYYY");
    assert_eq!(f[1], "22:13:20", "time HH:MM:SS");
    assert_eq!(f[2], "UTC", "timezone");
}

#[test]
fn l2t_timezone_applied() {
    let ny: chrono_tz::Tz = "America/New_York".parse().unwrap();
    let out = to_l2t_csv(&[history_event()], Some(ny));
    let f: Vec<&str> = out.lines().nth(1).unwrap().split(',').collect();
    // 22:13:20 UTC is 17:13:20 EST on 2023-11-14.
    assert_eq!(f[0], "11/14/2023");
    assert_eq!(f[1], "17:13:20");
    assert_eq!(f[2], "America/New_York");
}

#[test]
fn l2t_source_sourcetype_and_type() {
    let out = to_l2t_csv(&[history_event()], None);
    let f: Vec<&str> = out.lines().nth(1).unwrap().split(',').collect();
    assert_eq!(f[3], ".A..", "MACB — history visit is an access");
    assert_eq!(f[4], "WEBHIST", "source");
    assert_eq!(f[5], "Chromium History", "sourcetype");
    assert_eq!(f[6], "Last Visited Time", "type = timestamp desc");
    assert_eq!(f[11], "2", "version");
    assert_eq!(f[12], "/p/History", "filename");
    assert_eq!(f[15], "browser-forensic", "format");
}

#[test]
fn l2t_download_macb_is_birth() {
    let out = to_l2t_csv(&[download_event()], None);
    let f: Vec<&str> = out.lines().nth(1).unwrap().split(',').collect();
    assert_eq!(f[3], "...B", "download start is a birth time");
    assert_eq!(f[6], "Download Started Time");
}

#[test]
fn l2t_extra_carries_kv_attrs() {
    let out = to_l2t_csv(&[history_event()], None);
    let row = out.lines().nth(1).unwrap();
    assert!(row.contains("url=https://example.com/page"), "row: {row}");
    assert!(row.contains("title=Example"), "row: {row}");
}

#[test]
fn l2t_escapes_comma_bearing_value() {
    let e = BrowserEvent::new(
        TS_NS,
        BrowserFamily::Chromium,
        ArtifactKind::History,
        "/p/History",
        "visit",
    )
    .with_attr("title", json!("Doe, John"));
    let out = to_l2t_csv(&[e], None);
    let row = out.lines().nth(1).unwrap();
    // RFC 4180: the comma-bearing extra field must be double-quoted.
    assert!(
        row.contains("\"title=Doe, John\""),
        "comma value must be quoted, row: {row}"
    );
}

#[test]
fn l2t_escapes_embedded_quote() {
    let e = BrowserEvent::new(
        TS_NS,
        BrowserFamily::Chromium,
        ArtifactKind::History,
        "/p/History",
        "visit",
    )
    .with_attr("title", json!("a \"b\" c"))
    .with_attr("note", json!("x,y"));
    let out = to_l2t_csv(&[e], None);
    let row = out.lines().nth(1).unwrap();
    // A doubled quote ("") is the RFC 4180 escape inside a quoted field.
    assert!(
        row.contains("\"\""),
        "embedded quote must be doubled, row: {row}"
    );
}

// ---- HTML report ----

fn meta() -> ReportMeta {
    ReportMeta {
        case: Some("Case 42".to_string()),
        examiner: Some("A. Hui".to_string()),
        tool: "br4n6".to_string(),
        version: "0.2.0".to_string(),
        timezone: "UTC".to_string(),
        generated_at_ns: TS_NS,
        flags: vec![],
    }
}

#[test]
fn html_is_self_contained_document() {
    let out = to_html_report(&[history_event()], &meta());
    assert!(
        out.starts_with("<!DOCTYPE html>"),
        "must be a full document"
    );
    assert!(
        out.contains("<style"),
        "styles must be inlined (self-contained)"
    );
    assert!(out.contains("</html>"));
}

#[test]
fn html_header_shows_case_and_tool_meta() {
    let out = to_html_report(&[history_event()], &meta());
    assert!(out.contains("Case 42"));
    assert!(out.contains("A. Hui"));
    assert!(out.contains("br4n6"));
    assert!(out.contains("0.2.0"));
    assert!(out.contains("UTC"));
}

#[test]
fn html_escapes_xss_in_url() {
    let e = BrowserEvent::new(
        TS_NS,
        BrowserFamily::Chromium,
        ArtifactKind::History,
        "/p/History",
        "visit",
    )
    .with_attr(
        "url",
        json!("https://evil.example/<script>alert(1)</script>"),
    );
    let out = to_html_report(&[e], &meta());
    assert!(
        !out.contains("<script>alert(1)</script>"),
        "raw script tag must not appear"
    );
    assert!(
        out.contains("&lt;script&gt;"),
        "must HTML-escape angle brackets"
    );
}

#[test]
fn html_escapes_quote_and_amp_in_title() {
    let e = BrowserEvent::new(
        TS_NS,
        BrowserFamily::Chromium,
        ArtifactKind::History,
        "/p/History",
        "visit",
    )
    .with_attr("url", json!("https://example.com/a"))
    .with_attr("title", json!("Tom & \"Jerry\""));
    let out = to_html_report(&[e], &meta());
    assert!(out.contains("&amp;"), "ampersand escaped");
    assert!(
        out.contains("&quot;") || out.contains("&#x27;"),
        "quote escaped"
    );
}

#[test]
fn html_shows_per_artifact_counts() {
    let events = vec![history_event(), history_event(), download_event()];
    let out = to_html_report(&events, &meta());
    assert!(out.contains("History"), "artifact name present");
    assert!(out.contains("Downloads"), "artifact name present");
    // Two history events must be counted as 2 somewhere in the counts section.
    assert!(
        out.contains(">2<") || out.contains("2</td>"),
        "count of 2 shown"
    );
}

#[test]
fn html_lists_top_domains() {
    let a = BrowserEvent::new(
        TS_NS,
        BrowserFamily::Chromium,
        ArtifactKind::History,
        "/p",
        "v",
    )
    .with_attr("url", json!("https://top.example/one"));
    let b = BrowserEvent::new(
        TS_NS,
        BrowserFamily::Chromium,
        ArtifactKind::History,
        "/p",
        "v",
    )
    .with_attr("url", json!("https://top.example/two"));
    let out = to_html_report(&[a, b], &meta());
    assert!(out.contains("top.example"), "domain host surfaced");
}

#[test]
fn html_renders_and_escapes_flags() {
    let mut m = meta();
    m.flags = vec!["History cleared: 5 rows missing <sqlite>".to_string()];
    let out = to_html_report(&[history_event()], &m);
    assert!(
        out.contains("History cleared: 5 rows missing"),
        "flag text shown"
    );
    assert!(out.contains("&lt;sqlite&gt;"), "flag value HTML-escaped");
    assert!(!out.contains("<sqlite>"), "raw flag markup must not leak");
}

#[test]
fn html_timeline_shows_full_value_not_elided() {
    let long = "https://example.com/very/long/path/that/should/not/be/truncated/at/all/ever";
    let e = BrowserEvent::new(
        TS_NS,
        BrowserFamily::Chromium,
        ArtifactKind::History,
        "/p",
        "v",
    )
    .with_attr("url", json!(long));
    let out = to_html_report(&[e], &meta());
    assert!(
        out.contains(long),
        "value must appear in full, never elided"
    );
    assert!(
        !out.contains('\u{2026}'),
        "no ellipsis truncation of a value"
    );
}

#[test]
fn html_states_observation_not_conclusion() {
    let out = to_html_report(&[history_event()], &meta());
    let lower = out.to_lowercase();
    assert!(lower.contains("observ"), "frames findings as observations");
    assert!(!lower.contains("proves"), "no conclusion language");
}

#[test]
fn html_empty_events_is_valid_document() {
    let out = to_html_report(&[], &meta());
    assert!(out.starts_with("<!DOCTYPE html>"));
    assert!(out.contains("</html>"));
}
