#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Pure decision helpers for the `bw` CLI. The binary's `run_*` functions own the
//! actual parsing I/O and `println!`; the decisions that can be made without I/O
//! — merging carve stats, building the triage text summary, and inferring a
//! browser family from a file name — live here so they are directly unit-testable
//! (the Humble Object / functional-core split).

pub mod format;

use std::path::Path;

use browser_carve::CarveStats;
use browser_core::BrowserFamily;
use browser_rt::TriageReport;

/// Sum two carve passes (free-page + WAL) into one aggregate stat block.
#[must_use]
pub fn merge_carve_stats(a: &CarveStats, b: &CarveStats) -> CarveStats {
    CarveStats {
        bytes_scanned: a.bytes_scanned + b.bytes_scanned,
        pages_scanned: a.pages_scanned + b.pages_scanned,
        free_pages_found: a.free_pages_found + b.free_pages_found,
        records_recovered: a.records_recovered + b.records_recovered,
        records_partial: a.records_partial + b.records_partial,
    }
}

/// The header/summary lines of the text-format triage report (everything above the
/// per-event timeline). The caller prints these; the per-event lines stay in the
/// shell because they iterate the (already-`format`-rendered) events directly.
#[must_use]
pub fn triage_summary_lines(report: &TriageReport) -> Vec<String> {
    vec![
        "Browser Forensic Triage Report".to_string(),
        "==============================".to_string(),
        format!("Generated: {}", report.generated_at_ns),
        format!("Profiles found: {}", report.profiles.len()),
        format!("Events parsed: {}", report.events.len()),
        format!("Integrity indicators: {}", report.integrity.len()),
        format!("Carved records: {}", report.carved.len()),
    ]
}

/// Infer a browser family from a bare artifact file name when content sniffing
/// can't (e.g. Firefox JSON/sqlite artifacts and Safari's `history.db`). Returns
/// `None` for anything not uniquely tied to a family by name (e.g. `History`).
#[must_use]
pub fn infer_browser_from_filename(path: &Path) -> Option<BrowserFamily> {
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    if name == "history.db" {
        return Some(BrowserFamily::Safari);
    }
    if name == "places.sqlite"
        || name == "formhistory.sqlite"
        || name == "cookies.sqlite"
        || name == "extensions.json"
        || name == "logins.json"
        || name == "sessionstore.jsonlz4"
    {
        return Some(BrowserFamily::Firefox);
    }
    None
}
