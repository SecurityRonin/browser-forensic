//! Correlated-timeline export: one file per run in the format an analyst wants
//! (XLSX workbook, SQLite database, JSONL / CSV stream, or plain text), with an
//! optional interpretation column and a timezone for human-facing timestamps.
//!
//! This mirrors Hindsight's model — point at a profile, get a single correlated
//! output — rather than the per-artifact streaming the other subcommands use.

use std::io::Write;
use std::path::Path;

use anyhow::Result;
use browser_forensic_core::BrowserEvent;
use chrono_tz::Tz;
use clap::ValueEnum;

/// Output encoding for `br4n6 export`.
#[derive(Clone, Copy, Debug, ValueEnum, Default, PartialEq, Eq)]
pub enum ExportFormat {
    /// One human-readable line per event.
    #[default]
    Text,
    /// Newline-delimited JSON, one object per event.
    Jsonl,
    /// Comma-separated values with a header row.
    Csv,
    /// A SQLite database with a single `timeline` table.
    Sqlite,
    /// An XLSX workbook with a single `Timeline` sheet.
    Xlsx,
}

/// True for formats that must be written to a file (binary containers).
#[must_use]
pub fn is_file_only(format: ExportFormat) -> bool {
    matches!(format, ExportFormat::Sqlite | ExportFormat::Xlsx)
}

/// The stable export column order.
pub const COLUMNS: &[&str] = &[
    "timestamp",
    "browser",
    "artifact",
    "url",
    "title",
    "description",
    "interpretation",
    "source",
];

/// Compute the interpretation string for one event, if any.
#[must_use]
pub fn compute_interpretation(_e: &BrowserEvent) -> Option<String> {
    None
}

/// Add an `interpretation` attr to every event that has one.
pub fn apply_interpretation(_events: &mut [BrowserEvent]) {}

/// Render a Unix-nanosecond timestamp as RFC 3339 in the given zone (UTC if
/// `None`).
#[must_use]
pub fn render_timestamp(_ns: i64, _tz: Option<Tz>) -> String {
    String::new()
}

/// Extract the value of one export column for an event.
#[must_use]
pub fn cell(_e: &BrowserEvent, _column: &str, _tz: Option<Tz>) -> String {
    String::new()
}

/// Write text/jsonl/csv events to a stream.
///
/// # Errors
/// Propagates write errors.
pub fn write_stream<W: Write>(
    _events: &[BrowserEvent],
    _format: ExportFormat,
    _tz: Option<Tz>,
    _out: &mut W,
) -> Result<()> {
    anyhow::bail!("unimplemented")
}

/// Write a SQLite database with a `timeline` table to `path`.
///
/// # Errors
/// Propagates database and IO errors.
pub fn write_sqlite(_events: &[BrowserEvent], _tz: Option<Tz>, _path: &Path) -> Result<()> {
    anyhow::bail!("unimplemented")
}

/// Write an XLSX workbook with a `Timeline` sheet to `path`.
///
/// # Errors
/// Propagates workbook and IO errors.
pub fn write_xlsx(_events: &[BrowserEvent], _tz: Option<Tz>, _path: &Path) -> Result<()> {
    anyhow::bail!("unimplemented")
}
