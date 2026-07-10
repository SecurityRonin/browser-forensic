//! Correlated-timeline export: one file per run in the format an analyst wants
//! (XLSX workbook, SQLite database, JSONL / CSV stream, or plain text), with an
//! optional interpretation column and a timezone for human-facing timestamps.
//!
//! This mirrors Hindsight's model — point at a profile, get a single correlated
//! output — rather than the per-artifact streaming the other subcommands use.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use browser_forensic_core::BrowserEvent;
use browser_forensic_interpret::{interpret_cookie, interpret_url};
use chrono::DateTime;
use chrono_tz::Tz;
use clap::ValueEnum;
use serde_json::{json, Value};

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
///
/// URL-bearing events (history, downloads) run through the URL interpreters
/// (Google searches, query strings); events carrying a plaintext cookie
/// `(name, value)` run through the cookie interpreters (GA / Quantcast / BIG-IP).
#[must_use]
pub fn compute_interpretation(e: &BrowserEvent) -> Option<String> {
    if let Some(url) = e.attrs.get("url").and_then(Value::as_str) {
        if !url.is_empty() {
            if let Some(s) = interpret_url(url) {
                return Some(s);
            }
        }
    }
    let name = e.attrs.get("name").and_then(Value::as_str);
    let value = e.attrs.get("value").and_then(Value::as_str);
    if let (Some(name), Some(value)) = (name, value) {
        if let Some(s) = interpret_cookie(name, value) {
            return Some(s);
        }
    }
    None
}

/// Add an `interpretation` attr to every event that has one.
pub fn apply_interpretation(events: &mut [BrowserEvent]) {
    for e in events.iter_mut() {
        if let Some(s) = compute_interpretation(e) {
            e.attrs.insert("interpretation".to_string(), json!(s));
        }
    }
}

/// Render a Unix-nanosecond timestamp as RFC 3339 in the given zone (UTC if
/// `None`).
#[must_use]
pub fn render_timestamp(ns: i64, tz: Option<Tz>) -> String {
    let secs = ns.div_euclid(1_000_000_000);
    let nanos = u32::try_from(ns.rem_euclid(1_000_000_000)).unwrap_or(0);
    let Some(utc) = DateTime::from_timestamp(secs, nanos) else {
        return "invalid".to_string();
    };
    match tz {
        Some(tz) => utc.with_timezone(&tz).to_rfc3339(),
        None => utc.to_rfc3339(),
    }
}

fn attr_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Extract the value of one export column for an event.
#[must_use]
pub fn cell(e: &BrowserEvent, column: &str, tz: Option<Tz>) -> String {
    match column {
        "timestamp" => render_timestamp(e.timestamp_ns, tz),
        "browser" => e.browser.to_string(),
        "artifact" => e.artifact.to_string(),
        "description" => e.description.clone(),
        "source" => e.source.clone(),
        other => e.attrs.get(other).map(attr_string).unwrap_or_default(),
    }
}

fn row(e: &BrowserEvent, tz: Option<Tz>) -> Vec<String> {
    COLUMNS.iter().map(|c| cell(e, c, tz)).collect()
}

fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Write text/jsonl/csv events to a stream.
///
/// # Errors
/// Propagates write errors. Binary formats (`Sqlite`/`Xlsx`) are rejected here —
/// use [`write_sqlite`] / [`write_xlsx`].
pub fn write_stream<W: Write>(
    events: &[BrowserEvent],
    format: ExportFormat,
    tz: Option<Tz>,
    out: &mut W,
) -> Result<()> {
    match format {
        ExportFormat::Csv => {
            writeln!(out, "{}", COLUMNS.join(","))?;
            for e in events {
                let cells: Vec<String> = row(e, tz).iter().map(|c| csv_escape(c)).collect();
                writeln!(out, "{}", cells.join(","))?;
            }
        }
        ExportFormat::Jsonl => {
            for e in events {
                let mut obj = serde_json::Map::new();
                for (col, val) in COLUMNS.iter().zip(row(e, tz)) {
                    obj.insert((*col).to_string(), json!(val));
                }
                writeln!(out, "{}", Value::Object(obj))?;
            }
        }
        ExportFormat::Text => {
            for e in events {
                let interp = cell(e, "interpretation", tz);
                let suffix = if interp.is_empty() {
                    String::new()
                } else {
                    format!("  {{{interp}}}")
                };
                writeln!(
                    out,
                    "[{}] {}/{}: {}  <{}>{}",
                    cell(e, "timestamp", tz),
                    e.browser,
                    e.artifact,
                    e.description,
                    cell(e, "url", tz),
                    suffix,
                )?;
            }
        }
        ExportFormat::Sqlite | ExportFormat::Xlsx => {
            anyhow::bail!("{format:?} is a file format; use write_sqlite / write_xlsx");
        }
    }
    Ok(())
}

/// Write a SQLite database with a `timeline` table to `path`.
///
/// # Errors
/// Propagates database and IO errors.
pub fn write_sqlite(events: &[BrowserEvent], tz: Option<Tz>, path: &Path) -> Result<()> {
    // A fresh database each run; refuse to clobber an existing file silently.
    if path.exists() {
        std::fs::remove_file(path)
            .with_context(|| format!("removing existing {}", path.display()))?;
    }
    let conn =
        rusqlite::Connection::open(path).with_context(|| format!("creating {}", path.display()))?;
    let cols = COLUMNS
        .iter()
        .map(|c| format!("{c} TEXT"))
        .collect::<Vec<_>>()
        .join(", ");
    conn.execute(&format!("CREATE TABLE timeline ({cols})"), [])?;
    let placeholders = COLUMNS
        .iter()
        .enumerate()
        .map(|(i, _)| format!("?{}", i + 1))
        .collect::<Vec<_>>()
        .join(", ");
    let insert = format!(
        "INSERT INTO timeline ({}) VALUES ({placeholders})",
        COLUMNS.join(", ")
    );
    let tx = conn.unchecked_transaction()?;
    {
        let mut stmt = tx.prepare(&insert)?;
        for e in events {
            let cells = row(e, tz);
            let params: Vec<&dyn rusqlite::types::ToSql> = cells
                .iter()
                .map(|c| c as &dyn rusqlite::types::ToSql)
                .collect();
            stmt.execute(params.as_slice())?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Write an XLSX workbook with a `Timeline` sheet to `path`.
///
/// # Errors
/// Propagates workbook and IO errors.
pub fn write_xlsx(events: &[BrowserEvent], tz: Option<Tz>, path: &Path) -> Result<()> {
    use rust_xlsxwriter::{Format, Workbook};
    let mut wb = Workbook::new();
    let sheet = wb.add_worksheet();
    sheet
        .set_name("Timeline")
        .context("naming Timeline sheet")?;
    let header_fmt = Format::new().set_bold();
    for (col, name) in COLUMNS.iter().enumerate() {
        let col = u16::try_from(col).unwrap_or(u16::MAX);
        sheet
            .write_string_with_format(0, col, *name, &header_fmt)
            .context("writing header")?;
    }
    for (r, e) in events.iter().enumerate() {
        let excel_row = u32::try_from(r + 1).unwrap_or(u32::MAX);
        for (col, value) in row(e, tz).iter().enumerate() {
            let col = u16::try_from(col).unwrap_or(u16::MAX);
            sheet
                .write_string(excel_row, col, value)
                .context("writing cell")?;
        }
    }
    wb.save(path)
        .with_context(|| format!("saving {}", path.display()))?;
    Ok(())
}
