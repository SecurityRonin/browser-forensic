#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! IE / Edge-Legacy `WebCacheV01.dat` (ESE) browser-artifact parser.
//!
//! Internet Explorer (Trident) and legacy EdgeHTML/Spartan Edge store browsing
//! history, cookies, cached content and DOM storage in an Extensible Storage
//! Engine (ESE) database — `%LOCALAPPDATA%\Microsoft\Windows\WebCache\WebCacheV01.dat`
//! — not SQLite.
//!
//! This crate does **not** parse ESE itself: the fleet [`ese_core`] crate owns
//! the ESE binary format (header, B-tree, catalog, record decoding). This crate
//! is purely the WebCache *schema* layer on top of `ese_core`'s reader — it maps
//! the `Containers` table and each per-container `Container_#` table onto
//! [`BrowserEvent`]s.
//!
//! # Schema (authoritative source)
//!
//! libyal esedb-kb, "Microsoft Internet Explorer web cache (WebCache) database"
//! (J. Metz, 2021):
//! <https://github.com/libyal/esedb-kb/blob/main/documentation/MSIE%20web%20cache.asciidoc>
//!
//! - `Containers` — one row per container: `ContainerId` (id 1, i64), `Name`
//!   (id 128, text: History / Content / Cookies / DOMStore / iedownload /
//!   MSHist… ), `Directory` (id 257), `SecureDirectories` (id 258).
//! - `Container_<ContainerId>` — one row per cached entry: `Url` (id 256),
//!   `Filename` (id 257), `AccessCount` (id 9), and the FILETIME timestamp
//!   columns `CreationTime` (11), `ExpiryTime` (12), `ModifiedTime` (13),
//!   `AccessedTime` (14). The spec notes a `Container_#` table is sometimes
//!   absent for a declared container.

use std::path::Path;

use anyhow::{Context as _, Result};
use browser_forensic_core::timestamp::filetime_to_unix_nanos;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use ese_core::{decode_ese_record, decode_record, ColumnDef, EseDatabase, EseValue};

/// Classify a `Containers.Name` value into the browsing [`ArtifactKind`] its
/// `Container_#` table holds, or `None` for non-browsing / infrastructure
/// containers (`BackgroundTransferApi`, `iecompat`, `DNTException`, …).
///
/// Vocabulary per the libyal WebCache spec (see module docs). `MSHist…`
/// containers are per-period history partitions and classify as History.
#[must_use]
pub fn classify_container(name: &str) -> Option<ArtifactKind> {
    // Per-period history partitions: MSHist012026062220260629, …
    if name.starts_with("MSHist") {
        return Some(ArtifactKind::History);
    }
    // Fixed container names (case-insensitive — the store is not case-sensitive).
    if name.eq_ignore_ascii_case("History") {
        Some(ArtifactKind::History)
    } else if name.eq_ignore_ascii_case("Cookies") {
        Some(ArtifactKind::Cookies)
    } else if name.eq_ignore_ascii_case("Content") {
        // "Content" is the on-disk cache (INetCache).
        Some(ArtifactKind::Cache)
    } else if name.eq_ignore_ascii_case("iedownload") {
        Some(ArtifactKind::Downloads)
    } else if name.eq_ignore_ascii_case("DOMStore") {
        Some(ArtifactKind::LocalStorage)
    } else {
        None
    }
}

/// Infer the browser family from a container `Directory` path. Legacy Edge
/// (EdgeHTML) stores its WebCache containers under an app-container path
/// containing `MicrosoftEdge`; Internet Explorer does not.
#[must_use]
pub fn family_from_directory(directory: &str) -> BrowserFamily {
    if directory.to_ascii_lowercase().contains("microsoftedge") {
        BrowserFamily::EdgeLegacy
    } else {
        BrowserFamily::InternetExplorer
    }
}

/// Find a column value by name in a decoded record.
fn column<'a>(columns: &'a [(String, EseValue)], name: &str) -> Option<&'a EseValue> {
    columns.iter().find(|(n, _)| n == name).map(|(_, v)| v)
}

/// Decode an ESE text/large-text column to a `String`. WebCache text columns
/// arrive as `Text` (variable) or, for tagged large-text, `Binary` UTF-8 bytes.
/// Trailing NUL padding (common in tagged text) is trimmed. Empty → `None`.
fn ese_text(v: &EseValue) -> Option<String> {
    let s = match v {
        EseValue::Text(s) => s.clone(),
        EseValue::Binary(b) => String::from_utf8_lossy(b).into_owned(),
        _ => return None,
    };
    let s = s.trim_end_matches('\0').trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Read a FILETIME column (stored as a 64-bit signed/unsigned integer).
fn ese_filetime(v: &EseValue) -> Option<u64> {
    match v {
        EseValue::I64(n) => Some(*n as u64),
        EseValue::U64(n) => Some(*n),
        _ => None,
    }
}

/// Read a small unsigned integer column (AccessCount, EntryId, …).
fn ese_u64(v: &EseValue) -> Option<u64> {
    match v {
        EseValue::U8(n) => Some(u64::from(*n)),
        EseValue::U16(n) => Some(u64::from(*n)),
        EseValue::U32(n) => Some(u64::from(*n)),
        EseValue::U64(n) => Some(*n),
        EseValue::I16(n) if *n >= 0 => Some(*n as u64),
        EseValue::I32(n) if *n >= 0 => Some(*n as u64),
        EseValue::I64(n) if *n >= 0 => Some(*n as u64),
        _ => None,
    }
}

/// FILETIME timestamp columns in a `Container_#` record, most-to-least relevant
/// for the "when did this happen" event time.
const TIME_COLUMNS: [&str; 4] = ["AccessedTime", "ModifiedTime", "CreationTime", "SyncTime"];

/// Pick the primary event timestamp: the first non-zero FILETIME among
/// [`TIME_COLUMNS`]. A `0` FILETIME means "not set" and is skipped (converting
/// it would clamp to `i64::MIN`). Returns `0` when no timestamp is present.
fn primary_timestamp_ns(columns: &[(String, EseValue)]) -> i64 {
    for name in TIME_COLUMNS {
        if let Some(ft) = column(columns, name).and_then(ese_filetime) {
            if ft != 0 {
                return filetime_to_unix_nanos(ft);
            }
        }
    }
    0
}

/// Insert a FILETIME column into `attrs` as Unix nanoseconds, only when present
/// and non-zero (machine-faithful: absent stays absent, never a bogus MIN).
fn put_time_ns(
    attrs_ns: &mut serde_json::Map<String, serde_json::Value>,
    columns: &[(String, EseValue)],
    col: &str,
    key: &str,
) {
    if let Some(ft) = column(columns, col).and_then(ese_filetime) {
        if ft != 0 {
            attrs_ns.insert(
                key.to_string(),
                serde_json::json!(filetime_to_unix_nanos(ft)),
            );
        }
    }
}

/// Build a [`BrowserEvent`] from one decoded `Container_#` record.
///
/// Looks columns up by **name** (not fixed offset), so if `ese_core` gains
/// tagged-column (`id >= 256`) record decoding, `Url`/`Filename`/`ResponseHeaders`
/// populate automatically with no change here. Every column access is
/// bounds/`None`-safe — a record missing any column degrades that field.
#[must_use]
pub fn event_from_record(
    columns: &[(String, EseValue)],
    kind: &ArtifactKind,
    family: BrowserFamily,
    source: &str,
    container_name: &str,
) -> Option<BrowserEvent> {
    let url = column(columns, "Url").and_then(ese_text);
    let filename = column(columns, "Filename").and_then(ese_text);
    let description = url
        .clone()
        .or_else(|| filename.clone())
        .unwrap_or_else(|| format!("{container_name} entry"));

    let ts = primary_timestamp_ns(columns);
    let mut ev = BrowserEvent::new(ts, family, kind.clone(), source, description);

    ev = ev.with_attr("container", serde_json::json!(container_name));
    if let Some(u) = url {
        ev = ev.with_attr("url", serde_json::json!(u));
    }
    if let Some(f) = filename {
        ev = ev.with_attr("filename", serde_json::json!(f));
    }
    if let Some(id) = column(columns, "EntryId").and_then(ese_u64) {
        ev = ev.with_attr("entry_id", serde_json::json!(id));
    }
    if let Some(n) = column(columns, "AccessCount").and_then(ese_u64) {
        ev = ev.with_attr("access_count", serde_json::json!(n));
    }
    // Preserve every WebCache timestamp faithfully as Unix nanos.
    let mut times = serde_json::Map::new();
    put_time_ns(&mut times, columns, "AccessedTime", "accessed_time_ns");
    put_time_ns(&mut times, columns, "ModifiedTime", "modified_time_ns");
    put_time_ns(&mut times, columns, "CreationTime", "creation_time_ns");
    put_time_ns(&mut times, columns, "ExpiryTime", "expiry_time_ns");
    for (k, v) in times {
        ev = ev.with_attr(k, v);
    }
    Some(ev)
}

/// Decode one ESE data-definition record using the layout that matches the
/// database's on-disk format.
///
/// Real WebCacheV01.dat files use ESE's large-page (extended) format, where byte
/// 1 of a record is the highest variable data-type id and the `Url`/`Filename`
/// live in the tagged region (column id >= 256): these need
/// [`decode_ese_record`] with `extended = true`. Small-page fixtures use the
/// legacy layout ([`decode_record`], byte 1 = variable-column count). The
/// discriminator is [`EseDatabase::is_extended_format`] — a structural property
/// of the file, and the same fork `ese_core`'s own record cursor makes.
fn decode_table_record(
    data: &[u8],
    columns: &[ColumnDef],
    extended: bool,
) -> Result<Vec<(String, EseValue)>, ese_core::EseError> {
    if extended {
        decode_ese_record(data, columns, true)
    } else {
        decode_record(data, columns)
    }
}

/// Parse an IE / Edge-Legacy `WebCacheV01.dat` into browser events.
///
/// Opens the ESE database via [`ese_core`], reads the `Containers` table, and
/// for each browsing container reads its `Container_<id>` table, mapping records
/// to [`BrowserEvent`]s. Read-only. A missing/undecodable table or column
/// degrades that container to zero events rather than failing the whole parse.
///
/// # Errors
/// Returns an error only if the file cannot be opened as an ESE database or the
/// `Containers` table itself cannot be read (a bootstrap failure, surfaced loud
/// rather than absorbed into an empty result).
pub fn parse_webcache(path: &Path) -> Result<Vec<BrowserEvent>> {
    let db = EseDatabase::open(path)
        .with_context(|| format!("opening ESE WebCache database {}", path.display()))?;
    let source = path.display().to_string();
    // Real WebCache files are large-page (extended) format; small-page fixtures
    // are legacy. Pick the matching record decoder per this structural property.
    let extended = db.is_extended_format();

    // Bootstrap: the Containers table lists every container. A failure to read
    // it is a real error, surfaced loud — never absorbed into an empty result.
    let container_cols = db
        .table_columns("Containers")
        .context("reading Containers table columns")?;
    let container_cursor = db
        .table_records("Containers")
        .context("reading Containers table")?;

    // (ContainerId, Name, Directory) for each declared container.
    let mut containers: Vec<(i64, String, String)> = Vec::new();
    for rec in container_cursor {
        // A single corrupt page/record degrades to skip; the cursor recovers.
        let Ok((_, _, data)) = rec else { continue };
        let Ok(cols) = decode_table_record(&data, &container_cols, extended) else {
            continue;
        };
        let id = column(&cols, "ContainerId").and_then(|v| match v {
            EseValue::I64(n) => Some(*n),
            EseValue::U64(n) => i64::try_from(*n).ok(),
            _ => None,
        });
        let name = column(&cols, "Name").and_then(ese_text);
        let directory = column(&cols, "Directory")
            .and_then(ese_text)
            .unwrap_or_default();
        if let (Some(id), Some(name)) = (id, name) {
            containers.push((id, name, directory));
        }
    }

    let mut events = Vec::new();
    for (id, name, directory) in containers {
        // Only browsing containers become events; infrastructure containers
        // (BackgroundTransferApi, iecompat, …) are skipped.
        let Some(kind) = classify_container(&name) else {
            continue;
        };
        let family = family_from_directory(&directory);
        let table = format!("Container_{id}");

        // A declared container's Container_# table is sometimes absent (per the
        // WebCache spec) — degrade that container to zero events, never panic.
        let Ok(cols) = db.table_columns(&table) else {
            continue;
        };
        let Ok(cursor) = db.table_records(&table) else {
            continue;
        };
        for rec in cursor {
            let Ok((_, _, data)) = rec else { continue };
            let Ok(record_cols) = decode_table_record(&data, &cols, extended) else {
                continue;
            };
            if let Some(ev) = event_from_record(&record_cols, &kind, family.clone(), &source, &name)
            {
                events.push(ev);
            }
        }
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_known_browsing_containers() {
        assert_eq!(classify_container("Cookies"), Some(ArtifactKind::Cookies));
        assert_eq!(classify_container("History"), Some(ArtifactKind::History));
        assert_eq!(classify_container("Content"), Some(ArtifactKind::Cache));
        assert_eq!(
            classify_container("iedownload"),
            Some(ArtifactKind::Downloads)
        );
        assert_eq!(
            classify_container("DOMStore"),
            Some(ArtifactKind::LocalStorage)
        );
    }

    #[test]
    fn classify_mshist_period_containers_as_history() {
        // MSHist012026062220260629 etc. are per-period history partitions.
        assert_eq!(
            classify_container("MSHist012026062220260629"),
            Some(ArtifactKind::History)
        );
    }

    #[test]
    fn classify_case_insensitive_for_fixed_names() {
        assert_eq!(classify_container("cookies"), Some(ArtifactKind::Cookies));
        assert_eq!(classify_container("CONTENT"), Some(ArtifactKind::Cache));
    }

    #[test]
    fn classify_non_browsing_containers_return_none() {
        assert_eq!(classify_container("BackgroundTransferApi"), None);
        assert_eq!(classify_container("iecompat"), None);
        assert_eq!(classify_container("iecompatua"), None);
        assert_eq!(classify_container("DNTException"), None);
    }

    #[test]
    fn family_edge_legacy_from_microsoftedge_path() {
        let dir = r"C:\Users\u\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\#!001\MicrosoftEdge\Cache";
        assert_eq!(family_from_directory(dir), BrowserFamily::EdgeLegacy);
    }

    #[test]
    fn family_internet_explorer_from_ie_path() {
        let dir = r"C:\Users\u\AppData\Local\Microsoft\Windows\INetCache\IE";
        assert_eq!(family_from_directory(dir), BrowserFamily::InternetExplorer);
        assert_eq!(family_from_directory(""), BrowserFamily::InternetExplorer);
    }

    // ── event_from_record ────────────────────────────────────────────────────

    fn cols(pairs: &[(&str, EseValue)]) -> Vec<(String, EseValue)> {
        pairs
            .iter()
            .map(|(n, v)| ((*n).to_string(), v.clone()))
            .collect()
    }

    // 2023-01-01T00:00:00Z as a Windows FILETIME.
    const FT_2023: i64 = (1_672_531_200 + 11_644_473_600) * 10_000_000;

    #[test]
    fn event_extracts_url_and_accessed_time() {
        let c = cols(&[
            (
                "Url",
                EseValue::Text("Visited: user@https://example.com/".into()),
            ),
            ("AccessedTime", EseValue::I64(FT_2023)),
            ("AccessCount", EseValue::U32(3)),
        ]);
        let ev = event_from_record(
            &c,
            &ArtifactKind::History,
            BrowserFamily::InternetExplorer,
            "/w.dat",
            "History",
        )
        .expect("event");
        assert_eq!(ev.timestamp_ns, 1_672_531_200_000_000_000);
        assert_eq!(ev.artifact, ArtifactKind::History);
        assert_eq!(ev.browser, BrowserFamily::InternetExplorer);
        assert!(ev.description.contains("example.com"));
        assert_eq!(
            ev.attrs["url"],
            serde_json::json!("Visited: user@https://example.com/")
        );
        assert_eq!(ev.attrs["access_count"], serde_json::json!(3));
        assert_eq!(ev.attrs["container"], serde_json::json!("History"));
    }

    #[test]
    fn event_timestamp_falls_back_when_accessed_time_absent() {
        // No AccessedTime → fall back to ModifiedTime.
        let c = cols(&[
            ("Url", EseValue::Text("https://a.test/".into())),
            ("ModifiedTime", EseValue::I64(FT_2023)),
        ]);
        let ev = event_from_record(
            &c,
            &ArtifactKind::Cache,
            BrowserFamily::InternetExplorer,
            "/w.dat",
            "Content",
        )
        .expect("event");
        assert_eq!(ev.timestamp_ns, 1_672_531_200_000_000_000);
    }

    #[test]
    fn event_zero_filetime_is_not_converted_to_min() {
        // A "not set" FILETIME of 0 must yield timestamp 0, never i64::MIN.
        let c = cols(&[
            ("Url", EseValue::Text("https://a.test/".into())),
            ("AccessedTime", EseValue::I64(0)),
        ]);
        let ev = event_from_record(
            &c,
            &ArtifactKind::Cache,
            BrowserFamily::InternetExplorer,
            "/w.dat",
            "Content",
        )
        .expect("event");
        assert_eq!(ev.timestamp_ns, 0);
    }

    #[test]
    fn event_without_url_falls_back_to_filename_then_container() {
        let c = cols(&[("Filename", EseValue::Text("cachedfile.bin".into()))]);
        let ev = event_from_record(
            &c,
            &ArtifactKind::Cache,
            BrowserFamily::InternetExplorer,
            "/w.dat",
            "Content",
        )
        .expect("event");
        assert!(ev.description.contains("cachedfile.bin"));
    }

    #[test]
    fn parse_webcache_nonexistent_path_errors() {
        assert!(parse_webcache(Path::new("/no/such/WebCacheV01.dat")).is_err());
    }
}
