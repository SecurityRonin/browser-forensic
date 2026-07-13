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
use ese_core::{decode_record, EseDatabase, EseValue};

/// Classify a `Containers.Name` value into the browsing [`ArtifactKind`] its
/// `Container_#` table holds, or `None` for non-browsing / infrastructure
/// containers (`BackgroundTransferApi`, `iecompat`, `DNTException`, …).
///
/// Vocabulary per the libyal WebCache spec (see module docs). `MSHist…`
/// containers are per-period history partitions and classify as History.
#[must_use]
pub fn classify_container(_name: &str) -> Option<ArtifactKind> {
    None
}

/// Infer the browser family from a container `Directory` path. Legacy Edge
/// (EdgeHTML) stores its WebCache containers under an app-container path
/// containing `MicrosoftEdge`; Internet Explorer does not.
#[must_use]
pub fn family_from_directory(_directory: &str) -> BrowserFamily {
    BrowserFamily::InternetExplorer
}

/// Build a [`BrowserEvent`] from one decoded `Container_#` record.
#[must_use]
pub fn event_from_record(
    _columns: &[(String, EseValue)],
    _kind: &ArtifactKind,
    _family: BrowserFamily,
    _source: &str,
    _container_name: &str,
) -> Option<BrowserEvent> {
    None
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
pub fn parse_webcache(_path: &Path) -> Result<Vec<BrowserEvent>> {
    Ok(Vec::new())
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
