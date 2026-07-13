//! RFC 0001 Phase P8 — the reproducible `report --bundle` deliverable.
//!
//! A one-shot bundle written to a directory, self-contained and self-verifying:
//!
//! * `report.html`   — the court-presentable HTML report **with** the ranked,
//!   court-safe findings section (P0 finding model + D5 priority-cue framing).
//! * `timeline.xlsx` — the machine timeline as a spreadsheet (human review).
//! * `timeline.jsonl`— the machine timeline as newline-delimited JSON
//!   (round-trippable, D10 — one object per line, greppable and streamable).
//! * `manifest.json` — the chain-of-custody manifest (D11): every input's path +
//!   size + SHA-256 + MD5 + mtime, the tool + rule versions, detection basis
//!   (D8), the timezone-conversion rule, and the exact command line.
//! * `SHA256SUMS.txt`— a `sha256sum`-format sidecar over the four files above, so
//!   the bundle self-verifies with `sha256sum -c SHA256SUMS.txt`.
//!
//! This module only *assembles* existing engines (`report`, `export`,
//! `manifest`) — it is bundling + reproducibility, not new forensics. The caller
//! (`report --bundle`) gathers the events, the ranked findings, the report meta,
//! and the fully-populated manifest, then hands them here to serialize.

use std::path::Path;

use anyhow::{Context, Result};
use browser_forensic_core::finding::Finding;
use browser_forensic_core::BrowserEvent;
use browser_forensic_manifest::{Manifest, RuleVersion};
use chrono_tz::Tz;

use crate::export::{self, ExportFormat};
use crate::report::{self, ReportMeta};

/// The self-contained HTML report (findings + timeline).
pub const REPORT_HTML: &str = "report.html";
/// The machine timeline as a spreadsheet.
pub const TIMELINE_XLSX: &str = "timeline.xlsx";
/// The machine timeline as newline-delimited JSON.
pub const TIMELINE_JSONL: &str = "timeline.jsonl";
/// The chain-of-custody manifest.
pub const MANIFEST_JSON: &str = "manifest.json";
/// The `sha256sum`-format sidecar over every other bundle file.
pub const SHA256SUMS: &str = "SHA256SUMS.txt";

/// The four content files the sidecar hashes, in a stable order. `SHA256SUMS.txt`
/// is excluded — a checksum file never hashes itself.
const HASHED_FILES: &[&str] = &[REPORT_HTML, TIMELINE_XLSX, TIMELINE_JSONL, MANIFEST_JSON];

/// Everything the bundle serializes, gathered by the caller.
pub struct Bundle<'a> {
    /// The time-sorted event stream (the timeline).
    pub events: &'a [BrowserEvent],
    /// The ranked, court-safe findings (already ordered by priority).
    pub findings: &'a [Finding],
    /// Report header metadata (case, tool, version, timezone label).
    pub meta: &'a ReportMeta,
    /// The fully-populated chain-of-custody manifest (D11).
    pub manifest: &'a Manifest,
    /// Timezone for the human-facing timestamps in the timeline.
    pub tz: Option<Tz>,
}

/// Write the reproducible report bundle into `dir`, returning the filenames
/// written (sorted). Creates `dir` if it does not exist.
///
/// # Errors
/// Propagates directory-creation, serialization, and file-write failures.
pub fn write_bundle(dir: &Path, bundle: &Bundle) -> Result<Vec<String>> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating bundle directory {}", dir.display()))?;

    // report.html — the human deliverable (findings + timeline).
    let html = report::to_html_report_with_findings(bundle.events, bundle.meta, bundle.findings);
    write_file(dir, REPORT_HTML, html.as_bytes())?;

    // timeline.xlsx — machine timeline for spreadsheet review.
    export::write_xlsx(bundle.events, bundle.tz, &dir.join(TIMELINE_XLSX))
        .context("writing bundle timeline.xlsx")?;

    // timeline.jsonl — machine timeline, round-trippable (D10).
    let mut jsonl = Vec::new();
    export::write_stream(bundle.events, ExportFormat::Jsonl, bundle.tz, &mut jsonl)
        .context("serializing bundle timeline.jsonl")?;
    write_file(dir, TIMELINE_JSONL, &jsonl)?;

    // manifest.json — chain of custody (D11).
    let manifest_json = browser_forensic_manifest::to_json(bundle.manifest)
        .context("serializing bundle manifest")?;
    write_file(dir, MANIFEST_JSON, manifest_json.as_bytes())?;

    // SHA256SUMS.txt — the self-verifying sidecar over the four files above.
    let sums = sha256sums(dir, HASHED_FILES)?;
    write_file(dir, SHA256SUMS, sums.as_bytes())?;

    let mut names: Vec<String> = HASHED_FILES
        .iter()
        .map(|s| (*s).to_string())
        .chain(std::iter::once(SHA256SUMS.to_string()))
        .collect();
    names.sort();
    Ok(names)
}

/// Compute a `sha256sum`-format sidecar over `filenames` (relative to `dir`):
/// one `"<hex>  <filename>"` line per file, in the given order. Reuses the
/// manifest crate's streaming hasher so the digest matches an external
/// `sha256sum` byte-for-byte.
///
/// # Errors
/// Propagates a read/hash failure for any listed file.
pub fn sha256sums(dir: &Path, filenames: &[&str]) -> Result<String> {
    let mut out = String::new();
    for name in filenames {
        let path = dir.join(name);
        let digest = browser_forensic_manifest::hash_file(&path)
            .with_context(|| format!("hashing bundle file {}", path.display()))?;
        // Two spaces separate hash from name — the GNU coreutils binary-mode
        // shape that `sha256sum -c` consumes.
        out.push_str(&digest.sha256);
        out.push_str("  ");
        out.push_str(name);
        out.push('\n');
    }
    Ok(out)
}

/// Map the ranked findings to sorted, de-duplicated [`RuleVersion`] records
/// (RFC 0001 D11 — which rules ran, at which version). The version is parsed from
/// a trailing `.vN` segment of the `rule_id` (`investigate.exec_download.v1` →
/// `1`); a rule id without such a suffix records version `1`.
#[must_use]
pub fn rule_versions_from_findings(findings: &[Finding]) -> Vec<RuleVersion> {
    let mut seen: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for f in findings {
        seen.entry(f.rule_id.clone())
            .or_insert_with(|| rule_version(&f.rule_id));
    }
    seen.into_iter()
        .map(|(rule_id, version)| RuleVersion { rule_id, version })
        .collect()
}

/// Parse the version from a rule id's trailing `.vN` segment, defaulting to `1`.
fn rule_version(rule_id: &str) -> String {
    rule_id
        .rsplit('.')
        .next()
        .and_then(|seg| seg.strip_prefix('v'))
        .filter(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
        .map_or_else(|| "1".to_string(), ToString::to_string)
}

/// The timezone-conversion rule recorded in the manifest (RFC 0001 D11): what
/// zone the human-facing timestamps were rendered in and how they were derived.
#[must_use]
pub fn timezone_rule(tz: Option<Tz>) -> String {
    match tz {
        None => {
            "UTC; timestamps stored and rendered in UTC, no timezone conversion applied".to_string()
        }
        Some(zone) => format!(
            "timestamps stored in UTC and rendered in {} (IANA), DST-aware conversion",
            zone.name()
        ),
    }
}

/// Write one bundle file, surfacing the path on failure.
fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let path = dir.join(name);
    std::fs::write(&path, bytes).with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::finding::{
        Confidence, EvidenceSource, EvidenceState, Priority, Provenance, TimestampBasis,
        UserActionClaim,
    };
    use tempfile::TempDir;

    fn a_finding(rule_id: &str) -> Finding {
        Finding::new(
            Priority::High,
            Confidence::Medium,
            rule_id,
            "consistent with something",
            Provenance::new(
                EvidenceSource::Download,
                EvidenceState::Live,
                TimestampBasis::Explicit,
                UserActionClaim::Downloaded,
            ),
            "evidence",
        )
    }

    #[test]
    fn sha256sums_matches_a_known_vector() {
        // File bytes `b"abc"` → canonical SHA-256 (NIST FIPS-180 vector).
        let d = TempDir::new().unwrap();
        std::fs::write(d.path().join("f"), b"abc").unwrap();
        let sums = sha256sums(d.path(), &["f"]).unwrap();
        assert_eq!(
            sums,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  f\n"
        );
    }

    #[test]
    fn rule_version_parses_suffix_or_defaults() {
        assert_eq!(rule_version("a.b.v3"), "3");
        assert_eq!(rule_version("a.b.c"), "1");
        assert_eq!(rule_version("noversion"), "1");
        assert_eq!(rule_version("a.vx"), "1");
    }

    #[test]
    fn rule_versions_are_sorted_and_unique() {
        let rv = rule_versions_from_findings(&[
            a_finding("z.rule.v2"),
            a_finding("a.rule.v1"),
            a_finding("z.rule.v2"),
        ]);
        assert_eq!(rv.len(), 2);
        assert_eq!(rv[0].rule_id, "a.rule.v1");
        assert_eq!(rv[1].rule_id, "z.rule.v2");
        assert_eq!(rv[1].version, "2");
    }

    #[test]
    fn timezone_rule_distinguishes_utc_from_zoned() {
        assert!(timezone_rule(None).to_lowercase().contains("utc"));
        let ny: Tz = "America/New_York".parse().unwrap();
        assert!(timezone_rule(Some(ny)).contains("America/New_York"));
    }
}
