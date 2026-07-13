#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Case-level chain-of-custody manifest for browser evidence.
//!
//! Any `br4n6` run that reads evidence can emit a JSON manifest that records, for
//! every input file, its absolute path, size, SHA-256 (and MD5 for legacy-tool
//! interop), and modification time, alongside run metadata (tool + version, the
//! exact invocation, the acquisition time in UTC and a configured timezone, and
//! the host OS).
//!
//! ## What the manifest establishes — and what it does not
//!
//! The digests establish the **integrity of the extracted input files**: once the
//! manifest is written, any later modification of those files is detectable by
//! re-hashing them and comparing. The manifest does **not** by itself establish
//! the *provenance* of the source device or how the files were acquired — it
//! attests only to the extracted inputs at the recorded time. This limitation is
//! stated in the manifest header (`about`).
//!
//! The manifest is a plain JSON document; it may be sealed with an **external**
//! signature (gitsign, gpg, …) to bind it to an examiner. This crate does not
//! roll its own signing.
//!
//! ## Determinism
//!
//! Two runs over identical inputs produce byte-identical manifests except for the
//! acquisition timestamp: inputs are sorted by path, the JSON key order is fixed
//! by the struct layout, and no unordered map is serialized.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use browser_forensic_core::{BrowserFamily, Confidence};
use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use md5::Md5;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Schema identifier stamped into every manifest.
pub const SCHEMA_ID: &str = "browser-forensic/chain-of-custody/v1";

const ESTABLISHES: &str = "Records the SHA-256 and MD5 of each extracted input \
file at acquisition time — a verifiable integrity record: any later modification \
of these files is detectable by re-hashing and comparing.";

const LIMITATION: &str = "Attests to the integrity of the extracted input files \
only. It does not by itself establish the provenance of the source device or how \
the files were acquired.";

const EXTERNAL_SIGNING: &str = "This manifest may be sealed with an external \
signature (e.g. gitsign or gpg) to bind it to an examiner; the tool does not sign \
it itself.";

/// Honesty header: what the manifest establishes, its limit, and how to seal it.
#[derive(Debug, Clone, Serialize)]
pub struct ManifestAbout {
    /// What the recorded digests establish.
    pub establishes: String,
    /// The explicit epistemic limit of the record.
    pub limitation: String,
    /// How the manifest can be bound to an examiner (external signing).
    pub external_signing: String,
}

impl Default for ManifestAbout {
    fn default() -> Self {
        Self {
            establishes: ESTABLISHES.to_string(),
            limitation: LIMITATION.to_string(),
            external_signing: EXTERNAL_SIGNING.to_string(),
        }
    }
}

/// Metadata describing the run that produced the manifest.
#[derive(Debug, Clone, Serialize)]
pub struct RunMetadata {
    /// Tool name (e.g. `br4n6`).
    pub tool: String,
    /// Tool version (from `CARGO_PKG_VERSION`).
    pub version: String,
    /// The exact CLI invocation (process arguments joined by spaces).
    pub invocation: String,
    /// Acquisition time in UTC (RFC 3339).
    pub acquired_at_utc: String,
    /// The configured IANA timezone name (`UTC` when none was given).
    pub timezone: String,
    /// Acquisition time rendered in the configured timezone (RFC 3339).
    pub acquired_at_local: String,
    /// Host operating system (`std::env::consts::OS`).
    pub host_os: String,
}

impl RunMetadata {
    /// Capture run metadata using the current wall-clock time.
    #[must_use]
    pub fn capture(tool: &str, version: &str, args: &[String], tz: Option<Tz>) -> Self {
        Self::capture_at(tool, version, args, tz, Utc::now())
    }

    /// Capture run metadata at an explicit instant (testable seam).
    #[must_use]
    pub fn capture_at(
        tool: &str,
        version: &str,
        args: &[String],
        tz: Option<Tz>,
        now: DateTime<Utc>,
    ) -> Self {
        let (timezone, acquired_at_local) = match tz {
            Some(zone) => (
                zone.name().to_string(),
                now.with_timezone(&zone).to_rfc3339(),
            ),
            None => ("UTC".to_string(), now.to_rfc3339()),
        };
        Self {
            tool: tool.to_string(),
            version: version.to_string(),
            invocation: args.join(" "),
            acquired_at_utc: now.to_rfc3339(),
            timezone,
            acquired_at_local,
            host_os: std::env::consts::OS.to_string(),
        }
    }
}

/// One hashed evidence input.
#[derive(Debug, Clone, Serialize)]
pub struct InputFile {
    /// Absolute path to the file that was read.
    pub path: String,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Lowercase-hex SHA-256 of the file contents.
    pub sha256: String,
    /// Lowercase-hex MD5 of the file contents (legacy-tool interop).
    pub md5: String,
    /// File modification time in UTC (RFC 3339), when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime_utc: Option<String>,
    /// Hashing error for this file, when it could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The digest of a single file.
#[derive(Debug, Clone)]
pub struct FileDigest {
    /// File size in bytes.
    pub size_bytes: u64,
    /// Lowercase-hex SHA-256.
    pub sha256: String,
    /// Lowercase-hex MD5.
    pub md5: String,
    /// File modification time in UTC (RFC 3339), when available.
    pub mtime_utc: Option<String>,
}

/// One auto-detection result, recorded for court defensibility (RFC 0001 D8).
///
/// Detection is layered (magic bytes → schema probe → directory markers →
/// container probe); this records what each input was detected as, how confident
/// that call was, and the human-readable basis behind it.
#[derive(Debug, Clone, Serialize)]
pub struct DetectionRecord {
    /// Absolute path of the input the detector classified.
    pub path: String,
    /// The detected artifact kind, as a human string
    /// (e.g. `Chromium History (SQLite)`).
    pub detected_kind: String,
    /// Confidence in the classification (shares the [`Confidence`] axis with the
    /// finding model).
    pub confidence: Confidence,
    /// The layered basis for the call
    /// (e.g. `SQLite header + urls/visits schema + parent path .../Default/History`).
    pub basis: String,
}

/// A rule identifier paired with its version (RFC 0001 D11).
///
/// Recorded so a finding can be tied to the exact rule that produced it. A sorted
/// `Vec`, never a map, to keep the manifest deterministic.
#[derive(Debug, Clone, Serialize)]
pub struct RuleVersion {
    /// The rule identifier (e.g. `integrity.history.rowid_gap.v1`).
    pub rule_id: String,
    /// The rule's version string.
    pub version: String,
}

/// A complete chain-of-custody manifest.
#[derive(Debug, Clone, Serialize)]
pub struct Manifest {
    /// Schema identifier ([`SCHEMA_ID`]).
    pub schema: String,
    /// Honesty header describing what the manifest establishes and its limit.
    pub about: ManifestAbout,
    /// Metadata about the producing run.
    pub run: RunMetadata,
    /// Every hashed input, sorted by path for determinism.
    pub inputs: Vec<InputFile>,
    /// Per-input auto-detection basis + confidence (RFC 0001 D8). Omitted from
    /// the JSON when empty, so a run that does not populate it serializes exactly
    /// as before.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub detection_basis: Vec<DetectionRecord>,
    /// Sources that were skipped or whose parsers failed (RFC 0001 D8/D11).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub skipped_sources: Vec<String>,
    /// The producing tool's version, when recorded separately from [`RunMetadata`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_version: Option<String>,
    /// Versions of the rules that ran, for reproducibility (RFC 0001 D11).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rule_versions: Vec<RuleVersion>,
    /// Build hash of the tool, when available (RFC 0001 D11).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_hash: Option<String>,
    /// The timezone conversion rule applied to timestamps (RFC 0001 D11).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone_rule: Option<String>,
    /// Schema version of the tool's output records (RFC 0001 D11).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema_version: Option<String>,
}

/// Hash a single file, streaming its bytes through SHA-256 and MD5.
///
/// # Errors
/// Returns an error if the file cannot be opened or read.
pub fn hash_file(path: &Path) -> io::Result<FileDigest> {
    let mut file = fs::File::open(path)?;
    let mut sha = Sha256::new();
    let mut md5 = Md5::new();
    let mut buf = vec![0u8; 65_536];
    let mut size_bytes: u64 = 0;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        sha.update(&buf[..n]);
        md5.update(&buf[..n]);
        size_bytes += n as u64;
    }
    let mtime_utc = fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(rfc3339_utc);
    Ok(FileDigest {
        size_bytes,
        sha256: hex_lower(&sha.finalize()),
        md5: hex_lower(&md5.finalize()),
        mtime_utc,
    })
}

/// Enumerate the evidence input files under `path`.
///
/// A file resolves to itself; a directory is scanned for browser profiles (and,
/// failing that, treated as a single profile directory) and the known artifact
/// files each family stores. The result is absolute, sorted, and de-duplicated.
#[must_use]
pub fn enumerate_evidence(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![absolute(path)];
    }
    let mut out = Vec::new();
    let profiles = browser_forensic_discovery::discover_profiles(path);
    if profiles.is_empty() {
        for family in [
            BrowserFamily::Chromium,
            BrowserFamily::Firefox,
            BrowserFamily::Safari,
        ] {
            collect_artifacts(path, &family, &mut out);
        }
    } else {
        for profile in &profiles {
            collect_artifacts(&profile.path, &profile.browser, &mut out);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Build a manifest by hashing every input and attaching the run metadata.
#[must_use]
pub fn build_manifest(inputs: &[PathBuf], run: RunMetadata) -> Manifest {
    let mut files: Vec<InputFile> = inputs
        .iter()
        .map(|p| {
            let path = p.display().to_string();
            match hash_file(p) {
                Ok(d) => InputFile {
                    path,
                    size_bytes: d.size_bytes,
                    sha256: d.sha256,
                    md5: d.md5,
                    mtime_utc: d.mtime_utc,
                    error: None,
                },
                Err(e) => InputFile {
                    path,
                    size_bytes: 0,
                    sha256: String::new(),
                    md5: String::new(),
                    mtime_utc: None,
                    error: Some(e.to_string()),
                },
            }
        })
        .collect();
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Manifest {
        schema: SCHEMA_ID.to_string(),
        about: ManifestAbout::default(),
        run,
        inputs: files,
        detection_basis: Vec::new(),
        skipped_sources: Vec::new(),
        tool_version: None,
        rule_versions: Vec::new(),
        build_hash: None,
        timezone_rule: None,
        output_schema_version: None,
    }
}

/// Serialize a manifest to deterministic, pretty-printed JSON.
///
/// # Errors
/// Returns an error if serialization fails.
pub fn to_json(manifest: &Manifest) -> serde_json::Result<String> {
    serde_json::to_string_pretty(manifest)
}

// ---- private helpers -------------------------------------------------------

/// Lowercase-hex encode a digest.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String is infallible.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Render a `SystemTime` as an RFC 3339 UTC string.
fn rfc3339_utc(t: SystemTime) -> String {
    DateTime::<Utc>::from(t).to_rfc3339()
}

/// Best-effort absolute path: canonicalize, falling back to the input.
fn absolute(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Known top-level artifact file names a browser family stores in a profile dir.
fn artifact_names(family: &BrowserFamily) -> &'static [&'static str] {
    match family {
        BrowserFamily::Chromium => &[
            "History",
            "Cookies",
            "Bookmarks",
            "Web Data",
            "Login Data",
            "Preferences",
            "Secure Preferences",
        ],
        BrowserFamily::Firefox => &[
            "places.sqlite",
            "cookies.sqlite",
            "formhistory.sqlite",
            "favicons.sqlite",
            "sessionstore.jsonlz4",
            "extensions.json",
            "logins.json",
            "prefs.js",
        ],
        BrowserFamily::Safari => &["History.db"],
        // IE / Edge-Legacy consolidate history/cookies/cache/DOM storage into
        // one ESE database.
        BrowserFamily::InternetExplorer | BrowserFamily::EdgeLegacy => &["WebCacheV01.dat"],
    }
}

/// Push every existing known artifact under `dir` for `family` onto `out`.
fn collect_artifacts(dir: &Path, family: &BrowserFamily, out: &mut Vec<PathBuf>) {
    for name in artifact_names(family) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            out.push(absolute(&candidate));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::TempDir;

    fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 13, 12, 0, 0).unwrap()
    }

    fn fixed_run() -> RunMetadata {
        RunMetadata::capture_at(
            "br4n6",
            "0.2.0",
            &["br4n6".to_string(), "manifest".to_string()],
            None,
            fixed_now(),
        )
    }

    // Canonical published test vectors (NIST FIPS-180 / RFC 1321) — an
    // independent oracle, not a self-authored fixture.
    #[test]
    fn hash_file_empty_matches_canonical_vectors() {
        let d = TempDir::new().unwrap();
        let p = write_file(d.path(), "empty", b"");
        let fd = hash_file(&p).unwrap();
        assert_eq!(fd.size_bytes, 0);
        assert_eq!(
            fd.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(fd.md5, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn hash_file_abc_matches_canonical_vectors() {
        let d = TempDir::new().unwrap();
        let p = write_file(d.path(), "abc", b"abc");
        let fd = hash_file(&p).unwrap();
        assert_eq!(fd.size_bytes, 3);
        assert_eq!(
            fd.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(fd.md5, "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn hash_file_records_mtime() {
        let d = TempDir::new().unwrap();
        let p = write_file(d.path(), "x", b"hello");
        let fd = hash_file(&p).unwrap();
        assert!(fd.mtime_utc.is_some());
    }

    #[test]
    fn enumerate_single_file_returns_that_file() {
        let d = TempDir::new().unwrap();
        let p = write_file(d.path(), "History", b"data");
        let got = enumerate_evidence(&p);
        assert_eq!(got.len(), 1);
        assert!(got[0].ends_with("History"));
    }

    #[test]
    fn enumerate_profile_dir_finds_known_artifacts() {
        let d = TempDir::new().unwrap();
        write_file(d.path(), "History", b"h");
        write_file(d.path(), "Cookies", b"c");
        write_file(d.path(), "ignored.txt", b"x");
        let got = enumerate_evidence(d.path());
        let names: Vec<String> = got
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"History".to_string()));
        assert!(names.contains(&"Cookies".to_string()));
        assert!(!names.contains(&"ignored.txt".to_string()));
    }

    #[test]
    fn enumerate_empty_dir_is_empty() {
        let d = TempDir::new().unwrap();
        assert!(enumerate_evidence(d.path()).is_empty());
    }

    #[test]
    fn capture_at_utc_when_no_tz() {
        let rm = fixed_run();
        assert_eq!(rm.timezone, "UTC");
        assert_eq!(rm.tool, "br4n6");
        assert_eq!(rm.invocation, "br4n6 manifest");
        assert!(rm.acquired_at_utc.starts_with("2026-07-13T12:00:00"));
        assert!(!rm.host_os.is_empty());
    }

    #[test]
    fn capture_at_renders_configured_timezone() {
        let tz: Tz = "America/New_York".parse().unwrap();
        let rm = RunMetadata::capture_at("br4n6", "0.2.0", &[], Some(tz), fixed_now());
        assert_eq!(rm.timezone, "America/New_York");
        // 12:00 UTC in July == 08:00 EDT.
        assert!(rm.acquired_at_local.contains("08:00:00"));
    }

    #[test]
    fn build_manifest_sorts_inputs_and_is_deterministic() {
        let d = TempDir::new().unwrap();
        let b = write_file(d.path(), "b_file", b"bbb");
        let a = write_file(d.path(), "a_file", b"aaa");
        let inputs = vec![b, a];
        let m1 = build_manifest(&inputs, fixed_run());
        assert!(m1.inputs[0].path.ends_with("a_file"));
        assert!(m1.inputs[1].path.ends_with("b_file"));
        let m2 = build_manifest(&inputs, fixed_run());
        assert_eq!(to_json(&m1).unwrap(), to_json(&m2).unwrap());
    }

    #[test]
    fn empty_audit_fields_are_omitted_preserving_existing_output() {
        // A run that populates none of the D8/D11 audit fields must serialize
        // exactly as before — the new keys are absent, not empty arrays/nulls.
        let d = TempDir::new().unwrap();
        let p = write_file(d.path(), "abc", b"abc");
        let m = build_manifest(&[p], fixed_run());
        let json = to_json(&m).unwrap();
        for key in [
            "detection_basis",
            "skipped_sources",
            "tool_version",
            "rule_versions",
            "build_hash",
            "timezone_rule",
            "output_schema_version",
        ] {
            assert!(
                !json.contains(key),
                "unpopulated audit field `{key}` must be omitted from the JSON, got: {json}"
            );
        }
    }

    #[test]
    fn detection_basis_serializes_when_populated() {
        let d = TempDir::new().unwrap();
        let p = write_file(d.path(), "History", b"abc");
        let mut m = build_manifest(&[p], fixed_run());
        m.detection_basis.push(DetectionRecord {
            path: "/ev/Default/History".to_string(),
            detected_kind: "Chromium History (SQLite)".to_string(),
            confidence: Confidence::High,
            basis: "SQLite header + urls/visits schema + parent path .../Default/History"
                .to_string(),
        });
        let json = to_json(&m).unwrap();
        assert!(json.contains("detection_basis"));
        assert!(json.contains("Chromium History (SQLite)"));
        assert!(json.contains("urls/visits schema"));
        assert!(json.contains("High"), "confidence axis serialized");
    }

    #[test]
    fn skipped_sources_serialize_when_populated() {
        let d = TempDir::new().unwrap();
        let p = write_file(d.path(), "History", b"abc");
        let mut m = build_manifest(&[p], fixed_run());
        m.skipped_sources.push("encrypted cookies".to_string());
        m.skipped_sources.push("memory".to_string());
        let json = to_json(&m).unwrap();
        assert!(json.contains("skipped_sources"));
        assert!(json.contains("encrypted cookies"));
        assert!(json.contains("memory"));
    }

    #[test]
    fn versions_build_hash_and_rules_serialize_when_populated() {
        let d = TempDir::new().unwrap();
        let p = write_file(d.path(), "History", b"abc");
        let mut m = build_manifest(&[p], fixed_run());
        m.tool_version = Some("2.0.0".to_string());
        m.build_hash = Some("deadbeef".to_string());
        m.timezone_rule = Some("UTC, no DST conversion".to_string());
        m.output_schema_version = Some("browser-forensic/finding/v1".to_string());
        m.rule_versions.push(RuleVersion {
            rule_id: "integrity.history.rowid_gap.v1".to_string(),
            version: "1".to_string(),
        });
        let json = to_json(&m).unwrap();
        assert!(json.contains("2.0.0"), "tool_version");
        assert!(json.contains("deadbeef"), "build_hash");
        assert!(json.contains("UTC, no DST conversion"), "timezone_rule");
        assert!(
            json.contains("browser-forensic/finding/v1"),
            "output_schema_version"
        );
        assert!(
            json.contains("integrity.history.rowid_gap.v1"),
            "rule_versions rule_id"
        );
    }

    #[test]
    fn key_sources_omitted_when_unpopulated() {
        // A run that used no decryption keys must not serialize a `key_sources`
        // key at all (absent, not an empty array) — byte-for-byte as before.
        let d = TempDir::new().unwrap();
        let p = write_file(d.path(), "Cookies", b"abc");
        let m = build_manifest(&[p], fixed_run());
        let json = to_json(&m).unwrap();
        assert!(
            !json.contains("key_sources"),
            "unpopulated key_sources must be omitted: {json}"
        );
    }

    #[test]
    fn key_sources_record_found_vs_decrypted() {
        // D7/D11: the manifest hashes/identifies every key file used, and must
        // distinguish "key found/unwrapped" from "decrypted N items with it".
        let d = TempDir::new().unwrap();
        let p = write_file(d.path(), "Cookies", b"abc");
        let mut m = build_manifest(&[p], fixed_run());
        m.key_sources.push(KeySource {
            kind: "Local State (AES key, DPAPI-wrapped)".to_string(),
            path: Some("/ev/Default/Local State".to_string()),
            sha256: Some("aa11bb22".to_string()),
            detail: None,
            unwrapped: true,
            decrypted_items: 0,
        });
        m.key_sources.push(KeySource {
            kind: "DPAPI masterkey".to_string(),
            path: Some("/ev/Protect/S-1-5-21-1/GUID".to_string()),
            sha256: Some("cc33dd44".to_string()),
            detail: Some("masterkey a1b2c3d4-....".to_string()),
            unwrapped: true,
            decrypted_items: 3,
        });
        let json = to_json(&m).unwrap();
        assert!(
            json.contains("key_sources"),
            "key_sources serialized: {json}"
        );
        assert!(json.contains("Local State (AES key, DPAPI-wrapped)"));
        assert!(json.contains("aa11bb22"), "key-file SHA-256 recorded");
        assert!(json.contains("cc33dd44"), "masterkey SHA-256 recorded");
        assert!(json.contains("unwrapped"), "found/unwrapped flag recorded");
        assert!(json.contains("decrypted_items"), "decrypted count recorded");
        // Found-vs-decrypted: the Local State was unwrapped (found) but decrypted
        // nothing on its own (0); the masterkey path decrypted 3 items.
        assert!(json.contains("\"decrypted_items\": 0"));
        assert!(json.contains("\"decrypted_items\": 3"));
    }

    #[test]
    fn manifest_json_carries_schema_honesty_and_digests() {
        let d = TempDir::new().unwrap();
        let p = write_file(d.path(), "abc", b"abc");
        let m = build_manifest(&[p], fixed_run());
        let json = to_json(&m).unwrap();
        assert!(json.contains(SCHEMA_ID));
        assert!(json.contains("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        assert!(json.contains("900150983cd24fb0d6963f7d28e17f72"));
        // Honesty: integrity of extracted inputs, not device provenance; signable.
        assert!(json.contains("integrity"));
        assert!(json.to_lowercase().contains("provenance"));
        assert!(json.to_lowercase().contains("sign"));
    }
}
