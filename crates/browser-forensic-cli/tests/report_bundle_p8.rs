//! RFC 0001 Phase P8 — the reproducible `report --bundle` court/exam deliverable.
//!
//! A one-shot bundle to a directory: a self-contained HTML summary (ranked
//! findings via the P0 finding model + the D5 priority-cue framing), the machine
//! timeline (XLSX + JSONL), the chain-of-custody manifest (D11: inputs + hashes,
//! tool/rule versions, detection basis, timezone rule, exact command line), and a
//! SHA-256 sidecar hashing the bundle's own outputs so the bundle self-verifies.
//!
//! The pure-function tests are tier-3 (the bundling logic is UX assembly);
//! the end-to-end `br4n6 report --bundle` test is checked against an independent
//! oracle — the `sha2` digests in `SHA256SUMS.txt` are re-computed and compared
//! (tier-2), so a wrong sidecar cannot ship green.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use assert_cmd::Command;
use browser_forensic_cli::bundle::{
    self, Bundle, MANIFEST_JSON, REPORT_HTML, SHA256SUMS, TIMELINE_JSONL, TIMELINE_XLSX,
};
use browser_forensic_cli::report::{to_html_report, to_html_report_with_findings, ReportMeta};
use browser_forensic_core::finding::{
    Confidence, EvidenceSource, EvidenceState, Finding, Priority, Provenance, TimestampBasis,
    UserActionClaim,
};
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const TS_NS: i64 = 1_700_000_000_000_000_000;

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

fn history_event() -> BrowserEvent {
    BrowserEvent::new(
        TS_NS,
        BrowserFamily::Chromium,
        ArtifactKind::History,
        "/p/History",
        "visit",
    )
    .with_attr("url", serde_json::json!("https://example.com/page"))
    .with_attr("title", serde_json::json!("Example"))
}

fn exec_download_finding() -> Finding {
    let provenance = Provenance::new(
        EvidenceSource::Download,
        EvidenceState::Live,
        TimestampBasis::Explicit,
        UserActionClaim::Downloaded,
    );
    Finding::new(
        Priority::High,
        Confidence::Medium,
        "investigate.exec_download.v1",
        "consistent with an executable file downloaded via the browser",
        provenance,
        "/Users/x/Downloads/evil.exe",
    )
    .with_next("br4n6 artifact downloads <PATH>")
}

fn meta() -> ReportMeta {
    ReportMeta {
        case: None,
        examiner: None,
        tool: "br4n6".to_string(),
        version: "0.3.0".to_string(),
        timezone: "UTC".to_string(),
        generated_at_ns: TS_NS,
        flags: vec![],
    }
}

/// Build a manifest over a throwaway evidence file so the bundle carries a real
/// chain-of-custody document (tier-2 digests from `sha2`, not hand-typed).
fn synthetic_manifest(dir: &Path) -> browser_forensic_manifest::Manifest {
    let ev = dir.join("History");
    std::fs::write(&ev, b"abc").unwrap();
    let run = browser_forensic_manifest::RunMetadata::capture(
        "br4n6",
        "0.3.0",
        &["br4n6".to_string(), "report".to_string()],
        None,
    );
    browser_forensic_manifest::build_manifest(&[ev], run)
}

fn hex_sha256(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut h = Sha256::new();
    h.update(bytes);
    let d = h.finalize();
    d.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

// ---- pure bundle-writer tests ---------------------------------------------

#[test]
fn write_bundle_emits_every_expected_file() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("bundle");
    let events = [history_event()];
    let findings = [exec_download_finding()];
    let manifest = synthetic_manifest(dir.path());
    let b = Bundle {
        events: &events,
        findings: &findings,
        meta: &meta(),
        manifest: &manifest,
        tz: None,
    };
    let written = bundle::write_bundle(&out, &b).unwrap();
    for name in [
        REPORT_HTML,
        TIMELINE_XLSX,
        TIMELINE_JSONL,
        MANIFEST_JSON,
        SHA256SUMS,
    ] {
        assert!(
            out.join(name).is_file(),
            "bundle must contain {name}; wrote {written:?}"
        );
    }
}

#[test]
fn sidecar_hashes_match_the_actual_bundle_bytes() {
    // The SHA-256 sidecar must be a TRUE digest of the files it lists — re-hash
    // each listed file and compare (independent oracle).
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("bundle");
    let events = [history_event()];
    let findings = [exec_download_finding()];
    let manifest = synthetic_manifest(dir.path());
    let b = Bundle {
        events: &events,
        findings: &findings,
        meta: &meta(),
        manifest: &manifest,
        tz: None,
    };
    bundle::write_bundle(&out, &b).unwrap();

    let sums = std::fs::read_to_string(out.join(SHA256SUMS)).unwrap();
    let mut checked = 0;
    for line in sums.lines().filter(|l| !l.trim().is_empty()) {
        // `sha256sum` format: "<hex>  <filename>"
        let (hex, name) = line.split_once("  ").expect("sha256sum line shape");
        assert!(
            name != SHA256SUMS,
            "the sidecar must not hash itself: {line}"
        );
        let bytes = std::fs::read(out.join(name)).unwrap();
        assert_eq!(hex, hex_sha256(&bytes), "digest mismatch for {name}");
        checked += 1;
    }
    assert!(
        checked >= 4,
        "sidecar covers every bundle output, got {checked}"
    );
}

#[test]
fn single_file_report_has_no_findings_section_but_bundle_always_states_d5() {
    // The single-file `report --format html` path is unchanged — it renders NO
    // ranked-findings section. The bundle renderer always states the D5 cue, even
    // with zero findings (every bundle output states it once, per the RFC).
    let events = [history_event()];
    let plain = to_html_report(&events, &meta());
    assert!(
        !plain.contains("Ranked findings"),
        "single-file mode adds no findings section"
    );
    let with_empty = to_html_report_with_findings(&events, &meta(), &[]);
    assert!(
        with_empty.contains("Ranked findings"),
        "bundle renders the section"
    );
    assert!(
        with_empty
            .to_lowercase()
            .contains("not a finding of malice"),
        "bundle states the D5 cue even with no findings"
    );
}

#[test]
fn html_with_findings_shows_three_axes_and_priority_cue() {
    let events = [history_event()];
    let findings = [exec_download_finding()];
    let html = to_html_report_with_findings(&events, &meta(), &findings);
    for label in ["Priority:", "Confidence:", "Interpretation:"] {
        assert!(
            html.contains(label),
            "finding axis `{label}` rendered: {html}"
        );
    }
    // D5: every output states once that Priority is a triage cue, not malice.
    let lower = html.to_lowercase();
    assert!(
        lower.contains("attention cue") && lower.contains("not a finding of malice"),
        "priority-cue framing present"
    );
    assert!(html.contains("evil.exe"), "evidence shown in full");
}

#[test]
fn html_findings_are_escaped() {
    let provenance = Provenance::new(
        EvidenceSource::Download,
        EvidenceState::Live,
        TimestampBasis::Explicit,
        UserActionClaim::Downloaded,
    );
    let f = Finding::new(
        Priority::High,
        Confidence::Low,
        "investigate.exec_download.v1",
        "consistent with <script>alert(1)</script>",
        provenance,
        "/tmp/<b>x</b>.exe",
    );
    let html = to_html_report_with_findings(&[history_event()], &meta(), &[f]);
    assert!(
        !html.contains("<script>alert(1)</script>"),
        "raw script escaped"
    );
    assert!(html.contains("&lt;script&gt;"), "angle brackets escaped");
}

#[test]
fn rule_versions_dedup_and_parse_the_version_suffix() {
    let findings = [
        exec_download_finding(),
        exec_download_finding(),
        Finding::new(
            Priority::Medium,
            Confidence::Medium,
            "investigate.integrity.HistoryCleared.v2",
            "consistent with clearing",
            Provenance::new(
                EvidenceSource::History,
                EvidenceState::Deleted,
                TimestampBasis::None,
                UserActionClaim::Unknown,
            ),
            "gap",
        ),
    ];
    let rv = bundle::rule_versions_from_findings(&findings);
    assert_eq!(rv.len(), 2, "duplicate rule ids collapse to one entry");
    let exec = rv
        .iter()
        .find(|r| r.rule_id == "investigate.exec_download.v1")
        .expect("exec rule present");
    assert_eq!(exec.version, "1", "version parsed from the .vN suffix");
    let cleared = rv
        .iter()
        .find(|r| r.rule_id.contains("HistoryCleared"))
        .unwrap();
    assert_eq!(cleared.version, "2");
}

#[test]
fn timezone_rule_names_utc_and_the_zone() {
    let utc = bundle::timezone_rule(None).to_lowercase();
    assert!(utc.contains("utc"), "no-tz rule names UTC: {utc}");
    let ny: chrono_tz::Tz = "America/New_York".parse().unwrap();
    let zoned = bundle::timezone_rule(Some(ny));
    assert!(
        zoned.contains("America/New_York"),
        "zoned rule names the zone"
    );
}

// ---- end-to-end `br4n6 report --bundle` -----------------------------------

/// A Chrome-looking profile dir with a `History` file (bytes `b"abc"`).
fn chrome_profile(dir: &Path) -> std::path::PathBuf {
    let profile = dir.join("google-chrome").join("Default");
    std::fs::create_dir_all(&profile).unwrap();
    std::fs::write(profile.join("History"), b"abc").unwrap();
    profile
}

const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

#[test]
fn report_bundle_produces_a_self_verifying_bundle() {
    let dir = TempDir::new().unwrap();
    let profile = chrome_profile(dir.path());
    let out = dir.path().join("out");
    br4n6()
        .args(["report"])
        .arg(&profile)
        .arg("--bundle")
        .arg("-o")
        .arg(&out)
        .assert()
        .success();

    for name in [
        REPORT_HTML,
        TIMELINE_XLSX,
        TIMELINE_JSONL,
        MANIFEST_JSON,
        SHA256SUMS,
    ] {
        assert!(out.join(name).is_file(), "bundle wrote {name}");
    }
    // Manifest records the exact command line and the input's digest (D11).
    let manifest = std::fs::read_to_string(out.join(MANIFEST_JSON)).unwrap();
    assert!(manifest.contains("report"), "invocation recorded");
    assert!(manifest.contains(ABC_SHA256), "input SHA-256 recorded");
    assert!(
        manifest.contains("timezone_rule"),
        "D11 timezone rule recorded"
    );
    // Sidecar self-verification.
    let sums = std::fs::read_to_string(out.join(SHA256SUMS)).unwrap();
    for line in sums.lines().filter(|l| !l.trim().is_empty()) {
        let (hex, name) = line.split_once("  ").unwrap();
        let bytes = std::fs::read(out.join(name)).unwrap();
        assert_eq!(hex, hex_sha256(&bytes), "sidecar digest matches {name}");
    }
    // The HTML states the D5 court-safe framing.
    let html = std::fs::read_to_string(out.join(REPORT_HTML)).unwrap();
    assert!(
        html.to_lowercase().contains("not a finding of malice"),
        "D5 priority-cue footer present"
    );
}

#[test]
fn report_bundle_without_output_dir_errors() {
    let dir = TempDir::new().unwrap();
    let profile = chrome_profile(dir.path());
    br4n6()
        .args(["report"])
        .arg(&profile)
        .arg("--bundle")
        .assert()
        .failure();
}

#[test]
fn report_single_file_html_still_works() {
    // Regression: the historic single-file mode is untouched by the bundle flag.
    let dir = TempDir::new().unwrap();
    let profile = chrome_profile(dir.path());
    let out = br4n6()
        .args(["report"])
        .arg(&profile)
        .args(["--format", "html"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.starts_with("<!DOCTYPE html>"), "HTML to stdout");
}
