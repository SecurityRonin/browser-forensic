#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end coverage for `br4n6 investigate` (RFC 0001 Phase P3a): the ranked,
//! court-safe summary with tiering and the always-present skipped-work footer,
//! exercised against the `br4n6` binary over a Chrome profile fixture.

use assert_cmd::Command;
use rusqlite::Connection;
use std::path::PathBuf;
use tempfile::TempDir;

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

/// A Chrome profile whose `History` carries a visit and an executable download
/// (`evil.exe`) — enough to produce at least one ranked finding. Returns
/// `(TempDir, profile_dir)`; point `investigate` at the profile dir.
fn chrome_profile_with_exe_download() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let profile = dir.path().join("google-chrome").join("Default");
    std::fs::create_dir_all(&profile).unwrap();
    let history = profile.join("History");
    let conn = Connection::open(&history).unwrap();
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
         INSERT INTO urls VALUES (1,'https://example.com','Example',1,13327626000000000);
         INSERT INTO visits VALUES (1,1,13327626000000000,0,0);
         CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT NOT NULL DEFAULT '', start_time INTEGER NOT NULL DEFAULT 0, total_bytes INTEGER NOT NULL DEFAULT 0, state INTEGER NOT NULL DEFAULT 0, danger_type INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE downloads_url_chains (id INTEGER NOT NULL, chain_index INTEGER NOT NULL, url TEXT NOT NULL);
         INSERT INTO downloads (id,target_path,start_time,total_bytes,state,danger_type) VALUES (1,'/Users/x/Downloads/evil.exe',13327626000000000,1024,1,0);
         INSERT INTO downloads_url_chains (id,chain_index,url) VALUES (1,0,'https://evil.example/evil.exe');",
    )
    .unwrap();
    drop(conn);
    (dir, profile)
}

fn stdout_of(args: &[&str]) -> String {
    let out = br4n6().args(args).assert().success();
    String::from_utf8(out.get_output().stdout.clone()).unwrap()
}

#[test]
fn investigate_help_exits_zero() {
    br4n6().args(["investigate", "--help"]).assert().success();
}

#[test]
fn default_tier_is_standard() {
    let (_dir, profile) = chrome_profile_with_exe_download();
    let out = stdout_of(&["investigate", profile.to_str().unwrap(), "--format", "text"]);
    // The standard footer points at --deep for the expensive work …
    assert!(
        out.contains("investigate --deep"),
        "default (standard) footer points at --deep: {out}"
    );
    // … and does NOT name bounded freelist/WAL recovery as skipped (standard runs it).
    assert!(
        !out.to_lowercase().contains("freelist"),
        "standard does not skip bounded recovery: {out}"
    );
}

#[test]
fn quick_skips_more_than_standard() {
    let (_dir, profile) = chrome_profile_with_exe_download();
    let p = profile.to_str().unwrap();
    let quick = stdout_of(&["investigate", p, "--quick", "--format", "text"]);
    let standard = stdout_of(&["investigate", p, "--standard", "--format", "text"]);
    assert!(
        quick.to_lowercase().contains("freelist"),
        "quick footer names skipped bounded freelist/WAL recovery: {quick}"
    );
    assert!(
        !standard.to_lowercase().contains("freelist"),
        "standard footer does not (it runs that recovery): {standard}"
    );
}

#[test]
fn deep_is_marked_todo() {
    let (_dir, profile) = chrome_profile_with_exe_download();
    let out = stdout_of(&[
        "investigate",
        profile.to_str().unwrap(),
        "--deep",
        "--format",
        "text",
    ]);
    let lower = out.to_lowercase();
    assert!(
        lower.contains("not yet") || lower.contains("todo"),
        "deep is honestly marked unimplemented: {out}"
    );
    assert!(
        lower.contains("p3b") || lower.contains("p5"),
        "cites deferring phase: {out}"
    );
}

#[test]
fn text_render_shows_three_axes_and_next() {
    let (_dir, profile) = chrome_profile_with_exe_download();
    let out = stdout_of(&["investigate", profile.to_str().unwrap(), "--format", "text"]);
    for label in ["Priority:", "Confidence:", "Interpretation:", "Next:"] {
        assert!(
            out.contains(label),
            "render shows the `{label}` axis/pointer: {out}"
        );
    }
    // The finding's next: pointer is a concrete drill-down command.
    assert!(
        out.contains("br4n6 artifact"),
        "next: points at an artifact command: {out}"
    );
}

#[test]
fn text_render_shows_detection_header() {
    let (_dir, profile) = chrome_profile_with_exe_download();
    let out = stdout_of(&["investigate", profile.to_str().unwrap(), "--format", "text"]);
    assert!(
        out.contains("Detected:"),
        "first line names what was detected: {out}"
    );
}

#[test]
fn footer_always_present_even_with_no_profiles() {
    let empty = TempDir::new().unwrap();
    let out = stdout_of(&[
        "investigate",
        empty.path().to_str().unwrap(),
        "--format",
        "text",
    ]);
    assert!(
        out.contains("Deep recovery"),
        "the skipped-work footer is present even with nothing found: {out}"
    );
}

#[test]
fn piped_output_is_jsonl_with_stderr_notice() {
    let (_dir, profile) = chrome_profile_with_exe_download();
    // No --format on a (piped) stdout → JSONL findings + a loud stderr notice.
    let out = br4n6()
        .args(["investigate", profile.to_str().unwrap()])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("piped output") && stderr.contains("JSONL"),
        "the auto-switch to JSONL is announced on stderr: {stderr}"
    );
    let first = stdout
        .lines()
        .next()
        .expect("at least one JSONL finding line");
    let value: serde_json::Value = serde_json::from_str(first)
        .unwrap_or_else(|e| panic!("piped output line is JSON: {e}: {first}"));
    assert!(
        value.get("priority").is_some(),
        "each JSONL line is a serialized Finding (has priority): {first}"
    );
}

#[test]
fn nonexistent_path_fails_loudly() {
    br4n6()
        .args(["investigate", "/no/such/evidence/path", "--format", "text"])
        .assert()
        .failure();
}

// ---- issen-style resume UX: `-o <DIR>` is the only resume knob (RFC 0001 D2) --

/// Without `-o` investigate is stateless: it writes no resume state or manifest
/// into the evidence root.
#[test]
fn no_output_run_writes_nothing_into_evidence() {
    let (_dir, profile) = chrome_profile_with_exe_download();
    br4n6()
        .args(["investigate", profile.to_str().unwrap(), "--format", "text"])
        .assert()
        .success();
    assert!(
        !profile.join(".br4n6-resume.json").exists(),
        "a stateless run writes no resume file into the evidence"
    );
    assert!(
        !profile.join("manifest.json").exists(),
        "a stateless run writes no manifest into the evidence"
    );
}

/// The opt-in `--checkpoint <PATH>` knob is gone — resume state auto-derives from
/// `-o <DIR>`, never a user-supplied path.
#[test]
fn checkpoint_flag_is_gone() {
    let (_dir, profile) = chrome_profile_with_exe_download();
    br4n6()
        .args([
            "investigate",
            profile.to_str().unwrap(),
            "--checkpoint",
            "/tmp/x.json",
        ])
        .assert()
        .failure();
}

/// `-o <DIR>` writes the summary and a chain-of-custody manifest into DIR with no
/// `--manifest` needed — custody is automatic for a forensic tool.
#[test]
fn output_dir_writes_summary_and_manifest_automatically() {
    let (_dir, profile) = chrome_profile_with_exe_download();
    let outdir = TempDir::new().unwrap();
    br4n6()
        .args([
            "investigate",
            profile.to_str().unwrap(),
            "-o",
            outdir.path().to_str().unwrap(),
            "--format",
            "text",
        ])
        .assert()
        .success();
    let manifest = outdir.path().join("manifest.json");
    assert!(
        manifest.is_file(),
        "manifest is written automatically under -o (no --manifest needed)"
    );
    let man = std::fs::read_to_string(&manifest).unwrap();
    assert!(
        man.contains("detection_basis"),
        "the auto-manifest carries the detection basis: {man}"
    );
    let summary = outdir.path().join("summary.txt");
    assert!(summary.is_file(), "the summary is written under -o");
    let text = std::fs::read_to_string(&summary).unwrap();
    assert!(
        text.contains("Detected:"),
        "the summary file carries the render: {text}"
    );
}

/// A second run over the same evidence with the same `-o` resumes the completed
/// units and prints the issen-style `Resumed: N …` line on stderr.
#[test]
fn second_run_resumes_and_prints_resumed_line() {
    let (_dir, profile) = chrome_profile_with_exe_download();
    let outdir = TempDir::new().unwrap();
    let o = outdir.path().to_str().unwrap();
    let p = profile.to_str().unwrap();
    br4n6()
        .args(["investigate", p, "-o", o, "--format", "text"])
        .assert()
        .success();
    let out = br4n6()
        .args(["investigate", p, "-o", o, "--format", "text"])
        .assert()
        .success();
    let err = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        err.contains("Resumed:") && err.contains("skipped"),
        "the resumed run prints the issen-style resume line: {err}"
    );
}

/// `--restart` forces a fresh run — the existing resume state is ignored, so no
/// `Resumed:` line is printed.
#[test]
fn restart_forces_fresh_no_resume_line() {
    let (_dir, profile) = chrome_profile_with_exe_download();
    let outdir = TempDir::new().unwrap();
    let o = outdir.path().to_str().unwrap();
    let p = profile.to_str().unwrap();
    br4n6()
        .args(["investigate", p, "-o", o, "--format", "text"])
        .assert()
        .success();
    let out = br4n6()
        .args(["investigate", p, "-o", o, "--restart", "--format", "text"])
        .assert()
        .success();
    let err = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        !err.contains("Resumed:"),
        "--restart never resumes prior state: {err}"
    );
}

/// Different evidence pointed at the same `-o <DIR>` must NOT silently resume the
/// other evidence's units — the fingerprint mismatch restarts clean.
#[test]
fn different_evidence_same_output_does_not_silently_resume() {
    let (_dir_a, profile_a) = chrome_profile_with_exe_download();
    let (_dir_b, profile_b) = chrome_profile_with_exe_download();
    let outdir = TempDir::new().unwrap();
    let o = outdir.path().to_str().unwrap();
    br4n6()
        .args([
            "investigate",
            profile_a.to_str().unwrap(),
            "-o",
            o,
            "--format",
            "text",
        ])
        .assert()
        .success();
    let out = br4n6()
        .args([
            "investigate",
            profile_b.to_str().unwrap(),
            "-o",
            o,
            "--format",
            "text",
        ])
        .assert()
        .success();
    let err = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        !err.contains("Resumed:"),
        "a different evidence root must not resume another's state: {err}"
    );
}

/// `--manifest <PATH>` overrides the automatic `-o` manifest location: the
/// custody file lands at the override, not inside DIR.
#[test]
fn manifest_flag_overrides_output_dir_location() {
    let (_dir, profile) = chrome_profile_with_exe_download();
    let outdir = TempDir::new().unwrap();
    let elsewhere = TempDir::new().unwrap();
    let manifest = elsewhere.path().join("custody.json");
    br4n6()
        .args([
            "investigate",
            profile.to_str().unwrap(),
            "-o",
            outdir.path().to_str().unwrap(),
            "--manifest",
            manifest.to_str().unwrap(),
            "--format",
            "text",
        ])
        .assert()
        .success();
    assert!(
        manifest.is_file(),
        "--manifest writes the custody file at the override location"
    );
    assert!(
        !outdir.path().join("manifest.json").is_file(),
        "the override replaces the default -o manifest path (not written twice)"
    );
}
