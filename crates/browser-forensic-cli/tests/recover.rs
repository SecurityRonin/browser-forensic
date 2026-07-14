#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end coverage for `br4n6 recover` (RFC 0001 Phase P5b): the single
//! orchestrator verb that runs ALL applicable recovery over the evidence and
//! ranks the results — the examiner picks no submode (resolved-decision #2).
//! Exercised against the `br4n6` binary over profile / database / memory
//! fixtures.

use std::io::Write as _;

use assert_cmd::Command;
use rusqlite::Connection;
use std::path::PathBuf;
use tempfile::{NamedTempFile, TempDir};

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

/// A profile directory that yields findings across MULTIPLE recovery kinds:
/// a tampered `History` (visit-id gap 1 → 50, consistent with deleted visits →
/// tamper indicators) plus a `Network Persistent State` naming a contacted host
/// that survives a history clear (→ a recovered-domain finding). Returns
/// `(TempDir, profile_dir)`.
fn profile_with_multiple_recovery_kinds() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let profile = dir.path().join("google-chrome").join("Default");
    std::fs::create_dir_all(&profile).unwrap();

    let history = profile.join("History");
    let conn = Connection::open(&history).unwrap();
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT,
            visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL,
            visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
         INSERT INTO urls VALUES (1,'https://a.example','A',1,13300000000000000);
         INSERT INTO visits VALUES (1,1,13300000000000000,0,0);
         INSERT INTO visits VALUES (50,1,13300000001000000,0,0);",
    )
    .unwrap();
    conn.close().ok();

    // A recovered-domain source: a host that survives a history clear.
    std::fs::write(
        profile.join("Network Persistent State"),
        r#"{"net":{"http_server_properties":{"servers":[
            {"server":"https://recovered-tracker.example:443","supports_spdy":true}]}}}"#,
    )
    .unwrap();

    (dir, profile)
}

fn stdout_of(args: &[&str]) -> String {
    let out = br4n6().args(args).assert().success();
    String::from_utf8(out.get_output().stdout.clone()).unwrap()
}

#[test]
fn recover_help_exits_zero() {
    br4n6().args(["recover", "--help"]).assert().success();
}

#[test]
fn recover_help_lists_recovery_kinds_and_points_at_specialists() {
    // Discoverability (resolved-decision #2): help names the underlying recovery
    // kinds and points an expert at the `artifact`/specialist commands so a
    // targeted single run is still possible — but the default needs no submode.
    let help = stdout_of(&["recover", "--help"]);
    let low = help.to_lowercase();
    for kind in ["deleted", "cache", "domain", "bookmark", "tamper", "memory"] {
        assert!(low.contains(kind), "recover --help names `{kind}`: {help}");
    }
    assert!(
        low.contains("artifact"),
        "recover --help points at the artifact/specialist commands: {help}"
    );
}

#[test]
fn recover_over_profile_spans_multiple_kinds_no_mode_flag() {
    let (_dir, profile) = profile_with_multiple_recovery_kinds();
    // No submode flag — one call runs everything applicable.
    let out = stdout_of(&["recover", profile.to_str().unwrap(), "--format", "text"]);
    // Recovered-domain kind present …
    assert!(
        out.contains("recovered-tracker.example"),
        "recovers the contacted domain: {out}"
    );
    // … and the tamper kind present (a distinct recovery kind).
    let low = out.to_lowercase();
    assert!(
        low.contains("tamper") || low.contains("clearing") || low.contains("innocent alternative"),
        "surfaces tamper/anti-forensic indicators too: {out}"
    );
    // The three court-safe axes render.
    for label in ["Priority:", "Confidence:", "Interpretation:"] {
        assert!(
            out.contains(label),
            "render shows the `{label}` axis: {out}"
        );
    }
}

#[test]
fn recover_items_are_not_live() {
    let (_dir, profile) = profile_with_multiple_recovery_kinds();
    let out = stdout_of(&["recover", profile.to_str().unwrap(), "--format", "text"]);
    let low = out.to_lowercase();
    // Provenance state on recovered items is deleted / inferred / carved — never
    // asserted as a live, deliberate user act.
    assert!(
        low.contains("deleted") || low.contains("inferred") || low.contains("carved"),
        "recovered items carry an honest non-live state: {out}"
    );
}

#[test]
fn recover_profile_footer_names_memory_and_whole_image_not_run() {
    let (_dir, profile) = profile_with_multiple_recovery_kinds();
    let out = stdout_of(&["recover", profile.to_str().unwrap(), "--format", "text"]);
    let low = out.to_lowercase();
    assert!(
        low.contains("memory") && low.contains("not"),
        "footer states memory was NOT scanned over a profile: {out}"
    );
    assert!(
        low.contains("whole-image") || low.contains("whole image") || low.contains("carving"),
        "footer states whole-image carving was NOT run: {out}"
    );
}

#[test]
fn recover_piped_output_is_jsonl_with_stderr_notice() {
    let (_dir, profile) = profile_with_multiple_recovery_kinds();
    let out = br4n6()
        .args(["recover", profile.to_str().unwrap()])
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
        "each JSONL line is a serialized Finding: {first}"
    );
}

#[test]
fn recover_over_memory_image_carves_ram_and_names_profile_not_run() {
    // A readable buffer with a URL but no OS/process structure: the structured
    // memory carve degrades to a byte-scan (loud on stderr) and still surfaces
    // the URL — auto-selected as a memory-image scope purely from the PATH.
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"garbage https://ram-only.example/found more garbage")
        .unwrap();
    let out = br4n6()
        .args(["recover", "--format", "text", f.path().to_str().unwrap()])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("ram-only.example"),
        "memory scope surfaces the carved URL: {stdout}"
    );
    let low = stdout.to_lowercase();
    assert!(
        low.contains("profile") && low.contains("not"),
        "memory-image footer names profile recovery NOT run: {stdout}"
    );
}

/// Bytes of a Chromium `urls`-shaped SQLite carrying `url`, for planting in the
/// unallocated space of a raw disk image so the whole-image carve recovers it.
fn history_db_bytes(url: &str) -> Vec<u8> {
    let f = NamedTempFile::new().unwrap();
    {
        let conn = Connection::open(f.path()).unwrap();
        conn.execute_batch(
            "PRAGMA auto_vacuum = NONE;
             CREATE TABLE urls(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR,
                 visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER);",
        )
        .unwrap();
        for i in 0..8 {
            conn.execute(
                "INSERT INTO urls VALUES (?1,?2,?3,?4,?5,?6,0)",
                rusqlite::params![
                    i,
                    format!("https://filler{i}.example/path"),
                    format!("Filler {i}"),
                    i,
                    i,
                    13_300_000_000_000_000i64 + i64::from(i)
                ],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO urls VALUES (100,?1,?2,5,2,?3,0)",
            rusqlite::params![url, "Planted", 13_300_000_000_000_000i64],
        )
        .unwrap();
    }
    std::fs::read(f.path()).unwrap()
}

/// A raw disk image (MBR boot signature at byte 510) with a planted history DB in
/// unallocated space.
fn planted_disk_image(url: &str, db_off: usize) -> Vec<u8> {
    let db = history_db_bytes(url);
    let mut buf = vec![0u8; (db_off + db.len() + 4096).max(512)];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    buf[510] = 0x55;
    buf[511] = 0xAA;
    buf[db_off..db_off + db.len()].copy_from_slice(&db);
    buf
}

#[test]
fn recover_over_whole_disk_image_carves_planted_url_and_footer_says_ran() {
    // A raw disk image (partition-table signature) with a deleted history DB in
    // unallocated space: recover auto-selects the whole-image scope purely from
    // the PATH signature and surfaces the planted URL as a Carved artifact.
    let url = "https://planted.example/deleted-secret";
    let dir = TempDir::new().unwrap();
    let img = dir.path().join("case.dd");
    std::fs::write(&img, planted_disk_image(url, 2048)).unwrap();

    // JSONL is the byte-faithful, uncapped render — the wiring proof.
    let jsonl = stdout_of(&["recover", img.to_str().unwrap(), "--format", "jsonl"]);
    let hit = jsonl
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| {
            v.get("evidence")
                .and_then(|e| e.as_str())
                .is_some_and(|e| e.contains(url))
        })
        .unwrap_or_else(|| panic!("planted URL not surfaced as a carved finding: {jsonl}"));
    assert_eq!(
        hit.get("provenance")
            .and_then(|p| p.get("state"))
            .and_then(|s| s.as_str())
            .map(str::to_lowercase)
            .as_deref(),
        Some("carved"),
        "the recovered artifact carries a Carved state: {hit}"
    );

    // The human render's footer states the whole-image carve RAN.
    let text = stdout_of(&["recover", img.to_str().unwrap(), "--format", "text"]);
    let low = text.to_lowercase();
    assert!(
        low.contains("whole-image") && low.contains("ran"),
        "the footer states whole-image carving RAN: {text}"
    );
    assert!(
        !low.contains("whole-image carving was not run"),
        "the whole-image footer must not claim the carve was skipped: {text}"
    );
}

#[test]
fn recover_whole_image_flag_forces_scope_over_ambiguous_dump() {
    // A raw dump with no partition/container signature is ambiguous; --whole-image
    // opts it into the whole-image carve, and the footer reflects the carve RAN.
    let url = "https://forced.example/carved";
    let dir = TempDir::new().unwrap();
    let img = dir.path().join("ambiguous.raw");
    // No MBR signature here — only the explicit flag routes it to whole-image.
    let db = history_db_bytes(url);
    let mut buf = vec![7u8; 1024];
    buf.extend_from_slice(&db);
    buf.extend_from_slice(&[9u8; 4096]);
    std::fs::write(&img, &buf).unwrap();

    let jsonl = stdout_of(&[
        "recover",
        img.to_str().unwrap(),
        "--whole-image",
        "--format",
        "jsonl",
    ]);
    assert!(
        jsonl.contains(url),
        "the forced whole-image carve surfaces the planted URL: {jsonl}"
    );

    let text = stdout_of(&[
        "recover",
        img.to_str().unwrap(),
        "--whole-image",
        "--format",
        "text",
    ]);
    let low = text.to_lowercase();
    assert!(
        low.contains("whole-image") && low.contains("ran"),
        "--whole-image footer states the carve RAN: {text}"
    );
}

#[test]
fn recover_nonexistent_path_fails_loudly() {
    br4n6()
        .args(["recover", "/no/such/evidence/path", "--format", "text"])
        .assert()
        .failure();
}
