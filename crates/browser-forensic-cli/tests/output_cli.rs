#![allow(clippy::unwrap_used, clippy::expect_used)]
//! RFC 0001 Phase P2 — the output engine wired into real commands, driven
//! end-to-end through the `br4n6` binary. `assert_cmd` runs the child with a
//! piped (non-TTY) stdout, so these exercise the *pipe* branch of the auto-format
//! decision: a bare `--format`-less run switches to JSONL and announces it once
//! on stderr, while an explicit `--format` stays silent.

use std::path::PathBuf;

use assert_cmd::Command;
use rusqlite::Connection;
use tempfile::TempDir;

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

/// A Chrome `History` with one blocklistable host, returned as `(TempDir, home)`.
fn ioc_history() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let profile_dir = dir.path().join("google-chrome").join("Default");
    std::fs::create_dir_all(&profile_dir).unwrap();
    let history_path = profile_dir.join("History");
    let conn = Connection::open(&history_path).unwrap();
    conn.execute_batch(
        "CREATE TABLE urls (
            id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT DEFAULT '',
            visit_count INTEGER DEFAULT 0 NOT NULL, last_visit_time INTEGER NOT NULL);
        INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES
          ('https://tracker.evil.com/beacon', 'Tracker', 1, 13327628000000000),
          ('https://good.example.org/news', 'Good News', 1, 13327629000000000);",
    )
    .unwrap();
    (dir, profile_dir)
}

// ---- isatty auto-format + loud stderr notice ----

#[test]
fn find_piped_default_switches_to_jsonl_and_notices() {
    let (_dir, home) = ioc_history();
    let out = br4n6()
        .args(["find", "Tracker", home.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    // Default-on-a-pipe is machine JSONL...
    let first = stdout.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    serde_json::from_str::<serde_json::Value>(first).expect("piped default must be JSONL");
    assert!(
        stdout.contains("tracker.evil.com"),
        "the matched row must be present"
    );
    // ...and the schema switch is announced loudly, exactly once.
    assert!(
        stderr.contains("piped output"),
        "missing pipe notice: {stderr}"
    );
    assert!(stderr.contains("JSONL"), "notice must name JSONL: {stderr}");
    assert_eq!(
        stderr.matches("[notice]").count(),
        1,
        "notice must fire once"
    );
}

#[test]
fn find_explicit_format_suppresses_the_notice() {
    let (_dir, home) = ioc_history();
    let out = br4n6()
        .args([
            "find",
            "Tracker",
            home.to_str().unwrap(),
            "--format",
            "jsonl",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        !stderr.contains("[notice]"),
        "an explicit --format must NOT print the auto-switch notice: {stderr}"
    );
}

#[test]
fn find_terms_file_piped_default_notices() {
    let (_dir, home) = ioc_history();
    let list = home.join("blocklist.txt");
    std::fs::write(&list, "evil.com\n").unwrap();
    let out = br4n6()
        .args([
            "find",
            home.to_str().unwrap(),
            "--terms-file",
            list.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("piped output"),
        "find --terms-file missing pipe notice: {stderr}"
    );
}

// ---- negative-result discipline ----

#[test]
fn find_no_hits_states_where_it_looked_and_what_it_skipped() {
    let (_dir, home) = ioc_history();
    let out = br4n6()
        .args([
            "find",
            "no-such-term-zzz",
            home.to_str().unwrap(),
            "--format",
            "text",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stdout.trim().is_empty(),
        "no hits => empty stdout, got: {stdout}"
    );
    assert!(
        stderr.contains("no hits in"),
        "an empty result must prove it looked: {stderr}"
    );
    assert!(
        stderr.contains("skipped:"),
        "must name what it did not search: {stderr}"
    );
}

// ---- actionable SQLite-open errors ----

#[test]
fn corrupt_history_open_suggests_the_recovery_command() {
    let dir = TempDir::new().unwrap();
    let profile = dir.path().join("Google").join("Chrome").join("Default");
    std::fs::create_dir_all(&profile).unwrap();
    let history = profile.join("History");
    // Not a SQLite database — opening/reading it fails with SQLITE_NOTADB.
    std::fs::write(&history, b"this is definitely not a sqlite database file").unwrap();

    let out = br4n6()
        .args(["artifact", "history", history.to_str().unwrap()])
        .assert()
        .failure()
        .get_output()
        .clone();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("br4n6 recover"),
        "must suggest the recover orchestrator: {stderr}"
    );
    let low = stderr.to_ascii_lowercase();
    assert!(
        low.contains("corrupt") || low.contains("lock"),
        "must name the fault: {stderr}"
    );
    assert!(
        low.contains("not a database"),
        "must surface the underlying error: {stderr}"
    );
}

// ---- markdown-clean table adoption ----

#[test]
fn artifact_list_renders_a_markdown_table_without_box_drawing() {
    let out = br4n6().args(["artifact", "--list"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains('|'),
        "artifact --list should be a pipe-delimited table"
    );
    assert!(stdout.contains("NAME") && stdout.contains("BROWSER") && stdout.contains("RECORDS"));
    for c in ['┌', '┐', '└', '┘', '│', '─', '├', '┤', '┬', '┴', '┼'] {
        assert!(
            !stdout.contains(c),
            "box-drawing char {c:?} must never appear"
        );
    }
}
