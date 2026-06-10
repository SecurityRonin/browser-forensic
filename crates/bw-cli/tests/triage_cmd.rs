#![allow(clippy::unwrap_used, clippy::expect_used)]
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

#[test]
fn triage_subcommand_exists() {
    let mut cmd = Command::cargo_bin("bw").expect("bw binary");
    cmd.arg("triage").arg("--help");
    cmd.assert().success();
}

#[test]
fn triage_on_empty_home_succeeds() {
    let home = TempDir::new().expect("tempdir");
    let mut cmd = Command::cargo_bin("bw").expect("bw binary");
    cmd.arg("triage").arg("--home").arg(home.path());
    cmd.assert().success();
}

#[test]
fn triage_with_chrome_profile_finds_events() {
    let home = TempDir::new().expect("tempdir");
    let chrome_default = home
        .path()
        .join("Library/Application Support/Google/Chrome/Default");
    fs::create_dir_all(&chrome_default).expect("mkdir");

    let conn = rusqlite::Connection::open(chrome_default.join("History")).expect("open");
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
         INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 1, 13300000000000000);
         INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 0);"
    ).expect("setup");
    drop(conn);

    let mut cmd = Command::cargo_bin("bw").expect("bw binary");
    cmd.arg("triage")
        .arg("--home")
        .arg(home.path())
        .arg("--format")
        .arg("jsonl");
    let output = cmd.output().expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "triage should produce output");
}
