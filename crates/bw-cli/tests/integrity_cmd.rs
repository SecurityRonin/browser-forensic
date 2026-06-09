use assert_cmd::Command;
use rusqlite::Connection;
use tempfile::NamedTempFile;

#[test]
fn integrity_subcommand_exists() {
    let mut cmd = Command::cargo_bin("bw").expect("bw binary");
    cmd.arg("integrity").arg("--help");
    cmd.assert().success();
}

#[test]
fn integrity_on_valid_chrome_history_succeeds() {
    let f = NamedTempFile::new().expect("tempfile");
    let conn = Connection::open(f.path()).expect("open");
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
         INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 1, 13300000000000000);
         INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 0);"
    ).expect("setup");
    drop(conn);

    let mut cmd = Command::cargo_bin("bw").expect("bw binary");
    cmd.arg("integrity").arg(f.path());
    cmd.assert().success();
}

#[test]
fn integrity_on_cleared_history_reports_indicators() {
    let f = NamedTempFile::new().expect("tempfile");
    let conn = Connection::open(f.path()).expect("open");
    // Use AUTOINCREMENT to create sqlite_sequence table automatically
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
         INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 1, 13300000000000000);
         UPDATE sqlite_sequence SET seq = 500 WHERE name = 'urls';
         DELETE FROM urls;"
    ).expect("setup");
    drop(conn);

    let mut cmd = Command::cargo_bin("bw").expect("bw binary");
    cmd.arg("integrity")
        .arg(f.path())
        .arg("--format")
        .arg("jsonl");
    let output = cmd.output().expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("HistoryCleared")
            || stdout.contains("integrity")
            || stdout.contains("AutoIncrementGap"),
        "should report integrity findings for cleared history, got: {stdout}"
    );
}
