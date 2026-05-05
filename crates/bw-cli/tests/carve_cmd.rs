use assert_cmd::Command;
use rusqlite::Connection;
use tempfile::NamedTempFile;

#[test]
fn carve_subcommand_exists() {
    let mut cmd = Command::cargo_bin("bw").expect("bw binary");
    cmd.arg("carve").arg("--help");
    cmd.assert().success();
}

#[test]
fn carve_on_valid_db_succeeds() {
    let f = NamedTempFile::new().expect("tempfile");
    let conn = Connection::open(f.path()).expect("open");
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);
         INSERT INTO urls VALUES (1, 'https://example.com');"
    ).expect("setup");
    drop(conn);

    let mut cmd = Command::cargo_bin("bw").expect("bw binary");
    cmd.arg("carve").arg(f.path());
    cmd.assert().success();
}

#[test]
fn carve_jsonl_output_is_valid_json() {
    let f = NamedTempFile::new().expect("tempfile");
    let conn = Connection::open(f.path()).expect("open");
    conn.execute_batch("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);").expect("setup");
    drop(conn);

    let mut cmd = Command::cargo_bin("bw").expect("bw binary");
    cmd.arg("carve").arg(f.path()).arg("--format").arg("jsonl");
    let output = cmd.output().expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if !line.is_empty() {
            let _: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("Invalid JSON line: {line:?}, error: {e}"));
        }
    }
}
