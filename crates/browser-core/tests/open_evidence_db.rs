//! Contract tests for the read-only, WAL-safe evidence SQLite opener.
//!
//! These prove that `browser_core::sqlite::open_evidence_db`:
//!   (a) honors an uncheckpointed `-wal` (does NOT use `immutable=1`, which would
//!       silently drop the newest rows);
//!   (b) never mutates the original evidence file (no checkpoint on close);
//!   (c) hands back a connection through which writes fail.

use std::fs;
use std::time::Duration;

use rusqlite::{params, Connection, OpenFlags};
use tempfile::TempDir;

/// Build a Chromium-style `History` DB whose newest row lives ONLY in an
/// uncheckpointed `-wal` sidecar.
///
/// Returns `(dir, db_path, writer)`. The `dir` keeps the files on disk; the
/// `writer` connection is **kept open** so SQLite does not checkpoint-and-delete
/// the `-wal` on a last-connection close — exactly the live-acquisition scenario
/// where evidence is copied while a process still holds the DB. All three must
/// be kept alive for the duration of the test.
///
/// We force WAL mode, insert a "checkpointed" row, manually checkpoint it into
/// the main file, then insert a second "wal-only" row WITHOUT checkpointing. The
/// second row therefore exists only in `History-wal`.
fn build_db_with_populated_wal() -> (TempDir, std::path::PathBuf, Connection) {
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("History");

    let writer = Connection::open(&db_path).expect("open rw");
    writer
        .pragma_update(None, "journal_mode", "WAL")
        .expect("set wal");
    writer
        .execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, last_visit_time INTEGER);",
        )
        .expect("schema");
    writer
        .execute(
            "INSERT INTO urls (url, last_visit_time) VALUES (?1, ?2)",
            params!["https://checkpointed.example", 1_i64],
        )
        .expect("insert checkpointed");
    // Flush the first row into the main DB file.
    writer
        .pragma_update(None, "wal_checkpoint", "TRUNCATE")
        .expect("checkpoint");

    // This row stays in the -wal only (no checkpoint after it).
    writer
        .execute(
            "INSERT INTO urls (url, last_visit_time) VALUES (?1, ?2)",
            params!["https://wal-only.example", 2_i64],
        )
        .expect("insert wal-only");

    // Sanity: the -wal sidecar must exist and be non-empty while `writer` lives.
    let wal_path = wal_sidecar(&db_path);
    let wal_len = fs::metadata(&wal_path).expect("wal exists").len();
    assert!(wal_len > 0, "fixture must leave a populated -wal");

    (dir, db_path, writer)
}

fn wal_sidecar(db_path: &std::path::Path) -> std::path::PathBuf {
    let mut s = db_path.as_os_str().to_os_string();
    s.push("-wal");
    std::path::PathBuf::from(s)
}

#[test]
fn wal_only_row_is_visible_not_dropped() {
    let (_dir, db_path, _writer) = build_db_with_populated_wal();

    let db = browser_core::sqlite::open_evidence_db(&db_path).expect("open evidence db");

    let urls: Vec<String> = db
        .conn
        .prepare("SELECT url FROM urls ORDER BY id")
        .expect("prepare")
        .query_map([], |r| r.get::<_, String>(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect();

    // If the helper used immutable=1, the WAL would be ignored and this row
    // would be missing — the exact silent-data-loss bug we are guarding against.
    assert!(
        urls.iter().any(|u| u == "https://wal-only.example"),
        "the uncheckpointed WAL row must be visible; got {urls:?}"
    );
    assert!(
        urls.iter().any(|u| u == "https://checkpointed.example"),
        "the checkpointed row must also be visible; got {urls:?}"
    );
}

#[test]
fn original_file_is_not_mutated() {
    let (_dir, db_path, _writer) = build_db_with_populated_wal();
    let wal_path = wal_sidecar(&db_path);

    let db_before = fs::read(&db_path).expect("read db before");
    let wal_before = fs::read(&wal_path).expect("read wal before");
    let mtime_before = fs::metadata(&db_path)
        .expect("meta")
        .modified()
        .expect("mtime");

    {
        let db = browser_core::sqlite::open_evidence_db(&db_path).expect("open evidence db");
        // Read everything, then drop the connection — a read-write open would
        // checkpoint here, rewriting the main DB and truncating the -wal.
        let _n: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM urls", [], |r| r.get(0))
            .expect("count");
    }

    // Give the filesystem a beat in case of lazy mtime updates.
    std::thread::sleep(Duration::from_millis(10));

    let db_after = fs::read(&db_path).expect("read db after");
    let wal_after = fs::read(&wal_path).expect("read wal after");
    let mtime_after = fs::metadata(&db_path)
        .expect("meta")
        .modified()
        .expect("mtime");

    assert_eq!(db_before, db_after, "main DB bytes must be unchanged");
    assert_eq!(wal_before, wal_after, "-wal bytes must be unchanged");
    assert_eq!(mtime_before, mtime_after, "main DB mtime must be unchanged");
}

#[test]
fn writes_through_connection_fail() {
    let (_dir, db_path, _writer) = build_db_with_populated_wal();

    let db = browser_core::sqlite::open_evidence_db(&db_path).expect("open evidence db");
    let res = db.conn.execute(
        "INSERT INTO urls (url, last_visit_time) VALUES (?1, ?2)",
        params!["https://should-fail.example", 9_i64],
    );
    assert!(
        res.is_err(),
        "writing through an evidence connection must fail (read-only)"
    );
}

#[test]
fn provenance_records_snapshot_when_wal_present() {
    let (_dir, db_path, _writer) = build_db_with_populated_wal();

    let db = browser_core::sqlite::open_evidence_db(&db_path).expect("open evidence db");

    // A -wal was present, so the helper must have made a working-copy snapshot
    // and surfaced full provenance.
    assert_eq!(db.provenance.original_path, db_path);
    let snap = db
        .provenance
        .snapshot_path
        .as_ref()
        .expect("snapshot path recorded when -wal present");
    assert_ne!(snap, &db_path, "snapshot must be a copy, not the original");
    let sha = db
        .provenance
        .sha256
        .as_ref()
        .expect("sha256 recorded when snapshot made");
    assert_eq!(sha.len(), 64, "sha256 hex digest is 64 chars");
    assert!(db.provenance.copied_at.is_some(), "copied_at recorded");
}

#[test]
fn no_wal_opens_original_without_snapshot() {
    // A DB with no -wal opens copy-free (immutable on the original is safe).
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("History");
    let conn = Connection::open_with_flags(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )
    .expect("create");
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL);
         INSERT INTO urls (url) VALUES ('https://nowal.example');",
    )
    .expect("seed");
    drop(conn);
    // Ensure there is genuinely no -wal sidecar.
    let _ = fs::remove_file(wal_sidecar(&db_path));

    let db = browser_core::sqlite::open_evidence_db(&db_path).expect("open evidence db");
    let url: String = db
        .conn
        .query_row("SELECT url FROM urls", [], |r| r.get(0))
        .expect("read");
    assert_eq!(url, "https://nowal.example");
    assert!(
        db.provenance.snapshot_path.is_none(),
        "no -wal => no snapshot copy"
    );
}
