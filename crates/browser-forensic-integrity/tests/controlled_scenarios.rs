//! Tier-2 controlled-scenario validation for the tampering/clearing indicators.
//!
//! Ground truth is *constructed*: a real SQLite database is built with the real
//! engine (rusqlite / the `sqlite3` CLI), a baseline is recorded, then a specific
//! change is applied. The engine is the independent actor; we chose the scenario,
//! so this is tier 2 (not tier 1 real-world data). Each test asserts the detector
//! FIRES on the changed copy and stays SILENT on the pristine one — the honest
//! fires/silent oracle. Framing is intact: every indicator carries an innocent
//! alternative (asserted separately in the crate's unit tests).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::Command;

use browser_forensic_core::BrowserFamily;
use browser_forensic_integrity::sqlite_header::parse_header;
use browser_forensic_integrity::{
    check_header_anomalies, check_history_integrity, check_page_state, IntegrityIndicator,
};
use rusqlite::Connection;
use tempfile::tempdir;

fn chrome_schema(conn: &Connection) {
    conn.execute_batch(
        "PRAGMA auto_vacuum=NONE; PRAGMA secure_delete=OFF;
         CREATE TABLE urls (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL,
             title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
         CREATE TABLE visits (id INTEGER PRIMARY KEY AUTOINCREMENT, url INTEGER NOT NULL,
             visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);",
    )
    .unwrap();
}

/// A pristine Chromium history DB: sequential ids, in-the-past monotonic times,
/// summary values consistent with the visit rows.
fn build_pristine(path: &Path) {
    let conn = Connection::open(path).unwrap();
    chrome_schema(&conn);
    for i in 1..=20i64 {
        let t = 13_300_000_000_000_000 + i * 1_000_000;
        conn.execute(
            "INSERT INTO urls(id,url,title,visit_count,last_visit_time) VALUES (?1,?2,?3,1,?4)",
            rusqlite::params![i, format!("https://ex{i}.example/"), format!("T{i}"), t],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO visits(id,url,visit_time,from_visit,transition) VALUES (?1,?2,?3,0,0)",
            rusqlite::params![i, i, t],
        )
        .unwrap();
    }
    conn.close().ok();
}

fn chromium_indicators(path: &Path) -> Vec<IntegrityIndicator> {
    let mut v = Vec::new();
    v.extend(check_page_state(path).unwrap_or_default());
    v.extend(check_header_anomalies(path).unwrap_or_default());
    v.extend(check_history_integrity(path, BrowserFamily::Chromium).unwrap_or_default());
    v
}

/// A larger history DB whose rows span many pages, so deleting a swathe frees
/// whole pages onto the freelist (not merely in-page freeblocks).
fn build_page_spanning(path: &Path, n: i64) {
    let conn = Connection::open(path).unwrap();
    chrome_schema(&conn);
    for i in 1..=n {
        let t = 13_300_000_000_000_000 + i * 1_000_000;
        conn.execute(
            "INSERT INTO urls(id,url,title,visit_count,last_visit_time) VALUES (?1,?2,?3,1,?4)",
            rusqlite::params![
                i,
                format!("https://ex{i}.example/{}", "p".repeat(220)),
                format!("Title {i}"),
                t
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO visits(id,url,visit_time,from_visit,transition) VALUES (?1,?2,?3,0,0)",
            rusqlite::params![i, i, t],
        )
        .unwrap();
    }
    conn.close().ok();
}

#[test]
fn scenario_a_delete_produces_gap_and_freelist_growth() {
    let dir = tempdir().unwrap();
    let pristine = dir.path().join("pristine");
    build_page_spanning(&pristine, 300);
    // Pristine: no id gap, no freelist growth.
    let base = chromium_indicators(&pristine);
    assert!(
        !base
            .iter()
            .any(|i| matches!(i, IntegrityIndicator::VisitIdGap { .. })),
        "pristine must have no id gap: {base:?}"
    );
    assert!(
        !base
            .iter()
            .any(|i| matches!(i, IntegrityIndicator::FreelistGrowth { .. })),
        "pristine must have an empty freelist: {base:?}"
    );

    // Tamper: delete a large swathe of middle rows (no VACUUM).
    let tampered = dir.path().join("tampered");
    std::fs::copy(&pristine, &tampered).unwrap();
    {
        let conn = Connection::open(&tampered).unwrap();
        conn.execute("DELETE FROM visits WHERE id BETWEEN 50 AND 250", [])
            .unwrap();
        conn.execute("DELETE FROM urls WHERE id BETWEEN 50 AND 250", [])
            .unwrap();
        conn.close().ok();
    }
    let after = chromium_indicators(&tampered);
    assert!(
        after
            .iter()
            .any(|i| matches!(i, IntegrityIndicator::VisitIdGap { .. })),
        "deleting middle rows should leave an id gap: {after:?}"
    );
    assert!(
        after
            .iter()
            .any(|i| matches!(i, IntegrityIndicator::FreelistGrowth { free_pages, .. } if *free_pages > 0)),
        "a large deletion (no VACUUM) should free pages onto the freelist: {after:?}"
    );
}

#[test]
fn scenario_b_future_and_out_of_order_timestamps() {
    let dir = tempdir().unwrap();
    let pristine = dir.path().join("pristine");
    build_pristine(&pristine);
    let base = chromium_indicators(&pristine);
    assert!(
        !base
            .iter()
            .any(|i| matches!(i, IntegrityIndicator::TimestampInFuture { .. })),
        "pristine (past timestamps) must not fire future: {base:?}"
    );

    // Future timestamp: set one visit far in the future.
    let future = dir.path().join("future");
    std::fs::copy(&pristine, &future).unwrap();
    {
        let conn = Connection::open(&future).unwrap();
        conn.execute(
            "UPDATE visits SET visit_time=16000000000000000 WHERE id=10",
            [],
        )
        .unwrap();
        conn.close().ok();
    }
    assert!(
        chromium_indicators(&future)
            .iter()
            .any(|i| matches!(i, IntegrityIndicator::TimestampInFuture { .. })),
        "a future visit_time should fire TimestampInFuture"
    );

    // Out-of-order timestamp: a later id with an earlier time.
    let ooo = dir.path().join("ooo");
    std::fs::copy(&pristine, &ooo).unwrap();
    {
        let conn = Connection::open(&ooo).unwrap();
        conn.execute(
            "UPDATE visits SET visit_time=10000000000000000 WHERE id=15",
            [],
        )
        .unwrap();
        conn.close().ok();
    }
    assert!(
        chromium_indicators(&ooo)
            .iter()
            .any(|i| matches!(i, IntegrityIndicator::TimestampNonMonotonic { .. })),
        "an earlier time on a later id should fire TimestampNonMonotonic"
    );
}

#[test]
fn scenario_c_change_counter_bumps_under_real_sqlite() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("History");
    build_pristine(&db);

    let before = parse_header(&std::fs::read(&db).unwrap()).unwrap();
    // A pristine modern-SQLite DB keeps the fields in sync ⇒ no mismatch fires.
    assert!(
        !check_header_anomalies(&db)
            .unwrap()
            .iter()
            .any(|i| matches!(i, IntegrityIndicator::ChangeCounterMismatch { .. })),
        "pristine header should not fire a change-counter mismatch"
    );

    // Independent actor: edit through a fresh SQLite connection and confirm the
    // change counter advances (the header parser reads it correctly).
    {
        let conn = Connection::open(&db).unwrap();
        conn.execute("UPDATE urls SET title='edited' WHERE id=1", [])
            .unwrap();
        conn.close().ok();
    }
    let after = parse_header(&std::fs::read(&db).unwrap()).unwrap();
    assert!(
        after.change_counter > before.change_counter,
        "a committed write must bump the change counter ({} -> {})",
        before.change_counter,
        after.change_counter
    );
    // SQLite keeps version-valid-for in sync, so still no mismatch — the mismatch
    // signal is for edits by tools that DON'T maintain the field.
    assert_eq!(after.change_counter, after.version_valid_for);
}

#[test]
fn scenario_c_header_edit_by_foreign_tool_fires_mismatch() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("History");
    build_pristine(&db);
    // Simulate a writer that does not maintain version-valid-for (offset 92).
    let mut bytes = std::fs::read(&db).unwrap();
    let cc = u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
    bytes[92..96].copy_from_slice(&cc.wrapping_add(9).to_be_bytes());
    std::fs::write(&db, &bytes).unwrap();

    assert!(
        check_header_anomalies(&db)
            .unwrap()
            .iter()
            .any(|i| matches!(i, IntegrityIndicator::ChangeCounterMismatch { .. })),
        "a foreign-tool header edit should fire ChangeCounterMismatch"
    );
}

#[test]
fn adversarial_empty_single_and_vacuumed_do_not_falsely_fire() {
    let dir = tempdir().unwrap();

    // Empty DB (no user tables).
    let empty = dir.path().join("empty");
    Connection::open(&empty).unwrap().close().ok();
    let _ = chromium_indicators(&empty); // must not panic

    // Single-row DB.
    let single = dir.path().join("single");
    {
        let conn = Connection::open(&single).unwrap();
        chrome_schema(&conn);
        conn.execute(
            "INSERT INTO urls(id,url,title,visit_count,last_visit_time) VALUES (1,'https://a/','A',1,13300000000000000)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO visits(id,url,visit_time) VALUES (1,1,13300000000000000)",
            [],
        )
        .unwrap();
        conn.close().ok();
    }
    let single_ind = chromium_indicators(&single);
    assert!(
        !single_ind.iter().any(|i| matches!(
            i,
            IntegrityIndicator::VisitIdGap { .. } | IntegrityIndicator::FreelistGrowth { .. }
        )),
        "a clean single-row DB must not fire gap/freelist: {single_ind:?}"
    );

    // Already-vacuumed DB: delete then VACUUM ⇒ freelist reclaimed.
    let vac = dir.path().join("vac");
    {
        let conn = Connection::open(&vac).unwrap();
        chrome_schema(&conn);
        for i in 1..=50i64 {
            conn.execute(
                "INSERT INTO urls(id,url,title,visit_count,last_visit_time) VALUES (?1,?2,'T',1,13300000000000000)",
                rusqlite::params![i, format!("https://ex{i}.example/{}", "x".repeat(80))],
            )
            .unwrap();
        }
        conn.execute("DELETE FROM urls WHERE id > 5", []).unwrap();
        conn.execute("VACUUM", []).unwrap();
        conn.close().ok();
    }
    assert!(
        !check_page_state(&vac)
            .unwrap()
            .iter()
            .any(|i| matches!(i, IntegrityIndicator::FreelistGrowth { .. })),
        "a VACUUMed DB has an empty freelist and must not fire FreelistGrowth"
    );
}

/// If the `sqlite3` CLI is available, use it as a fully independent actor to bump
/// the change counter and confirm the parser observes it (real-tool oracle).
#[test]
fn sqlite3_cli_edit_bumps_change_counter_when_available() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("History");
    build_pristine(&db);
    let have = Command::new("sqlite3")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !have {
        eprintln!("skipping: sqlite3 CLI not available");
        return;
    }
    let before = parse_header(&std::fs::read(&db).unwrap()).unwrap();
    let ok = Command::new("sqlite3")
        .arg(&db)
        .arg("UPDATE urls SET title='cli-edit' WHERE id=2;")
        .output()
        .unwrap()
        .status
        .success();
    assert!(ok, "sqlite3 edit should succeed");
    let after = parse_header(&std::fs::read(&db).unwrap()).unwrap();
    assert!(
        after.change_counter > before.change_counter,
        "sqlite3 CLI write must bump the change counter"
    );
}
