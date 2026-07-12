#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end coverage for the Milestone-17 Firefox subcommands:
//! `typed-input` (moz_inputhistory), `annotations` (moz_annos), and
//! `deleted-bookmarks` (bookmarkbackups/*.jsonlz4 diff vs current moz_bookmarks).

use assert_cmd::Command;
use rusqlite::Connection;
use std::path::Path;
use tempfile::TempDir;

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

const MOZLZ4_MAGIC: &[u8] = b"mozLz40\0";

/// Mint a `bookmarkbackups/<name>` mozLz4 file holding a bookmark tree.
fn mint_backup(profile: &Path, name: &str, bookmarks: &[(&str, &str, i64)]) {
    let backups = profile.join("bookmarkbackups");
    std::fs::create_dir_all(&backups).unwrap();
    let children: Vec<_> = bookmarks
        .iter()
        .map(|(title, uri, added)| {
            serde_json::json!({
                "guid": "aaaaaaaaaaaa", "title": title, "typeCode": 1,
                "type": "text/x-moz-place", "uri": uri, "dateAdded": added,
            })
        })
        .collect();
    let tree = serde_json::json!({
        "guid": "root________", "title": "", "typeCode": 2,
        "type": "text/x-moz-place-container", "root": "placesRoot", "children": children,
    });
    let payload = serde_json::to_vec(&tree).unwrap();
    let mut framed = Vec::new();
    framed.extend_from_slice(MOZLZ4_MAGIC);
    framed.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    framed.extend_from_slice(&lz4_flex::block::compress(&payload));
    std::fs::write(backups.join(name), framed).unwrap();
}

/// Build a Firefox profile dir with a places.sqlite carrying typed input,
/// an annotation, and one current bookmark ("https://a.example/").
fn build_profile() -> TempDir {
    let dir = TempDir::new().unwrap();
    let places = dir.path().join("places.sqlite");
    let conn = Connection::open(&places).unwrap();
    conn.execute_batch(
        "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT NOT NULL);
         CREATE TABLE moz_inputhistory (place_id INTEGER NOT NULL, input LONGVARCHAR NOT NULL,
             use_count INTEGER, PRIMARY KEY (place_id, input));
         CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name VARCHAR(32) UNIQUE NOT NULL);
         CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER NOT NULL,
             anno_attribute_id INTEGER, content LONGVARCHAR, flags INTEGER DEFAULT 0,
             expiration INTEGER DEFAULT 0, type INTEGER DEFAULT 0, dateAdded INTEGER DEFAULT 0,
             lastModified INTEGER DEFAULT 0);
         CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER,
             title TEXT, dateAdded INTEGER);
         INSERT INTO moz_places (id, url) VALUES (1, 'https://a.example/');
         INSERT INTO moz_inputhistory (place_id, input, use_count) VALUES (1, 'a.exa', 0.42);
         INSERT INTO moz_anno_attributes (id, name) VALUES (1, 'my/annotation');
         INSERT INTO moz_annos (place_id, anno_attribute_id, content, dateAdded, lastModified)
             VALUES (1, 1, 'the-content', 1648000000000000, 1648000000000001);
         INSERT INTO moz_bookmarks (type, fk, title, dateAdded) VALUES (1, 1, 'Kept', 100);",
    )
    .unwrap();
    drop(conn);
    dir
}

#[test]
fn typed_input_prints_typed_string() {
    let dir = build_profile();
    let places = dir.path().join("places.sqlite");
    let out = br4n6()
        .args(["typed-input", places.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("a.exa"), "typed string missing: {stdout}");
}

#[test]
fn annotations_prints_annotation() {
    let dir = build_profile();
    let places = dir.path().join("places.sqlite");
    let out = br4n6()
        .args(["annotations", places.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("my/annotation"),
        "annotation missing: {stdout}"
    );
    assert!(stdout.contains("the-content"), "content missing: {stdout}");
}

#[test]
fn deleted_bookmarks_recovers_absent_bookmark() {
    let dir = build_profile();
    // Backup held the kept bookmark AND a now-deleted one.
    mint_backup(
        dir.path(),
        "bookmarks-2024-06-01_2_hash.jsonlz4",
        &[
            ("Kept", "https://a.example/", 100),
            ("Deleted", "https://gone.example/", 200),
        ],
    );
    let out = br4n6()
        .args(["deleted-bookmarks", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("gone.example"),
        "recovered url missing: {stdout}"
    );
    assert!(
        stdout.contains("absent from current"),
        "recovery framing missing: {stdout}"
    );
    // The kept bookmark must NOT be reported as recovered.
    assert!(
        !stdout.contains("a.example/ \u{2014}"),
        "kept bookmark wrongly recovered: {stdout}"
    );
}

#[test]
fn deleted_bookmarks_no_backups_is_clean() {
    let dir = build_profile();
    let out = br4n6()
        .args(["deleted-bookmarks", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
}

#[test]
fn m17_subcommands_help_exit_0() {
    for sub in ["typed-input", "annotations", "deleted-bookmarks"] {
        br4n6().args([sub, "--help"]).assert().success();
    }
}
