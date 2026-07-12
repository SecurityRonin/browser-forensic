//! Firefox `places.sqlite` page-annotation parser (`moz_annos`).
//!
//! `moz_annos` stores named key/value annotations the browser attaches to a
//! page: the attribute name lives in `moz_anno_attributes` (`anno_attribute_id`
//! -> `name`), the value in `content`, with `dateAdded` / `lastModified`
//! timestamps. Mozilla ref: `toolkit/components/places/nsPlacesTables.h`
//! (`CREATE_MOZ_ANNOS`, `CREATE_MOZ_ANNO_ATTRIBUTES`).
//!
//! Content is typed (`type`: string / int / double / binary in
//! `nsAnnotationService`), so it is read as a dynamic value and never forced to
//! a single Rust type. Annotations are surfaced as recorded, without
//! interpretation. Timestamps are Firefox PRTime microseconds.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::sqlite::open_evidence_db;
use browser_forensic_core::timestamp::unix_micros_to_nanos;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

/// Convert a dynamic SQLite value into JSON without erroring on any storage
/// class (annotation `content` may be text, integer, double, or binary).
fn value_to_json(v: rusqlite::types::Value) -> serde_json::Value {
    use rusqlite::types::Value;
    match v {
        Value::Null => serde_json::Value::Null,
        Value::Integer(i) => json!(i),
        Value::Real(f) => json!(f),
        Value::Text(s) => json!(s),
        Value::Blob(b) => json!(format!("<{} bytes binary>", b.len())),
    }
}

/// Parse a Firefox `places.sqlite` file for page annotations.
///
/// # Errors
///
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_annotations(path: &Path) -> Result<Vec<BrowserEvent>> {
    let db = open_evidence_db(path)?;
    let conn = &db.conn;
    let mut stmt = conn.prepare(
        "SELECT a.name, an.content, an.dateAdded, an.lastModified, p.url \
         FROM moz_annos an \
         JOIN moz_anno_attributes a ON an.anno_attribute_id = a.id \
         JOIN moz_places p ON an.place_id = p.id \
         ORDER BY an.dateAdded ASC",
    )?;
    let source = path.to_string_lossy().into_owned();
    let events: Vec<BrowserEvent> = stmt
        .query_map([], |row| {
            let name: String = row.get(0)?;
            let content = value_to_json(row.get::<_, rusqlite::types::Value>(1)?);
            let date_added_us: i64 = row.get::<_, Option<i64>>(2)?.unwrap_or(0);
            let last_modified_us: i64 = row.get::<_, Option<i64>>(3)?.unwrap_or(0);
            let url: String = row.get(4)?;
            Ok((name, content, date_added_us, last_modified_us, url))
        })?
        .filter_map(std::result::Result::ok)
        .map(|(name, content, date_added_us, last_modified_us, url)| {
            let ts_ns = unix_micros_to_nanos(date_added_us);
            let content_display = content
                .as_str()
                .map_or_else(|| content.to_string(), ToString::to_string);
            let desc = format!("annotation \u{201c}{name}\u{201d} = {content_display} on {url}");
            BrowserEvent::new(
                ts_ns,
                BrowserFamily::Firefox,
                ArtifactKind::Annotation,
                &source,
                desc,
            )
            .with_attr("name", json!(name))
            .with_attr("content", content)
            .with_attr("url", json!(url))
            .with_attr("last_modified_us", json!(last_modified_us))
        })
        .collect();
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::test_utils::sqlite::TestDb;
    use rusqlite::params;

    // Schema mirrors a real places.sqlite (verified on-disk).
    const SCHEMA: &str = "CREATE TABLE moz_places (
        id  INTEGER PRIMARY KEY,
        url TEXT NOT NULL
    );
    CREATE TABLE moz_anno_attributes (
        id   INTEGER PRIMARY KEY,
        name VARCHAR(32) UNIQUE NOT NULL
    );
    CREATE TABLE moz_annos (
        id                INTEGER PRIMARY KEY,
        place_id          INTEGER NOT NULL,
        anno_attribute_id INTEGER,
        content           LONGVARCHAR,
        flags             INTEGER DEFAULT 0,
        expiration        INTEGER DEFAULT 0,
        type              INTEGER DEFAULT 0,
        dateAdded         INTEGER DEFAULT 0,
        lastModified      INTEGER DEFAULT 0
    );";

    fn seed(db: &TestDb, url: &str, attr: &str) -> (i64, i64) {
        db.insert("INSERT INTO moz_places (url) VALUES (?1)", params![url]);
        db.insert(
            "INSERT INTO moz_anno_attributes (name) VALUES (?1)",
            params![attr],
        );
        let conn = rusqlite::Connection::open(db.path()).unwrap();
        let pid: i64 = conn
            .query_row(
                "SELECT id FROM moz_places WHERE url=?1",
                params![url],
                |r| r.get(0),
            )
            .unwrap();
        let aid: i64 = conn
            .query_row(
                "SELECT id FROM moz_anno_attributes WHERE name=?1",
                params![attr],
                |r| r.get(0),
            )
            .unwrap();
        (pid, aid)
    }

    #[test]
    fn empty_annos_returns_empty() {
        let db = TestDb::new(SCHEMA);
        assert!(parse_annotations(db.path()).unwrap().is_empty());
    }

    #[test]
    fn single_string_annotation_emits_event() {
        let db = TestDb::new(SCHEMA);
        let (pid, aid) = seed(
            &db,
            "https://example.com/",
            "bookmarkProperties/description",
        );
        db.insert(
            "INSERT INTO moz_annos (place_id, anno_attribute_id, content, dateAdded, lastModified) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![pid, aid, "a note", 1_648_000_000_000_000_i64, 1_648_000_000_000_001_i64],
        );
        let events = parse_annotations(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::Annotation);
        assert_eq!(ev.browser, BrowserFamily::Firefox);
        assert_eq!(ev.attrs["name"], json!("bookmarkProperties/description"));
        assert_eq!(ev.attrs["content"], json!("a note"));
        assert_eq!(ev.attrs["url"], json!("https://example.com/"));
        assert_eq!(ev.timestamp_ns, 1_648_000_000_000_000_i64 * 1_000);
        assert_eq!(
            ev.attrs["last_modified_us"],
            json!(1_648_000_000_000_001_i64)
        );
    }

    #[test]
    fn binary_content_does_not_error() {
        // Annotation content may be a BLOB (TYPE_BINARY). BLOB is exempt from the
        // column's TEXT affinity, so it exercises value_to_json's non-text branch:
        // the parser must surface it as a size marker, never error.
        let db = TestDb::new(SCHEMA);
        let (pid, aid) = seed(&db, "https://n.example/", "some/blob");
        db.insert(
            "INSERT INTO moz_annos (place_id, anno_attribute_id, content, dateAdded) \
             VALUES (?1, ?2, ?3, ?4)",
            params![pid, aid, vec![0xde_u8, 0xad, 0xbe, 0xef], 0_i64],
        );
        let events = parse_annotations(db.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].attrs["content"], json!("<4 bytes binary>"));
    }

    #[test]
    fn annotation_without_matching_place_is_excluded() {
        let db = TestDb::new(SCHEMA);
        db.insert(
            "INSERT INTO moz_anno_attributes (name) VALUES (?1)",
            params!["orphan/attr"],
        );
        db.insert(
            "INSERT INTO moz_annos (place_id, anno_attribute_id, content, dateAdded) \
             VALUES (?1, ?2, ?3, ?4)",
            params![999_i64, 1_i64, "x", 0_i64],
        );
        assert!(parse_annotations(db.path()).unwrap().is_empty());
    }
}
