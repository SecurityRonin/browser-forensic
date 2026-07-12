//! Safari / `CFURLCache` (`Cache.db`) response-body extraction.
//!
//! Safari and every `NSURLSession`/`CFNetwork` client on macOS/iOS persist their
//! HTTP cache as a SQLite database (`Cache.db`) plus an optional `fsCachedData/`
//! directory of overflow bodies. The relevant tables are:
//!
//! ```text
//! cfurl_cache_response(entry_ID, request_key = URL, time_stamp, partition, …)
//! cfurl_cache_receiver_data(entry_ID, isDataOnFS, receiver_data = BODY)
//! cfurl_cache_blob_data(entry_ID, response_object, request_object, …)
//! ```
//!
//! * `receiver_data` holds the response body **inline** when `isDataOnFS = 0`.
//!   When `isDataOnFS = 1`, `receiver_data` is instead the UUID filename of the
//!   body under `fsCachedData/<UUID>` next to the database.
//! * `response_object` is an archived `NSHTTPURLResponse` stored as a binary
//!   property list. Its top-level `Array` holds, by index:
//!   `[0]` a `{_CFURLString}` dict (the URL), `[1]` the response time as a
//!   `CFAbsoluteTime` (seconds since 2001-01-01), `[3]` the HTTP status code,
//!   `[4]` a header dictionary, `[6]` the MIME type.
//!
//! Body-compression finding (verified across 273 real `Cache.db` files, 15 836
//! bodies): `CFURLCache` **usually stores the already-decoded body** even when
//! the response carried a `Content-Encoding` (e.g. a `Content-Encoding: br`
//! response whose stored body is plain JSON), but **occasionally stores the
//! wire-compressed body** (gzip observed). So the stored body is only decoded
//! when it actually looks compressed for the declared encoding; otherwise it is
//! surfaced verbatim as the usable content. Decoding reuses the shared
//! [`decode_body`](crate::decode_body) dispatch and its bomb caps.
//!
//! Untrusted-input posture: `#![forbid(unsafe_code)]` (crate-wide), no
//! `unwrap`/`expect`, the database is opened **read-only + immutable** (no
//! evidence mutation, no lock contention), and a malformed row is skipped, never
//! panicked on.

use std::io::Cursor;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};

use crate::decompress::{decode_body, DecompressLimits};
use crate::error::CacheError;
use crate::resource::CachedResource;

/// Seconds between the `CFAbsoluteTime` epoch (2001-01-01) and the Unix epoch.
const CF_EPOCH_TO_UNIX_SECS: f64 = 978_307_200.0;

/// Enumerate every recoverable [`CachedResource`] in a Safari `Cache.db`,
/// using default decompression limits.
///
/// Best-effort: a missing/locked database or a malformed row yields fewer (or
/// zero) resources rather than an error. Use [`try_parse_safari_cache_db`] when
/// a database-open failure must surface loudly (bootstrap vs. artifact-missing).
#[must_use]
pub fn parse_safari_cache_db(db_path: &Path) -> Vec<CachedResource> {
    try_parse_safari_cache_db(db_path, &DecompressLimits::default()).unwrap_or_default()
}

/// Enumerate every recoverable [`CachedResource`], surfacing a database-open or
/// query failure as a loud [`CacheError`] (per-row failures are still skipped).
///
/// # Errors
///
/// Returns [`CacheError::Sqlite`] when the database cannot be opened or the base
/// query fails — a bootstrap failure that must not be mistaken for an empty
/// cache.
pub fn try_parse_safari_cache_db(
    db_path: &Path,
    limits: &DecompressLimits,
) -> Result<Vec<CachedResource>, CacheError> {
    let sqlite_err = |e: rusqlite::Error| CacheError::Sqlite {
        path: db_path.display().to_string(),
        detail: e.to_string(),
    };

    // Read-only + immutable: never mutate the evidence, never take a lock.
    let uri = format!("file:{}?immutable=1", db_path.display());
    let conn = Connection::open_with_flags(
        &uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(sqlite_err)?;

    let fs_dir = db_path
        .parent()
        .map_or_else(|| PathBuf::from("fsCachedData"), |p| p.join("fsCachedData"));

    let mut stmt = conn
        .prepare(
            "SELECT r.entry_ID, r.request_key, rd.isDataOnFS, rd.receiver_data, bd.response_object \
             FROM cfurl_cache_response r \
             LEFT JOIN cfurl_cache_receiver_data rd ON rd.entry_ID = r.entry_ID \
             LEFT JOIN cfurl_cache_blob_data bd ON bd.entry_ID = r.entry_ID",
        )
        .map_err(sqlite_err)?;

    let rows = stmt
        .query_map([], |row| {
            Ok(RawRow {
                url: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                is_on_fs: row.get::<_, Option<i64>>(2)?.unwrap_or(0) != 0,
                receiver_data: row.get::<_, Option<Vec<u8>>>(3)?,
                response_object: row.get::<_, Option<Vec<u8>>>(4)?,
            })
        })
        .map_err(sqlite_err)?;

    let mut out = Vec::new();
    for row in rows {
        // A single corrupt row must not abort the whole cache walk.
        let Ok(row) = row else { continue };
        out.push(build_resource(row, db_path, &fs_dir, limits));
    }
    Ok(out)
}

/// One row of the joined query, pre-decode.
struct RawRow {
    url: String,
    is_on_fs: bool,
    receiver_data: Option<Vec<u8>>,
    response_object: Option<Vec<u8>>,
}

/// Turn a joined row into a [`CachedResource`], reading an on-FS body and
/// decoding the stored body under its declared `Content-Encoding`.
fn build_resource(
    row: RawRow,
    db_path: &Path,
    fs_dir: &Path,
    limits: &DecompressLimits,
) -> CachedResource {
    let meta = row
        .response_object
        .as_deref()
        .map(parse_response_object)
        .unwrap_or_default();

    // Body: inline bytes, or the fsCachedData/<UUID> file for on-FS entries.
    let mut fs_note: Option<String> = None;
    let raw_body = match (row.is_on_fs, row.receiver_data) {
        (true, Some(uuid_bytes)) => {
            let uuid = String::from_utf8_lossy(&uuid_bytes);
            let path = fs_dir.join(uuid.as_ref());
            match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    // Fail-loud on the specific missing overflow file, but keep
                    // the resource (URL + headers are still evidence).
                    fs_note = Some(format!("on-FS body {} unreadable: {e}", path.display()));
                    Vec::new()
                }
            }
        }
        (false, Some(b)) => b,
        (_, None) => Vec::new(),
    };

    let (decoded_body, body_decoded, mut decode_note) =
        decode_safari_body(meta.content_encoding.as_deref(), &raw_body, limits);
    if let Some(n) = fs_note {
        decode_note = Some(match decode_note {
            Some(d) => format!("{n}; {d}"),
            None => n,
        });
    }

    CachedResource {
        url: row.url,
        http_status: meta.http_status,
        status_line: meta.status_line,
        headers: meta.headers,
        content_type: meta.content_type,
        content_encoding: meta.content_encoding,
        request_time_ns: None,
        response_time_ns: meta.response_time_ns,
        raw_body,
        decoded_body,
        body_decoded,
        decode_note,
        source_file: db_path.to_path_buf(),
        sparse_file: None,
    }
}

/// Decode a Safari-stored body, accounting for `CFURLCache` usually storing the
/// **already-decoded** content even when a `Content-Encoding` is declared.
///
/// Only bodies that actually look compressed for the declared encoding are run
/// through [`decode_body`]; a declared-but-absent encoding (plaintext body) is
/// returned verbatim as the usable content. A genuine decompression-bomb cap
/// breach is surfaced loudly (raw retained, `body_decoded = false`).
fn decode_safari_body(
    encoding: Option<&str>,
    raw: &[u8],
    limits: &DecompressLimits,
) -> (Vec<u8>, bool, Option<String>) {
    let token = encoding.map(|e| e.trim().to_ascii_lowercase());
    let looks_compressed = match token.as_deref() {
        Some("gzip" | "x-gzip") => raw.starts_with(&[0x1f, 0x8b]),
        Some("zstd") => raw.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]),
        // brotli/deflate have no reliable magic — attempt and fall back.
        Some("br" | "deflate") => true,
        _ => false,
    };

    if !looks_compressed {
        // identity/absent/unknown encoding, or a compressed encoding whose stored
        // body was already decoded (no matching magic) → the stored body IS the
        // usable content.
        let note = token
            .as_deref()
            .filter(|t| matches!(*t, "gzip" | "x-gzip" | "zstd"))
            .map(|t| format!("Content-Encoding {t} declared but body stored decompressed"));
        return (raw.to_vec(), true, note);
    }

    match decode_body(encoding, raw, limits) {
        Ok(o) if o.decoded => (o.bytes, true, o.note),
        Ok(o) => (o.bytes, false, o.note),
        // A real bomb (cap/ratio) is a loud failure: keep raw, flag it.
        Err(e @ (CacheError::OutputCapExceeded { .. } | CacheError::RatioExceeded { .. })) => {
            (raw.to_vec(), false, Some(format!("decode failed: {e}")))
        }
        // A format error means the "compressed" body was actually stored decoded.
        Err(_) => (
            raw.to_vec(),
            true,
            token.map(|t| format!("Content-Encoding {t} declared but body stored decompressed")),
        ),
    }
}

/// Metadata recovered from an archived `NSHTTPURLResponse` binary plist.
#[derive(Default)]
struct ResponseMeta {
    http_status: Option<u16>,
    status_line: Option<String>,
    headers: Vec<(String, String)>,
    content_type: Option<String>,
    content_encoding: Option<String>,
    response_time_ns: Option<i64>,
}

/// Parse the `response_object` binary plist into [`ResponseMeta`].
///
/// Never fails: on malformed input it returns whatever could be recovered
/// (possibly an empty [`ResponseMeta`]), never a panic. Header order/case from
/// the nested `__hhaa__` archive is not reconstructed (documented limitation);
/// the flattened header dictionary is used, which preserves every header's
/// name and value.
fn parse_response_object(blob: &[u8]) -> ResponseMeta {
    let Ok(value) = plist::Value::from_reader(Cursor::new(blob)) else {
        return ResponseMeta::default();
    };
    let Some(array) = value
        .as_dictionary()
        .and_then(|d| d.get("Array"))
        .and_then(plist::Value::as_array)
    else {
        return ResponseMeta::default();
    };

    let http_status = array
        .get(3)
        .and_then(plist::Value::as_signed_integer)
        .and_then(|n| u16::try_from(n).ok());
    let status_line = http_status.map(|c| format!("HTTP {c}"));

    let mut headers = Vec::new();
    if let Some(dict) = array.get(4).and_then(plist::Value::as_dictionary) {
        for (k, v) in dict {
            // `__hhaa__` is the nested ordered-header archive, not a real header.
            if k == "__hhaa__" {
                continue;
            }
            if let Some(val) = v.as_string() {
                headers.push((k.clone(), val.to_string()));
            }
        }
    }

    let content_encoding = header_value(&headers, "content-encoding");
    let content_type = header_value(&headers, "content-type").or_else(|| {
        array
            .get(6)
            .and_then(plist::Value::as_string)
            .map(str::to_string)
    });

    // Array[1] is the response time as CFAbsoluteTime (seconds since 2001).
    let response_time_ns = array
        .get(1)
        .and_then(plist::Value::as_real)
        .filter(|t| *t > 0.0)
        .map(|cf| ((cf + CF_EPOCH_TO_UNIX_SECS) * 1_000_000_000.0) as i64);

    ResponseMeta {
        http_status,
        status_line,
        headers,
        content_type,
        content_encoding,
        response_time_ns,
    }
}

/// Case-insensitive first-match header lookup.
fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use plist::Value;
    use std::io::Write;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// Build a `response_object` binary plist matching the real archived
    /// NSHTTPURLResponse layout (Array[3]=status, [4]=headers, [6]=mime).
    fn build_response_object(
        url: &str,
        status: i64,
        headers: &[(&str, &str)],
        mime: &str,
    ) -> Vec<u8> {
        let mut url_dict = plist::Dictionary::new();
        url_dict.insert("_CFURLString".into(), Value::String(url.into()));
        url_dict.insert("_CFURLStringType".into(), Value::Integer(15.into()));
        let mut hdr = plist::Dictionary::new();
        for (k, v) in headers {
            hdr.insert((*k).into(), Value::String((*v).into()));
        }
        let array = Value::Array(vec![
            Value::Dictionary(url_dict),
            Value::Real(760_000_000.0),
            Value::Integer(0.into()),
            Value::Integer(status.into()),
            Value::Dictionary(hdr),
            Value::Integer(0.into()),
            Value::String(mime.into()),
        ]);
        let mut root = plist::Dictionary::new();
        root.insert("Array".into(), array);
        root.insert("Version".into(), Value::Integer(1.into()));
        let mut buf = Vec::new();
        Value::Dictionary(root).to_writer_binary(&mut buf).unwrap();
        buf
    }

    /// One synthetic cache row: (entry_ID, URL, isDataOnFS, body, response_object).
    type Row<'a> = (i64, &'a str, i64, &'a [u8], Vec<u8>);

    /// Build a minimal in-memory-backed Safari Cache.db on disk.
    fn build_cache_db(dir: &Path, rows: &[Row<'_>]) -> PathBuf {
        let db_path = dir.join("Cache.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE cfurl_cache_response(entry_ID INTEGER PRIMARY KEY, version INTEGER, \
               hash_value INTEGER, storage_policy INTEGER, request_key TEXT, time_stamp TEXT, partition TEXT);
             CREATE TABLE cfurl_cache_receiver_data(entry_ID INTEGER PRIMARY KEY, isDataOnFS INTEGER, receiver_data BLOB);
             CREATE TABLE cfurl_cache_blob_data(entry_ID INTEGER PRIMARY KEY, response_object BLOB, request_object BLOB, proto_props BLOB, user_info BLOB);",
        )
        .unwrap();
        for (eid, url, on_fs, body, resp_obj) in rows {
            conn.execute(
                "INSERT INTO cfurl_cache_response(entry_ID, request_key, time_stamp) VALUES (?1, ?2, '2026-01-01 00:00:00')",
                rusqlite::params![eid, url],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO cfurl_cache_receiver_data(entry_ID, isDataOnFS, receiver_data) VALUES (?1, ?2, ?3)",
                rusqlite::params![eid, on_fs, body],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO cfurl_cache_blob_data(entry_ID, response_object) VALUES (?1, ?2)",
                rusqlite::params![eid, resp_obj],
            )
            .unwrap();
        }
        db_path
    }

    #[test]
    fn inline_plaintext_body_with_declared_br_is_kept_verbatim() {
        // Mirrors real CFURLCache: Content-Encoding: br but body stored decoded.
        let dir = tempfile::TempDir::new().unwrap();
        let ro = build_response_object(
            "https://api.test/manifest.json",
            200,
            &[
                ("Content-Type", "application/json"),
                ("Content-Encoding", "br"),
            ],
            "application/json",
        );
        let body = br#"{"name":"rc"}"#;
        let db = build_cache_db(
            dir.path(),
            &[(1, "https://api.test/manifest.json", 0, body, ro)],
        );
        let res = parse_safari_cache_db(&db);
        assert_eq!(res.len(), 1);
        let r = &res[0];
        assert_eq!(r.url, "https://api.test/manifest.json");
        assert_eq!(r.http_status, Some(200));
        assert_eq!(r.content_type.as_deref(), Some("application/json"));
        assert_eq!(r.content_encoding.as_deref(), Some("br"));
        assert_eq!(r.decoded_body, body);
        assert!(r.body_decoded, "plaintext-with-br body is usable content");
        assert!(r.response_time_ns.is_some());
    }

    #[test]
    fn inline_gzip_body_is_decompressed() {
        let dir = tempfile::TempDir::new().unwrap();
        let plain = b"hello safari gzip body";
        let ro = build_response_object(
            "https://api.test/g",
            200,
            &[("Content-Encoding", "gzip"), ("Content-Type", "text/plain")],
            "text/plain",
        );
        let db = build_cache_db(
            dir.path(),
            &[(1, "https://api.test/g", 0, &gzip(plain), ro)],
        );
        let res = parse_safari_cache_db(&db);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].decoded_body, plain);
        assert!(res[0].body_decoded);
    }

    #[test]
    fn on_fs_body_read_from_fscacheddata() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = "AAAA1111-2222-3333-4444-555566667777";
        let fs = dir.path().join("fsCachedData");
        std::fs::create_dir_all(&fs).unwrap();
        std::fs::write(fs.join(uuid), b"on-fs body content").unwrap();
        let ro = build_response_object(
            "https://big.test/",
            200,
            &[("Content-Type", "image/png")],
            "image/png",
        );
        let db = build_cache_db(
            dir.path(),
            &[(1, "https://big.test/", 1, uuid.as_bytes(), ro)],
        );
        let res = parse_safari_cache_db(&db);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].decoded_body, b"on-fs body content");
        assert!(res[0].body_decoded);
    }

    #[test]
    fn on_fs_body_with_text_receiver_data_column() {
        // Real CFURLCache stores the on-FS UUID as a TEXT value in the BLOB
        // column (verified on a live Cache.db); the row must not be dropped just
        // because the storage class is Text rather than Blob.
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = "EB767E55-CE67-4B09-B5AA-6CFCE9E8EEB2";
        let fs = dir.path().join("fsCachedData");
        std::fs::create_dir_all(&fs).unwrap();
        std::fs::write(fs.join(uuid), b"text-column on-fs body").unwrap();
        let db_path = dir.path().join("Cache.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE cfurl_cache_response(entry_ID INTEGER PRIMARY KEY, request_key TEXT, time_stamp TEXT);
             CREATE TABLE cfurl_cache_receiver_data(entry_ID INTEGER PRIMARY KEY, isDataOnFS INTEGER, receiver_data BLOB);
             CREATE TABLE cfurl_cache_blob_data(entry_ID INTEGER PRIMARY KEY, response_object BLOB);
             INSERT INTO cfurl_cache_response VALUES (1, 'https://onfs-text.test/', '2026-01-01 00:00:00');",
        )
        .unwrap();
        // Insert receiver_data as a TEXT value (a &str param -> SQLITE_TEXT).
        conn.execute(
            "INSERT INTO cfurl_cache_receiver_data(entry_ID, isDataOnFS, receiver_data) VALUES (1, 1, ?1)",
            rusqlite::params![uuid],
        )
        .unwrap();
        drop(conn);
        let res = parse_safari_cache_db(&db_path);
        assert_eq!(res.len(), 1, "on-FS row with TEXT UUID must not be dropped");
        assert_eq!(res[0].url, "https://onfs-text.test/");
        assert_eq!(res[0].decoded_body, b"text-column on-fs body");
    }

    #[test]
    fn on_fs_missing_file_keeps_resource_with_note() {
        let dir = tempfile::TempDir::new().unwrap();
        let ro = build_response_object("https://gone.test/", 200, &[], "application/octet-stream");
        let db = build_cache_db(
            dir.path(),
            &[(
                1,
                "https://gone.test/",
                1,
                b"DEAD0000-0000-0000-0000-000000000000",
                ro,
            )],
        );
        let res = parse_safari_cache_db(&db);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].url, "https://gone.test/");
        assert!(res[0].raw_body.is_empty());
        assert!(
            res[0]
                .decode_note
                .as_deref()
                .unwrap_or("")
                .contains("unreadable"),
            "missing on-FS body must be flagged: {:?}",
            res[0].decode_note
        );
    }

    #[test]
    fn missing_db_returns_empty_but_try_errs() {
        let missing = Path::new("/nonexistent/dir/Cache.db");
        assert!(parse_safari_cache_db(missing).is_empty());
        let err = try_parse_safari_cache_db(missing, &DecompressLimits::default()).unwrap_err();
        assert!(matches!(err, CacheError::Sqlite { .. }), "{err}");
    }

    #[test]
    fn null_response_object_still_yields_url_and_body() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("Cache.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE cfurl_cache_response(entry_ID INTEGER PRIMARY KEY, request_key TEXT, time_stamp TEXT);
             CREATE TABLE cfurl_cache_receiver_data(entry_ID INTEGER PRIMARY KEY, isDataOnFS INTEGER, receiver_data BLOB);
             CREATE TABLE cfurl_cache_blob_data(entry_ID INTEGER PRIMARY KEY, response_object BLOB);
             INSERT INTO cfurl_cache_response VALUES (1, 'https://noblob.test/', '2026-01-01 00:00:00');
             INSERT INTO cfurl_cache_receiver_data VALUES (1, 0, X'6162630a');",
        )
        .unwrap();
        drop(conn);
        let res = parse_safari_cache_db(&db_path);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].url, "https://noblob.test/");
        assert_eq!(res[0].decoded_body, b"abc\n");
        assert!(res[0].http_status.is_none());
    }

    #[test]
    fn garbage_response_object_does_not_panic() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = build_cache_db(
            dir.path(),
            &[(
                1,
                "https://junk.test/",
                0,
                b"body",
                vec![0xde, 0xad, 0xbe, 0xef],
            )],
        );
        let res = parse_safari_cache_db(&db);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].decoded_body, b"body");
        assert!(res[0].http_status.is_none());
    }
}
