//! Service Worker **CacheStorage** (Cache API) response-body extraction.
//!
//! A page's service worker stores full offline responses via the Cache API
//! (`caches.open(name)` → `cache.put(request, response)`). These survive a
//! history/cookie wipe, so they are a rich source of "what a web-app actually
//! fetched and rendered offline". On disk (Chromium
//! `content/browser/cache_storage/`):
//!
//! ```text
//! <profile>/Service Worker/CacheStorage/
//!   <origin-hash>/                 SHA-1 of the storage key / origin
//!     index.txt                    serialized `CacheStorageIndex` proto: cache name -> cache-dir UUID
//!     <uuid-1>/                    one disk_cache (SimpleCache) per named cache
//!       <hash>_0                   SimpleCache entry: key = request URL
//!       index, index-dir/
//!     <uuid-2>/ ...
//! ```
//!
//! Each SimpleCache `<hash>_0` entry carries the **request URL** as its key,
//! the **`CacheMetadata` proto** (request method + request/response headers +
//! response status + times — `content/browser/cache_storage/cache_storage.proto`)
//! in **stream 0**, and the **response body** in **stream 1**. This module
//! reuses [`parse_simple_entry`](crate::parse_simple_entry) for the SimpleCache
//! framing and the published `protobuf-forensic-core` decoder for the protos.
//!
//! Two honesty notes grounded in real data (Slack/Discord/Electron corpora):
//!   * The Cache API stores the **already-decoded delivered body** in stream 1,
//!     even when the response metadata still advertises a `Content-Encoding`
//!     (observed: 1684/1684 `br`/`gzip`-declaring Slack entries stored plain).
//!     So a declared encoding is surfaced as metadata; the stored bytes are the
//!     usable body and are not re-inflated unless they genuinely decode.
//!   * The `CacheMetadata` proto has **no request-entity-body field** — the
//!     Cache API does not persist POST request bodies. This module surfaces the
//!     request *method* and *headers*; a request body is not recoverable here.

use protobuf_forensic_core::{decode, Field, FieldValue};

/// Decode protobuf bytes into a flat field list; malformed input yields an empty
/// list (best-effort recovery, never a panic).
fn fields(bytes: &[u8]) -> Vec<Field> {
    decode(bytes).unwrap_or_default()
}

/// The raw payload of the first length-delimited (`LEN`) field with this number.
fn len_raw<'a>(fields: &'a [Field], number: u64) -> Option<&'a [u8]> {
    fields.iter().find_map(|f| match &f.value {
        FieldValue::Len(lv) if f.number == number => Some(lv.raw.as_slice()),
        _ => None,
    })
}

/// A length-delimited field read as a lossy-UTF-8 string.
fn str_field(fields: &[Field], number: u64) -> Option<String> {
    len_raw(fields, number).map(|b| String::from_utf8_lossy(b).into_owned())
}

/// The first varint field with this number.
fn varint_field(fields: &[Field], number: u64) -> Option<u64> {
    fields.iter().find_map(|f| match &f.value {
        FieldValue::Varint(v) if f.number == number => Some(*v),
        _ => None,
    })
}

/// Raw payloads of *every* length-delimited field with this number (a repeated
/// `LEN` field — repeated submessages or repeated strings).
fn repeated_len_raw<'a>(fields: &'a [Field], number: u64) -> impl Iterator<Item = &'a [u8]> {
    fields.iter().filter_map(move |f| match &f.value {
        FieldValue::Len(lv) if f.number == number => Some(lv.raw.as_slice()),
        _ => None,
    })
}

/// Decode a `bytes` field holding a UTF-16LE string (Chromium `u16string_name`).
fn utf16le_field(fields: &[Field], number: u64) -> Option<String> {
    let raw = len_raw(fields, number)?;
    if raw.len() < 2 {
        return None;
    }
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

/// One named cache listed in a CacheStorage `index.txt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntry {
    /// The cache name as passed to `caches.open(name)` (e.g. `config-cache`).
    pub name: String,
    /// The on-disk directory (a UUID) holding this cache's disk_cache instance.
    pub cache_dir: String,
}

/// A parsed CacheStorage `index.txt` (`CacheStorageIndex` proto).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheStorageIndex {
    /// The storage key (field 3) — the partitioned origin, e.g.
    /// `https://app.slack.com/`. Preferred origin attribution.
    pub storage_key: Option<String>,
    /// The legacy `origin` (field 2, deprecated) if present.
    pub origin: Option<String>,
    /// The named caches this origin holds, in file order.
    pub caches: Vec<CacheEntry>,
}

impl CacheStorageIndex {
    /// Best available origin attribution: `storage_key`, else the legacy
    /// `origin`.
    #[must_use]
    pub fn origin_attribution(&self) -> Option<&str> {
        self.storage_key.as_deref().or(self.origin.as_deref())
    }
}

/// Parse a CacheStorage `index.txt` (`CacheStorageIndex` proto) into the list of
/// named caches plus the origin attribution.
///
/// Never panics: malformed/truncated proto input yields whatever caches could be
/// recovered (possibly none), never an error or panic — a partial index still
/// lets the caller walk the cache directories that *are* present on disk.
#[must_use]
pub fn parse_cachestorage_index(bytes: &[u8]) -> CacheStorageIndex {
    let top = fields(bytes);
    // repeated Cache cache = 1
    let caches = repeated_len_raw(&top, 1)
        .filter_map(|raw| {
            let cf = fields(raw);
            let cache_dir = str_field(&cf, 2)?; // cache_dir = 2 (the UUID)
                                                // Prefer u16string_name (7) over the legacy UTF-8 name (1).
            let name = utf16le_field(&cf, 7)
                .or_else(|| str_field(&cf, 1))
                .unwrap_or_default();
            Some(CacheEntry { name, cache_dir })
        })
        .collect();
    CacheStorageIndex {
        storage_key: str_field(&top, 3), // storage_key = 3
        origin: str_field(&top, 2),      // origin = 2 (deprecated)
        caches,
    }
}

/// Decoded `CacheMetadata` proto from a CacheStorage entry's **stream 0**
/// (`content/browser/cache_storage/cache_storage.proto`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheStorageMeta {
    /// The request method (`CacheRequest.method`), e.g. `GET`, `POST`.
    pub request_method: Option<String>,
    /// The request headers (`CacheRequest.headers`), in file order.
    pub request_headers: Vec<(String, String)>,
    /// The HTTP status code (`CacheResponse.status_code`).
    pub http_status: Option<u16>,
    /// The HTTP status text (`CacheResponse.status_text`), often empty for HTTP/2.
    pub status_text: Option<String>,
    /// The Fetch response type (`CacheResponse.response_type`) as its raw enum
    /// value; see [`response_type_name`](CacheStorageMeta::response_type_name).
    pub response_type: Option<i64>,
    /// The response headers (`CacheResponse.headers`), in file order.
    pub headers: Vec<(String, String)>,
    /// The computed MIME type (`CacheResponse.mime_type`), if stored.
    pub mime_type: Option<String>,
    /// Response time (Unix nanoseconds), from `CacheResponse.response_time`.
    pub response_time_ns: Option<i64>,
    /// Cache entry time (Unix nanoseconds), from `CacheMetadata.entry_time`.
    pub entry_time_ns: Option<i64>,
}

impl CacheStorageMeta {
    /// Case-insensitive lookup of the first *response* header with this name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The response `Content-Type` header value, if present.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// The response `Content-Encoding` header value, if present. Note: in the
    /// Cache API the stored body is already decoded, so this is metadata about
    /// the *original wire* response, not the stored bytes.
    #[must_use]
    pub fn content_encoding(&self) -> Option<&str> {
        self.header("content-encoding")
    }

    /// The Fetch `Response.type` name for the stored `response_type` enum
    /// (`content.proto CacheResponse.ResponseType`). An `opaque` type flags a
    /// cross-origin no-cors response whose body/headers the page could not read.
    #[must_use]
    pub fn response_type_name(&self) -> Option<&'static str> {
        Some(match self.response_type? {
            0 => "basic",
            1 => "cors",
            2 => "default",
            3 => "error",
            4 => "opaque",
            5 => "opaqueredirect",
            _ => "unknown",
        })
    }
}

/// Parse a CacheStorage entry's stream 0 (`CacheMetadata` proto) into
/// [`CacheStorageMeta`].
///
/// Never fails: malformed/truncated proto input returns whatever could be
/// recovered (possibly an empty [`CacheStorageMeta`]), never a panic.
#[must_use]
pub fn parse_cachestorage_metadata(_stream0: &[u8]) -> CacheStorageMeta {
    // GREEN in the next commit.
    CacheStorageMeta::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- minimal protobuf wire-format encoders for building fixtures ---
    fn varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                break;
            }
        }
    }
    fn tag(field: u64, wire: u8, out: &mut Vec<u8>) {
        varint((field << 3) | u64::from(wire), out);
    }
    fn len_field(field: u64, payload: &[u8], out: &mut Vec<u8>) {
        tag(field, 2, out);
        varint(payload.len() as u64, out);
        out.extend_from_slice(payload);
    }
    fn varint_field(field: u64, v: u64, out: &mut Vec<u8>) {
        tag(field, 0, out);
        varint(v, out);
    }

    /// Build a `CacheStorageIndex.Cache` submessage: name(1)=name, cache_dir(2)=dir.
    fn cache_msg(name: &str, dir: &str, u16name: Option<&str>) -> Vec<u8> {
        let mut m = Vec::new();
        len_field(1, name.as_bytes(), &mut m);
        len_field(2, dir.as_bytes(), &mut m);
        varint_field(3, 4096, &mut m); // size
        if let Some(u) = u16name {
            let utf16: Vec<u8> = u.encode_utf16().flat_map(u16::to_le_bytes).collect();
            len_field(7, &utf16, &mut m);
        }
        m
    }

    fn build_index(caches: &[(&str, &str, Option<&str>)], storage_key: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for (n, d, u) in caches {
            let m = cache_msg(n, d, *u);
            len_field(1, &m, &mut out); // repeated Cache cache = 1
        }
        len_field(3, storage_key.as_bytes(), &mut out); // storage_key = 3
        out
    }

    #[test]
    fn parses_caches_and_storage_key() {
        let bytes = build_index(
            &[
                ("config-cache", "68f870d4-ed4e-4331-b7bd-7faed95e3d5e", None),
                (
                    "gantry-1783559853",
                    "41f90ad2-2e86-466e-9b40-3d8f1d369bb1",
                    None,
                ),
            ],
            "https://app.slack.com/",
        );
        let idx = parse_cachestorage_index(&bytes);
        assert_eq!(idx.storage_key.as_deref(), Some("https://app.slack.com/"));
        assert_eq!(idx.caches.len(), 2);
        assert_eq!(idx.caches[0].name, "config-cache");
        assert_eq!(
            idx.caches[0].cache_dir,
            "68f870d4-ed4e-4331-b7bd-7faed95e3d5e"
        );
        assert_eq!(idx.caches[1].name, "gantry-1783559853");
    }

    #[test]
    fn prefers_u16string_name_when_present() {
        // Newer caches carry the name as UTF-16 in field 7; it takes precedence.
        let bytes = build_index(
            &[("legacy", "abcd-uuid", Some("réal-café"))],
            "https://x.test/",
        );
        let idx = parse_cachestorage_index(&bytes);
        assert_eq!(idx.caches.len(), 1);
        assert_eq!(idx.caches[0].name, "réal-café");
    }

    #[test]
    fn empty_input_yields_empty_index_no_panic() {
        let idx = parse_cachestorage_index(&[]);
        assert!(idx.caches.is_empty());
        assert!(idx.storage_key.is_none());
    }

    #[test]
    fn garbage_input_does_not_panic() {
        // Random bytes must never panic; recover nothing rather than crash.
        let idx = parse_cachestorage_index(&[0xff, 0x00, 0x80, 0x80, 0x80, 0x7f, 0x13, 0x37]);
        // No assertion on contents — the property under test is "no panic".
        let _ = idx.caches.len();
    }

    #[test]
    fn origin_attribution_prefers_storage_key() {
        let idx = CacheStorageIndex {
            storage_key: Some("https://sk/".to_string()),
            origin: Some("https://og/".to_string()),
            caches: vec![],
        };
        assert_eq!(idx.origin_attribution(), Some("https://sk/"));
        let idx2 = CacheStorageIndex {
            storage_key: None,
            origin: Some("https://og/".to_string()),
            caches: vec![],
        };
        assert_eq!(idx2.origin_attribution(), Some("https://og/"));
    }

    // --- CacheMetadata (stream 0) fixtures ---

    /// A `CacheHeaderMap`: name(1)=name, value(2)=value.
    fn header_msg(name: &str, value: &str) -> Vec<u8> {
        let mut m = Vec::new();
        len_field(1, name.as_bytes(), &mut m);
        len_field(2, value.as_bytes(), &mut m);
        m
    }

    /// A `CacheRequest`: method(1), repeated headers(2).
    fn request_msg(method: &str, headers: &[(&str, &str)]) -> Vec<u8> {
        let mut m = Vec::new();
        len_field(1, method.as_bytes(), &mut m);
        for (k, v) in headers {
            let h = header_msg(k, v);
            len_field(2, &h, &mut m);
        }
        m
    }

    /// A `CacheResponse`: status_code(1), status_text(2), response_type(3),
    /// repeated headers(4), response_time(6), mime_type(13).
    #[allow(clippy::too_many_arguments)]
    fn response_msg(
        status: u64,
        status_text: &str,
        rtype: u64,
        headers: &[(&str, &str)],
        response_time_us: u64,
        mime: &str,
    ) -> Vec<u8> {
        let mut m = Vec::new();
        varint_field(1, status, &mut m);
        len_field(2, status_text.as_bytes(), &mut m);
        varint_field(3, rtype, &mut m);
        for (k, v) in headers {
            let h = header_msg(k, v);
            len_field(4, &h, &mut m);
        }
        varint_field(6, response_time_us, &mut m);
        len_field(13, mime.as_bytes(), &mut m);
        m
    }

    /// A full `CacheMetadata`: request(1), response(2), entry_time(3).
    fn metadata_msg(request: &[u8], response: &[u8], entry_time_us: u64) -> Vec<u8> {
        let mut m = Vec::new();
        len_field(1, request, &mut m);
        len_field(2, response, &mut m);
        varint_field(3, entry_time_us, &mut m);
        m
    }

    // 2026-07-08T03:40:23.945607Z as base::Time internal µs (µs since 1601),
    // matching the real Slack entry decoded by protoc --decode_raw (tier-1).
    const RESP_WIN_US: u64 = 13_427_955_623_945_607;
    // WIN_TO_UNIX_MICROS = 11_644_473_600_000_000; Unix ns = (win-offset)*1000.
    const RESP_UNIX_NS: i64 = (RESP_WIN_US as i64 - 11_644_473_600_000_000) * 1_000;

    #[test]
    fn parses_request_response_and_times() {
        let req = request_msg("GET", &[("accept", "*/*")]);
        let resp = response_msg(
            200,
            "",
            1, // CORS_TYPE
            &[
                ("content-type", "application/javascript; charset=UTF-8"),
                ("content-encoding", "br"),
            ],
            RESP_WIN_US,
            "application/javascript",
        );
        let meta_bytes = metadata_msg(&req, &resp, RESP_WIN_US);
        let meta = parse_cachestorage_metadata(&meta_bytes);

        assert_eq!(meta.request_method.as_deref(), Some("GET"));
        assert_eq!(meta.request_headers, vec![("accept".into(), "*/*".into())]);
        assert_eq!(meta.http_status, Some(200));
        assert_eq!(meta.response_type, Some(1));
        assert_eq!(meta.response_type_name(), Some("cors"));
        assert_eq!(
            meta.content_type(),
            Some("application/javascript; charset=UTF-8")
        );
        assert_eq!(meta.content_encoding(), Some("br"));
        assert_eq!(meta.mime_type.as_deref(), Some("application/javascript"));
        assert_eq!(meta.response_time_ns, Some(RESP_UNIX_NS));
        assert_eq!(meta.entry_time_ns, Some(RESP_UNIX_NS));
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let req = request_msg("POST", &[]);
        let resp = response_msg(204, "No Content", 2, &[("X-Custom", "v")], 0, "");
        let meta = parse_cachestorage_metadata(&metadata_msg(&req, &resp, 0));
        assert_eq!(meta.request_method.as_deref(), Some("POST"));
        assert_eq!(meta.http_status, Some(204));
        assert_eq!(meta.header("x-CUSTOM"), Some("v"));
        // Zero times -> None.
        assert_eq!(meta.response_time_ns, None);
        assert_eq!(meta.entry_time_ns, None);
    }

    #[test]
    fn garbage_metadata_yields_empty_no_panic() {
        let meta = parse_cachestorage_metadata(&[0xff, 0x81, 0x80, 0x00, 0x2a]);
        assert!(meta.request_method.is_none());
        assert!(meta.headers.is_empty());
        let meta2 = parse_cachestorage_metadata(&[]);
        assert!(meta2.http_status.is_none());
    }
}
