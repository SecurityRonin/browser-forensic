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

use std::path::{Path, PathBuf};

use protobuf_forensic_core::{decode, Field, FieldValue};

use crate::decompress::{decode_body, DecompressLimits};
use crate::error::CacheError;
use crate::simple::parse_simple_entry;

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
/// Decode a repeated `CacheHeaderMap` field (name(1), value(2)) into ordered
/// `(name, value)` pairs.
fn header_pairs(parent: &[Field], number: u64) -> Vec<(String, String)> {
    repeated_len_raw(parent, number)
        .map(|raw| {
            let hf = fields(raw);
            let name = str_field(&hf, 1).unwrap_or_default();
            let value = str_field(&hf, 2).unwrap_or_default();
            (name, value)
        })
        .collect()
}

#[must_use]
pub fn parse_cachestorage_metadata(stream0: &[u8]) -> CacheStorageMeta {
    let top = fields(stream0);

    // CacheRequest request = 1
    let (request_method, request_headers) = match len_raw(&top, 1) {
        Some(raw) => {
            let rf = fields(raw);
            (str_field(&rf, 1), header_pairs(&rf, 2))
        }
        None => (None, Vec::new()),
    };

    // CacheResponse response = 2
    let mut http_status = None;
    let mut status_text = None;
    let mut response_type = None;
    let mut headers = Vec::new();
    let mut mime_type = None;
    let mut response_time_ns = None;
    if let Some(raw) = len_raw(&top, 2) {
        let rf = fields(raw);
        http_status = varint_field(&rf, 1).and_then(|v| u16::try_from(v).ok());
        status_text = str_field(&rf, 2);
        response_type = varint_field(&rf, 3).map(|v| i64::from_le_bytes(v.to_le_bytes()));
        headers = header_pairs(&rf, 4);
        mime_type = str_field(&rf, 13);
        response_time_ns = varint_field(&rf, 6).and_then(|v| {
            crate::http_meta::win_micros_to_unix_ns(i64::from_le_bytes(v.to_le_bytes()))
        });
    }

    // CacheMetadata.entry_time = 3
    let entry_time_ns = varint_field(&top, 3)
        .and_then(|v| crate::http_meta::win_micros_to_unix_ns(i64::from_le_bytes(v.to_le_bytes())));

    CacheStorageMeta {
        request_method,
        request_headers,
        http_status,
        status_text,
        response_type,
        headers,
        mime_type,
        response_time_ns,
        entry_time_ns,
    }
}

/// A single cached HTTP response recovered from a Service Worker CacheStorage
/// (Cache API) entry, with cache-name + origin attribution and the request
/// method/headers that keyed it.
///
/// Forensic reading: "the response for `url`, cached by `storage_key`'s service
/// worker under cache `cache_name`". This is a *cached* response — consistent
/// with the app having fetched `url` — and cached is not the same as rendered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheStorageResource {
    /// The request URL — the SimpleCache entry key.
    pub url: String,
    /// The cache name (`caches.open(name)`), from the `index.txt`.
    pub cache_name: String,
    /// The on-disk cache directory (UUID) this entry lives in.
    pub cache_dir: String,
    /// The origin/storage-key attribution from the `index.txt`, if recovered.
    pub storage_key: Option<String>,
    /// The request method (`GET`/`POST`/…). Note: the Cache API metadata proto
    /// stores the method and request headers but **not** the request entity
    /// body, so a POST body is not recoverable from this artifact.
    pub request_method: Option<String>,
    /// The request headers stored with the entry, in file order.
    pub request_headers: Vec<(String, String)>,
    /// HTTP response status code.
    pub http_status: Option<u16>,
    /// HTTP response status text.
    pub status_text: Option<String>,
    /// The Fetch response type enum (`basic`/`cors`/`opaque`/…) as a raw value.
    pub response_type: Option<i64>,
    /// Response headers in file order.
    pub headers: Vec<(String, String)>,
    /// `Content-Type` response header value, if present.
    pub content_type: Option<String>,
    /// `Content-Encoding` response header value. Metadata about the original
    /// wire response; the stored body is already decoded (see `body`).
    pub content_encoding: Option<String>,
    /// Computed MIME type from the metadata, if stored.
    pub mime_type: Option<String>,
    /// Response time (Unix nanoseconds), if recovered.
    pub response_time_ns: Option<i64>,
    /// Cache entry time (Unix nanoseconds), if recovered.
    pub entry_time_ns: Option<i64>,
    /// The body exactly as stored on disk (stream 1).
    pub raw_body: Vec<u8>,
    /// The usable response body. The Cache API stores the already-decoded
    /// delivered body, so this normally equals `raw_body`; if an entry is
    /// genuinely wire-compressed it is inflated here (see `body_note`).
    pub body: Vec<u8>,
    /// Any caveat about the body (declared-but-not-applied encoding, or a
    /// successful re-inflation).
    pub body_note: Option<String>,
    /// The `[hash]_0` file this resource came from.
    pub source_file: PathBuf,
}

/// Build a [`CacheStorageResource`] from the raw bytes of a CacheStorage
/// `[hash]_0` entry plus its cache attribution.
///
/// # Errors
/// Returns a [`CacheError`] only when the SimpleCache entry framing is invalid.
pub fn resource_from_cachestorage_entry(
    _data: &[u8],
    _cache_name: &str,
    _cache_dir: &str,
    _storage_key: Option<&str>,
    _source_file: PathBuf,
    _limits: &DecompressLimits,
) -> Result<CacheStorageResource, CacheError> {
    // GREEN in the next commit.
    Ok(CacheStorageResource::default())
}

/// Enumerate every recoverable [`CacheStorageResource`] in a single cache's
/// disk_cache directory (`<origin-hash>/<uuid>/`). Best-effort: malformed
/// entries are skipped, never panicked on.
#[must_use]
pub fn parse_cachestorage_cache_dir(
    _uuid_dir: &Path,
    _cache_name: &str,
    _cache_dir: &str,
    _storage_key: Option<&str>,
    _limits: &DecompressLimits,
) -> Vec<CacheStorageResource> {
    // GREEN in the next commit.
    Vec::new()
}

/// Enumerate every recoverable [`CacheStorageResource`] under a CacheStorage
/// path, using default decompression limits.
///
/// `path` may be a single `<origin-hash>/` directory (containing `index.txt`)
/// or the `CacheStorage/` root (whose immediate children are origin-hash dirs);
/// both are handled. Best-effort and panic-free.
#[must_use]
pub fn parse_cachestorage_dir(path: &Path) -> Vec<CacheStorageResource> {
    parse_cachestorage_dir_with(path, &DecompressLimits::default())
}

/// Enumerate every recoverable [`CacheStorageResource`], with explicit limits.
#[must_use]
pub fn parse_cachestorage_dir_with(
    _path: &Path,
    _limits: &DecompressLimits,
) -> Vec<CacheStorageResource> {
    // GREEN in the next commit.
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simple::{EOF_MAGIC, HEADER_MAGIC};
    use tempfile::TempDir;

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

    // --- full CacheStorage `_0` entry + directory fixtures ---

    fn push_eof(out: &mut Vec<u8>, flags: u32, stream_size: u32) {
        out.extend_from_slice(&EOF_MAGIC.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // data_crc32
        out.extend_from_slice(&stream_size.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]); // pad to 24
    }

    /// Build a SimpleCache `_0` file: stream 1 = body, stream 0 = CacheMetadata
    /// proto (mirrors the layout in `simple.rs`).
    fn build_cs_entry(url: &str, body: &[u8], meta: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&HEADER_MAGIC.to_le_bytes());
        out.extend_from_slice(&5u32.to_le_bytes()); // version 5 (as seen on disk)
        out.extend_from_slice(&(url.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // key_hash
        out.extend_from_slice(&[0u8; 4]); // pad to 24
        out.extend_from_slice(url.as_bytes());
        out.extend_from_slice(body);
        push_eof(&mut out, 1, body.len() as u32); // stream 1 EOF (FLAG_HAS_CRC32)
        out.extend_from_slice(meta);
        push_eof(&mut out, 1, meta.len() as u32); // stream 0 EOF
        out
    }

    fn simple_get_meta(status: u64, headers: &[(&str, &str)], body_mime: &str) -> Vec<u8> {
        let req = request_msg("GET", &[]);
        let resp = response_msg(status, "", 2, headers, RESP_WIN_US, body_mime);
        metadata_msg(&req, &resp, RESP_WIN_US)
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn resource_from_entry_captures_request_and_response() {
        let body = b"[\"en-US\",\"en-GB\"]";
        let meta = simple_get_meta(
            200,
            &[("content-type", "application/json")],
            "application/json",
        );
        let data = build_cs_entry("https://slack.com/locales", body, &meta);
        let res = resource_from_cachestorage_entry(
            &data,
            "config-cache",
            "68f8-uuid",
            Some("https://app.slack.com/"),
            PathBuf::from("/tmp/abc_0"),
            &DecompressLimits::default(),
        )
        .unwrap();
        assert_eq!(res.url, "https://slack.com/locales");
        assert_eq!(res.cache_name, "config-cache");
        assert_eq!(res.cache_dir, "68f8-uuid");
        assert_eq!(res.storage_key.as_deref(), Some("https://app.slack.com/"));
        assert_eq!(res.request_method.as_deref(), Some("GET"));
        assert_eq!(res.http_status, Some(200));
        assert_eq!(res.content_type.as_deref(), Some("application/json"));
        assert_eq!(res.mime_type.as_deref(), Some("application/json"));
        assert_eq!(res.response_time_ns, Some(RESP_UNIX_NS));
        assert_eq!(res.raw_body, body);
        assert_eq!(res.body, body);
        assert!(res.body_note.is_none());
    }

    #[test]
    fn body_stored_decoded_when_encoding_declared_but_plaintext() {
        // Real Cache API behaviour: header says `br`, body is plaintext JS.
        let body = b"\"use strict\";console.log(1)";
        let meta = simple_get_meta(
            200,
            &[
                ("content-type", "application/javascript"),
                ("content-encoding", "br"),
            ],
            "application/javascript",
        );
        let data = build_cs_entry("https://a.slack-edge.com/app.js", body, &meta);
        let res = resource_from_cachestorage_entry(
            &data,
            "gantry",
            "uuid",
            None,
            PathBuf::from("/tmp/x_0"),
            &DecompressLimits::default(),
        )
        .unwrap();
        assert_eq!(res.content_encoding.as_deref(), Some("br"));
        // Body kept as the stored (already-delivered) bytes, not a failed decode.
        assert_eq!(res.body, body);
        let note = res.body_note.expect("note explaining stored-decoded body");
        assert!(note.contains("stored decoded"), "{note}");
    }

    #[test]
    fn wire_compressed_body_is_reinflated() {
        let plain = b"genuinely gzip-compressed payload 0123456789";
        let body = gzip(plain);
        let meta = simple_get_meta(200, &[("content-encoding", "gzip")], "text/plain");
        let data = build_cs_entry("https://x/y", &body, &meta);
        let res = resource_from_cachestorage_entry(
            &data,
            "c",
            "u",
            None,
            PathBuf::from("/tmp/z_0"),
            &DecompressLimits::default(),
        )
        .unwrap();
        assert_eq!(res.raw_body, body);
        assert_eq!(res.body, plain);
        assert!(res.body_note.is_some());
    }

    #[test]
    fn dir_walks_index_and_caches() {
        let root = TempDir::new().unwrap();
        let origin_hash = root.path().join("4c237d5e33167c88");
        let uuid = "68f870d4-ed4e-4331-b7bd-7faed95e3d5e";
        std::fs::create_dir_all(origin_hash.join(uuid)).unwrap();
        // index.txt maps config-cache -> uuid, storage_key = app origin.
        let index = build_index(&[("config-cache", uuid, None)], "https://app.slack.com/");
        std::fs::write(origin_hash.join("index.txt"), index).unwrap();
        // one entry in the cache dir
        let meta = simple_get_meta(200, &[("content-type", "text/html")], "text/html");
        let entry = build_cs_entry("https://slack.com/page", b"<html>hi</html>", &meta);
        std::fs::write(origin_hash.join(uuid).join("aaaa1111_0"), entry).unwrap();
        // non-entry files must be ignored
        std::fs::write(origin_hash.join(uuid).join("index"), b"junk").unwrap();

        let mut res = parse_cachestorage_dir(&origin_hash);
        assert_eq!(res.len(), 1);
        let r = res.pop().unwrap();
        assert_eq!(r.url, "https://slack.com/page");
        assert_eq!(r.cache_name, "config-cache");
        assert_eq!(r.storage_key.as_deref(), Some("https://app.slack.com/"));
        assert_eq!(r.body, b"<html>hi</html>");
    }

    #[test]
    fn root_dir_with_origin_hash_children_walked() {
        // Passing the CacheStorage root (children are origin-hash dirs) works.
        let root = TempDir::new().unwrap();
        let origin_hash = root.path().join("deadbeefcafef00d");
        let uuid = "11111111-2222-3333-4444-555555555555";
        std::fs::create_dir_all(origin_hash.join(uuid)).unwrap();
        let index = build_index(&[("v1", uuid, None)], "https://ex.test/");
        std::fs::write(origin_hash.join("index.txt"), index).unwrap();
        let meta = simple_get_meta(200, &[], "text/plain");
        let entry = build_cs_entry("https://ex.test/x", b"body", &meta);
        std::fs::write(origin_hash.join(uuid).join("bbbb2222_0"), entry).unwrap();

        let res = parse_cachestorage_dir(root.path());
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].cache_name, "v1");
    }

    #[test]
    fn missing_index_yields_empty_no_panic() {
        let root = TempDir::new().unwrap();
        // A directory with no index.txt anywhere.
        std::fs::create_dir_all(root.path().join("some-uuid")).unwrap();
        let res = parse_cachestorage_dir(root.path());
        assert!(res.is_empty());
        // A path that doesn't exist at all.
        let res2 = parse_cachestorage_dir(Path::new("/nonexistent/cachestorage"));
        assert!(res2.is_empty());
    }
}
