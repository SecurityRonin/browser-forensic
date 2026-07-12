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
pub fn parse_cachestorage_index(_bytes: &[u8]) -> CacheStorageIndex {
    // GREEN in the next commit.
    CacheStorageIndex::default()
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
}
