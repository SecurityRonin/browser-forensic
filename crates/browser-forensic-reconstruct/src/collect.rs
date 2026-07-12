//! Build a [`ResourceIndex`] from the on-disk cache backends.
//!
//! Converts the two `browser-forensic-cache` recovery types
//! ([`CachedResource`] from SimpleCache/cache2/Safari, [`CacheStorageResource`]
//! from the Cache API) into the normalized [`IndexedResource`], and walks a
//! user-supplied path — a single cache directory/file or a whole profile —
//! trying every applicable backend and merging the results.

use std::path::Path;

use browser_forensic_cache::{
    parse_cachestorage_dir, parse_firefox_cache2_dir, parse_safari_cache_db,
    parse_simple_cache_dir, CacheStorageResource, CachedResource,
};

use crate::index::{CacheSource, IndexedResource, ResourceIndex};

/// Strip `Content-Type` parameters and lower-case, for use as a `data:` URI
/// MIME and for html/image classification. The full header is preserved
/// separately for WARC fidelity.
fn norm_ct(ct: Option<&str>) -> Option<String> {
    ct.and_then(|c| c.split(';').next())
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(str::to_ascii_lowercase)
}

/// Convert a [`CachedResource`] (RED stub — returns an empty placeholder).
#[must_use]
pub fn indexed_from_cached(_res: &CachedResource, _source: CacheSource) -> IndexedResource {
    IndexedResource {
        url: String::new(),
        source: CacheSource::ChromiumSimpleCache,
        cached_time_ns: None,
        content_type: None,
        http_status: None,
        status_line: None,
        headers: Vec::new(),
        body: Vec::new(),
        source_file: std::path::PathBuf::new(),
    }
}

/// Convert a [`CacheStorageResource`] (RED stub — returns an empty placeholder).
#[must_use]
pub fn indexed_from_cachestorage(_res: &CacheStorageResource) -> IndexedResource {
    IndexedResource {
        url: String::new(),
        source: CacheSource::CacheStorage,
        cached_time_ns: None,
        content_type: None,
        http_status: None,
        status_line: None,
        headers: Vec::new(),
        body: Vec::new(),
        source_file: std::path::PathBuf::new(),
    }
}

impl ResourceIndex {
    /// Build an index from a cache path (RED stub — returns empty).
    #[must_use]
    pub fn from_cache_dir(_path: &Path) -> Self {
        let _ = (
            parse_simple_cache_dir as fn(&Path) -> Vec<CachedResource>,
            parse_firefox_cache2_dir as fn(&Path) -> Vec<CachedResource>,
            parse_safari_cache_db as fn(&Path) -> Vec<CachedResource>,
            parse_cachestorage_dir as fn(&Path) -> Vec<CacheStorageResource>,
        );
        ResourceIndex::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn cached(url: &str, ct: &str, decoded: &[u8]) -> CachedResource {
        CachedResource {
            url: url.to_string(),
            http_status: Some(200),
            status_line: Some("HTTP/1.1 200 OK".to_string()),
            headers: vec![("Content-Type".to_string(), ct.to_string())],
            content_type: Some(ct.to_string()),
            content_encoding: Some("gzip".to_string()),
            request_time_ns: Some(111),
            response_time_ns: Some(222),
            raw_body: b"COMPRESSED".to_vec(),
            decoded_body: decoded.to_vec(),
            body_decoded: true,
            decode_note: None,
            source_file: PathBuf::from("/tmp/abc_0"),
            sparse_file: None,
        }
    }

    #[test]
    fn cached_conversion_maps_fields_and_picks_decoded_body() {
        let res = cached("https://ex.com/", "text/html; charset=utf-8", b"<html>hi");
        let ir = indexed_from_cached(&res, CacheSource::ChromiumSimpleCache);
        assert_eq!(ir.url, "https://ex.com/");
        assert_eq!(ir.source, CacheSource::ChromiumSimpleCache);
        // Decoded body chosen over the still-compressed raw body.
        assert_eq!(ir.body, b"<html>hi");
        // Content-Type parameters stripped, lower-cased.
        assert_eq!(ir.content_type.as_deref(), Some("text/html"));
        assert!(ir.is_html());
        // Response time preferred as the cached timestamp.
        assert_eq!(ir.cached_time_ns, Some(222));
        assert_eq!(ir.status_line.as_deref(), Some("HTTP/1.1 200 OK"));
        // Original headers carried through for WARC.
        assert_eq!(ir.headers.len(), 1);
    }

    #[test]
    fn cached_conversion_uses_raw_when_not_decoded() {
        let mut res = cached("https://ex.com/x", "image/png", b"");
        res.body_decoded = false;
        res.raw_body = b"RAWPNG".to_vec();
        let ir = indexed_from_cached(&res, CacheSource::FirefoxCache2);
        assert_eq!(ir.body, b"RAWPNG");
    }

    #[test]
    fn cachestorage_conversion_maps_fields() {
        let res = CacheStorageResource {
            url: "https://ex.com/api".to_string(),
            content_type: Some("application/json".to_string()),
            http_status: Some(200),
            status_text: Some("OK".to_string()),
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            response_time_ns: Some(999),
            entry_time_ns: Some(1),
            body: b"{}".to_vec(),
            ..Default::default()
        };
        let ir = indexed_from_cachestorage(&res);
        assert_eq!(ir.url, "https://ex.com/api");
        assert_eq!(ir.source, CacheSource::CacheStorage);
        assert_eq!(ir.body, b"{}");
        assert_eq!(ir.content_type.as_deref(), Some("application/json"));
        assert_eq!(ir.cached_time_ns, Some(999));
        assert!(ir.status_line.as_deref().unwrap_or("").contains("200"));
    }

    #[test]
    fn from_empty_dir_is_empty_no_panic() {
        let dir = TempDir::new().unwrap();
        let idx = ResourceIndex::from_cache_dir(dir.path());
        assert!(idx.is_empty());
    }

    #[test]
    fn from_nonexistent_path_is_empty_no_panic() {
        let idx = ResourceIndex::from_cache_dir(Path::new("/no/such/path/xyz"));
        assert!(idx.is_empty());
    }
}
