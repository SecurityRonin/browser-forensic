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

/// Extract the real request URL from a browser cache key.
///
/// Modern browsers partition the HTTP cache by network-isolation key, so the
/// on-disk key is not a bare URL:
/// * Chromium split-cache keys look like
///   `1/0/_dk_<top-frame-site> <frame-site> <url>` — space-separated tokens
///   with the request URL last (URLs never contain a raw space).
/// * Firefox cache2 keys prefix a partition with `,:` before the URL
///   (`O^partitionKey=...,:https://...`).
///
/// Both prefixes are stripped by taking the segment after the last `,:` and
/// then the last whitespace-separated token. A key that is already a clean URL
/// is returned unchanged.
#[must_use]
pub fn extract_request_url(key: &str) -> String {
    let trimmed = key.trim();
    // Firefox partition: the URL follows the last `,:`.
    let after_partition = trimmed.rsplit(",:").next().unwrap_or(trimmed);
    // Chromium NIK/double-key prefix: the URL is the last space-separated token.
    let last_token = after_partition
        .rsplit(char::is_whitespace)
        .next()
        .unwrap_or(after_partition);
    last_token.to_string()
}

/// Convert a [`CachedResource`] (SimpleCache / cache2 / Safari) into the
/// normalized index type, choosing the usable (decoded) body.
#[must_use]
pub fn indexed_from_cached(res: &CachedResource, source: CacheSource) -> IndexedResource {
    let body = if res.body_decoded {
        res.decoded_body.clone()
    } else {
        res.raw_body.clone()
    };
    IndexedResource {
        url: extract_request_url(&res.url),
        source,
        cached_time_ns: res.response_time_ns.or(res.request_time_ns),
        content_type: norm_ct(res.content_type.as_deref()),
        http_status: res.http_status,
        status_line: res.status_line.clone(),
        headers: res.headers.clone(),
        body,
        source_file: res.source_file.clone(),
    }
}

/// Convert a [`CacheStorageResource`] (Cache API) into the normalized index
/// type. The Cache API stores the already-delivered body.
#[must_use]
pub fn indexed_from_cachestorage(res: &CacheStorageResource) -> IndexedResource {
    let status_line = res.http_status.map(|s| {
        let text = res.status_text.clone().unwrap_or_default();
        format!("HTTP/1.1 {s} {text}").trim_end().to_string()
    });
    IndexedResource {
        url: extract_request_url(&res.url),
        source: CacheSource::CacheStorage,
        cached_time_ns: res.response_time_ns.or(res.entry_time_ns),
        content_type: norm_ct(res.content_type.as_deref()),
        http_status: res.http_status,
        status_line,
        headers: res.headers.clone(),
        body: res.body.clone(),
        source_file: res.source_file.clone(),
    }
}

impl ResourceIndex {
    /// Build an index from a cache path — a single cache directory/file or a
    /// whole profile. Every applicable backend is tried against the path and a
    /// fixed set of well-known sub-paths, and results are merged (later inserts
    /// win per URL). Best-effort and panic-free.
    #[must_use]
    pub fn from_cache_dir(path: &Path) -> Self {
        let mut idx = ResourceIndex::new();
        collect_into(path, &mut idx);
        idx
    }
}

/// Add SimpleCache resources found directly under `dir`.
fn add_simple(dir: &Path, idx: &mut ResourceIndex) {
    for res in parse_simple_cache_dir(dir) {
        idx.insert(indexed_from_cached(&res, CacheSource::ChromiumSimpleCache));
    }
}

/// Add Firefox cache2 resources found directly under `dir`.
fn add_firefox(dir: &Path, idx: &mut ResourceIndex) {
    for res in parse_firefox_cache2_dir(dir) {
        idx.insert(indexed_from_cached(&res, CacheSource::FirefoxCache2));
    }
}

/// Add Safari resources from a `Cache.db` file.
fn add_safari(db: &Path, idx: &mut ResourceIndex) {
    if db.is_file() {
        for res in parse_safari_cache_db(db) {
            idx.insert(indexed_from_cached(&res, CacheSource::SafariCacheDb));
        }
    }
}

/// Add Service Worker CacheStorage resources found under `dir`.
fn add_cachestorage(dir: &Path, idx: &mut ResourceIndex) {
    if dir.is_dir() {
        for res in parse_cachestorage_dir(dir) {
            idx.insert(indexed_from_cachestorage(&res));
        }
    }
}

/// Try every backend against `path` and a fixed set of well-known sub-paths.
/// The parsers are individually best-effort (they return empty on a
/// non-matching directory), so calling all of them is safe.
fn collect_into(path: &Path, idx: &mut ResourceIndex) {
    // A single Safari Cache.db file.
    if path.is_file() {
        add_safari(path, idx);
        return;
    }
    if !path.is_dir() {
        return;
    }

    // Chromium SimpleCache: the path itself or the standard sub-layouts.
    for sub in [
        path.to_path_buf(),
        path.join("Cache_Data"),
        path.join("Cache").join("Cache_Data"),
        path.join("Default").join("Cache").join("Cache_Data"),
    ] {
        add_simple(&sub, idx);
    }

    // Firefox cache2 entries.
    for sub in [
        path.to_path_buf(),
        path.join("entries"),
        path.join("cache2").join("entries"),
    ] {
        add_firefox(&sub, idx);
    }

    // Safari Cache.db files.
    for sub in [path.join("Cache.db"), path.join("Cache").join("Cache.db")] {
        add_safari(&sub, idx);
    }

    // Service Worker CacheStorage.
    for sub in [
        path.to_path_buf(),
        path.join("Service Worker").join("CacheStorage"),
        path.join("Default")
            .join("Service Worker")
            .join("CacheStorage"),
    ] {
        add_cachestorage(&sub, idx);
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
    fn extract_url_strips_chromium_double_key_prefix() {
        // Chromium partitioned (split-cache) key: NIK prefix + `_dk_` + the
        // top-frame site, the frame site, then the real request URL last.
        let key = "1/0/_dk_http://localhost http://localhost http://localhost:8137/index.html";
        assert_eq!(extract_request_url(key), "http://localhost:8137/index.html");
    }

    #[test]
    fn extract_url_passes_clean_url_through() {
        assert_eq!(
            extract_request_url("https://ex.com/a?b=1"),
            "https://ex.com/a?b=1"
        );
    }

    #[test]
    fn extract_url_strips_firefox_partition_prefix() {
        // Firefox cache2 keys prefix a partition with `,:` before the URL.
        let key = "O^partitionKey=%28https%2Cexample.com%29,:https://ex.com/style.css";
        assert_eq!(extract_request_url(key), "https://ex.com/style.css");
    }

    #[test]
    fn cached_conversion_cleans_partitioned_key() {
        let mut res = cached("https://placeholder/", "text/html", b"<html>");
        res.url =
            "1/0/_dk_http://localhost http://localhost http://localhost:8137/page.html".to_string();
        let ir = indexed_from_cached(&res, CacheSource::ChromiumSimpleCache);
        assert_eq!(ir.url, "http://localhost:8137/page.html");
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
