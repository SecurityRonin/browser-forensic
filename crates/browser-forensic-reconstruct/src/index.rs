//! URL-keyed index of cached resources, built from any/all cache backends.
//!
//! A reconstruction resolves each sub-resource reference (a `<script src>`, a
//! CSS `url(...)`, …) against this index. Lookups normalize the URL (drop the
//! fragment, lower-case the host) so a reference and its cached key match even
//! when they differ only cosmetically.

use std::collections::HashMap;
use std::path::PathBuf;

/// Which on-disk cache backend a resource was recovered from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheSource {
    /// Chromium-family SimpleCache (`Cache/Cache_Data/`).
    ChromiumSimpleCache,
    /// Firefox `cache2/entries/`.
    FirefoxCache2,
    /// Safari `Cache.db`.
    SafariCacheDb,
    /// Service Worker CacheStorage (Cache API).
    CacheStorage,
}

impl CacheSource {
    /// A stable, human/machine-readable label for the backend.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            CacheSource::ChromiumSimpleCache => "chromium-simplecache",
            CacheSource::FirefoxCache2 => "firefox-cache2",
            CacheSource::SafariCacheDb => "safari-cachedb",
            CacheSource::CacheStorage => "cachestorage",
        }
    }
}

/// A single cached resource, normalized across backends.
#[derive(Debug, Clone)]
pub struct IndexedResource {
    /// The resource URL exactly as recovered (the cache key).
    pub url: String,
    /// The backend it came from.
    pub source: CacheSource,
    /// This resource's own cached timestamp (Unix nanoseconds), if known.
    pub cached_time_ns: Option<i64>,
    /// `Content-Type` value with any parameters stripped, lower-cased.
    pub content_type: Option<String>,
    /// HTTP status code, if known.
    pub http_status: Option<u16>,
    /// The usable (decoded) resource body.
    pub body: Vec<u8>,
    /// The on-disk file this resource came from.
    pub source_file: PathBuf,
}

impl IndexedResource {
    /// `true` when the resource is an HTML document.
    #[must_use]
    pub fn is_html(&self) -> bool {
        let _ = self;
        false
    }

    /// `true` when the resource is an image.
    #[must_use]
    pub fn is_image(&self) -> bool {
        let _ = self;
        false
    }

    /// The MIME type to use in a `data:` URI, falling back to a safe default.
    #[must_use]
    pub fn data_uri_mime(&self) -> &str {
        let _ = self;
        "application/octet-stream"
    }
}

/// A URL-keyed index of cached resources with fragment-insensitive lookup.
#[derive(Debug, Default)]
pub struct ResourceIndex {
    by_url: HashMap<String, IndexedResource>,
    order: Vec<String>,
}

/// Normalize a URL for indexing/lookup (RED stub — not yet implemented).
#[must_use]
pub fn normalize_url(raw: &str) -> String {
    raw.to_string()
}

/// Resolve a possibly-relative reference against a base URL (RED stub).
#[must_use]
pub fn resolve_ref(_base: &str, _reference: &str) -> Option<String> {
    None
}

impl ResourceIndex {
    /// A new, empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a resource (RED stub — does nothing).
    pub fn insert(&mut self, _resource: IndexedResource) {}

    /// Look up a resource by URL (RED stub).
    #[must_use]
    pub fn get(&self, _url: &str) -> Option<&IndexedResource> {
        None
    }

    /// Resolve a reference against `base` and look up the result (RED stub).
    #[must_use]
    pub fn resolve(&self, _base: &str, _reference: &str) -> Option<&IndexedResource> {
        None
    }

    /// Number of indexed resources.
    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// `true` when the index holds no resources.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Iterate resources in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &IndexedResource> {
        self.order.iter().filter_map(move |k| self.by_url.get(k))
    }

    /// Every indexed HTML document, in insertion order (RED stub).
    #[must_use]
    pub fn html_entries(&self) -> Vec<&IndexedResource> {
        Vec::new()
    }

    /// Every indexed image, in insertion order (RED stub).
    #[must_use]
    pub fn images(&self) -> Vec<&IndexedResource> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(url: &str, ct: &str, body: &[u8]) -> IndexedResource {
        IndexedResource {
            url: url.to_string(),
            source: CacheSource::ChromiumSimpleCache,
            cached_time_ns: Some(1_700_000_000_000_000_000),
            content_type: Some(ct.to_string()),
            http_status: Some(200),
            body: body.to_vec(),
            source_file: PathBuf::from("/tmp/x_0"),
        }
    }

    #[test]
    fn normalize_drops_fragment() {
        assert_eq!(normalize_url("https://ex.com/a#frag"), "https://ex.com/a");
    }

    #[test]
    fn get_is_fragment_insensitive() {
        let mut idx = ResourceIndex::new();
        idx.insert(res("https://ex.com/style.css", "text/css", b"body{}"));
        assert!(idx.get("https://ex.com/style.css#x").is_some());
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn resolve_relative_reference() {
        let mut idx = ResourceIndex::new();
        idx.insert(res(
            "https://ex.com/assets/logo.png",
            "image/png",
            b"\x89PNG",
        ));
        let hit = idx.resolve("https://ex.com/page/index.html", "../assets/logo.png");
        assert!(hit.is_some(), "relative ref should resolve into the index");
        assert_eq!(hit.unwrap().url, "https://ex.com/assets/logo.png");
    }

    #[test]
    fn html_and_image_filters() {
        let mut idx = ResourceIndex::new();
        idx.insert(res(
            "https://ex.com/",
            "text/html; charset=utf-8",
            b"<html>",
        ));
        idx.insert(res("https://ex.com/a.png", "image/png", b"\x89PNG"));
        idx.insert(res("https://ex.com/s.css", "text/css", b"x{}"));
        assert_eq!(idx.html_entries().len(), 1);
        assert_eq!(idx.images().len(), 1);
    }

    #[test]
    fn duplicate_url_keeps_single_entry_latest_wins() {
        let mut idx = ResourceIndex::new();
        idx.insert(res("https://ex.com/a", "text/plain", b"old"));
        idx.insert(res("https://ex.com/a", "text/plain", b"new"));
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.get("https://ex.com/a").unwrap().body, b"new");
    }
}
