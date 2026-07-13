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
    /// Chromium-family legacy Blockfile (`index` + `data_0..3`; GPUCache,
    /// ShaderCache, Code Cache).
    ChromiumBlockfile,
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
            CacheSource::ChromiumBlockfile => "chromium-blockfile",
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
    /// The full HTTP status line (e.g. `HTTP/1.1 200 OK`), if recovered.
    pub status_line: Option<String>,
    /// Response headers in the order recovered from the cache. Carried so a
    /// WARC `response` record can reproduce the original HTTP response block.
    pub headers: Vec<(String, String)>,
    /// The usable (decoded) resource body.
    pub body: Vec<u8>,
    /// The on-disk file this resource came from.
    pub source_file: PathBuf,
}

impl IndexedResource {
    /// `true` when the resource is an HTML document.
    #[must_use]
    pub fn is_html(&self) -> bool {
        self.content_type
            .as_deref()
            .is_some_and(|c| c.starts_with("text/html") || c.starts_with("application/xhtml"))
    }

    /// `true` when the resource is an image.
    #[must_use]
    pub fn is_image(&self) -> bool {
        self.content_type
            .as_deref()
            .is_some_and(|c| c.starts_with("image/"))
    }

    /// The MIME type to use in a `data:` URI, falling back to a safe default.
    #[must_use]
    pub fn data_uri_mime(&self) -> &str {
        self.content_type
            .as_deref()
            .unwrap_or("application/octet-stream")
    }
}

/// A URL-keyed index of cached resources with fragment-insensitive lookup.
#[derive(Debug, Default)]
pub struct ResourceIndex {
    by_url: HashMap<String, IndexedResource>,
    order: Vec<String>,
}

/// Normalize a URL for indexing/lookup: parse, drop the fragment, and keep the
/// scheme, host (lower-cased by the parser), port, path, and query. On a parse
/// failure the trimmed input is returned unchanged so opaque keys still match
/// themselves.
#[must_use]
pub fn normalize_url(raw: &str) -> String {
    match url::Url::parse(raw.trim()) {
        Ok(mut u) => {
            u.set_fragment(None);
            u.to_string()
        }
        Err(_) => raw.trim().to_string(),
    }
}

/// Resolve a possibly-relative reference against a base URL, returning the
/// absolute, normalized form. Returns `None` when neither the reference nor the
/// base yields a usable absolute URL.
#[must_use]
pub fn resolve_ref(base: &str, reference: &str) -> Option<String> {
    let reference = reference.trim();
    if reference.is_empty() {
        return None;
    }
    if let Ok(base_url) = url::Url::parse(base.trim()) {
        if let Ok(mut joined) = base_url.join(reference) {
            joined.set_fragment(None);
            return Some(joined.to_string());
        }
    }
    // No usable base — accept the reference only if it is already absolute.
    url::Url::parse(reference).ok().map(|mut u| {
        u.set_fragment(None);
        u.to_string()
    })
}

impl ResourceIndex {
    /// A new, empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a resource. A later insert for the same normalized URL replaces
    /// the earlier one (keeps a single entry per key, insertion order stable).
    pub fn insert(&mut self, resource: IndexedResource) {
        let key = normalize_url(&resource.url);
        if !self.by_url.contains_key(&key) {
            self.order.push(key.clone());
        }
        self.by_url.insert(key, resource);
    }

    /// Look up a resource by URL (normalized internally).
    #[must_use]
    pub fn get(&self, url: &str) -> Option<&IndexedResource> {
        self.by_url.get(&normalize_url(url))
    }

    /// Resolve a reference against `base` and look up the result.
    #[must_use]
    pub fn resolve(&self, base: &str, reference: &str) -> Option<&IndexedResource> {
        let abs = resolve_ref(base, reference)?;
        self.by_url.get(&normalize_url(&abs))
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

    /// Every indexed HTML document, in insertion order.
    #[must_use]
    pub fn html_entries(&self) -> Vec<&IndexedResource> {
        self.iter().filter(|r| r.is_html()).collect()
    }

    /// Every indexed image, in insertion order.
    #[must_use]
    pub fn images(&self) -> Vec<&IndexedResource> {
        self.iter().filter(|r| r.is_image()).collect()
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
            status_line: Some("HTTP/1.1 200 OK".to_string()),
            headers: Vec::new(),
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
