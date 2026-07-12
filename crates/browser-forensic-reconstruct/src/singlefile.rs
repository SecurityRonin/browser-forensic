//! Self-contained single-file HTML reconstruction.
//!
//! Given the cache index and a target page URL, parse the cached HTML and
//! resolve every sub-resource reference (`<link rel=stylesheet>`,
//! `<script src>`, `<img src>`/`srcset`, `<source>`, favicons, and `url(...)`
//! in inline/linked CSS) against the index. Found resources are inlined as
//! `data:` URIs; missing ones are left as visible placeholders and recorded in
//! the manifest. A prominent provenance banner is prepended to the page.
//!
//! Robustness: input HTML is size-capped, the number of inlined sub-resources
//! and the total output size are bounded, and malformed markup is handled
//! lossily (never panics — on any rewrite error the un-inlined body is returned
//! still carrying the banner and manifest).

use crate::index::ResourceIndex;
use crate::manifest::Manifest;

/// A reconstructed self-contained page: the HTML plus its provenance manifest.
#[derive(Debug, Clone)]
pub struct ReconstructedPage {
    /// The self-contained HTML (banner prepended, sub-resources inlined).
    pub html: String,
    /// The provenance manifest (found vs missing sub-resources).
    pub manifest: Manifest,
}

/// Reconstruct a self-contained single-file HTML page for `target_url`.
///
/// Returns `None` when `target_url` is not an HTML document present in the
/// index (RED stub — not yet implemented).
#[must_use]
pub fn reconstruct_singlefile(
    _index: &ResourceIndex,
    _target_url: &str,
) -> Option<ReconstructedPage> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{CacheSource, IndexedResource};
    use std::path::PathBuf;

    fn r(url: &str, ct: &str, body: &[u8]) -> IndexedResource {
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

    fn sample_index() -> ResourceIndex {
        let mut idx = ResourceIndex::new();
        let html = br#"<!doctype html><html><head>
            <link rel="stylesheet" href="/s.css">
            <script src="/app.js"></script>
            <script src="/gone.js"></script>
            </head><body>
            <img src="/logo.png">
            <img src="/missing.png">
            </body></html>"#;
        idx.insert(r("https://ex.com/", "text/html; charset=utf-8", html));
        idx.insert(r(
            "https://ex.com/s.css",
            "text/css",
            b"body{background:url(/bg.png)}",
        ));
        idx.insert(r(
            "https://ex.com/app.js",
            "application/javascript",
            b"console.log(1)",
        ));
        idx.insert(r("https://ex.com/logo.png", "image/png", b"\x89PNG-logo"));
        idx.insert(r("https://ex.com/bg.png", "image/png", b"\x89PNG-bg"));
        idx
    }

    #[test]
    fn unknown_target_returns_none() {
        let idx = sample_index();
        assert!(reconstruct_singlefile(&idx, "https://ex.com/nope").is_none());
    }

    #[test]
    fn banner_is_prepended() {
        let idx = sample_index();
        let page = reconstruct_singlefile(&idx, "https://ex.com/").unwrap();
        assert!(page.html.contains("Reconstructed from cached resources"));
    }

    #[test]
    fn present_subresources_are_inlined() {
        let idx = sample_index();
        let page = reconstruct_singlefile(&idx, "https://ex.com/").unwrap();
        // The original relative references are replaced by data: URIs.
        assert!(
            page.html.contains("data:image/png;base64,"),
            "image inlined"
        );
        assert!(
            page.html.contains("data:application/javascript;base64,"),
            "script inlined"
        );
        // CSS inlined as a <style> block with its url(bg.png) rewritten.
        assert!(
            page.html.contains("<style"),
            "stylesheet inlined as <style>"
        );
        // The found set covers every present sub-resource, including the CSS's bg.png.
        let found: Vec<&str> = page.manifest.found.iter().map(|f| f.url.as_str()).collect();
        for u in [
            "https://ex.com/s.css",
            "https://ex.com/app.js",
            "https://ex.com/logo.png",
            "https://ex.com/bg.png",
        ] {
            assert!(found.contains(&u), "manifest.found must include {u}");
        }
    }

    #[test]
    fn missing_subresources_are_shown_as_gaps() {
        let idx = sample_index();
        let page = reconstruct_singlefile(&idx, "https://ex.com/").unwrap();
        let missing: Vec<&str> = page
            .manifest
            .missing
            .iter()
            .map(|m| m.url.as_str())
            .collect();
        assert!(missing.contains(&"https://ex.com/missing.png"));
        assert!(missing.contains(&"https://ex.com/gone.js"));
        // The missing image leaves a visible marker in the HTML.
        assert!(
            page.html.to_lowercase().contains("missing"),
            "missing resource must leave a visible placeholder"
        );
    }

    #[test]
    fn malformed_html_does_not_panic() {
        let mut idx = ResourceIndex::new();
        idx.insert(r(
            "https://ex.com/",
            "text/html",
            b"<html><body><img src=\"/x.png\" <<< <script src=unclosed",
        ));
        let page = reconstruct_singlefile(&idx, "https://ex.com/").unwrap();
        assert!(page.html.contains("Reconstructed from cached resources"));
    }

    #[test]
    fn circular_css_import_terminates() {
        let mut idx = ResourceIndex::new();
        idx.insert(r(
            "https://ex.com/",
            "text/html",
            b"<html><head><link rel=stylesheet href=/a.css></head><body></body></html>",
        ));
        // a.css imports b.css imports a.css — must not loop.
        idx.insert(r(
            "https://ex.com/a.css",
            "text/css",
            b"@import url(/b.css);",
        ));
        idx.insert(r(
            "https://ex.com/b.css",
            "text/css",
            b"@import url(/a.css);",
        ));
        let page = reconstruct_singlefile(&idx, "https://ex.com/").unwrap();
        assert!(page.html.contains("Reconstructed from cached resources"));
    }
}
