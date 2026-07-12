//! Env-gated tier-1 oracle: reconstruct a page from a REAL Chromium cache.
//!
//! Skipped unless `BFRECON_CHROME_CACHE_DIR` points at a Chromium
//! `Cache/Cache_Data/` directory (or a profile directory). Generate one with a
//! static page carrying CSS + images, e.g.:
//!
//! ```sh
//! mkdir -p /tmp/site && cd /tmp/site
//! printf '<!doctype html><link rel=stylesheet href=style.css><img src=pic.png>' > index.html
//! # ... add style.css + pic.png ...
//! python3 -m http.server 8137 &
//! "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
//!   --headless=new --user-data-dir=/tmp/recon-profile http://localhost:8137/ & sleep 8; kill %2
//! export BFRECON_CHROME_CACHE_DIR=/tmp/recon-profile/Default/Cache/Cache_Data
//! ```
//!
//! Ground truth: the page's cached sub-resources (the CSS, images, scripts it
//! references) must be recovered from the cache and inlined as `data:` URIs,
//! the provenance banner + manifest must be present, and any reference NOT in
//! cache must appear in the missing list. This is tier-1 (real browser output),
//! an independent check on the synthetic unit fixtures.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use browser_forensic_reconstruct::{reconstruct_singlefile, ResourceIndex};

#[test]
fn chrome_cache_page_reconstructs_with_inlined_subresources() {
    let Ok(dir) = std::env::var("BFRECON_CHROME_CACHE_DIR") else {
        eprintln!("skip: set BFRECON_CHROME_CACHE_DIR to a Chromium Cache_Data (or profile) dir");
        return;
    };

    let index = ResourceIndex::from_cache_dir(Path::new(&dir));
    assert!(
        !index.is_empty(),
        "expected recoverable cached resources under {dir}"
    );

    let pages = index.html_entries();
    assert!(!pages.is_empty(), "expected at least one cached HTML page");

    // Reconstruct the page with the most recoverable sub-resources.
    let mut best = None;
    let mut best_found = 0usize;
    for p in &pages {
        if let Some(rec) = reconstruct_singlefile(&index, &p.url) {
            if best.is_none() || rec.manifest.found.len() > best_found {
                best_found = rec.manifest.found.len();
                best = Some((p.url.clone(), rec));
            }
        }
    }
    let (url, rec) = best.expect("at least one HTML page reconstructs");

    // Provenance banner (human-visible) + machine-readable manifest present.
    assert!(
        rec.html.contains("Reconstructed from cached resources"),
        "reconstructed HTML must carry the provenance banner"
    );
    assert!(
        rec.manifest
            .to_json()
            .contains("Reconstructed from cached resources"),
        "manifest JSON must carry the provenance statement"
    );
    // A real page pulls in cached sub-resources, inlined as data: URIs.
    assert!(
        !rec.manifest.found.is_empty(),
        "a real page should have sub-resources recovered from cache"
    );
    assert!(
        rec.html.contains("data:"),
        "found sub-resources must be inlined as data: URIs"
    );

    eprintln!(
        "oracle: reconstructed {url} — {} sub-resources found in cache, {} referenced but missing",
        rec.manifest.found.len(),
        rec.manifest.missing.len()
    );
}
