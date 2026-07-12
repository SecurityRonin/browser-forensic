//! Env-gated tier-1 oracle against a REAL Chromium SimpleCache directory.
//!
//! This test is skipped unless `BFCACHE_CHROME_CACHE_DIR` points at a Chromium
//! `Cache/Cache_Data/` directory. Generate one with, e.g.:
//!
//! ```sh
//! "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
//!   --headless=new --user-data-dir=/tmp/m1a1-profile https://www.iana.org/ &
//! sleep 12 && kill %1
//! export BFCACHE_CHROME_CACHE_DIR=/tmp/m1a1-profile/Default/Cache/Cache_Data
//! ```
//!
//! Provenance / ground truth: the decoded body of each content-hashed
//! (immutable) asset was cross-checked byte-for-byte against `curl` of the same
//! URL during development — decoded brotli bodies for
//! `www.iana.org/static/js/jquery.a8e7cabd4d49.js` (78 748 B) and
//! `.../css/iana_website.80c103cc08b6.css` (82 866 B) matched `curl`'s SHA-256
//! exactly. The cache directory itself is ephemeral (`/tmp`) and never
//! committed, per the fleet test-data provenance standard.

use std::path::Path;

use browser_forensic_cache::parse_simple_cache_dir;

#[test]
fn chrome_simplecache_real_dir_enumerates_and_decodes() {
    let Ok(dir) = std::env::var("BFCACHE_CHROME_CACHE_DIR") else {
        eprintln!("skip: set BFCACHE_CHROME_CACHE_DIR to a Chromium Cache_Data dir");
        return;
    };

    let resources = parse_simple_cache_dir(Path::new(&dir));
    assert!(
        !resources.is_empty(),
        "expected recoverable cached resources under {dir}"
    );

    let mut decoded_compressed = 0usize;
    let mut saw_gzip = false;
    let mut saw_brotli = false;

    for r in &resources {
        // A recovered entry has a URL and a status line/code from stream 0.
        assert!(!r.url.is_empty(), "resource URL must not be empty");

        // No silent decode failure: either we produced usable content, or the
        // encoding was identity/absent, or we recorded a note.
        assert!(
            r.body_decoded || r.content_encoding.is_none() || r.decode_note.is_some(),
            "decode of {} silently failed: {:?}",
            r.url,
            r.decode_note
        );

        match r.content_encoding.as_deref() {
            // Note: a tiny payload can decode SMALLER than its stored size
            // (compression overhead exceeds the savings), so body length is
            // not asserted — the byte-for-byte curl cross-check (see module
            // doc) is what establishes decode correctness.
            Some("gzip") if r.body_decoded => {
                saw_gzip = true;
                decoded_compressed += 1;
            }
            Some("br") if r.body_decoded => {
                saw_brotli = true;
                decoded_compressed += 1;
            }
            _ => {}
        }
    }

    // A rendered page pulls in both gzip- and brotli-encoded sub-resources.
    assert!(
        decoded_compressed > 0,
        "expected at least one compressed body to decode"
    );
    eprintln!(
        "oracle: {} resources, {} compressed bodies decoded (gzip={saw_gzip}, br={saw_brotli})",
        resources.len(),
        decoded_compressed
    );
}
