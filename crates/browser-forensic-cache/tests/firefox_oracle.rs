//! Env-gated tier-1 oracle against a REAL Firefox `cache2/entries/` directory.
//!
//! Skipped unless `BFCACHE_FIREFOX_ENTRIES_DIR` points at a Firefox profile's
//! `cache2/entries` directory, e.g.:
//!
//! ```sh
//! export BFCACHE_FIREFOX_ENTRIES_DIR=~/Library/Caches/Firefox/Profiles/<p>/cache2/entries
//! ```
//!
//! Provenance / ground truth: during development the brotli-encoded body of the
//! immutable, content-hashed asset
//! `www.gstatic.com/images/branding/googlelogo/svg/googlelogo_surface_dark_74x24px.svg`
//! (688 stored bytes) was decoded through this crate and cross-checked
//! byte-for-byte against `curl` of the same URL — both SHA-256
//! `85cc8d7da542d99fb3bc9d9237a537a8a75f8a519d6a27ee6c5f0210da9f8e6d`. That
//! establishes the Firefox body is stored wire-compressed and this crate decodes
//! it correctly. The cache profile itself is never committed (per the fleet
//! test-data provenance standard).

use std::path::Path;

use browser_forensic_cache::parse_firefox_cache2_dir;

#[test]
fn firefox_cache2_real_dir_enumerates_and_decodes() {
    let Ok(dir) = std::env::var("BFCACHE_FIREFOX_ENTRIES_DIR") else {
        eprintln!("skip: set BFCACHE_FIREFOX_ENTRIES_DIR to a Firefox cache2/entries dir");
        return;
    };

    let resources = parse_firefox_cache2_dir(Path::new(&dir));
    assert!(
        !resources.is_empty(),
        "expected recoverable cached resources under {dir}"
    );

    let mut decoded_compressed = 0usize;
    let mut saw_gzip = false;
    let mut saw_brotli = false;

    for r in &resources {
        assert!(!r.url.is_empty(), "resource URL must not be empty");
        // No silent decode failure: usable content, identity/absent encoding, or
        // a recorded note.
        assert!(
            r.body_decoded || r.content_encoding.is_none() || r.decode_note.is_some(),
            "decode of {} silently failed: {:?}",
            r.url,
            r.decode_note
        );
        match r.content_encoding.as_deref() {
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

    assert!(
        decoded_compressed > 0,
        "expected at least one wire-compressed Firefox body to decode"
    );
    eprintln!(
        "firefox oracle: {} resources, {} compressed bodies decoded (gzip={saw_gzip}, br={saw_brotli})",
        resources.len(),
        decoded_compressed
    );
}
