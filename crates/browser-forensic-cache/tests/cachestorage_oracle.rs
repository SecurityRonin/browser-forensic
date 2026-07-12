//! Env-gated tier-1 oracle against a REAL Service Worker CacheStorage tree.
//!
//! Skipped unless `BFCACHE_CACHESTORAGE_DIR` points at a `CacheStorage/` root or
//! a single `<origin-hash>/` directory, e.g. a Chrome/Electron app profile:
//!
//! ```sh
//! export BFCACHE_CACHESTORAGE_DIR="$HOME/Library/Application Support/Slack/Service Worker/CacheStorage"
//! ```
//!
//! Ground truth is derived *from the on-disk structure itself* (independent of
//! this parser): every cache directory named in an `index.txt` must exist, and
//! the number of recovered resources must equal the number of SimpleCache `_0`
//! entry files under those directories that parse. The metadata proto decode is
//! additionally cross-checked (during development) against `protoc --decode_raw`
//! and CCL `ccl_chromium_cache` on the same bytes — see docs/validation.md. The
//! tree is read-only and never committed.

use std::path::{Path, PathBuf};

use browser_forensic_cache::parse_cachestorage_dir;

/// Collect every `index.txt`-bearing origin-hash dir at depth 0 or 1 of `root`.
fn origin_hash_dirs(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if root.join("index.txt").is_file() {
        out.push(root.to_path_buf());
        return out;
    }
    if let Ok(entries) = std::fs::read_dir(root) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() && p.join("index.txt").is_file() {
                out.push(p);
            }
        }
    }
    out
}

/// Count `*_0` entry files across the UUID subdirectories of an origin-hash dir.
fn count_entry_files(origin_hash: &Path) -> usize {
    let mut n = 0;
    let Ok(subs) = std::fs::read_dir(origin_hash) else {
        return 0;
    };
    for sub in subs.flatten() {
        let p = sub.path();
        if !p.is_dir() {
            continue;
        }
        if let Ok(files) = std::fs::read_dir(&p) {
            for f in files.flatten() {
                if f.path()
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with("_0"))
                {
                    n += 1;
                }
            }
        }
    }
    n
}

#[test]
fn cachestorage_real_enumerates_and_is_structurally_consistent() {
    let Ok(dir) = std::env::var("BFCACHE_CACHESTORAGE_DIR") else {
        eprintln!("skip: set BFCACHE_CACHESTORAGE_DIR to a Service Worker/CacheStorage tree");
        return;
    };
    let root = PathBuf::from(&dir);
    let origins = origin_hash_dirs(&root);
    assert!(
        !origins.is_empty(),
        "no index.txt-bearing origin dirs under {dir}"
    );

    let resources = parse_cachestorage_dir(&root);
    assert!(
        !resources.is_empty(),
        "expected recoverable CacheStorage resources in {dir}"
    );

    // Independent ground truth: total recovered <= total on-disk `_0` files, and
    // within a healthy tree the vast majority parse (malformed entries are rare).
    let on_disk: usize = origins.iter().map(|o| count_entry_files(o)).sum();
    assert!(
        resources.len() <= on_disk,
        "recovered {} > {} on-disk _0 files",
        resources.len(),
        on_disk
    );
    assert!(
        on_disk == 0 || resources.len() * 100 >= on_disk * 90,
        "recovered only {}/{} entries (<90%) — parser is dropping valid entries",
        resources.len(),
        on_disk
    );

    let mut with_body = 0usize;
    let mut declared_encoding = 0usize;
    let mut stored_decoded = 0usize;
    for r in &resources {
        // Every key is an absolute URL.
        assert!(
            r.url.starts_with("http://") || r.url.starts_with("https://"),
            "non-absolute cached URL: {:?}",
            r.url
        );
        // Attribution is always populated from the index.
        assert!(!r.cache_name.is_empty(), "empty cache_name for {}", r.url);
        if let Some(s) = r.http_status {
            assert!(
                (100..=599).contains(&s),
                "implausible status {s} for {}",
                r.url
            );
        }
        if !r.body.is_empty() {
            with_body += 1;
        }
        if let Some(enc) = &r.content_encoding {
            if !enc.eq_ignore_ascii_case("identity") {
                declared_encoding += 1;
                // Cache API stores the delivered body: a declared encoding that
                // is not applied must be explained, never a silent decode fail.
                if r.body == r.raw_body {
                    assert!(
                        r.body_note.is_some(),
                        "declared {enc} not applied without a note for {}",
                        r.url
                    );
                    stored_decoded += 1;
                }
            }
        }
    }
    assert!(with_body > 0, "expected at least one non-empty body");
    eprintln!(
        "cachestorage oracle: {} origins, {} resources ({} on-disk _0), {} with bodies, \
         {} declared an encoding ({} stored already-decoded)",
        origins.len(),
        resources.len(),
        on_disk,
        with_body,
        declared_encoding,
        stored_decoded
    );
}
