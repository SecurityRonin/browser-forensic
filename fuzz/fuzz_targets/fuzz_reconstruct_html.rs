#![no_main]
//! Fuzz the single-file HTML reconstruction path: the lol_html sub-resource
//! extractor, the bounds-safe CSS `url(...)` scanner, and the gallery builder.
//! Invariant: arbitrary (attacker-controllable) HTML/CSS/image bytes must never
//! panic — they are lossily decoded and bounded.

use std::path::PathBuf;

use browser_forensic_reconstruct::{
    build_gallery, gallery_index_html, reconstruct_singlefile, CacheSource, IndexedResource,
    ResourceIndex,
};
use libfuzzer_sys::fuzz_target;

fn res(url: &str, ct: &str, body: Vec<u8>) -> IndexedResource {
    IndexedResource {
        url: url.to_string(),
        source: CacheSource::ChromiumSimpleCache,
        cached_time_ns: Some(1),
        content_type: Some(ct.to_string()),
        http_status: Some(200),
        status_line: Some("HTTP/1.1 200 OK".to_string()),
        headers: Vec::new(),
        body,
        source_file: PathBuf::new(),
    }
}

fuzz_target!(|data: &[u8]| {
    let mut idx = ResourceIndex::new();
    // The fuzz bytes drive every parser surface: as the page HTML, as a linked
    // stylesheet (CSS url() scanner), and as an image (data-URI + gallery).
    idx.insert(res("https://f.test/", "text/html", data.to_vec()));
    idx.insert(res("https://f.test/s.css", "text/css", data.to_vec()));
    idx.insert(res("https://f.test/logo.png", "image/png", data.to_vec()));

    let _ = reconstruct_singlefile(&idx, "https://f.test/");

    let gallery = build_gallery(&idx);
    let _ = gallery_index_html(&gallery);
});
