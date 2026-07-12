#![no_main]
//! Fuzz the WARC writer path: arbitrary bytes become a resource's header value
//! and body (and its status line), then a WARC stream is written to a Vec.
//! Invariant: writing must never panic on hostile header/body bytes.

use std::path::PathBuf;

use browser_forensic_reconstruct::{write_warc, CacheSource, IndexedResource};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data).into_owned();
    let res = IndexedResource {
        url: format!(
            "https://f.test/{}",
            text.chars().take(32).collect::<String>()
        ),
        source: CacheSource::CacheStorage,
        cached_time_ns: Some(1),
        content_type: Some(text.chars().take(48).collect::<String>()),
        http_status: Some(200),
        status_line: Some(text.lines().next().unwrap_or("HTTP/1.1 200 OK").to_string()),
        headers: vec![("X-Fuzz".to_string(), text.clone())],
        body: data.to_vec(),
        source_file: PathBuf::new(),
    };
    let resources = vec![res];
    let mut buf = Vec::new();
    let _ = write_warc(resources.iter(), Some("https://f.test/"), &mut buf);
});
