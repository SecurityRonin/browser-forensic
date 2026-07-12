#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Chromium SimpleCache response-body extraction and panic-free HTTP decompression.
//!
//! This crate reads Chromium-family (`Chrome`, `Edge`, `Brave`, `Opera`, …)
//! `Cache/Cache_Data/` directories written in the **SimpleCache** on-disk format,
//! recovers each cached HTTP response (URL, status, headers, and the response
//! body), and transparently decodes the body's `Content-Encoding`
//! (`gzip`/`deflate`/`br`/`zstd`/`identity`) with hard output + ratio caps so a
//! decompression bomb can neither panic nor exhaust memory.
//!
//! Untrusted-input posture: `#![forbid(unsafe_code)]`, no `unwrap`/`expect` in
//! production code, every offset/size bounds-checked before use.

pub mod decompress;
pub mod error;
pub mod firefox;
pub mod http_meta;
pub mod resource;
pub mod simple;

pub use decompress::{decode_body, DecodeOutcome, DecompressLimits};
pub use error::CacheError;
pub use firefox::{
    parse_firefox_cache2_dir, parse_firefox_cache2_dir_with, parse_firefox_cache2_file,
    resource_from_cache2_bytes,
};
pub use http_meta::{parse_http_meta, HttpMeta};
pub use resource::{
    parse_simple_cache_dir, parse_simple_cache_dir_with, parse_simple_cache_file,
    resource_from_entry_bytes, CachedResource,
};
pub use simple::{parse_simple_entry, SimpleEntry};
