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
pub mod http_meta;
pub mod simple;

pub use decompress::{decode_body, DecodeOutcome, DecompressLimits};
pub use error::CacheError;
pub use http_meta::{parse_http_meta, HttpMeta};
pub use simple::{parse_simple_entry, SimpleEntry};
