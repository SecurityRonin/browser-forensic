//! The public `CachedResource` type and `Cache/` directory enumeration.
//!
//! Ties the pieces together: [`parse_simple_entry`](crate::parse_simple_entry)
//! recovers the URL + stream bytes, [`parse_http_meta`](crate::parse_http_meta)
//! decodes the response metadata, and [`decode_body`](crate::decode_body)
//! transparently decompresses the body under its `Content-Encoding`.

use std::path::{Path, PathBuf};

use crate::decompress::{decode_body, DecompressLimits};
use crate::error::CacheError;
use crate::http_meta::parse_http_meta;
use crate::simple::parse_simple_entry;

/// A single cached HTTP response recovered from a SimpleCache entry.
#[derive(Debug, Clone)]
pub struct CachedResource {
    /// The request URL (the SimpleCache key).
    pub url: String,
    /// HTTP status code, if recovered from stream 0.
    pub http_status: Option<u16>,
    /// Full HTTP status line, e.g. `HTTP/1.1 200 OK`.
    pub status_line: Option<String>,
    /// Response headers in file order.
    pub headers: Vec<(String, String)>,
    /// `Content-Type` header value, if present.
    pub content_type: Option<String>,
    /// `Content-Encoding` header value (the on-the-wire body compression).
    pub content_encoding: Option<String>,
    /// Request time (Unix nanoseconds), if recovered.
    pub request_time_ns: Option<i64>,
    /// Response time (Unix nanoseconds), if recovered.
    pub response_time_ns: Option<i64>,
    /// The response body exactly as stored (still `Content-Encoding`-compressed).
    pub raw_body: Vec<u8>,
    /// The decoded body. Equals `raw_body` for `identity`/unknown encodings.
    pub decoded_body: Vec<u8>,
    /// `true` when `decoded_body` is the usable decoded content.
    pub body_decoded: bool,
    /// Any decode caveat: unknown encoding, deflate variant, or a decode error
    /// (the body is retained raw rather than dropped when decoding fails).
    pub decode_note: Option<String>,
    /// The `[hash]_0` file this resource came from.
    pub source_file: PathBuf,
    /// The companion `[hash]_s` sparse file, if one exists. Its range
    /// reassembly is not performed here (documented follow-up limitation);
    /// its presence is surfaced so a large/streamed body is not silently missed.
    pub sparse_file: Option<PathBuf>,
}

/// Build a [`CachedResource`] from the raw bytes of a `[hash]_0` entry.
///
/// A body that fails to decode (bomb, malformed stream) does not discard the
/// resource: `raw_body` is retained and the failure is recorded in
/// `decode_note` (fail-loud, no data loss).
///
/// # Errors
///
/// Returns a [`CacheError`] only when the entry structure itself is invalid.
pub fn resource_from_entry_bytes(
    data: &[u8],
    source_file: PathBuf,
    sparse_file: Option<PathBuf>,
    limits: &DecompressLimits,
) -> Result<CachedResource, CacheError> {
    // RED stub — implementation added in the GREEN commit.
    let _ = (data, &source_file, &sparse_file, limits);
    Err(CacheError::TooSmall { found: 0, need: 0 })
}

/// Parse a single `[hash]_0` file into a [`CachedResource`].
///
/// # Errors
///
/// Returns a [`CacheError`] if the file cannot be read or its structure is
/// invalid.
pub fn parse_simple_cache_file(
    path: &Path,
    limits: &DecompressLimits,
) -> Result<CachedResource, CacheError> {
    // RED stub — implementation added in the GREEN commit.
    let _ = (path, limits);
    Err(CacheError::TooSmall { found: 0, need: 0 })
}

/// Enumerate every recoverable [`CachedResource`] in a `Cache/` (or
/// `Cache/Cache_Data/`) directory, using default decompression limits.
///
/// Best-effort: unreadable or malformed entries are skipped, never panicked on.
#[must_use]
pub fn parse_simple_cache_dir(cache_dir: &Path) -> Vec<CachedResource> {
    parse_simple_cache_dir_with(cache_dir, &DecompressLimits::default())
}

/// Enumerate every recoverable [`CachedResource`], with explicit limits.
#[must_use]
pub fn parse_simple_cache_dir_with(
    cache_dir: &Path,
    limits: &DecompressLimits,
) -> Vec<CachedResource> {
    // RED stub — implementation added in the GREEN commit.
    let _ = (cache_dir, limits);
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simple::{EOF_MAGIC, EOF_SIZE, HEADER_MAGIC, HEADER_SIZE};
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    use tempfile::TempDir;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// Build a valid `_0` file (mirrors the layout verified in `simple`).
    fn build_entry(url: &str, stream1: &[u8], stream0: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&HEADER_MAGIC.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(url.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(url.as_bytes());
        out.extend_from_slice(stream1);
        push_eof(&mut out, 1, stream1.len() as u32);
        out.extend_from_slice(stream0);
        push_eof(&mut out, 1, stream0.len() as u32);
        out
    }

    fn push_eof(out: &mut Vec<u8>, flags: u32, stream_size: u32) {
        out.extend_from_slice(&EOF_MAGIC.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&stream_size.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]);
        let _ = EOF_SIZE;
    }

    #[test]
    fn gzip_entry_decodes_body() {
        let html = b"<html>hi there</html>";
        let body = gzip(html);
        let headers = b"HTTP/1.1 200 OK\0Content-Type: text/html\0Content-Encoding: gzip\0\0";
        let data = build_entry("https://example.com/", &body, headers);
        let res = resource_from_entry_bytes(
            &data,
            PathBuf::from("/tmp/abc_0"),
            None,
            &DecompressLimits::default(),
        )
        .unwrap();
        assert_eq!(res.url, "https://example.com/");
        assert_eq!(res.http_status, Some(200));
        assert_eq!(res.content_type.as_deref(), Some("text/html"));
        assert_eq!(res.content_encoding.as_deref(), Some("gzip"));
        assert_eq!(res.raw_body, body);
        assert_eq!(res.decoded_body, html);
        assert!(res.body_decoded);
    }

    #[test]
    fn identity_body_passthrough() {
        let headers = b"HTTP/1.1 200 OK\0Content-Type: text/plain\0\0";
        let data = build_entry("https://a.test/x", b"raw text", headers);
        let res = resource_from_entry_bytes(
            &data,
            PathBuf::from("/tmp/x_0"),
            None,
            &DecompressLimits::default(),
        )
        .unwrap();
        assert_eq!(res.decoded_body, b"raw text");
        assert!(res.body_decoded);
        assert!(res.content_encoding.is_none());
    }

    #[test]
    fn dir_enumerates_entries_and_skips_index() {
        let dir = TempDir::new().unwrap();
        let h = b"HTTP/1.1 200 OK\0\0";
        std::fs::write(
            dir.path().join("aaaa1111_0"),
            build_entry("https://a/1", b"b1", h),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("bbbb2222_0"),
            build_entry("https://a/2", b"b2", h),
        )
        .unwrap();
        // Index files must be ignored.
        std::fs::write(dir.path().join("index"), b"not a cache entry").unwrap();
        std::fs::write(dir.path().join("the-real-index"), b"nope").unwrap();
        let mut res = parse_simple_cache_dir(dir.path());
        res.sort_by(|a, b| a.url.cmp(&b.url));
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].url, "https://a/1");
        assert_eq!(res[1].url, "https://a/2");
    }

    #[test]
    fn sparse_companion_detected() {
        let dir = TempDir::new().unwrap();
        let h = b"HTTP/1.1 206 Partial Content\0\0";
        std::fs::write(
            dir.path().join("dead0001_0"),
            build_entry("https://a/s", b"", h),
        )
        .unwrap();
        std::fs::write(dir.path().join("dead0001_s"), b"sparse ranges here").unwrap();
        let res = parse_simple_cache_dir(dir.path());
        assert_eq!(res.len(), 1);
        assert!(
            res[0].sparse_file.is_some(),
            "sparse companion should be surfaced"
        );
    }

    #[test]
    fn malformed_entry_skipped_no_panic() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("junk0000_0"), vec![0u8; 40]).unwrap();
        let res = parse_simple_cache_dir(dir.path());
        assert!(res.is_empty());
    }
}
