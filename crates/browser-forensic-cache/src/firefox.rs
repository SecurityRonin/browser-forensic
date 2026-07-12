//! Firefox `cache2` response-body extraction.
//!
//! Firefox stores each cached HTTP response as one file under
//! `<profile>/cache2/entries/<40-hex-SHA1-of-key>`. The on-disk layout, per
//! `netwerk/cache2/CacheFileMetadata.{h,cpp}` and `CacheFileChunk.h`, is:
//!
//! ```text
//! [ body: bodyLen bytes                                   ]  the wire response body
//! [ chunk hashes: uint16 BE, one per 256 KiB body chunk   ]  2 * ceil(bodyLen / 262144) bytes
//! [ uint32 metadata self-hash                             ]  hash of the metadata that follows
//! [ CacheFileMetadataHeader                               ]  see below
//! [ key (NUL-terminated cache key)                        ]  keySize bytes
//! [ elements: "\0name\0value\0name\0value…"               ]  NUL-delimited name/value pairs
//! [ uint32 metadataOffset (big-endian)                    ]  == bodyLen (start of chunk hashes)
//! ```
//!
//! The trailing big-endian `uint32` is the offset to the metadata section — and
//! because the metadata section begins immediately after the body's chunk-hash
//! array, **that offset equals `bodyLen`** (verified against real Firefox 128
//! entries: the value points at the first chunk-hash byte, not past it). The
//! header is:
//!
//! ```text
//! CacheFileMetadataHeader {
//!   uint32 mVersion;         // 1, 2, or 3
//!   uint32 mFetchCount;
//!   uint32 mLastFetched;     // unix seconds
//!   uint32 mLastModified;    // unix seconds
//!   uint32 mFrecency;
//!   uint32 mExpirationTime;  // unix seconds
//!   uint32 mKeySize;         // length of the key, excluding its trailing NUL
//!   uint32 mFlags;           // ADDED in version 2 — absent (28-byte header) in v1
//! }
//! ```
//!
//! The response status line and headers (including `Content-Encoding`) live in
//! the `response-head` element as a normal CRLF-delimited HTTP header block. The
//! body is stored **exactly as received on the wire** — still compressed under
//! its `Content-Encoding` — so it is decoded through the shared
//! [`decode_body`](crate::decode_body) dispatch (tier-1 oracle: a brotli-encoded
//! `gstatic.com` SVG decoded byte-for-byte identical to `curl` of the same
//! immutable, content-hashed URL).
//!
//! Untrusted-input posture: `#![forbid(unsafe_code)]` (crate-wide), no
//! `unwrap`/`expect`, every offset/size/count bounds-checked before use and all
//! chunk-hash arithmetic overflow-checked.

use std::path::{Path, PathBuf};

use crate::decompress::{decode_body, DecompressLimits};
use crate::error::CacheError;
use crate::resource::CachedResource;

/// A single 256 KiB body chunk carries a 2-byte hash in the chunk-hash array.
const CHUNK_SIZE: u64 = 256 * 1024;

/// Parse a single Firefox `cache2` entry file into a [`CachedResource`].
///
/// # Errors
///
/// Returns a [`CacheError`] if the file cannot be read or its structure is
/// invalid (too small, out-of-bounds offset/size, non-UTF-8 key).
pub fn parse_firefox_cache2_file(
    path: &Path,
    limits: &DecompressLimits,
) -> Result<CachedResource, CacheError> {
    let data = std::fs::read(path).map_err(|e| CacheError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;
    resource_from_cache2_bytes(&data, path.to_path_buf(), limits)
}

/// Enumerate every recoverable [`CachedResource`] in a `cache2/entries/`
/// directory, using default decompression limits.
///
/// Best-effort: unreadable or malformed entries are skipped, never panicked on.
#[must_use]
pub fn parse_firefox_cache2_dir(entries_dir: &Path) -> Vec<CachedResource> {
    parse_firefox_cache2_dir_with(entries_dir, &DecompressLimits::default())
}

/// Enumerate every recoverable [`CachedResource`], with explicit limits.
#[must_use]
pub fn parse_firefox_cache2_dir_with(
    entries_dir: &Path,
    limits: &DecompressLimits,
) -> Vec<CachedResource> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(entries_dir) else {
        return out;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Ok(resource) = parse_firefox_cache2_file(&path, limits) {
            out.push(resource);
        }
    }
    out
}

/// Build a [`CachedResource`] from the raw bytes of a `cache2` entry file.
///
/// A body that fails to decode (bomb, malformed stream) does not discard the
/// resource: `raw_body` is retained and the failure is recorded in
/// `decode_note` (fail-loud, no data loss).
///
/// # Errors
///
/// Returns a [`CacheError`] when the entry structure itself is invalid.
pub fn resource_from_cache2_bytes(
    data: &[u8],
    source_file: PathBuf,
    limits: &DecompressLimits,
) -> Result<CachedResource, CacheError> {
    let _ = (data, source_file, limits, decode_body);
    unimplemented!("firefox cache2 body extraction — GREEN pending")
}

/// Everything recovered from the metadata section of a `cache2` entry.
struct Cache2Metadata {
    url: String,
    http_status: Option<u16>,
    status_line: Option<String>,
    headers: Vec<(String, String)>,
    content_type: Option<String>,
    content_encoding: Option<String>,
    /// `mLastFetched` as Unix nanoseconds, if non-zero.
    last_fetched_ns: Option<i64>,
    body_len: usize,
}

/// Decode the metadata section (header + key + elements) of a `cache2` file.
fn parse_cache2_metadata(data: &[u8]) -> Result<Cache2Metadata, CacheError> {
    let n = data.len();
    // Trailing big-endian u32 = metadata offset = bodyLen.
    if n < 4 {
        return Err(CacheError::TooSmall { found: n, need: 4 });
    }
    let body_len =
        u32::from_be_bytes([data[n - 4], data[n - 3], data[n - 2], data[n - 1]]) as usize;
    if body_len > n {
        return Err(CacheError::OutOfBounds {
            field: "metadataOffset",
            value: body_len as u64,
            file_len: n,
        });
    }

    // Chunk-hash array: one uint16 per 256 KiB body chunk. Overflow-checked.
    let chunk_count = body_len.div_ceil(CHUNK_SIZE as usize);
    let hash_bytes = chunk_count.checked_mul(2).ok_or(CacheError::OutOfBounds {
        field: "chunkHashArray",
        value: chunk_count as u64,
        file_len: n,
    })?;

    // metadata section = [chunk hashes][u32 self-hash][CacheFileMetadataHeader]…
    let hdr_off = body_len
        .checked_add(hash_bytes)
        .and_then(|v| v.checked_add(4))
        .ok_or(CacheError::OutOfBounds {
            field: "metadataHeaderOffset",
            value: (body_len + hash_bytes) as u64,
            file_len: n,
        })?;

    // Header needs at least 7 u32 (v1); v2/v3 add mFlags for 8 u32.
    let version = read_u32_be(data, hdr_off).ok_or(CacheError::OutOfBounds {
        field: "mVersion",
        value: hdr_off as u64,
        file_len: n,
    })?;
    let key_size = read_u32_be(data, hdr_off + 24).ok_or(CacheError::OutOfBounds {
        field: "mKeySize",
        value: (hdr_off + 24) as u64,
        file_len: n,
    })? as usize;
    let last_fetched = read_u32_be(data, hdr_off + 8);

    // v1 header is 28 bytes (no mFlags); v2/v3 are 32 bytes.
    let header_len = if version >= 2 { 32 } else { 28 };
    let key_off = hdr_off
        .checked_add(header_len)
        .ok_or(CacheError::OutOfBounds {
            field: "keyOffset",
            value: hdr_off as u64,
            file_len: n,
        })?;
    let key_end = key_off
        .checked_add(key_size)
        .ok_or(CacheError::OutOfBounds {
            field: "mKeySize",
            value: key_size as u64,
            file_len: n,
        })?;
    // Key must fit before the trailing 4-byte offset.
    if key_end > n.saturating_sub(4) {
        return Err(CacheError::OutOfBounds {
            field: "mKeySize",
            value: key_size as u64,
            file_len: n,
        });
    }
    let key_bytes = &data[key_off..key_end];
    let key = std::str::from_utf8(key_bytes).map_err(|_| CacheError::KeyNotUtf8 {
        len: key_size,
        offset: key_off,
    })?;
    let url = url_from_key(key);

    // Elements: the metadata section runs from key_end to the trailing offset.
    let elements = data.get(key_end..n - 4).unwrap_or(&[]);
    let response_head = find_element(elements, b"response-head");
    let (status_line, headers) = match response_head {
        Some(block) => parse_response_head(block),
        None => (None, Vec::new()),
    };
    let http_status = status_line.as_deref().and_then(status_code);
    let content_type = header_value(&headers, "content-type");
    let content_encoding = header_value(&headers, "content-encoding");

    Ok(Cache2Metadata {
        url,
        http_status,
        status_line,
        headers,
        content_type,
        content_encoding,
        last_fetched_ns: last_fetched
            .filter(|&s| s != 0)
            .and_then(|s| i64::from(s).checked_mul(1_000_000_000)),
        body_len,
    })
}

/// Recover the request URL from a Firefox cache key.
///
/// Keys are `[origin-attribute tags]:[URL]`; the tags (`O^partitionKey=…`,
/// `a`, `~expiry`, …) are comma-joined and never contain a bare `:`, so the URL
/// is everything after the first colon. Exotic tag schemes are a documented
/// limitation — the whole key is returned unchanged when no colon is present.
fn url_from_key(key: &str) -> String {
    key.split_once(':')
        .map_or_else(|| key.to_string(), |(_, url)| url.to_string())
}

/// Find a NUL-delimited element value by name within the elements block.
///
/// Elements are stored as `\0name\0value\0name\0value…`; every name is preceded
/// by a NUL (the leading separator or the previous value's terminator), so the
/// value is the run of bytes after `\0name\0` up to the next NUL.
fn find_element<'a>(elements: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    // Build the needle `\0name\0`; also accept `name\0` at offset 0.
    let after_name = |start: usize| -> &'a [u8] {
        let rest = &elements[start..];
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        &rest[..end]
    };
    // Case 1: element block begins directly with this name (no leading NUL).
    if elements.starts_with(name) && elements.get(name.len()) == Some(&0) {
        return Some(after_name(name.len() + 1));
    }
    // Case 2: `\0name\0value` somewhere in the block.
    let mut needle = Vec::with_capacity(name.len() + 2);
    needle.push(0u8);
    needle.extend_from_slice(name);
    needle.push(0u8);
    let pos = elements
        .windows(needle.len())
        .position(|w| w == needle.as_slice())?;
    Some(after_name(pos + needle.len()))
}

/// Parse a CRLF-delimited HTTP response-head block into (status line, headers).
fn parse_response_head(block: &[u8]) -> (Option<String>, Vec<(String, String)>) {
    let text = String::from_utf8_lossy(block);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().map(|s| s.trim_end().to_string());
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    (status_line.filter(|s| !s.is_empty()), headers)
}

/// Case-insensitive first-match header lookup.
fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

/// Extract the numeric status code from a status line like `HTTP/2 200 OK`.
fn status_code(status_line: &str) -> Option<u16> {
    status_line.split_whitespace().nth(1)?.parse().ok()
}

#[inline]
fn read_u32_be(data: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let s = data.get(off..end)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// Build a valid `cache2` entry file mirroring the real on-disk layout.
    fn build_cache2(key: &str, body: &[u8], response_head: &str, version: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(body);
        // chunk hashes: 2 bytes per 256 KiB chunk (content ignored by parser).
        let chunks = body.len().div_ceil(CHUNK_SIZE as usize);
        out.extend(std::iter::repeat_n(0u8, chunks * 2));
        // 4-byte metadata self-hash (ignored).
        out.extend_from_slice(&[0u8; 4]);
        // CacheFileMetadataHeader.
        out.extend_from_slice(&version.to_be_bytes()); // mVersion
        out.extend_from_slice(&1u32.to_be_bytes()); // mFetchCount
        out.extend_from_slice(&1_700_000_000u32.to_be_bytes()); // mLastFetched
        out.extend_from_slice(&1_690_000_000u32.to_be_bytes()); // mLastModified
        out.extend_from_slice(&0u32.to_be_bytes()); // mFrecency
        out.extend_from_slice(&0u32.to_be_bytes()); // mExpirationTime
        out.extend_from_slice(&(key.len() as u32).to_be_bytes()); // mKeySize
        if version >= 2 {
            out.extend_from_slice(&0u32.to_be_bytes()); // mFlags
        }
        out.extend_from_slice(key.as_bytes());
        // elements: leading NUL then \0-delimited name/value pairs.
        out.push(0);
        out.extend_from_slice(b"request-method\0GET\0");
        out.extend_from_slice(b"response-head\0");
        out.extend_from_slice(response_head.as_bytes());
        out.push(0);
        // trailing big-endian metadata offset == bodyLen.
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out
    }

    const RH_GZIP: &str = "HTTP/2 200 \r\ncontent-type: text/html\r\ncontent-encoding: gzip\r\n";

    #[test]
    fn gzip_entry_decodes_body_v3() {
        let html = b"<html>firefox cache2 works</html>";
        let body = gzip(html);
        let data = build_cache2(
            "O^partitionKey=%28https%2Cexample.com%29,:https://example.com/",
            &body,
            RH_GZIP,
            3,
        );
        let res = resource_from_cache2_bytes(
            &data,
            PathBuf::from("/tmp/e"),
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
        assert!(res.response_time_ns.is_some());
    }

    #[test]
    fn v1_header_has_no_flags_field() {
        let body = b"identity body";
        let rh = "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n";
        let data = build_cache2("a,:https://a.test/x", body, rh, 1);
        let res = resource_from_cache2_bytes(
            &data,
            PathBuf::from("/tmp/e"),
            &DecompressLimits::default(),
        )
        .unwrap();
        assert_eq!(res.url, "https://a.test/x");
        assert_eq!(res.http_status, Some(200));
        assert_eq!(res.decoded_body, body);
        assert!(res.content_encoding.is_none());
    }

    #[test]
    fn empty_body_entry_parses() {
        let data = build_cache2(":https://empty.test/", b"", "HTTP/2 204 \r\n", 3);
        let res = resource_from_cache2_bytes(
            &data,
            PathBuf::from("/tmp/e"),
            &DecompressLimits::default(),
        )
        .unwrap();
        assert_eq!(res.url, "https://empty.test/");
        assert_eq!(res.http_status, Some(204));
        assert!(res.raw_body.is_empty());
    }

    #[test]
    fn multi_chunk_body_hash_array_sized_correctly() {
        // Body just over one 256 KiB chunk -> 2 chunks -> 4 hash bytes.
        let body = vec![0x41u8; (CHUNK_SIZE as usize) + 10];
        let data = build_cache2(":https://big.test/", &body, "HTTP/2 200 \r\n", 3);
        let res = resource_from_cache2_bytes(
            &data,
            PathBuf::from("/tmp/e"),
            &DecompressLimits::default(),
        )
        .unwrap();
        assert_eq!(res.raw_body.len(), body.len());
        assert_eq!(res.url, "https://big.test/");
    }

    #[test]
    fn truncated_file_errs_no_panic() {
        let data = build_cache2(":https://x/", b"body", "HTTP/2 200 \r\n", 3);
        for cut in [0usize, 1, 3, 8, data.len() / 2, data.len() - 1] {
            let _ = resource_from_cache2_bytes(
                &data[..cut.min(data.len())],
                PathBuf::from("/tmp/e"),
                &DecompressLimits::default(),
            );
        }
    }

    #[test]
    fn lying_metadata_offset_beyond_file_errs() {
        let mut data = build_cache2(":https://x/", b"body", "HTTP/2 200 \r\n", 3);
        let n = data.len();
        // Rewrite trailing offset to a value larger than the file.
        data[n - 4..].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        let err = resource_from_cache2_bytes(
            &data,
            PathBuf::from("/tmp/e"),
            &DecompressLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(err, CacheError::OutOfBounds { .. }), "{err}");
    }

    #[test]
    fn huge_keysize_errs_no_panic() {
        let mut data = build_cache2(":https://x/", b"body", "HTTP/2 200 \r\n", 3);
        // Locate the header and overwrite mKeySize with a huge value.
        let body_len = 4usize; // "body"
        let hdr_off = body_len + 2 /*chunk hash*/ + 4 /*self-hash*/;
        data[hdr_off + 24..hdr_off + 28].copy_from_slice(&0x7FFF_FFFFu32.to_be_bytes());
        let err = resource_from_cache2_bytes(
            &data,
            PathBuf::from("/tmp/e"),
            &DecompressLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(err, CacheError::OutOfBounds { .. }), "{err}");
    }

    #[test]
    fn dir_enumerates_entries() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("AAAA1111"),
            build_cache2(":https://a/1", b"b1", "HTTP/2 200 \r\n", 3),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("BBBB2222"),
            build_cache2(":https://a/2", b"b2", "HTTP/2 200 \r\n", 3),
        )
        .unwrap();
        let mut res = parse_firefox_cache2_dir(dir.path());
        res.sort_by(|a, b| a.url.cmp(&b.url));
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].url, "https://a/1");
        assert_eq!(res[1].url, "https://a/2");
    }
}
