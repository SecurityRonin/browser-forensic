//! Chromium SimpleCache per-entry (`[hash]_0`) parser.
//!
//! Layout verified against Chromium `net/disk_cache/simple/simple_entry_format.h`
//! and `simple_synchronous_entry.cc` (`GetOffsetInFile`):
//!
//! ```text
//! [SimpleFileHeader (24)]  magic8, version4, key_length4, key_hash4, pad4
//! [key: key_length bytes]  the cache key (the request URL)
//! [stream 1 data]          the response BODY, as received (still Content-Encoding compressed)
//! [SimpleFileEOF (24)]     final_magic8, flags4, data_crc32_4, stream_size4, pad4  (stream 1 EOF)
//! [stream 0 data]          the pickled HttpResponseInfo (status line + headers)
//! [optional key SHA-256 (32)]  present iff stream-0 EOF flags & FLAG_HAS_KEY_SHA256
//! [SimpleFileEOF (24)]     stream 0 EOF; its stream_size field is the stream-0 length
//! ```
//!
//! Every offset and size is bounds-checked against the file length *before* use.

use crate::error::CacheError;

/// `kSimpleInitialMagicNumber` — first 8 bytes of a `[hash]_0` file.
pub const HEADER_MAGIC: u64 = 0xfcfb_6d1b_a772_5c30;
/// `kSimpleFinalMagicNumber` — first 8 bytes of every `SimpleFileEOF` record.
pub const EOF_MAGIC: u64 = 0xf4fa_6f45_970d_41d8;
/// `kSimpleSparseRangeMagicNumber` — first 8 bytes of a sparse (`_s`) range header.
pub const SPARSE_RANGE_MAGIC: u64 = 0xeb97_bf01_6553_676b;

/// `sizeof(SimpleFileHeader)` on disk: 20 bytes of fields, 8-byte aligned to 24.
pub const HEADER_SIZE: usize = 24;
/// `sizeof(SimpleFileEOF)` on disk: 20 bytes of fields, 8-byte aligned to 24.
pub const EOF_SIZE: usize = 24;
/// Size of the optional key SHA-256 digest preceding the stream-0 EOF.
pub const KEY_SHA256_SIZE: usize = 32;

const FLAG_HAS_CRC32: u32 = 1 << 0;
const FLAG_HAS_KEY_SHA256: u32 = 1 << 1;

/// Sanity cap on the cache key (URL) length. Real keys are well under this;
/// a value beyond it signals a corrupt/hostile `key_length` field.
const MAX_KEY_LEN: usize = 64 * 1024;

/// A parsed SimpleCache `_0` entry: the key plus the raw stream-0/stream-1 bytes.
#[derive(Debug, Clone)]
pub struct SimpleEntry {
    /// The cache key — the request URL (Chromium stores the key as the URL,
    /// optionally prefixed by a partition/isolation key on newer builds).
    pub url: String,
    /// Stream 0: pickled `HttpResponseInfo` (status line + response headers).
    pub stream0: Vec<u8>,
    /// Stream 1: the response body, exactly as received on the wire
    /// (still `Content-Encoding`-compressed).
    pub stream1: Vec<u8>,
    /// Whether the stream-0 EOF advertised a CRC32 (informational).
    pub stream0_has_crc32: bool,
    /// Whether the entry carried a key SHA-256 digest before the stream-0 EOF.
    pub has_key_sha256: bool,
}

#[inline]
fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let slice = data.get(off..end)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[inline]
fn read_u64_le(data: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let slice = data.get(off..end)?;
    let mut b = [0u8; 8];
    b.copy_from_slice(slice);
    Some(u64::from_le_bytes(b))
}

/// Parse a SimpleCache `[hash]_0` entry from its raw bytes.
///
/// Returns the URL plus the raw stream-0 (headers) and stream-1 (body) byte
/// ranges. Malformed input (bad magic, truncation, a lying stream size, a
/// non-UTF-8 key) yields a descriptive [`CacheError`]; the parser never panics.
///
/// # Errors
///
/// See [`CacheError`] — every variant names the offending value and offset.
pub fn parse_simple_entry(data: &[u8]) -> Result<SimpleEntry, CacheError> {
    let file_len = data.len();
    let min = HEADER_SIZE + EOF_SIZE;
    if file_len < min {
        return Err(CacheError::TooSmall {
            found: file_len,
            need: min,
        });
    }

    // --- SimpleFileHeader ---
    let header_magic = read_u64_le(data, 0).ok_or(CacheError::TooSmall {
        found: file_len,
        need: min,
    })?;
    if header_magic != HEADER_MAGIC {
        return Err(CacheError::BadHeaderMagic {
            found: header_magic,
            expected: HEADER_MAGIC,
        });
    }
    // version at [8..12], key_length at [12..16], key_hash at [16..20].
    let key_length = read_u32_le(data, 12).ok_or(CacheError::OutOfBounds {
        field: "key_length",
        value: 0,
        file_len,
    })? as usize;
    if key_length == 0 || key_length > MAX_KEY_LEN {
        return Err(CacheError::OutOfBounds {
            field: "key_length",
            value: key_length as u64,
            file_len,
        });
    }
    let key_start = HEADER_SIZE;
    let key_end = key_start
        .checked_add(key_length)
        .filter(|&e| e <= file_len)
        .ok_or(CacheError::OutOfBounds {
            field: "key_end",
            value: key_length as u64,
            file_len,
        })?;
    let url = std::str::from_utf8(&data[key_start..key_end])
        .map_err(|_| CacheError::KeyNotUtf8 {
            len: key_length,
            offset: key_start,
        })?
        .to_string();

    let located = locate_streams(data, file_len, key_end)?;

    Ok(SimpleEntry {
        url,
        stream0: data[located.stream0.clone()].to_vec(),
        stream1: data[located.stream1.clone()].to_vec(),
        stream0_has_crc32: located.stream0_has_crc32,
        has_key_sha256: located.has_key_sha256,
    })
}

/// Byte ranges of the two streams inside a `_0` file, plus stream-0 EOF flags.
struct StreamLayout {
    stream0: std::ops::Range<usize>,
    stream1: std::ops::Range<usize>,
    stream0_has_crc32: bool,
    has_key_sha256: bool,
}

/// Locate stream 0 (headers) and stream 1 (body) by working back from the
/// stream-0 EOF, validating both EOF magics. Every offset is bounds-checked.
fn locate_streams(
    data: &[u8],
    file_len: usize,
    key_end: usize,
) -> Result<StreamLayout, CacheError> {
    // --- stream-0 EOF (the final 24 bytes) ---
    let eof0_off = file_len - EOF_SIZE;
    let eof0_magic = read_u64_le(data, eof0_off).ok_or(CacheError::OutOfBounds {
        field: "eof0_offset",
        value: eof0_off as u64,
        file_len,
    })?;
    if eof0_magic != EOF_MAGIC {
        return Err(CacheError::BadEofMagic {
            found: eof0_magic,
            offset: eof0_off,
            expected: EOF_MAGIC,
        });
    }
    let eof0_flags = read_u32_le(data, eof0_off + 8).unwrap_or(0);
    let stream0_size = read_u32_le(data, eof0_off + 16).unwrap_or(0) as usize;
    let stream0_has_crc32 = eof0_flags & FLAG_HAS_CRC32 != 0;
    let has_key_sha256 = eof0_flags & FLAG_HAS_KEY_SHA256 != 0;
    let sha_len = if has_key_sha256 { KEY_SHA256_SIZE } else { 0 };

    // stream 0 data sits directly before the optional SHA-256 + the stream-0 EOF.
    let stream0_end = eof0_off
        .checked_sub(sha_len)
        .ok_or(CacheError::OutOfBounds {
            field: "stream0_end",
            value: sha_len as u64,
            file_len,
        })?;
    let stream0_start = stream0_end
        .checked_sub(stream0_size)
        .ok_or(CacheError::OutOfBounds {
            field: "stream0_size",
            value: stream0_size as u64,
            file_len,
        })?;

    // Immediately before stream 0 sits the stream-1 EOF record.
    let eof1_off = stream0_start
        .checked_sub(EOF_SIZE)
        .ok_or(CacheError::OutOfBounds {
            field: "eof1_offset",
            value: stream0_start as u64,
            file_len,
        })?;
    if eof1_off < key_end {
        return Err(CacheError::OutOfBounds {
            field: "stream1_range",
            value: eof1_off as u64,
            file_len,
        });
    }
    let eof1_magic = read_u64_le(data, eof1_off).ok_or(CacheError::OutOfBounds {
        field: "eof1_offset",
        value: eof1_off as u64,
        file_len,
    })?;
    if eof1_magic != EOF_MAGIC {
        return Err(CacheError::BadEofMagic {
            found: eof1_magic,
            offset: eof1_off,
            expected: EOF_MAGIC,
        });
    }

    Ok(StreamLayout {
        // stream 1 (body) fills the gap between the key and the stream-1 EOF.
        stream1: key_end..eof1_off,
        stream0: stream0_start..stream0_end,
        stream0_has_crc32,
        has_key_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid SimpleCache `_0` file from parts, mirroring Chromium's
    /// on-disk layout (see module doc). `flags`/`sha256` control the stream-0 EOF.
    fn build_entry(url: &str, stream1: &[u8], stream0: &[u8], sha256: Option<[u8; 32]>) -> Vec<u8> {
        let mut out = Vec::new();
        // SimpleFileHeader
        out.extend_from_slice(&HEADER_MAGIC.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // version
        out.extend_from_slice(&(url.len() as u32).to_le_bytes()); // key_length
        out.extend_from_slice(&0u32.to_le_bytes()); // key_hash
        out.extend_from_slice(&[0u8; 4]); // pad to 24
        assert_eq!(out.len(), HEADER_SIZE);
        // key
        out.extend_from_slice(url.as_bytes());
        // stream 1 (body)
        out.extend_from_slice(stream1);
        // stream 1 EOF
        push_eof(&mut out, 0, stream1.len() as u32);
        // stream 0 (headers)
        out.extend_from_slice(stream0);
        // optional key SHA-256
        let mut flags = FLAG_HAS_CRC32;
        if let Some(sha) = sha256 {
            out.extend_from_slice(&sha);
            flags |= FLAG_HAS_KEY_SHA256;
        }
        // stream 0 EOF (carries stream0 size)
        push_eof(&mut out, flags, stream0.len() as u32);
        out
    }

    fn push_eof(out: &mut Vec<u8>, flags: u32, stream_size: u32) {
        out.extend_from_slice(&EOF_MAGIC.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // data_crc32
        out.extend_from_slice(&stream_size.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]); // pad to 24
    }

    #[test]
    fn parses_url_body_and_headers() {
        let body = b"<html>hello</html>";
        let headers = b"HTTP/1.1 200 OK\0Content-Type: text/html\0\0";
        let data = build_entry("https://example.com/", body, headers, None);
        let entry = parse_simple_entry(&data).expect("valid entry");
        assert_eq!(entry.url, "https://example.com/");
        assert_eq!(entry.stream1, body);
        assert_eq!(entry.stream0, headers);
        assert!(!entry.has_key_sha256);
    }

    #[test]
    fn parses_entry_with_key_sha256() {
        let body = b"body-bytes";
        let headers = b"HTTP/1.1 304 Not Modified\0\0";
        let data = build_entry("https://a.test/x", body, headers, Some([7u8; 32]));
        let entry = parse_simple_entry(&data).expect("valid entry");
        assert_eq!(entry.url, "https://a.test/x");
        assert_eq!(entry.stream1, body);
        assert!(entry.has_key_sha256);
    }

    #[test]
    fn empty_body_is_ok() {
        let headers = b"HTTP/1.1 204 No Content\0\0";
        let data = build_entry("https://a.test/e", b"", headers, None);
        let entry = parse_simple_entry(&data).expect("valid entry");
        assert!(entry.stream1.is_empty());
    }

    #[test]
    fn bad_header_magic_errs() {
        let mut data = build_entry("https://a.test/x", b"b", b"HTTP/1.1 200 OK\0\0", None);
        data[0] ^= 0xff;
        let err = parse_simple_entry(&data).unwrap_err();
        assert!(matches!(err, CacheError::BadHeaderMagic { .. }), "{err}");
    }

    #[test]
    fn truncated_file_errs() {
        let data = vec![0u8; 10];
        let err = parse_simple_entry(&data).unwrap_err();
        assert!(matches!(err, CacheError::TooSmall { .. }), "{err}");
    }

    #[test]
    fn lying_stream0_size_errs() {
        // A stream_size larger than the whole file must not panic — it must Err.
        let mut data = build_entry("https://a.test/x", b"body", b"HTTP/1.1 200 OK\0\0", None);
        let eof0 = data.len() - EOF_SIZE;
        // overwrite stream_size (offset +16 within the EOF) with a huge value
        data[eof0 + 16..eof0 + 20].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        let err = parse_simple_entry(&data).unwrap_err();
        assert!(matches!(err, CacheError::OutOfBounds { .. }), "{err}");
    }

    #[test]
    fn corrupt_eof1_magic_errs() {
        // Corrupt the stream-1 EOF so a lying layout is caught, not trusted.
        let body = b"12345678";
        let headers = b"HTTP/1.1 200 OK\0\0";
        let mut data = build_entry("https://a.test/x", body, headers, None);
        // stream-1 EOF starts right after key+body: HEADER + url.len + body.len
        let eof1 = HEADER_SIZE + "https://a.test/x".len() + body.len();
        data[eof1] ^= 0xff;
        let err = parse_simple_entry(&data).unwrap_err();
        assert!(matches!(err, CacheError::BadEofMagic { .. }), "{err}");
    }

    #[test]
    fn truncation_at_every_length_never_panics() {
        // Every prefix of a valid entry — including lengths that leave an EOF
        // offset or key_length field pointing past the (now shorter) buffer —
        // must yield Ok or a descriptive Err, never an out-of-bounds panic.
        let full = build_entry(
            "https://a.test/x",
            b"body-bytes",
            b"HTTP/1.1 200 OK\0\0",
            None,
        );
        for len in 0..=full.len() {
            let _ = parse_simple_entry(&full[..len]);
        }
    }

    #[test]
    fn lying_eof_offsets_and_flags_never_panic() {
        // Corrupt each byte of the stream-0 EOF record (magic, flags, size) to a
        // hostile value; a lying stream size / flag word must be rejected, not
        // trusted into an out-of-bounds slice.
        let base = build_entry(
            "https://a.test/x",
            b"12345678",
            b"HTTP/1.1 200 OK\0\0",
            None,
        );
        let eof0 = base.len() - EOF_SIZE;
        for byte in eof0..base.len() {
            let mut data = base.clone();
            data[byte] = 0xff;
            let _ = parse_simple_entry(&data);
        }
    }

    #[test]
    fn non_utf8_key_errs() {
        let mut data = build_entry("https://a.test/x", b"b", b"HTTP/1.1 200 OK\0\0", None);
        // Corrupt a key byte to invalid UTF-8 (0xff is never valid in UTF-8).
        data[HEADER_SIZE] = 0xff;
        let err = parse_simple_entry(&data).unwrap_err();
        assert!(matches!(err, CacheError::KeyNotUtf8 { .. }), "{err}");
    }
}
