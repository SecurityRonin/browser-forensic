//! Panic-free, memory-bounded HTTP `Content-Encoding` decompression.
//!
//! SimpleCache stores the response body exactly as received on the wire, so it
//! is still compressed under the response's `Content-Encoding`. This module
//! decodes `gzip`/`deflate`/`br`/`zstd`/`identity` using vetted ecosystem
//! crates (`flate2`, `brotli`, pure-Rust `ruzstd`) behind a single dispatch,
//! with a hard absolute-output cap **and** an expansion-ratio cap so a
//! decompression bomb yields an `Err`, never an out-of-memory or panic.
//!
//! Unknown/unsupported encodings are never a silent failure: the raw bytes are
//! returned together with a note naming the offending encoding token.

use std::io::Read;

use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use ruzstd::decoding::StreamingDecoder;

use crate::error::CacheError;

/// Caps that bound decompression output (defends against decompression bombs).
#[derive(Debug, Clone, Copy)]
pub struct DecompressLimits {
    /// Absolute maximum decoded bytes. Output past this is an error, not an OOM.
    pub max_output: usize,
    /// Maximum decoded/input size ratio. Guards highly-compressible bombs whose
    /// absolute size is modest but whose expansion factor is extreme.
    pub max_ratio: usize,
}

impl Default for DecompressLimits {
    fn default() -> Self {
        Self {
            max_output: 128 * 1024 * 1024, // 128 MiB
            max_ratio: 1_000,
        }
    }
}

/// The result of decoding a response body.
#[derive(Debug, Clone)]
pub struct DecodeOutcome {
    /// Decoded content bytes — or the raw bytes when the encoding is unknown.
    pub bytes: Vec<u8>,
    /// `true` when `bytes` are the usable decoded content (`identity` counts).
    /// `false` when the encoding was unrecognized and `bytes` are still raw.
    pub decoded: bool,
    /// A human-readable note (unknown encoding, deflate variant, …), if any.
    pub note: Option<String>,
}

/// Decode a response body given its `Content-Encoding`.
///
/// # Errors
///
/// Returns [`CacheError::Decompress`] on malformed compressed input,
/// [`CacheError::OutputCapExceeded`] / [`CacheError::RatioExceeded`] when the
/// output would breach the [`DecompressLimits`]. Never panics.
pub fn decode_body(
    encoding: Option<&str>,
    raw: &[u8],
    limits: &DecompressLimits,
) -> Result<DecodeOutcome, CacheError> {
    let token = encoding.map(|e| e.trim().to_ascii_lowercase());
    match token.as_deref() {
        None | Some("" | "identity") => Ok(DecodeOutcome {
            bytes: raw.to_vec(),
            decoded: true,
            note: None,
        }),
        Some("gzip" | "x-gzip") => Ok(DecodeOutcome {
            bytes: read_capped(GzDecoder::new(raw), raw.len(), limits, "gzip")?,
            decoded: true,
            note: None,
        }),
        Some("deflate") => decode_deflate(raw, limits),
        Some("br") => Ok(DecodeOutcome {
            bytes: read_capped(
                brotli::Decompressor::new(raw, 8192),
                raw.len(),
                limits,
                "br",
            )?,
            decoded: true,
            note: None,
        }),
        Some("zstd") => {
            let decoder = StreamingDecoder::new(raw).map_err(|e| CacheError::Decompress {
                encoding: "zstd".to_string(),
                detail: e.to_string(),
            })?;
            Ok(DecodeOutcome {
                bytes: read_capped(decoder, raw.len(), limits, "zstd")?,
                decoded: true,
                note: None,
            })
        }
        Some(other) => Ok(DecodeOutcome {
            bytes: raw.to_vec(),
            decoded: false,
            note: Some(format!(
                "unsupported content-encoding: {other:?} ({} raw bytes retained)",
                raw.len()
            )),
        }),
    }
}

/// Read a decoder to EOF, enforcing the absolute-output and ratio caps as it
/// goes so peak memory never exceeds `max_output`.
fn read_capped<R: Read>(
    mut r: R,
    input_len: usize,
    limits: &DecompressLimits,
    encoding: &str,
) -> Result<Vec<u8>, CacheError> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                return Err(CacheError::Decompress {
                    encoding: encoding.to_string(),
                    detail: e.to_string(),
                })
            }
        };
        let new_len = out.len() + n;
        if new_len > limits.max_output {
            return Err(CacheError::OutputCapExceeded {
                produced: new_len,
                cap: limits.max_output,
            });
        }
        if input_len > 0 && new_len > input_len.saturating_mul(limits.max_ratio) {
            return Err(CacheError::RatioExceeded {
                input: input_len,
                output: new_len,
                max_ratio: limits.max_ratio,
            });
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

/// HTTP `deflate` is ambiguous (usually zlib-wrapped, occasionally raw DEFLATE).
/// Try zlib first, fall back to raw DEFLATE — but never mask a cap breach.
fn decode_deflate(raw: &[u8], limits: &DecompressLimits) -> Result<DecodeOutcome, CacheError> {
    match read_capped(ZlibDecoder::new(raw), raw.len(), limits, "deflate") {
        Ok(bytes) => Ok(DecodeOutcome {
            bytes,
            decoded: true,
            note: None,
        }),
        Err(e @ (CacheError::OutputCapExceeded { .. } | CacheError::RatioExceeded { .. })) => {
            Err(e)
        }
        Err(_) => {
            let bytes = read_capped(DeflateDecoder::new(raw), raw.len(), limits, "deflate")?;
            Ok(DecodeOutcome {
                bytes,
                decoded: true,
                note: Some("decoded as raw DEFLATE (no zlib header)".to_string()),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::{GzEncoder, ZlibEncoder};
    use flate2::Compression;
    use std::io::Write;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    // Real `brotli -q 11` / `zstd -19` CLI output (tier-2 oracle: independent encoder).
    const BR_HEX: &str = "1f4300b8c4dc46a95e88dbf46f514411840335080e3970f89634cf030dc402871cd28dcfa9c5d8da76f8f602ae73241d75f023c985e8567de89c1035e7434cb900";
    const BR_PLAIN: &str = "brotli works: the quick brown fox jumps over the lazy dog 0123456789";
    const ZS_HEX: &str = "28b52ffd04681102007a73746420776f726b733a2074686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672030313233343536373839810960f9";
    const ZS_PLAIN: &str = "zstd works: the quick brown fox jumps over the lazy dog 0123456789";

    #[test]
    fn identity_and_none_pass_through() {
        let raw = b"plain body";
        let d = DecompressLimits::default();
        for enc in [None, Some("identity"), Some(""), Some(" IDENTITY ")] {
            let out = decode_body(enc, raw, &d).unwrap();
            assert_eq!(out.bytes, raw, "enc={enc:?}");
            assert!(out.decoded);
        }
    }

    #[test]
    fn gzip_roundtrip() {
        let plain = b"gzip works: the quick brown fox jumps over the lazy dog 0123456789";
        let out = decode_body(Some("gzip"), &gzip(plain), &DecompressLimits::default()).unwrap();
        assert_eq!(out.bytes, plain);
        assert!(out.decoded);
    }

    #[test]
    fn deflate_zlib_roundtrip() {
        let plain = b"deflate/zlib works 0123456789 abcdefghijklmnop";
        let out = decode_body(Some("deflate"), &zlib(plain), &DecompressLimits::default()).unwrap();
        assert_eq!(out.bytes, plain);
    }

    #[test]
    fn brotli_decodes_real_vector() {
        let out = decode_body(Some("br"), &hex(BR_HEX), &DecompressLimits::default()).unwrap();
        assert_eq!(out.bytes, BR_PLAIN.as_bytes());
        assert!(out.decoded);
    }

    #[test]
    fn zstd_decodes_real_vector() {
        let out = decode_body(Some("zstd"), &hex(ZS_HEX), &DecompressLimits::default()).unwrap();
        assert_eq!(out.bytes, ZS_PLAIN.as_bytes());
        assert!(out.decoded);
    }

    #[test]
    fn unknown_encoding_returns_raw_with_note() {
        let raw = b"who knows";
        let out = decode_body(Some("snappy"), raw, &DecompressLimits::default()).unwrap();
        assert_eq!(out.bytes, raw);
        assert!(!out.decoded);
        let note = out.note.expect("note present");
        assert!(
            note.contains("snappy"),
            "note should name the token: {note}"
        );
    }

    #[test]
    fn output_cap_exceeded_errs() {
        let bomb = gzip(&vec![0u8; 4 * 1024 * 1024]); // ~4 MiB of zeros
        let limits = DecompressLimits {
            max_output: 64 * 1024,
            max_ratio: usize::MAX,
        };
        let err = decode_body(Some("gzip"), &bomb, &limits).unwrap_err();
        assert!(matches!(err, CacheError::OutputCapExceeded { .. }), "{err}");
    }

    #[test]
    fn ratio_bomb_errs() {
        let bomb = gzip(&vec![0u8; 4 * 1024 * 1024]);
        let limits = DecompressLimits {
            max_output: usize::MAX,
            max_ratio: 10,
        };
        let err = decode_body(Some("gzip"), &bomb, &limits).unwrap_err();
        assert!(matches!(err, CacheError::RatioExceeded { .. }), "{err}");
    }

    #[test]
    fn malformed_gzip_errs_no_panic() {
        let junk = vec![0x1f, 0x8b, 0x08, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22];
        let err = decode_body(Some("gzip"), &junk, &DecompressLimits::default()).unwrap_err();
        assert!(matches!(err, CacheError::Decompress { .. }), "{err}");
    }
}
