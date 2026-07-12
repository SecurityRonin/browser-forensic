//! Error type for cache parsing and decompression.
//!
//! Every variant carries the offending value + location so an investigator can
//! identify what failed (Fail-loud: never report "unknown" without the bytes).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("file too small: {found} bytes, need at least {need}")]
    TooSmall { found: usize, need: usize },

    #[error(
        "bad SimpleCache header magic at offset 0: found {found:#018x}, expected {expected:#018x}"
    )]
    BadHeaderMagic { found: u64, expected: u64 },

    #[error("bad SimpleCache EOF magic at offset {offset}: found {found:#018x}, expected {expected:#018x}")]
    BadEofMagic {
        found: u64,
        offset: usize,
        expected: u64,
    },

    #[error("field `{field}` value {value} out of bounds for a {file_len}-byte file")]
    OutOfBounds {
        field: &'static str,
        value: u64,
        file_len: usize,
    },

    #[error("cache key (URL) is not valid UTF-8 ({len} bytes at offset {offset})")]
    KeyNotUtf8 { len: usize, offset: usize },

    #[error("decompression failed for `{encoding}` input: {detail}")]
    Decompress { encoding: String, detail: String },

    #[error("decompressed output exceeds absolute cap: produced >= {produced} bytes (cap {cap})")]
    OutputCapExceeded { produced: usize, cap: usize },

    #[error("decompression ratio bomb: {input} input bytes expanded past {output} bytes (max ratio {max_ratio}x)")]
    RatioExceeded {
        input: usize,
        output: usize,
        max_ratio: usize,
    },

    #[error("i/o error reading `{path}`: {detail}")]
    Io { path: String, detail: String },
}
