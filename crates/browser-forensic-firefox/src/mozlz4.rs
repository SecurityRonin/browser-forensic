//! Bounds-checked mozLz4 (`.jsonlz4`) decompression, shared by the Firefox
//! `sessionstore.jsonlz4` and `bookmarkbackups/*.jsonlz4` parsers.
//!
//! Framing (Mozilla `toolkit/components/lz4.js` and `mozilla::Compression` in
//! `mfbt/lz4/`): 8-byte magic `mozLz40\0`, a 4-byte little-endian uncompressed
//! size, then a single raw LZ4 block. The magic constant is reused from
//! `forensicnomicon::sqlite::MOZLZ4_MAGIC`.
//!
//! The declared size is capped before allocation so a tiny hostile file that
//! declares a huge output cannot exhaust memory (decompression-bomb guard);
//! malformed input yields an `Err`, never a panic.

use anyhow::{anyhow, Result};
use forensicnomicon::sqlite::MOZLZ4_MAGIC;

/// Length of the mozLz4 header: 8-byte magic + 4-byte little-endian size.
pub const MOZLZ4_HEADER_LEN: usize = 12;

/// Hard cap on the declared uncompressed size (decompression-bomb guard). 256
/// MiB is far above any real Firefox bookmark backup or sessionstore, yet bounds
/// the up-front allocation a hostile declared size could request.
pub const MAX_DECOMPRESSED: usize = 256 * 1024 * 1024;

/// Decompress a mozLz4 buffer with the default [`MAX_DECOMPRESSED`] cap.
///
/// # Errors
/// Returns an error if the buffer is shorter than the header, has the wrong
/// magic, declares a size over the cap, or the LZ4 block is malformed.
pub fn decompress_mozlz4(data: &[u8]) -> Result<Vec<u8>> {
    decompress_mozlz4_capped(data, MAX_DECOMPRESSED)
}

/// Decompress a mozLz4 buffer, rejecting a declared uncompressed size larger
/// than `cap` before any allocation.
///
/// # Errors
/// See [`decompress_mozlz4`].
pub fn decompress_mozlz4_capped(_data: &[u8], _cap: usize) -> Result<Vec<u8>> {
    // RED stub: real implementation lands in the GREEN commit.
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frame arbitrary bytes as a valid mozLz4 buffer (mint a `.jsonlz4`).
    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MOZLZ4_MAGIC);
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&lz4_flex::block::compress(payload));
        out
    }

    #[test]
    fn roundtrips_a_valid_mozlz4_buffer() {
        let payload = br#"{"version":[1],"children":[]}"#;
        let framed = frame(payload);
        let out = decompress_mozlz4(&framed).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn rejects_input_shorter_than_header() {
        let err = decompress_mozlz4(b"mozLz4").unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut framed = frame(b"hello");
        framed[3] = b'X';
        let err = decompress_mozlz4(&framed).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("magic"));
    }

    #[test]
    fn rejects_declared_size_over_cap() {
        // Valid magic, but the declared size is absurd: bomb guard must reject
        // before allocating.
        let mut framed = Vec::new();
        framed.extend_from_slice(MOZLZ4_MAGIC);
        framed.extend_from_slice(&u32::MAX.to_le_bytes());
        framed.extend_from_slice(&[0u8; 4]);
        let err = decompress_mozlz4_capped(&framed, 1024).unwrap_err();
        assert!(err.to_string().contains("cap") || err.to_string().contains("bomb"));
    }

    #[test]
    fn malformed_block_errors_without_panicking() {
        // Valid header declaring 4096 bytes, but the "block" is garbage.
        let mut framed = Vec::new();
        framed.extend_from_slice(MOZLZ4_MAGIC);
        framed.extend_from_slice(&4096u32.to_le_bytes());
        framed.extend_from_slice(&[0xffu8; 8]);
        assert!(decompress_mozlz4(&framed).is_err());
    }
}
