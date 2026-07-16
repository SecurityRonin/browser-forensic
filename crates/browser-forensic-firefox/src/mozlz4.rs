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
pub fn decompress_mozlz4_capped(data: &[u8], cap: usize) -> Result<Vec<u8>> {
    if data.len() < MOZLZ4_HEADER_LEN {
        return Err(anyhow!(
            "mozLz4 file too short: {} bytes (need at least {MOZLZ4_HEADER_LEN} for the header)",
            data.len()
        ));
    }
    if &data[..8] != MOZLZ4_MAGIC {
        return Err(anyhow!(
            "invalid mozLz4 magic {:02x?} at offset 0 (expected {:02x?})",
            &data[..8],
            MOZLZ4_MAGIC
        ));
    }
    // data.len() >= MOZLZ4_HEADER_LEN (guard above), so the declared-size u32 at
    // offset 8 is in range; the shared bounded reader returns its exact value.
    let declared = safe_read::le_u32(data, 8) as usize;
    if declared > cap {
        return Err(anyhow!(
            "mozLz4 declared uncompressed size {declared} exceeds cap {cap} \
             (possible decompression bomb)"
        ));
    }
    lz4_flex::block::decompress(&data[MOZLZ4_HEADER_LEN..], declared)
        .map_err(|e| anyhow!("mozLz4 LZ4 block decompression failed: {e}"))
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
    fn truncation_at_every_length_never_panics() {
        // The 12-byte header (magic + declared-size u32) read must tolerate any
        // truncation of a valid buffer without an out-of-bounds panic.
        let framed = frame(br#"{"version":[1],"children":[]}"#);
        for len in 0..=framed.len() {
            let _ = decompress_mozlz4(&framed[..len]);
        }
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
