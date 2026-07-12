//! Little-endian varint and truncated-int decoders used throughout the Chromium
//! IndexedDB LevelDB coding.
//!
//! Both mirror `content/browser/indexed_db/indexed_db_leveldb_coding.{h,cc}`:
//!
//! * [`read_le_varint`] is the LevelDB `DecodeVarInt` — an unsigned LEB128 with a
//!   hard 10-byte (64-bit) ceiling, so a corrupt continuation-bit run can never
//!   spin past the value it encodes.
//! * [`decode_truncated_int`] is the "dumb" `DecodeInt`: raw little-endian bytes
//!   with no length prefix, sized by its position at the end of a key or value.

/// Maximum bytes a 64-bit LEB128 varint can occupy (`ceil(64 / 7)`).
const MAX_VARINT_LEN: usize = 10;

/// Decode an unsigned little-endian varint (LEB128) from the front of `data`.
///
/// Returns `(value, bytes_consumed)`, or `None` when the buffer ends mid-varint
/// or the continuation bits run past [`MAX_VARINT_LEN`] (a malformed/overlong
/// encoding). Never panics and never reads out of bounds.
#[must_use]
pub(crate) fn read_le_varint(_data: &[u8]) -> Option<(u64, usize)> {
    // RED stub — real decoder lands in the GREEN commit.
    None
}

/// Decode a truncated little-endian integer occupying *all* of `data`.
///
/// Chromium's `EncodeInt` writes little-endian bytes until no `1` bits remain;
/// the decoder must already know the width (it sits at the end of a key or
/// value). More than 8 bytes cannot fit a `u64`, so trailing bytes past the
/// eighth are ignored rather than wrapping.
#[must_use]
pub(crate) fn decode_truncated_int(_data: &[u8]) -> u64 {
    // RED stub — real decoder lands in the GREEN commit.
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_byte_varint() {
        assert_eq!(read_le_varint(&[0x00]), Some((0, 1)));
        assert_eq!(read_le_varint(&[0x05]), Some((5, 1)));
        assert_eq!(read_le_varint(&[0x7f]), Some((127, 1)));
    }

    #[test]
    fn multi_byte_varint() {
        // 128 = 0x80 0x01
        assert_eq!(read_le_varint(&[0x80, 0x01]), Some((128, 2)));
        // 300 = 0xac 0x02
        assert_eq!(read_le_varint(&[0xac, 0x02]), Some((300, 2)));
        // Consumes only the varint, leaving trailing bytes.
        assert_eq!(read_le_varint(&[0xac, 0x02, 0xff, 0xff]), Some((300, 2)));
    }

    #[test]
    fn truncated_varint_is_none() {
        // Continuation bit set but buffer ends.
        assert_eq!(read_le_varint(&[0x80]), None);
        assert_eq!(read_le_varint(&[]), None);
    }

    #[test]
    fn overlong_varint_is_none() {
        // 11 bytes all with the continuation bit set: past the 64-bit ceiling.
        let overlong = [0x80u8; 11];
        assert_eq!(read_le_varint(&overlong), None);
    }

    #[test]
    fn truncated_int_le() {
        assert_eq!(decode_truncated_int(&[0x01]), 1);
        assert_eq!(decode_truncated_int(&[0x00, 0x01]), 256);
        assert_eq!(decode_truncated_int(&[0xff, 0xff]), 0xffff);
        assert_eq!(decode_truncated_int(&[]), 0);
    }

    #[test]
    fn truncated_int_ignores_bytes_past_u64() {
        // 9 bytes: the 9th must not wrap the u64.
        let bytes = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        assert_eq!(decode_truncated_int(&bytes), u64::MAX);
    }
}
