//! The Blink value wrapper that sits between a LevelDB record value and its V8
//! `ValueSerializer` payload.
//!
//! Mirrors `third_party/blink/renderer/modules/indexeddb/idb_value_wrapping.cc`
//! and `.../bindings/core/v8/serialization/trailer_reader.h`. A stored value is:
//!
//! ```text
//! <value_version varint> 0xFF <blink_version varint> [wrapper] <V8 stream…>
//! ```
//!
//! where `[wrapper]` is either a `kReplaceWithBlob` marker (the real payload
//! lives in an external `.blob` file — out of scope here, surfaced as
//! [`Wrapper::ExternalBlob`]) or, for `blink_version >=`
//! [`MIN_WIRE_FORMAT_VERSION_FOR_TRAILER`], a 13-byte trailer that is skipped.
//! What remains is the V8 stream for [`super::v8::decode_v8`].

use super::varint::read_le_varint;

/// Blink wire-format version at which a 13-byte trailer precedes the V8 stream.
const MIN_WIRE_FORMAT_VERSION_FOR_TRAILER: u64 = 21;
/// Size of that trailer (`kTrailerOffsetTag` byte + u64 offset + u32 length).
const TRAILER_SIZE: usize = 13;
/// Blink type tag that opens the wrapper.
const BLINK_TYPE_TAG: u8 = 0xff;
/// Marker byte: the payload is stored in an external blob file.
const REPLACE_WITH_BLOB: u8 = 0x01;

/// The result of unwrapping a record value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Wrapper<'a> {
    /// An inline V8 `ValueSerializer` stream, ready to decode.
    V8 { v8: &'a [u8], blink_version: u64 },
    /// The value was wrapped out to an external blob file (not decoded here).
    ExternalBlob {
        blink_version: u64,
        size: u64,
        index: u64,
    },
    /// The wrapper was missing or truncated — surfaced, never guessed.
    Malformed,
}

/// Strip the Blink wrapper from a record value, returning the inline V8 stream
/// (or an [`ExternalBlob`] / [`Malformed`] result). Never panics.
///
/// [`ExternalBlob`]: Wrapper::ExternalBlob
/// [`Malformed`]: Wrapper::Malformed
#[must_use]
pub(crate) fn strip_blink_wrapper(value: &[u8]) -> Wrapper<'_> {
    // Leading value-version varint.
    let Some((_value_version, vv_len)) = read_le_varint(value) else {
        return Wrapper::Malformed;
    };
    let mut pos = vv_len;

    // Blink type tag.
    if value.get(pos) != Some(&BLINK_TYPE_TAG) {
        return Wrapper::Malformed;
    }
    pos += 1;

    // Blink wire-format version.
    let Some(rest) = value.get(pos..) else {
        return Wrapper::Malformed;
    };
    let Some((blink_version, bv_len)) = read_le_varint(rest) else {
        return Wrapper::Malformed;
    };
    pos += bv_len;

    // Peek: external-blob marker, or an inline stream (optionally trailered).
    match value.get(pos) {
        Some(&REPLACE_WITH_BLOB) => {
            pos += 1;
            let Some((size, s_len)) = value.get(pos..).and_then(read_le_varint) else {
                return Wrapper::Malformed;
            };
            pos += s_len;
            let Some((index, _i_len)) = value.get(pos..).and_then(read_le_varint) else {
                return Wrapper::Malformed;
            };
            Wrapper::ExternalBlob {
                blink_version,
                size,
                index,
            }
        }
        Some(_) => {
            if blink_version >= MIN_WIRE_FORMAT_VERSION_FOR_TRAILER {
                // Skip the 13-byte trailer; require it to be fully present.
                match pos.checked_add(TRAILER_SIZE) {
                    Some(after) if after <= value.len() => pos = after,
                    _ => return Wrapper::Malformed,
                }
            }
            match value.get(pos..) {
                Some(v8) => Wrapper::V8 { v8, blink_version },
                None => Wrapper::Malformed,
            }
        }
        None => Wrapper::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn real_reddit_value_trailered_v21() {
        // 03 | ff 15 | fe + 12 trailer bytes | ff0f 22 05 "false"
        let v = hx("03ff15fe000000000000000000000000ff0f220566616c7365");
        match strip_blink_wrapper(&v) {
            Wrapper::V8 { v8, blink_version } => {
                assert_eq!(blink_version, 21);
                assert_eq!(v8, hx("ff0f220566616c7365").as_slice());
            }
            other => panic!("expected V8, got {other:?}"),
        }
    }

    #[test]
    fn real_whatsapp_value_no_trailer_v20() {
        // 02 | ff 14 | ff0d ... (blink v20 < 21 -> no trailer)
        let v =
            hx("02ff14ff0d6f22036b6579220b72656d656d6265722d6d65220576616c75652204747275657b02");
        match strip_blink_wrapper(&v) {
            Wrapper::V8 { v8, blink_version } => {
                assert_eq!(blink_version, 20);
                assert_eq!(v8[0], 0xff);
                assert_eq!(v8[1], 0x0d);
            }
            other => panic!("expected V8, got {other:?}"),
        }
    }

    #[test]
    fn external_blob_surfaced() {
        // 00 | ff 15 | 01 (blob) | size 0x40 | index 0x02
        let v = hx("00ff15014002");
        match strip_blink_wrapper(&v) {
            Wrapper::ExternalBlob {
                blink_version,
                size,
                index,
            } => {
                assert_eq!(blink_version, 21);
                assert_eq!(size, 0x40);
                assert_eq!(index, 0x02);
            }
            other => panic!("expected ExternalBlob, got {other:?}"),
        }
    }

    #[test]
    fn missing_blink_tag_is_malformed() {
        // leading varint 03 then 0x00 (not 0xff)
        assert_eq!(strip_blink_wrapper(&hx("0300")), Wrapper::Malformed);
    }

    #[test]
    fn truncated_trailer_is_malformed() {
        // v21 promises a 13-byte trailer but only a few bytes follow.
        assert_eq!(strip_blink_wrapper(&hx("03ff15fe0000")), Wrapper::Malformed);
    }

    #[test]
    fn empty_is_malformed() {
        assert_eq!(strip_blink_wrapper(&[]), Wrapper::Malformed);
    }
}
