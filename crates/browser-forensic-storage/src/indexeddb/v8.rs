//! Panic-free decoder for the V8 `ValueSerializer` stream that IndexedDB stores
//! as a record value (inside the Blink wrapper — see [`super::envelope`]).
//!
//! Mirrors `v8/src/objects/value-serializer.cc`. A stream is `0xff <version u8
//! varint>` followed by one tagged value. This decoder covers the subset that
//! carries ordinary structured data — the objects, arrays, strings, numbers,
//! booleans, dates, maps, sets and big-ints that messenger/web-app records use —
//! and renders them to [`serde_json::Value`].
//!
//! Tags outside that subset (host objects, typed-array views, WASM, shared
//! objects, errors, …) are **surfaced, never fabricated**: the offending tag
//! byte and its offset are recorded in [`V8Decoded::unsupported`] and parsing
//! stops at that point (the payload length is unknown, so continuing would
//! misalign the stream). The value decoded up to that point is still returned.
//!
//! Every read is bounds-checked, recursion is depth-capped, and no allocation is
//! sized from an untrusted count — malformed input yields a partial decode or a
//! `None` header result, never a panic or an unbounded allocation.

use serde_json::{json, Map, Value};

use super::varint::read_le_varint;

/// Maximum container nesting before the decoder gives up (defends against a
/// deeply-nested-object bomb). Real records nest only a handful deep.
const MAX_DEPTH: usize = 128;
/// Maximum BigInt magnitude width we render to a decimal string.
const MAX_BIGINT_BYTES: usize = 64;
/// Maximum ArrayBuffer bytes rendered to hex (larger buffers are summarised).
const MAX_ARRAYBUFFER_HEX_BYTES: usize = 4096;

/// One unsupported tag encountered during decoding: the raw byte and where it
/// sat, so an examiner can identify it from the spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnsupportedTag {
    pub tag: u8,
    pub offset: usize,
}

/// The outcome of decoding a V8 value stream.
#[derive(Debug, Clone)]
pub(crate) struct V8Decoded {
    /// Best-effort JSON rendering of the value (partial if `complete` is false).
    pub value: Value,
    /// The stream's self-declared serializer version (0 if no `0xff` header).
    pub version: u32,
    /// Tags the decoder could not decode, surfaced verbatim.
    pub unsupported: Vec<UnsupportedTag>,
    /// True if the whole stream decoded cleanly; false if it stopped early on an
    /// unsupported tag or malformed bytes.
    pub complete: bool,
}

/// Decode a V8 `ValueSerializer` stream. Returns `None` only when there is not
/// even a single readable value (empty input). Otherwise a [`V8Decoded`] is
/// always produced — possibly partial, with `unsupported`/`complete` flagging
/// anything that could not be honestly decoded.
#[allow(dead_code, unused_variables)]
#[must_use]
pub(crate) fn decode_v8(data: &[u8]) -> Option<V8Decoded> {
    // RED stub — real decoder lands in the GREEN commit.
    None
}

#[allow(dead_code)]
#[must_use]
fn decode_v8_impl(data: &[u8]) -> Option<V8Decoded> {
    if data.is_empty() {
        return None;
    }
    let mut d = Decoder {
        data,
        pos: 0,
        unsupported: Vec::new(),
        aborted: false,
        id_table: Vec::new(),
    };
    let version = d.read_header();
    let value = match d.read_value(0) {
        Some(v) => v,
        None => {
            // Malformed/truncated before a value completed.
            d.aborted = true;
            Value::Null
        }
    };
    Some(V8Decoded {
        value,
        version,
        complete: !d.aborted && d.unsupported.is_empty(),
        unsupported: d.unsupported,
    })
}

struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
    unsupported: Vec<UnsupportedTag>,
    aborted: bool,
    /// Object-reference table: index = V8 object id, in creation order.
    id_table: Vec<Value>,
}

impl<'a> Decoder<'a> {
    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn take(&mut self) -> Option<u8> {
        let b = self.data.get(self.pos).copied()?;
        self.pos += 1;
        Some(b)
    }

    fn take_slice(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let s = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn read_varint(&mut self) -> Option<u64> {
        let (v, used) = read_le_varint(self.data.get(self.pos..)?)?;
        self.pos += used;
        Some(v)
    }

    /// Consume a leading `0xff <version>` header if present; return the version.
    fn read_header(&mut self) -> u32 {
        if self.peek() == Some(0xff) {
            self.pos += 1;
            let v = self.read_varint().unwrap_or(0);
            u32::try_from(v).unwrap_or(0)
        } else {
            0
        }
    }

    /// Skip padding / verify-count tags that carry no value.
    fn read_tag(&mut self) -> Option<u8> {
        loop {
            let t = self.take()?;
            // kPadding (\0), kVerifyObjectCount (?) are interstitial.
            if t == 0x00 || t == b'?' {
                continue;
            }
            return Some(t);
        }
    }

    fn abort_unsupported(&mut self, tag: u8, offset: usize) -> Value {
        self.aborted = true;
        self.unsupported.push(UnsupportedTag { tag, offset });
        json!({
            "__v8_unsupported__": {
                "tag": format!("0x{tag:02x}"),
                "tag_char": (tag as char).to_string(),
                "offset": offset,
            }
        })
    }

    #[allow(clippy::too_many_lines)]
    fn read_value(&mut self, depth: usize) -> Option<Value> {
        if self.aborted {
            return None;
        }
        if depth > MAX_DEPTH {
            self.aborted = true;
            return None;
        }
        let tag_offset = self.pos;
        let tag = self.read_tag()?;
        let value = match tag {
            b'_' | b'-' => Value::Null,        // undefined / the-hole
            b'0' => Value::Null,               // null
            b'T' | b'y' => Value::Bool(true),  // true / TrueObject
            b'F' | b'x' => Value::Bool(false), // false / FalseObject
            b'I' => {
                let raw = self.read_varint()?;
                json!(zigzag_decode(raw))
            }
            b'U' => {
                let raw = self.read_varint()?;
                json!(raw)
            }
            b'N' | b'n' => {
                // Double / NumberObject: 8 LE bytes.
                let raw = self.take_slice(8)?;
                let mut b = [0u8; 8];
                b.copy_from_slice(raw);
                json_number(f64::from_le_bytes(b))
            }
            b'D' => {
                // Date: 8 LE bytes, ms since epoch.
                let raw = self.take_slice(8)?;
                let mut b = [0u8; 8];
                b.copy_from_slice(raw);
                json_number(f64::from_le_bytes(b))
            }
            b'S' => self.read_utf8_string()?,
            b'"' => self.read_one_byte_string()?,
            b'c' => self.read_two_byte_string()?,
            b's' => self.read_value(depth)?, // StringObject wraps a string tag
            b'Z' | b'z' => self.read_bigint()?,
            b'^' => {
                let id = self.read_varint()?;
                let idx = usize::try_from(id).ok()?;
                self.id_table.get(idx).cloned().unwrap_or(Value::Null)
            }
            b'o' => self.read_js_object(depth)?,
            b'A' => self.read_dense_array(depth)?,
            b'a' => self.read_sparse_array(depth)?,
            b';' => self.read_js_map(depth)?,
            b'\'' => self.read_js_set(depth)?,
            b'B' => self.read_arraybuffer()?,
            b'R' => self.read_regexp()?,
            _ => self.abort_unsupported(tag, tag_offset),
        };
        Some(value)
    }

    fn read_utf8_string(&mut self) -> Option<Value> {
        let len = usize::try_from(self.read_varint()?).ok()?;
        let bytes = self.take_slice(len)?;
        Some(json!(String::from_utf8_lossy(bytes).into_owned()))
    }

    fn read_one_byte_string(&mut self) -> Option<Value> {
        let len = usize::try_from(self.read_varint()?).ok()?;
        let bytes = self.take_slice(len)?;
        // Latin-1: each byte is a code point.
        Some(json!(bytes.iter().map(|&b| b as char).collect::<String>()))
    }

    fn read_two_byte_string(&mut self) -> Option<Value> {
        let len = usize::try_from(self.read_varint()?).ok()?;
        let bytes = self.take_slice(len)?;
        let units = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]));
        let s: String = char::decode_utf16(units)
            .map(|r| r.unwrap_or('\u{fffd}'))
            .collect();
        Some(json!(s))
    }

    fn read_bigint(&mut self) -> Option<Value> {
        // bitfield: bit 0 = sign, remaining bits = byte length.
        let bitfield = self.read_varint()?;
        let negative = bitfield & 1 == 1;
        let byte_len = usize::try_from(bitfield >> 1).ok()?;
        let bytes = self.take_slice(byte_len)?;
        if byte_len > MAX_BIGINT_BYTES {
            // Too wide to render safely; surface it honestly.
            return Some(json!({
                "__v8_bigint__": { "bytes_hex": crate::to_hex(bytes), "negative": negative }
            }));
        }
        Some(json!(bigint_to_decimal(bytes, negative)))
    }

    fn read_js_object(&mut self, depth: usize) -> Option<Value> {
        let id = self.reserve_id();
        let mut map = Map::new();
        loop {
            if self.aborted {
                break;
            }
            if self.peek() == Some(b'{') {
                self.pos += 1;
                let _count = self.read_varint(); // property count (advisory)
                break;
            }
            let key = self.read_value(depth + 1)?;
            let val = self.read_value(depth + 1)?;
            map.insert(value_to_key(&key), val);
        }
        let value = Value::Object(map);
        self.set_id(id, value.clone());
        Some(value)
    }

    fn read_dense_array(&mut self, depth: usize) -> Option<Value> {
        let id = self.reserve_id();
        let len = usize::try_from(self.read_varint()?).ok()?;
        let mut items = Vec::new();
        for _ in 0..len {
            if self.aborted {
                break;
            }
            items.push(self.read_value(depth + 1)?);
        }
        // Trailing named properties, then end tag + counts.
        loop {
            if self.aborted {
                break;
            }
            if self.peek() == Some(b'$') {
                self.pos += 1;
                let _props = self.read_varint();
                let _length = self.read_varint();
                break;
            }
            // key/value property on the array object — read and discard the key,
            // keep the value's bytes consumed (rare on IDB records).
            let _k = self.read_value(depth + 1)?;
            let _v = self.read_value(depth + 1)?;
        }
        let value = Value::Array(items);
        self.set_id(id, value.clone());
        Some(value)
    }

    fn read_sparse_array(&mut self, depth: usize) -> Option<Value> {
        // Rendered as an object of index -> value (avoids a huge dense alloc).
        let id = self.reserve_id();
        let _length = self.read_varint()?;
        let mut map = Map::new();
        loop {
            if self.aborted {
                break;
            }
            if self.peek() == Some(b'@') {
                self.pos += 1;
                let _props = self.read_varint();
                let _length2 = self.read_varint();
                break;
            }
            let key = self.read_value(depth + 1)?;
            let val = self.read_value(depth + 1)?;
            map.insert(value_to_key(&key), val);
        }
        let value = Value::Object(map);
        self.set_id(id, value.clone());
        Some(value)
    }

    fn read_js_map(&mut self, depth: usize) -> Option<Value> {
        // Rendered as an array of [key, value] pairs (keys may be non-string).
        let id = self.reserve_id();
        let mut pairs = Vec::new();
        loop {
            if self.aborted {
                break;
            }
            if self.peek() == Some(b':') {
                self.pos += 1;
                let _count = self.read_varint();
                break;
            }
            let k = self.read_value(depth + 1)?;
            let v = self.read_value(depth + 1)?;
            pairs.push(Value::Array(vec![k, v]));
        }
        let value = json!({ "__v8_map__": pairs });
        self.set_id(id, value.clone());
        Some(value)
    }

    fn read_js_set(&mut self, depth: usize) -> Option<Value> {
        let id = self.reserve_id();
        let mut items = Vec::new();
        loop {
            if self.aborted {
                break;
            }
            if self.peek() == Some(b',') {
                self.pos += 1;
                let _count = self.read_varint();
                break;
            }
            items.push(self.read_value(depth + 1)?);
        }
        let value = json!({ "__v8_set__": items });
        self.set_id(id, value.clone());
        Some(value)
    }

    fn read_arraybuffer(&mut self) -> Option<Value> {
        let id = self.reserve_id();
        let len = usize::try_from(self.read_varint()?).ok()?;
        let bytes = self.take_slice(len)?;
        let value = if len > MAX_ARRAYBUFFER_HEX_BYTES {
            json!({ "__v8_arraybuffer__": { "len": len, "hex_truncated": crate::to_hex(&bytes[..MAX_ARRAYBUFFER_HEX_BYTES]) } })
        } else {
            json!({ "__v8_arraybuffer__": { "len": len, "hex": crate::to_hex(bytes) } })
        };
        self.set_id(id, value.clone());
        Some(value)
    }

    fn read_regexp(&mut self) -> Option<Value> {
        let pattern = self.read_value(0)?;
        let flags = self.read_varint()?;
        Some(json!({ "__v8_regexp__": { "source": pattern, "flags": flags } }))
    }

    fn reserve_id(&mut self) -> usize {
        let idx = self.id_table.len();
        self.id_table.push(Value::Null);
        idx
    }

    fn set_id(&mut self, idx: usize, value: Value) {
        if let Some(slot) = self.id_table.get_mut(idx) {
            *slot = value;
        }
    }
}

/// ZigZag-decode an unsigned varint into a signed integer (V8 `kInt32`).
fn zigzag_decode(n: u64) -> i64 {
    ((n >> 1) as i64) ^ -((n & 1) as i64)
}

/// JSON does not represent NaN/Infinity; those degrade to null rather than
/// producing invalid JSON.
fn json_number(f: f64) -> Value {
    serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number)
}

/// Render an object/map key `Value` to a JSON object-key string.
fn value_to_key(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

/// Convert little-endian magnitude bytes to a signed decimal string.
fn bigint_to_decimal(bytes: &[u8], negative: bool) -> String {
    // Repeated base-256 -> base-10 long division. `bytes` is small (<= 64).
    let mut digits: Vec<u8> = Vec::new(); // base-10 digits, little-endian
    for &byte in bytes.iter().rev() {
        // multiply existing by 256 and add byte
        let mut carry = u32::from(byte);
        for d in &mut digits {
            let cur = u32::from(*d) * 256 + carry;
            *d = (cur % 10) as u8;
            carry = cur / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    if digits.is_empty() {
        return "0".to_string();
    }
    let mut s = String::new();
    if negative {
        s.push('-');
    }
    for &d in digits.iter().rev() {
        s.push((b'0' + d) as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse an ASCII-hex string into bytes (test helper).
    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn real_reddit_string_false() {
        // V8 portion of the real Reddit `disable_pns` value: ff0f 22 05 "false".
        let d = decode_v8(&hx("ff0f220566616c7365")).unwrap();
        assert_eq!(d.version, 15);
        assert_eq!(d.value, json!("false"));
        assert!(d.complete);
        assert!(d.unsupported.is_empty());
    }

    #[test]
    fn real_linkedin_object_of_ints() {
        // ff0f o "sequenceNumber" I(29) "PageViewEvent" I(3) { 2
        let d = decode_v8(&hx(
            "ff0f6f220e73657175656e63654e756d626572493a220d50616765566965774576656e7449067b02",
        ))
        .unwrap();
        assert_eq!(d.value, json!({"sequenceNumber": 29, "PageViewEvent": 3}));
        assert!(d.complete);
    }

    #[test]
    fn real_whatsapp_nested_object() {
        // ff0d o "key" "remember-me" "value" "true" { 2 (blink v20, no trailer)
        let d = decode_v8(&hx(
            "ff0d6f22036b6579220b72656d656d6265722d6d65220576616c75652204747275657b02",
        ))
        .unwrap();
        assert_eq!(d.version, 13);
        assert_eq!(d.value, json!({"key": "remember-me", "value": "true"}));
    }

    #[test]
    fn primitives() {
        assert_eq!(decode_v8(&hx("ff0f54")).unwrap().value, json!(true));
        assert_eq!(decode_v8(&hx("ff0f46")).unwrap().value, json!(false));
        assert_eq!(decode_v8(&hx("ff0f30")).unwrap().value, json!(null));
        assert_eq!(decode_v8(&hx("ff0f5f")).unwrap().value, json!(null)); // undefined
        assert_eq!(decode_v8(&hx("ff0f55ac02")).unwrap().value, json!(300)); // U 300
        assert_eq!(decode_v8(&hx("ff0f4903")).unwrap().value, json!(-2)); // I zigzag(3)=-2
        let mut b = hx("ff0f4e");
        b.extend_from_slice(&1.5f64.to_le_bytes());
        assert_eq!(decode_v8(&b).unwrap().value, json!(1.5)); // N double
    }

    #[test]
    fn dense_array() {
        // A len2 [I(2)][I(4)] $ props0 length2  -> [2, 4]
        let d = decode_v8(&hx("ff0f410249044908240002")).unwrap();
        assert_eq!(d.value, json!([2, 4]));
        assert!(d.complete);
    }

    #[test]
    fn unsupported_tag_surfaced_not_fabricated() {
        // 'V' (ArrayBufferView) is unsupported -> recorded, not guessed.
        let d = decode_v8(&hx("ff0f56")).unwrap();
        assert!(!d.complete);
        assert_eq!(d.unsupported.len(), 1);
        assert_eq!(d.unsupported[0].tag, b'V');
    }

    #[test]
    fn unsupported_inside_object_keeps_partial() {
        // o "a" I(1) "b" <unsupported 'w'>
        let d = decode_v8(&hx("ff0f6f220161490222016277")).unwrap();
        assert_eq!(d.value["a"], json!(1)); // the good field survives
        assert!(!d.complete);
        assert_eq!(d.unsupported[0].tag, b'w');
    }

    #[test]
    fn truncated_string_no_panic() {
        // "S" claims 20 bytes but only 3 present -> partial, no panic.
        let d = decode_v8(&hx("ff0f5314616263")).unwrap();
        assert!(!d.complete);
    }

    #[test]
    fn empty_is_none() {
        assert!(decode_v8(&[]).is_none());
    }

    #[test]
    fn deeply_nested_object_bounded() {
        // 200 nested single-key objects exceeds MAX_DEPTH -> aborts, no panic.
        let mut b = hx("ff0f");
        for _ in 0..200 {
            b.push(b'o'); // begin object
            b.extend_from_slice(&hx("220161")); // key "a"
        }
        b.push(b'T'); // deepest value true
        let d = decode_v8(&b).unwrap();
        assert!(!d.complete);
    }

    #[test]
    fn bigint_small() {
        // Z bitfield byte_len=1 sign=0 -> 2; digit 0x05 -> "5"
        assert_eq!(decode_v8(&hx("ff0f5a0205")).unwrap().value, json!("5"));
        // negative: bitfield=3, byte 0x0a -> "-10"
        assert_eq!(decode_v8(&hx("ff0f5a030a")).unwrap().value, json!("-10"));
    }

    #[test]
    fn object_reference_resolves() {
        // Outer object: "self" -> ^0 (ref to the outer object id 0).
        // ff0f o "a" ^0 { 1  -> {"a": {} } (cycle rendered as the reserved slot)
        let d = decode_v8(&hx("ff0f6f2201615e007b01")).unwrap();
        assert!(d.value.is_object());
    }
}
