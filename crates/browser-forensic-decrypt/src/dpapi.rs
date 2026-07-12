//! Windows DPAPI (`[MS-DPAPI]`) master-key and blob decryption, plus Chromium
//! `Local State` key recovery.
//!
//! No maintained Rust crate implements offline DPAPI, so the *format* handling is
//! reimplemented here; every cryptographic primitive is a RustCrypto crate
//! (`sha1`, `sha2`, `hmac`, `aes`, `cbc`) — nothing is hand-rolled. The key
//! derivation follows the reverse-engineered reference settled on by the
//! community: Benjamin Delpy's DPAPI notes and impacket's `dpapi.py`, which is
//! also the independent oracle the test vectors are checked against (see
//! `tests/data/README.md`).
//!
//! # Chain
//! 1. `prekey = HMAC-SHA1(SHA1(password_utf16le), (sid || NUL)_utf16le)`.
//! 2. The master-key file is decrypted with a **Microsoft-specific iterated
//!    HMAC-SHA512 KDF** (NOT standard PBKDF2 — each round's PRF input is the
//!    accumulated XOR) → AES-256-CBC → a 64-byte master key, gated by an HMAC.
//! 3. The blob derives a session key `HMAC-SHA512(SHA1(masterkey), salt)` →
//!    AES-256-CBC → the protected secret; the trailing signature is verified.
//! 4. Chromium `Local State` holds `base64("DPAPI" || blob)`; the blob's
//!    plaintext is the 32-byte AES-256-GCM profile key.
//!
//! # Scope
//! Only the modern algorithm pair Chromium produces on Windows 10/11 is
//! supported: `HashAlgo = CALG_SHA_512`, `CryptAlgo = CALG_AES_256`. Any other
//! algorithm id is refused loudly with the offending value (never fabricated).

use aes::Aes256;
use base64::Engine;
use cbc::cipher::block_padding::{NoPadding, Pkcs7};
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha1::{Digest, Sha1};
use sha2::Sha512;

use crate::error::{DecryptError, Result};

type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// `CALG_SHA_512` — the only supported `HashAlgo`.
const CALG_SHA_512: u32 = 0x0000_800E;
/// `CALG_AES_256` — the only supported `CryptAlgo`.
const CALG_AES_256: u32 = 0x0000_6610;
/// Fixed size of the `MasterKeyFile` header preceding the master-key section.
const MKF_HEADER_LEN: usize = 128;
/// Upper bound on the master-key KDF iteration count (real values are well under
/// this; the cap turns a hostile file into a loud error, not a hang).
const MAX_ITERATIONS: u32 = 10_000_000;

/// A parsed DPAPI blob (`DPAPI_BLOB`).
#[derive(Debug, Clone)]
pub struct DpapiBlob {
    /// GUID of the master key that protects this blob.
    pub guid_masterkey: [u8; 16],
    /// Symmetric-cipher algorithm id (`CryptAlgo`).
    pub crypt_algo: u32,
    /// Key-derivation salt.
    pub salt: Vec<u8>,
    /// Hash algorithm id (`HashAlgo`).
    pub hash_algo: u32,
    /// The `HMac` salt used for the trailing signature.
    pub hmac_salt: Vec<u8>,
    /// The ciphertext payload.
    pub data: Vec<u8>,
    /// The trailing signature (`Sign`).
    pub sign: Vec<u8>,
    /// The byte range the signature authenticates (`raw[20 .. len-signlen-4]`).
    pub to_sign: Vec<u8>,
}

/// How the DPAPI master key is supplied to key recovery.
pub enum DpapiSecret<'a> {
    /// A pre-decrypted 64-byte DPAPI master key.
    MasterKey([u8; 64]),
    /// A user password plus the SID and the raw master-key file bytes.
    UserPassword {
        /// The user's logon password (empty string if none).
        password: &'a str,
        /// The user SID (e.g. `S-1-5-21-…-1001`).
        sid: &'a str,
        /// Raw bytes of `%APPDATA%/Microsoft/Protect/<SID>/<GUID>`.
        masterkey_file: &'a [u8],
    },
}

/// Read a little-endian `u32` at `off`, or a loud parse error.
fn read_u32_le(buf: &[u8], off: usize) -> Result<u32> {
    let end = off
        .checked_add(4)
        .ok_or_else(|| DecryptError::Dpapi("offset overflow reading u32".into()))?;
    let bytes = buf
        .get(off..end)
        .ok_or_else(|| DecryptError::Dpapi(format!("truncated: need 4 bytes at offset {off}")))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read a little-endian `u64` at `off`, or a loud parse error.
fn read_u64_le(buf: &[u8], off: usize) -> Result<u64> {
    let end = off
        .checked_add(8)
        .ok_or_else(|| DecryptError::Dpapi("offset overflow reading u64".into()))?;
    let b = buf
        .get(off..end)
        .ok_or_else(|| DecryptError::Dpapi(format!("truncated: need 8 bytes at offset {off}")))?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// Borrow `len` bytes at `off`, or a loud parse error naming the shortfall.
fn take(buf: &[u8], off: usize, len: usize) -> Result<&[u8]> {
    let end = off
        .checked_add(len)
        .ok_or_else(|| DecryptError::Dpapi("offset overflow reading slice".into()))?;
    buf.get(off..end).ok_or_else(|| {
        DecryptError::Dpapi(format!(
            "truncated: need {len} bytes at offset {off}, have {}",
            buf.len()
        ))
    })
}

/// Lowercase hex.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Encode `s` as UTF-16LE bytes.
fn utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// HMAC-SHA512 of `msg` under `key` (64 bytes). HMAC accepts any key length.
fn hmac_sha512(key: &[u8], msg: &[u8]) -> Result<[u8; 64]> {
    let mut m = <Hmac<Sha512>>::new_from_slice(key)
        .map_err(|e| DecryptError::Dpapi(format!("HMAC-SHA512 init: {e}")))?;
    m.update(msg);
    let out = m.finalize().into_bytes();
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&out);
    Ok(arr)
}

/// HMAC-SHA1 of `msg` under `key` (20 bytes).
fn hmac_sha1(key: &[u8], msg: &[u8]) -> Result<[u8; 20]> {
    let mut m = <Hmac<Sha1>>::new_from_slice(key)
        .map_err(|e| DecryptError::Dpapi(format!("HMAC-SHA1 init: {e}")))?;
    m.update(msg);
    let out = m.finalize().into_bytes();
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&out);
    Ok(arr)
}

/// Derive the SHA1 pre-key from a user password + SID:
/// `HMAC-SHA1(SHA1(password_utf16le), (sid || NUL)_utf16le)`.
#[must_use]
pub fn derive_dpapi_prekey_sha1(password: &str, sid: &str) -> [u8; 20] {
    let pwhash = Sha1::digest(utf16le(password));
    let mut sid_nul = String::with_capacity(sid.len() + 1);
    sid_nul.push_str(sid);
    sid_nul.push('\0');
    // HMAC-SHA1 init cannot fail for a valid-length key; on the impossible error
    // fall back to zeros (still non-fabricating: it will fail the downstream HMAC).
    hmac_sha1(&pwhash, &utf16le(&sid_nul)).unwrap_or([0u8; 20])
}

/// Microsoft DPAPI master-key KDF (impacket-exact, reverse-engineered from real
/// Windows): iterated HMAC-SHA512 where each round's PRF input is the accumulated
/// XOR, not the previous block. This is deliberately NOT RFC-2898 PBKDF2.
fn ms_derive_key_sha512(
    passphrase: &[u8],
    salt: &[u8],
    keylen: usize,
    count: u32,
) -> Result<Vec<u8>> {
    if count > MAX_ITERATIONS {
        return Err(DecryptError::Dpapi(format!(
            "master-key iteration count {count} exceeds the {MAX_ITERATIONS} cap"
        )));
    }
    let mut out = Vec::with_capacity(keylen + 64);
    let mut block_index: u32 = 1;
    while out.len() < keylen {
        let mut msg = salt.to_vec();
        msg.extend_from_slice(&block_index.to_be_bytes()); // pack("!L", i) — big-endian
        block_index = block_index
            .checked_add(1)
            .ok_or_else(|| DecryptError::Dpapi("KDF block index overflow".into()))?;
        let mut derived = hmac_sha512(passphrase, &msg)?;
        for _ in 0..count.saturating_sub(1) {
            let actual = hmac_sha512(passphrase, &derived)?;
            for (d, a) in derived.iter_mut().zip(actual.iter()) {
                *d ^= *a;
            }
        }
        out.extend_from_slice(&derived);
    }
    out.truncate(keylen);
    Ok(out)
}

/// Decrypt a DPAPI master-key file with a SHA1 pre-key, returning the 64-byte
/// master key. The trailing HMAC is verified — a wrong password (or damaged file)
/// is a loud [`DecryptError::WrongDpapiPassword`], never a fabricated key.
///
/// # Errors
/// * [`DecryptError::Dpapi`] on a truncated / malformed file.
/// * [`DecryptError::UnsupportedAlgorithm`] for a non-`SHA512`/`AES-256` pair.
/// * [`DecryptError::WrongDpapiPassword`] when the HMAC does not verify.
pub fn decrypt_masterkey_file(mkf: &[u8], prekey: &[u8; 20]) -> Result<[u8; 64]> {
    // MasterKeyFile header: fixed 128 bytes; MasterKeyLen is a u64 at offset 96.
    let mk_len = read_u64_le(mkf, 96)?;
    let mk_len = usize::try_from(mk_len)
        .map_err(|_| DecryptError::Dpapi("master-key length does not fit in usize".into()))?;
    let section = take(mkf, MKF_HEADER_LEN, mk_len)?;

    // MasterKey section: Version(4) Salt(16) IterationCount(4) HashAlgo(4)
    // CryptAlgo(4) data(rest).
    let salt = take(section, 4, 16)?.to_vec();
    let iterations = read_u32_le(section, 20)?;
    let hash_algo = read_u32_le(section, 24)?;
    let crypt_algo = read_u32_le(section, 28)?;
    let data = section
        .get(32..)
        .ok_or_else(|| DecryptError::Dpapi("master-key section has no ciphertext".into()))?;

    require_modern_algos(hash_algo, crypt_algo)?;
    if data.is_empty() || data.len() % 16 != 0 {
        return Err(DecryptError::Dpapi(format!(
            "master-key ciphertext length {} is not a non-zero multiple of 16",
            data.len()
        )));
    }

    // Derive AES-256 key + IV, then AES-256-CBC (no padding: fixed layout).
    let derived = ms_derive_key_sha512(prekey, &salt, 32 + 16, iterations)?;
    let (ckey, iv) = derived.split_at(32);
    let mut buf = data.to_vec();
    let clear = Aes256CbcDec::new(ckey.into(), iv.into())
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|e| DecryptError::Dpapi(format!("master-key AES-CBC failed: {e}")))?;

    // Layout: hmac_salt(16) || hmac(64) || masterkey(64). Verify then extract.
    if clear.len() < 16 + 64 + 64 {
        return Err(DecryptError::Dpapi(format!(
            "master-key plaintext length {} is too short for salt+hmac+key",
            clear.len()
        )));
    }
    let hmac_salt = &clear[..16];
    let stored_hmac = &clear[16..16 + 64];
    let masterkey = &clear[clear.len() - 64..];

    let hmac_key = hmac_sha512(prekey, hmac_salt)?;
    let calc = hmac_sha512(&hmac_key, masterkey)?;
    if calc.as_slice() != stored_hmac {
        return Err(DecryptError::WrongDpapiPassword);
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(masterkey);
    Ok(out)
}

/// Parse a DPAPI blob into its fields (bounds-checked; never panics).
///
/// # Errors
/// [`DecryptError::Dpapi`] on truncation or malformed length fields.
pub fn parse_dpapi_blob(bytes: &[u8]) -> Result<DpapiBlob> {
    // Version(4) GuidCredential(16) MasterKeyVersion(4) GuidMasterKey(16)
    // Flags(4) DescriptionLen(4) Description(..) CryptAlgo(4) CryptAlgoLen(4)
    // SaltLen(4) Salt(..) HMacKeyLen(4) HMacKey(..) HashAlgo(4) HashAlgoLen(4)
    // HMacLen(4) HMac(..) DataLen(4) Data(..) SignLen(4) Sign(..)
    let mut guid_mk = [0u8; 16];
    guid_mk.copy_from_slice(take(bytes, 24, 16)?);

    let mut off = 44usize; // past Version+GuidCredential+MasterKeyVersion+GuidMasterKey+Flags
    let desc_len = read_u32_le(bytes, off)? as usize;
    off += 4;
    let _description = take(bytes, off, desc_len)?;
    off += desc_len;

    let crypt_algo = read_u32_le(bytes, off)?;
    off += 4;
    let _crypt_algo_len = read_u32_le(bytes, off)?;
    off += 4;

    let salt_len = read_u32_le(bytes, off)? as usize;
    off += 4;
    let salt = take(bytes, off, salt_len)?.to_vec();
    off += salt_len;

    let hmac_key_len = read_u32_le(bytes, off)? as usize;
    off += 4;
    let _hmac_key = take(bytes, off, hmac_key_len)?;
    off += hmac_key_len;

    let hash_algo = read_u32_le(bytes, off)?;
    off += 4;
    let _hash_algo_len = read_u32_le(bytes, off)?;
    off += 4;

    let hmac_len = read_u32_le(bytes, off)? as usize;
    off += 4;
    let hmac_salt = take(bytes, off, hmac_len)?.to_vec();
    off += hmac_len;

    let data_len = read_u32_le(bytes, off)? as usize;
    off += 4;
    let data = take(bytes, off, data_len)?.to_vec();
    off += data_len;

    let sign_len = read_u32_le(bytes, off)? as usize;
    off += 4;
    let sign = take(bytes, off, sign_len)?.to_vec();

    // to_sign = raw[20 .. len - sign_len - 4]  (per [MS-DPAPI] / impacket).
    let tail = 20usize
        .checked_add(sign_len)
        .and_then(|v| v.checked_add(4))
        .ok_or_else(|| DecryptError::Dpapi("signature length overflow".into()))?;
    if bytes.len() < tail {
        return Err(DecryptError::Dpapi(
            "blob too short for the signed range".into(),
        ));
    }
    let to_sign = bytes[20..bytes.len() - sign_len - 4].to_vec();

    Ok(DpapiBlob {
        guid_masterkey: guid_mk,
        crypt_algo,
        salt,
        hash_algo,
        hmac_salt,
        data,
        sign,
        to_sign,
    })
}

/// Decrypt a DPAPI blob with a 64-byte master key, returning the protected
/// plaintext. The trailing signature is verified with the standard HMAC-SHA512
/// construction used by modern Windows; a wrong key also fails PKCS7 unpadding.
/// Either way the result is a loud `Err`, never fabricated plaintext.
///
/// # Errors
/// * [`DecryptError::Dpapi`] on parse failure, unsupported algorithm, PKCS7
///   failure, or signature mismatch.
pub fn decrypt_dpapi_blob(
    blob: &[u8],
    masterkey: &[u8; 64],
    entropy: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let parsed = parse_dpapi_blob(blob)?;
    require_modern_algos(parsed.hash_algo, parsed.crypt_algo)?;

    // Session key: HMAC-SHA512(SHA1(masterkey), salt [|| entropy]); 64 bytes ≥ the
    // 32-byte AES-256 key, so no CryptDeriveKey extension is needed.
    let key_hash = Sha1::digest(masterkey);
    let mut m = <Hmac<Sha512>>::new_from_slice(&key_hash)
        .map_err(|e| DecryptError::Dpapi(format!("HMAC-SHA512 init: {e}")))?;
    m.update(&parsed.salt);
    if let Some(e) = entropy {
        m.update(e);
    }
    let session = m.finalize().into_bytes();

    if parsed.data.is_empty() || parsed.data.len() % 16 != 0 {
        return Err(DecryptError::Dpapi(format!(
            "blob ciphertext length {} is not a non-zero multiple of 16",
            parsed.data.len()
        )));
    }
    let iv = [0u8; 16];
    let mut buf = parsed.data.clone();
    let plaintext = Aes256CbcDec::new(session[..32].into(), (&iv).into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| DecryptError::Dpapi(format!("blob PKCS7 unpad failed (wrong key?): {e}")))?
        .to_vec();

    // Verify the signature: HMAC-SHA512(SHA1(masterkey), hmac_salt || [entropy] || to_sign).
    let mut sm = <Hmac<Sha512>>::new_from_slice(&key_hash)
        .map_err(|e| DecryptError::Dpapi(format!("HMAC-SHA512 init: {e}")))?;
    sm.update(&parsed.hmac_salt);
    if let Some(e) = entropy {
        sm.update(e);
    }
    sm.update(&parsed.to_sign);
    let calc = sm.finalize().into_bytes();
    if calc.as_slice() != parsed.sign.as_slice() {
        return Err(DecryptError::Dpapi(format!(
            "blob signature mismatch (expected sign hex {}, computed {})",
            hex(&parsed.sign),
            hex(&calc)
        )));
    }
    Ok(plaintext)
}

/// Recover the 32-byte AES-256-GCM profile key from Chromium `Local State`.
///
/// `local_state_json` is the contents of the profile's `Local State` file; the
/// key lives at `os_crypt.encrypted_key` as `base64("DPAPI" || DPAPI_BLOB)`.
///
/// # Errors
/// * [`DecryptError::LocalState`] if the JSON / key / base64 / `DPAPI` prefix is
///   missing or malformed.
/// * The [`decrypt_masterkey_file`] / [`decrypt_dpapi_blob`] errors otherwise.
pub fn decrypt_chromium_key_dpapi(
    local_state_json: &str,
    secret: &DpapiSecret,
) -> Result<[u8; 32]> {
    let root: serde_json::Value = serde_json::from_str(local_state_json)
        .map_err(|e| DecryptError::LocalState(format!("Local State is not valid JSON: {e}")))?;
    let b64 = root
        .get("os_crypt")
        .and_then(|v| v.get("encrypted_key"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            DecryptError::LocalState("os_crypt.encrypted_key missing or not a string".into())
        })?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| DecryptError::Base64(format!("os_crypt.encrypted_key: {e}")))?;
    let blob = decoded.strip_prefix(b"DPAPI").ok_or_else(|| {
        DecryptError::LocalState(format!(
            "os_crypt.encrypted_key does not begin with the 'DPAPI' tag (leading bytes, hex: {})",
            hex(&decoded[..decoded.len().min(5)])
        ))
    })?;

    let masterkey = match secret {
        DpapiSecret::MasterKey(mk) => *mk,
        DpapiSecret::UserPassword {
            password,
            sid,
            masterkey_file,
        } => {
            let prekey = derive_dpapi_prekey_sha1(password, sid);
            decrypt_masterkey_file(masterkey_file, &prekey)?
        }
    };

    let plaintext = decrypt_dpapi_blob(blob, &masterkey, None)?;
    <[u8; 32]>::try_from(plaintext.as_slice()).map_err(|_| {
        DecryptError::Dpapi(format!(
            "recovered key is {} bytes, expected 32 (AES-256)",
            plaintext.len()
        ))
    })
}

/// Reject any algorithm pair other than the modern `SHA512`/`AES-256` one that
/// Chromium produces on Windows 10/11 — loudly, with the offending value.
fn require_modern_algos(hash_algo: u32, crypt_algo: u32) -> Result<()> {
    if hash_algo != CALG_SHA_512 {
        return Err(DecryptError::UnsupportedAlgorithm(format!(
            "HashAlgo {hash_algo:#010x} (only CALG_SHA_512 {CALG_SHA_512:#010x} is supported)"
        )));
    }
    if crypt_algo != CALG_AES_256 {
        return Err(DecryptError::UnsupportedAlgorithm(format!(
            "CryptAlgo {crypt_algo:#010x} (only CALG_AES_256 {CALG_AES_256:#010x} is supported)"
        )));
    }
    Ok(())
}
