//! Windows Chromium value decryption (`v10`/`v11` AES-256-GCM).
//!
//! Each stored value is `<3-byte version prefix> || <12-byte nonce> || <ciphertext>
//! || <16-byte GCM tag>`, AES-256-GCM under the 32-byte profile key recovered
//! from `Local State` via DPAPI (see [`crate::dpapi`]). Layout and constants per
//! Chromium `components/os_crypt/sync/os_crypt_win.cc`
//! (`kEncryptionVersionPrefix = "v10"`, `kNonceLength = 96/8`, `kKeyLength =
//! 256/8`). App-Bound (`v20`, Chrome 127+) wraps the key with the SYSTEM
//! `elevation_service` and is refused offline — never fabricated.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

use crate::error::{DecryptError, Result};

/// 96-bit GCM nonce, per Chromium `kNonceLength`.
const NONCE_LEN: usize = 12;
/// 128-bit GCM authentication tag.
const TAG_LEN: usize = 16;
/// 3-byte Chromium value version prefix.
const PREFIX_LEN: usize = 3;

/// Decrypt one Windows Chromium `v10`/`v11` value (cookie / login / autofill).
///
/// `key` is the 32-byte AES-256-GCM profile key from
/// [`crate::dpapi::decrypt_chromium_key_dpapi`].
///
/// # Errors
/// * [`DecryptError::AppBoundUnsupported`] for a `v20` App-Bound value (no SYSTEM
///   key supplied) — refused, never fabricated.
/// * [`DecryptError::UnknownVersion`] for any other prefix (carries the bytes).
/// * [`DecryptError::Gcm`] when the value is too short or the tag fails to verify
///   (wrong key or tampered data). Never returns plausible-but-wrong plaintext.
pub fn decrypt_chromium_value_win(encrypted: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let prefix = &encrypted[..encrypted.len().min(PREFIX_LEN)];
    match prefix {
        b"v10" | b"v11" => decrypt_gcm(encrypted, key),
        b"v20" => Err(DecryptError::AppBoundUnsupported(format!(
            "value is App-Bound Encryption (v20, Chrome 127+); its key is wrapped by \
             the SYSTEM elevation_service and requires the SYSTEM DPAPI master key, \
             which was not supplied (leading bytes, hex: {})",
            hex(prefix)
        ))),
        _ => Err(DecryptError::UnknownVersion(hex(prefix))),
    }
}

/// Decrypt a `v10`/`v11` GCM body: `nonce(12) || ciphertext || tag(16)`.
fn decrypt_gcm(encrypted: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    // Minimum: prefix + nonce + tag (empty ciphertext is valid). Guard the slice
    // so a truncated value is a loud Err, never an out-of-bounds panic.
    if encrypted.len() < PREFIX_LEN + NONCE_LEN + TAG_LEN {
        return Err(DecryptError::Gcm(format!(
            "value length {} is shorter than prefix(3)+nonce(12)+tag(16)=31",
            encrypted.len()
        )));
    }
    let nonce = &encrypted[PREFIX_LEN..PREFIX_LEN + NONCE_LEN];
    let ct_and_tag = &encrypted[PREFIX_LEN + NONCE_LEN..];
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(Nonce::from_slice(nonce), ct_and_tag)
        .map_err(|_| DecryptError::Gcm("tag did not verify (wrong key or tampered value)".into()))
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
