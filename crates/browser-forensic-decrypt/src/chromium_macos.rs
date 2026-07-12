//! macOS Chromium `v10` value decryption.
//!
//! The storage key is derived from the login-Keychain "… Safe Storage" password
//! (`PBKDF2-HMAC-SHA1(pw, "saltysalt", 1003, 16)` → AES-128), and each `v10`
//! value is AES-128-CBC with a fixed 16×`0x20` IV (see Chromium
//! `os_crypt_mac.mm`). Reading the Keychain password is the explicit opt-in step.

use crate::error::Result;

/// Derive the AES-128 storage key from a "… Safe Storage" Keychain password.
#[must_use]
pub fn derive_chromium_macos_key(_safe_storage_password: &[u8]) -> [u8; 16] {
    [0u8; 16]
}

/// Decrypt one Chromium `v10` value (cookie/login blob) with `storage_key`.
///
/// # Errors
/// Returns [`crate::DecryptError::NotV10`] if the blob lacks the `v10` prefix, or
/// [`crate::DecryptError::Decrypt`] on invalid padding (a wrong key) — never
/// fabricated plaintext.
pub fn decrypt_chromium_value_macos(_encrypted: &[u8], _storage_key: &[u8; 16]) -> Result<Vec<u8>> {
    Err(crate::error::DecryptError::Decrypt(
        "decrypt_chromium_value_macos not yet implemented".into(),
    ))
}

/// Read a "… Safe Storage" password from the macOS login Keychain.
///
/// This shells out to `security find-generic-password`, which prompts the user
/// for authorization — the explicit, user-visible opt-in for cookie decryption.
///
/// # Errors
/// Returns [`crate::DecryptError::Keychain`] if the item is absent or access is
/// denied.
pub fn fetch_macos_keychain_key(_service: &str) -> Result<String> {
    Err(crate::error::DecryptError::Keychain(
        "fetch_macos_keychain_key not yet implemented".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DecryptError;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // Vectors produced by an INDEPENDENT oracle (Python hashlib + cryptography):
    //   key  = pbkdf2_hmac('sha1', b'peanuts', b'saltysalt', 1003, 16)
    //   blob = b'v10' + AES-128-CBC(key, iv=0x20*16, PKCS7)(b'hello world')
    // Tier-2: we chose the scenario but did NOT author the answer key.
    const ORACLE_KEY_HEX: &str = "d9a09d499b4e1b7461f28e67972c6dbd";
    const ORACLE_BLOB_HEX: &str = "763130e3a734c938eab1a344e5ddfc9cc61cc7";
    // Same plaintext encrypted under a DIFFERENT key ('wrongpw'); decrypting it
    // with ORACLE_KEY fails PKCS7 unpadding (verified against the oracle).
    const WRONGKEY_BLOB_HEX: &str = "763130507e7858fdff3f7677b1a36a4977ea48";

    #[test]
    fn key_derivation_matches_independent_oracle() {
        let key = derive_chromium_macos_key(b"peanuts");
        assert_eq!(hex(&key), ORACLE_KEY_HEX);
    }

    #[test]
    fn decrypt_v10_recovers_oracle_plaintext() {
        let key = derive_chromium_macos_key(b"peanuts");
        let pt = decrypt_chromium_value_macos(&unhex(ORACLE_BLOB_HEX), &key).unwrap();
        assert_eq!(pt, b"hello world");
    }

    #[test]
    fn wrong_key_refuses_never_fabricates() {
        // Decrypt the good blob under the WRONG key: must be a loud Err, and must
        // NOT return the real plaintext (fabrication guard).
        let wrong = derive_chromium_macos_key(b"wrongpw");
        let res = decrypt_chromium_value_macos(&unhex(ORACLE_BLOB_HEX), &wrong);
        assert!(matches!(res, Err(DecryptError::Decrypt(_))));
        assert_ne!(res.ok(), Some(b"hello world".to_vec()));
    }

    #[test]
    fn wrongkey_blob_under_right_key_is_error() {
        let key = derive_chromium_macos_key(b"peanuts");
        let res = decrypt_chromium_value_macos(&unhex(WRONGKEY_BLOB_HEX), &key);
        assert!(matches!(res, Err(DecryptError::Decrypt(_))));
    }

    #[test]
    fn missing_v10_prefix_surfaces_leading_bytes() {
        let key = derive_chromium_macos_key(b"peanuts");
        let blob = b"abc\x01\x02"; // not v10
        match decrypt_chromium_value_macos(blob, &key) {
            Err(DecryptError::NotV10(bytes)) => assert_eq!(bytes, "616263"),
            other => panic!("expected NotV10, got {other:?}"),
        }
    }

    #[test]
    fn non_block_aligned_ciphertext_is_error() {
        let key = derive_chromium_macos_key(b"peanuts");
        let blob = b"v10\x00\x01\x02\x03\x04"; // 5-byte ciphertext, not a 16-multiple
        assert!(matches!(
            decrypt_chromium_value_macos(blob, &key),
            Err(DecryptError::Decrypt(_))
        ));
    }
}
