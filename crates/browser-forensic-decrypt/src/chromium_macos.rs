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
