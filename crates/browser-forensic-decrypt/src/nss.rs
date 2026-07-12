//! Firefox NSS decryption (`key4.db` + `logins.json`).
//!
//! Implements both NSS PBE schemes: legacy 3DES-CBC (key/IV derived by the NSS
//! SHA1-based PBE) and modern PBES2 (PBKDF2-HMAC-SHA256 → AES-256-CBC). The
//! master key is unwrapped from `nssPrivate` after the `metadata` password-check
//! verifies the supplied master password; a wrong password fails loud.

use std::path::Path;

use crate::error::Result;

/// One decrypted Firefox login.
///
/// `password` is `Some` only when the caller passed `include_passwords = true`.
/// The crown-jewel password is not even materialized without that opt-in.
#[derive(Debug, Clone)]
pub struct DecryptedLogin {
    /// The `hostname` field from `logins.json`.
    pub hostname: String,
    /// The decrypted username.
    pub username: String,
    /// The decrypted password, present only under an explicit opt-in.
    pub password: Option<String>,
}

/// Decrypt the logins in a Firefox profile.
///
/// `key4_db` and `logins_json` are the two profile files; `master_password` is
/// the empty string when no master password is set. When `include_passwords` is
/// `false`, each returned login's `password` is `None` and the password
/// ciphertext is never decrypted.
///
/// # Errors
/// Returns a [`crate::DecryptError`] on a wrong master password, a damaged key
/// database, an unparseable blob, or an unsupported algorithm.
pub fn decrypt_firefox_logins(
    _key4_db: &Path,
    _logins_json: &Path,
    _master_password: &str,
    _include_passwords: bool,
) -> Result<Vec<DecryptedLogin>> {
    Err(crate::error::DecryptError::KeyDb(
        "decrypt_firefox_logins not yet implemented".into(),
    ))
}
