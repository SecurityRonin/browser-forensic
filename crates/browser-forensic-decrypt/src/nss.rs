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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DecryptError;
    use std::path::PathBuf;

    // Known credentials baked into the fixtures (see tests/data/README.md);
    // firepwd.py (third party) independently recovers these from ffpbes2/.
    const KNOWN_USER: &str = "alice@example.com";
    const KNOWN_PASS: &str = "S3cr3t-Passw0rd!";

    fn fixture(scheme: &str) -> (PathBuf, PathBuf) {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data")
            .join(scheme);
        (base.join("key4.db"), base.join("logins.json"))
    }

    #[test]
    fn pbes2_recovers_username_without_password_by_default() {
        let (k, l) = fixture("ffpbes2");
        let logins = decrypt_firefox_logins(&k, &l, "", false).unwrap();
        assert_eq!(logins.len(), 1);
        assert_eq!(logins[0].username, KNOWN_USER);
        assert_eq!(logins[0].hostname, "https://accounts.example.com");
        // Crown-jewel guard: no password materialized without the opt-in.
        assert_eq!(logins[0].password, None);
    }

    #[test]
    fn pbes2_recovers_password_with_optin() {
        let (k, l) = fixture("ffpbes2");
        let logins = decrypt_firefox_logins(&k, &l, "", true).unwrap();
        assert_eq!(logins[0].username, KNOWN_USER);
        assert_eq!(logins[0].password.as_deref(), Some(KNOWN_PASS));
    }

    #[test]
    fn three_des_recovers_known_credentials() {
        let (k, l) = fixture("ff3des");
        let logins = decrypt_firefox_logins(&k, &l, "", true).unwrap();
        assert_eq!(logins.len(), 1);
        assert_eq!(logins[0].username, KNOWN_USER);
        assert_eq!(logins[0].password.as_deref(), Some(KNOWN_PASS));
    }

    #[test]
    fn wrong_master_password_refuses() {
        let (k, l) = fixture("ffpbes2");
        let res = decrypt_firefox_logins(&k, &l, "definitely-wrong", true);
        assert!(matches!(res, Err(DecryptError::WrongMasterPassword)));
    }

    #[test]
    fn missing_key4_db_is_loud_error() {
        let (_k, l) = fixture("ffpbes2");
        let res = decrypt_firefox_logins(&PathBuf::from("/nonexistent/key4.db"), &l, "", false);
        assert!(res.is_err());
    }
}
