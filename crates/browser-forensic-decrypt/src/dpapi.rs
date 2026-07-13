//! Windows DPAPI (`[MS-DPAPI]`) master-key and blob decryption, plus Chromium
//! `Local State` key recovery.
//!
//! The DPAPI *format* handling (master-key file parse + KDF, blob parse +
//! session-key derivation, `Local State` base64/`DPAPI`-prefix stripping) is
//! **delegated to the fleet [`dpapi_core`] crate** (`dpapi-forensic`) rather than
//! hand-rolled here — one audited, fuzz-hardened, impacket-validated
//! implementation serves the whole fleet (DRY). Every cryptographic primitive in
//! `dpapi-core` is a RustCrypto crate; nothing is hand-rolled.
//!
//! What stays local is the thin glue this crate owns:
//! * type-preserving wrappers so the public API keeps returning this crate's
//!   `[u8; 32]` / `[u8; 64]` / [`DecryptError`] shapes;
//! * the [`DpapiError`] → [`DecryptError`] mapping (a wrong master-key password
//!   surfaces as [`DecryptError::WrongDpapiPassword`], never a fabricated key);
//! * the Chromium `Local State` JSON extraction (`os_crypt.encrypted_key`), which
//!   is browser-specific and lives above the byte-oriented `dpapi-core` boundary;
//! * the opt-in / secret-required flow ([`DpapiSecret`]).
//!
//! # Chain (implemented by `dpapi-core`)
//! 1. `prekey = HMAC-SHA1(SHA1(password_utf16le), (sid || NUL)_utf16le)`.
//! 2. The master-key file is decrypted with the Microsoft iterated HMAC-SHA512
//!    KDF → AES-256-CBC → a 64-byte master key, gated by an HMAC.
//! 3. The blob derives a session key `HMAC-SHA512(SHA1(masterkey), salt)` →
//!    AES-256-CBC → the protected secret; the trailing signature is verified.
//! 4. Chromium `Local State` holds `base64("DPAPI" || blob)`; the blob's
//!    plaintext is the 32-byte AES-256-GCM profile key.

use dpapi_core::DpapiError;

use crate::error::{DecryptError, Result};

// Re-export the byte-oriented blob parser + type from the fleet crate so callers
// (and the robustness tests) reach the single audited implementation.
pub use dpapi_core::{parse_dpapi_blob, DpapiBlob};

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

/// Map a `dpapi-core` error onto this crate's typed [`DecryptError`], preserving
/// the offending value in the message (`dpapi-core` errors already carry it).
fn map_dpapi_err(e: DpapiError) -> DecryptError {
    let msg = e.to_string();
    match e {
        DpapiError::UnsupportedAlgId(_) => DecryptError::UnsupportedAlgorithm(msg),
        DpapiError::Base64Error => DecryptError::Base64(msg),
        DpapiError::MissingDpapiPrefix(_) => DecryptError::LocalState(msg),
        _ => DecryptError::Dpapi(msg),
    }
}

/// Derive the SHA1 pre-key from a user password + SID:
/// `HMAC-SHA1(SHA1(password_utf16le), (sid || NUL)_utf16le)`.
///
/// Delegates to [`dpapi_core::prekey_from_password`]; the derivation cannot fail
/// for a valid-length SHA1 key, so the impossible error path falls back to zeros
/// (still non-fabricating — a zero pre-key fails the downstream master-key HMAC).
#[must_use]
pub fn derive_dpapi_prekey_sha1(password: &str, sid: &str) -> [u8; 20] {
    dpapi_core::prekey_from_password(sid, password).unwrap_or([0u8; 20])
}

/// Decrypt a DPAPI master-key file with a SHA1 pre-key, returning the 64-byte
/// master key. The trailing HMAC is verified — a wrong password (or damaged file)
/// is a loud [`DecryptError::WrongDpapiPassword`], never a fabricated key.
///
/// # Errors
/// * [`DecryptError::Dpapi`] on a truncated / malformed file.
/// * [`DecryptError::UnsupportedAlgorithm`] for an unsupported algorithm id.
/// * [`DecryptError::WrongDpapiPassword`] when the HMAC does not verify.
pub fn decrypt_masterkey_file(mkf: &[u8], prekey: &[u8; 20]) -> Result<[u8; 64]> {
    let file = dpapi_core::parse_masterkey_file(mkf).map_err(map_dpapi_err)?;
    let mk = dpapi_core::parse_master_key(&file.master_key).map_err(map_dpapi_err)?;
    dpapi_core::derive_master_key_from_prekey(&mk, prekey).map_err(|e| match e {
        DpapiError::HmacMismatch => DecryptError::WrongDpapiPassword,
        other => map_dpapi_err(other),
    })
}

/// Decrypt a DPAPI blob with a 64-byte master key, returning the protected
/// plaintext. The trailing signature is verified; a wrong key fails the signature
/// (or PKCS7 unpadding). Either way the result is a loud `Err`, never fabricated.
///
/// # Errors
/// [`DecryptError::Dpapi`] / [`DecryptError::UnsupportedAlgorithm`] on parse
/// failure, unsupported algorithm, PKCS7 failure, or signature mismatch.
pub fn decrypt_dpapi_blob(
    blob: &[u8],
    masterkey: &[u8; 64],
    entropy: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let parsed = dpapi_core::parse_dpapi_blob(blob).map_err(map_dpapi_err)?;
    dpapi_core::decrypt_dpapi_blob(&parsed, masterkey, entropy).map_err(map_dpapi_err)
}

/// Recover the 32-byte AES-256-GCM profile key from Chromium `Local State`.
///
/// `local_state_json` is the contents of the profile's `Local State` file; the
/// key lives at `os_crypt.encrypted_key` as `base64("DPAPI" || DPAPI_BLOB)`. The
/// JSON extraction is done here; the base64/`DPAPI`-prefix strip and the blob
/// decryption are delegated to [`dpapi_core`].
///
/// # Errors
/// * [`DecryptError::LocalState`] if the JSON / key / `DPAPI` prefix is missing or
///   malformed; [`DecryptError::Base64`] on a bad base64 value.
/// * The [`decrypt_masterkey_file`] errors when deriving from a password.
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
    let blob =
        dpapi_core::parse_local_state_encrypted_key(b64.as_bytes()).map_err(map_dpapi_err)?;

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

    dpapi_core::decrypt_local_state_key(&blob, &masterkey).map_err(map_dpapi_err)
}
