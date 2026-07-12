//! Windows DPAPI (`[MS-DPAPI]`) — STUB, implemented in the GREEN step.

use crate::error::{DecryptError, Result};

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
    /// The byte range that the signature authenticates.
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

/// Derive the SHA1 pre-key from a user password + SID.
#[must_use]
pub fn derive_dpapi_prekey_sha1(_password: &str, _sid: &str) -> [u8; 20] {
    [0u8; 20]
}

/// Parse a DPAPI blob. STUB.
///
/// # Errors
/// STUB.
pub fn parse_dpapi_blob(_bytes: &[u8]) -> Result<DpapiBlob> {
    Err(DecryptError::Dpapi("not implemented".into()))
}

/// Decrypt a DPAPI master-key file with a SHA1 pre-key. STUB.
///
/// # Errors
/// STUB.
pub fn decrypt_masterkey_file(_mkf: &[u8], _prekey: &[u8; 20]) -> Result<[u8; 64]> {
    Err(DecryptError::Dpapi("not implemented".into()))
}

/// Decrypt a DPAPI blob with a 64-byte master key. STUB.
///
/// # Errors
/// STUB.
pub fn decrypt_dpapi_blob(
    _blob: &[u8],
    _masterkey: &[u8; 64],
    _entropy: Option<&[u8]>,
) -> Result<Vec<u8>> {
    Err(DecryptError::Dpapi("not implemented".into()))
}

/// Recover the 32-byte AES-256-GCM profile key from Chromium `Local State`. STUB.
///
/// # Errors
/// STUB.
pub fn decrypt_chromium_key_dpapi(
    _local_state_json: &str,
    _secret: &DpapiSecret,
) -> Result<[u8; 32]> {
    Err(DecryptError::Dpapi("not implemented".into()))
}
