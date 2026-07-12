//! Typed decryption errors.
//!
//! Every failure path is a distinct, loud `Err` — the crate NEVER returns
//! plausible-but-wrong plaintext. A wrong key surfaces as [`DecryptError::Decrypt`]
//! (CBC unpad failure) or [`DecryptError::WrongMasterPassword`] (password-check
//! mismatch), never as garbage bytes.

/// An error raised while decrypting a browser secret.
#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    /// The ASN.1/DER structure could not be parsed or did not match the
    /// expected NSS layout. Carries a description of what was expected.
    #[error("ASN.1/DER decode error: {0}")]
    Asn1(String),

    /// An algorithm OID was found that this crate does not implement. Carries
    /// the raw OID content bytes (hex) so the investigator can identify it.
    #[error("unsupported algorithm OID (content bytes, hex): {0}")]
    UnsupportedAlgorithm(String),

    /// The master-password verification (`password-check`) failed: the supplied
    /// master password is wrong, or the key material is damaged.
    #[error(
        "master password incorrect or key material damaged (NSS password-check did not match)"
    )]
    WrongMasterPassword,

    /// A CBC decryption produced invalid padding — the wrong key was used, or
    /// the ciphertext is corrupt. This is the loud refusal, never a fabrication.
    #[error("decryption failed (invalid padding / wrong key): {0}")]
    Decrypt(String),

    /// The `key4.db` NSS key database could not be opened or queried.
    #[error("key4.db read error: {0}")]
    KeyDb(String),

    /// The `logins.json` file could not be read or parsed.
    #[error("logins.json error: {0}")]
    LoginsJson(String),

    /// No usable NSS private key (CKA_ID row) was found in `nssPrivate`.
    #[error("no NSS encryption key found in key4.db (nssPrivate/CKA_ID row absent)")]
    NoKey,

    /// Reading the macOS Keychain Safe Storage password failed. Carries the
    /// underlying reason (e.g. user denied access, item not found).
    #[error("macOS Keychain read failed: {0}")]
    Keychain(String),

    /// A Chromium encrypted value did not carry the expected `v10` prefix.
    /// Carries the actual leading bytes (hex) that were found instead.
    #[error("not a Chromium 'v10' CBC blob (leading bytes, hex): {0}")]
    NotV10(String),

    /// A decrypted value was not valid UTF-8 where text was expected. Carries
    /// the byte length so the caller knows data was present but non-text.
    #[error("decrypted value is not valid UTF-8 ({0} bytes)")]
    NotUtf8(usize),

    /// A Windows Chromium value carried an unrecognized version prefix (not
    /// `v10`/`v11`/`v20`). Carries the actual leading bytes (hex) found instead.
    #[error("unrecognized Chromium value prefix (leading bytes, hex): {0}")]
    UnknownVersion(String),

    /// A Windows Chromium value uses App-Bound Encryption (`v20`, Chrome 127+),
    /// whose key is wrapped by the SYSTEM `elevation_service`. Offline recovery
    /// needs the SYSTEM DPAPI master key, which was not supplied — REFUSED rather
    /// than fabricated. Carries a diagnostic.
    #[error("App-Bound Encryption (v20) is not decryptable without the SYSTEM key: {0}")]
    AppBoundUnsupported(String),

    /// AES-256-GCM authentication failed: the tag did not verify. The key is
    /// wrong or the ciphertext/tag was tampered with. Loud refusal, never a
    /// fabricated value.
    #[error("AES-256-GCM authentication failed (wrong key or tampered data): {0}")]
    Gcm(String),

    /// A DPAPI blob or master-key file could not be parsed or decrypted. Carries
    /// a description (and, where relevant, the offending value / offset).
    #[error("DPAPI error: {0}")]
    Dpapi(String),

    /// The DPAPI master-key HMAC check failed: the supplied user password (or
    /// pre-derived key) is wrong, or the master-key file is damaged. The loud
    /// refusal that gates a wrong password — never a fabricated key.
    #[error("DPAPI master-key password incorrect or file damaged (HMAC did not verify)")]
    WrongDpapiPassword,

    /// Chromium `Local State` could not be parsed, or its
    /// `os_crypt.encrypted_key` was missing / not valid base64. Carries the
    /// reason.
    #[error("Chromium Local State error: {0}")]
    LocalState(String),

    /// A base64 field could not be decoded. Carries the reason.
    #[error("base64 decode error: {0}")]
    Base64(String),

    /// An underlying I/O failure.
    #[error("io error: {0}")]
    Io(String),
}

/// Convenience alias for results in this crate.
pub type Result<T> = std::result::Result<T, DecryptError>;
