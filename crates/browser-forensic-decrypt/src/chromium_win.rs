//! Windows Chromium value decryption (`v10`/`v11` AES-256-GCM) and Local State
//! key recovery (DPAPI). STUB — implemented in the GREEN step.

use crate::error::{DecryptError, Result};

/// Decrypt one Windows Chromium `v10`/`v11` value (cookie/login/etc.).
///
/// # Errors
/// STUB.
pub fn decrypt_chromium_value_win(_encrypted: &[u8], _key: &[u8; 32]) -> Result<Vec<u8>> {
    Err(DecryptError::Dpapi("not implemented".into()))
}
