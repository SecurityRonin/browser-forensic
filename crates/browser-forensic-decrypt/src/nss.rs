//! Firefox NSS decryption (`key4.db` + `logins.json`).
//!
//! Implements both NSS PBE schemes: legacy 3DES-CBC (key/IV derived by the NSS
//! SHA1-based PBE) and modern PBES2 (PBKDF2-HMAC-SHA256 → AES-256-CBC). The
//! master key is unwrapped from `nssPrivate` after the `metadata` password-check
//! verifies the supplied master password; a wrong password fails loud.

use std::path::Path;

use cbc::cipher::{block_padding::NoPadding, block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha1::{Digest, Sha1};

use crate::asn1::{
    decode_login_blob, decode_pbe_item, LoginBlob, PbeItem, OID_AES256_CBC, OID_DES_EDE3_CBC,
};
use crate::error::{DecryptError, Result};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type TDesCbcDec = cbc::Decryptor<des::TdesEde3>;

/// The NSS SDR key id (`CKA_ID`) that wraps the master key.
const CKA_ID: &[u8] = &[0xf8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// Plaintext the `password-check` item must decrypt to when the master password
/// is correct.
const PASSWORD_CHECK: &[u8] = b"password-check\x02\x02";

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
    key4_db: &Path,
    logins_json: &Path,
    master_password: &str,
    include_passwords: bool,
) -> Result<Vec<DecryptedLogin>> {
    let master_key = derive_master_key(key4_db, master_password.as_bytes())?;

    let raw = std::fs::read(logins_json).map_err(|e| DecryptError::LoginsJson(e.to_string()))?;
    let json: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| DecryptError::LoginsJson(e.to_string()))?;
    let logins = json
        .get("logins")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();

    let mut out = Vec::new();
    for login in logins {
        let hostname = login
            .get("hostname")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string();
        let (Some(enc_user), Some(enc_pass)) = (
            login
                .get("encryptedUsername")
                .and_then(serde_json::Value::as_str),
            login
                .get("encryptedPassword")
                .and_then(serde_json::Value::as_str),
        ) else {
            continue;
        };
        let username = decrypt_login_field(enc_user, &master_key)?;
        // The crown jewel is only decrypted under the explicit opt-in.
        let password = if include_passwords {
            Some(decrypt_login_field(enc_pass, &master_key)?)
        } else {
            None
        };
        out.push(DecryptedLogin {
            hostname,
            username,
            password,
        });
    }
    Ok(out)
}

/// Base64-decode, ASN.1-decode and decrypt a single `logins.json` field.
fn decrypt_login_field(b64: &str, master_key: &[u8]) -> Result<String> {
    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| DecryptError::LoginsJson(format!("base64: {e}")))?;
    let blob = decode_login_blob(&der)?;
    let plaintext = decrypt_login_blob(&blob, master_key)?;
    String::from_utf8(plaintext).map_err(|e| DecryptError::NotUtf8(e.as_bytes().len()))
}

/// Decrypt a login blob with the master key, selecting the cipher from the
/// blob's own OID and PKCS7-unpadding (a wrong key fails loud).
fn decrypt_login_blob(blob: &LoginBlob, master_key: &[u8]) -> Result<Vec<u8>> {
    match blob.cipher_oid.as_slice() {
        OID_DES_EDE3_CBC => {
            let key = master_key
                .get(..24)
                .ok_or_else(|| DecryptError::Decrypt("master key shorter than 24 bytes".into()))?;
            cbc_decrypt_pkcs7::<TDesCbcDec>(key, &blob.iv, &blob.ciphertext)
        }
        OID_AES256_CBC => {
            let key = master_key
                .get(..32)
                .ok_or_else(|| DecryptError::Decrypt("master key shorter than 32 bytes".into()))?;
            cbc_decrypt_pkcs7::<Aes256CbcDec>(key, &blob.iv, &blob.ciphertext)
        }
        other => Err(DecryptError::UnsupportedAlgorithm(hex(other))),
    }
}

/// Derive the NSS master key from `key4.db`: verify the master password against
/// the `metadata` password-check, then unwrap the `nssPrivate` key. Returns the
/// raw (still PKCS7-padded) key material; callers truncate per cipher.
fn derive_master_key(key4_db: &Path, master_password: &[u8]) -> Result<Vec<u8>> {
    let conn =
        rusqlite::Connection::open_with_flags(key4_db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| DecryptError::KeyDb(e.to_string()))?;

    let (global_salt, item2): (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT item1, item2 FROM metadata WHERE id = 'password'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|e| DecryptError::KeyDb(format!("metadata password row: {e}")))?;

    let check = decrypt_pbe(&decode_pbe_item(&item2)?, master_password, &global_salt)?;
    if !check.starts_with(PASSWORD_CHECK) {
        return Err(DecryptError::WrongMasterPassword);
    }

    let a11 = find_nss_private_key(&conn)?;
    decrypt_pbe(&decode_pbe_item(&a11)?, master_password, &global_salt)
}

/// Find the `nssPrivate` row whose `a102` is the SDR `CKA_ID` and return its
/// `a11` wrapped-key bytes.
fn find_nss_private_key(conn: &rusqlite::Connection) -> Result<Vec<u8>> {
    let mut stmt = conn
        .prepare("SELECT a11, a102 FROM nssPrivate")
        .map_err(|e| DecryptError::KeyDb(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            let a11: Option<Vec<u8>> = row.get(0)?;
            let a102: Option<Vec<u8>> = row.get(1)?;
            Ok((a11, a102))
        })
        .map_err(|e| DecryptError::KeyDb(e.to_string()))?;
    for row in rows {
        let (a11, a102) = row.map_err(|e| DecryptError::KeyDb(e.to_string()))?;
        if let (Some(a11), Some(a102)) = (a11, a102) {
            if a102 == CKA_ID {
                return Ok(a11);
            }
        }
    }
    Err(DecryptError::NoKey)
}

/// Decrypt a PBE item (`item2` or `a11`) with the master password. Returns the
/// raw decrypted bytes WITHOUT unpadding (matching NSS semantics: the caller
/// checks a fixed prefix or truncates the key).
fn decrypt_pbe(item: &PbeItem, master_password: &[u8], global_salt: &[u8]) -> Result<Vec<u8>> {
    match item {
        PbeItem::TripleDes {
            entry_salt,
            ciphertext,
        } => {
            let (key, iv) = moz_3des_key_iv(global_salt, master_password, entry_salt);
            cbc_decrypt_nopad::<TDesCbcDec>(&key, &iv, ciphertext)
        }
        PbeItem::Pbes2 {
            entry_salt,
            iteration_count,
            key_length,
            iv,
            ciphertext,
        } => {
            if *key_length != 32 {
                return Err(DecryptError::UnsupportedAlgorithm(format!(
                    "PBES2 key length {key_length} (only 32 supported)"
                )));
            }
            let mut hashed = Sha1::new();
            hashed.update(global_salt);
            hashed.update(master_password);
            let k = hashed.finalize();
            let derived =
                pbkdf2::pbkdf2_hmac_array::<sha2::Sha256, 32>(&k, entry_salt, *iteration_count);
            // NSS stores the 16-byte IV as a 14-byte OCTET STRING; the real IV is
            // the DER re-encoding `04 0e || <14 bytes>` (nss rev fc636973ad06).
            let mut real_iv = Vec::with_capacity(2 + iv.len());
            real_iv.push(0x04);
            real_iv.push(0x0e);
            real_iv.extend_from_slice(iv);
            cbc_decrypt_nopad::<Aes256CbcDec>(&derived, &real_iv, ciphertext)
        }
    }
}

/// Derive the 3DES key and IV from the NSS SHA1-based PBE (mirrors NSS
/// `decryptMoz3DES`; see firepwd and drh-consultancy key3.html).
fn moz_3des_key_iv(
    global_salt: &[u8],
    master_password: &[u8],
    entry_salt: &[u8],
) -> ([u8; 24], [u8; 8]) {
    type HmacSha1 = Hmac<Sha1>;

    let mut hp_h = Sha1::new();
    hp_h.update(global_salt);
    hp_h.update(master_password);
    let hp = hp_h.finalize();

    // pes = entry_salt right-padded with zeros to 20 bytes.
    let mut pes = [0u8; 20];
    let n = entry_salt.len().min(20);
    pes[..n].copy_from_slice(&entry_salt[..n]);

    let mut chp_h = Sha1::new();
    chp_h.update(hp);
    chp_h.update(entry_salt);
    let chp = chp_h.finalize();

    let k1 = hmac_sha1::<HmacSha1>(&chp, &[&pes, entry_salt]);
    let tk = hmac_sha1::<HmacSha1>(&chp, &[&pes]);
    let k2 = hmac_sha1::<HmacSha1>(&chp, &[&tk, entry_salt]);

    let mut k = [0u8; 40];
    k[..20].copy_from_slice(&k1);
    k[20..].copy_from_slice(&k2);

    let mut key = [0u8; 24];
    key.copy_from_slice(&k[..24]);
    let mut iv = [0u8; 8];
    iv.copy_from_slice(&k[32..40]);
    (key, iv)
}

/// One-shot HMAC-SHA1 over the concatenation of `parts`.
fn hmac_sha1<M: Mac + hmac::digest::KeyInit>(key: &[u8], parts: &[&[u8]]) -> [u8; 20] {
    let mut mac = <M as hmac::digest::KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| <M as hmac::digest::KeyInit>::new(key.into()));
    for p in parts {
        mac.update(p);
    }
    let out = mac.finalize().into_bytes();
    let mut fixed = [0u8; 20];
    fixed.copy_from_slice(&out[..20]);
    fixed
}

/// CBC decrypt with PKCS7 unpadding — invalid padding (wrong key) fails loud.
fn cbc_decrypt_pkcs7<C>(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>>
where
    C: KeyIvInit + BlockDecryptMut,
{
    let dec = C::new_from_slices(key, iv)
        .map_err(|e| DecryptError::Decrypt(format!("bad key/iv length: {e}")))?;
    dec.decrypt_padded_vec_mut::<Pkcs7>(ct)
        .map_err(|e| DecryptError::Decrypt(format!("PKCS7 unpad failed (wrong key?): {e}")))
}

/// CBC decrypt WITHOUT unpadding (NSS check/key material carries raw padding).
fn cbc_decrypt_nopad<C>(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>>
where
    C: KeyIvInit + BlockDecryptMut,
{
    let dec = C::new_from_slices(key, iv)
        .map_err(|e| DecryptError::Decrypt(format!("bad key/iv length: {e}")))?;
    dec.decrypt_padded_vec_mut::<NoPadding>(ct)
        .map_err(|e| DecryptError::Decrypt(format!("CBC decrypt failed: {e}")))
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
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
