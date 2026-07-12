//! Minimal, bounds-checked ASN.1/DER decoding of the NSS structures.
//!
//! The blobs decoded here are attacker-controllable (a `key4.db` or `logins.json`
//! handed to the tool as evidence), so parsing runs on the audited [`der`] crate's
//! length-checked reader rather than hand-rolled offset math.
//!
//! Structures (see firepwd, lclevy — the canonical pure reference):
//! * login blob (`encryptedUsername`/`encryptedPassword`, base64-decoded):
//!   `SEQUENCE { OCTETSTRING keyId, SEQUENCE { OID cipher, OCTETSTRING iv }, OCTETSTRING ct }`
//! * PBE item (`metadata.item2`, `nssPrivate.a11`): a PKCS#5/PKCS#12 PBE wrapper,
//!   either legacy `pbeWithSha1AndTripleDES-CBC` or modern PKCS#5 PBES2.

use crate::error::{DecryptError, Result};

/// OID content bytes for `pbeWithSha1AndTripleDES-CBC` (1.2.840.113549.1.12.5.1.3).
pub const OID_PBE_SHA1_3DES: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x05, 0x01, 0x03,
];
/// OID content bytes for PKCS#5 PBES2 (1.2.840.113549.1.5.13).
pub const OID_PBES2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];
/// OID content bytes for PKCS#5 PBKDF2 (1.2.840.113549.1.5.12).
pub const OID_PBKDF2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c];
/// OID content bytes for `des-ede3-cbc` (1.2.840.113549.3.7).
pub const OID_DES_EDE3_CBC: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07];
/// OID content bytes for `aes256-CBC` (2.16.840.1.101.3.4.1.42).
pub const OID_AES256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];

/// A parsed login blob (one `encryptedUsername` or `encryptedPassword`).
#[derive(Debug, Clone)]
pub struct LoginBlob {
    /// NSS key id (`CKA_ID`); expected to be `f800…0001`.
    pub key_id: Vec<u8>,
    /// The inner cipher OID content bytes (`des-ede3-cbc` or `aes256-CBC`).
    pub cipher_oid: Vec<u8>,
    /// The CBC initialization vector.
    pub iv: Vec<u8>,
    /// The ciphertext to decrypt with the derived master key.
    pub ciphertext: Vec<u8>,
}

/// A parsed PBE item — the password-check (`item2`) or wrapped key (`a11`).
#[derive(Debug, Clone)]
pub enum PbeItem {
    /// Legacy `pbeWithSha1AndTripleDES-CBC`.
    TripleDes {
        /// Per-entry salt.
        entry_salt: Vec<u8>,
        /// The 3DES-CBC ciphertext.
        ciphertext: Vec<u8>,
    },
    /// Modern PKCS#5 PBES2 = PBKDF2-HMAC-SHA256 → AES-256-CBC.
    Pbes2 {
        /// PBKDF2 salt.
        entry_salt: Vec<u8>,
        /// PBKDF2 iteration count.
        iteration_count: u32,
        /// Derived-key length in bytes (32 for AES-256).
        key_length: u32,
        /// The AES-256-CBC IV as stored (14-byte OCTET STRING; reconstructed by
        /// [`crate::nss`] per the NSS convention).
        iv: Vec<u8>,
        /// The AES-256-CBC ciphertext.
        ciphertext: Vec<u8>,
    },
}

/// Decode a base64-then-DER login blob into its key id, cipher OID, IV and
/// ciphertext.
///
/// # Errors
/// Returns [`DecryptError::Asn1`] if the structure does not match the expected
/// NSS login layout.
pub fn decode_login_blob(_der_bytes: &[u8]) -> Result<LoginBlob> {
    Err(DecryptError::Asn1(
        "decode_login_blob not yet implemented".into(),
    ))
}

/// Decode a PBE item (`metadata.item2` or `nssPrivate.a11`).
///
/// # Errors
/// Returns [`DecryptError::Asn1`] for a malformed structure, or
/// [`DecryptError::UnsupportedAlgorithm`] (carrying the raw OID bytes) for an
/// algorithm this crate does not implement.
pub fn decode_pbe_item(_der_bytes: &[u8]) -> Result<PbeItem> {
    Err(DecryptError::Asn1(
        "decode_pbe_item not yet implemented".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a DER TLV with definite short/long-form length.
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        let len = body.len();
        if len < 0x80 {
            v.push(len as u8);
        } else if len < 0x100 {
            v.push(0x81);
            v.push(len as u8);
        } else {
            v.push(0x82);
            v.push((len >> 8) as u8);
            v.push((len & 0xff) as u8);
        }
        v.extend_from_slice(body);
        v
    }
    fn seq(children: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = children.iter().flatten().copied().collect();
        tlv(0x30, &body)
    }
    fn octet(b: &[u8]) -> Vec<u8> {
        tlv(0x04, b)
    }
    fn oid(content: &[u8]) -> Vec<u8> {
        tlv(0x06, content)
    }
    fn int(b: &[u8]) -> Vec<u8> {
        tlv(0x02, b)
    }

    #[test]
    fn decode_login_blob_extracts_fields() {
        let key_id = [0xf8u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let iv = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let ct = [9u8; 16];
        let blob = seq(&[
            octet(&key_id),
            seq(&[oid(OID_DES_EDE3_CBC), octet(&iv)]),
            octet(&ct),
        ]);
        let parsed = decode_login_blob(&blob).unwrap();
        assert_eq!(parsed.key_id, key_id);
        assert_eq!(parsed.cipher_oid, OID_DES_EDE3_CBC);
        assert_eq!(parsed.iv, iv);
        assert_eq!(parsed.ciphertext, ct);
    }

    #[test]
    fn decode_pbe_item_3des() {
        let entry_salt = [0xaau8; 20];
        let ct = [0xbbu8; 16];
        let item = seq(&[
            seq(&[
                oid(OID_PBE_SHA1_3DES),
                seq(&[octet(&entry_salt), int(&[0x01])]),
            ]),
            octet(&ct),
        ]);
        match decode_pbe_item(&item).unwrap() {
            PbeItem::TripleDes {
                entry_salt: es,
                ciphertext,
            } => {
                assert_eq!(es, entry_salt);
                assert_eq!(ciphertext, ct);
            }
            other => panic!("expected TripleDes, got {other:?}"),
        }
    }

    #[test]
    fn decode_pbe_item_pbes2() {
        let entry_salt = [0xccu8; 32];
        let iv = [0xddu8; 14];
        let ct = [0xeeu8; 48];
        let kdf = seq(&[
            oid(OID_PBKDF2),
            seq(&[
                octet(&entry_salt),
                int(&[0x27, 0x10]), // 10000
                int(&[0x20]),       // 32
                seq(&[oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09])]),
            ]),
        ]);
        let enc = seq(&[oid(OID_AES256_CBC), octet(&iv)]);
        let item = seq(&[seq(&[oid(OID_PBES2), seq(&[kdf, enc])]), octet(&ct)]);
        match decode_pbe_item(&item).unwrap() {
            PbeItem::Pbes2 {
                entry_salt: es,
                iteration_count,
                key_length,
                iv: got_iv,
                ciphertext,
            } => {
                assert_eq!(es, entry_salt);
                assert_eq!(iteration_count, 10_000);
                assert_eq!(key_length, 32);
                assert_eq!(got_iv, iv);
                assert_eq!(ciphertext, ct);
            }
            other => panic!("expected Pbes2, got {other:?}"),
        }
    }

    #[test]
    fn decode_pbe_item_unknown_oid_surfaces_bytes() {
        let bogus = [0x2a, 0x03, 0x04, 0x05];
        let item = seq(&[seq(&[oid(&bogus), octet(&[0])]), octet(&[0])]);
        match decode_pbe_item(&item) {
            Err(DecryptError::UnsupportedAlgorithm(oid_hex)) => {
                assert_eq!(oid_hex, "2a030405");
            }
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn decode_login_blob_truncated_is_error() {
        let truncated = [0x30, 0x0a, 0x04, 0x02, 0x01];
        assert!(decode_login_blob(&truncated).is_err());
    }

    #[test]
    fn decode_login_blob_wrong_shape_is_error() {
        let not_seq = int(&[0x01]);
        assert!(matches!(
            decode_login_blob(&not_seq),
            Err(DecryptError::Asn1(_))
        ));
    }
}
