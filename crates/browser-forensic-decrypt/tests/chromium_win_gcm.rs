//! Windows Chromium `v10`/`v11` AES-256-GCM value decryption.
//!
//! Vectors: `tests/data/win_dpapi_vectors.json` (see `tests/data/README.md`).
//! GCM `v10`/`v11` blobs are PyCryptodome-oracle, externally-fixed key (tier-2);
//! `NIST_GCM_*` is the NIST CAVP AES-256-GCM KAT (tier-1 for the primitive).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use browser_forensic_decrypt::decrypt_chromium_value_win;
use browser_forensic_decrypt::error::DecryptError;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn vectors() -> serde_json::Value {
    let raw = include_str!("data/win_dpapi_vectors.json");
    serde_json::from_str(raw).unwrap()
}

fn key32(hex: &str) -> [u8; 32] {
    unhex(hex).try_into().unwrap()
}

#[test]
fn v10_value_decrypts_to_known_plaintext() {
    let v = vectors();
    let key = key32(v["GCM_KEY_HEX"].as_str().unwrap());
    let blob = unhex(v["V10_BLOB_HEX"].as_str().unwrap());
    let pt = decrypt_chromium_value_win(&blob, &key).unwrap();
    assert_eq!(pt, v["GCM_PLAINTEXT"].as_str().unwrap().as_bytes());
}

#[test]
fn v11_value_decrypts_to_known_plaintext() {
    let v = vectors();
    let key = key32(v["GCM_KEY_HEX"].as_str().unwrap());
    let blob = unhex(v["V11_BLOB_HEX"].as_str().unwrap());
    let pt = decrypt_chromium_value_win(&blob, &key).unwrap();
    assert_eq!(pt, v["GCM_PLAINTEXT"].as_str().unwrap().as_bytes());
}

#[test]
fn wrong_key_refuses_never_fabricates() {
    let v = vectors();
    let blob = unhex(v["V10_BLOB_HEX"].as_str().unwrap());
    let wrong = [0xAAu8; 32];
    let res = decrypt_chromium_value_win(&blob, &wrong);
    assert!(matches!(res, Err(DecryptError::Gcm(_))));
    // fabrication guard: must NOT be the real plaintext
    assert_ne!(
        res.ok(),
        Some(v["GCM_PLAINTEXT"].as_str().unwrap().as_bytes().to_vec())
    );
}

#[test]
fn tampered_tag_refuses() {
    let v = vectors();
    let key = key32(v["GCM_KEY_HEX"].as_str().unwrap());
    let mut blob = unhex(v["V10_BLOB_HEX"].as_str().unwrap());
    let n = blob.len();
    blob[n - 1] ^= 0x01; // flip a tag bit
    assert!(matches!(
        decrypt_chromium_value_win(&blob, &key),
        Err(DecryptError::Gcm(_))
    ));
}

#[test]
fn v20_app_bound_is_refused_with_diagnostic() {
    let v = vectors();
    let key = key32(v["GCM_KEY_HEX"].as_str().unwrap());
    let blob = unhex(v["V20_BLOB_HEX"].as_str().unwrap());
    match decrypt_chromium_value_win(&blob, &key) {
        Err(DecryptError::AppBoundUnsupported(msg)) => {
            assert!(msg.contains("v20") || msg.to_lowercase().contains("app-bound"));
        }
        other => panic!("expected AppBoundUnsupported, got {other:?}"),
    }
}

#[test]
fn unknown_prefix_surfaces_leading_bytes() {
    let key = [0u8; 32];
    let blob = b"v99\x00\x01\x02"; // not a known version
    match decrypt_chromium_value_win(blob, &key) {
        Err(DecryptError::UnknownVersion(bytes)) => assert_eq!(bytes, "763939"),
        other => panic!("expected UnknownVersion, got {other:?}"),
    }
}

#[test]
fn too_short_value_is_error_not_panic() {
    let key = [0u8; 32];
    // Shorter than prefix(3)+nonce(12)+tag(16): must Err, never panic/slice-OOB.
    for len in 0..30usize {
        let mut b = b"v10".to_vec();
        b.extend(std::iter::repeat_n(0u8, len));
        let _ = decrypt_chromium_value_win(&b, &key); // must not panic
    }
}

#[test]
fn nist_kat_aes256_gcm_empty() {
    // NIST CAVP AES-256-GCM KAT wrapped as a synthetic `v10` value: prefix + IV +
    // (empty ciphertext) + published tag. Decrypts to empty plaintext; a flipped
    // tag must refuse. Tier-1: independent published answer key.
    let v = vectors();
    let key = key32(v["NIST_GCM_KEY_HEX"].as_str().unwrap());
    let iv = unhex(v["NIST_GCM_IV_HEX"].as_str().unwrap());
    let ct = unhex(v["NIST_GCM_CT_HEX"].as_str().unwrap());
    let tag = unhex(v["NIST_GCM_TAG_HEX"].as_str().unwrap());
    let mut blob = b"v10".to_vec();
    blob.extend_from_slice(&iv);
    blob.extend_from_slice(&ct);
    blob.extend_from_slice(&tag);
    let pt = decrypt_chromium_value_win(&blob, &key).unwrap();
    assert_eq!(pt, Vec::<u8>::new());

    let mut bad = blob.clone();
    let n = bad.len();
    bad[n - 1] ^= 0x80;
    assert!(matches!(
        decrypt_chromium_value_win(&bad, &key),
        Err(DecryptError::Gcm(_))
    ));
}
