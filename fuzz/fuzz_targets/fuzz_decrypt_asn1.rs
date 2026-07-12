#![no_main]
//! Fuzz the opt-in decryption parsers over attacker-controlled bytes: the NSS
//! ASN.1/DER login-blob and PBE-item decoders, and the macOS Chromium `v10`
//! blob path (length/prefix/padding handling). These consume evidence files
//! handed to the tool, so the invariant is "must never panic" — every malformed
//! input must return a typed `Err`, not crash and not fabricate plaintext.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = browser_forensic_decrypt::asn1::decode_login_blob(data);
    let _ = browser_forensic_decrypt::asn1::decode_pbe_item(data);
    // v10 CBC blob path with a fixed key: exercises prefix/alignment/unpad guards.
    let key = [0u8; 16];
    let _ = browser_forensic_decrypt::decrypt_chromium_value_macos(data, &key);
});
