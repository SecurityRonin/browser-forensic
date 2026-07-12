#![no_main]
//! Fuzz the Windows Chromium DPAPI decryption parsers over attacker-controlled
//! bytes: the DPAPI blob parser, the Chromium `Local State` key recovery path
//! (JSON + base64 + `DPAPI` prefix + blob), and the `v10`/`v11`/`v20` GCM value
//! path. These consume evidence handed to the tool, so the invariant is "must
//! never panic": every malformed input must return a typed `Err`, not crash and
//! not fabricate plaintext.
use browser_forensic_decrypt::dpapi::{self, DpapiSecret};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. Raw DPAPI blob parser (bounds/length handling).
    let _ = dpapi::parse_dpapi_blob(data);

    // 2. Blob decryption with a fixed master key (AES-CBC/PKCS7/sign paths). The
    //    KDF is deliberately NOT exercised here (a hostile iteration count would
    //    be a slow, uninteresting path); key recovery below uses a supplied key.
    let masterkey = [0x11u8; 64];
    let _ = dpapi::decrypt_dpapi_blob(data, &masterkey, None);

    // 3. Local State key recovery: JSON + base64 + "DPAPI" prefix + blob, using a
    //    supplied master key so no KDF runs. Treat the bytes as UTF-8 JSON.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = dpapi::decrypt_chromium_key_dpapi(s, &DpapiSecret::MasterKey(masterkey));
    }

    // 4. GCM value path (prefix/nonce/tag length guards).
    let key = [0x22u8; 32];
    let _ = browser_forensic_decrypt::decrypt_chromium_value_win(data, &key);
});
