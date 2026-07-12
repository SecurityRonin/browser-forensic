//! Chromium cookie domain-binding prefix (cookie-DB schema v24+).
//!
//! Since `Cookies` schema version 24, Chromium prepends the raw 32-byte
//! `SHA-256(domain)` digest to a cookie's plaintext value BEFORE encryption,
//! then verifies and strips it on load. Per Chromium
//! `net/extras/sqlite/sqlite_persistent_cookie_store.cc`:
//!
//! * encrypt path — `EncryptString(StrCat({crypto::SHA256HashString(cc.Domain()),
//!   cc.Value()}), …)`;
//! * load path — `StartsWith(value, crypto::SHA256HashString(domain))` then
//!   `value = value.substr(correct_hash.length())`, else `kHashFailed`.
//!
//! `domain` is the `host_key` column verbatim (the cookie's canonical
//! `Domain()`, e.g. `127.0.0.1` or `.example.com`); the digest is the raw
//! 32-byte SHA-256 output, not hex.

use sha2::{Digest, Sha256};

/// Length of the raw SHA-256 domain-binding prefix, in bytes.
const DOMAIN_HASH_LEN: usize = 32;

/// Strip Chromium's `SHA-256(host_key)` domain-binding prefix from a decrypted
/// cookie plaintext.
///
/// Returns `(value, verified)`:
///
/// * `(plaintext[32..], true)` when `plaintext` is at least 32 bytes AND its
///   first 32 bytes equal `SHA-256(host_key)` — the v24+ domain binding is
///   present and matches.
/// * `(plaintext, false)` otherwise — the plaintext is returned UNCHANGED. This
///   covers pre-v24 cookies (no prefix) and, deliberately, a *mismatch*: a
///   32-byte prefix that is NOT `SHA-256(host_key)`. A mismatch is meaningful,
///   not noise to hide — it is consistent with the cookie value having been
///   moved between domains — so the raw bytes are surfaced with the flag, never
///   silently stripped.
///
/// The hash check (not a bare length test) is what protects a legitimately
/// ≥32-byte value that is not domain-bound: its first 32 bytes will not equal
/// `SHA-256(host_key)`, so it passes through intact.
#[must_use]
pub fn strip_domain_hash_prefix(plaintext: &[u8], host_key: &str) -> (Vec<u8>, bool) {
    let _ = (plaintext, host_key);
    todo!("implemented in the GREEN step")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    // Independent oracle: SHA-256("127.0.0.1"), confirmed byte-identical by two
    // unrelated tools (`shasum -a 256` and Python `hashlib`).
    const SHA256_LOCALHOST_HEX: &str =
        "12ca17b49af2289436f303e0166030a21e525d266e209267433801a8fd4071a0";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn strips_prefix_and_verifies_real_tier1_vector() {
        // Reconstruct the real captured macOS plaintext SHA-256(host) || value,
        // with host=127.0.0.1 and the planted br4n6 probe as the cookie value.
        let host = "127.0.0.1";
        let value = b"br4n6-tier1-probe-7f3a91c2";
        let mut plaintext = Sha256::digest(host.as_bytes()).to_vec();
        plaintext.extend_from_slice(value);
        let (out, verified) = strip_domain_hash_prefix(&plaintext, host);
        assert!(verified);
        assert_eq!(out, value);
    }

    #[test]
    fn prefix_matches_independent_sha256_oracle() {
        // The stripped prefix is exactly SHA-256("127.0.0.1") from an unrelated
        // tool — not one this crate produced.
        let host = "127.0.0.1";
        let value = b"br4n6-tier1-probe-7f3a91c2";
        let mut plaintext = unhex(SHA256_LOCALHOST_HEX);
        plaintext.extend_from_slice(value);
        let (out, verified) = strip_domain_hash_prefix(&plaintext, host);
        assert!(verified);
        assert_eq!(out, value);
    }

    #[test]
    fn wrong_host_key_passes_raw_through_unstripped() {
        // Prefix is SHA-256("127.0.0.1") but a DIFFERENT host is claimed: the
        // mismatch is surfaced raw (verified=false), no bytes dropped — the
        // "moved between domains" signal.
        let value = b"br4n6-tier1-probe-7f3a91c2";
        let mut plaintext = unhex(SHA256_LOCALHOST_HEX);
        plaintext.extend_from_slice(value);
        let (out, verified) = strip_domain_hash_prefix(&plaintext, "evil.example.com");
        assert!(!verified);
        assert_eq!(out, plaintext);
    }

    #[test]
    fn short_value_without_prefix_is_unchanged() {
        // A pre-v24 cookie shorter than 32 bytes is never mis-stripped.
        let (out, verified) = strip_domain_hash_prefix(b"session-token=SECRET42", ".example.com");
        assert!(!verified);
        assert_eq!(out, b"session-token=SECRET42");
    }

    #[test]
    fn long_unprefixed_value_not_mis_stripped() {
        // A legitimately >=32-byte value that is NOT domain-bound passes through
        // intact — the hash check, not the length, protects it.
        let value = b"this-is-a-forty-two-byte-cookie-value-abcd!";
        assert!(value.len() > DOMAIN_HASH_LEN);
        let (out, verified) = strip_domain_hash_prefix(value, "example.com");
        assert!(!verified);
        assert_eq!(out, value);
    }
}
