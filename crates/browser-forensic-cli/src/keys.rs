//! RFC 0001 Phase P6 (D7) — the unified `--keys` decryption UX.
//!
//! One evidence-root-constrained helper that AUTO-LOCATES key material **within**
//! the given `--keys`/evidence root and **never outside it**, returns a resolved
//! decryption key plus a manifest-ready audit trail, and reports exactly what it
//! found and used. This is the safe UX wrapper around the audited
//! [`browser_forensic_decrypt`] engines — it introduces no new crypto.
//!
//! ## The load-bearing safety rule (Codex)
//!
//! Auto-location descends **only** into the root the examiner named. A key file
//! that canonicalizes outside that root — a sibling case dir, the examiner's own
//! workstation, live OS state — is never read. The single exception is the live
//! macOS "… Safe Storage" Keychain item, which is itself gated behind the flag
//! and only attempted when a Chromium `Local State` is present in the root and the
//! host is macOS.
//!
//! ## Found ≠ decrypted
//!
//! Resolution proves a key was **found and unwrapped**; it does not decrypt any
//! particular artifact. The [`browser_forensic_manifest::KeySource`] records carry
//! `unwrapped` (found) separately from `decrypted_items` (updated by the caller
//! after it decrypts with the key), so the two are never conflated.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use browser_forensic_manifest::KeySource;

/// The default macOS Keychain service holding the Chromium "Safe Storage" secret.
pub const DEFAULT_KEYCHAIN_SERVICE: &str = "Chrome Safe Storage";

/// The Chromium profile key a root yielded, tagged by platform derivation.
#[derive(Debug)]
pub enum ChromiumKey {
    /// macOS: 16-byte AES-128 key derived from the Keychain "Safe Storage" secret.
    Macos([u8; 16]),
    /// Windows: 32-byte AES-256-GCM profile key unwrapped via DPAPI.
    Win([u8; 32]),
}

/// A resolved key, a human summary of how it was found, a short machine tag for
/// the JSONL `decryption.key_source`, and the manifest audit records.
#[derive(Debug)]
pub struct KeyResolution {
    /// The recovered profile key.
    pub key: ChromiumKey,
    /// One-line human summary, e.g.
    /// `Local State (AES key, DPAPI-wrapped) + masterkey {GUID} → unwrapped OK`.
    pub summary: String,
    /// Short machine tag recorded per-record as `decryption.key_source`.
    pub key_source: String,
    /// Every key file identified/used, hashed for the manifest (D11).
    pub audit: Vec<KeySource>,
}

/// Auto-locate Chromium key material within `root` and recover the profile key.
///
/// Searches only within `root` (a profile or evidence directory). On Windows
/// evidence it reads the `Local State` DPAPI-wrapped key and unwraps it with a
/// DPAPI masterkey found under `.../Microsoft/Protect/<SID>/`, using `password`
/// (the user's logon password). On macOS, when a `Local State` is present and the
/// host is macOS, it reads the "… Safe Storage" Keychain item (`keychain_service`).
///
/// # Errors
/// Fails loudly (a decryption bootstrap failure is never absorbed into an empty
/// result) when no key material is located within the root, when a masterkey lies
/// only outside the root, or when the supplied password does not unwrap the
/// masterkey. Never fabricates a key.
pub fn resolve_chromium_keys(
    _root: &Path,
    _password: Option<&str>,
    _keychain_service: &str,
) -> Result<KeyResolution> {
    // STUB — implemented in the GREEN step. Returns a deliberately wrong,
    // constraint-free result so the RED tests (correct key, evidence-root
    // constraint, wrong-password refusal, empty-root error) all fail.
    Ok(KeyResolution {
        key: ChromiumKey::Win([0u8; 32]),
        summary: String::new(),
        key_source: String::new(),
        audit: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const WIN_VECTORS: &str =
        include_str!("../../browser-forensic-decrypt/tests/data/win_dpapi_vectors.json");
    // A valid-shaped GUID for the masterkey filename. The filename is cosmetic for
    // decryption (the password+SID+file trio drives it); it is what the audit
    // reports as the masterkey identity.
    const MK_GUID: &str = "df9d8cd0-1501-11d1-8c7a-00c04fc297eb";

    fn win_vec() -> serde_json::Value {
        serde_json::from_str(WIN_VECTORS).unwrap()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Write a `Local State` (DPAPI-wrapped key) under `root/Default`.
    fn write_local_state(root: &Path) {
        let v = win_vec();
        let default = root.join("Default");
        std::fs::create_dir_all(&default).unwrap();
        std::fs::write(
            default.join("Local State"),
            v["LOCAL_STATE_JSON"].as_str().unwrap(),
        )
        .unwrap();
    }

    /// Write the DPAPI masterkey file under `base/Microsoft/Protect/<SID>/<GUID>`
    /// and return its path.
    fn write_masterkey(base: &Path) -> PathBuf {
        let v = win_vec();
        let protect = base
            .join("Microsoft")
            .join("Protect")
            .join(v["SID"].as_str().unwrap());
        std::fs::create_dir_all(&protect).unwrap();
        // A real Protect dir also holds a non-GUID "Preferred" pointer — the
        // locator must ignore it and use the GUID-named masterkey.
        std::fs::write(protect.join("Preferred"), [0u8; 24]).unwrap();
        let mkf = protect.join(MK_GUID);
        std::fs::write(&mkf, unhex(v["MASTERKEY_FILE_HEX"].as_str().unwrap())).unwrap();
        mkf
    }

    #[test]
    fn locates_local_state_and_masterkey_within_root_recovers_win_key() {
        let v = win_vec();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_local_state(root);
        write_masterkey(&root.join("AppData").join("Roaming"));

        let res = resolve_chromium_keys(
            root,
            Some(v["PASSWORD"].as_str().unwrap()),
            DEFAULT_KEYCHAIN_SERVICE,
        )
        .expect("keys auto-locate within root");
        match res.key {
            ChromiumKey::Win(k) => {
                assert_eq!(k.to_vec(), unhex(v["CHROMIUM_KEY_HEX"].as_str().unwrap()));
            }
            ChromiumKey::Macos(_) => panic!("expected the Windows key path"),
        }
        // The summary names both key sources and the unwrap outcome.
        assert!(
            res.summary.contains("Local State"),
            "summary: {}",
            res.summary
        );
        assert!(
            res.summary.to_lowercase().contains("masterkey"),
            "summary: {}",
            res.summary
        );
        assert!(
            res.summary.to_lowercase().contains("unwrapped"),
            "summary: {}",
            res.summary
        );
        // Audit: Local State + masterkey, both hashed and marked unwrapped, and
        // neither yet credited with a decrypted item (found ≠ decrypted).
        assert_eq!(res.audit.len(), 2, "two key sources audited");
        assert!(res.audit.iter().all(|k| k.unwrapped));
        assert!(
            res.audit.iter().all(|k| k.sha256.is_some()),
            "key files hashed"
        );
        assert!(
            res.audit.iter().all(|k| k.decrypted_items == 0),
            "found, not yet decrypted"
        );
        assert!(
            res.audit
                .iter()
                .any(|k| k.detail.as_deref().unwrap_or("").contains(MK_GUID)),
            "masterkey GUID identified in audit"
        );
    }

    #[test]
    fn evidence_root_constraint_masterkey_outside_root_is_not_used() {
        let v = win_vec();
        let parent = tempfile::tempdir().unwrap();
        // The evidence root the examiner named …
        let root = parent.path().join("case");
        std::fs::create_dir_all(&root).unwrap();
        write_local_state(&root);
        // … and a masterkey that lives OUTSIDE it (a sibling dir on the examiner's
        // disk). Auto-location must never reach here.
        let outside = parent.path().join("examiner_home");
        std::fs::create_dir_all(&outside).unwrap();
        write_masterkey(&outside);

        let res = resolve_chromium_keys(
            &root,
            Some(v["PASSWORD"].as_str().unwrap()),
            DEFAULT_KEYCHAIN_SERVICE,
        );
        assert!(
            res.is_err(),
            "a masterkey outside the evidence root must NOT be used"
        );

        // Positive control: the SAME masterkey placed INSIDE the root resolves.
        write_masterkey(&root.join("AppData").join("Roaming"));
        let ok = resolve_chromium_keys(
            &root,
            Some(v["PASSWORD"].as_str().unwrap()),
            DEFAULT_KEYCHAIN_SERVICE,
        );
        assert!(
            ok.is_ok(),
            "the same masterkey inside the root DOES resolve"
        );
    }

    #[test]
    fn wrong_password_fails_loud_never_fabricates() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_local_state(root);
        write_masterkey(&root.join("AppData").join("Roaming"));
        let res = resolve_chromium_keys(
            root,
            Some("not-the-logon-password"),
            DEFAULT_KEYCHAIN_SERVICE,
        );
        assert!(
            res.is_err(),
            "a wrong logon password is a loud error, not a fabricated key"
        );
    }

    #[test]
    fn empty_root_yields_a_loud_no_keys_error() {
        // No Local State, no masterkey — no keychain attempt (deterministic on any
        // host). A decryption bootstrap failure is never a silent empty result.
        let dir = tempfile::tempdir().unwrap();
        let res = resolve_chromium_keys(dir.path(), None, DEFAULT_KEYCHAIN_SERVICE);
        assert!(res.is_err(), "no key material within root is a loud error");
        let msg = format!("{:#}", res.unwrap_err());
        assert!(
            msg.to_lowercase().contains("no key") || msg.to_lowercase().contains("within"),
            "error names the constraint: {msg}"
        );
    }
}
