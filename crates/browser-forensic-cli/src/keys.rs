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

use anyhow::Result;
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
    root: &Path,
    password: Option<&str>,
    keychain_service: &str,
) -> Result<KeyResolution> {
    // Constrain every path to the canonical root: a key file that resolves
    // outside the examiner-named root is never read (the load-bearing rule).
    let base = if root.is_dir() {
        root.to_path_buf()
    } else {
        root.parent().unwrap_or(root).to_path_buf()
    };
    let files = collect_files_within(&base);

    // Windows: a `Local State` carrying a DPAPI-wrapped `os_crypt.encrypted_key`.
    let local_state = files.iter().find_map(|p| {
        if p.file_name().and_then(|n| n.to_str()) != Some("Local State") {
            return None;
        }
        let json = std::fs::read_to_string(p).ok()?;
        local_state_has_dpapi_key(&json).then_some((p.clone(), json))
    });

    if let Some((ls_path, ls_json)) = local_state {
        return resolve_windows(&base, &ls_path, &ls_json, password.unwrap_or(""), &files);
    }

    // macOS: the key is not in `Local State` — it lives in the login Keychain.
    // Attempted only when a Chromium `Local State` is present in the root and the
    // host is live macOS (the one flag-gated live-OS read D7 permits).
    let has_local_state = files
        .iter()
        .any(|p| p.file_name().and_then(|n| n.to_str()) == Some("Local State"));
    if has_local_state {
        return resolve_macos(keychain_service);
    }

    anyhow::bail!(
        "no key material located within {}: no `Local State` with a DPAPI-wrapped key was found, \
         and the macOS Safe Storage Keychain is only readable on a live macOS host. \
         Point --keys at the profile/evidence root that holds the keys.",
        base.display()
    )
}

/// Locate the Firefox NSS key database (`key4.db`) **within** `root`, returning
/// its path and a manifest audit record. The `logins.json` it protects is read
/// separately from the artifact path by the caller.
///
/// # Errors
/// Fails loudly when no `key4.db` is found within the root — a `key4.db` outside
/// the evidence root is never read.
pub fn locate_firefox_key4(root: &Path) -> Result<(PathBuf, Vec<KeySource>)> {
    let base = if root.is_dir() {
        root.to_path_buf()
    } else {
        root.parent().unwrap_or(root).to_path_buf()
    };
    let key4 = collect_files_within(&base)
        .into_iter()
        .find(|p| p.file_name().and_then(|n| n.to_str()) == Some("key4.db"))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no key4.db (Firefox NSS key database) found within {} — a key4.db outside the \
                 evidence root is not read. Point --keys at the profile that holds it.",
                base.display()
            )
        })?;
    let audit = vec![key_source_file("Firefox NSS key4.db", &key4, None)];
    Ok((key4, audit))
}

/// Recover the Windows AES-256-GCM profile key: unwrap the `Local State` key with
/// a DPAPI masterkey located under `.../Protect/<SID>/` **within the root**.
fn resolve_windows(
    base: &Path,
    ls_path: &Path,
    ls_json: &str,
    password: &str,
    files: &[PathBuf],
) -> Result<KeyResolution> {
    use browser_forensic_decrypt::DpapiSecret;

    // Masterkey candidates: GUID-named files sitting under a `Protect` ancestor,
    // discovered ONLY within the evidence root. The `Preferred` pointer and other
    // non-GUID files are ignored.
    let candidates: Vec<&PathBuf> = files.iter().filter(|p| is_masterkey_candidate(p)).collect();

    if candidates.is_empty() {
        anyhow::bail!(
            "found a DPAPI-wrapped key in {} but no DPAPI masterkey under any \
             .../Microsoft/Protect/<SID>/ within {} — a masterkey outside the evidence root is \
             not read. Copy the user's Protect directory into the evidence root, or point --keys \
             at a root that contains it.",
            ls_path.display(),
            base.display()
        );
    }

    let mut last_err: Option<String> = None;
    for mkf_path in candidates {
        let Some(sid) = sid_from_masterkey_path(mkf_path) else {
            continue;
        };
        let Ok(mkf) = std::fs::read(mkf_path) else {
            continue;
        };
        match browser_forensic_decrypt::decrypt_chromium_key_dpapi(
            ls_json,
            &DpapiSecret::UserPassword {
                password,
                sid: &sid,
                masterkey_file: &mkf,
            },
        ) {
            Ok(key) => {
                let guid = mkf_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("<unknown>")
                    .to_string();
                let audit = vec![
                    key_source_file("Local State (AES key, DPAPI-wrapped)", ls_path, None),
                    key_source_file(
                        "DPAPI masterkey",
                        mkf_path,
                        Some(format!("masterkey {guid}; SID {sid}")),
                    ),
                ];
                return Ok(KeyResolution {
                    key: ChromiumKey::Win(key),
                    summary: format!(
                        "Local State (AES key, DPAPI-wrapped) + masterkey {guid} \u{2192} unwrapped OK"
                    ),
                    key_source: format!("Local State + DPAPI masterkey {guid}"),
                    audit,
                });
            }
            Err(e) => last_err = Some(e.to_string()),
        }
    }

    anyhow::bail!(
        "located a DPAPI-wrapped key in {} and {} candidate masterkey file(s) within the root, \
         but none unwrapped it — the logon password (--password-stdin) may be wrong, or the \
         masterkey does not belong to this profile. Last error: {}",
        ls_path.display(),
        files.iter().filter(|p| is_masterkey_candidate(p)).count(),
        last_err.as_deref().unwrap_or("none")
    )
}

/// Recover the macOS AES-128 profile key from the login Keychain. Only compiled to
/// actually read the Keychain on macOS; elsewhere it is a loud, honest refusal.
#[cfg(target_os = "macos")]
fn resolve_macos(keychain_service: &str) -> Result<KeyResolution> {
    let password =
        browser_forensic_decrypt::fetch_macos_keychain_key(keychain_service).map_err(|e| {
            anyhow::anyhow!("reading '{keychain_service}' from the macOS login Keychain: {e}")
        })?;
    let key = browser_forensic_decrypt::derive_chromium_macos_key(password.as_bytes());
    Ok(KeyResolution {
        key: ChromiumKey::Macos(key),
        summary: format!(
            "macOS Safe Storage Keychain ('{keychain_service}') \u{2192} key derived OK"
        ),
        key_source: format!("macOS Safe Storage Keychain ('{keychain_service}')"),
        audit: vec![KeySource {
            kind: "macOS Safe Storage keychain".to_string(),
            path: None,
            sha256: None,
            detail: Some(keychain_service.to_string()),
            unwrapped: true,
            decrypted_items: 0,
        }],
    })
}

/// Non-macOS hosts cannot read the macOS Keychain: fail loudly, never fabricate.
#[cfg(not(target_os = "macos"))]
fn resolve_macos(keychain_service: &str) -> Result<KeyResolution> {
    anyhow::bail!(
        "the profile's key lives in the macOS Safe Storage Keychain ('{keychain_service}'), \
         which is only readable on a live macOS host — this host is not macOS"
    )
}

/// A [`KeySource`] audit record for a key file, hashed for identity.
fn key_source_file(kind: &str, path: &Path, detail: Option<String>) -> KeySource {
    let sha256 = browser_forensic_manifest::hash_file(path)
        .ok()
        .map(|d| d.sha256);
    KeySource {
        kind: kind.to_string(),
        path: Some(path.display().to_string()),
        sha256,
        detail,
        unwrapped: true,
        decrypted_items: 0,
    }
}

/// Whether a Chromium `Local State` JSON carries a DPAPI-wrapped `os_crypt`
/// key (`base64("DPAPI" || blob)` — Windows). A macOS profile has no such key.
fn local_state_has_dpapi_key(json: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|v| {
            v.get("os_crypt")
                .and_then(|o| o.get("encrypted_key"))
                .and_then(serde_json::Value::as_str)
                .map(|k| k.starts_with("RFBBUEk")) // base64("DPAPI")
        })
        .unwrap_or(false)
}

/// Whether `path` looks like a DPAPI masterkey file: a GUID-named file directly
/// under a `Protect` ancestor directory.
fn is_masterkey_candidate(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if !is_guid_name(name) {
        return false;
    }
    path.ancestors()
        .any(|a| a.file_name().and_then(|n| n.to_str()) == Some("Protect"))
}

/// The `<SID>` a masterkey file sits under (`.../Protect/<SID>/<GUID>`): its
/// immediate parent directory name.
fn sid_from_masterkey_path(path: &Path) -> Option<String> {
    path.parent()?
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
}

/// Whether `name` is a canonical GUID string (`8-4-4-4-12` hex with hyphens).
fn is_guid_name(name: &str) -> bool {
    if name.len() != 36 {
        return false;
    }
    name.bytes().enumerate().all(|(i, b)| {
        if matches!(i, 8 | 13 | 18 | 23) {
            b == b'-'
        } else {
            b.is_ascii_hexdigit()
        }
    })
}

/// Every regular file within `base`, constrained to the canonical root: symlinks
/// are skipped and each result's canonical path must stay under the canonical
/// root, so auto-location can never escape the evidence root.
fn collect_files_within(base: &Path) -> Vec<PathBuf> {
    let Ok(canon_root) = std::fs::canonicalize(base) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut stack = vec![(canon_root.clone(), 0usize)];
    const MAX_DEPTH: usize = 24;
    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            // Never follow symlinks — that is how a search escapes its root.
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            let path = entry.path();
            if ft.is_dir() {
                stack.push((path, depth + 1));
            } else if ft.is_file() && path.starts_with(&canon_root) {
                out.push(path);
            }
        }
    }
    out.sort();
    out
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
