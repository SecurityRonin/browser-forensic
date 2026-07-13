//! RFC 0001 P6 (D7) — unified `--keys` decryption UX, end-to-end.
//!
//! Tier-2: the Windows fixtures are built from the decrypt crate's
//! impacket-/NIST-vouched `win_dpapi_vectors.json`. The Local State DPAPI-wrapped
//! key, the masterkey file, and the logon password together recover the
//! AES-256-GCM profile key, which decrypts the v10 cookie value end-to-end. The
//! whole chain runs on any host (no live Keychain), so it is CI-deterministic on
//! macOS and Linux alike.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;

const WIN_VECTORS: &str =
    include_str!("../../browser-forensic-decrypt/tests/data/win_dpapi_vectors.json");
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

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

/// Build a Windows Chromium evidence root: `Default/{Local State, Cookies}` and a
/// `.../Microsoft/Protect/<SID>/<GUID>` masterkey, all WITHIN the root. `blobs`
/// are the per-cookie `encrypted_value` payloads. Returns (root, cookies_path).
fn build_win_root(root: &Path, blobs: &[Vec<u8>]) -> PathBuf {
    let v = win_vec();
    // Nest under a "Chrome" dir so the plain (no-keys) path can detect the family
    // from the vendor string — the keys root still contains everything.
    let base = root.join("Chrome");
    let default = base.join("Default");
    std::fs::create_dir_all(&default).unwrap();
    std::fs::write(
        default.join("Local State"),
        v["LOCAL_STATE_JSON"].as_str().unwrap(),
    )
    .unwrap();

    let protect = base
        .join("AppData")
        .join("Roaming")
        .join("Microsoft")
        .join("Protect")
        .join(v["SID"].as_str().unwrap());
    std::fs::create_dir_all(&protect).unwrap();
    std::fs::write(protect.join("Preferred"), [0u8; 24]).unwrap();
    std::fs::write(
        protect.join(MK_GUID),
        unhex(v["MASTERKEY_FILE_HEX"].as_str().unwrap()),
    )
    .unwrap();

    let cookies = default.join("Cookies");
    let conn = rusqlite::Connection::open(&cookies).unwrap();
    conn.execute_batch(
        "CREATE TABLE cookies (creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL, \
         name TEXT NOT NULL, path TEXT NOT NULL, expires_utc INTEGER DEFAULT 0, \
         is_secure INTEGER DEFAULT 0, is_httponly INTEGER DEFAULT 0, \
         samesite INTEGER DEFAULT 0, encrypted_value BLOB DEFAULT '');",
    )
    .unwrap();
    for (i, blob) in blobs.iter().enumerate() {
        conn.execute(
            "INSERT INTO cookies (creation_utc, host_key, name, path, encrypted_value) \
             VALUES (?1, '.example.com', ?2, '/', ?3)",
            rusqlite::params![13_327_626_000_000_000_i64 + i as i64, format!("c{i}"), blob],
        )
        .unwrap();
    }
    drop(conn);
    cookies
}

#[test]
fn cookies_keys_decrypts_windows_and_marks_provenance() {
    let v = win_vec();
    let dir = tempfile::tempdir().unwrap();
    let v10 = unhex(v["V10_BLOB_HEX"].as_str().unwrap());
    let cookies = build_win_root(dir.path(), &[v10]);

    let out = br4n6()
        .args(["artifact", "cookies"])
        .arg(&cookies)
        .arg("--keys")
        .arg(dir.path())
        .args(["--password-stdin", "--format", "jsonl"])
        .write_stdin(v["PASSWORD"].as_str().unwrap())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let plaintext = v["GCM_PLAINTEXT"].as_str().unwrap();
    assert!(
        stdout.contains(plaintext),
        "decrypted value present: {stdout}"
    );
    assert!(
        stdout.contains("\"encrypted\":false") || stdout.contains("\"encrypted\": false"),
        "JSONL marks the record decrypted: {stdout}"
    );
    assert!(
        stdout.contains("key_source"),
        "JSONL carries the key source: {stdout}"
    );
    // The "Keys:" provenance line lands on stderr, naming the unwrap outcome.
    assert!(
        stderr.contains("Keys:"),
        "stderr announces the key sources: {stderr}"
    );
    assert!(
        stderr.to_lowercase().contains("unwrapped ok"),
        "names the unwrap outcome: {stderr}"
    );
}

#[test]
fn cookies_without_keys_counts_encrypted_and_never_drops() {
    let v = win_vec();
    let dir = tempfile::tempdir().unwrap();
    let v10 = unhex(v["V10_BLOB_HEX"].as_str().unwrap());
    let cookies = build_win_root(dir.path(), &[v10]);

    let out = br4n6()
        .args(["artifact", "cookies"])
        .arg(&cookies)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Encrypted material is COUNTED and pointed at --keys, never silently dropped.
    assert!(
        stderr.to_lowercase().contains("encrypted"),
        "reports encrypted count: {stderr}"
    );
    assert!(stderr.contains("--keys"), "suggests --keys: {stderr}");
    // The cookie is still REPORTED (non-zero-drop), and NO plaintext leaks.
    assert!(
        stdout.contains("ENCRYPTED") || stdout.contains(".example.com"),
        "the encrypted cookie is still listed: {stdout}"
    );
    assert!(
        !stdout.contains(v["GCM_PLAINTEXT"].as_str().unwrap()),
        "no plaintext without keys"
    );
}

#[test]
fn cookies_v20_app_bound_refused_never_fabricated() {
    let v = win_vec();
    let dir = tempfile::tempdir().unwrap();
    let v20 = unhex(v["V20_BLOB_HEX"].as_str().unwrap());
    let cookies = build_win_root(dir.path(), &[v20]);

    let out = br4n6()
        .args(["artifact", "cookies"])
        .arg(&cookies)
        .arg("--keys")
        .arg(dir.path())
        .args(["--password-stdin", "--format", "jsonl"])
        .write_stdin(v["PASSWORD"].as_str().unwrap())
        .output()
        .unwrap();
    // A per-row v20 refusal is loud on the row, not a hard failure of the run.
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("DECRYPT_FAILED"),
        "v20 refused with a loud marker: {stdout}"
    );
    assert!(
        stdout.contains("\"encrypted\":true") || stdout.contains("\"encrypted\": true"),
        "an un-decrypted row stays marked encrypted: {stdout}"
    );
}

#[test]
fn cookies_keys_manifest_records_key_source_found_vs_decrypted() {
    let v = win_vec();
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("manifest.json");
    let v10 = unhex(v["V10_BLOB_HEX"].as_str().unwrap());
    let cookies = build_win_root(dir.path(), &[v10]);

    let out = br4n6()
        .args(["artifact", "cookies"])
        .arg(&cookies)
        .arg("--keys")
        .arg(dir.path())
        .args(["--password-stdin"])
        .arg("--manifest")
        .arg(&manifest)
        .write_stdin(v["PASSWORD"].as_str().unwrap())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let json = std::fs::read_to_string(&manifest).unwrap();
    assert!(
        json.contains("key_sources"),
        "manifest records key sources: {json}"
    );
    assert!(json.contains("Local State (AES key, DPAPI-wrapped)"));
    assert!(json.contains("DPAPI masterkey"));
    assert!(json.contains(MK_GUID), "masterkey GUID identified");
    assert!(
        json.contains("\"unwrapped\": true"),
        "key found flag recorded"
    );
    assert!(
        json.contains("decrypted_items"),
        "found-vs-decrypted count recorded"
    );
    // Found ≠ decrypted: at least one source decrypted the single cookie.
    assert!(
        json.contains("\"decrypted_items\": 1"),
        "one item decrypted: {json}"
    );
}

#[test]
fn cookies_has_no_argv_password_and_old_soup_is_gone() {
    let dir = tempfile::tempdir().unwrap();
    let cookies = build_win_root(dir.path(), &[]);
    for bad in [
        "--password",
        "--dpapi-masterkey",
        "--dpapi-password",
        "--decrypt-win",
        "--decrypt-macos",
        "--local-state",
    ] {
        let out = br4n6()
            .args(["artifact", "cookies"])
            .arg(&cookies)
            .args([bad, "x"])
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "removed/absent flag `{bad}` must be rejected (no argv secret, clean break)"
        );
    }
}
