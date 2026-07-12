//! Opt-in decryption CLI integration tests.
//!
//! Firefox credential tests are tier-1: they reuse the firepwd-vouched fixtures
//! in `browser-forensic-decrypt/tests/data`. The Chromium cookie test is tier-2:
//! the fixture was AES-128-CBC-encrypted by an independent Python oracle under a
//! known Safe-Storage key.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use browser_forensic_cli::cli::{decrypt_chromium_cookies, decrypt_firefox_credentials};

const KNOWN_USER: &str = "alice@example.com";
const KNOWN_PASS: &str = "S3cr3t-Passw0rd!";

fn firefox_fixture(scheme: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../browser-forensic-decrypt/tests/data")
        .join(scheme)
}

fn cookie_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/chromium_cookies_v10.sqlite")
}

// pbkdf2_hmac_sha1("peanuts","saltysalt",1003,16) — the fixture's storage key.
const COOKIE_KEY: [u8; 16] = [
    0xd9, 0xa0, 0x9d, 0x49, 0x9b, 0x4e, 0x1b, 0x74, 0x61, 0xf2, 0x8e, 0x67, 0x97, 0x2c, 0x6d, 0xbd,
];

fn attr(ev: &browser_forensic_core::BrowserEvent, k: &str) -> String {
    ev.attrs
        .get(k)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

#[test]
fn firefox_credentials_username_only_by_default() {
    let events = decrypt_firefox_credentials(&firefox_fixture("ffpbes2"), "", false).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(attr(&events[0], "username"), KNOWN_USER);
    // Crown-jewel guard: the password plaintext appears nowhere.
    let json = serde_json::to_string(&events).unwrap();
    assert!(
        !json.contains(KNOWN_PASS),
        "password must not leak by default"
    );
}

#[test]
fn firefox_credentials_password_with_optin() {
    let events = decrypt_firefox_credentials(&firefox_fixture("ffpbes2"), "", true).unwrap();
    assert_eq!(attr(&events[0], "username"), KNOWN_USER);
    assert_eq!(attr(&events[0], "password"), KNOWN_PASS);
}

#[test]
fn firefox_credentials_3des_scheme() {
    let events = decrypt_firefox_credentials(&firefox_fixture("ff3des"), "", true).unwrap();
    assert_eq!(attr(&events[0], "username"), KNOWN_USER);
    assert_eq!(attr(&events[0], "password"), KNOWN_PASS);
}

#[test]
fn firefox_credentials_wrong_master_password_errors() {
    let res = decrypt_firefox_credentials(&firefox_fixture("ffpbes2"), "wrong", true);
    assert!(res.is_err());
}

#[test]
fn chromium_cookie_decrypts_with_correct_key() {
    let events = decrypt_chromium_cookies(&cookie_fixture(), &COOKIE_KEY).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(attr(&events[0], "host"), ".example.com");
    assert_eq!(attr(&events[0], "value"), "cookievalue123");
}

#[test]
fn chromium_cookie_wrong_key_refuses_never_fabricates() {
    let wrong = [0u8; 16];
    let events = decrypt_chromium_cookies(&cookie_fixture(), &wrong).unwrap();
    let value = attr(&events[0], "value");
    assert!(
        value.starts_with("DECRYPT_FAILED"),
        "wrong key must surface a loud marker, got {value:?}"
    );
    assert_ne!(value, "cookievalue123");
}
