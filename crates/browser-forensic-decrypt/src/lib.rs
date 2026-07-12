#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Opt-in decryption of encrypted browser secrets.
//!
//! This crate is a **separate, opt-in** code path. The artifact parsers in the
//! rest of the suite keep surfacing encrypted values as the opaque string
//! `"ENCRYPTED"`; nothing here runs unless a caller explicitly supplies a secret
//! (a Firefox master password, or an authorized macOS Keychain read, or a raw
//! key). Decryption is NEVER silent and NEVER on by default.
//!
//! # Scope (Milestone 2a)
//!
//! * **Firefox NSS** — `key4.db` + `logins.json`, both the legacy 3DES-CBC PBE
//!   and the modern PBES2 (PBKDF2-HMAC-SHA256 → AES-256-CBC) schemes.
//! * **macOS Chromium `v10`** — AES-128-CBC keyed from the login-Keychain
//!   "… Safe Storage" password.
//!
//! Windows DPAPI / AES-GCM (`v10`) and App-Bound (`v20`) are a deferred
//! follow-up and are intentionally NOT implemented here.
//!
//! # Guarantees
//!
//! * **RustCrypto only** — every primitive comes from an audited crate
//!   (`aes`, `cbc`, `des`, `pbkdf2`, `hmac`, `sha1`, `sha2`); nothing is
//!   hand-rolled.
//! * **Never fabricates** — a wrong or absent key produces a loud
//!   [`DecryptError`], never plausible-but-wrong bytes.
//! * **Passwords are gated twice** — decrypting a login *password* requires the
//!   caller to pass `include_passwords = true` in addition to opting into
//!   decryption; usernames and cookie values need only the decrypt opt-in.

pub mod asn1;
pub mod chromium_macos;
pub mod chromium_win;
pub mod dpapi;
pub mod error;
pub mod nss;

pub use chromium_macos::{
    decrypt_chromium_value_macos, derive_chromium_macos_key, fetch_macos_keychain_key,
};
pub use chromium_win::decrypt_chromium_value_win;
pub use dpapi::{
    decrypt_chromium_key_dpapi, decrypt_dpapi_blob, decrypt_masterkey_file, DpapiSecret,
};
pub use error::{DecryptError, Result};
pub use nss::{decrypt_firefox_logins, DecryptedLogin};
