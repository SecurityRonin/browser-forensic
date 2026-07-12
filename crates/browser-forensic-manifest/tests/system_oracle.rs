#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tier-1 cross-check: our SHA-256 / MD5 of a real file must exactly equal the
//! digests produced by the operating system's own tools (`shasum -a 256` /
//! `md5`, or their GNU coreutils equivalents). The oracle is an independent
//! third-party implementation shipped with the OS, not a fixture we authored.
//!
//! Skips cleanly when neither tool is present (keeps CI green on minimal images).

use std::io::Write;
use std::process::Command;

use browser_forensic_manifest::hash_file;
use tempfile::NamedTempFile;

/// Run `program args… path`, return the first whitespace token of stdout
/// (the digest column) on success, or `None` if the program is unavailable.
fn oracle_digest(program: &str, args: &[&str], path: &std::path::Path) -> Option<String> {
    let out = Command::new(program).args(args).arg(path).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    text.split_whitespace().next().map(str::to_lowercase)
}

/// First working SHA-256 oracle: BSD `shasum -a 256` or GNU `sha256sum`.
fn sha256_oracle(path: &std::path::Path) -> Option<String> {
    oracle_digest("shasum", &["-a", "256"], path).or_else(|| oracle_digest("sha256sum", &[], path))
}

/// First working MD5 oracle: BSD `md5 -q` or GNU `md5sum`.
fn md5_oracle(path: &std::path::Path) -> Option<String> {
    oracle_digest("md5", &["-q"], path).or_else(|| oracle_digest("md5sum", &[], path))
}

#[test]
fn digests_match_system_tools_on_real_bytes() {
    // Non-trivial, non-repeating content so a broken chunk loop would diverge.
    let mut f = NamedTempFile::new().unwrap();
    let mut bytes = Vec::with_capacity(200_003);
    for i in 0..200_003u32 {
        bytes.push((i.wrapping_mul(2_654_435_761) >> 13) as u8);
    }
    f.write_all(&bytes).unwrap();
    f.flush().unwrap();
    let path = f.path();

    let ours = hash_file(path).expect("hash_file");

    match sha256_oracle(path) {
        Some(expected) => assert_eq!(ours.sha256, expected, "SHA-256 must match system oracle"),
        None => eprintln!("skip: no shasum/sha256sum on PATH"),
    }
    match md5_oracle(path) {
        Some(expected) => assert_eq!(ours.md5, expected, "MD5 must match system oracle"),
        None => eprintln!("skip: no md5/md5sum on PATH"),
    }
    assert_eq!(ours.size_bytes, bytes.len() as u64);
}
