//! `br4n6 memory PATH` — process-attributed memory carve with byte-scan fallback.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write as _;

use assert_cmd::Command;
use tempfile::NamedTempFile;

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

#[test]
fn memory_subcommand_help_exits_0() {
    br4n6().args(["memory", "--help"]).assert().success();
}

#[test]
fn memory_nonexistent_image_fails_loud() {
    // An unreadable image is a hard bootstrap failure — fail loud, non-zero.
    br4n6()
        .args(["memory", "/nonexistent/does-not-exist.mem"])
        .assert()
        .failure();
}

#[test]
fn memory_unstructured_buffer_degrades_to_byte_scan() {
    // A readable buffer with a URL but no OS/process structure: the structured
    // carve cannot attribute it, so the CLI degrades to a raw byte-scan (loud
    // on stderr) and still succeeds with the scanned URL — never a silent empty.
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"garbage https://example.com/found more garbage")
        .unwrap();
    let out = br4n6()
        .args(["memory", "--format", "jsonl", f.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "byte-scan fallback should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("example.com"),
        "byte-scan fallback should surface the URL; stdout={stdout}"
    );
}
