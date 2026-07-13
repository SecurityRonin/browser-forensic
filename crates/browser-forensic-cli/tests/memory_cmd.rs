//! Memory carving is now reached through the `recover` orchestrator (RFC 0001
//! P5b clean break): the standalone `memory` command was removed, and `recover`
//! auto-selects the memory-image scope from the PATH shape. These tests cover
//! that supersession over the `br4n6` binary.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write as _;

use assert_cmd::Command;
use tempfile::NamedTempFile;

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

#[test]
fn standalone_memory_command_is_removed() {
    // The former `memory` verb no longer exists — invoking it is an unknown
    // subcommand error (clean break, no alias).
    br4n6()
        .args(["memory", "/nonexistent/does-not-exist.mem"])
        .assert()
        .failure();
}

#[test]
fn recover_nonexistent_image_fails_loud() {
    // An unreadable image under recover is a hard bootstrap failure — fail loud,
    // non-zero, never a silent empty "nothing recovered".
    br4n6()
        .args(["recover", "/nonexistent/does-not-exist.mem"])
        .assert()
        .failure();
}

#[test]
fn recover_unstructured_buffer_degrades_to_byte_scan() {
    // A readable buffer with a URL but no OS/process structure: recover auto-
    // selects the memory-image scope, the structured carve cannot attribute it,
    // so it degrades to a raw byte-scan (loud on stderr) and still surfaces the
    // scanned URL — never a silent empty.
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"garbage https://example.com/found more garbage")
        .unwrap();
    let out = br4n6()
        .args(["recover", "--format", "jsonl", f.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "byte-scan fallback should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("example.com"),
        "byte-scan fallback should surface the URL; stdout={stdout}"
    );
}
