#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end coverage for `br4n6 manifest` and the `export --manifest FILE`
//! auto-emit path: the chain-of-custody manifest records SHA-256/MD5 + run
//! metadata for every evidence input read.

use assert_cmd::Command;
use std::path::PathBuf;
use tempfile::TempDir;

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

/// A Chrome-looking profile directory containing a `History` file with the
/// canonical bytes `b"abc"` (SHA-256 `ba7816bf…`, MD5 `900150983…`).
fn chrome_profile_with_abc_history() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let profile = dir.path().join("google-chrome").join("Default");
    std::fs::create_dir_all(&profile).unwrap();
    std::fs::write(profile.join("History"), b"abc").unwrap();
    (dir, profile)
}

const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const ABC_MD5: &str = "900150983cd24fb0d6963f7d28e17f72";

#[test]
fn manifest_help_exits_0() {
    br4n6().args(["manifest", "--help"]).assert().success();
}

#[test]
fn manifest_single_file_prints_json_with_digests() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("History");
    std::fs::write(&file, b"abc").unwrap();

    let out = br4n6().args(["manifest"]).arg(&file).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains(ABC_SHA256), "sha256 present: {stdout}");
    assert!(stdout.contains(ABC_MD5), "md5 present");
    assert!(stdout.contains("chain-of-custody"), "schema id present");
    assert!(stdout.to_lowercase().contains("provenance"), "honesty note");
}

#[test]
fn manifest_profile_dir_hashes_history() {
    let (_dir, profile) = chrome_profile_with_abc_history();
    let out = br4n6().args(["manifest"]).arg(&profile).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains(ABC_SHA256),
        "History sha256 present: {stdout}"
    );
}

#[test]
fn manifest_out_writes_file() {
    let (dir, profile) = chrome_profile_with_abc_history();
    let out_path = dir.path().join("manifest.json");
    br4n6()
        .args(["manifest"])
        .arg(&profile)
        .arg("--out")
        .arg(&out_path)
        .assert()
        .success();
    let written = std::fs::read_to_string(&out_path).unwrap();
    assert!(written.contains(ABC_SHA256));
    assert!(written.contains("\"tool\""));
    assert!(written.contains("\"invocation\""));
}

#[test]
fn manifest_empty_dir_errors() {
    let dir = TempDir::new().unwrap();
    let out = br4n6()
        .args(["manifest"])
        .arg(dir.path())
        .assert()
        .failure();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("no recognized"),
        "diagnostic names cause: {stderr}"
    );
}

#[test]
fn export_manifest_flag_emits_manifest() {
    let (dir, profile) = chrome_profile_with_abc_history();
    // Give the profile a real SQLite History so export can parse it, but hash the
    // manifest over whatever evidence files are present.
    let manifest_path = dir.path().join("m.json");
    br4n6()
        .args(["export"])
        .arg(&profile)
        .args(["--format", "jsonl", "--manifest"])
        .arg(&manifest_path)
        .assert()
        .success();
    assert!(manifest_path.is_file(), "manifest file written");
    let written = std::fs::read_to_string(&manifest_path).unwrap();
    assert!(written.contains(ABC_SHA256), "manifest hashes History");
}
