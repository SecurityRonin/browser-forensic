#![allow(clippy::unwrap_used, clippy::expect_used)]
use assert_cmd::Command;

#[test]
fn bw_help_exits_0() {
    Command::cargo_bin("bw")
        .unwrap()
        .arg("--help")
        .assert()
        .success();
}

#[test]
fn bw_timeline_help_exits_0() {
    Command::cargo_bin("bw")
        .unwrap()
        .args(["timeline", "--help"])
        .assert()
        .success();
}

#[test]
fn bw_timeline_nonexistent_path_fails() {
    Command::cargo_bin("bw")
        .unwrap()
        .args(["timeline", "/nonexistent/History"])
        .assert()
        .failure();
}

#[test]
fn bw_cookies_help_exits_0() {
    Command::cargo_bin("bw")
        .unwrap()
        .args(["cookies", "--help"])
        .assert()
        .success();
}

#[test]
fn bw_downloads_help_exits_0() {
    Command::cargo_bin("bw")
        .unwrap()
        .args(["downloads", "--help"])
        .assert()
        .success();
}

#[test]
fn bw_bookmarks_help_exits_0() {
    Command::cargo_bin("bw")
        .unwrap()
        .args(["bookmarks", "--help"])
        .assert()
        .success();
}

#[test]
fn bw_extensions_help_exits_0() {
    Command::cargo_bin("bw")
        .unwrap()
        .args(["extensions", "--help"])
        .assert()
        .success();
}

#[test]
fn bw_login_data_help_exits_0() {
    Command::cargo_bin("bw")
        .unwrap()
        .args(["login-data", "--help"])
        .assert()
        .success();
}

#[test]
fn bw_autofill_help_exits_0() {
    Command::cargo_bin("bw")
        .unwrap()
        .args(["autofill", "--help"])
        .assert()
        .success();
}

#[test]
fn bw_session_help_exits_0() {
    Command::cargo_bin("bw")
        .unwrap()
        .args(["session", "--help"])
        .assert()
        .success();
}

#[test]
fn bw_cache_help_exits_0() {
    Command::cargo_bin("bw")
        .unwrap()
        .args(["cache", "--help"])
        .assert()
        .success();
}

#[test]
fn bw_profiles_help_exits_0() {
    Command::cargo_bin("bw")
        .unwrap()
        .args(["profiles", "--help"])
        .assert()
        .success();
}

#[test]
fn bw_analyze_help_exits_0() {
    Command::cargo_bin("bw")
        .unwrap()
        .args(["analyze", "--help"])
        .assert()
        .success();
}

#[test]
fn bw_profiles_exits_0() {
    Command::cargo_bin("bw")
        .unwrap()
        .args(["profiles"])
        .assert()
        .success();
}
