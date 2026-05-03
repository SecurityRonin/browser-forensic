use assert_cmd::Command;

#[test]
fn bw_help_exits_0() {
    Command::cargo_bin("bw").unwrap().arg("--help").assert().success();
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
