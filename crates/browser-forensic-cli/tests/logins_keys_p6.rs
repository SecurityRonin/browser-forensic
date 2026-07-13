//! RFC 0001 P6 (D7) — `artifact logins` unified `--keys` UX, end-to-end.
//!
//! Tier-1: reuses the firepwd-vouched Firefox NSS fixtures in
//! `browser-forensic-decrypt/tests/data` (known username + password under an
//! empty master password). Passwords are double-gated: `--keys` decrypts, and
//! `--reveal-secrets <FILE>` materializes plaintext to a file only — never the
//! terminal.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use assert_cmd::Command;

const KNOWN_USER: &str = "alice@example.com";
const KNOWN_PASS: &str = "S3cr3t-Passw0rd!";

fn ffpbes2() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../browser-forensic-decrypt/tests/data/ffpbes2")
}

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

#[test]
fn logins_keys_shows_usernames_but_never_passwords_on_terminal() {
    let out = br4n6()
        .args(["artifact", "logins"])
        .arg(ffpbes2())
        .arg("--keys")
        .arg(ffpbes2())
        .args(["--password-stdin"])
        .write_stdin("")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains(KNOWN_USER), "username shown: {stdout}");
    assert!(
        !stdout.contains(KNOWN_PASS),
        "password MUST NOT appear on the terminal by default: {stdout}"
    );
    assert!(
        stdout.contains("reveal-secrets"),
        "password rendered as a file-output placeholder: {stdout}"
    );
    assert!(
        stderr.contains("Keys:"),
        "announces the key source: {stderr}"
    );
}

#[test]
fn logins_reveal_secrets_writes_password_to_file_not_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let secrets = dir.path().join("secrets.txt");
    let out = br4n6()
        .args(["artifact", "logins"])
        .arg(ffpbes2())
        .arg("--keys")
        .arg(ffpbes2())
        .args(["--password-stdin"])
        .arg("--reveal-secrets")
        .arg(&secrets)
        .write_stdin("")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The plaintext password goes to the FILE …
    let file = std::fs::read_to_string(&secrets).unwrap();
    assert!(file.contains(KNOWN_PASS), "secret written to file: {file}");
    assert!(
        file.contains(KNOWN_USER),
        "secret file identifies the account"
    );
    // … and NEVER to stdout, even with --reveal-secrets set.
    assert!(
        !stdout.contains(KNOWN_PASS),
        "password must never reach stdout: {stdout}"
    );
    assert!(
        stdout.contains(KNOWN_USER),
        "username still shown on stdout"
    );
}

#[test]
fn logins_has_no_argv_password_and_old_optin_flags_are_gone() {
    for bad in [
        "--master-password",
        "--include-passwords",
        "--decrypt",
        "--password",
    ] {
        let out = br4n6()
            .args(["artifact", "logins"])
            .arg(ffpbes2())
            .args([bad, "x"])
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "removed/absent flag `{bad}` must be rejected (no argv secret, clean break)"
        );
    }
}
