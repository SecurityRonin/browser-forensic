//! `br4n6 cachestorage PATH` — end-to-end CLI test over a synthetic Service
//! Worker CacheStorage tree built from proto + SimpleCache wire bytes.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use assert_cmd::Command;
use tempfile::TempDir;

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

// --- minimal protobuf + SimpleCache encoders (mirror the on-disk layout) ---

fn varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}
fn tag(field: u64, wire: u8, out: &mut Vec<u8>) {
    varint((field << 3) | u64::from(wire), out);
}
fn len_field(field: u64, payload: &[u8], out: &mut Vec<u8>) {
    tag(field, 2, out);
    varint(payload.len() as u64, out);
    out.extend_from_slice(payload);
}
fn varint_field(field: u64, v: u64, out: &mut Vec<u8>) {
    tag(field, 0, out);
    varint(v, out);
}

fn index_txt(name: &str, uuid: &str, storage_key: &str) -> Vec<u8> {
    let mut cache = Vec::new();
    len_field(1, name.as_bytes(), &mut cache);
    len_field(2, uuid.as_bytes(), &mut cache);
    let mut out = Vec::new();
    len_field(1, &cache, &mut out);
    len_field(3, storage_key.as_bytes(), &mut out);
    out
}

fn header(name: &str, value: &str) -> Vec<u8> {
    let mut m = Vec::new();
    len_field(1, name.as_bytes(), &mut m);
    len_field(2, value.as_bytes(), &mut m);
    m
}

fn metadata(method: &str, status: u64, headers: &[(&str, &str)]) -> Vec<u8> {
    let mut req = Vec::new();
    len_field(1, method.as_bytes(), &mut req);
    let mut resp = Vec::new();
    varint_field(1, status, &mut resp);
    len_field(2, b"", &mut resp);
    varint_field(3, 2, &mut resp);
    for (k, v) in headers {
        let h = header(k, v);
        len_field(4, &h, &mut resp);
    }
    let mut out = Vec::new();
    len_field(1, &req, &mut out);
    len_field(2, &resp, &mut out);
    out
}

const HEADER_MAGIC: u64 = 0xfcfb_6d1b_a772_5c30;
const EOF_MAGIC: u64 = 0xf4fa_6f45_970d_41d8;

fn push_eof(out: &mut Vec<u8>, size: u32) {
    out.extend_from_slice(&EOF_MAGIC.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // FLAG_HAS_CRC32
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]);
}

fn cs_entry(url: &str, body: &[u8], meta: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&HEADER_MAGIC.to_le_bytes());
    out.extend_from_slice(&5u32.to_le_bytes());
    out.extend_from_slice(&(url.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(url.as_bytes());
    out.extend_from_slice(body);
    push_eof(&mut out, body.len() as u32);
    out.extend_from_slice(meta);
    push_eof(&mut out, meta.len() as u32);
    out
}

/// Build a `<origin-hash>/` CacheStorage dir with one cache holding one entry.
fn build_tree() -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();
    let origin_hash = dir.path().join("4c237d5e33167c88");
    let uuid = "68f870d4-ed4e-4331-b7bd-7faed95e3d5e";
    std::fs::create_dir_all(origin_hash.join(uuid)).unwrap();
    std::fs::write(
        origin_hash.join("index.txt"),
        index_txt("config-cache", uuid, "https://app.slack.com/"),
    )
    .unwrap();
    let meta = metadata("GET", 200, &[("content-type", "application/json")]);
    let entry = cs_entry("https://slack.com/locales", b"[\"en-US\"]", &meta);
    std::fs::write(origin_hash.join(uuid).join("823a203fd344c931_0"), entry).unwrap();
    let oh = origin_hash.clone();
    (dir, oh)
}

#[test]
fn cachestorage_help_exits_0() {
    br4n6()
        .args(["artifact", "cachestorage", "--help"])
        .assert()
        .success();
}

#[test]
fn cachestorage_empty_dir_succeeds() {
    let dir = TempDir::new().unwrap();
    br4n6()
        .args(["artifact", "cachestorage", dir.path().to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn cachestorage_jsonl_recovers_entry() {
    let (_dir, oh) = build_tree();
    let output = br4n6()
        .args([
            "artifact",
            "cachestorage",
            "--format",
            "jsonl",
            oh.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cachestorage failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut saw_url = false;
    for line in stdout.lines().filter(|l| !l.is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("line is not valid JSON: {e}\n{line}"));
        if v.to_string().contains("https://slack.com/locales") {
            saw_url = true;
            assert!(
                v.to_string().contains("config-cache"),
                "cache name attribution missing: {line}"
            );
        }
    }
    assert!(saw_url, "recovered URL not present in output:\n{stdout}");
    let _ = Path::new(&oh);
}
