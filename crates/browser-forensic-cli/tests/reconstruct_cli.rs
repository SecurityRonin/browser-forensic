//! `br4n6 reconstruct PATH --out DIR [--url TARGET] [--format html|warc|gallery]`
//! — end-to-end CLI test over a synthetic Chromium SimpleCache directory.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;

use assert_cmd::Command;
use tempfile::TempDir;

fn br4n6() -> Command {
    Command::cargo_bin("br4n6").unwrap()
}

const HEADER_MAGIC: u64 = 0xfcfb_6d1b_a772_5c30;
const EOF_MAGIC: u64 = 0xf4fa_6f45_970d_41d8;

fn push_eof(out: &mut Vec<u8>, size: u32) {
    out.extend_from_slice(&EOF_MAGIC.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]);
}

/// Build a SimpleCache `[hash]_0` entry: stream1 = body, stream0 = null-
/// delimited HTTP header block.
fn simple_entry(url: &str, body: &[u8], meta: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&HEADER_MAGIC.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
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

fn tiny_png() -> Vec<u8> {
    let mut b = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    b.extend_from_slice(&[0, 0, 0, 13]);
    b.extend_from_slice(b"IHDR");
    b.extend_from_slice(&2u32.to_be_bytes());
    b.extend_from_slice(&2u32.to_be_bytes());
    b.extend_from_slice(&[8, 2, 0, 0, 0]);
    b
}

fn build_cache() -> TempDir {
    let dir = TempDir::new().unwrap();
    let html =
        b"<!doctype html><html><body><h1>hi</h1><img src=/logo.png><img src=/gone.png></body></html>";
    fs::write(
        dir.path().join("aaaa0001_0"),
        simple_entry(
            "https://ex.com/",
            html,
            b"HTTP/1.1 200 OK\0Content-Type: text/html\0\0",
        ),
    )
    .unwrap();
    fs::write(
        dir.path().join("bbbb0002_0"),
        simple_entry(
            "https://ex.com/logo.png",
            &tiny_png(),
            b"HTTP/1.1 200 OK\0Content-Type: image/png\0\0",
        ),
    )
    .unwrap();
    dir
}

#[test]
fn reconstruct_help_exits_0() {
    br4n6().args(["reconstruct", "--help"]).assert().success();
}

#[test]
fn reconstruct_html_writes_page_with_banner_and_inlines_image() {
    let cache = build_cache();
    let out = TempDir::new().unwrap();
    br4n6()
        .args([
            "reconstruct",
            cache.path().to_str().unwrap(),
            "--out",
            out.path().to_str().unwrap(),
            "--format",
            "html",
            "--url",
            "https://ex.com/",
        ])
        .assert()
        .success();

    let html = fs::read_dir(out.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "html"))
        .expect("an html output file");
    let content = fs::read_to_string(&html).unwrap();
    assert!(content.contains("Reconstructed from cached resources"));
    assert!(content.contains("data:image/png"), "present image inlined");

    // The provenance manifest sidecar exists and shows the missing image.
    let manifest = fs::read_dir(out.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.to_string_lossy().ends_with(".manifest.json"))
        .expect("a manifest.json sidecar");
    let mj = fs::read_to_string(&manifest).unwrap();
    assert!(
        mj.contains("https://ex.com/gone.png"),
        "missing gap recorded"
    );
}

#[test]
fn reconstruct_gallery_writes_index() {
    let cache = build_cache();
    let out = TempDir::new().unwrap();
    br4n6()
        .args([
            "reconstruct",
            cache.path().to_str().unwrap(),
            "--out",
            out.path().to_str().unwrap(),
            "--format",
            "gallery",
        ])
        .assert()
        .success();
    let index = out.path().join("index.html");
    assert!(index.is_file(), "gallery index.html written");
    assert!(fs::read_to_string(&index)
        .unwrap()
        .contains("Reconstructed from cached resources"));
}
