// Each integration-test binary compiles this module separately and uses a
// different subset of helpers, so unused-in-one-binary is expected.
#![allow(dead_code)]

//! Shared helpers for integration tests.
//!
//! Real Brave fixtures are gitignored (they hold personal browsing history), so on
//! CI or a fresh clone they are absent. Tests that need them call
//! [`open_fixture_or_skip`], which skips loudly instead of failing — synthetic
//! tests still run everywhere and guard the decode logic portably.

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use snss::{read_records, RecordStream};

pub fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

/// Read a real fixture, or return `None` with a visible skip notice if it is not
/// present locally (e.g. on CI). Never silently passes: the notice names the file
/// and how to populate it.
pub fn open_fixture_or_skip(name: &str) -> Option<RecordStream> {
    let path = fixture_path(name);
    match File::open(&path) {
        Ok(f) => Some(read_records(BufReader::new(f)).expect("valid SNSS header")),
        Err(_) => {
            eprintln!(
                "SKIP: fixture {name} absent at {} — run scripts/copy-fixtures.sh to populate",
                path.display()
            );
            None
        }
    }
}

// --- Synthetic SNSS builders (committed, no personal data) -------------------
// These let tests construct known command streams to pin decode behaviour. The
// real-fixture tests remain the authoritative check against Chromium's output.
#[allow(dead_code)] // each test file uses a subset
pub mod build {
    /// A Chromium Pickle UpdateTabNavigation payload: 4-byte LE length header,
    /// then 4-byte-aligned tab_id, index, UTF-8 url, UTF-16-LE title.
    pub fn nav(tab_id: i32, index: i32, url: &str, title: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&tab_id.to_le_bytes());
        body.extend_from_slice(&index.to_le_bytes());
        body.extend_from_slice(&(url.len() as i32).to_le_bytes());
        body.extend_from_slice(url.as_bytes());
        pad4(&mut body);
        let units: Vec<u16> = title.encode_utf16().collect();
        body.extend_from_slice(&(units.len() as i32).to_le_bytes());
        for u in &units {
            body.extend_from_slice(&u.to_le_bytes());
        }
        pad4(&mut body);
        let mut out = (body.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(&body);
        out
    }

    /// A raw two-i32 POD payload (SetTabWindow, TabIndexInWindow, SelectedNav…).
    pub fn pair(a: i32, b: i32) -> Vec<u8> {
        let mut v = a.to_le_bytes().to_vec();
        v.extend_from_slice(&b.to_le_bytes());
        v
    }

    /// A SetPinnedState POD payload: `{tab_id: i32, pinned: bool}` padded to 8.
    pub fn pinned(tab_id: i32, pinned: bool) -> Vec<u8> {
        let mut v = tab_id.to_le_bytes().to_vec();
        v.push(pinned as u8);
        v.extend_from_slice(&[0, 0, 0]); // pad to 8 as Chromium does
        v
    }

    /// A LastActiveTime POD payload: `{tab_id: i32, _pad: i32, time: i64}`.
    pub fn last_active(tab_id: i32, win_micros: i64) -> Vec<u8> {
        let mut v = tab_id.to_le_bytes().to_vec();
        v.extend_from_slice(&0i32.to_le_bytes());
        v.extend_from_slice(&win_micros.to_le_bytes());
        v
    }

    /// Assemble a full SNSS v3 file from `(command_id, payload)` records.
    pub fn snss(records: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut out = b"SNSS".to_vec();
        out.extend_from_slice(&3i32.to_le_bytes());
        for (id, payload) in records {
            let size = (payload.len() + 1) as u16;
            out.extend_from_slice(&size.to_le_bytes());
            out.push(*id);
            out.extend_from_slice(payload);
        }
        out
    }

    fn pad4(v: &mut Vec<u8>) {
        while v.len() % 4 != 0 {
            v.push(0);
        }
    }
}
