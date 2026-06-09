//! Source discovery — glob a Sessions directory into typed sources.
//!
//! Synthetic SNSS files in cargo's per-binary temp dir give deterministic,
//! personal-data-free coverage; a smoke test exercises the real profile when one
//! is present.

use snss::{SessionStore, SourceKind, Warning};

mod common;
use common::build;
use std::fs;
use std::path::PathBuf;

fn tmp_subdir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn open_dir_classifies_and_orders_sources() {
    let dir = tmp_subdir("discovery_basic");
    // Higher numeric suffix == newer (Brave's Windows-epoch filename stamp).
    fs::write(
        dir.join("Session_100"),
        build::snss(&[(6, build::nav(1, 0, "https://old", "o"))]),
    )
    .unwrap();
    fs::write(
        dir.join("Session_200"),
        build::snss(&[
            (0, build::pair(9, 1)),
            (6, build::nav(1, 0, "https://new", "n")),
        ]),
    )
    .unwrap();
    fs::write(
        dir.join("Tabs_50"),
        build::snss(&[(1, build::nav(5, 0, "https://closed", "c"))]),
    )
    .unwrap();
    fs::write(
        dir.join("Apps_10"),
        build::snss(&[(6, build::nav(2, 0, "https://app", "a"))]),
    )
    .unwrap();

    let store = SessionStore::open_dir(&dir).expect("opens");
    assert!(store.warnings().is_empty(), "{:?}", store.warnings());

    let kinds: Vec<SourceKind> = store.sources().iter().map(|s| s.kind).collect();
    assert_eq!(
        kinds,
        vec![
            SourceKind::Current,
            SourceKind::Last,
            SourceKind::RecentlyClosed,
            SourceKind::Apps
        ]
    );

    // Newest Session_* (200) is Current and contains the "new" navigation.
    let current = &store.sources()[0];
    assert_eq!(current.kind, SourceKind::Current);
    assert!(current.path.ends_with("Session_200"));
    let url = &current.windows[0].tabs[0].current_nav().url;
    assert_eq!(url, "https://new");
}

#[test]
fn open_dir_missing_directory_is_an_error() {
    let missing = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("does_not_exist_xyz");
    assert!(SessionStore::open_dir(&missing).is_err());
}

#[test]
fn open_dir_empty_directory_yields_no_sources() {
    let dir = tmp_subdir("discovery_empty");
    let store = SessionStore::open_dir(&dir).expect("opens");
    assert!(store.sources().is_empty());
    assert!(store.warnings().is_empty());
}

#[test]
fn open_dir_skips_unreadable_file_with_a_warning() {
    let dir = tmp_subdir("discovery_bad");
    // Newest is valid (Current); the older Session file is garbage (Last slot).
    fs::write(
        dir.join("Session_200"),
        build::snss(&[(6, build::nav(1, 0, "https://ok", "k"))]),
    )
    .unwrap();
    fs::write(dir.join("Session_100"), b"NOT-AN-SNSS-FILE").unwrap();

    let store = SessionStore::open_dir(&dir).expect("opens despite one bad file");
    // The good source is still usable.
    assert!(store
        .sources()
        .iter()
        .any(|s| s.kind == SourceKind::Current));
    // The bad one is surfaced, not silently dropped.
    assert!(
        store
            .warnings()
            .iter()
            .any(|w| matches!(w, Warning::UnreadableSource { .. })),
        "expected an UnreadableSource warning, got {:?}",
        store.warnings()
    );
}

/// Smoke test against the real profile when present: loads without panic and
/// finds at least a Current source with content.
#[test]
fn open_default_profile_loads_real_data_when_present() {
    let store = match SessionStore::open_default_profile() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("SKIP: no default Brave profile on this machine");
            return;
        }
    };
    if store.sources().is_empty() {
        eprintln!("SKIP: default profile has no session files");
        return;
    }
    assert!(store
        .sources()
        .iter()
        .any(|s| s.kind == SourceKind::Current));
}
