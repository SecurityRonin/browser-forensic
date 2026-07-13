#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Sync guard for the committed `BrowserEvent` JSON Schema.
//!
//! `docs/browserevent.schema.json` is a *generated* artifact — `br4n6 schema`
//! derives it from the live Rust types via schemars. This test re-runs the
//! subcommand and asserts the committed copy still matches, so the schema can
//! never silently drift from the serialized shape. If it fails, regenerate:
//!
//! ```text
//! br4n6 schema > docs/browserevent.schema.json
//! ```

use assert_cmd::Command;

#[test]
fn schema_subcommand_matches_committed_file() {
    let committed_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/browserevent.schema.json");
    let committed_raw = std::fs::read_to_string(&committed_path).unwrap_or_else(|e| {
        panic!(
            "committed schema not found at {}: {e} — run `br4n6 schema > docs/browserevent.schema.json`",
            committed_path.display()
        )
    });

    let assert = Command::cargo_bin("br4n6")
        .unwrap()
        .arg("schema")
        .assert()
        .success();
    let generated_raw = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    // Compare as parsed JSON so pretty-print / trailing-newline noise cannot
    // trigger a false mismatch — the semantic schema is what must stay in sync.
    let generated: serde_json::Value = serde_json::from_str(&generated_raw).unwrap();
    let committed: serde_json::Value = serde_json::from_str(&committed_raw).unwrap();
    assert_eq!(
        committed, generated,
        "docs/browserevent.schema.json is stale — regenerate with `br4n6 schema > docs/browserevent.schema.json`"
    );
}
