#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Sync guard for the committed `Finding` JSON Schema.
//!
//! `docs/finding.schema.json` is a *generated* artifact — it is derived from the
//! live Rust types via schemars ([`browser_forensic_core::finding_schema`]). This
//! test regenerates it and asserts the committed copy still matches, so the
//! schema can never silently drift from the serialized shape.
//!
//! P0 of RFC 0001 deliberately surfaces `Finding` through **no** subcommand yet
//! (the `schema` command still emits only `BrowserEvent`, unchanged), so this
//! guard calls the core generator directly rather than running the binary. When
//! it fails, regenerate:
//!
//! ```text
//! cargo run -p browser-forensic-core --features schema --example gen_finding_schema \
//!   > docs/finding.schema.json
//! ```

#[test]
fn finding_schema_matches_committed_file() {
    let committed_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/finding.schema.json");
    let committed_raw = std::fs::read_to_string(&committed_path).unwrap_or_else(|e| {
        panic!(
            "committed schema not found at {}: {e} — regenerate docs/finding.schema.json",
            committed_path.display()
        )
    });

    let schema = browser_forensic_core::finding_schema();
    // Compare as parsed JSON so pretty-print / trailing-newline noise cannot
    // trigger a false mismatch — the semantic schema is what must stay in sync.
    let generated: serde_json::Value = serde_json::to_value(&schema).unwrap();
    let committed: serde_json::Value = serde_json::from_str(&committed_raw).unwrap();
    assert_eq!(
        committed, generated,
        "docs/finding.schema.json is stale — regenerate it (see this file's header)"
    );
}
