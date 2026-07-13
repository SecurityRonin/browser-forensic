//! Regenerate the committed `Finding` JSON Schema.
//!
//! ```text
//! cargo run -p browser-forensic-core --features schema --example gen_finding_schema \
//!   > docs/finding.schema.json
//! ```
//!
//! The schema is derived from the Rust types via schemars, so it never drifts
//! from the serialized shape; the CLI `finding_schema_sync` test keeps the
//! committed copy in step.

fn main() {
    let schema = browser_forensic_core::finding_schema();
    match serde_json::to_string_pretty(&schema) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("failed to serialize Finding schema: {e}");
            std::process::exit(1);
        }
    }
}
