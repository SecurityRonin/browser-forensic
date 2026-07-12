//! Chromium `TransportSecurity` (HSTS/HPKP) parser — **non-enumerable**.
//!
//! Chromium stores dynamic HSTS/HPKP state with the host **hashed**: the key is
//! `base64(SHA-256(canonicalized host))` (Chromium `TransportSecurityState` /
//! `TransportSecurityPersister`). You therefore **cannot enumerate** the domains
//! from this file — you can only *candidate-test* a host you already suspect by
//! hashing it and looking for a match. This parser surfaces each hash plus its
//! `sts_observed` / `expiry` and clearly marks it non-enumerable; it never
//! presents a hash as a recovered domain.
//!
//! Two on-disk layouts are handled: the modern `{ "sts": [ {host, …} ], "version": N }`
//! array and the legacy flat map `{ "<hash>": {…}, "version": N }`. Timestamps
//! (`sts_observed`, `expiry`) are Unix epoch **seconds** (floating point).

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::timestamp::unix_secs_f64_to_nanos;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::{json, Value};

const HSTS_HASHED_NOTE: &str = "HSTS/HPKP pin; the host is stored as \
     base64(SHA-256(canonicalized host)) — a known host can be candidate-tested by hashing it, \
     but the domain cannot be enumerated from this value";

/// Build one non-enumerable HSTS event from a hash + its entry object.
fn hsts_event(source: &str, host_hash: &str, entry: &Value) -> BrowserEvent {
    let sts_observed = entry.get("sts_observed").and_then(Value::as_f64);
    let expiry = entry.get("expiry").and_then(Value::as_f64);
    let mode = entry.get("mode").and_then(Value::as_str).unwrap_or("");
    let include_subdomains = entry
        .get("sts_include_subdomains")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let ts_ns = sts_observed.map_or(0, unix_secs_f64_to_nanos);

    let mut ev = BrowserEvent::new(
        ts_ns,
        BrowserFamily::Chromium,
        ArtifactKind::RecoveredDomain,
        source,
        format!("HSTS pin (hashed host {host_hash}) mode={mode}"),
    )
    .with_attr("host_hash", json!(host_hash))
    .with_attr("enumerable", json!(false))
    .with_attr("source_artifact", json!("TransportSecurity"))
    .with_attr("mode", json!(mode))
    .with_attr("include_subdomains", json!(include_subdomains))
    .with_attr("recovery_note", json!(HSTS_HASHED_NOTE));
    if let Some(exp) = expiry {
        ev = ev.with_attr("expiry_ns", json!(unix_secs_f64_to_nanos(exp)));
    }
    ev
}

/// Parse a Chromium `TransportSecurity` JSON file. Entries are **hashed** and
/// marked non-enumerable — no domain is ever recovered here.
///
/// # Errors
///
/// Returns an error if the file cannot be read or is not valid JSON.
pub fn parse_transport_security(path: &Path) -> Result<Vec<BrowserEvent>> {
    let data = std::fs::read_to_string(path)?;
    let root: Value = serde_json::from_str(&data)?;
    let source = path.to_string_lossy().into_owned();
    let mut events = Vec::new();

    // Modern layout: { "sts": [ { "host": "<hash>", ... } ], "version": N }.
    if let Some(arr) = root.get("sts").and_then(Value::as_array) {
        for entry in arr {
            if let Some(host_hash) = entry.get("host").and_then(Value::as_str) {
                events.push(hsts_event(&source, host_hash, entry));
            }
        }
        return Ok(events);
    }

    // Legacy layout: flat map keyed by the hash. Skip scalar keys like "version".
    if let Some(map) = root.as_object() {
        for (host_hash, entry) in map {
            if entry.is_object() {
                events.push(hsts_event(&source, host_hash, entry));
            }
        }
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_json(json_data: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(json_data.as_bytes()).expect("write");
        f
    }

    #[test]
    fn modern_sts_array_hash_marked_non_enumerable() {
        let f = write_json(
            r#"{"sts":[
                {"host":"AB5Rtvg91B+Qx43td2FzdLyGYvKvoqUE76q5oqlatOs=",
                 "mode":"force-https","sts_include_subdomains":true,
                 "sts_observed":1700000000.5,"expiry":1800000000.0}
            ],"version":2}"#,
        );
        let events = parse_transport_security(f.path()).expect("parse");
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::RecoveredDomain);
        assert_eq!(ev.attrs["enumerable"], json!(false));
        assert_eq!(
            ev.attrs["host_hash"],
            json!("AB5Rtvg91B+Qx43td2FzdLyGYvKvoqUE76q5oqlatOs=")
        );
        // No cleartext domain is ever produced for HSTS.
        assert!(!ev.attrs.contains_key("domain"));
        assert_eq!(ev.attrs["include_subdomains"], json!(true));
        // sts_observed 1700000000.5s -> ns.
        assert_eq!(ev.timestamp_ns, 1_700_000_000_500_000_000);
        assert!(ev.attrs["recovery_note"]
            .as_str()
            .unwrap()
            .contains("cannot be enumerated"));
    }

    #[test]
    fn legacy_flat_map_skips_version_scalar() {
        let f = write_json(
            r#"{"J3lZ8host+hash+base64+value+AAAAAAAAAAAAAAAAA=":
                {"mode":"force-https","sts_observed":1600000000.0,"expiry":1700000000.0},
               "version":2}"#,
        );
        let events = parse_transport_security(f.path()).expect("parse");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].attrs["enumerable"], json!(false));
        assert!(events[0].attrs.contains_key("host_hash"));
    }

    #[test]
    fn empty_returns_empty() {
        assert!(parse_transport_security(write_json("{}").path())
            .expect("parse")
            .is_empty());
        assert!(
            parse_transport_security(write_json(r#"{"sts":[],"version":2}"#).path())
                .expect("parse")
                .is_empty()
        );
    }

    #[test]
    fn malformed_json_returns_error() {
        assert!(parse_transport_security(write_json("{not json").path()).is_err());
    }
}
