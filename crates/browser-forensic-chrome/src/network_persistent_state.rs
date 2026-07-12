//! Chromium `Network Persistent State` recovered-domain parser.
//!
//! Recovers **cleartext hostnames** the browser connected to that survive a
//! history clear. Chromium's `HttpServerProperties` remembers, per origin,
//! whether the server spoke HTTP/2 (`supports_spdy`) or advertised an HTTP/3 /
//! QUIC *alternative service*, and which of those advertisements are currently
//! broken. It is serialized to the `Network Persistent State` JSON file under
//! `net.http_server_properties` by
//! `net/http/http_server_properties_manager.cc`
//! (`HttpServerPropertiesManager::WriteToPrefs` /
//! `HttpServerProperties::WriteToJson`).
//!
//! Honesty: a host here is one the browser *contacted*, recovered independently
//! of history — but it may be a subresource / third-party (CDN, ad, tracker),
//! not necessarily a user-navigated top-level site. Events carry that caveat in
//! `recovery_note`.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::timestamp::webkit_micros_to_unix_nanos;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::{json, Value};

/// Honest caveat attached to every host recovered from a network-state artifact.
pub(crate) const CONTACTED_NOTE: &str = "contacted host, recovered independently of history; \
     may be a subresource/third-party (CDN, ad, tracker), not necessarily a user-navigated site";

/// Extract a bare hostname from a Chromium origin string. `server` entries are
/// full origins (`https://host:443`); `broken_alternative_services[].host` is
/// already bare. Returns `None` if no host can be parsed.
fn host_of(origin: &str) -> Option<String> {
    if let Ok(u) = url::Url::parse(origin) {
        if let Some(h) = u.host_str() {
            return Some(h.to_string());
        }
    }
    // Already-bare host (broken-alt-svc entries): accept if it looks like one.
    let trimmed = origin.trim();
    if !trimmed.is_empty() && !trimmed.contains(['/', ' ']) {
        return Some(trimmed.to_string());
    }
    None
}

/// Read a WebKit-microsecond value stored as a JSON string or number.
fn webkit_value(v: &Value) -> Option<i64> {
    match v {
        Value::String(s) => s.parse::<i64>().ok(),
        Value::Number(n) => n.as_i64(),
        _ => None,
    }
}

/// Parse a Chromium `Network Persistent State` JSON file into recovered-domain
/// events.
///
/// # Errors
///
/// Returns an error if the file cannot be read or is not valid JSON.
pub fn parse_network_persistent_state(path: &Path) -> Result<Vec<BrowserEvent>> {
    let data = std::fs::read_to_string(path)?;
    let root: Value = serde_json::from_str(&data)?;
    let source = path.to_string_lossy().into_owned();
    let mut events = Vec::new();

    let Some(props) = root.pointer("/net/http_server_properties") else {
        return Ok(events);
    };

    if let Some(servers) = props.get("servers").and_then(Value::as_array) {
        for entry in servers {
            let Some(server) = entry.get("server").and_then(Value::as_str) else {
                continue;
            };
            let Some(host) = host_of(server) else {
                continue;
            };
            let supports_spdy = entry
                .get("supports_spdy")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let protocols: Vec<String> = entry
                .get("alternative_service")
                .and_then(Value::as_array)
                .map(|alts| {
                    alts.iter()
                        .filter_map(|a| a.get("protocol_str").and_then(Value::as_str))
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            events.push(
                BrowserEvent::new(
                    0,
                    BrowserFamily::Chromium,
                    ArtifactKind::RecoveredDomain,
                    &source,
                    format!("{host} — contacted (HTTP server properties)"),
                )
                .with_attr("domain", json!(host))
                .with_attr("origin", json!(server))
                .with_attr("source_artifact", json!("Network Persistent State"))
                .with_attr("supports_spdy", json!(supports_spdy))
                .with_attr("alt_protocols", json!(protocols))
                .with_attr("recovery_note", json!(CONTACTED_NOTE)),
            );
        }
    }

    if let Some(broken) = props
        .get("broken_alternative_services")
        .and_then(Value::as_array)
    {
        for entry in broken {
            let Some(host) = entry.get("host").and_then(Value::as_str).and_then(host_of) else {
                continue;
            };
            let protocol = entry
                .get("protocol_str")
                .and_then(Value::as_str)
                .unwrap_or("");
            let broken_until = entry.get("broken_until").and_then(webkit_value);
            let ts_ns = broken_until.map_or(0, webkit_micros_to_unix_nanos);
            let mut ev = BrowserEvent::new(
                ts_ns,
                BrowserFamily::Chromium,
                ArtifactKind::RecoveredDomain,
                &source,
                format!("{host} — contacted (broken alt-svc {protocol})"),
            )
            .with_attr("domain", json!(host))
            .with_attr("source_artifact", json!("Network Persistent State"))
            .with_attr("alt_svc_broken", json!(true))
            .with_attr("protocol", json!(protocol))
            .with_attr("recovery_note", json!(CONTACTED_NOTE));
            if let Some(count) = entry.get("broken_count").and_then(Value::as_i64) {
                ev = ev.with_attr("broken_count", json!(count));
            }
            events.push(ev);
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
    fn extracts_server_host_as_recovered_domain() {
        let f = write_json(
            r#"{"net":{"http_server_properties":{"servers":[
                {"server":"https://cdn.example.com:443","supports_spdy":true,
                 "alternative_service":[{"protocol_str":"quic","port":443}]}
            ]}}}"#,
        );
        let events = parse_network_persistent_state(f.path()).expect("parse");
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::RecoveredDomain);
        assert_eq!(ev.browser, BrowserFamily::Chromium);
        assert_eq!(ev.attrs["domain"], json!("cdn.example.com"));
        assert_eq!(ev.attrs["supports_spdy"], json!(true));
        assert_eq!(ev.attrs["alt_protocols"], json!(["quic"]));
        // Honesty caveat must be present and mention subresource/third-party.
        assert!(ev.attrs["recovery_note"]
            .as_str()
            .unwrap()
            .contains("subresource/third-party"));
    }

    #[test]
    fn broken_alt_service_host_with_broken_until_timestamp() {
        // WebKit micros for 2023-11-14 22:13:20 UTC.
        let webkit = (1_700_000_000_i64 + 11_644_473_600) * 1_000_000;
        let f = write_json(&format!(
            r#"{{"net":{{"http_server_properties":{{"broken_alternative_services":[
                {{"host":"tracker.example.net","port":443,"protocol_str":"quic",
                 "broken_count":3,"broken_until":"{webkit}"}}
            ]}}}}}}"#
        ));
        let events = parse_network_persistent_state(f.path()).expect("parse");
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.attrs["domain"], json!("tracker.example.net"));
        assert_eq!(ev.attrs["protocol"], json!("quic"));
        assert_eq!(ev.attrs["broken_count"], json!(3));
        assert_eq!(ev.timestamp_ns, 1_700_000_000_000_000_000);
    }

    #[test]
    fn both_server_and_broken_entries_surface() {
        let f = write_json(
            r#"{"net":{"http_server_properties":{
                "servers":[{"server":"https://a.example.com"}],
                "broken_alternative_services":[{"host":"b.example.com","protocol_str":"h3"}]
            }}}"#,
        );
        let events = parse_network_persistent_state(f.path()).expect("parse");
        let domains: std::collections::HashSet<_> = events
            .iter()
            .map(|e| e.attrs["domain"].as_str().unwrap().to_string())
            .collect();
        assert!(domains.contains("a.example.com"));
        assert!(domains.contains("b.example.com"));
    }

    #[test]
    fn empty_or_missing_properties_returns_empty() {
        assert!(parse_network_persistent_state(write_json("{}").path())
            .expect("parse")
            .is_empty());
        assert!(parse_network_persistent_state(
            write_json(r#"{"net":{"http_server_properties":{}}}"#).path()
        )
        .expect("parse")
        .is_empty());
    }

    #[test]
    fn malformed_json_returns_error() {
        assert!(parse_network_persistent_state(write_json("{not json").path()).is_err());
    }
}
