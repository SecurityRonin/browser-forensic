//! Firefox `SiteSecurityServiceState.txt` recovered-domain parser (best-effort).
//!
//! Unlike Chromium (which hashes HSTS hosts), Firefox stores its HSTS state with
//! **cleartext hostnames**, so these domains are directly recoverable and survive
//! a history clear. The file is written by Mozilla's `nsSiteSecurityService` via
//! the `DataStorage` backend as tab-separated lines:
//!
//! ```text
//! <host>:HSTS\t<score>\t<lastAccessedDays>\t<expiryMs>,<state>,<includeSubdomains>
//! ```
//!
//! Layout varies across Firefox versions (extra trailing fields, HPKP entries),
//! so parsing is deliberately tolerant: unrecognized or malformed lines are
//! skipped, never fatal.

use std::path::Path;

use browser_forensic_core::timestamp::{unix_millis_to_nanos, unix_secs_to_nanos};
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

const FF_HSTS_NOTE: &str = "HSTS host recorded in cleartext by Firefox — domain recovered \
     independently of history; consistent with a prior HTTPS connection (may be a \
     subresource/third-party)";

const DAY_SECS: i64 = 86_400;

/// Parse a Firefox `SiteSecurityServiceState.txt` file into recovered-domain
/// events. Best-effort: malformed lines are skipped.
///
/// # Errors
///
/// Returns an error only if the file cannot be read.
pub fn parse_site_security(path: &Path) -> anyhow::Result<Vec<BrowserEvent>> {
    let bytes = std::fs::read(path)?;
    let text = String::from_utf8_lossy(&bytes);
    let source = path.to_string_lossy().into_owned();
    Ok(parse_lines(&text, &source))
}

/// Pure line parser (testable and fuzzable without touching the filesystem).
#[must_use]
pub fn parse_lines(text: &str, source: &str) -> Vec<BrowserEvent> {
    let mut events = Vec::new();
    for line in text.lines() {
        if let Some(ev) = parse_line(line, source) {
            events.push(ev);
        }
    }
    events
}

fn parse_line(line: &str, source: &str) -> Option<BrowserEvent> {
    let mut fields = line.split('\t');
    let key = fields.next()?.trim();
    let host = key.strip_suffix(":HSTS")?;
    if host.is_empty() {
        return None;
    }
    // Remaining tab fields: <score> <lastAccessedDays> <value>.
    let rest: Vec<&str> = fields.collect();
    let last_accessed_days = rest.get(1).and_then(|s| s.trim().parse::<i64>().ok());
    let value = rest.last().copied().unwrap_or("");

    // value = <expiryMs>,<state>,<includeSubdomains> (extra fields tolerated).
    let mut parts = value.split(',');
    let expiry_ms = parts.next().and_then(|s| s.trim().parse::<i64>().ok());
    let state = parts.next().and_then(|s| s.trim().parse::<i64>().ok());
    let include_subdomains = matches!(parts.next().map(str::trim), Some("1"));

    let ts_ns = last_accessed_days.map_or(0, |d| unix_secs_to_nanos(d * DAY_SECS));

    let mut ev = BrowserEvent::new(
        ts_ns,
        BrowserFamily::Firefox,
        ArtifactKind::RecoveredDomain,
        source,
        format!("{host} — HSTS host (cleartext)"),
    )
    .with_attr("domain", json!(host))
    .with_attr("source_artifact", json!("SiteSecurityServiceState.txt"))
    .with_attr("include_subdomains", json!(include_subdomains))
    .with_attr("recovery_note", json!(FF_HSTS_NOTE));
    if let Some(exp) = expiry_ms {
        ev = ev.with_attr("expiry_ns", json!(unix_millis_to_nanos(exp)));
    }
    if let Some(s) = state {
        ev = ev.with_attr("hsts_state", json!(s));
    }
    Some(ev)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleartext_hsts_host_recovered_with_last_access() {
        // lastAccessedDays = 19600 -> unix secs 19600*86400.
        let line = "secure.example.com:HSTS\t9\t19600\t1800000000000,1,1";
        let events = parse_lines(line, "/p/SiteSecurityServiceState.txt");
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.artifact, ArtifactKind::RecoveredDomain);
        assert_eq!(ev.browser, BrowserFamily::Firefox);
        assert_eq!(ev.attrs["domain"], json!("secure.example.com"));
        assert_eq!(ev.attrs["include_subdomains"], json!(true));
        assert_eq!(ev.attrs["hsts_state"], json!(1));
        assert_eq!(ev.timestamp_ns, 19600 * 86_400 * 1_000_000_000);
        assert!(ev.attrs["recovery_note"]
            .as_str()
            .unwrap()
            .contains("cleartext"));
    }

    #[test]
    fn non_hsts_line_skipped() {
        let line = "example.com:HPKP\t1\t19600\tsomething";
        assert!(parse_lines(line, "src").is_empty());
    }

    #[test]
    fn malformed_lines_never_panic() {
        let junk = "\n\t\t\t\n:HSTS\tx\ty\tz\ngarbage without tabs\nhost:HSTS";
        // Must not panic; the ":HSTS" (empty host) line is skipped, a bare
        // "host:HSTS" with no value still yields a domain.
        let events = parse_lines(junk, "src");
        assert!(events.iter().all(|e| e.attrs["domain"] != json!("")));
    }

    #[test]
    fn empty_returns_empty() {
        assert!(parse_lines("", "src").is_empty());
    }

    #[test]
    fn include_subdomains_false_when_zero() {
        let line = "a.example.org:HSTS\t9\t19000\t1800000000000,1,0";
        let events = parse_lines(line, "src");
        assert_eq!(events[0].attrs["include_subdomains"], json!(false));
    }
}
