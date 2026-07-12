//! Registrable-domain (eTLD+1) derivation from a [`BrowserEvent`]'s
//! URL/host-bearing fields.
//!
//! ## Host-derivation rule (documented heuristic — NOT a full public-suffix list)
//!
//! 1. A value is turned into a *host*: a full URL (`scheme://…`) is parsed with
//!    the `url` crate and its host taken; a bare value has any path, port and
//!    userinfo stripped. IPv4/IPv6 literals are kept verbatim.
//! 2. The host is reduced to a *registrable domain* by taking the last two DNS
//!    labels — except when the host ends in a known two-level registry suffix
//!    (`co.uk`, `com.au`, `co.jp`, …), where the last three labels are taken.
//!    The two-level set is a small, documented list of common
//!    `<second-level>.<ccTLD>` registries.
//!
//! This heuristic is correct for the common cases (`www.google.com` →
//! `google.com`, `x.bbc.co.uk` → `bbc.co.uk`) but does **not** consult the full
//! Mozilla Public Suffix List: private suffixes (`github.io`, `s3.amazonaws.com`)
//! and less-common multi-level ccTLDs may collapse to a broader registrable
//! domain than a PSL would yield. Callers needing PSL-exact behavior should
//! substitute a public-suffix crate.

use browser_forensic_core::BrowserEvent;

/// Attr keys whose value is a full URL; the host is parsed out of it.
const URL_FIELDS: &[&str] = &[
    "url",
    "page_url",
    "referrer_url",
    "origin",
    "final_url",
    "target_url",
    "opener_url",
];

/// Attr keys whose value is already a bare host / domain (no scheme).
const BARE_HOST_FIELDS: &[&str] = &["host", "domain", "report_to_host", "hostname"];

/// Common `<second-level>.<ccTLD>` registry labels: when a host's last label is
/// a two-letter ccTLD and its second-to-last label is one of these, the
/// registrable domain spans three labels (`bbc` + `co` + `uk`). Documented,
/// bounded heuristic — not the full Public Suffix List.
const SECOND_LEVEL_REGISTRY: &[&str] = &[
    "co", "com", "org", "net", "gov", "edu", "ac", "mil", "gob", "go", "ne", "or", "in", "govt",
    "school",
];

/// Extract a lowercased host from a URL or bare-host string.
///
/// Returns `None` for an empty value or one with no discernible host.
#[must_use]
pub fn host_of(value: &str) -> Option<String> {
    let _ = value;
    None
}

/// Reduce a host to its registrable domain (eTLD+1) via the documented
/// heuristic. IP literals are returned unchanged. Returns `None` for an empty
/// host.
#[must_use]
pub fn registrable_domain(host: &str) -> Option<String> {
    let _ = host;
    None
}

/// Every distinct registrable domain derivable from an event's URL/host fields,
/// in first-seen order.
#[must_use]
pub fn event_registrable_domains(event: &BrowserEvent) -> Vec<String> {
    let _ = event;
    Vec::new()
}

/// The single registrable domain that best identifies an event: the first
/// present of its primary URL/host fields (`url`, `origin`, `page_url`, …).
#[must_use]
pub fn primary_registrable_domain(event: &BrowserEvent) -> Option<String> {
    let _ = event;
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::{ArtifactKind, BrowserFamily};
    use serde_json::json;

    #[test]
    fn host_of_parses_full_url() {
        assert_eq!(
            host_of("https://www.Example.com/path?q=1"),
            Some("www.example.com".to_string())
        );
        assert_eq!(
            host_of("http://a.b.c.co.uk:8443/x"),
            Some("a.b.c.co.uk".to_string())
        );
    }

    #[test]
    fn host_of_handles_bare_host_with_port_and_path() {
        assert_eq!(host_of("Example.COM"), Some("example.com".to_string()));
        assert_eq!(
            host_of("example.com:443/foo"),
            Some("example.com".to_string())
        );
        assert_eq!(
            host_of("user@mail.example.org"),
            Some("mail.example.org".to_string())
        );
    }

    #[test]
    fn host_of_empty_is_none() {
        assert_eq!(host_of(""), None);
        assert_eq!(host_of("   "), None);
    }

    #[test]
    fn registrable_domain_two_labels() {
        assert_eq!(
            registrable_domain("google.com"),
            Some("google.com".to_string())
        );
        assert_eq!(
            registrable_domain("www.google.com"),
            Some("google.com".to_string())
        );
        assert_eq!(
            registrable_domain("a.b.c.google.com"),
            Some("google.com".to_string())
        );
    }

    #[test]
    fn registrable_domain_two_level_cctld() {
        assert_eq!(
            registrable_domain("bbc.co.uk"),
            Some("bbc.co.uk".to_string())
        );
        assert_eq!(
            registrable_domain("x.y.bbc.co.uk"),
            Some("bbc.co.uk".to_string())
        );
        assert_eq!(
            registrable_domain("shop.example.com.au"),
            Some("example.com.au".to_string())
        );
    }

    #[test]
    fn registrable_domain_single_label_and_ip() {
        assert_eq!(
            registrable_domain("localhost"),
            Some("localhost".to_string())
        );
        assert_eq!(
            registrable_domain("127.0.0.1"),
            Some("127.0.0.1".to_string())
        );
        assert_eq!(registrable_domain("::1"), Some("::1".to_string()));
        assert_eq!(registrable_domain(""), None);
    }

    fn ev_with(attrs: &[(&str, serde_json::Value)]) -> BrowserEvent {
        let mut e = BrowserEvent::new(
            1_000,
            BrowserFamily::Chromium,
            ArtifactKind::History,
            "/src",
            "desc",
        );
        for (k, v) in attrs {
            e = e.with_attr(*k, v.clone());
        }
        e
    }

    #[test]
    fn event_registrable_domains_collects_url_and_bare_fields() {
        let e = ev_with(&[
            ("url", json!("https://www.google.com/search")),
            ("referrer_url", json!("https://mail.google.com/")),
            ("host", json!("cdn.example.co.uk")),
        ]);
        let mut got = event_registrable_domains(&e);
        got.sort();
        assert_eq!(
            got,
            vec!["example.co.uk".to_string(), "google.com".to_string()]
        );
    }

    #[test]
    fn primary_registrable_domain_prefers_url() {
        let e = ev_with(&[
            ("host", json!("other.example.org")),
            ("url", json!("https://sub.primary.com/x")),
        ]);
        assert_eq!(
            primary_registrable_domain(&e),
            Some("primary.com".to_string())
        );
    }

    #[test]
    fn primary_registrable_domain_none_when_no_host_fields() {
        let e = ev_with(&[("note", json!("no host here"))]);
        assert_eq!(primary_registrable_domain(&e), None);
    }
}
