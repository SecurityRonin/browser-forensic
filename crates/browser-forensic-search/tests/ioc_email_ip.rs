//! Email and IPv4/IPv6 candidate extraction. IP validity is decided by the std
//! `Ipv4Addr`/`Ipv6Addr` parsers (the oracle), so out-of-range octets are
//! rejected. Emails come from the `linkify` boundary-aware finder.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use browser_forensic_search::ioc::{extract_from_text, IocKind};
use browser_forensic_search::{extract_iocs, IocMatch};
use serde_json::json;

fn kinds(text: &str) -> Vec<(IocKind, String)> {
    extract_from_text(text)
        .into_iter()
        .map(|(k, v, _off, _note)| (k, v))
        .collect()
}

fn has(text: &str, kind: IocKind, value: &str) -> bool {
    kinds(text).iter().any(|(k, v)| *k == kind && v == value)
}

#[test]
fn extracts_simple_email() {
    assert!(has(
        "contact alice@example.com now",
        IocKind::Email,
        "alice@example.com"
    ));
}

#[test]
fn extracts_plus_and_subdomain_email() {
    assert!(has(
        "to bob.smith+tag@sub.example.co.uk please",
        IocKind::Email,
        "bob.smith+tag@sub.example.co.uk"
    ));
}

#[test]
fn extracts_ipv4() {
    assert!(has("host 192.168.1.1 up", IocKind::Ipv4, "192.168.1.1"));
    assert!(has("dns 8.8.8.8", IocKind::Ipv4, "8.8.8.8"));
}

#[test]
fn rejects_out_of_range_ipv4() {
    // 999 and 256 are not valid octets; the std parser rejects them.
    let found = kinds("bad 999.1.1.1 and 256.256.256.256");
    assert!(
        !found.iter().any(|(k, _)| *k == IocKind::Ipv4),
        "no valid IPv4 should be found, got {found:?}"
    );
}

#[test]
fn extracts_ipv6() {
    assert!(has("addr 2001:db8::1 seen", IocKind::Ipv6, "2001:db8::1"));
    assert!(has("loopback ::1 here", IocKind::Ipv6, "::1"));
    assert!(has(
        "link fe80::1ff:fe23:4567:890a end",
        IocKind::Ipv6,
        "fe80::1ff:fe23:4567:890a"
    ));
}

#[test]
fn offset_points_at_value() {
    let text = "xx 8.8.8.8";
    let hit = extract_from_text(text)
        .into_iter()
        .find(|(k, _, _, _)| *k == IocKind::Ipv4)
        .expect("ipv4");
    let (_, value, offset, _) = hit;
    assert_eq!(&text[offset..offset + value.len()], "8.8.8.8");
    assert_eq!(offset, 3);
}

#[test]
fn aggregator_attributes_event_and_field() {
    let events = vec![
        BrowserEvent::new(
            1,
            BrowserFamily::Chromium,
            ArtifactKind::Autofill,
            "/Web Data",
            "autofill value",
        )
        .with_attr("value", json!("alice@example.com")),
        BrowserEvent::new(
            2,
            BrowserFamily::Chromium,
            ArtifactKind::History,
            "/History",
            "visited",
        )
        .with_attr("url", json!("http://8.8.8.8/path")),
    ];
    let iocs: Vec<IocMatch> = extract_iocs(&events);

    let email = iocs
        .iter()
        .find(|m| m.kind == IocKind::Email)
        .expect("email match");
    assert_eq!(email.value, "alice@example.com");
    assert_eq!(email.event_index, 0);
    assert_eq!(email.field, "value");

    let ip = iocs
        .iter()
        .find(|m| m.kind == IocKind::Ipv4)
        .expect("ipv4 match");
    assert_eq!(ip.value, "8.8.8.8");
    assert_eq!(ip.event_index, 1);
    assert_eq!(ip.field, "url");
}

#[test]
fn plain_text_has_no_false_iocs() {
    assert!(kinds("the quick brown fox jumps over the lazy dog").is_empty());
}
