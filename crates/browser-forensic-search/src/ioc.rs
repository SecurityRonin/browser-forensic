//! Entity / indicator-of-compromise extraction over browser events.
//!
//! Every match this module reports is a **candidate**: a string whose shape
//! (and, where a cheap oracle exists, whose checksum) matches an entity class.
//! A match is never an assertion that the value *is* a real email address,
//! wallet, card, or address in use — only that it looks like one. Callers must
//! preserve that framing when presenting results.
//!
//! Extractors run over each event's textual surface ([`text_fields`]), and each
//! field is char-safely length-bounded before scanning so an oversized value
//! cannot dominate a run.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use browser_forensic_core::BrowserEvent;
use linkify::{LinkFinder, LinkKind};
use regex::Regex;
use serde::Serialize;

use crate::filter::{bound, text_fields};

/// The class of a candidate entity match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    /// An RFC-5321-shaped email address.
    Email,
    /// A syntactically valid IPv4 address.
    Ipv4,
    /// A syntactically valid IPv6 address.
    Ipv6,
    /// A Base58Check-shaped, checksum-valid Bitcoin address candidate.
    BitcoinBase58,
    /// A Bech32/Bech32m-shaped, checksum-valid Bitcoin (segwit) address candidate.
    BitcoinBech32,
    /// An Ethereum-address-shaped candidate (`0x` + 40 hex).
    Ethereum,
    /// A credit-card-shaped, Luhn-valid digit run.
    CreditCard,
    /// A search term read from a URL's query parameters.
    SearchTerm,
}

impl IocKind {
    /// A short, stable label for text/CSV output.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::BitcoinBase58 => "btc_base58",
            Self::BitcoinBech32 => "btc_bech32",
            Self::Ethereum => "eth",
            Self::CreditCard => "credit_card_candidate",
            Self::SearchTerm => "search_term",
        }
    }
}

/// One candidate entity located in an event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IocMatch {
    /// The entity class.
    pub kind: IocKind,
    /// The matched value (verbatim; never truncated).
    pub value: String,
    /// Index of the source event in the slice passed to [`extract_iocs`].
    pub event_index: usize,
    /// The field the value was found in (`url`, `title`, `description`, …).
    pub field: String,
    /// Byte offset of the value within that (length-bounded) field.
    pub offset: usize,
    /// An honesty qualifier: `Luhn-valid`, `checksum-valid`, the search engine,
    /// or an EIP-55 note. `None` when the class needs none.
    pub note: Option<String>,
}

/// A single extracted candidate within one text field, before it is attributed
/// to an event: `(kind, value, byte offset, note)`.
pub type TextHit = (IocKind, String, usize, Option<String>);

/// Extract every candidate entity from all events, attributing each to its
/// source event and field. Results are in `(event, field, offset)` order.
#[must_use]
pub fn extract_iocs(events: &[BrowserEvent]) -> Vec<IocMatch> {
    let mut out = Vec::new();
    for (event_index, event) in events.iter().enumerate() {
        for (field, text) in text_fields(event) {
            let bounded = bound(text);
            for (kind, value, offset, note) in extract_from_text(bounded) {
                out.push(IocMatch {
                    kind,
                    value,
                    event_index,
                    field: field.to_string(),
                    offset,
                    note,
                });
            }
        }
    }
    out
}

/// Extract every candidate entity from a single text run.
///
/// The caller is responsible for length-bounding `text`; [`extract_iocs`] does
/// so via [`crate::filter::bound`].
#[must_use]
pub fn extract_from_text(text: &str) -> Vec<TextHit> {
    let mut out = Vec::new();
    extract_emails(text, &mut out);
    extract_ipv4(text, &mut out);
    extract_ipv6(text, &mut out);
    out.sort_by_key(|(_, _, offset, _)| *offset);
    out
}

/// RFC-5321-shaped email addresses, found with `linkify`'s boundary-aware
/// scanner (which correctly excludes trailing punctuation).
fn extract_emails(text: &str, out: &mut Vec<TextHit>) {
    let mut finder = LinkFinder::new();
    finder.kinds(&[LinkKind::Email]);
    for link in finder.links(text) {
        out.push((
            IocKind::Email,
            link.as_str().to_string(),
            link.start(),
            None,
        ));
    }
}

/// Lazily compile a constant pattern into a process-wide cache. The patterns in
/// this module are compile-time constants known to be valid; a compilation
/// failure (which cannot occur) degrades to "no matches", never a panic.
fn cached_regex(cell: &'static OnceLock<Option<Regex>>, pattern: &str) -> Option<&'static Regex> {
    cell.get_or_init(|| Regex::new(pattern).ok()).as_ref()
}

/// IPv4 candidates: a dotted-quad *shape* whose octets are then validated by the
/// std [`Ipv4Addr`] parser (the oracle), so out-of-range octets are rejected.
fn extract_ipv4(text: &str, out: &mut Vec<TextHit>) {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    let Some(re) = cached_regex(&RE, r"\b\d{1,3}(?:\.\d{1,3}){3}\b") else {
        return;
    };
    for m in re.find_iter(text) {
        if m.as_str().parse::<Ipv4Addr>().is_ok() {
            out.push((IocKind::Ipv4, m.as_str().to_string(), m.start(), None));
        }
    }
}

/// IPv6 candidates: runs of hex groups joined by two or more colons, validated
/// by the std [`Ipv6Addr`] parser. A run that is not a syntactically valid IPv6
/// (e.g. a MAC address or an `HH:MM:SS` time) is rejected by the parser.
fn extract_ipv6(text: &str, out: &mut Vec<TextHit>) {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    let Some(re) = cached_regex(&RE, r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,}") else {
        return;
    };
    for m in re.find_iter(text) {
        if m.as_str().parse::<Ipv6Addr>().is_ok() {
            out.push((IocKind::Ipv6, m.as_str().to_string(), m.start(), None));
        }
    }
}
