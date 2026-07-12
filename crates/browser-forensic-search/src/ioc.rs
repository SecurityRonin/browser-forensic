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
use sha2::{Digest, Sha256};

use crate::filter::{bound, text_fields};

/// The Bitcoin base58 alphabet (no `0`, `O`, `I`, `l`).
const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

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
    extract_credit_cards(text, &mut out);
    extract_btc_base58(text, &mut out);
    extract_btc_bech32(text, &mut out);
    extract_eth(text, &mut out);
    extract_search_terms(text, &mut out);
    out.sort_by_key(|(_, _, offset, _)| *offset);
    out
}

/// Search terms read from URL query parameters. Every URL in the text (bare or
/// embedded) is passed to browser-forensic-interpret's `search_query`; a hit
/// yields the decoded term as the value and the engine name as the note. This
/// is a fact read from the URL, not an inference.
fn extract_search_terms(text: &str, out: &mut Vec<TextHit>) {
    let mut finder = LinkFinder::new();
    finder.kinds(&[LinkKind::Url]);
    for link in finder.links(text) {
        if let Some(sq) = browser_forensic_interpret::search_query(link.as_str()) {
            out.push((IocKind::SearchTerm, sq.term, link.start(), Some(sq.engine)));
        }
    }
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

/// Credit-card candidates: contiguous 13–19 digit runs that pass the Luhn
/// checksum. Grouped forms (spaces/dashes between digit groups) are not matched
/// — a known, documented limitation. A Luhn-valid run is only a *candidate*; a
/// non-card identifier can be Luhn-valid by chance.
fn extract_credit_cards(text: &str, out: &mut Vec<TextHit>) {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    let Some(re) = cached_regex(&RE, r"\b\d{13,19}\b") else {
        return;
    };
    for m in re.find_iter(text) {
        if luhn_valid(m.as_str()) {
            out.push((
                IocKind::CreditCard,
                m.as_str().to_string(),
                m.start(),
                Some("Luhn-valid".to_string()),
            ));
        }
    }
}

/// The Luhn checksum over a string of ASCII digits.
fn luhn_valid(digits: &str) -> bool {
    let mut sum: u32 = 0;
    let mut double = false;
    for c in digits.bytes().rev() {
        if !c.is_ascii_digit() {
            return false;
        }
        let mut d = u32::from(c - b'0');
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }
    sum % 10 == 0
}

/// Bitcoin base58check address candidates (P2PKH `1…` / P2SH `3…`). The shape is
/// matched, then base58-decoded and the 4-byte double-SHA256 checksum verified
/// (an independent oracle) — only checksum-valid strings are reported.
fn extract_btc_base58(text: &str, out: &mut Vec<TextHit>) {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    let Some(re) = cached_regex(&RE, r"\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b") else {
        return;
    };
    for m in re.find_iter(text) {
        if base58check_valid(m.as_str()) {
            out.push((
                IocKind::BitcoinBase58,
                m.as_str().to_string(),
                m.start(),
                Some("checksum-valid".to_string()),
            ));
        }
    }
}

/// Decode a base58 string and verify it is a well-formed 25-byte base58check
/// payload (`version || 20-byte hash || 4-byte checksum`).
fn base58check_valid(s: &str) -> bool {
    let Some(bytes) = base58_decode(s) else {
        return false;
    };
    if bytes.len() != 25 {
        return false;
    }
    let (payload, checksum) = bytes.split_at(21);
    let digest = double_sha256(payload);
    digest[..4] == *checksum
}

/// Big-endian base58 decode. Returns `None` on any character outside the
/// alphabet. Leading `1`s map to leading zero bytes.
fn base58_decode(s: &str) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = vec![0];
    for c in s.bytes() {
        let val = BASE58.iter().position(|&b| b == c)?;
        let mut carry = val;
        for byte in &mut bytes {
            carry += usize::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    for c in s.bytes() {
        if c == b'1' {
            bytes.push(0);
        } else {
            break;
        }
    }
    bytes.reverse();
    Some(bytes)
}

/// Double SHA-256, using the audited `sha2` crate (never a hand-rolled hash).
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

/// Bitcoin bech32/bech32m (segwit) address candidates (`bc1…` / `tb1…`). The
/// `bech32` crate validates the HRP, witness version, and BCH checksum — only
/// fully valid segwit addresses on the mainnet/testnet HRPs are reported.
fn extract_btc_bech32(text: &str, out: &mut Vec<TextHit>) {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    let Some(re) = cached_regex(
        &RE,
        r"\b(?:bc|tb)1[023456789acdefghjklmnpqrstuvwxyz]{6,87}\b",
    ) else {
        return;
    };
    for m in re.find_iter(text) {
        if let Ok((hrp, _version, _program)) = bech32::segwit::decode(m.as_str()) {
            if hrp.to_string() == "bc" || hrp.to_string() == "tb" {
                out.push((
                    IocKind::BitcoinBech32,
                    m.as_str().to_string(),
                    m.start(),
                    Some("checksum-valid".to_string()),
                ));
            }
        }
    }
}

/// Ethereum-address-shaped candidates (`0x` + 40 hex). The note records whether
/// an EIP-55 mixed-case checksum is present; it is *not* verified here (that
/// would require keccak256). All-one-case addresses carry no case checksum.
fn extract_eth(text: &str, out: &mut Vec<TextHit>) {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    let Some(re) = cached_regex(&RE, r"\b0x[0-9a-fA-F]{40}\b") else {
        return;
    };
    for m in re.find_iter(text) {
        let hex = &m.as_str()[2..];
        let has_upper = hex.bytes().any(|b| b.is_ascii_uppercase());
        let has_lower = hex.bytes().any(|b| b.is_ascii_lowercase());
        let note = if has_upper && has_lower {
            "EIP-55 mixed-case checksum present (unverified)"
        } else {
            "all one case, no case checksum"
        };
        out.push((
            IocKind::Ethereum,
            m.as_str().to_string(),
            m.start(),
            Some(note.to_string()),
        ));
    }
}
