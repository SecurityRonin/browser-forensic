#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Interpretation plugins for browser artifacts — a clean-room reimplementation
//! of the Hindsight (`obsidianforensics/hindsight`) interpretation plugins.
//!
//! Two entry points turn a raw artifact value into a human-readable
//! *interpretation* string:
//!
//! - [`interpret_url`] — Google search-term extraction, then a generic
//!   query-string fallback.
//! - [`interpret_cookie`] — Google Analytics / Quantcast / F5 BIG-IP load-balancer
//!   decoding, then a generic embedded-timestamp scan.
//!
//! All timestamps funnel through [`friendly_date`], which replicates Hindsight's
//! magnitude-based `to_datetime` ladder: the *units* of an integer timestamp
//! (Unix seconds / millis / micros, or WebKit micros/millis/seconds) are inferred
//! from its magnitude, not declared by the caller.

use url::Url;

/// WebKit/Chrome epoch (1601-01-01) offset from the Unix epoch, in seconds.
const WEBKIT_UNIX_OFFSET_SECS: i64 = 11_644_473_600;
const WEBKIT_UNIX_OFFSET_MS: i64 = WEBKIT_UNIX_OFFSET_SECS * 1_000;

/// Convert a raw integer timestamp to Unix milliseconds, inferring units from
/// magnitude. Mirrors Hindsight's `to_datetime` ladder (`pyhindsight/utils.py`).
/// Returns `None` for values outside the representable range.
fn to_datetime_millis(ts: i64) -> Option<i64> {
    // Boundaries and branch order match Hindsight exactly.
    if ts >= 253_402_300_800_000_000 {
        None // datetime.max sentinel — treat as out of range
    } else if ts > 13_700_000_000_000_000 || ts > 12_000_000_000_000_000 {
        Some(ts / 1_000 - WEBKIT_UNIX_OFFSET_MS) // WebKit micros
    } else if ts > 1_280_000_000_000_000 && ts < 2_500_000_000_000_000 {
        Some(ts / 1_000) // Unix micros
    } else if ts > 1_280_000_000_000 && ts < 2_500_000_000_000 {
        Some(ts) // Unix millis
    } else if ts > 12_906_777_600_000 && ts < 15_000_000_000_000 {
        Some(ts - WEBKIT_UNIX_OFFSET_MS) // WebKit millis
    } else if (12_900_000_000..15_000_000_000).contains(&ts) {
        Some((ts - WEBKIT_UNIX_OFFSET_SECS) * 1_000) // WebKit seconds
    } else if ts > 0 {
        Some(ts * 1_000) // Unix seconds
    } else {
        None
    }
}

/// Render a raw integer timestamp as `YYYY-MM-DD HH:MM:SS.mmm` in UTC.
///
/// Units are inferred from the integer's magnitude, matching Hindsight's
/// `to_datetime` ladder. Returns `None` for values outside the representable
/// range.
#[must_use]
pub fn friendly_date(raw_ts: i64) -> Option<String> {
    let ms = to_datetime_millis(raw_ts)?;
    let dt = chrono::DateTime::from_timestamp_millis(ms)?;
    Some(dt.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
}

/// Interpret a URL: Google search terms first, generic query-string fallback.
#[must_use]
pub fn interpret_url(url: &str) -> Option<String> {
    google_searches(url).or_else(|| query_string(url))
}

/// A search-engine query recovered from a URL's parameters.
///
/// `engine` names the recognised provider (`"Google"`, `"Bing"`,
/// `"DuckDuckGo"`, `"YouTube"`, `"Amazon"`) or `"Generic"` when the host is
/// unknown but a well-known search parameter (`q`/`p`/`query`/`search`) carries
/// a term. The `term` is the percent-decoded, `+`→space value of that
/// parameter. This is a *fact* read out of the URL, not an inference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchQuery {
    /// Recognised search provider, or `"Generic"`.
    pub engine: String,
    /// The decoded search term.
    pub term: String,
}

/// Extract a search term from a URL by matching known search-engine hosts and
/// their query parameters, falling back to generic `q`/`p`/`query`/`search`
/// parameters on any host. Returns `None` when no search parameter is present.
///
/// Extends [`interpret_url`]'s Google-only search-term logic to Bing,
/// DuckDuckGo, YouTube, and Amazon, and exposes the raw term (rather than a
/// prose interpretation) for downstream entity extraction.
#[must_use]
pub fn search_query(_url: &str) -> Option<SearchQuery> {
    // GREEN cycle replaces this stub with the multi-engine implementation.
    None
}

/// Interpret a cookie `(name, value)`: GA / Quantcast / BIG-IP, then a generic
/// embedded-timestamp scan.
#[must_use]
pub fn interpret_cookie(name: &str, value: &str) -> Option<String> {
    google_analytics(name, value)
        .or_else(|| quantcast(name, value))
        .or_else(|| load_balancer(value))
        .or_else(|| generic_timestamp(value))
}

// ---------------------------------------------------------------------------
// google_searches
// ---------------------------------------------------------------------------

/// Collect all `(key, value)` query pairs (percent-decoded, `+`→space) from the
/// URL's query string and, if present, a `k=v`-shaped fragment (`#q=...`).
fn collect_pairs(u: &Url) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = u
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    if let Some(frag) = u.fragment() {
        for (k, v) in url::form_urlencoded::parse(frag.as_bytes()) {
            pairs.push((k.into_owned(), v.into_owned()));
        }
    }
    pairs
}

fn first<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

const ORDINALS: [&str; 10] = [
    "zeroth", "first", "second", "third", "fourth", "fifth", "sixth", "seventh", "eighth", "ninth",
];

fn as_qdr_fragment(val: &str) -> Option<String> {
    let mut chars = val.chars();
    let unit = match chars.next()? {
        's' => "second",
        'n' => "minute",
        'h' => "hour",
        'd' => "day",
        'w' => "week",
        'm' => "month",
        'y' => "year",
        _ => return None,
    };
    let digits: String = chars.take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        Some(format!("Results in the past {unit}"))
    } else {
        Some(format!("Results in the past {digits} {unit}s"))
    }
}

fn tbs_fragment(val: &str) -> Option<String> {
    if let Some(rest) = val.strip_prefix("qdr:") {
        return as_qdr_fragment(rest);
    }
    if let Some(rest) = val.strip_prefix("cdr:1,") {
        // cd_min:MM/DD/YYYY,cd_max:MM/DD/YYYY
        let mut min = "";
        let mut max = "";
        for part in rest.split(',') {
            if let Some(v) = part.strip_prefix("cd_min:") {
                min = v;
            } else if let Some(v) = part.strip_prefix("cd_max:") {
                max = v;
            }
        }
        return Some(format!("Results in custom range {min} - {max}"));
    }
    let label = match val {
        "dfn:1" | "dfn" => "Dictionary definition",
        "img" => "Sites with images",
        "clir:1" | "clir" => "Translated sites",
        "li:1" | "li" => "Verbatim results",
        "vid:1" | "vid" => "Video results",
        "nws:1" | "nws" => "News results",
        "sbd:1" | "sbd" => "Sorted by date",
        _ => return None,
    };
    Some(label.to_string())
}

#[allow(clippy::too_many_lines)]
fn google_searches(url: &str) -> Option<String> {
    let u = Url::parse(url).ok()?;
    let host = u.host_str()?;
    if host != "www.google" && !host.starts_with("www.google.") {
        return None;
    }
    let path = u.path();
    let frag_is_q = u
        .fragment()
        .is_some_and(|f| f.starts_with("q=") || f == "q");
    if path != "/search" && path != "/webhp" && !frag_is_q {
        return None;
    }

    let pairs = collect_pairs(&u);
    let q = first(&pairs, "q")?;
    let base = format!("Searched for \"{q}\"");

    let mut extras: Vec<String> = Vec::new();
    if let Some(v) = first(&pairs, "pws") {
        extras.push(format!(
            "Google personalization turned {}",
            if v == "1" { "on" } else { "off" }
        ));
    }
    if let Some(v) = first(&pairs, "num") {
        extras.push(format!("Showing {v} results per page"));
    }
    if let Some(v) = first(&pairs, "filter") {
        extras.push(format!(
            "{} results filter on",
            if v == "1" { "Omitted" } else { "Similar" }
        ));
    }
    if let Some(v) = first(&pairs, "btnl") {
        extras.push(format!(
            "\"I'm Feeling Lucky\" search {}",
            if v == "1" { "on" } else { "off" }
        ));
    }
    if let Some(v) = first(&pairs, "safe") {
        extras.push(format!("SafeSearch: {v}"));
    }
    if let Some(v) = first(&pairs, "as_qdr") {
        if let Some(frag) = as_qdr_fragment(v) {
            extras.push(frag);
        }
    }
    if let Some(v) = first(&pairs, "tbs") {
        if let Some(frag) = tbs_fragment(v) {
            extras.push(frag);
        }
    }
    if let (Some(biw), Some(bih)) = (first(&pairs, "biw"), first(&pairs, "bih")) {
        extras.push(format!("Browser screen {biw}x{bih}"));
    }
    if let Some(pq) = first(&pairs, "pq") {
        if pq != q {
            extras.push(format!("Previous query: \"{pq}\""));
        }
    }
    if let Some(oq) = first(&pairs, "oq") {
        if oq != q {
            match first(&pairs, "aq").and_then(|aq| aq.parse::<usize>().ok()) {
                Some(idx) if idx < ORDINALS.len() => extras.push(format!(
                    "Typed \"{oq}\" before clicking on the {} suggestion",
                    ORDINALS[idx]
                )),
                _ => extras.push(format!("Typed \"{oq}\" before clicking on a suggestion")),
            }
        }
    }
    if let Some(v) = first(&pairs, "as_sitesearch") {
        extras.push(format!("Search only {v}"));
    }
    if let Some(v) = first(&pairs, "as_filetype") {
        extras.push(format!("Show only {v} files"));
    }
    if let Some(v) = first(&pairs, "sourceid") {
        extras.push(format!("Using {v}"));
    }

    if extras.is_empty() {
        Some(base)
    } else {
        Some(format!("{base} [ {}]", extras.join(" | ")))
    }
}

// ---------------------------------------------------------------------------
// query_string_parser (fallback)
// ---------------------------------------------------------------------------

fn query_string(url: &str) -> Option<String> {
    let u = Url::parse(url).ok()?;
    let query = u.query()?;
    if query.is_empty() {
        return None;
    }
    let mut seen: Vec<String> = Vec::new();
    let mut out: Vec<String> = Vec::new();
    // parse_qs splits on both `&` and `;`.
    for part in query.split(['&', ';']) {
        if let Some((k, v)) = url::form_urlencoded::parse(part.as_bytes()).next() {
            if k.is_empty() || v.is_empty() || seen.iter().any(|s| s == k.as_ref()) {
                continue;
            }
            seen.push(k.clone().into_owned());
            out.push(format!("{k}: {v}"));
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(format!("{} [Query String Parser]", out.join(" | ")))
    }
}

// ---------------------------------------------------------------------------
// google_analytics
// ---------------------------------------------------------------------------

const GA_TAG: &str = "[Google Analytics Cookie]";

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn ga_time(part: &str) -> Option<String> {
    if part.len() == 10 && all_digits(part) {
        friendly_date(part.parse::<i64>().ok()?)
    } else {
        None
    }
}

fn google_analytics(name: &str, value: &str) -> Option<String> {
    match name {
        "__utma" => {
            // domainHash.visitorId.firstVisit.previousVisit.lastVisit.sessions
            let p: Vec<&str> = value.split('.').collect();
            if p.len() < 6 {
                return None;
            }
            let first = ga_time(p[2])?;
            let prev = ga_time(p[3])?;
            let last = ga_time(p[4])?;
            Some(format!(
                "Domain Hash: {} | Unique Visitor ID: {} | First Visit: {first} | \
                 Previous Visit: {prev} | Last Visit: {last} | Number of Sessions: {} | {GA_TAG}",
                p[0], p[1], p[5]
            ))
        }
        "__utmb" => {
            // domainHash.pagesViewed.<ignored>.lastVisit
            let p: Vec<&str> = value.split('.').collect();
            if p.len() < 4 {
                return None;
            }
            let last = ga_time(p[3])?;
            Some(format!(
                "Domain Hash: {} | Pages Viewed: {} | Last Visit: {last} | {GA_TAG}",
                p[0], p[1]
            ))
        }
        "__utmc" => {
            if all_digits(value) {
                Some(format!("Domain Hash: {value} | {GA_TAG}"))
            } else {
                None
            }
        }
        "__utmv" => {
            let (hash, custom) = value.split_once('.')?;
            let custom = custom.strip_prefix('|').unwrap_or(custom);
            Some(format!(
                "Domain Hash: {hash} | Custom Values: {custom} | {GA_TAG}"
            ))
        }
        "__utmz" => utmz(value),
        "_ga" => {
            // GA1.<scope>.<clientIdA>.<clientIdB(10-digit)>
            let p: Vec<&str> = value.split('.').collect();
            if p.len() < 4 || p[0] != "GA1" {
                return None;
            }
            let client_b = p[3];
            let first = ga_time(client_b)?;
            Some(format!(
                "Client ID: {}.{} | First Visit: {first} | {GA_TAG}",
                p[2], client_b
            ))
        }
        _ => None,
    }
}

fn utmz(value: &str) -> Option<String> {
    // domainHash.lastVisit.sessions.sources.<campaign blob>
    let p: Vec<&str> = value.splitn(5, '.').collect();
    if p.len() < 4 {
        return None;
    }
    let last = ga_time(p[1])?;
    let mut out = format!(
        "Domain Hash: {} | Last Visit: {last} | Sessions: {} | Sources: {} | ",
        p[0], p[2], p[3]
    );
    if let Some(blob) = p.get(4) {
        // strip a leading "utm", then split fragments on "|utm"
        let blob = blob.strip_prefix("utm").unwrap_or(blob);
        let mut csr = "";
        let mut cmd = "";
        let mut ccn = "";
        let mut ctr = "";
        let mut cct = "";
        for frag in blob.split("|utm") {
            if let Some((k, v)) = frag.split_once('=') {
                match k {
                    "csr" => csr = v,
                    "cmd" => cmd = v,
                    "ccn" => ccn = v,
                    "ctr" => ctr = v,
                    "cct" => cct = v,
                    _ => {}
                }
            }
        }
        match cmd {
            "referral" => {
                out.push_str(&format!("Referrer: {csr}{cct}"));
                if ccn != "(referral)" && !ccn.is_empty() {
                    out.push_str(&format!(" | Ad Campaign Info: {ccn}"));
                }
            }
            "organic" => {
                out.push_str("Last Type of Access: organic");
                if !ctr.is_empty() {
                    out.push_str(&format!(" | Search keywords: {ctr}"));
                }
            }
            "" => {
                let mut bits = Vec::new();
                if !csr.is_empty() {
                    bits.push(format!("Last Source Site: {csr}"));
                }
                if !ccn.is_empty() {
                    bits.push(format!("Ad Campaign Info: {ccn}"));
                }
                if !ctr.is_empty() {
                    bits.push(format!("Keyword(s) from Search that Found Site: {ctr}"));
                }
                if !cct.is_empty() {
                    bits.push(format!(
                        "Path to the page on the site of the referring link: {cct}"
                    ));
                }
                out.push_str(&bits.join(" | "));
            }
            _ => {
                out.push_str(&format!("Last Type of Access: {ccn}"));
                if !ctr.is_empty() {
                    out.push_str(&format!(" | Search keywords: {ctr}"));
                }
            }
        }
    }
    out.push_str(&format!(" {GA_TAG}"));
    Some(out)
}

// ---------------------------------------------------------------------------
// quantcast (__qca)
// ---------------------------------------------------------------------------

fn quantcast(name: &str, value: &str) -> Option<String> {
    if name != "__qca" {
        return None;
    }
    // P0-<id>-<timestamp 10..13 digits>
    let p: Vec<&str> = value.split('-').collect();
    if p.len() != 3 || p[0] != "P0" || !all_digits(p[1]) {
        return None;
    }
    let ts = p[2];
    if !(10..=13).contains(&ts.len()) || !all_digits(ts) {
        return None;
    }
    let when = friendly_date(ts.parse::<i64>().ok()?)?;
    Some(format!("{when} [Quantcast Cookie Timestamp]"))
}

// ---------------------------------------------------------------------------
// load_balancer (F5 BIG-IP)
// ---------------------------------------------------------------------------

fn load_balancer(value: &str) -> Option<String> {
    // <host 8..10 digits>.<port 1..5 digits>.<0000>
    let p: Vec<&str> = value.split('.').collect();
    if p.len() != 3 {
        return None;
    }
    let (host_s, port_s, tail) = (p[0], p[1], p[2]);
    let well_formed = (8..=10).contains(&host_s.len())
        && all_digits(host_s)
        && (1..=5).contains(&port_s.len())
        && all_digits(port_s)
        && tail.len() == 4
        && all_digits(tail);
    if !well_formed {
        return None;
    }
    // host is a little-endian uint32 IP; octets are the packed bytes in order.
    let host: u32 = host_s.parse().ok()?;
    let ip = format!(
        "{}.{}.{}.{}",
        host & 0xFF,
        (host >> 8) & 0xFF,
        (host >> 16) & 0xFF,
        (host >> 24) & 0xFF
    );
    // port is a little-endian uint16 reassembled big-endian == a byte swap.
    let port: u16 = port_s.parse().ok()?;
    let port = ((port & 0xFF) << 8) | (port >> 8);
    Some(format!(
        "Server IP: {ip} | Server Port: {port} [BIG-IP Cookie]"
    ))
}

// ---------------------------------------------------------------------------
// generic_timestamps
// ---------------------------------------------------------------------------

fn generic_timestamp(value: &str) -> Option<String> {
    // Whole-value: starts with '1', all digits, length 10/13/17.
    if value.starts_with('1') && all_digits(value) && matches!(value.len(), 10 | 13 | 17) {
        let when = friendly_date(value.parse::<i64>().ok()?)?;
        return Some(format!("{when} [potential timestamp]"));
    }
    // Embedded: the literal "timestamp" followed by a 10..17 digit run.
    if let Some(idx) = value.find("timestamp") {
        let bytes = value.as_bytes();
        let mut i = idx + "timestamp".len();
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let run = &value[start..i];
                if (10..=17).contains(&run.len()) {
                    let when = friendly_date(run.parse::<i64>().ok()?)?;
                    return Some(format!("{when} [potential timestamp]"));
                }
            } else {
                i += 1;
            }
        }
    }
    None
}
