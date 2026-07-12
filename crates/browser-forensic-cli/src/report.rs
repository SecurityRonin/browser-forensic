//! DFIR-interop serializers over the collected `BrowserEvent` stream: TSK
//! bodyfile (mactime), plaso / log2timeline `l2t_csv`, and a self-contained,
//! court-presentable HTML report.
//!
//! These are new *serializers* over the events already gathered by
//! `browser_forensic_triage`; they collect nothing of their own. Machine
//! formats (bodyfile, `l2t_csv`) stay faithful and round-trippable; the HTML
//! report is a human view with every value HTML-escaped and shown in full.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use browser_forensic_core::{ArtifactKind, BrowserEvent};
use chrono_tz::Tz;
use clap::ValueEnum;
use serde_json::Value;

/// Output format for `br4n6 report`.
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum ReportFormat {
    /// TSK bodyfile (mactime 3.x) for `mactime`/`log2timeline`.
    Bodyfile,
    /// plaso / log2timeline `l2t_csv`.
    L2t,
    /// A self-contained, court-presentable HTML report.
    Html,
}

/// Which MAC slot a browser event's single timestamp represents. A
/// `BrowserEvent` carries exactly one time; its meaning is fixed by the
/// artifact kind (a history row's time is a visit/access, a download's is a
/// creation/birth), so the slot is derived from the artifact — not guessed per
/// record.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Macb {
    Modify,
    Access,
    Birth,
}

impl Macb {
    /// The l2t_csv `MACB` group string (M A C B, dot for an inactive slot).
    /// The metadata-change (C) slot is never active for browser artifacts.
    fn letters(self) -> &'static str {
        match self {
            Self::Modify => "M...",
            Self::Access => ".A..",
            Self::Birth => "...B",
        }
    }
}

/// Map an artifact kind to (which MAC slot its timestamp fills, a human label
/// for that time). This is the single structural rule both machine serializers
/// share; adding an artifact kind forces a choice here.
// One arm per variant (not `A | B =>`) is deliberate: a new `ArtifactKind` must
// pick its slot/label explicitly, even where the result coincides with another.
#[allow(clippy::match_same_arms)]
fn timestamp_semantic(kind: &ArtifactKind) -> (Macb, &'static str) {
    match kind {
        ArtifactKind::History => (Macb::Access, "Last Visited Time"),
        ArtifactKind::Downloads => (Macb::Birth, "Download Started Time"),
        ArtifactKind::Cookies => (Macb::Access, "Last Access Time"),
        ArtifactKind::Bookmarks => (Macb::Birth, "Added Time"),
        ArtifactKind::Cache => (Macb::Access, "Last Access Time"),
        ArtifactKind::Extensions => (Macb::Birth, "Install Time"),
        ArtifactKind::Autofill => (Macb::Access, "Last Used Time"),
        ArtifactKind::Session => (Macb::Modify, "Last Modified Time"),
        ArtifactKind::LoginData => (Macb::Access, "Last Used Time"),
        ArtifactKind::Preferences => (Macb::Modify, "Modified Time"),
        ArtifactKind::LocalStorage => (Macb::Modify, "Modified Time"),
        ArtifactKind::Integrity => (Macb::Modify, "Event Time"),
        ArtifactKind::Carved => (Macb::Modify, "Recovered Record Time"),
        ArtifactKind::Memory => (Macb::Modify, "Observed Time"),
        ArtifactKind::Permission => (Macb::Modify, "Last Modified Time"),
        ArtifactKind::CreditCard => (Macb::Modify, "Last Modified Time"),
        ArtifactKind::AuthToken => (Macb::Access, "Last Used Time"),
        ArtifactKind::RecoveredDomain => (Macb::Access, "Last Contacted Time"),
        ArtifactKind::Favicon => (Macb::Access, "Last Requested Time"),
        ArtifactKind::TopSite => (Macb::Access, "Last Visited Time"),
        ArtifactKind::Shortcut => (Macb::Access, "Last Used Time"),
        ArtifactKind::NetworkPrediction => (Macb::Access, "Last Used Time"),
        ArtifactKind::MediaPlayback => (Macb::Access, "Last Playback Time"),
        ArtifactKind::TypedInput => (Macb::Access, "Typed Input Time"),
        ArtifactKind::Annotation => (Macb::Birth, "Annotation Added Time"),
        ArtifactKind::RecoveredBookmark => (Macb::Birth, "Added Time (from backup)"),
    }
}

/// Read a string-valued attribute, if present and a string.
fn attr_str<'a>(e: &'a BrowserEvent, key: &str) -> Option<&'a str> {
    e.attrs.get(key).and_then(Value::as_str)
}

/// The most identifying detail for a row: URL, else host, else description.
fn primary_detail(e: &BrowserEvent) -> String {
    if let Some(u) = attr_str(e, "url") {
        if !u.is_empty() {
            return u.to_string();
        }
    }
    if let Some(h) = attr_str(e, "host") {
        if !h.is_empty() {
            return h.to_string();
        }
    }
    e.description.clone()
}

/// Unix seconds (floored) from Unix nanoseconds. `div_euclid` keeps pre-epoch
/// times monotone.
fn unix_seconds(ns: i64) -> i64 {
    ns.div_euclid(1_000_000_000)
}

/// Neutralize characters that would break a single bodyfile row: the `|` field
/// delimiter and any newline. Values are preserved otherwise (no truncation).
fn bodyfile_sanitize(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '|' => '/',
            '\n' | '\r' => ' ',
            other => other,
        })
        .collect()
}

/// Serialize events as a TSK bodyfile (mactime 3.x format).
///
/// One row per event: `MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|
/// crtime`, pipe-delimited, times in Unix seconds. `MD5`, `inode`, `mode`,
/// `UID`, `GID`, `size` are `0` (browser events carry no filesystem metadata);
/// the event's single timestamp goes in the MAC slot the artifact implies
/// (see [`timestamp_semantic`]) and the other three slots are `0`.
///
/// Spec: SleuthKit body file 3.x
/// (<https://wiki.sleuthkit.org/index.php?title=Body_file>), consumed by
/// `mactime` (<https://sleuthkit.org/sleuthkit/man/mactime.html>).
#[must_use]
pub fn to_bodyfile(events: &[BrowserEvent]) -> String {
    let mut out = String::new();
    for e in events {
        let (macb, label) = timestamp_semantic(&e.artifact);
        let secs = unix_seconds(e.timestamp_ns);
        // ctime (inode-metadata change) has no browser-artifact meaning, so it
        // is always 0; the event's time lands in atime, mtime, or crtime.
        let (mut atime, mut mtime, mut crtime) = (0_i64, 0_i64, 0_i64);
        let ctime = 0_i64;
        match macb {
            Macb::Access => atime = secs,
            Macb::Modify => mtime = secs,
            Macb::Birth => crtime = secs,
        }
        let name = bodyfile_sanitize(&format!(
            "[{} {}] {} ({label})",
            e.browser.to_string().to_lowercase(),
            e.artifact.to_string().to_lowercase(),
            primary_detail(e),
        ));
        out.push_str(&format!(
            "0|{name}|0|0|0|0|0|{atime}|{mtime}|{ctime}|{crtime}\n"
        ));
    }
    out
}

/// The fixed l2t_csv column header.
const L2T_HEADER: &str =
    "date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra";

/// RFC 4180 field escaping: wrap in double quotes and double any embedded quote
/// when the value contains a comma, quote, CR, or LF.
fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Render (date `MM/DD/YYYY`, time `HH:MM:SS`) for an event in the given zone
/// (UTC when `None`). A non-representable timestamp degrades to zero fields
/// rather than panicking.
fn l2t_date_time(ns: i64, tz: Option<Tz>) -> (String, String) {
    let secs = ns.div_euclid(1_000_000_000);
    let nanos = u32::try_from(ns.rem_euclid(1_000_000_000)).unwrap_or(0);
    let Some(utc) = chrono::DateTime::from_timestamp(secs, nanos) else {
        return ("00/00/0000".to_string(), "00:00:00".to_string());
    };
    match tz {
        Some(t) => {
            let d = utc.with_timezone(&t);
            (
                d.format("%m/%d/%Y").to_string(),
                d.format("%H:%M:%S").to_string(),
            )
        }
        None => (
            utc.format("%m/%d/%Y").to_string(),
            utc.format("%H:%M:%S").to_string(),
        ),
    }
}

/// The `desc` (full detail) column: description, plus the URL when present.
fn l2t_desc(e: &BrowserEvent) -> String {
    match attr_str(e, "url") {
        Some(u) if !u.is_empty() => format!("{} [{u}]", e.description),
        _ => e.description.clone(),
    }
}

/// The `extra` column: every attribute as `k=v`, key-sorted for determinism,
/// `; `-joined (plaso's convention).
fn l2t_extra(e: &BrowserEvent) -> String {
    let mut kv: Vec<(&String, &Value)> = e.attrs.iter().collect();
    kv.sort_by(|a, b| a.0.cmp(b.0));
    kv.iter()
        .map(|(k, v)| {
            let val = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            format!("{k}={val}")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Serialize events as plaso / log2timeline `l2t_csv`.
///
/// A fixed 17-column header followed by one row per event. `date`/`time` are
/// rendered in `tz` (UTC when `None`); `source` is always `WEBHIST`;
/// `sourcetype`/`type`/`MACB` come from the artifact ([`timestamp_semantic`]);
/// `extra` carries every attribute as `k=v`. Every field is RFC 4180-escaped,
/// so a value can never break the column structure. Values are faithful — no
/// humanizing or truncation.
///
/// Format: log2timeline `l2t_csv`
/// (<https://forensics.wiki/l2t_csv/>); the `MACB` and `type` (timestamp
/// description) semantics follow plaso's output documentation
/// (<https://plaso.readthedocs.io/en/latest/sources/user/Output-and-formatting.html>).
#[must_use]
pub fn to_l2t_csv(events: &[BrowserEvent], tz: Option<Tz>) -> String {
    let tz_label = tz.map_or("UTC", chrono_tz::Tz::name);
    let mut out = String::from(L2T_HEADER);
    out.push('\n');
    for e in events {
        let (macb, type_label) = timestamp_semantic(&e.artifact);
        let (date, time) = l2t_date_time(e.timestamp_ns, tz);
        let sourcetype = format!("{} {}", e.browser, e.artifact);
        let fields = [
            date,
            time,
            tz_label.to_string(),
            macb.letters().to_string(),
            "WEBHIST".to_string(),
            sourcetype,
            type_label.to_string(),
            attr_str(e, "user").unwrap_or_default().to_string(),
            attr_str(e, "host").unwrap_or_default().to_string(),
            e.description.clone(),
            l2t_desc(e),
            "2".to_string(),
            e.source.clone(),
            String::new(),
            String::new(),
            "browser-forensic".to_string(),
            l2t_extra(e),
        ];
        let row: Vec<String> = fields.iter().map(|f| csv_field(f)).collect();
        out.push_str(&row.join(","));
        out.push('\n');
    }
    out
}

/// Case-level context for an HTML report header. Populated by the caller (the
/// `report` subcommand): `flags` carries integrity / anti-forensic observations
/// gathered outside the event stream (e.g. history-clearing indicators, carved
/// record counts) so the pure serializer can render them without re-collecting.
#[derive(Debug, Clone)]
pub struct ReportMeta {
    /// Case / matter reference, if supplied.
    pub case: Option<String>,
    /// Examiner name, if supplied.
    pub examiner: Option<String>,
    /// Tool name (e.g. `br4n6`).
    pub tool: String,
    /// Tool version.
    pub version: String,
    /// IANA timezone label the timeline is rendered in (e.g. `UTC`).
    pub timezone: String,
    /// Report generation time (Unix nanoseconds).
    pub generated_at_ns: i64,
    /// Integrity / anti-forensic observations to surface (already plain text).
    pub flags: Vec<String>,
}

/// HTML-escape a value for safe placement in element text or a double-quoted
/// attribute: `&`, `<`, `>`, `"`, `'`. Never trusts URLs/titles/flags verbatim.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            other => out.push(other),
        }
    }
    out
}

/// Host of an event's URL, if it has a parseable one.
fn event_host(e: &BrowserEvent) -> Option<String> {
    let u = attr_str(e, "url")?;
    url::Url::parse(u)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_string))
}

/// The number of timeline rows rendered inline. Beyond this the report notes
/// how many whole rows were omitted (never eliding a value mid-field).
const HTML_TIMELINE_ROWS: usize = 1000;

/// Serialize events as a self-contained, court-presentable HTML report.
///
/// A single HTML document with inlined styles: a case/tool/version/timezone
/// header, per-artifact counts, top domains, integrity / anti-forensic flags
/// (from `meta`), and a chronological timeline table. Every value —
/// URLs, titles, flags, paths — is HTML-escaped (XSS guard) and shown in full;
/// only whole trailing rows past [`HTML_TIMELINE_ROWS`] are omitted, with a
/// note. Findings are framed as observations of what was recovered, not
/// conclusions.
#[must_use]
pub fn to_html_report(events: &[BrowserEvent], meta: &ReportMeta) -> String {
    let mut h = String::new();
    html_open(&mut h, meta);
    html_meta_table(&mut h, events, meta);
    html_counts(&mut h, events);
    html_domains(&mut h, events);
    html_flags(&mut h, meta);
    html_timeline(&mut h, events, meta);
    h.push_str(CAPTION);
    h.push_str("</body>\n</html>\n");
    h
}

/// Document preamble: doctype, head, inlined styles, and the `<h1>`.
fn html_open(h: &mut String, meta: &ReportMeta) {
    h.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    let suffix = meta
        .case
        .as_deref()
        .map(|c| format!(" — {}", html_escape(c)))
        .unwrap_or_default();
    let _ = writeln!(h, "<title>Browser Forensic Report{suffix}</title>");
    h.push_str(STYLE);
    h.push_str("</head>\n<body>\n<h1>Browser Forensic Report</h1>\n");
}

/// The case / tool / timezone / totals header table.
fn html_meta_table(h: &mut String, events: &[BrowserEvent], meta: &ReportMeta) {
    let generated = render_rfc3339(meta.generated_at_ns, &meta.timezone);
    h.push_str("<table class=\"meta\">\n");
    if let Some(c) = &meta.case {
        let _ = writeln!(h, "<tr><th>Case</th><td>{}</td></tr>", html_escape(c));
    }
    if let Some(x) = &meta.examiner {
        let _ = writeln!(h, "<tr><th>Examiner</th><td>{}</td></tr>", html_escape(x));
    }
    let _ = writeln!(
        h,
        "<tr><th>Tool</th><td>{} {}</td></tr>",
        html_escape(&meta.tool),
        html_escape(&meta.version)
    );
    let _ = writeln!(
        h,
        "<tr><th>Timezone</th><td>{}</td></tr>",
        html_escape(&meta.timezone)
    );
    let _ = writeln!(
        h,
        "<tr><th>Generated</th><td>{}</td></tr>",
        html_escape(&generated)
    );
    let _ = writeln!(h, "<tr><th>Total events</th><td>{}</td></tr>", events.len());
    h.push_str("</table>\n");
}

/// Per-artifact counts table (stable order by artifact name).
fn html_counts(h: &mut String, events: &[BrowserEvent]) {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for e in events {
        *counts.entry(e.artifact.to_string()).or_default() += 1;
    }
    h.push_str(
        "<h2>Artifacts observed</h2>\n<table class=\"counts\">\n<tr><th>Artifact</th><th>Count</th></tr>\n",
    );
    for (name, n) in &counts {
        let _ = writeln!(h, "<tr><td>{}</td><td>{n}</td></tr>", html_escape(name));
    }
    h.push_str("</table>\n");
}

/// Top-10 domains by event count (desc count, then host asc).
fn html_domains(h: &mut String, events: &[BrowserEvent]) {
    let mut domains: BTreeMap<String, usize> = BTreeMap::new();
    for e in events {
        if let Some(host) = event_host(e) {
            *domains.entry(host).or_default() += 1;
        }
    }
    let mut top: Vec<(String, usize)> = domains.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    top.truncate(10);
    h.push_str("<h2>Top domains</h2>\n");
    if top.is_empty() {
        h.push_str("<p>No URL-bearing events were present.</p>\n");
        return;
    }
    h.push_str("<table class=\"domains\">\n<tr><th>Domain</th><th>Events</th></tr>\n");
    for (host, n) in &top {
        let _ = writeln!(h, "<tr><td>{}</td><td>{n}</td></tr>", html_escape(host));
    }
    h.push_str("</table>\n");
}

/// Integrity / anti-forensic observations from [`ReportMeta::flags`].
fn html_flags(h: &mut String, meta: &ReportMeta) {
    h.push_str("<h2>Integrity &amp; anti-forensic observations</h2>\n");
    if meta.flags.is_empty() {
        h.push_str(
            "<p>No integrity or anti-forensic indicators were recorded in this event set.</p>\n",
        );
        return;
    }
    h.push_str("<ul class=\"flags\">\n");
    for flag in &meta.flags {
        let _ = writeln!(h, "<li>{}</li>", html_escape(flag));
    }
    h.push_str("</ul>\n");
}

/// The chronological timeline table (first [`HTML_TIMELINE_ROWS`] events).
fn html_timeline(h: &mut String, events: &[BrowserEvent], meta: &ReportMeta) {
    let tz = meta.timezone.parse::<Tz>().ok();
    h.push_str("<h2>Timeline</h2>\n<table class=\"timeline\">\n<tr><th>Time</th><th>Browser</th><th>Artifact</th><th>Detail</th></tr>\n");
    for e in events.iter().take(HTML_TIMELINE_ROWS) {
        let _ = writeln!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&render_rfc3339_tz(e.timestamp_ns, tz)),
            html_escape(&e.browser.to_string()),
            html_escape(&e.artifact.to_string()),
            html_escape(&html_detail(e))
        );
    }
    h.push_str("</table>\n");
    if events.len() > HTML_TIMELINE_ROWS {
        let _ = writeln!(
            h,
            "<p class=\"note\">Showing the first {} of {} events in time order; values shown are verbatim.</p>",
            HTML_TIMELINE_ROWS,
            events.len()
        );
    }
}

/// The most identifying, court-readable detail for a timeline row: title and
/// URL when present (both shown in full), else the description.
fn html_detail(e: &BrowserEvent) -> String {
    let title = attr_str(e, "title").filter(|s| !s.is_empty());
    let url = attr_str(e, "url").filter(|s| !s.is_empty());
    match (title, url) {
        (Some(t), Some(u)) => format!("{t} — {u}"),
        (Some(t), None) => t.to_string(),
        (None, Some(u)) => u.to_string(),
        (None, None) => e.description.clone(),
    }
}

/// Render Unix nanoseconds as RFC 3339 in a timezone given by IANA label
/// (UTC if the label does not parse).
fn render_rfc3339(ns: i64, tz_label: &str) -> String {
    render_rfc3339_tz(ns, tz_label.parse::<Tz>().ok())
}

/// Render Unix nanoseconds as RFC 3339 in `tz` (UTC when `None`), never panics.
fn render_rfc3339_tz(ns: i64, tz: Option<Tz>) -> String {
    let secs = ns.div_euclid(1_000_000_000);
    let nanos = u32::try_from(ns.rem_euclid(1_000_000_000)).unwrap_or(0);
    let Some(utc) = chrono::DateTime::from_timestamp(secs, nanos) else {
        return "invalid".to_string();
    };
    match tz {
        Some(t) => utc.with_timezone(&t).to_rfc3339(),
        None => utc.to_rfc3339(),
    }
}

/// Epistemic caption: states what the report is and its limit — an observation
/// of the evidence, not a conclusion drawn from it.
const CAPTION: &str = "<p class=\"caption\">This report lists browser artifacts recovered from the collected data and records what was observed — the presence, timing, and attributes of each artifact — together with its evidentiary limits. It does not assert intent or authorship.</p>\n";

/// Inlined stylesheet keeping the report self-contained and legible in print.
const STYLE: &str = "<style>\nbody{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#111;line-height:1.4}\nh1{font-size:1.5rem;border-bottom:2px solid #333;padding-bottom:.3rem}\nh2{font-size:1.15rem;margin-top:1.6rem}\ntable{border-collapse:collapse;margin:.5rem 0;width:100%}\nth,td{border:1px solid #bbb;padding:.3rem .5rem;text-align:left;vertical-align:top;font-size:.9rem}\nth{background:#f0f0f0}\ntable.meta{width:auto}\ntable.meta th{width:9rem}\n.timeline td:nth-child(4){word-break:break-all}\n.caption,.note{font-size:.8rem;color:#555;margin-top:1rem}\n.flags li{margin:.2rem 0}\n</style>\n";
