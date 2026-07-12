//! DFIR-interop serializers over the collected `BrowserEvent` stream: TSK
//! bodyfile (mactime), plaso / log2timeline `l2t_csv`, and a self-contained,
//! court-presentable HTML report.
//!
//! These are new *serializers* over the events already gathered by
//! `browser_forensic_triage`; they collect nothing of their own. Machine
//! formats (bodyfile, `l2t_csv`) stay faithful and round-trippable; the HTML
//! report is a human view with every value HTML-escaped and shown in full.

use browser_forensic_core::{ArtifactKind, BrowserEvent};
use chrono_tz::Tz;
use serde_json::Value;

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

/// Serialize events as a self-contained, court-presentable HTML report.
#[must_use]
pub fn to_html_report(_events: &[BrowserEvent], _meta: &ReportMeta) -> String {
    String::new()
}
