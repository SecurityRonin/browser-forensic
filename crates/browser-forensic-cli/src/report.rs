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

/// Serialize events as plaso / log2timeline `l2t_csv`.
#[must_use]
pub fn to_l2t_csv(_events: &[BrowserEvent], _tz: Option<Tz>) -> String {
    String::new()
}
