//! DFIR-interop serializers over the collected `BrowserEvent` stream: TSK
//! bodyfile (mactime), plaso / log2timeline `l2t_csv`, and a self-contained,
//! court-presentable HTML report.
//!
//! These are new *serializers* over the events already gathered by
//! `browser_forensic_triage`; they collect nothing of their own. Machine
//! formats (bodyfile, `l2t_csv`) stay faithful and round-trippable; the HTML
//! report is a human view with every value HTML-escaped and shown in full.

use browser_forensic_core::BrowserEvent;

/// Serialize events as a TSK bodyfile (mactime 3.x format).
#[must_use]
pub fn to_bodyfile(_events: &[BrowserEvent]) -> String {
    String::new()
}
