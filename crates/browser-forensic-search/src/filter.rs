//! Substring / regex search over browser events, with field scoping and a
//! timestamp window.
//!
//! The regex engine is the `regex` crate — a finite-automata implementation with
//! **linear-time** matching and no catastrophic backtracking, safe to run over
//! attacker-controllable event text. Each field is length-bounded before
//! matching so a pathologically large value cannot dominate a scan.

use browser_forensic_core::BrowserEvent;

/// Per-field byte cap applied before matching. Event text beyond this is not
/// scanned — bounds work against a single oversized value (e.g. a data: URL).
pub const MAX_FIELD_LEN: usize = 1 << 20; // 1 MiB

/// A search pattern: a plain case-sensitive substring, or a compiled regex.
#[derive(Debug, Clone)]
pub enum Pattern {
    /// Case-sensitive substring test.
    Substring(String),
    /// Compiled `regex` pattern (linear-time matching).
    Regex(regex::Regex),
}

impl Pattern {
    /// Build a substring pattern.
    pub fn substring(s: impl Into<String>) -> Self {
        Self::Substring(s.into())
    }

    /// Compile a regex pattern with a bounded compiled size (rejects a pattern
    /// that would compile to an enormous automaton). Matching is linear in the
    /// haystack length regardless of the pattern.
    ///
    /// # Errors
    /// Returns the underlying [`regex::Error`] when the pattern is invalid or
    /// exceeds the size limit.
    pub fn regex(pat: &str) -> Result<Self, regex::Error> {
        let re = regex::RegexBuilder::new(pat)
            .size_limit(10 * (1 << 20))
            .build()?;
        Ok(Self::Regex(re))
    }

    /// True if `haystack` (already length-bounded by the caller) matches.
    #[must_use]
    pub fn is_match(&self, haystack: &str) -> bool {
        match self {
            Self::Substring(s) => haystack.contains(s.as_str()),
            Self::Regex(re) => re.is_match(haystack),
        }
    }
}

/// A search over a slice of events: an optional pattern (absent = match every
/// event, i.e. a pure time filter), an optional field allow-list, and an
/// inclusive `[from_ns, to_ns]` timestamp window (either bound optional).
#[derive(Debug, Clone, Default)]
pub struct EventQuery {
    /// The pattern to match; `None` matches all events (time-only filter).
    pub pattern: Option<Pattern>,
    /// Field names to search. Empty = the event's whole textual surface
    /// (`description`, `source`, and every string-valued attribute).
    pub fields: Vec<String>,
    /// Inclusive lower timestamp bound (Unix nanoseconds), if any.
    pub from_ns: Option<i64>,
    /// Inclusive upper timestamp bound (Unix nanoseconds), if any.
    pub to_ns: Option<i64>,
}

/// Return the events matching `query`, in input order.
#[must_use]
pub fn filter_events<'a>(events: &'a [BrowserEvent], query: &EventQuery) -> Vec<&'a BrowserEvent> {
    events
        .iter()
        .filter(|e| in_window(e.timestamp_ns, query) && matches_pattern(e, query))
        .collect()
}

/// Inclusive `[from_ns, to_ns]` bounds check; an absent bound never excludes.
fn in_window(ts: i64, query: &EventQuery) -> bool {
    query.from_ns.map_or(true, |from| ts >= from) && query.to_ns.map_or(true, |to| ts <= to)
}

/// True when the query has no pattern (time-only), or any in-scope field of the
/// event matches the pattern.
fn matches_pattern(event: &BrowserEvent, query: &EventQuery) -> bool {
    let Some(pattern) = &query.pattern else {
        return true;
    };
    for_each_field(event, &query.fields, |text| {
        let bounded = bound(text);
        pattern.is_match(bounded)
    })
}

/// Cap `text` to `MAX_FIELD_LEN` bytes on a UTF-8 char boundary.
fn bound(text: &str) -> &str {
    if text.len() <= MAX_FIELD_LEN {
        return text;
    }
    let mut end = MAX_FIELD_LEN;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Invoke `pred` on each in-scope textual field, short-circuiting on the first
/// `true`. With an empty `fields` allow-list the whole textual surface is
/// searched: `description`, `source`, and every string-valued attribute.
fn for_each_field(
    event: &BrowserEvent,
    fields: &[String],
    mut pred: impl FnMut(&str) -> bool,
) -> bool {
    let want = |name: &str| fields.is_empty() || fields.iter().any(|f| f == name);

    if want("description") && pred(&event.description) {
        return true;
    }
    if want("source") && pred(&event.source) {
        return true;
    }
    for (key, value) in &event.attrs {
        if want(key) {
            if let Some(s) = value.as_str() {
                if pred(s) {
                    return true;
                }
            }
        }
    }
    false
}
