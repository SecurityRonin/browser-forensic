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
    // GREEN cycle replaces this stub with the real matcher.
    let _ = (events, query);
    Vec::new()
}
