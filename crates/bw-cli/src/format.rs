//! Output formatting for browser forensic events.

use browser_core::BrowserEvent;

/// CSV header for timeline output.
pub const TIMELINE_CSV_HEADER: &str = "timestamp,browser,artifact,source,description";

/// Escape a string for CSV: wraps in double quotes if it contains commas or quotes.
pub fn csv_escape(s: &str) -> String {
    todo!("not yet implemented")
}

/// Format a Unix nanosecond timestamp as RFC3339.
pub fn format_timestamp_ns(ns: i64) -> String {
    todo!("not yet implemented")
}

/// Format a [`BrowserEvent`] as a human-readable text line.
pub fn event_to_text(ev: &BrowserEvent) -> String {
    todo!("not yet implemented")
}

/// Format a [`BrowserEvent`] as a JSONL (newline-delimited JSON) string.
pub fn event_to_jsonl(ev: &BrowserEvent) -> String {
    todo!("not yet implemented")
}

/// Format a [`BrowserEvent`] as a CSV row (5 fields).
pub fn event_to_csv_row(ev: &BrowserEvent) -> String {
    todo!("not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily};

    fn make_event() -> BrowserEvent {
        BrowserEvent::new(
            1_648_000_000_000_000_000_i64,
            BrowserFamily::Chromium,
            ArtifactKind::History,
            "/path/to/History",
            "Example Page",
        )
    }

    #[test]
    fn csv_escape_plain_string() {
        assert_eq!(csv_escape("hello"), "hello");
    }

    #[test]
    fn csv_escape_string_with_comma() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
    }

    #[test]
    fn csv_escape_string_with_double_quote() {
        // say "hi" -> "say ""hi"""
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn format_timestamp_ns_is_rfc3339() {
        let result = format_timestamp_ns(1_648_000_000_000_000_000);
        // RFC3339 contains 'T' separator
        assert!(result.contains('T'), "not RFC3339: {result}");
    }

    #[test]
    fn event_to_csv_row_has_five_fields() {
        let ev = make_event();
        let row = event_to_csv_row(&ev);
        // CSV row should have at least 4 commas (5 fields)
        let field_count = row.split(',').count();
        assert!(field_count >= 5, "not enough fields: {row}");
    }
}
