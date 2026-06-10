#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Browser memory scanning — extract browser artifacts from raw byte buffers.

use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use url::Url;

/// Scan a raw byte buffer for HTTP/HTTPS URLs.
///
/// Each valid URL found becomes a [`BrowserEvent`] with [`ArtifactKind::Memory`].
/// Null bytes (`\0`) are treated as URL terminators.
#[must_use]
pub fn scan_bytes_for_urls(data: &[u8]) -> Vec<BrowserEvent> {
    // Replace null bytes with spaces so string searching works across null-terminated blobs.
    let text = String::from_utf8_lossy(data).replace('\0', " ");
    let mut events = Vec::new();

    for prefix in &["https://", "http://"] {
        let mut search = text.as_str();
        while let Some(start) = search.find(prefix) {
            let candidate = &search[start..];
            // A URL ends at whitespace or common delimiters.
            let end = candidate
                .find(|c: char| {
                    c.is_ascii_whitespace() || c == '"' || c == '\'' || c == '<' || c == '>'
                })
                .unwrap_or(candidate.len());
            let raw = &candidate[..end];
            if let Ok(parsed) = Url::parse(raw) {
                let ev = BrowserEvent::new(
                    0,
                    BrowserFamily::Chromium,
                    ArtifactKind::Memory,
                    "memory",
                    parsed.as_str(),
                )
                .with_attr("url", serde_json::Value::String(parsed.into()));
                events.push(ev);
            }
            // Advance past this occurrence to avoid infinite loop.
            search = &search[start + prefix.len()..];
        }
    }

    events
}

/// Scan a raw byte buffer for HTTP `Cookie:` headers.
///
/// Each cookie header line found becomes a [`BrowserEvent`] with [`ArtifactKind::Memory`].
#[must_use]
pub fn scan_bytes_for_cookies(data: &[u8]) -> Vec<BrowserEvent> {
    let text = String::from_utf8_lossy(data).replace('\0', " ");
    let mut events = Vec::new();
    const MARKER: &str = "Cookie: ";

    let mut search = text.as_str();
    while let Some(start) = search.find(MARKER) {
        let rest = &search[start + MARKER.len()..];
        // Cookie value ends at CRLF, LF, or end of string.
        let end = rest.find(['\r', '\n']).unwrap_or(rest.len());
        let cookie_value = rest[..end].trim().to_string();
        if !cookie_value.is_empty() {
            let ev = BrowserEvent::new(
                0,
                BrowserFamily::Chromium,
                ArtifactKind::Memory,
                "memory",
                format!("Cookie: {cookie_value}"),
            )
            .with_attr("cookie", serde_json::Value::String(cookie_value));
            events.push(ev);
        }
        search = &search[start + MARKER.len()..];
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::ArtifactKind;

    #[test]
    fn scan_bytes_for_urls_finds_https() {
        let data = b"some garbage https://example.com/page more garbage";
        let events = scan_bytes_for_urls(data);
        assert!(!events.is_empty(), "should find at least one URL");
        assert!(events.iter().all(|e| e.artifact == ArtifactKind::Memory));
    }

    #[test]
    fn scan_bytes_for_urls_finds_http() {
        let data = b"prefix http://insecure.example.com/path suffix";
        let events = scan_bytes_for_urls(data);
        assert!(!events.is_empty());
    }

    #[test]
    fn scan_bytes_for_urls_empty_data_returns_empty() {
        let events = scan_bytes_for_urls(b"");
        assert!(events.is_empty());
    }

    #[test]
    fn scan_bytes_for_urls_no_urls_returns_empty() {
        let data = b"no urls here just some text about things";
        let events = scan_bytes_for_urls(data);
        assert!(events.is_empty());
    }

    #[test]
    fn scan_bytes_for_urls_multiple_urls() {
        let data = b"first https://a.com/1 then https://b.com/2 end";
        let events = scan_bytes_for_urls(data);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn scan_bytes_for_urls_handles_null_terminated() {
        let mut data = Vec::new();
        data.extend_from_slice(b"https://example.com/page");
        data.push(0);
        data.extend_from_slice(b"more data");

        let events = scan_bytes_for_urls(&data);
        assert!(!events.is_empty());
    }

    #[test]
    fn scan_bytes_for_cookies_finds_cookie_header() {
        let data = b"GET / HTTP/1.1\r\nCookie: session_id=abc123; user=test\r\n\r\n";
        let events = scan_bytes_for_cookies(data);
        assert!(!events.is_empty(), "should find cookie header");
    }

    #[test]
    fn scan_bytes_for_cookies_empty_returns_empty() {
        let events = scan_bytes_for_cookies(b"no cookies");
        assert!(events.is_empty());
    }
}
