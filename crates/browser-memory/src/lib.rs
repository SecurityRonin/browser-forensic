#![deny(clippy::unwrap_used)]
//! Browser memory scanning — extract browser artifacts from raw byte buffers.

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
