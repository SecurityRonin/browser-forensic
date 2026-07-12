//! Parse SimpleCache stream 0 — the pickled `HttpResponseInfo` — into the HTTP
//! status line, response headers, and request/response timestamps.
//!
//! Layout (Chromium `net/http/http_response_info.cc` `HttpResponseInfo::Persist`
//! + `base::Pickle`):
//!
//! ```text
//! [u32 payload_size]                 base::Pickle header
//! [i32 flags]                        RESPONSE_INFO_VERSION + flag bits
//! [i64 request_time]                 base::Time internal (µs since 1601-01-01)
//! [i64 response_time]                base::Time internal
//! [i32 header_str_len]               base::Pickle::WriteString length prefix
//! [header_str bytes, 4-byte padded]  NUL-delimited: "HTTP/1.1 200 OK\0Key: Val\0…"
//! ```
//!
//! Scope limit: only this metadata prefix + the header block are decoded. The
//! remainder of the pickle (SSL cert chain, connection info, etc.) is not
//! parsed. If the structured prefix does not validate (format drift across
//! Chromium versions), we fall back to scanning for the `HTTP/` header block so
//! headers are still recovered — the timestamps are then reported as `None`.

/// µs between the Windows/`base::Time` epoch (1601-01-01) and the Unix epoch.
const WIN_TO_UNIX_MICROS: i64 = 11_644_473_600_000_000;

/// Decoded HTTP response metadata from SimpleCache stream 0.
#[derive(Debug, Clone, Default)]
pub struct HttpMeta {
    /// The full HTTP status line, e.g. `HTTP/1.1 200 OK`.
    pub status_line: Option<String>,
    /// The numeric HTTP status code, e.g. `200`.
    pub http_status: Option<u16>,
    /// Response headers in file order (`name`, `value`); names as stored.
    pub headers: Vec<(String, String)>,
    /// Request time (Unix nanoseconds), if the structured pickle prefix parsed.
    pub request_time_ns: Option<i64>,
    /// Response time (Unix nanoseconds), if the structured pickle prefix parsed.
    pub response_time_ns: Option<i64>,
}

impl HttpMeta {
    /// Case-insensitive lookup of the first header with the given name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The `Content-Type` header value, if present.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// The `Content-Encoding` header value (the on-the-wire body compression).
    #[must_use]
    pub fn content_encoding(&self) -> Option<&str> {
        self.header("content-encoding")
    }
}

/// Parse SimpleCache stream 0 into [`HttpMeta`].
///
/// Never fails: on malformed input it returns whatever could be recovered
/// (possibly an empty [`HttpMeta`]), never a panic.
#[must_use]
pub fn parse_http_meta(stream0: &[u8]) -> HttpMeta {
    // RED stub — implementation added in the GREEN commit.
    let _ = stream0;
    HttpMeta::default()
}

/// Convert a `base::Time` internal value (µs since 1601-01-01) to Unix ns.
/// Returns `None` for a null time (0) or on overflow.
fn win_micros_to_unix_ns(internal_micros: i64) -> Option<i64> {
    if internal_micros == 0 {
        return None;
    }
    let unix_micros = internal_micros.checked_sub(WIN_TO_UNIX_MICROS)?;
    unix_micros.checked_mul(1_000)
}

/// Split a NUL-delimited HTTP header block into (status_line, headers).
fn split_header_block(block: &str) -> (Option<String>, Vec<(String, String)>) {
    let mut segments = block.split('\0').filter(|s| !s.is_empty());
    let status_line = segments.next().map(str::to_string);
    let mut headers = Vec::new();
    for seg in segments {
        if let Some((k, v)) = seg.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    (status_line, headers)
}

/// Extract the numeric status code from a status line like `HTTP/1.1 200 OK`.
fn status_code(status_line: &str) -> Option<u16> {
    status_line.split_whitespace().nth(1)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_pickle(
        status_line: &str,
        headers: &[(&str, &str)],
        req_us: i64,
        resp_us: i64,
    ) -> Vec<u8> {
        let mut hdr = String::new();
        hdr.push_str(status_line);
        hdr.push('\0');
        for (k, v) in headers {
            hdr.push_str(k);
            hdr.push_str(": ");
            hdr.push_str(v);
            hdr.push('\0');
        }
        hdr.push('\0');
        let hbytes = hdr.as_bytes();

        let mut payload = Vec::new();
        payload.extend_from_slice(&0i32.to_le_bytes()); // flags
        payload.extend_from_slice(&req_us.to_le_bytes());
        payload.extend_from_slice(&resp_us.to_le_bytes());
        payload.extend_from_slice(&(hbytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(hbytes);
        while payload.len() % 4 != 0 {
            payload.push(0);
        }

        let mut out = Vec::new();
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&payload);
        out
    }

    // Unix 2021-01-01T00:00:00Z = 1_609_459_200 s.
    const RESP_UNIX_S: i64 = 1_609_459_200;
    fn resp_win_us() -> i64 {
        (RESP_UNIX_S + 11_644_473_600) * 1_000_000
    }

    #[test]
    fn parses_status_headers_and_times() {
        let data = build_pickle(
            "HTTP/1.1 200 OK",
            &[
                ("Content-Type", "text/html; charset=utf-8"),
                ("Content-Encoding", "gzip"),
            ],
            resp_win_us(),
            resp_win_us(),
        );
        let meta = parse_http_meta(&data);
        assert_eq!(meta.http_status, Some(200));
        assert_eq!(meta.status_line.as_deref(), Some("HTTP/1.1 200 OK"));
        assert_eq!(meta.content_type(), Some("text/html; charset=utf-8"));
        assert_eq!(meta.content_encoding(), Some("gzip"));
        assert_eq!(meta.response_time_ns, Some(RESP_UNIX_S * 1_000_000_000));
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let data = build_pickle("HTTP/1.1 200 OK", &[("Content-Type", "image/png")], 0, 0);
        let meta = parse_http_meta(&data);
        assert_eq!(meta.header("CONTENT-TYPE"), Some("image/png"));
        // Null time -> None.
        assert_eq!(meta.request_time_ns, None);
    }

    #[test]
    fn falls_back_to_scanning_when_prefix_invalid() {
        // No valid pickle prefix, but a HTTP header block is embedded.
        let mut data = vec![0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x11];
        data.extend_from_slice(b"HTTP/1.1 404 Not Found\0Content-Type: text/plain\0\0");
        let meta = parse_http_meta(&data);
        assert_eq!(meta.http_status, Some(404));
        assert_eq!(meta.content_type(), Some("text/plain"));
        assert_eq!(meta.request_time_ns, None);
    }

    #[test]
    fn garbage_yields_empty_meta_no_panic() {
        let meta = parse_http_meta(&[0u8; 3]);
        assert!(meta.status_line.is_none());
        assert!(meta.headers.is_empty());
        let meta2 = parse_http_meta(&[]);
        assert!(meta2.status_line.is_none());
    }
}
