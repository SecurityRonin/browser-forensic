//! WARC (ISO 28500) output of cached resources.
//!
//! Emits an archival-defensible WARC stream: a leading `warcinfo` record
//! carrying the provenance statement, then one `response` record per cached
//! resource (original `WARC-Target-URI` plus a reconstructed HTTP response
//! block: status line, headers, and body). The result is replayable in pywb /
//! replayweb.page.

use std::io::{self, Write};

use crate::index::IndexedResource;

/// Counts returned by [`write_warc`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WarcStats {
    /// Number of `response` records written (one per resource).
    pub responses: usize,
    /// Total bytes written to the output.
    pub bytes_written: usize,
}

/// Write a WARC stream for `resources` to `out`.
///
/// A `warcinfo` record carrying the provenance statement is written first,
/// then one `response` record per resource (RED stub — writes nothing).
///
/// # Errors
/// Propagates any write error from `out`.
pub fn write_warc<'a, I, W>(
    _resources: I,
    _target_url: Option<&str>,
    _out: &mut W,
) -> io::Result<WarcStats>
where
    I: IntoIterator<Item = &'a IndexedResource>,
    W: Write,
{
    Ok(WarcStats::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{CacheSource, IndexedResource};
    use std::path::PathBuf;

    fn res(url: &str, ct: &str, hdrs: &[(&str, &str)], body: &[u8]) -> IndexedResource {
        IndexedResource {
            url: url.to_string(),
            source: CacheSource::ChromiumSimpleCache,
            cached_time_ns: Some(1_700_000_000_000_000_000),
            content_type: Some(ct.to_string()),
            http_status: Some(200),
            status_line: Some("HTTP/1.1 200 OK".to_string()),
            headers: hdrs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            body: body.to_vec(),
            source_file: PathBuf::from("/tmp/x_0"),
        }
    }

    fn write_to_vec(resources: &[IndexedResource], target: Option<&str>) -> (Vec<u8>, WarcStats) {
        let mut buf = Vec::new();
        let stats = write_warc(resources.iter(), target, &mut buf).unwrap();
        (buf, stats)
    }

    #[test]
    fn starts_with_warc_version_and_warcinfo() {
        let r = vec![res("https://ex.com/", "text/html", &[], b"<html>")];
        let (buf, _) = write_to_vec(&r, Some("https://ex.com/"));
        let s = String::from_utf8_lossy(&buf);
        assert!(
            s.starts_with("WARC/"),
            "must begin with a WARC version line"
        );
        assert!(
            s.contains("WARC-Type: warcinfo"),
            "leading warcinfo record required"
        );
        assert!(
            s.contains("Reconstructed from cached resources"),
            "warcinfo must carry the provenance statement"
        );
    }

    #[test]
    fn response_record_has_target_uri_headers_and_body() {
        let r = vec![res(
            "https://ex.com/app.js",
            "application/javascript",
            &[("X-Test", "yes")],
            b"console.log(1)",
        )];
        let (buf, stats) = write_to_vec(&r, None);
        let s = String::from_utf8_lossy(&buf);
        assert!(s.contains("WARC-Type: response"));
        assert!(s.contains("WARC-Target-URI: https://ex.com/app.js"));
        // application/http response block type.
        assert!(s.contains("application/http"));
        // Original header preserved inside the response block.
        assert!(s.contains("X-Test: yes"));
        // Body present.
        assert!(s.contains("console.log(1)"));
        assert_eq!(stats.responses, 1);
    }

    #[test]
    fn one_response_record_per_resource() {
        let r = vec![
            res("https://ex.com/a", "text/html", &[], b"a"),
            res("https://ex.com/b", "text/css", &[], b"b"),
            res("https://ex.com/c", "image/png", &[], b"c"),
        ];
        let (buf, stats) = write_to_vec(&r, None);
        assert_eq!(stats.responses, 3);
        let s = String::from_utf8_lossy(&buf);
        assert_eq!(s.matches("WARC-Type: response").count(), 3);
        assert_eq!(s.matches("WARC-Type: warcinfo").count(), 1);
    }

    #[test]
    fn empty_input_still_writes_warcinfo() {
        let (buf, stats) = write_to_vec(&[], None);
        let s = String::from_utf8_lossy(&buf);
        assert!(s.contains("WARC-Type: warcinfo"));
        assert_eq!(stats.responses, 0);
    }
}
