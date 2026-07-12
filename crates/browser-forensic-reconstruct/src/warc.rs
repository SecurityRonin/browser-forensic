//! WARC (ISO 28500) output of cached resources.
//!
//! Emits an archival-defensible WARC stream: a leading `warcinfo` record
//! carrying the provenance statement, then one `response` record per cached
//! resource (original `WARC-Target-URI` plus a reconstructed HTTP response
//! block: status line, headers, and body). The result is replayable in pywb /
//! replayweb.page.

use std::io::{self, Write};

use warc::{RecordBuilder, RecordType, WarcHeader, WarcWriter};

use crate::index::IndexedResource;
use crate::manifest::PROVENANCE_BANNER;

/// Reproduce the HTTP response block (status line, headers, blank line, body)
/// for one resource. Content-coding headers are dropped and `Content-Length`
/// recomputed because the stored body is already decoded — so the block
/// replays correctly.
fn http_response_block(res: &IndexedResource) -> Vec<u8> {
    let mut block = Vec::with_capacity(res.body.len() + 256);
    let status = res
        .status_line
        .clone()
        .unwrap_or_else(|| format!("HTTP/1.1 {} ", res.http_status.unwrap_or(200)));
    block.extend_from_slice(status.trim_end().as_bytes());
    block.extend_from_slice(b"\r\n");

    let mut wrote_content_type = false;
    for (k, v) in &res.headers {
        let kl = k.to_ascii_lowercase();
        if kl == "content-encoding" || kl == "transfer-encoding" || kl == "content-length" {
            continue;
        }
        if kl == "content-type" {
            wrote_content_type = true;
        }
        block.extend_from_slice(k.as_bytes());
        block.extend_from_slice(b": ");
        block.extend_from_slice(v.as_bytes());
        block.extend_from_slice(b"\r\n");
    }
    if !wrote_content_type {
        if let Some(ct) = &res.content_type {
            block.extend_from_slice(b"Content-Type: ");
            block.extend_from_slice(ct.as_bytes());
            block.extend_from_slice(b"\r\n");
        }
    }
    block.extend_from_slice(format!("Content-Length: {}\r\n", res.body.len()).as_bytes());
    block.extend_from_slice(b"\r\n");
    block.extend_from_slice(&res.body);
    block
}

fn build_err(e: &warc::Error) -> io::Error {
    io::Error::other(format!("WARC record build failed: {e}"))
}

/// The leading `warcinfo` record body (`application/warc-fields`), carrying the
/// provenance statement so the archive is self-describing.
fn warcinfo_fields(target_url: Option<&str>) -> String {
    let mut s = String::new();
    s.push_str("software: browser-forensic-reconstruct\r\n");
    s.push_str("format: WARC File Format 1.1\r\n");
    s.push_str("conformsTo: http://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/\r\n");
    if let Some(t) = target_url {
        s.push_str("x-target-uri: ");
        s.push_str(t);
        s.push_str("\r\n");
    }
    s.push_str("x-provenance: ");
    s.push_str(PROVENANCE_BANNER);
    s.push_str("\r\n");
    s
}

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
    resources: I,
    target_url: Option<&str>,
    out: &mut W,
) -> io::Result<WarcStats>
where
    I: IntoIterator<Item = &'a IndexedResource>,
    W: Write,
{
    let mut writer = WarcWriter::new(out);
    let mut bytes_written = 0usize;
    let mut responses = 0usize;

    // Leading warcinfo record with the provenance statement.
    let info = RecordBuilder::default()
        .version("1.1".to_string())
        .warc_type(RecordType::WarcInfo)
        .header(WarcHeader::ContentType, "application/warc-fields")
        .body(warcinfo_fields(target_url).into_bytes())
        .build()
        .map_err(|e| build_err(&e))?;
    bytes_written += writer.write(&info)?;

    for res in resources {
        let block = http_response_block(res);
        let mut builder = RecordBuilder::default()
            .version("1.1".to_string())
            .warc_type(RecordType::Response)
            .header(WarcHeader::TargetURI, res.url.clone())
            .header(WarcHeader::ContentType, "application/http;msgtype=response")
            .header(
                WarcHeader::Unknown("warc-x-cache-source".to_string()),
                res.source.label(),
            );
        if let Some(ns) = res.cached_time_ns {
            builder = builder.header(
                WarcHeader::Unknown("warc-x-cache-time-ns".to_string()),
                ns.to_string(),
            );
        }
        let record = builder.body(block).build().map_err(|e| build_err(&e))?;
        bytes_written += writer.write(&record)?;
        responses += 1;
    }

    Ok(WarcStats {
        responses,
        bytes_written,
    })
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
        // WARC field names are case-insensitive per spec; compare lower-cased.
        let sl = s.to_lowercase();
        assert!(
            sl.contains("warc-type: warcinfo"),
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
        let sl = s.to_lowercase();
        assert!(sl.contains("warc-type: response"));
        assert!(sl.contains("warc-target-uri: https://ex.com/app.js"));
        // application/http response block type.
        assert!(sl.contains("application/http"));
        // Original header preserved (verbatim casing) inside the response block.
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
        let sl = String::from_utf8_lossy(&buf).to_lowercase();
        assert_eq!(sl.matches("warc-type: response").count(), 3);
        assert_eq!(sl.matches("warc-type: warcinfo").count(), 1);
    }

    #[test]
    fn empty_input_still_writes_warcinfo() {
        let (buf, stats) = write_to_vec(&[], None);
        let sl = String::from_utf8_lossy(&buf).to_lowercase();
        assert!(sl.contains("warc-type: warcinfo"));
        assert_eq!(stats.responses, 0);
    }
}
