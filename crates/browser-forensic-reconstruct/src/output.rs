//! Orchestration: reconstruct an artifact from the index and write it to an
//! output directory.
//!
//! Each format writes a provenance `*.manifest.json` alongside the viewable
//! artifact so the honesty statement and the found/missing enumeration travel
//! with the output on disk, not only inside the HTML banner.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::gallery::{build_gallery, gallery_index_html};
use crate::index::ResourceIndex;
use crate::singlefile::reconstruct_singlefile;
use crate::warc::write_warc;

/// The reconstruction output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Self-contained single-file HTML page(s).
    Html,
    /// A replayable WARC archive.
    Warc,
    /// A cached-image gallery.
    Gallery,
}

/// What a reconstruction run produced.
#[derive(Debug, Clone, Default)]
pub struct ReconstructReport {
    /// Files written, in write order.
    pub files_written: Vec<PathBuf>,
    /// Sub-resources found in cache (across the reconstructed page(s)).
    pub found: usize,
    /// Sub-resources referenced but missing.
    pub missing: usize,
    /// Images written (gallery format).
    pub images: usize,
    /// Response records written (WARC format).
    pub responses: usize,
    /// HTML pages reconstructed (html format).
    pub pages: usize,
}

/// A filename-safe stem derived from a URL (RED stub is unused here).
fn page_stem(url: &str) -> String {
    let _ = url;
    String::new()
}

/// Reconstruct and write the chosen artifact to `out_dir` (RED stub — writes
/// nothing).
///
/// # Errors
/// Propagates filesystem write errors.
pub fn reconstruct_to_dir(
    _index: &ResourceIndex,
    _out_dir: &Path,
    _target: Option<&str>,
    _format: OutputFormat,
) -> io::Result<ReconstructReport> {
    let _ = (
        page_stem,
        build_gallery as fn(&ResourceIndex) -> crate::gallery::Gallery,
        gallery_index_html as fn(&crate::gallery::Gallery) -> String,
        reconstruct_singlefile
            as fn(&ResourceIndex, &str) -> Option<crate::singlefile::ReconstructedPage>,
    );
    Ok(ReconstructReport::default())
}

/// Write `bytes` to `dir/name`, recording the path.
fn write_file(
    dir: &Path,
    name: &str,
    bytes: &[u8],
    report: &mut ReconstructReport,
) -> io::Result<()> {
    let path = dir.join(name);
    let mut f = fs::File::create(&path)?;
    f.write_all(bytes)?;
    report.files_written.push(path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{CacheSource, IndexedResource};
    use tempfile::TempDir;

    fn r(url: &str, ct: &str, body: &[u8]) -> IndexedResource {
        IndexedResource {
            url: url.to_string(),
            source: CacheSource::ChromiumSimpleCache,
            cached_time_ns: Some(1),
            content_type: Some(ct.to_string()),
            http_status: Some(200),
            status_line: Some("HTTP/1.1 200 OK".to_string()),
            headers: vec![("Content-Type".to_string(), ct.to_string())],
            body: body.to_vec(),
            source_file: PathBuf::from("/tmp/x_0"),
        }
    }

    fn png() -> Vec<u8> {
        let mut b = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        b.extend_from_slice(&[0, 0, 0, 13]);
        b.extend_from_slice(b"IHDR");
        b.extend_from_slice(&2u32.to_be_bytes());
        b.extend_from_slice(&2u32.to_be_bytes());
        b.extend_from_slice(&[8, 2, 0, 0, 0]);
        b
    }

    fn idx() -> ResourceIndex {
        let mut i = ResourceIndex::new();
        i.insert(r(
            "https://ex.com/",
            "text/html",
            b"<html><body><img src=/a.png><img src=/missing.png></body></html>",
        ));
        i.insert(r("https://ex.com/a.png", "image/png", &png()));
        i
    }

    fn read(path: &Path) -> String {
        String::from_utf8_lossy(&std::fs::read(path).unwrap()).into_owned()
    }

    #[test]
    fn html_writes_page_and_manifest() {
        let out = TempDir::new().unwrap();
        let report = reconstruct_to_dir(
            &idx(),
            out.path(),
            Some("https://ex.com/"),
            OutputFormat::Html,
        )
        .unwrap();
        assert_eq!(report.pages, 1);
        let html = report
            .files_written
            .iter()
            .find(|p| p.extension().is_some_and(|e| e == "html"))
            .expect("an html file");
        assert!(read(html).contains("Reconstructed from cached resources"));
        let manifest = report
            .files_written
            .iter()
            .find(|p| p.to_string_lossy().ends_with(".manifest.json"))
            .expect("a manifest.json");
        let mj = read(manifest);
        assert!(mj.contains("Reconstructed from cached resources"));
        assert!(mj.contains("https://ex.com/missing.png"));
        assert_eq!(report.missing, 1);
    }

    #[test]
    fn gallery_writes_index_and_images() {
        let out = TempDir::new().unwrap();
        let report = reconstruct_to_dir(&idx(), out.path(), None, OutputFormat::Gallery).unwrap();
        assert_eq!(report.images, 1);
        assert!(out.path().join("index.html").is_file());
        assert!(
            read(&out.path().join("index.html")).contains("Reconstructed from cached resources")
        );
        // The one image file was written and is non-empty.
        let img = report
            .files_written
            .iter()
            .find(|p| p.extension().is_some_and(|e| e == "png"))
            .expect("a png file");
        assert!(std::fs::metadata(img).unwrap().len() > 0);
    }

    #[test]
    fn warc_writes_replayable_archive() {
        let out = TempDir::new().unwrap();
        let report = reconstruct_to_dir(&idx(), out.path(), None, OutputFormat::Warc).unwrap();
        let warc = report
            .files_written
            .iter()
            .find(|p| p.extension().is_some_and(|e| e == "warc"))
            .expect("a warc file");
        let s = read(warc);
        assert!(s.starts_with("WARC/"));
        assert!(s.to_lowercase().contains("warc-type: warcinfo"));
        assert!(report.responses >= 2);
    }
}
