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

/// A filename-safe stem derived from a URL: host + path, non-safe chars mapped
/// to `_`, length-capped. Falls back to `page` for an empty result.
fn page_stem(url: &str) -> String {
    let core = url
        .split_once("://")
        .map_or(url, |(_, rest)| rest)
        .split(['?', '#'])
        .next()
        .unwrap_or(url);
    let mut stem: String = core
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(80)
        .collect();
    let trimmed = stem.trim_matches('_');
    if trimmed.is_empty() {
        stem = "page".to_string();
    } else {
        stem = trimmed.to_string();
    }
    stem
}

/// Reconstruct and write the chosen artifact to `out_dir`.
///
/// * `Html` — reconstruct `target` (or every cached HTML page when `target` is
///   `None`), writing each self-contained page plus its `*.manifest.json`.
/// * `Warc` — write a replayable WARC of the whole cache, or of `target`'s page
///   and its found sub-resources when `target` is given.
/// * `Gallery` — write a cached-image gallery (`index.html` + image files).
///
/// # Errors
/// Propagates filesystem write errors.
pub fn reconstruct_to_dir(
    index: &ResourceIndex,
    out_dir: &Path,
    target: Option<&str>,
    format: OutputFormat,
) -> io::Result<ReconstructReport> {
    fs::create_dir_all(out_dir)?;
    let mut report = ReconstructReport::default();
    match format {
        OutputFormat::Html => write_html(index, out_dir, target, &mut report)?,
        OutputFormat::Warc => write_warc_output(index, out_dir, target, &mut report)?,
        OutputFormat::Gallery => write_gallery(index, out_dir, &mut report)?,
    }
    Ok(report)
}

fn write_html(
    index: &ResourceIndex,
    out_dir: &Path,
    target: Option<&str>,
    report: &mut ReconstructReport,
) -> io::Result<()> {
    let targets: Vec<String> = match target {
        Some(t) => vec![t.to_string()],
        None => index.html_entries().iter().map(|r| r.url.clone()).collect(),
    };
    let mut used = std::collections::HashSet::new();
    for turl in targets {
        let Some(page) = reconstruct_singlefile(index, &turl) else {
            continue;
        };
        let mut stem = page_stem(&turl);
        while !used.insert(stem.clone()) {
            stem = format!("{stem}_");
        }
        write_file(
            out_dir,
            &format!("{stem}.html"),
            page.html.as_bytes(),
            report,
        )?;
        write_file(
            out_dir,
            &format!("{stem}.manifest.json"),
            page.manifest.to_json().as_bytes(),
            report,
        )?;
        report.found += page.manifest.found.len();
        report.missing += page.manifest.missing.len();
        report.pages += 1;
    }
    Ok(())
}

fn write_warc_output(
    index: &ResourceIndex,
    out_dir: &Path,
    target: Option<&str>,
    report: &mut ReconstructReport,
) -> io::Result<()> {
    // Scope: a target page + its found sub-resources, or the whole cache.
    let resources: Vec<&crate::index::IndexedResource> = match target {
        Some(t) => {
            let mut urls = vec![crate::index::normalize_url(t)];
            if let Some(page) = reconstruct_singlefile(index, t) {
                for f in &page.manifest.found {
                    urls.push(crate::index::normalize_url(&f.url));
                }
            }
            urls.iter().filter_map(|u| index.get(u)).collect()
        }
        None => index.iter().collect(),
    };
    let mut buf = Vec::new();
    let stats = write_warc(resources, target, &mut buf)?;
    write_file(out_dir, "reconstruction.warc", &buf, report)?;
    report.responses = stats.responses;
    Ok(())
}

fn write_gallery(
    index: &ResourceIndex,
    out_dir: &Path,
    report: &mut ReconstructReport,
) -> io::Result<()> {
    let gallery = build_gallery(index);
    let html = gallery_index_html(&gallery);
    write_file(out_dir, "index.html", html.as_bytes(), report)?;
    write_file(
        out_dir,
        "gallery.manifest.json",
        gallery.manifest.to_json().as_bytes(),
        report,
    )?;
    for img in &gallery.images {
        if let Some(res) = index.get(&img.url) {
            write_file(out_dir, &img.filename, &res.body, report)?;
        }
    }
    report.found = gallery.manifest.found.len();
    report.images = gallery.images.len();
    Ok(())
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
