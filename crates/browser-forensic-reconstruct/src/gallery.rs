//! Cached-image gallery reconstruction.
//!
//! Collects every `image/*` resource in the cache index into a gallery: each
//! entry carries its URL, cache source, own cached timestamp, byte length, a
//! sanitized on-disk filename, and (cheaply, from the header only) its pixel
//! dimensions. [`gallery_index_html`] renders a simple browsable page, and the
//! whole set is described by a provenance [`Manifest`].

use std::collections::HashSet;

use imagesize::blob_size;

use crate::index::ResourceIndex;
use crate::manifest::{FoundResource, Manifest};
use crate::util::escape_html;

/// Map a content-type to a conventional file extension.
fn ext_from_content_type(content_type: Option<&str>) -> &'static str {
    let ct = content_type
        .and_then(|c| c.split(';').next())
        .map_or("", str::trim)
        .to_ascii_lowercase();
    match ct.as_str() {
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/svg+xml" => "svg",
        "image/bmp" => "bmp",
        "image/x-icon" | "image/vnd.microsoft.icon" => "ico",
        "image/avif" => "avif",
        "image/tiff" => "tiff",
        _ => "img",
    }
}

/// The last path segment of a URL, without the query or fragment.
fn base_name(url: &str) -> String {
    let no_frag = url.split('#').next().unwrap_or(url);
    let no_query = no_frag.split('?').next().unwrap_or(no_frag);
    no_query
        .rsplit('/')
        .find(|s| !s.is_empty())
        .unwrap_or("")
        .to_string()
}

/// Keep only filename-safe characters, capping the length.
fn sanitize(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if out.trim_matches(['.', '_']).is_empty() {
        out = "image".to_string();
    }
    out
}

/// A sanitized, collision-free filename for image index `i`.
fn unique_filename(
    i: usize,
    url: &str,
    content_type: Option<&str>,
    used: &mut HashSet<String>,
) -> String {
    let base = sanitize(&base_name(url));
    let with_ext = if base.contains('.') {
        base
    } else {
        format!("{base}.{}", ext_from_content_type(content_type))
    };
    let mut candidate = format!("{i:04}_{with_ext}");
    let mut n = 1usize;
    while !used.insert(candidate.clone()) {
        candidate = format!("{i:04}_{n}_{with_ext}");
        n += 1;
    }
    candidate
}

/// One cached image in the gallery.
#[derive(Debug, Clone)]
pub struct GalleryImage {
    /// The image URL (its cache key).
    pub url: String,
    /// The cache backend it was recovered from.
    pub source: String,
    /// The image's own cached timestamp (Unix nanoseconds), if known.
    pub cached_time_ns: Option<i64>,
    /// The `Content-Type`, if known.
    pub content_type: Option<String>,
    /// Pixel width, if cheaply derivable from the image header.
    pub width: Option<u32>,
    /// Pixel height, if cheaply derivable from the image header.
    pub height: Option<u32>,
    /// A sanitized, collision-free filename for the on-disk image copy.
    pub filename: String,
    /// The image body length in bytes.
    pub byte_len: usize,
}

/// A cached-image gallery: the images plus a provenance manifest.
#[derive(Debug, Clone)]
pub struct Gallery {
    /// The gallery images, in index order.
    pub images: Vec<GalleryImage>,
    /// The provenance manifest (every image recorded as found).
    pub manifest: Manifest,
}

/// Build a gallery from every `image/*` resource in the index. Pixel
/// dimensions are read cheaply from the image header (`None` when the header
/// is unparseable — the image is still listed).
#[must_use]
pub fn build_gallery(index: &ResourceIndex) -> Gallery {
    let mut manifest = Manifest::new(None);
    let mut images = Vec::new();
    let mut used = HashSet::new();
    for (i, res) in index.images().into_iter().enumerate() {
        let (width, height) = match blob_size(&res.body) {
            Ok(s) => (u32::try_from(s.width).ok(), u32::try_from(s.height).ok()),
            Err(_) => (None, None),
        };
        let filename = unique_filename(i, &res.url, res.content_type.as_deref(), &mut used);
        manifest.add_found(FoundResource {
            url: res.url.clone(),
            source: res.source.label().to_string(),
            cached_time_ns: res.cached_time_ns,
            content_type: res.content_type.clone(),
        });
        images.push(GalleryImage {
            url: res.url.clone(),
            source: res.source.label().to_string(),
            cached_time_ns: res.cached_time_ns,
            content_type: res.content_type.clone(),
            width,
            height,
            filename,
            byte_len: res.body.len(),
        });
    }
    Gallery { images, manifest }
}

/// Render the gallery as a self-contained browsable HTML index. Images are
/// referenced by their `filename` (written alongside this page by the caller).
#[must_use]
pub fn gallery_index_html(gallery: &Gallery) -> String {
    let mut s = String::new();
    s.push_str(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <title>Cached image gallery</title><style>\
         body{font-family:system-ui,-apple-system,sans-serif;margin:16px}\
         .grid{display:flex;flex-wrap:wrap;gap:12px}\
         figure{margin:0;border:1px solid #ccc;border-radius:6px;padding:8px;width:230px}\
         img{max-width:214px;max-height:214px;display:block}\
         figcaption{font-size:11px;word-break:break-all;margin-top:6px;color:#333}\
         </style></head><body>",
    );
    s.push_str(&gallery.manifest.banner_html());
    s.push_str(&format!(
        "<p>{} cached image(s) recovered.</p><div class=\"grid\">",
        gallery.images.len()
    ));
    for img in &gallery.images {
        s.push_str("<figure>");
        s.push_str(&format!(
            "<img src=\"{}\" loading=\"lazy\" alt=\"{}\">",
            escape_html(&img.filename),
            escape_html(&img.url)
        ));
        s.push_str("<figcaption>");
        s.push_str(&escape_html(&img.url));
        s.push_str(&format!(
            "<br>{} · {} bytes",
            escape_html(&img.source),
            img.byte_len
        ));
        if let (Some(w), Some(h)) = (img.width, img.height) {
            s.push_str(&format!(" · {w}×{h}"));
        }
        if let Some(ts) = img.cached_time_ns {
            s.push_str(&format!("<br>cached_time_ns={ts}"));
        }
        s.push_str("</figcaption></figure>");
    }
    s.push_str("</div></body></html>");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{CacheSource, IndexedResource};
    use std::path::PathBuf;

    fn tiny_png(w: u32, h: u32) -> Vec<u8> {
        let mut b = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        b.extend_from_slice(&[0, 0, 0, 13]); // IHDR length
        b.extend_from_slice(b"IHDR");
        b.extend_from_slice(&w.to_be_bytes());
        b.extend_from_slice(&h.to_be_bytes());
        b.extend_from_slice(&[8, 2, 0, 0, 0]); // depth/colour/compression/filter/interlace
        b
    }

    fn r(url: &str, ct: &str, body: &[u8]) -> IndexedResource {
        IndexedResource {
            url: url.to_string(),
            source: CacheSource::FirefoxCache2,
            cached_time_ns: Some(1_700_000_000_000_000_000),
            content_type: Some(ct.to_string()),
            http_status: Some(200),
            status_line: Some("HTTP/1.1 200 OK".to_string()),
            headers: Vec::new(),
            body: body.to_vec(),
            source_file: PathBuf::from("/tmp/x_0"),
        }
    }

    fn sample() -> ResourceIndex {
        let mut idx = ResourceIndex::new();
        idx.insert(r("https://ex.com/", "text/html", b"<html>"));
        idx.insert(r("https://ex.com/photo.png", "image/png", &tiny_png(2, 3)));
        idx.insert(r("https://ex.com/icon.gif", "image/gif", b"GIF")); // too short → no dims
        idx.insert(r("https://ex.com/s.css", "text/css", b"x{}"));
        idx
    }

    #[test]
    fn collects_only_images() {
        let g = build_gallery(&sample());
        assert_eq!(g.images.len(), 2);
        let urls: Vec<&str> = g.images.iter().map(|i| i.url.as_str()).collect();
        assert!(urls.contains(&"https://ex.com/photo.png"));
        assert!(urls.contains(&"https://ex.com/icon.gif"));
    }

    #[test]
    fn dimensions_parsed_when_cheap() {
        let g = build_gallery(&sample());
        let png = g
            .images
            .iter()
            .find(|i| i.url.ends_with("photo.png"))
            .unwrap();
        assert_eq!(png.width, Some(2));
        assert_eq!(png.height, Some(3));
        // An unparseable image yields no dimensions but is still listed.
        let gif = g
            .images
            .iter()
            .find(|i| i.url.ends_with("icon.gif"))
            .unwrap();
        assert_eq!(gif.width, None);
    }

    #[test]
    fn manifest_records_images_as_found_with_provenance() {
        let g = build_gallery(&sample());
        assert!(g
            .manifest
            .provenance
            .contains("Reconstructed from cached resources"));
        assert_eq!(g.manifest.found.len(), 2);
    }

    #[test]
    fn filenames_are_unique() {
        let g = build_gallery(&sample());
        let a = &g.images[0].filename;
        let b = &g.images[1].filename;
        assert_ne!(a, b);
        assert!(!a.is_empty() && !b.is_empty());
    }

    #[test]
    fn index_html_has_banner_and_references_each_image() {
        let g = build_gallery(&sample());
        let html = gallery_index_html(&g);
        assert!(html.contains("Reconstructed from cached resources"));
        for img in &g.images {
            assert!(
                html.contains(&img.filename),
                "gallery must reference {}",
                img.filename
            );
            assert!(html.contains(&img.url), "gallery must show the source URL");
        }
    }
}
