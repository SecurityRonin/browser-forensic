//! Cached-image gallery reconstruction.
//!
//! Collects every `image/*` resource in the cache index into a gallery: each
//! entry carries its URL, cache source, own cached timestamp, byte length, a
//! sanitized on-disk filename, and (cheaply, from the header only) its pixel
//! dimensions. [`gallery_index_html`] renders a simple browsable page, and the
//! whole set is described by a provenance [`Manifest`].

use crate::index::ResourceIndex;
use crate::manifest::Manifest;

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

/// Build a gallery from every `image/*` resource in the index (RED stub).
#[must_use]
pub fn build_gallery(_index: &ResourceIndex) -> Gallery {
    Gallery {
        images: Vec::new(),
        manifest: Manifest::new(None),
    }
}

/// Render the gallery as a self-contained browsable HTML index (RED stub).
#[must_use]
pub fn gallery_index_html(_gallery: &Gallery) -> String {
    String::new()
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
