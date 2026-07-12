//! The provenance manifest that every reconstructed artifact carries.
//!
//! A cache reconstruction is **not** a screenshot of what the user saw. The
//! manifest states that limit in machine-readable JSON and, via
//! [`Manifest::banner_html`], as a human-visible banner — enumerating which
//! sub-resources were found in cache (with their own cached timestamps and
//! backend) and which were referenced but missing, so gaps are shown rather
//! than hidden.

use serde::Serialize;

/// The provenance statement carried, verbatim, by every reconstructed artifact.
pub const PROVENANCE_BANNER: &str = "Reconstructed from cached resources — partial, not a rendered capture; JS-generated/lazy-loaded/auth-gated content may be absent; component resources may carry different cache timestamps.";

/// A sub-resource that was located in the cache and inlined/included.
#[derive(Debug, Clone, Serialize)]
pub struct FoundResource {
    /// The absolute resource URL.
    pub url: String,
    /// The cache backend it was recovered from.
    pub source: String,
    /// This resource's own cached timestamp (Unix nanoseconds), if known.
    pub cached_time_ns: Option<i64>,
    /// The resource `Content-Type`, if known.
    pub content_type: Option<String>,
}

/// A sub-resource that the page referenced but which was absent from the cache.
#[derive(Debug, Clone, Serialize)]
pub struct MissingResource {
    /// The absolute resource URL that could not be found.
    pub url: String,
    /// How the page referenced it (e.g. `img[src]`, `link[stylesheet]`).
    pub referenced_as: String,
}

/// The provenance manifest for one reconstructed page (or a whole cache).
#[derive(Debug, Clone, Serialize)]
pub struct Manifest {
    /// The verbatim provenance statement ([`PROVENANCE_BANNER`]).
    pub provenance: String,
    /// The page URL being reconstructed, if this manifest is page-scoped.
    pub target_url: Option<String>,
    /// Sub-resources found in cache and included.
    pub found: Vec<FoundResource>,
    /// Sub-resources referenced but missing from cache.
    pub missing: Vec<MissingResource>,
}

impl Manifest {
    /// A new, empty manifest for an optional target page (RED stub).
    #[must_use]
    pub fn new(_target_url: Option<String>) -> Self {
        Self {
            provenance: String::new(),
            target_url: None,
            found: Vec::new(),
            missing: Vec::new(),
        }
    }

    /// Record a found sub-resource (RED stub).
    pub fn add_found(&mut self, _found: FoundResource) {}

    /// Record a missing sub-resource (RED stub).
    pub fn add_missing(&mut self, _missing: MissingResource) {}

    /// Serialize the manifest to pretty JSON (RED stub).
    #[must_use]
    pub fn to_json(&self) -> String {
        String::new()
    }

    /// Render the human-visible provenance banner as an HTML fragment (RED stub).
    #[must_use]
    pub fn banner_html(&self) -> String {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_manifest_carries_verbatim_provenance() {
        let m = Manifest::new(Some("https://ex.com/".into()));
        assert_eq!(m.provenance, PROVENANCE_BANNER);
        assert_eq!(m.target_url.as_deref(), Some("https://ex.com/"));
    }

    #[test]
    fn json_contains_provenance_and_both_lists() {
        let mut m = Manifest::new(None);
        m.add_found(FoundResource {
            url: "https://ex.com/a.css".into(),
            source: "chromium-simplecache".into(),
            cached_time_ns: Some(123),
            content_type: Some("text/css".into()),
        });
        m.add_missing(MissingResource {
            url: "https://ex.com/b.js".into(),
            referenced_as: "script[src]".into(),
        });
        let json = m.to_json();
        assert!(json.contains("Reconstructed from cached resources"));
        assert!(json.contains("https://ex.com/a.css"));
        assert!(json.contains("https://ex.com/b.js"));
        assert!(json.contains("\"found\""));
        assert!(json.contains("\"missing\""));
    }

    #[test]
    fn banner_html_is_human_visible_and_shows_gaps() {
        let mut m = Manifest::new(Some("https://ex.com/".into()));
        m.add_found(FoundResource {
            url: "https://ex.com/a.css".into(),
            source: "chromium-simplecache".into(),
            cached_time_ns: Some(123),
            content_type: Some("text/css".into()),
        });
        m.add_missing(MissingResource {
            url: "https://ex.com/b.js".into(),
            referenced_as: "script[src]".into(),
        });
        let html = m.banner_html();
        // The honesty statement must be visible, verbatim.
        assert!(html.contains("Reconstructed from cached resources"));
        // Both the found asset and the missing gap must be shown.
        assert!(html.contains("https://ex.com/a.css"));
        assert!(html.contains("https://ex.com/b.js"));
        assert!(
            html.to_lowercase().contains("missing"),
            "missing resources must be labelled as gaps"
        );
    }
}
