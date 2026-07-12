//! The provenance manifest that every reconstructed artifact carries.
//!
//! A cache reconstruction is **not** a screenshot of what the user saw. The
//! manifest states that limit in machine-readable JSON and, via
//! [`Manifest::banner_html`], as a human-visible banner — enumerating which
//! sub-resources were found in cache (with their own cached timestamps and
//! backend) and which were referenced but missing, so gaps are shown rather
//! than hidden.

use serde::Serialize;

use crate::util::escape_html;

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
    /// A new, empty manifest for an optional target page. The provenance
    /// statement is set verbatim so it can never be silently dropped.
    #[must_use]
    pub fn new(target_url: Option<String>) -> Self {
        Self {
            provenance: PROVENANCE_BANNER.to_string(),
            target_url,
            found: Vec::new(),
            missing: Vec::new(),
        }
    }

    /// Record a found sub-resource.
    pub fn add_found(&mut self, found: FoundResource) {
        self.found.push(found);
    }

    /// Record a missing sub-resource.
    pub fn add_missing(&mut self, missing: MissingResource) {
        self.missing.push(missing);
    }

    /// Serialize the manifest to pretty JSON. Serialization of this plain,
    /// owned structure cannot fail; on the impossible error path an error
    /// object is emitted rather than panicking.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self)
            .unwrap_or_else(|e| format!("{{\"error\":\"manifest serialization failed: {e}\"}}"))
    }

    /// Render the human-visible provenance banner as a self-contained HTML
    /// fragment: the verbatim honesty statement, then a collapsible manifest
    /// listing every found sub-resource (URL, backend, cached timestamp) and
    /// every referenced-but-missing one (shown as an explicit gap).
    #[must_use]
    pub fn banner_html(&self) -> String {
        let mut s = String::new();
        s.push_str(
            "<div style=\"all:initial;display:block;font-family:system-ui,-apple-system,\
             sans-serif;background:#3a1d1d;color:#f6d5d5;border:2px solid #b23b3b;\
             border-radius:6px;padding:12px 16px;margin:0 0 16px 0;line-height:1.4\">",
        );
        s.push_str("<strong style=\"display:block;font-size:15px;margin-bottom:6px\">");
        s.push_str("⚠ Cache reconstruction — NOT a rendered capture</strong>");
        s.push_str("<div style=\"font-size:13px\">");
        s.push_str(&escape_html(PROVENANCE_BANNER));
        s.push_str("</div>");
        if let Some(t) = &self.target_url {
            s.push_str("<div style=\"font-size:12px;margin-top:6px;opacity:.85\">Target page: ");
            s.push_str(&escape_html(t));
            s.push_str("</div>");
        }

        s.push_str("<details style=\"margin-top:8px;font-size:12px\"><summary>");
        s.push_str(&format!(
            "Manifest: {} sub-resource(s) found in cache, {} referenced but MISSING",
            self.found.len(),
            self.missing.len()
        ));
        s.push_str("</summary>");

        if !self.found.is_empty() {
            s.push_str("<div style=\"margin-top:6px\"><em>Found in cache:</em><ul>");
            for f in &self.found {
                s.push_str("<li>");
                s.push_str(&escape_html(&f.url));
                s.push_str(&format!(
                    " <span style=\"opacity:.7\">[{}",
                    escape_html(&f.source)
                ));
                if let Some(ts) = f.cached_time_ns {
                    s.push_str(&format!(", cached_time_ns={ts}"));
                }
                s.push_str("]</span></li>");
            }
            s.push_str("</ul></div>");
        }

        s.push_str("<div style=\"margin-top:6px\"><em>Referenced but MISSING from cache:</em>");
        if self.missing.is_empty() {
            s.push_str(" <span style=\"opacity:.7\">(none)</span></div>");
        } else {
            s.push_str("<ul>");
            for m in &self.missing {
                s.push_str("<li>MISSING ");
                s.push_str(&escape_html(&m.url));
                s.push_str(&format!(
                    " <span style=\"opacity:.7\">({})</span></li>",
                    escape_html(&m.referenced_as)
                ));
            }
            s.push_str("</ul></div>");
        }
        s.push_str("</details></div>");
        s
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
