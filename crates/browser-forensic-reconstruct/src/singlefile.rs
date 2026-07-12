//! Self-contained single-file HTML reconstruction.
//!
//! Given the cache index and a target page URL, parse the cached HTML and
//! resolve every sub-resource reference (`<link rel=stylesheet>`,
//! `<script src>`, `<img src>`/`srcset`, `<source>`, favicons, and `url(...)`
//! in inline/linked CSS) against the index. Found resources are inlined as
//! `data:` URIs; missing ones are left as visible placeholders and recorded in
//! the manifest. A prominent provenance banner is prepended to the page.
//!
//! Robustness: input HTML is size-capped, the number of inlined sub-resources
//! and the total output size are bounded, and malformed markup is handled
//! lossily (never panics — on any rewrite error the un-inlined body is returned
//! still carrying the banner and manifest).

use std::cell::{Cell, RefCell};
use std::collections::HashSet;

use base64::Engine as _;
use lol_html::html_content::{ContentType, Element, TextChunk};
use lol_html::{element, rewrite_str, text, RewriteStrSettings};

use crate::index::{normalize_url, resolve_ref, IndexedResource, ResourceIndex};
use crate::manifest::{FoundResource, Manifest, MissingResource};
use crate::util::escape_html;

/// Cap on HTML input handed to the rewriter (larger inputs are truncated).
const MAX_HTML_INPUT: usize = 32 * 1024 * 1024;
/// Cap on the number of sub-resources inlined into one page.
const MAX_SUBRESOURCES: usize = 5000;
/// Cap on the total bytes of inlined `data:` URIs emitted for one page.
const MAX_OUTPUT_BYTES: usize = 96 * 1024 * 1024;
/// Cap on the number of `url(...)` rewrites performed in a single CSS text.
const MAX_CSS_URLS: usize = 2000;

/// A reconstructed self-contained page: the HTML plus its provenance manifest.
#[derive(Debug, Clone)]
pub struct ReconstructedPage {
    /// The self-contained HTML (banner prepended, sub-resources inlined).
    pub html: String,
    /// The provenance manifest (found vs missing sub-resources).
    pub manifest: Manifest,
}

/// Mutable rewrite state, threaded through the (single-threaded) lol_html
/// handlers via interior mutability.
struct State<'i> {
    index: &'i ResourceIndex,
    page_base: String,
    manifest: RefCell<Manifest>,
    seen: RefCell<HashSet<String>>,
    emitted: Cell<usize>,
    count: Cell<usize>,
}

impl State<'_> {
    fn budget_ok(&self, add: usize) -> bool {
        self.count.get() < MAX_SUBRESOURCES
            && self.emitted.get().saturating_add(add) <= MAX_OUTPUT_BYTES
    }

    fn note_emitted(&self, n: usize) {
        self.emitted.set(self.emitted.get().saturating_add(n));
        self.count.set(self.count.get().saturating_add(1));
    }

    fn record_found(&self, res: &IndexedResource) {
        if self.seen.borrow_mut().insert(normalize_url(&res.url)) {
            self.manifest.borrow_mut().add_found(FoundResource {
                url: res.url.clone(),
                source: res.source.label().to_string(),
                cached_time_ns: res.cached_time_ns,
                content_type: res.content_type.clone(),
            });
        }
    }

    fn record_missing(&self, url: &str, referenced_as: &str) {
        if self.seen.borrow_mut().insert(normalize_url(url)) {
            self.manifest.borrow_mut().add_missing(MissingResource {
                url: url.to_string(),
                referenced_as: referenced_as.to_string(),
            });
        }
    }
}

fn data_uri(mime: &str, bytes: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    format!("data:{mime};base64,{b64}")
}

/// A small, visible SVG placeholder (`data:` URI) naming the missing resource.
fn missing_placeholder(url: &str) -> String {
    let label = escape_html(url);
    let svg = format!(
        "<svg xmlns='http://www.w3.org/2000/svg' width='220' height='40'>\
         <rect width='100%' height='100%' fill='#f4e0e0' stroke='#b23b3b'/>\
         <text x='6' y='24' font-family='monospace' font-size='10' fill='#b23b3b'>\
         MISSING FROM CACHE</text><title>MISSING: {label}</title></svg>"
    );
    data_uri("image/svg+xml", svg.as_bytes())
}

/// Rewrite every `url(...)` in a CSS text: inline a found target as a `data:`
/// URI (recording it found), record a missing one, and leave `data:`/fragment
/// refs untouched. Bounded by [`MAX_CSS_URLS`]; no recursion (so a circular
/// `@import` cannot loop). Byte-cursor scan kept on char boundaries.
fn rewrite_css_urls(css: &str, css_base: &str, state: &State) -> String {
    let bytes = css.as_bytes();
    let mut out = String::with_capacity(css.len());
    let mut i = 0usize;
    let mut rewrites = 0usize;
    while i < css.len() {
        if rewrites < MAX_CSS_URLS
            && i + 4 <= css.len()
            && bytes[i..i + 4].eq_ignore_ascii_case(b"url(")
        {
            if let Some(close) = css[i + 4..].find(')') {
                let inner = &css[i + 4..i + 4 + close];
                let raw_ref = inner.trim().trim_matches(|c| c == '"' || c == '\'').trim();
                out.push_str("url(");
                if raw_ref.is_empty() || raw_ref.starts_with("data:") || raw_ref.starts_with('#') {
                    out.push_str(inner);
                } else if let Some(res) = state.index.resolve(css_base, raw_ref) {
                    if state.budget_ok(res.body.len()) {
                        let uri = data_uri(res.data_uri_mime(), &res.body);
                        state.note_emitted(uri.len());
                        state.record_found(res);
                        out.push('"');
                        out.push_str(&uri);
                        out.push('"');
                        rewrites += 1;
                    } else {
                        out.push_str(inner);
                    }
                } else {
                    if let Some(abs) = resolve_ref(css_base, raw_ref) {
                        state.record_missing(&abs, "css url()");
                    }
                    out.push_str(inner);
                }
                out.push(')');
                i += 4 + close + 1;
                continue;
            }
        }
        // Not a url(...) start — copy one whole char and advance past it.
        let ch = css[i..].chars().next().unwrap_or('\u{fffd}');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Rewrite an HTML `srcset` value, inlining found candidates and dropping
/// missing ones (which are recorded). Returns the new srcset (possibly empty).
fn rewrite_srcset(srcset: &str, state: &State, referenced_as: &str) -> String {
    let mut kept = Vec::new();
    for candidate in srcset.split(',') {
        let mut parts = candidate.split_whitespace();
        let Some(url_ref) = parts.next() else {
            continue;
        };
        let descriptor = parts.next().unwrap_or("");
        if url_ref.starts_with("data:") {
            kept.push(candidate.trim().to_string());
            continue;
        }
        if let Some(res) = state.index.resolve(&state.page_base, url_ref) {
            if state.budget_ok(res.body.len()) {
                let uri = data_uri(res.data_uri_mime(), &res.body);
                state.note_emitted(uri.len());
                state.record_found(res);
                kept.push(if descriptor.is_empty() {
                    uri
                } else {
                    format!("{uri} {descriptor}")
                });
                continue;
            }
        }
        if let Some(abs) = resolve_ref(&state.page_base, url_ref) {
            state.record_missing(&abs, referenced_as);
        }
    }
    kept.join(", ")
}

fn handle_link(el: &mut Element, state: &State) {
    let rel = el.get_attribute("rel").unwrap_or_default().to_lowercase();
    let rels: Vec<&str> = rel.split_whitespace().collect();
    let Some(href) = el.get_attribute("href") else {
        return;
    };
    if href.trim().is_empty() {
        return;
    }
    el.remove_attribute("integrity");
    if rels.contains(&"stylesheet") {
        if let Some(res) = state.index.resolve(&state.page_base, &href) {
            if state.budget_ok(res.body.len()) {
                let css_base =
                    resolve_ref(&state.page_base, &href).unwrap_or_else(|| state.page_base.clone());
                let css = String::from_utf8_lossy(&res.body);
                let rewritten = rewrite_css_urls(&css, &css_base, state);
                let uri = data_uri("text/css", rewritten.as_bytes());
                state.note_emitted(uri.len());
                state.record_found(res);
                let _ = el.set_attribute("href", &uri);
                return;
            }
        }
        if let Some(abs) = resolve_ref(&state.page_base, &href) {
            state.record_missing(&abs, "link[stylesheet]");
            el.replace(
                &format!("<!-- br4n6: MISSING stylesheet {} -->", escape_html(&abs)),
                ContentType::Html,
            );
        }
    } else if rels.contains(&"icon") || rels.contains(&"shortcut") {
        inline_href_or_mark(el, &href, state, "link[icon]");
    }
}

/// Inline the `href` of a link-like element as a `data:` URI if found, else
/// mark it missing.
fn inline_href_or_mark(el: &mut Element, href: &str, state: &State, referenced_as: &str) {
    if let Some(res) = state.index.resolve(&state.page_base, href) {
        if state.budget_ok(res.body.len()) {
            let uri = data_uri(res.data_uri_mime(), &res.body);
            state.note_emitted(uri.len());
            state.record_found(res);
            let _ = el.set_attribute("href", &uri);
            return;
        }
    }
    if let Some(abs) = resolve_ref(&state.page_base, href) {
        state.record_missing(&abs, referenced_as);
        let _ = el.set_attribute("data-br4n6-missing", &abs);
    }
}

fn handle_script(el: &mut Element, state: &State) {
    let Some(src) = el.get_attribute("src") else {
        return;
    };
    if src.trim().is_empty() || src.starts_with("data:") {
        return;
    }
    el.remove_attribute("integrity");
    el.remove_attribute("crossorigin");
    if let Some(res) = state.index.resolve(&state.page_base, &src) {
        if state.budget_ok(res.body.len()) {
            let mime = res
                .content_type
                .as_deref()
                .unwrap_or("application/javascript");
            let uri = data_uri(mime, &res.body);
            state.note_emitted(uri.len());
            state.record_found(res);
            let _ = el.set_attribute("src", &uri);
            return;
        }
    }
    if let Some(abs) = resolve_ref(&state.page_base, &src) {
        state.record_missing(&abs, "script[src]");
        let _ = el.set_attribute("data-br4n6-missing", &abs);
        el.remove_attribute("src");
    }
}

fn handle_media_src(
    el: &mut Element,
    state: &State,
    referenced_as: &str,
    missing_placeholder_img: bool,
) {
    if let Some(src) = el.get_attribute("src") {
        if !src.trim().is_empty() && !src.starts_with("data:") {
            if let Some(res) = state.index.resolve(&state.page_base, &src) {
                if state.budget_ok(res.body.len()) {
                    let uri = data_uri(res.data_uri_mime(), &res.body);
                    state.note_emitted(uri.len());
                    state.record_found(res);
                    let _ = el.set_attribute("src", &uri);
                } else if let Some(abs) = resolve_ref(&state.page_base, &src) {
                    state.record_missing(&abs, referenced_as);
                }
            } else if let Some(abs) = resolve_ref(&state.page_base, &src) {
                state.record_missing(&abs, referenced_as);
                if missing_placeholder_img {
                    let _ = el.set_attribute("src", &missing_placeholder(&abs));
                    let _ = el.set_attribute("alt", &format!("MISSING FROM CACHE: {abs}"));
                }
                let _ = el.set_attribute("data-br4n6-missing", &abs);
            }
        }
    }
    if let Some(ss) = el.get_attribute("srcset") {
        if !ss.trim().is_empty() {
            let new = rewrite_srcset(&ss, state, referenced_as);
            if new.is_empty() {
                el.remove_attribute("srcset");
            } else {
                let _ = el.set_attribute("srcset", &new);
            }
        }
    }
}

fn handle_style_attr(el: &mut Element, state: &State) {
    if let Some(s) = el.get_attribute("style") {
        if s.to_lowercase().contains("url(") {
            let new = rewrite_css_urls(&s, &state.page_base, state);
            let _ = el.set_attribute("style", &new);
        }
    }
}

fn handle_style_text(t: &mut TextChunk, state: &State) {
    let s = t.as_str();
    if s.to_lowercase().contains("url(") {
        let new = rewrite_css_urls(s, &state.page_base, state);
        t.set_str(new);
    }
}

/// Run the sub-resource inlining pass. On any rewriter error the original HTML
/// is returned unchanged (lossy, never panics) — the banner and manifest are
/// still produced by the caller.
fn inline_pass(html: &str, state: &State) -> String {
    let settings = RewriteStrSettings::new()
        .with_strict(false)
        .append_element_content_handler(element!("link", |el| {
            handle_link(el, state);
            Ok(())
        }))
        .append_element_content_handler(element!("script[src]", |el| {
            handle_script(el, state);
            Ok(())
        }))
        .append_element_content_handler(element!("img", |el| {
            handle_media_src(el, state, "img", true);
            Ok(())
        }))
        .append_element_content_handler(element!("source", |el| {
            handle_media_src(el, state, "source", false);
            Ok(())
        }))
        .append_element_content_handler(element!("[style]", |el| {
            handle_style_attr(el, state);
            Ok(())
        }))
        .append_element_content_handler(text!("style", |t| {
            handle_style_text(t, state);
            Ok(())
        }));
    rewrite_str(html, settings).unwrap_or_else(|_| html.to_string())
}

/// Prepend the provenance banner to `<body>`; if the document has no usable
/// body, prefix it to the whole string so the banner is always present.
fn inject_banner(html: &str, banner: &str) -> String {
    let inserted = Cell::new(false);
    let settings = RewriteStrSettings::new()
        .with_strict(false)
        .append_element_content_handler(element!("body", |el| {
            el.prepend(banner, ContentType::Html);
            inserted.set(true);
            Ok(())
        }));
    match rewrite_str(html, settings) {
        Ok(out) if inserted.get() => out,
        Ok(out) => format!("{banner}{out}"),
        Err(_) => format!("{banner}{html}"),
    }
}

/// Reconstruct a self-contained single-file HTML page for `target_url`.
///
/// Returns `None` when `target_url` is not an HTML document present in the
/// index.
#[must_use]
pub fn reconstruct_singlefile(
    index: &ResourceIndex,
    target_url: &str,
) -> Option<ReconstructedPage> {
    let target = index.get(target_url)?;
    if !target.is_html() {
        return None;
    }
    let base = normalize_url(&target.url);
    let raw = if target.body.len() > MAX_HTML_INPUT {
        &target.body[..MAX_HTML_INPUT]
    } else {
        &target.body[..]
    };
    let html = String::from_utf8_lossy(raw).into_owned();

    let state = State {
        index,
        page_base: base.clone(),
        manifest: RefCell::new(Manifest::new(Some(base))),
        seen: RefCell::new(HashSet::new()),
        emitted: Cell::new(0),
        count: Cell::new(0),
    };

    let inlined = inline_pass(&html, &state);
    let manifest = state.manifest.into_inner();
    let banner = manifest.banner_html();
    let final_html = inject_banner(&inlined, &banner);
    Some(ReconstructedPage {
        html: final_html,
        manifest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{CacheSource, IndexedResource};
    use std::path::PathBuf;

    fn r(url: &str, ct: &str, body: &[u8]) -> IndexedResource {
        IndexedResource {
            url: url.to_string(),
            source: CacheSource::ChromiumSimpleCache,
            cached_time_ns: Some(1_700_000_000_000_000_000),
            content_type: Some(ct.to_string()),
            http_status: Some(200),
            body: body.to_vec(),
            source_file: PathBuf::from("/tmp/x_0"),
        }
    }

    fn sample_index() -> ResourceIndex {
        let mut idx = ResourceIndex::new();
        let html = br#"<!doctype html><html><head>
            <link rel="stylesheet" href="/s.css">
            <script src="/app.js"></script>
            <script src="/gone.js"></script>
            </head><body>
            <img src="/logo.png">
            <img src="/missing.png">
            </body></html>"#;
        idx.insert(r("https://ex.com/", "text/html; charset=utf-8", html));
        idx.insert(r(
            "https://ex.com/s.css",
            "text/css",
            b"body{background:url(/bg.png)}",
        ));
        idx.insert(r(
            "https://ex.com/app.js",
            "application/javascript",
            b"console.log(1)",
        ));
        idx.insert(r("https://ex.com/logo.png", "image/png", b"\x89PNG-logo"));
        idx.insert(r("https://ex.com/bg.png", "image/png", b"\x89PNG-bg"));
        idx
    }

    #[test]
    fn unknown_target_returns_none() {
        let idx = sample_index();
        assert!(reconstruct_singlefile(&idx, "https://ex.com/nope").is_none());
    }

    #[test]
    fn banner_is_prepended() {
        let idx = sample_index();
        let page = reconstruct_singlefile(&idx, "https://ex.com/").unwrap();
        assert!(page.html.contains("Reconstructed from cached resources"));
    }

    #[test]
    fn present_subresources_are_inlined() {
        let idx = sample_index();
        let page = reconstruct_singlefile(&idx, "https://ex.com/").unwrap();
        // The original relative references are replaced by data: URIs.
        assert!(
            page.html.contains("data:image/png;base64,"),
            "image inlined"
        );
        assert!(
            page.html.contains("data:application/javascript;base64,"),
            "script inlined"
        );
        // Stylesheet inlined as a data:text/css URI with its url(bg.png) rewritten.
        assert!(
            page.html.contains("data:text/css;base64,"),
            "stylesheet inlined as data:text/css"
        );
        // The found set covers every present sub-resource, including the CSS's bg.png.
        let found: Vec<&str> = page.manifest.found.iter().map(|f| f.url.as_str()).collect();
        for u in [
            "https://ex.com/s.css",
            "https://ex.com/app.js",
            "https://ex.com/logo.png",
            "https://ex.com/bg.png",
        ] {
            assert!(found.contains(&u), "manifest.found must include {u}");
        }
    }

    #[test]
    fn missing_subresources_are_shown_as_gaps() {
        let idx = sample_index();
        let page = reconstruct_singlefile(&idx, "https://ex.com/").unwrap();
        let missing: Vec<&str> = page
            .manifest
            .missing
            .iter()
            .map(|m| m.url.as_str())
            .collect();
        assert!(missing.contains(&"https://ex.com/missing.png"));
        assert!(missing.contains(&"https://ex.com/gone.js"));
        // The missing image leaves a visible marker in the HTML.
        assert!(
            page.html.to_lowercase().contains("missing"),
            "missing resource must leave a visible placeholder"
        );
    }

    #[test]
    fn malformed_html_does_not_panic() {
        let mut idx = ResourceIndex::new();
        idx.insert(r(
            "https://ex.com/",
            "text/html",
            b"<html><body><img src=\"/x.png\" <<< <script src=unclosed",
        ));
        let page = reconstruct_singlefile(&idx, "https://ex.com/").unwrap();
        assert!(page.html.contains("Reconstructed from cached resources"));
    }

    #[test]
    fn circular_css_import_terminates() {
        let mut idx = ResourceIndex::new();
        idx.insert(r(
            "https://ex.com/",
            "text/html",
            b"<html><head><link rel=stylesheet href=/a.css></head><body></body></html>",
        ));
        // a.css imports b.css imports a.css — must not loop.
        idx.insert(r(
            "https://ex.com/a.css",
            "text/css",
            b"@import url(/b.css);",
        ));
        idx.insert(r(
            "https://ex.com/b.css",
            "text/css",
            b"@import url(/a.css);",
        ));
        let page = reconstruct_singlefile(&idx, "https://ex.com/").unwrap();
        assert!(page.html.contains("Reconstructed from cached resources"));
    }
}
