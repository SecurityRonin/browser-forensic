//! Structured, process-attributed browser-artifact carving from a memory image.
//!
//! This rides on the fleet [`memory-forensic`](https://github.com/SecurityRonin/memory-forensic)
//! (`memf`) framework instead of scanning a whole buffer blind:
//!
//! 1. [`memf_format::open_dump_with_raw_fallback`] opens the image (raw/LiME/AVML/crash-dump).
//! 2. Symbols are resolved from an ISF file or auto-profiled from the kernel PDB
//!    ([`memf_symbols::AutoProfile`]); [`memf_session::build_analysis_context`]
//!    recovers the OS, DTB/CR3, and `PsActiveProcessHead`.
//! 3. A [`VirtualAddressSpace`] + [`ObjectReader`] drive memf's Windows browser
//!    walkers ([`memf_windows::browser_sessions`] / [`memf_windows::browser_cookies`]),
//!    which enumerate `_EPROCESS`, filter browser processes, and scan each
//!    process's committed heap.
//!
//! Every event is tagged with the **owning pid and process image name** —
//! Volatility-style attribution a whole-image byte scan cannot provide.
//!
//! # What is structurally recovered vs. best-effort
//!
//! - **Structurally recovered:** the process list (page-table-translated
//!   `_EPROCESS` walk) and per-process heap membership. An extracted URL or
//!   cookie is attributed to a *named process at a known pid* — not merely
//!   "present somewhere in the image".
//! - **Best-effort within a process:** the artifacts themselves are still
//!   pattern-scanned from heap bytes (URL and `Set-Cookie`/Netscape-jar
//!   patterns). Reconstructing complete history/cookie SQLite DBs from
//!   in-memory `_CACHE_` structures is out of scope.
//!
//! When the image has no resolvable process structure (a raw buffer, or a
//! non-Windows image), this fails with a [`MemoryCarveError::is_degradable`]
//! error so the caller can fall back to the raw [`crate::scan_bytes_for_urls`] /
//! [`crate::scan_bytes_for_cookies`] byte scan. A genuine bootstrap failure
//! (unreadable image, or a Windows image with no usable profile) fails loud.

use std::path::Path;
use std::sync::Arc;

use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use memf_core::object_reader::ObjectReader;
use memf_core::vas::{TranslationMode, VirtualAddressSpace};
use memf_format::PhysicalMemoryProvider;
use memf_session::OsProfile;
use memf_symbols::SymbolResolver;
use serde_json::json;

/// Failure modes of [`carve_memory_image`].
///
/// [`is_degradable`](MemoryCarveError::is_degradable) separates the two policy
/// classes: a **hard bootstrap failure** (fail loud, non-zero) from a case the
/// caller may **degrade** to a raw byte scan (loud warning, never silent empty).
#[derive(Debug, thiserror::Error)]
pub enum MemoryCarveError {
    /// The image file could not be opened (missing, unreadable, unrecognized).
    /// A hard bootstrap failure — never silently degraded.
    #[error("cannot open memory image {path}: {source}")]
    Open {
        /// The image path, verbatim.
        path: String,
        /// The underlying open error.
        source: anyhow::Error,
    },

    /// The image is a recognized Windows OS image but no usable profile could be
    /// established (no symbols, or the `_EPROCESS` walk failed). Fails loud so
    /// the analyst supplies `--symbols <ISF>` rather than seeing a false empty.
    #[error("Windows image but no usable profile: {0}")]
    NoProfile(String),

    /// The image has no recognizable OS/process structure (a raw buffer). The
    /// caller should degrade to a raw byte scan.
    #[error("no OS/process structure in image ({0}); raw byte-scan fallback applies")]
    NotAnOsImage(String),

    /// A recognized OS with no browser-process walker yet (Linux/macOS). The
    /// caller should degrade to a raw byte scan of the whole image.
    #[error(
        "process-attributed browser carve is Windows-only today; {os} image not yet supported"
    )]
    UnsupportedOs {
        /// The detected OS name.
        os: String,
    },
}

impl MemoryCarveError {
    /// Whether the caller may degrade to a raw byte scan (loud) instead of
    /// failing loud. `true` for "not an OS image" and "unsupported OS"; `false`
    /// for open failures and Windows-with-no-profile (both fail loud).
    #[must_use]
    pub fn is_degradable(&self) -> bool {
        matches!(self, Self::NotAnOsImage(_) | Self::UnsupportedOs { .. })
    }
}

/// Classify a process image name into a [`BrowserFamily`], or `None` for a
/// non-browser process. Case-insensitive.
#[must_use]
pub fn browser_family_for_process(image_name: &str) -> Option<BrowserFamily> {
    let name = image_name.to_ascii_lowercase();
    match name.as_str() {
        "chrome.exe" | "msedge.exe" | "brave.exe" | "opera.exe" | "vivaldi.exe"
        | "chromium.exe" => Some(BrowserFamily::Chromium),
        "firefox.exe" => Some(BrowserFamily::Firefox),
        _ => None,
    }
}

/// Carve process-attributed browser artifacts from a memory image, auto-resolving
/// symbols from the kernel PDB where possible.
///
/// Equivalent to [`carve_memory_image_with_symbols`] with no ISF file.
///
/// # Errors
/// See [`MemoryCarveError`]. Bootstrap failures fail loud; a raw/unsupported
/// image returns a [`MemoryCarveError::is_degradable`] error.
pub fn carve_memory_image(path: &Path) -> Result<Vec<BrowserEvent>, MemoryCarveError> {
    carve_memory_image_with_symbols(path, None)
}

/// Carve process-attributed browser artifacts from a memory image.
///
/// `isf` is an optional Volatility-3 ISF symbol file. When `None`, symbols are
/// auto-profiled from the dump (kernel PDB; may need network + a symbol cache).
///
/// # Errors
/// See [`MemoryCarveError`].
pub fn carve_memory_image_with_symbols(
    path: &Path,
    isf: Option<&Path>,
) -> Result<Vec<BrowserEvent>, MemoryCarveError> {
    // 1. Open the image. An I/O / unrecognized-format failure is a hard bootstrap
    //    failure (fail loud), never a silent empty.
    let boxed =
        memf_format::open_dump_with_raw_fallback(path).map_err(|e| MemoryCarveError::Open {
            path: path.display().to_string(),
            source: anyhow::Error::new(e),
        })?;
    // Arc so the browser walkers (which clone the provider per process to build a
    // per-process address space) satisfy their `P: PhysicalMemoryProvider + Clone`.
    let provider: Arc<dyn PhysicalMemoryProvider> = Arc::from(boxed);

    // 2. Symbols + OS/DTB/list-head bootstrap.
    let resolver = resolve_symbols(&provider, isf)?;
    let metadata = provider.metadata();

    let os = memf_session::detect_os(metadata.as_ref(), resolver.as_ref())
        .map_err(|e| MemoryCarveError::NotAnOsImage(e.to_string()))?;
    if os != OsProfile::Windows {
        return Err(MemoryCarveError::UnsupportedOs { os: os.to_string() });
    }

    let ctx = memf_session::build_analysis_context(
        metadata.as_ref(),
        resolver.as_ref(),
        provider.as_ref(),
    )
    .map_err(|e| MemoryCarveError::NoProfile(e.to_string()))?;

    let head = ctx.ps_active_process_head.ok_or_else(|| {
        MemoryCarveError::NoProfile(
            "PsActiveProcessHead unresolved (no header value, no symbol RVA); supply --symbols <ISF>"
                .to_string(),
        )
    })?;

    // 3. Build the virtual-address reader and drive memf's browser walkers.
    //    x86-64 4-level paging, matching the memf binary / 4n6mount default.
    let vas = VirtualAddressSpace::new(provider, ctx.cr3, TranslationMode::X86_64FourLevel);
    let reader = ObjectReader::new(vas, resolver);

    let mut events = Vec::new();

    let sessions =
        memf_windows::browser_sessions::walk_browser_sessions(&reader, head).map_err(|e| {
            MemoryCarveError::NoProfile(format!("browser session (URL) walk failed: {e}"))
        })?;
    for s in sessions {
        events.push(url_event(s.pid, &s.image_name, &s.url, &s.source_hint));
    }

    let cookies = memf_windows::browser_cookies::walk_browser_cookies(&reader, head)
        .map_err(|e| MemoryCarveError::NoProfile(format!("browser cookie walk failed: {e}")))?;
    for c in cookies {
        events.push(cookie_event(
            c.pid,
            &c.image_name,
            &c.domain,
            &c.name,
            &c.value,
            c.path.as_deref(),
            c.encrypted,
        ));
    }

    Ok(events)
}

/// Distinct browser processes referenced by a carved event set, as
/// `(pid, image_name)` — a convenience for callers reporting attribution.
#[must_use]
pub fn browser_processes(events: &[BrowserEvent]) -> Vec<(u64, String)> {
    let mut seen = std::collections::BTreeSet::new();
    for ev in events {
        let pid = ev.attrs.get("pid").and_then(serde_json::Value::as_u64);
        let proc = ev
            .attrs
            .get("process")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        if let (Some(pid), Some(proc)) = (pid, proc) {
            seen.insert((pid, proc));
        }
    }
    seen.into_iter().collect()
}

/// Resolve a symbol backend: an explicit ISF file (fail loud if unreadable), or
/// auto-profile from the dump, degrading to an empty resolver if the kernel PDB
/// cannot be acquired (the caller surfaces a clear "no profile" error later).
fn resolve_symbols(
    provider: &Arc<dyn PhysicalMemoryProvider>,
    isf: Option<&Path>,
) -> Result<Box<dyn SymbolResolver>, MemoryCarveError> {
    if let Some(p) = isf {
        return memf_symbols::isf::IsfResolver::from_path(p)
            .map(|r| Box::new(r) as Box<dyn SymbolResolver>)
            .map_err(|e| {
                MemoryCarveError::NoProfile(format!("cannot load ISF symbols {}: {e}", p.display()))
            });
    }

    if let Ok(auto) = memf_symbols::AutoProfile::new() {
        if let Ok(resolver) = auto.from_dump(provider) {
            return Ok(resolver);
        }
    }

    memf_symbols::isf::IsfResolver::from_value(&json!({}))
        .map(|r| Box::new(r) as Box<dyn SymbolResolver>)
        .map_err(|e| MemoryCarveError::NoProfile(format!("empty symbol resolver init failed: {e}")))
}

/// Build a process-attributed URL event (memory-resident tab/navigation URL).
fn url_event(pid: u64, image_name: &str, url: &str, source_hint: &str) -> BrowserEvent {
    let family = browser_family_for_process(image_name).unwrap_or(BrowserFamily::Chromium);
    BrowserEvent::new(
        0,
        family,
        ArtifactKind::Memory,
        format!("memory:{image_name}#{pid}"),
        format!("navigation URL in {image_name} (pid {pid}): {url}"),
    )
    .with_attr("pid", json!(pid))
    .with_attr("process", json!(image_name))
    .with_attr("url", json!(url))
    .with_attr("source_hint", json!(source_hint))
    .with_attr("recovery", json!("structured"))
}

/// Build a process-attributed cookie event.
fn cookie_event(
    pid: u64,
    image_name: &str,
    domain: &str,
    name: &str,
    value: &str,
    path: Option<&str>,
    encrypted: bool,
) -> BrowserEvent {
    let family = browser_family_for_process(image_name).unwrap_or(BrowserFamily::Chromium);
    let mut ev = BrowserEvent::new(
        0,
        family,
        ArtifactKind::Cookies,
        format!("memory:{image_name}#{pid}"),
        format!("cookie {name} for {domain} in {image_name} (pid {pid})"),
    )
    .with_attr("pid", json!(pid))
    .with_attr("process", json!(image_name))
    .with_attr("domain", json!(domain))
    .with_attr("name", json!(name))
    .with_attr("value", json!(value))
    .with_attr("encrypted", json!(encrypted))
    .with_attr("recovery", json!("structured"));
    if let Some(p) = path {
        ev = ev.with_attr("path", json!(p));
    }
    ev
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::Value;

    #[test]
    fn url_event_carries_pid_and_process_attribution() {
        let ev = url_event(1234, "chrome.exe", "https://example.com/a", "url-scan");
        assert_eq!(ev.artifact, ArtifactKind::Memory);
        assert_eq!(ev.browser, BrowserFamily::Chromium);
        assert_eq!(ev.attrs.get("pid").and_then(Value::as_u64), Some(1234));
        assert_eq!(
            ev.attrs.get("process").and_then(Value::as_str),
            Some("chrome.exe")
        );
        assert_eq!(
            ev.attrs.get("url").and_then(Value::as_str),
            Some("https://example.com/a")
        );
        assert_eq!(
            ev.attrs.get("recovery").and_then(Value::as_str),
            Some("structured")
        );
    }

    #[test]
    fn cookie_event_carries_attribution_and_fields() {
        let ev = cookie_event(
            99,
            "firefox.exe",
            ".example.com",
            "sid",
            "abc123",
            Some("/"),
            false,
        );
        assert_eq!(ev.artifact, ArtifactKind::Cookies);
        assert_eq!(ev.browser, BrowserFamily::Firefox);
        assert_eq!(ev.attrs.get("pid").and_then(Value::as_u64), Some(99));
        assert_eq!(
            ev.attrs.get("domain").and_then(Value::as_str),
            Some(".example.com")
        );
        assert_eq!(ev.attrs.get("name").and_then(Value::as_str), Some("sid"));
        assert_eq!(ev.attrs.get("path").and_then(Value::as_str), Some("/"));
        assert_eq!(
            ev.attrs.get("encrypted").and_then(Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn cookie_event_omits_absent_path() {
        let ev = cookie_event(1, "chrome.exe", "d", "n", "v", None, true);
        assert!(!ev.attrs.contains_key("path"));
        assert_eq!(
            ev.attrs.get("encrypted").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn browser_processes_dedups_by_pid_and_name() {
        let evs = vec![
            url_event(10, "chrome.exe", "https://a.com", "url-scan"),
            url_event(10, "chrome.exe", "https://b.com", "url-scan"),
            cookie_event(20, "firefox.exe", "d", "n", "v", None, false),
        ];
        let procs = browser_processes(&evs);
        assert_eq!(
            procs,
            vec![
                (10, "chrome.exe".to_string()),
                (20, "firefox.exe".to_string())
            ]
        );
    }

    #[test]
    fn error_degradability_matches_policy() {
        assert!(MemoryCarveError::NotAnOsImage("x".into()).is_degradable());
        assert!(MemoryCarveError::UnsupportedOs { os: "Linux".into() }.is_degradable());
        assert!(!MemoryCarveError::NoProfile("x".into()).is_degradable());
        assert!(!MemoryCarveError::Open {
            path: "p".into(),
            source: anyhow::anyhow!("io")
        }
        .is_degradable());
    }
}
