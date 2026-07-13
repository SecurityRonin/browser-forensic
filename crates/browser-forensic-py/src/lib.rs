//! Python bindings for `browser-forensic` (`br4n6`).
//!
//! A thin binding layer over `browser-forensic-triage` and
//! `browser-forensic-discovery` — no parsing logic lives here. It exposes two
//! read-only entry points that return plain Python objects (dicts / lists) so
//! callers can pipe browser artifacts straight into pandas, notebooks, or their
//! own pipelines:
//!
//! * [`discover_profiles`] — locate browser profiles under a home directory.
//! * [`parse_profile`] — parse one profile directory into a triage-report dict
//!   whose `events` are [`BrowserEvent`](browser_forensic_core::BrowserEvent)
//!   dicts.
//!
//! Follow-ups deferred by design (Milestone 9 scope is Python + JSON Schema): a
//! C ABI (`cdylib` + `cbindgen` header) and a WASM/`wasm-bindgen` build.

#![deny(unsafe_code)]

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

use browser_forensic_core::BrowserFamily;

/// Map a case-insensitive family string to [`BrowserFamily`], failing loud on an
/// unrecognized value (the offending string is echoed back).
fn parse_family(browser: &str) -> PyResult<BrowserFamily> {
    match browser.to_ascii_lowercase().as_str() {
        "chromium" | "chrome" => Ok(BrowserFamily::Chromium),
        "firefox" | "gecko" => Ok(BrowserFamily::Firefox),
        "safari" | "webkit" => Ok(BrowserFamily::Safari),
        other => Err(PyValueError::new_err(format!(
            "unknown browser family {other:?}; expected one of: chromium, firefox, safari"
        ))),
    }
}

/// Convert any serde-`Serialize` value into a Python object (dict / list / …).
fn to_py<T: serde::Serialize>(py: Python<'_>, value: &T, what: &str) -> PyResult<Py<PyAny>> {
    let json = serde_json::to_value(value)
        .map_err(|e| PyRuntimeError::new_err(format!("serialize {what}: {e}")))?;
    pythonize::pythonize(py, &json)
        .map(pyo3::Bound::unbind)
        .map_err(|e| PyRuntimeError::new_err(format!("convert {what} to python: {e}")))
}

/// Discover browser profiles under `home_dir`.
///
/// Returns a list of profile dicts (`browser`, `name`, `path`, `container`).
#[pyfunction]
fn discover_profiles(py: Python<'_>, home_dir: &str) -> PyResult<Py<PyAny>> {
    let profiles = browser_forensic_discovery::discover_profiles(std::path::Path::new(home_dir));
    to_py(py, &profiles, "profiles")
}

/// Parse a single browser profile directory into a triage-report dict.
///
/// `browser` is one of `chromium` / `firefox` / `safari` (case-insensitive).
/// The returned dict carries `events` (a list of `BrowserEvent` dicts), plus
/// `carved`, `integrity`, `profiles`, and `generated_at_ns`.
#[pyfunction]
fn parse_profile(py: Python<'_>, profile_path: &str, browser: &str) -> PyResult<Py<PyAny>> {
    let family = parse_family(browser)?;
    let report =
        browser_forensic_triage::triage_profile(std::path::Path::new(profile_path), family)
            .map_err(|e| PyRuntimeError::new_err(format!("parse_profile failed: {e:#}")))?;
    to_py(py, &report, "report")
}

/// The `browser_forensic` Python module.
#[pymodule]
fn browser_forensic(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(discover_profiles, m)?)?;
    m.add_function(wrap_pyfunction!(parse_profile, m)?)?;
    Ok(())
}
