#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Cross-artifact / cross-browser correlation over the normalized
//! [`browser_forensic_core::BrowserEvent`] stream.
//!
//! This crate is a **read-only consumer** of events already parsed and collected
//! by the readers and the triage layer. It does not open or parse any artifact
//! itself; it correlates what the rest of the suite produced:
//!
//! * [`host`] — derive a *registrable domain* (eTLD+1) from an event's
//!   URL/host-bearing fields, via a documented heuristic (no external
//!   public-suffix list).
//!
//! ## What correlation is — and is not
//!
//! Correlation here is **co-occurrence by URL / host / time**: a fact about the
//! collected data, not proof of causation, intent, or a user's deliberate act.
//! A referrer/redirect edge reflects exactly what a browser's own `visits`
//! linkage recorded (M3 reconstruction); a co-occurrence edge means only "these
//! hosts appear within N seconds of each other", never that the user navigated
//! from one to the other.

pub mod graph;
pub mod host;
pub mod rollup;
pub mod timeline;
