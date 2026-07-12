#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Search, filter, and entity/IOC extraction over normalized [`BrowserEvent`]s.
//!
//! A read-only analysis layer that never touches the source artifacts again:
//! it operates purely on the [`BrowserEvent`] rows the collector already
//! produced (and, optionally, cached-body text passed in as untrusted bytes).
//!
//! - [`filter`] — substring / regex search across an event's textual fields,
//!   with field scoping and a `[from, to]` timestamp window.
//!
//! All entity matches this crate reports are **candidates**: a string that
//! matches the shape (and, where cheap, a checksum) of the entity. They are
//! never asserted to *be* a real card, wallet, or address.

pub mod filter;

pub use filter::{filter_events, EventQuery, Pattern};
