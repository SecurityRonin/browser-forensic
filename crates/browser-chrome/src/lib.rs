//! Chromium-family (Chrome, Edge, Brave, Opera) browser artifact parsers.

pub mod history;

pub use history::parse_history;
