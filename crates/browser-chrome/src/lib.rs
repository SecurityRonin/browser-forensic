//! Chromium-family (Chrome, Edge, Brave, Opera) browser artifact parsers.

pub mod history;
pub mod cookies;
pub mod downloads;

pub use history::parse_history;
pub use cookies::parse_cookies;
pub use downloads::parse_downloads;
