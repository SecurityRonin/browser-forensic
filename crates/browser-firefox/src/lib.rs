//! Firefox/Gecko browser artifact parsers.

pub mod history;
pub mod cookies;

pub use history::parse_history;
pub use cookies::parse_cookies;
