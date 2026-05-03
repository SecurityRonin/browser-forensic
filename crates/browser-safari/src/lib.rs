//! Safari browser artifact parsers.

pub mod history;
pub mod downloads;

pub use history::parse_history;
pub use downloads::parse_downloads;
