//! Chromium-family (Chrome, Edge, Brave, Opera) browser artifact parsers.

pub mod history;
pub mod cookies;
pub mod downloads;
pub mod bookmarks;
pub mod extensions;
pub mod login_data;
pub mod autofill;
pub mod cache;

pub use history::parse_history;
pub use cookies::parse_cookies;
pub use downloads::parse_downloads;
pub use bookmarks::parse_bookmarks;
pub use extensions::parse_extensions;
pub use login_data::parse_login_data;
pub use autofill::parse_autofill;
pub use cache::parse_cache;
