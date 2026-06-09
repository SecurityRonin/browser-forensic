//! Firefox/Gecko browser artifact parsers.

pub mod autofill;
pub mod bookmarks;
pub mod cache;
pub mod cookies;
pub mod downloads;
pub mod extensions;
pub mod history;
pub mod login_data;
pub mod session;

pub use autofill::parse_autofill;
pub use bookmarks::parse_bookmarks;
pub use cache::parse_cache;
pub use cookies::parse_cookies;
pub use downloads::parse_downloads;
pub use extensions::parse_extensions;
pub use history::parse_history;
pub use login_data::parse_login_data;
pub use session::parse_session;
