#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Firefox/Gecko browser artifact parsers.

pub mod annotations;
pub mod autofill;
pub mod bookmarks;
pub mod cache;
pub mod cookies;
pub mod downloads;
pub mod extensions;
pub mod history;
pub mod login_data;
pub mod mozlz4;
pub mod permissions;
pub mod preferences;
pub mod session;
pub mod site_security;
pub mod typed_input;
pub mod visits;

pub use annotations::parse_annotations;
pub use autofill::parse_autofill;
pub use bookmarks::parse_bookmarks;
pub use cache::parse_cache;
pub use cookies::parse_cookies;
pub use downloads::parse_downloads;
pub use extensions::parse_extensions;
pub use history::parse_history;
pub use login_data::parse_login_data;
pub use permissions::parse_permissions as parse_firefox_permissions;
pub use preferences::parse_preferences as parse_firefox_preferences;
pub use session::parse_session;
pub use site_security::parse_site_security;
pub use typed_input::parse_typed_input;
pub use visits::parse_visits;
