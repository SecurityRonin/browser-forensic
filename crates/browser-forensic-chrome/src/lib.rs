#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Chromium-family (Chrome, Edge, Brave, Opera) browser artifact parsers.

pub mod autofill;
pub mod bookmarks;
pub mod cache;
pub mod cookies;
pub mod downloads;
pub mod extensions;
pub mod history;
pub mod local_state;
pub mod login_data;
pub mod permissions;
pub mod preferences;
pub mod session;
pub mod visits;
pub mod web_data;

pub use autofill::parse_autofill;
pub use bookmarks::parse_bookmarks;
pub use cache::parse_cache;
pub use cookies::parse_cookies;
pub use downloads::parse_downloads;
pub use extensions::parse_extensions;
pub use history::parse_history;
pub use local_state::parse_local_state;
pub use login_data::parse_login_data;
pub use permissions::parse_permissions;
pub use preferences::parse_preferences;
pub use session::parse_session;
pub use visits::{collapse_redirects, parse_visits};
pub use web_data::parse_web_data;
