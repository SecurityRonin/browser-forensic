#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Chromium-family (Chrome, Edge, Brave, Opera) browser artifact parsers.

pub mod autofill;
pub mod bookmarks;
pub mod cache;
pub mod cookies;
pub mod dips;
pub mod downloads;
pub mod extensions;
pub mod favicons;
pub mod history;
pub mod local_state;
pub mod login_data;
pub mod nel;
pub mod network_persistent_state;
pub mod permissions;
pub mod preferences;
pub mod session;
pub mod shortcuts;
pub mod top_sites;
pub mod transport_security;
pub mod visits;
pub mod web_data;

pub use autofill::parse_autofill;
pub use bookmarks::parse_bookmarks;
pub use cache::parse_cache;
pub use cookies::parse_cookies;
pub use dips::parse_dips;
pub use downloads::parse_downloads;
pub use extensions::parse_extensions;
pub use favicons::parse_favicons;
pub use history::parse_history;
pub use local_state::parse_local_state;
pub use login_data::parse_login_data;
pub use nel::parse_reporting_and_nel;
pub use network_persistent_state::parse_network_persistent_state;
pub use permissions::parse_permissions;
pub use preferences::parse_preferences;
pub use session::parse_session;
pub use shortcuts::parse_shortcuts;
pub use top_sites::parse_top_sites;
pub use transport_security::parse_transport_security;
pub use visits::{collapse_redirects, parse_visits};
pub use web_data::parse_web_data;
