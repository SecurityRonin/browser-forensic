#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Chromium-family (Chrome, Edge, Brave, Opera) browser artifact parsers.
//!
//! # Deferred: Reading List
//!
//! Modern Chromium does **not** persist the reading list as a standalone
//! SQLite or JSON file. Reading-list entries are a sync data type
//! (`ReadingListSpecifics`), stored inside the profile's `Sync Data/LevelDB`
//! directory — a LevelDB key-value store holding serialized sync protobufs
//! (verified: no `Reading List` file exists in Chrome/Brave/Edge profiles on
//! macOS; the data lives under `<Profile>/Sync Data/LevelDB`). Parsing it needs
//! a full LevelDB reader plus sync-protobuf decoding, not a simple table scan,
//! so it is deferred (YAGNI) rather than forced into a SQLite/JSON parser. A
//! future implementation would build on the LevelDB handling in
//! `browser-forensic-storage`. Reference: CCL `ccl_chromium_reader`
//! (<https://github.com/cclgroupltd/ccl_chromium_reader>).

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
pub mod media_history;
pub mod nel;
pub mod network_action_predictor;
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
pub use cookies::{parse_cookies, parse_extension_cookies};
pub use dips::parse_dips;
pub use downloads::parse_downloads;
pub use extensions::parse_extensions;
pub use favicons::parse_favicons;
pub use history::parse_history;
pub use local_state::parse_local_state;
pub use login_data::parse_login_data;
pub use media_history::parse_media_history;
pub use nel::parse_reporting_and_nel;
pub use network_action_predictor::parse_network_action_predictor;
pub use network_persistent_state::parse_network_persistent_state;
pub use permissions::parse_permissions;
pub use preferences::parse_preferences;
pub use session::parse_session;
pub use shortcuts::parse_shortcuts;
pub use top_sites::parse_top_sites;
pub use transport_security::parse_transport_security;
pub use visits::{collapse_redirects, parse_visits};
pub use web_data::parse_web_data;
