//! Chromium-family `Media History` parser.
//!
//! Chromium 86+ records audio/video playback in a dedicated `Media History`
//! SQLite database (`components/media_history/`). Three tables carry forensic
//! value:
//!
//! * `playback(url, watch_time_s, has_video, has_audio, last_updated_time_s)` —
//!   per-URL playback with how long it was watched;
//! * `playbackSession(url, duration_ms, position_ms, title, source_title,
//!   last_updated_time_s, …)` — richer per-session detail including the media
//!   title and the last resume `position_ms` (where the user left off);
//! * `origin(origin, aggregate_watchtime_audio_video_s, last_updated_time_s)` —
//!   per-origin aggregate watch time.
//!
//! Every timestamp column is `last_updated_time_s`, a **WebKit timestamp in
//! seconds** (microseconds ÷ 1e6) — converted by scaling to microseconds and
//! reusing the shared WebKit helper (no hand-rolled epoch).
//!
//! Schema reference: <https://dfir.blog/media-history-database-added-to-chrome/>
//! (the Chromium `media_history` component). No `Media History` sample was
//! present on the development host, so this parser is validated against
//! fixtures built from that documented schema; the tier-1 `sqlite3` oracle in
//! `tests/coverage_oracle.rs` runs whenever a real database is supplied.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::sqlite::open_evidence_db;
use browser_forensic_core::timestamp::webkit_micros_to_unix_nanos;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

const MEDIA_NOTE: &str = "audio/video playback recorded by Chromium Media History";

/// Convert a `last_updated_time_s` WebKit-**seconds** value to Unix nanoseconds
/// by scaling to microseconds and reusing the shared WebKit helper (saturating,
/// never-panic — the offset epoch lives in the helper, not here).
fn webkit_secs_to_unix_nanos(secs: i64) -> i64 {
    webkit_micros_to_unix_nanos(secs.saturating_mul(1_000_000))
}

/// Parse a Chromium `Media History` database into media-playback events.
///
/// # Errors
///
/// Returns an error only if the SQLite file cannot be opened.
pub fn parse_media_history(_path: &Path) -> Result<Vec<BrowserEvent>> {
    // RED stub — replaced by the real queries in GREEN.
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::test_utils::sqlite::TestDb;
    use rusqlite::params;

    // Schema mirrors the Chromium media_history component (per the DFIR writeup).
    const SCHEMA: &str = "CREATE TABLE origin(id INTEGER PRIMARY KEY, origin TEXT, last_updated_time_s INTEGER, aggregate_watchtime_audio_video_s INTEGER);
        CREATE TABLE playback(id INTEGER PRIMARY KEY, origin_id INTEGER, url TEXT, watch_time_s INTEGER, has_video INTEGER, has_audio INTEGER, last_updated_time_s INTEGER);
        CREATE TABLE playbackSession(id INTEGER PRIMARY KEY, origin_id INTEGER, url TEXT, duration_ms INTEGER, position_ms INTEGER, last_updated_time_s INTEGER, title TEXT, artist TEXT, album TEXT, source_title TEXT);";

    fn webkit_secs_for_unix(unix_secs: i64) -> i64 {
        unix_secs + 11_644_473_600
    }

    #[test]
    fn parse_empty_returns_empty() {
        let db = TestDb::new(SCHEMA);
        assert!(parse_media_history(db.path()).unwrap().is_empty());
    }

    #[test]
    fn playback_row_emits_event_with_webkit_seconds() {
        let db = TestDb::new(SCHEMA);
        let lut = webkit_secs_for_unix(1_700_000_000);
        db.insert(
            "INSERT INTO playback (url, watch_time_s, has_video, has_audio, last_updated_time_s) VALUES (?1, ?2, ?3, ?4, ?5)",
            params!["https://youtube.com/watch?v=abc", 393_i64, 1_i64, 1_i64, lut],
        );
        let events = parse_media_history(db.path()).unwrap();
        let ev = events
            .iter()
            .find(|e| e.attrs.get("media_kind") == Some(&json!("playback")))
            .expect("playback event");
        assert_eq!(ev.artifact, ArtifactKind::MediaPlayback);
        assert_eq!(ev.attrs["url"], json!("https://youtube.com/watch?v=abc"));
        assert_eq!(ev.attrs["watch_time_s"], json!(393));
        assert_eq!(ev.attrs["has_video"], json!(true));
        // WebKit-SECONDS conversion (not microseconds).
        assert_eq!(ev.timestamp_ns, 1_700_000_000_000_000_000);
    }

    #[test]
    fn playback_session_row_surfaces_title_and_position() {
        let db = TestDb::new(SCHEMA);
        let lut = webkit_secs_for_unix(1_600_000_000);
        db.insert(
            "INSERT INTO playbackSession (url, duration_ms, position_ms, last_updated_time_s, title, source_title) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params!["https://youtube.com/watch?v=xyz", 2_476_101_i64, 595_280_i64, lut, "SANS DFIR Summit 2020", "dfir.blog"],
        );
        let events = parse_media_history(db.path()).unwrap();
        let ev = events
            .iter()
            .find(|e| e.attrs.get("media_kind") == Some(&json!("session")))
            .expect("session event");
        assert_eq!(ev.attrs["title"], json!("SANS DFIR Summit 2020"));
        assert_eq!(ev.attrs["position_ms"], json!(595_280));
        assert_eq!(ev.attrs["duration_ms"], json!(2_476_101));
        assert_eq!(ev.attrs["source_title"], json!("dfir.blog"));
        assert_eq!(ev.timestamp_ns, 1_600_000_000_000_000_000);
    }

    #[test]
    fn origin_row_surfaces_aggregate_watchtime() {
        let db = TestDb::new(SCHEMA);
        let lut = webkit_secs_for_unix(1_500_000_000);
        db.insert(
            "INSERT INTO origin (origin, last_updated_time_s, aggregate_watchtime_audio_video_s) VALUES (?1, ?2, ?3)",
            params!["https://www.twitch.tv", lut, 3_i64],
        );
        let events = parse_media_history(db.path()).unwrap();
        let ev = events
            .iter()
            .find(|e| e.attrs.get("media_kind") == Some(&json!("origin")))
            .expect("origin event");
        assert_eq!(ev.attrs["origin"], json!("https://www.twitch.tv"));
        assert_eq!(ev.attrs["aggregate_watchtime_s"], json!(3));
    }

    #[test]
    fn missing_tables_degrade_to_empty() {
        let db = TestDb::new("CREATE TABLE meta(key TEXT, value TEXT);");
        assert!(parse_media_history(db.path()).unwrap().is_empty());
    }
}
