//! Cookie integrity checks across browser families.

use std::path::Path;

use anyhow::Result;
use browser_core::sqlite::open_evidence_db;
use browser_core::BrowserFamily;

use crate::IntegrityIndicator;

/// Check a browser cookie database for timestamp anomalies.
///
/// Detects cookies where creation timestamp > last_access timestamp,
/// which is impossible under normal browser operation and indicates timestamp manipulation.
pub fn check_cookie_integrity(
    path: &Path,
    browser: BrowserFamily,
) -> Result<Vec<IntegrityIndicator>> {
    match browser {
        BrowserFamily::Chromium => check_chromium_cookies(path),
        BrowserFamily::Firefox => check_firefox_cookies(path),
        BrowserFamily::Safari => Ok(Vec::new()), // Safari uses binary cookies format, not SQLite
    }
}

fn check_chromium_cookies(path: &Path) -> Result<Vec<IntegrityIndicator>> {
    let db = open_evidence_db(path)?;
    let conn = &db.conn;
    let mut indicators = Vec::new();

    let mut stmt = conn.prepare(
        "SELECT host_key, creation_utc, last_access_utc FROM cookies WHERE last_access_utc > 0",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;

    for row in rows.flatten() {
        let (host, creation, last_access) = row;
        if creation > last_access {
            // Webkit timestamps: microseconds since 1601-01-01
            indicators.push(IntegrityIndicator::CookieTimestampAnomaly {
                path: path.to_path_buf(),
                host,
                creation_ns: creation.saturating_mul(1000),
                last_access_ns: last_access.saturating_mul(1000),
            });
        }
    }
    Ok(indicators)
}

fn check_firefox_cookies(path: &Path) -> Result<Vec<IntegrityIndicator>> {
    let db = open_evidence_db(path)?;
    let conn = &db.conn;
    let mut indicators = Vec::new();

    let mut stmt = conn.prepare(
        "SELECT host, creationTime, lastAccessed FROM moz_cookies WHERE lastAccessed > 0",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;

    for row in rows.flatten() {
        let (host, creation, last_access) = row;
        if creation > last_access {
            // Firefox uses microseconds since Unix epoch
            indicators.push(IntegrityIndicator::CookieTimestampAnomaly {
                path: path.to_path_buf(),
                host,
                creation_ns: creation * 1000,
                last_access_ns: last_access * 1000,
            });
        }
    }
    Ok(indicators)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IntegrityIndicator;
    use browser_core::test_utils::sqlite::TestDb;
    use browser_core::BrowserFamily;

    fn chrome_cookies_schema() -> &'static str {
        "CREATE TABLE cookies (
            creation_utc INTEGER NOT NULL,
            host_key TEXT NOT NULL,
            name TEXT NOT NULL,
            value TEXT,
            path TEXT,
            expires_utc INTEGER,
            last_access_utc INTEGER,
            is_httponly INTEGER,
            is_secure INTEGER
        );"
    }

    #[test]
    fn chromium_cookies_clean_returns_empty() {
        let db = TestDb::new(chrome_cookies_schema());
        // creation_utc < last_access_utc -- normal
        db.insert(
            "INSERT INTO cookies VALUES (13000000000000000, '.example.com', 'sid', 'abc', '/', 13100000000000000, 13000000001000000, 0, 1)",
            rusqlite::params![],
        );

        let result = check_cookie_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(result.is_empty());
    }

    #[test]
    fn chromium_cookie_creation_after_last_access_detected() {
        let db = TestDb::new(chrome_cookies_schema());
        // creation_utc (13200000000000000) > last_access_utc (13100000000000000) -- impossible
        db.insert(
            "INSERT INTO cookies VALUES (13200000000000000, '.evil.com', 'tracking', 'x', '/', 13300000000000000, 13100000000000000, 0, 0)",
            rusqlite::params![],
        );

        let result = check_cookie_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(result.iter().any(|i| matches!(i, IntegrityIndicator::CookieTimestampAnomaly { host, .. } if host == ".evil.com")));
    }

    fn firefox_cookies_schema() -> &'static str {
        "CREATE TABLE moz_cookies (
            id INTEGER PRIMARY KEY,
            baseDomain TEXT,
            host TEXT,
            name TEXT,
            value TEXT,
            path TEXT,
            expiry INTEGER,
            lastAccessed INTEGER,
            creationTime INTEGER,
            isSecure INTEGER,
            isHttpOnly INTEGER
        );"
    }

    #[test]
    fn firefox_cookie_creation_after_last_access_detected() {
        let db = TestDb::new(firefox_cookies_schema());
        // creationTime (1800000000000000) > lastAccessed (1700000000000000) -- impossible
        db.insert(
            "INSERT INTO moz_cookies VALUES (1, 'evil.com', '.evil.com', 'track', 'x', '/', 1800000000, 1700000000000000, 1800000000000000, 0, 0)",
            rusqlite::params![],
        );

        let result = check_cookie_integrity(db.path(), BrowserFamily::Firefox).expect("check");
        assert!(result
            .iter()
            .any(|i| matches!(i, IntegrityIndicator::CookieTimestampAnomaly { .. })));
    }
}
