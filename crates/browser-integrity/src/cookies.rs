//! Cookie integrity checks across browser families.

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::BrowserFamily;
    use browser_core::test_utils::sqlite::TestDb;
    use crate::IntegrityIndicator;

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
        assert!(result.iter().any(|i| matches!(i, IntegrityIndicator::CookieTimestampAnomaly { .. })));
    }
}
