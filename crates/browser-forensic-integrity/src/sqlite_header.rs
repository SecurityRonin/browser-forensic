//! Bounds-checked parser for the 100-byte SQLite database header.
//!
//! sqlite-core exposes only page_size/reserved/text_encoding from the header, so
//! the manual-edit indicators (file change counter vs version-valid-for, the
//! write/read format versions, schema cookie, application/user version) need a
//! direct read of the documented header layout (file-format spec §1.3). This
//! parser never panics and never indexes out of bounds on a short/garbage file.

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn real_db_bytes() -> Vec<u8> {
        let dir = tempdir().expect("tempdir");
        let p = dir.path().join("h.db");
        let conn = rusqlite::Connection::open(&p).expect("open");
        conn.execute_batch(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);
             INSERT INTO t(v) VALUES ('a');",
        )
        .expect("schema");
        drop(conn);
        std::fs::read(&p).expect("read")
    }

    #[test]
    fn parses_real_sqlite_header() {
        let bytes = real_db_bytes();
        let h = parse_header(&bytes).expect("valid header");
        assert!(h.page_size >= 512, "page size {} too small", h.page_size);
        // A DB written by a modern SQLite keeps change_counter == version_valid_for.
        assert_eq!(
            h.change_counter, h.version_valid_for,
            "fresh DB should have change_counter == version_valid_for"
        );
        // write/read version are 1 (rollback journal) or 2 (WAL).
        assert!(h.write_version == 1 || h.write_version == 2);
        assert!(h.read_version == 1 || h.read_version == 2);
    }

    #[test]
    fn rejects_short_or_garbage_input() {
        assert!(parse_header(b"").is_none());
        assert!(parse_header(b"not a sqlite database at all, but long enough........").is_none());
        // Correct length, wrong magic.
        let mut buf = vec![0u8; 100];
        buf[..16].copy_from_slice(b"NOTSQLITE format");
        assert!(parse_header(&buf).is_none());
    }

    #[test]
    fn extracts_manual_edit_fields() {
        let bytes = real_db_bytes();
        let h = parse_header(&bytes).expect("valid header");
        // freelist is empty on a fresh insert-only DB.
        assert_eq!(h.freelist_pages, 0);
        // schema cookie advances on DDL, so a DB with a table has cookie >= 1.
        assert!(h.schema_cookie >= 1);
    }
}
