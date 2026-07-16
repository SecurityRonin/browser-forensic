//! Bounds-checked parser for the 100-byte SQLite database header.
//!
//! sqlite-core exposes only page_size/reserved/text_encoding from the header, so
//! the manual-edit indicators (file change counter vs version-valid-for, the
//! write/read format versions, schema cookie, application/user version) need a
//! direct read of the documented header layout (file-format spec §1.3). This
//! parser never panics and never indexes out of bounds on a short/garbage file.

/// The SQLite database file header magic string (file-format spec §1.2): the
/// first 16 bytes of every valid database, `"SQLite format 3\0"`.
pub const MAGIC: &[u8; 16] = b"SQLite format 3\x00";

/// The fixed size of the SQLite database header, in bytes.
pub const HEADER_LEN: usize = 100;

/// Documented fields of the 100-byte SQLite header relevant to manual-edit
/// detection. Offsets per the file-format specification (§1.3); all multi-byte
/// integers are big-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqliteHeader {
    /// Logical page size in bytes (offset 16). A stored value of 1 means 65536.
    pub page_size: u32,
    /// File format write version (offset 18): 1 = legacy, 2 = WAL.
    pub write_version: u8,
    /// File format read version (offset 19): 1 = legacy, 2 = WAL.
    pub read_version: u8,
    /// File change counter (offset 24), incremented on every unlocked write.
    pub change_counter: u32,
    /// In-header database size in pages (offset 28).
    pub page_count: u32,
    /// Number of free pages on the freelist (offset 36).
    pub freelist_pages: u32,
    /// Schema cookie (offset 40), incremented on every schema (DDL) change.
    pub schema_cookie: u32,
    /// Schema format number (offset 44): 1..=4 are defined.
    pub schema_format: u32,
    /// Database text encoding (offset 56): 1 = UTF-8, 2 = UTF-16le, 3 = UTF-16be.
    pub text_encoding: u32,
    /// User version (offset 60), set only by `PRAGMA user_version`.
    pub user_version: u32,
    /// Application ID (offset 68), set only by `PRAGMA application_id`.
    pub application_id: u32,
    /// Version-valid-for number (offset 92): the change-counter value when the
    /// SQLite version number at offset 96 was written.
    pub version_valid_for: u32,
    /// SQLITE_VERSION_NUMBER of the library that last wrote the file (offset 96).
    pub sqlite_version_number: u32,
}

/// Read a big-endian `u32` at `offset`, returning `None` if it would run past
/// the end of `bytes` (never panics, never indexes out of bounds).
fn be_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Parse the 100-byte SQLite header from the start of `bytes`.
///
/// Returns `None` when `bytes` is shorter than the header or does not begin with
/// the SQLite magic — a non-database or truncated file, handled without panicking.
#[must_use]
pub fn parse_header(bytes: &[u8]) -> Option<SqliteHeader> {
    let header = bytes.get(..HEADER_LEN)?;
    if &header[..16] != MAGIC.as_slice() {
        return None;
    }

    // page_size is a 2-byte BE value at offset 16; the stored value 1 encodes the
    // real page size 65536 (file-format spec §1.3.2).
    let raw_page_size = u16::from_be_bytes([header[16], header[17]]);
    let page_size = if raw_page_size == 1 {
        65_536
    } else {
        u32::from(raw_page_size)
    };

    Some(SqliteHeader {
        page_size,
        write_version: header[18],
        read_version: header[19],
        change_counter: be_u32(header, 24)?,
        page_count: be_u32(header, 28)?,
        freelist_pages: be_u32(header, 36)?,
        schema_cookie: be_u32(header, 40)?,
        schema_format: be_u32(header, 44)?,
        text_encoding: be_u32(header, 56)?,
        user_version: be_u32(header, 60)?,
        application_id: be_u32(header, 68)?,
        version_valid_for: be_u32(header, 92)?,
        sqlite_version_number: be_u32(header, 96)?,
    })
}

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
    fn truncation_at_every_length_never_panics() {
        // Every prefix of a real database header — including lengths shorter than
        // a field's offset+width — must return None or a header, never an
        // out-of-bounds panic on the fixed-offset big-endian field reads.
        let bytes = real_db_bytes();
        for len in 0..=bytes.len().min(HEADER_LEN + 4) {
            let _ = parse_header(&bytes[..len]);
        }
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
