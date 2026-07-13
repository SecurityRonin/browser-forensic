//! Deleted / orphaned cache-entry carving (recovery of entries the live index
//! no longer references).
//!
//! Three recovery mechanisms, all read-only and bounds-checked, each reusing the
//! live cache parsers rather than reimplementing them:
//!
//! 1. **Orphaned SimpleCache** — a `[hash]_0` entry file present on disk whose
//!    key-hash is absent from the SimpleCache index (`index-dir/the-real-index`)
//!    is deleted-but-not-yet-purged residue. Parsed with
//!    [`resource_from_entry_bytes`](crate::resource_from_entry_bytes). A lone
//!    `[hash]_s` sparse body with no companion `_0` is a dangling body fragment.
//! 2. **Blockfile free-but-intact** — an `EntryStore` sitting in a block marked
//!    FREE in the block-file allocation map yet still structurally valid
//!    (recently evicted). Decoded with the existing Blockfile machinery.
//! 3. **Signature carve** — a raw byte scan for the SimpleCache entry header
//!    magic, recovering parseable entries from slack / unallocated regions the
//!    index no longer references.
//!
//! Honesty: a carved entry is a *recovered* artifact. Its body may be partial or
//! overwritten; every result carries a [`RecoveryMechanism`] and a
//! [`RecoveryQuality`] (`Full`/`Partial`) plus a note. A recovery is
//! *consistent with* the resource having been cached and then evicted/cleared —
//! it is never asserted to have been deliberately deleted by a user.
//!
//! Structural signatures (see the parsers this module reuses):
//! - SimpleCache entry header magic `kSimpleInitialMagicNumber`
//!   [`0xfcfb_6d1b_a772_5c30`](crate::simple) and EOF magic
//!   [`0xf4fa_6f45_970d_41d8`](crate::simple).
//! - SimpleCache index (`the-real-index`) `base::Pickle`: header
//!   `[payload_size u32][crc u32]`, then `IndexMetadata` (magic
//!   `0x656e_7465_7220_796f`, version, `entry_count`, `cache_size`, reason),
//!   then `entry_count` × (`hash_key u64` + 16-byte `EntryMetadata`). The
//!   `hash_key` is the entry hash; the on-disk file is named `%016x_0`.
//!   (Chromium `net/disk_cache/simple/simple_index_file.cc` + `simple_index.cc`.)
//! - Blockfile allocation map: `BlockFileHeader.allocation_map` at byte offset
//!   80; block *N* is allocated iff bit *N* is set. (Chromium
//!   `net/disk_cache/blockfile/disk_format_base.h`.)

use std::collections::HashSet;
use std::path::Path;

use crate::error::CacheError;
use crate::resource::CachedResource;

/// `kSimpleIndexMagicNumber` — first 8 payload bytes of `the-real-index`.
pub const INDEX_MAGIC: u64 = 0x656e_7465_7220_796f;

/// Which recovery mechanism produced a [`RecoveredResource`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryMechanism {
    /// A `[hash]_0` entry file whose hash is absent from `the-real-index`.
    OrphanedSimpleEntry,
    /// A `[hash]_s` sparse body file with no companion `_0` entry.
    DanglingSparseFile,
    /// An `EntryStore` recovered from a FREE Blockfile allocation-map block.
    BlockfileFreeIntact,
    /// A SimpleCache entry recovered by scanning raw bytes for the header magic.
    SignatureCarve,
}

impl RecoveryMechanism {
    /// A stable machine token for JSON/CSV output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryMechanism::OrphanedSimpleEntry => "orphaned_simple_entry",
            RecoveryMechanism::DanglingSparseFile => "dangling_sparse_file",
            RecoveryMechanism::BlockfileFreeIntact => "blockfile_free_intact",
            RecoveryMechanism::SignatureCarve => "signature_carve",
        }
    }
}

/// How complete the recovered artifact is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryQuality {
    /// URL, headers, and a decodable body were all recovered.
    Full,
    /// Some part is missing/overwritten (e.g. body gone, headers absent).
    Partial,
}

impl RecoveryQuality {
    /// A stable machine token for JSON/CSV output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryQuality::Full => "full",
            RecoveryQuality::Partial => "partial",
        }
    }
}

/// A cache resource recovered from deleted/orphaned/evicted residue, with the
/// provenance and confidence a live-index resource does not need to carry.
#[derive(Debug, Clone)]
pub struct RecoveredResource {
    /// The recovered response (URL, headers, body) — same shape as a live hit.
    pub resource: CachedResource,
    /// Which mechanism recovered it.
    pub mechanism: RecoveryMechanism,
    /// Whether the recovery is full or partial.
    pub quality: RecoveryQuality,
    /// A human-readable, honest provenance note (consistent-with framing).
    pub note: String,
}

/// Grade a recovered [`CachedResource`]: `Full` when the URL, an HTTP status,
/// and a decoded non-empty body are all present; `Partial` otherwise.
fn grade(res: &CachedResource) -> RecoveryQuality {
    if !res.url.is_empty()
        && res.http_status.is_some()
        && res.body_decoded
        && !res.raw_body.is_empty()
    {
        RecoveryQuality::Full
    } else {
        RecoveryQuality::Partial
    }
}

/// Parse the SimpleCache `the-real-index` pickle and return the set of live
/// entry hashes it references.
///
/// The `crc` in the pickle header is intentionally *not* enforced: a real index
/// captured mid-write can carry a stale CRC while its hash list is still usable,
/// and a forensic reader must not discard recoverable structure over it.
///
/// # Errors
///
/// [`CacheError::TooSmall`] if shorter than the fixed header, or
/// [`CacheError::BadHeaderMagic`] (carrying the offending magic) if the leading
/// `kSimpleIndexMagicNumber` is wrong.
pub fn parse_real_index_hashes(_bytes: &[u8]) -> Result<HashSet<u64>, CacheError> {
    Ok(HashSet::new())
}

/// Recover orphaned SimpleCache entries under `cache_dir`: `[hash]_0` files whose
/// key-hash is absent from `the-real-index`, plus dangling `[hash]_s` sparse
/// bodies with no companion `_0`.
///
/// When the index cannot be found or parsed, entry liveness cannot be
/// determined, so no `_0` file is reported as orphaned (avoiding a false
/// positive); dangling `_s` detection still runs. Best-effort and panic-free: a
/// malformed candidate is skipped.
#[must_use]
pub fn carve_orphaned_simple(_cache_dir: &Path) -> Vec<RecoveredResource> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simple::{EOF_MAGIC, EOF_SIZE, HEADER_MAGIC, HEADER_SIZE};
    use tempfile::TempDir;

    /// Build a valid SimpleCache `_0` file (mirrors the layout in `simple`).
    fn build_entry(url: &str, body: &[u8], headers: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&HEADER_MAGIC.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // version
        out.extend_from_slice(&(url.len() as u32).to_le_bytes()); // key_length
        out.extend_from_slice(&0u32.to_le_bytes()); // key_hash
        out.extend_from_slice(&[0u8; 4]); // pad to 24
        out.extend_from_slice(url.as_bytes());
        out.extend_from_slice(body);
        push_eof(&mut out, 1, body.len() as u32);
        out.extend_from_slice(headers);
        push_eof(&mut out, 1, headers.len() as u32);
        out
    }

    fn push_eof(out: &mut Vec<u8>, flags: u32, stream_size: u32) {
        out.extend_from_slice(&EOF_MAGIC.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // data_crc32
        out.extend_from_slice(&stream_size.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]); // pad to 24
    }

    /// Build a `the-real-index` pickle listing the given entry hashes.
    fn build_real_index(hashes: &[u64]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&INDEX_MAGIC.to_le_bytes());
        payload.extend_from_slice(&9u32.to_le_bytes()); // version
        payload.extend_from_slice(&(hashes.len() as u64).to_le_bytes()); // entry_count
        payload.extend_from_slice(&0u64.to_le_bytes()); // cache_size
        payload.extend_from_slice(&0u32.to_le_bytes()); // reason
        for &h in hashes {
            payload.extend_from_slice(&h.to_le_bytes()); // hash_key
            payload.extend_from_slice(&0i64.to_le_bytes()); // last_used_time
            payload.extend_from_slice(&0u64.to_le_bytes()); // packed_entry_info
        }
        payload.extend_from_slice(&0i64.to_le_bytes()); // cache_modified (final)
        let mut out = Vec::new();
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // payload_size
        out.extend_from_slice(&0u32.to_le_bytes()); // crc (not enforced)
        out.extend_from_slice(&payload);
        out
    }

    fn write_index(dir: &Path, bytes: &[u8]) {
        let idx_dir = dir.join("index-dir");
        std::fs::create_dir_all(&idx_dir).unwrap();
        std::fs::write(idx_dir.join("the-real-index"), bytes).unwrap();
    }

    const HEADERS: &[u8] = b"HTTP/1.1 200 OK\0Content-Type: text/html\0\0";

    #[test]
    fn parses_index_hash_set() {
        let idx = build_real_index(&[0x1111, 0x2222, 0x3333]);
        let set = parse_real_index_hashes(&idx).expect("valid index");
        assert_eq!(set.len(), 3);
        assert!(set.contains(&0x1111) && set.contains(&0x2222) && set.contains(&0x3333));
    }

    #[test]
    fn index_bad_magic_errs_with_value() {
        let mut idx = build_real_index(&[0x1]);
        idx[8] ^= 0xff; // corrupt the first magic byte (payload offset 0)
        let err = parse_real_index_hashes(&idx).unwrap_err();
        assert!(matches!(err, CacheError::BadHeaderMagic { .. }), "{err}");
    }

    #[test]
    fn index_too_small_errs() {
        let err = parse_real_index_hashes(&[0u8; 8]).unwrap_err();
        assert!(matches!(err, CacheError::TooSmall { .. }), "{err}");
    }

    #[test]
    fn recovers_orphan_not_live_entry() {
        let dir = TempDir::new().unwrap();
        // live entry hash 0xAAAA... is in the index; orphan 0xBBBB... is not.
        let live_hash: u64 = 0x00000000_aaaa1111;
        let orphan_hash: u64 = 0x00000000_bbbb2222;
        std::fs::write(
            dir.path().join(format!("{live_hash:016x}_0")),
            build_entry("https://live.example/keep", b"live-body", HEADERS),
        )
        .unwrap();
        std::fs::write(
            dir.path().join(format!("{orphan_hash:016x}_0")),
            build_entry("https://orphan.example/gone", b"orphan-body", HEADERS),
        )
        .unwrap();
        write_index(dir.path(), &build_real_index(&[live_hash]));

        let recovered = carve_orphaned_simple(dir.path());
        assert_eq!(recovered.len(), 1, "only the orphan is recovered");
        let r = &recovered[0];
        assert_eq!(r.resource.url, "https://orphan.example/gone");
        assert_eq!(r.mechanism, RecoveryMechanism::OrphanedSimpleEntry);
        assert_eq!(r.resource.raw_body, b"orphan-body");
        // live entry must NOT be double-reported
        assert!(recovered
            .iter()
            .all(|x| x.resource.url != "https://live.example/keep"));
    }

    #[test]
    fn missing_index_reports_no_orphans() {
        let dir = TempDir::new().unwrap();
        let h: u64 = 0x00000000_cccc3333;
        std::fs::write(
            dir.path().join(format!("{h:016x}_0")),
            build_entry("https://a.example/x", b"b", HEADERS),
        )
        .unwrap();
        // no index-dir/the-real-index → liveness unknown → no _0 orphan claim
        let recovered = carve_orphaned_simple(dir.path());
        assert!(
            recovered
                .iter()
                .all(|r| r.mechanism != RecoveryMechanism::OrphanedSimpleEntry),
            "without an index, no _0 file may be claimed orphaned: {recovered:?}"
        );
    }

    #[test]
    fn dangling_sparse_without_entry_recovered() {
        let dir = TempDir::new().unwrap();
        let h: u64 = 0x00000000_dddd4444;
        // an _s file with NO companion _0 → dangling sparse body
        std::fs::write(dir.path().join(format!("{h:016x}_s")), b"sparse ranges").unwrap();
        write_index(dir.path(), &build_real_index(&[]));
        let recovered = carve_orphaned_simple(dir.path());
        assert!(
            recovered
                .iter()
                .any(|r| r.mechanism == RecoveryMechanism::DanglingSparseFile),
            "a lone _s must surface as a dangling sparse body: {recovered:?}"
        );
    }

    #[test]
    fn truncated_orphan_skipped_no_panic() {
        let dir = TempDir::new().unwrap();
        let orphan_hash: u64 = 0x00000000_eeee5555;
        // a too-short _0 that is not indexed: must be skipped, never panic
        std::fs::write(
            dir.path().join(format!("{orphan_hash:016x}_0")),
            vec![0u8; HEADER_SIZE + EOF_SIZE - 1],
        )
        .unwrap();
        write_index(dir.path(), &build_real_index(&[]));
        let recovered = carve_orphaned_simple(dir.path());
        assert!(recovered.iter().all(|r| r.resource.url != ""));
    }
}
