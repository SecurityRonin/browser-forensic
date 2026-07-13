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

use crate::blockfile::{
    block_allocated, build_resource, load_block_file, parse_entry_store, resolve_key, BlockFiles,
    BLOCK_HEADER_SIZE, ENTRY_BLOCK_SIZE, MAX_BLOCKS_IN_BITMAP,
};
use crate::decompress::DecompressLimits;
use crate::error::CacheError;
use crate::resource::{resource_from_entry_bytes, CachedResource};
use crate::simple::{EOF_MAGIC, EOF_SIZE, HEADER_MAGIC, HEADER_SIZE};

/// Highest `data_N` block-file selector probed when carving free blocks (the
/// `CacheAddr` file selector is an 8-bit field; real caches use only a handful).
const MAX_BLOCK_FILE_SELECTOR: u32 = 255;

/// Largest span a single carved SimpleCache entry may occupy (header → stream-0
/// EOF). Bounds the signature scan against a lying/garbage buffer.
const MAX_CARVE_ENTRY: usize = 64 * 1024 * 1024;
/// Cap on the number of entries a single signature carve will emit.
const MAX_CARVED_ENTRIES: usize = 1_000_000;

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
pub fn parse_real_index_hashes(bytes: &[u8]) -> Result<HashSet<u64>, CacheError> {
    // Pickle header (8) + IndexMetadata (magic8 version4 entry_count8 cache_size8
    // reason4 = 32) — the fixed prefix before the first hash_key.
    const HEADER: usize = 8;
    const META_END: usize = HEADER + 32; // first hash_key begins here (offset 40)
    const ENTRY_STRIDE: usize = 24; // hash_key(8) + EntryMetadata(16)
    const MAX_ENTRIES: u64 = 8 * 1024 * 1024;

    if bytes.len() < META_END {
        return Err(CacheError::TooSmall {
            found: bytes.len(),
            need: META_END,
        });
    }
    let magic = rd_u64(bytes, HEADER).unwrap_or(0);
    if magic != INDEX_MAGIC {
        return Err(CacheError::BadHeaderMagic {
            found: magic,
            expected: INDEX_MAGIC,
        });
    }
    let entry_count = rd_u64(bytes, HEADER + 12).unwrap_or(0);
    // Bound the declared count against what the file can actually hold (the
    // trailing i64 cache_modified sits after the last entry).
    let available = bytes.len().saturating_sub(META_END).saturating_sub(8) / ENTRY_STRIDE;
    let count = entry_count.min(MAX_ENTRIES).min(available as u64) as usize;

    let mut set = HashSet::with_capacity(count);
    for i in 0..count {
        let off = META_END + i * ENTRY_STRIDE;
        if let Some(hash) = rd_u64(bytes, off) {
            set.insert(hash);
        }
    }
    Ok(set)
}

/// Bounded little-endian `u64` read; `None` when out of range.
fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let s = b.get(off..end)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}

/// Read `the-real-index` from a SimpleCache directory: the modern
/// `index-dir/the-real-index`, falling back to a flattened `the-real-index`.
fn read_real_index(cache_dir: &Path) -> Option<Vec<u8>> {
    let modern = cache_dir.join("index-dir").join("the-real-index");
    if let Ok(b) = std::fs::read(&modern) {
        return Some(b);
    }
    std::fs::read(cache_dir.join("the-real-index")).ok()
}

/// Parse `[0-9a-f]{16}` from a `<hash>_<stream>` filename into the entry hash.
fn hash_from_name(name: &str, suffix: &str) -> Option<u64> {
    let stem = name.strip_suffix(suffix)?;
    if stem.len() != 16 || !stem.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(stem, 16).ok()
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
pub fn carve_orphaned_simple(cache_dir: &Path) -> Vec<RecoveredResource> {
    let limits = DecompressLimits::default();
    let live = read_real_index(cache_dir).and_then(|b| parse_real_index_hashes(&b).ok());

    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(cache_dir) else {
        return out;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !path.is_file() {
            continue;
        }

        if let Some(hash) = hash_from_name(name, "_0") {
            // Only claim a _0 orphan when the index is present and does NOT list
            // the hash; without an index, liveness is unknown (no false claim).
            let Some(live_set) = &live else { continue };
            if live_set.contains(&hash) {
                continue; // live entry — never double-report it
            }
            let Ok(data) = std::fs::read(&path) else {
                continue;
            };
            let sparse = sparse_companion(&path);
            let Ok(res) = resource_from_entry_bytes(&data, path.clone(), sparse, &limits) else {
                continue; // malformed orphan — skip, never panic
            };
            let quality = grade(&res);
            let note = format!(
                "recovered from an orphaned SimpleCache entry (hash {hash:016x} absent from \
                 the-real-index); consistent with the resource having been cached then \
                 evicted/cleared, not proof of deliberate deletion"
            );
            out.push(RecoveredResource {
                resource: res,
                mechanism: RecoveryMechanism::OrphanedSimpleEntry,
                quality,
                note,
            });
        } else if let Some(hash) = hash_from_name(name, "_s") {
            // A sparse body whose companion _0 is absent is a dangling fragment:
            // the entry that held its URL and headers is gone, so the URL is
            // unknown. Surface the bytes without fabricating a URL.
            let entry0 = path.with_file_name(format!("{hash:016x}_0"));
            if entry0.is_file() {
                continue; // the entry exists; handled via its _0 above
            }
            let Ok(body) = std::fs::read(&path) else {
                continue;
            };
            out.push(dangling_sparse_resource(&path, hash, body));
        }
    }
    out
}

/// Given a `[hash]_0` path, return its `[hash]_s` companion if present.
fn sparse_companion(entry_path: &Path) -> Option<std::path::PathBuf> {
    let name = entry_path.file_name()?.to_str()?;
    let stem = name.strip_suffix("_0")?;
    let sparse = entry_path.with_file_name(format!("{stem}_s"));
    sparse.is_file().then_some(sparse)
}

/// Build a [`RecoveredResource`] for a dangling `[hash]_s` sparse body: the URL
/// is unknown (its `_0` is gone), so it is left empty and the note says so.
fn dangling_sparse_resource(path: &Path, hash: u64, body: Vec<u8>) -> RecoveredResource {
    let note = format!(
        "recovered orphaned SimpleCache sparse body (hash {hash:016x}); the companion _0 entry \
         holding its URL and headers is absent, so the request URL is unknown; consistent with \
         a streamed/range response having been cached then evicted"
    );
    let resource = CachedResource {
        url: String::new(),
        http_status: None,
        status_line: None,
        headers: Vec::new(),
        content_type: None,
        content_encoding: None,
        request_time_ns: None,
        response_time_ns: None,
        raw_body: body.clone(),
        decoded_body: body,
        body_decoded: false,
        decode_note: Some("sparse range reassembly not performed".to_string()),
        source_file: path.to_path_buf(),
        sparse_file: Some(path.to_path_buf()),
    };
    RecoveredResource {
        resource,
        mechanism: RecoveryMechanism::DanglingSparseFile,
        quality: RecoveryQuality::Partial,
        note,
    }
}

/// Recover Blockfile entries that survive in blocks the allocation map marks
/// FREE — recently evicted `EntryStore`s not yet overwritten.
///
/// Only `BLOCK_256` (`data_N` with a 256-byte block size) files hold entries; a
/// free block is carved only when it decodes to an `EntryStore` whose key is a
/// non-empty URL (`://`), filtering freed body/header/rankings blocks. Allocated
/// (live) blocks are skipped, so a live entry is never double-reported.
/// Best-effort and panic-free; every offset is bounds-checked.
#[must_use]
pub fn carve_blockfile_free(cache_dir: &Path) -> Vec<RecoveredResource> {
    let limits = DecompressLimits::default();
    let index_path = cache_dir.join("index");
    let mut out = Vec::new();

    for selector in 0..=MAX_BLOCK_FILE_SELECTOR {
        let Some(bd) = load_block_file(cache_dir, selector) else {
            continue;
        };
        // Only 256-byte block files hold `EntryStore`s; larger blocks are body
        // and header data, `data_0` is 36-byte rankings.
        if bd.entry_size != ENTRY_BLOCK_SIZE {
            continue;
        }
        let slots = bd.bytes.len().saturating_sub(BLOCK_HEADER_SIZE) / ENTRY_BLOCK_SIZE;
        let slots = slots.min(MAX_BLOCKS_IN_BITMAP);

        // A dedicated reader for resolving each recovered entry's streams.
        let mut cache = BlockFiles::new(cache_dir);
        for block in 0..slots {
            if block_allocated(&bd.bytes, block) {
                continue; // allocated == live; never double-report it
            }
            let start = BLOCK_HEADER_SIZE + block * ENTRY_BLOCK_SIZE;
            let Some(bytes) = bd.bytes.get(start..start + ENTRY_BLOCK_SIZE) else {
                continue;
            };
            let Some(es) = parse_entry_store(bytes) else {
                continue;
            };
            let Some(url) = resolve_key(&es, bytes, &mut cache) else {
                continue;
            };
            // Structural filter: a real cache key is a URL. This rejects freed
            // body/header blocks that happen to decode into an EntryStore shape.
            if !url.contains("://") {
                continue;
            }
            let res = build_resource(&es, url, &index_path, &mut cache, &limits);
            let quality = grade(&res);
            let note = format!(
                "recovered from a FREE Blockfile block (allocation-map bit clear at data_{selector} \
                 block {block}); consistent with the entry having been evicted but not yet \
                 overwritten, not proof of deliberate deletion"
            );
            out.push(RecoveredResource {
                resource: res,
                mechanism: RecoveryMechanism::BlockfileFreeIntact,
                quality,
                note,
            });
        }
    }
    out
}

/// Scan an arbitrary byte buffer (a cache directory's slack, an unallocated
/// region, a raw image window) for the SimpleCache entry header magic and
/// recover every parseable entry it finds — entries the live index no longer
/// references.
///
/// For each header hit the entry's extent is resolved by trying each following
/// EOF-magic position as the stream-0 EOF and taking the first that parses, so a
/// premature/garbage EOF is rejected rather than trusted. `source` labels the
/// provenance of every recovered resource. Bounds-checked and panic-free; a
/// header with no valid entry is skipped.
#[must_use]
pub fn carve_signature(buf: &[u8], source: &Path) -> Vec<RecoveredResource> {
    let limits = DecompressLimits::default();
    let magic = HEADER_MAGIC.to_le_bytes();
    let eof = EOF_MAGIC.to_le_bytes();

    // One pass to locate every EOF-magic position, so each header's extent is
    // resolved by lookup rather than a rescan.
    let eof_positions: Vec<usize> = find_magic_positions(buf, eof);

    let mut out = Vec::new();
    let mut i = 0usize;
    while i + HEADER_SIZE + EOF_SIZE <= buf.len() {
        if buf.get(i..i + 8) != Some(&magic[..]) {
            i += 1;
            continue;
        }
        let window_end = i.saturating_add(MAX_CARVE_ENTRY).min(buf.len());
        let mut advanced = false;
        for &e in &eof_positions {
            if e < i + HEADER_SIZE {
                continue;
            }
            let end = match e.checked_add(EOF_SIZE) {
                Some(v) if v <= window_end => v,
                _ => break, // positions are sorted; past the window
            };
            let Some(slice) = buf.get(i..end) else {
                break;
            };
            if let Ok(res) = resource_from_entry_bytes(slice, source.to_path_buf(), None, &limits) {
                let quality = grade(&res);
                let note = format!(
                    "recovered by SimpleCache signature carve (header magic at offset {i} in \
                     {}); consistent with a cached response present in slack/unallocated space \
                     that the live index no longer references",
                    source.display()
                );
                out.push(RecoveredResource {
                    resource: res,
                    mechanism: RecoveryMechanism::SignatureCarve,
                    quality,
                    note,
                });
                i = end; // advance past the recovered entry
                advanced = true;
                break;
            }
        }
        if !advanced {
            i += 1;
        }
        if out.len() >= MAX_CARVED_ENTRIES {
            break;
        }
    }
    out
}

/// All byte offsets in `buf` where the 8-byte `needle` occurs (ascending).
fn find_magic_positions(buf: &[u8], needle: [u8; 8]) -> Vec<usize> {
    let mut positions = Vec::new();
    if buf.len() < 8 {
        return positions;
    }
    for off in 0..=buf.len() - 8 {
        if buf.get(off..off + 8) == Some(&needle[..]) {
            positions.push(off);
        }
    }
    positions
}

/// Run the on-disk recovery mechanisms against a cache directory: orphaned
/// SimpleCache entries ([`carve_orphaned_simple`]) and free-but-intact Blockfile
/// entries ([`carve_blockfile_free`]). Signature carving of raw slack is a
/// separate entry point ([`carve_signature`]) since it takes a byte buffer.
#[must_use]
pub fn carve_cache_dir(cache_dir: &Path) -> Vec<RecoveredResource> {
    let mut out = carve_orphaned_simple(cache_dir);
    out.extend(carve_blockfile_free(cache_dir));
    out
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

    // -- Blockfile free-but-intact carve ------------------------------------

    use crate::blockfile::BLOCK_MAGIC;

    fn block256_header() -> Vec<u8> {
        let mut h = vec![0u8; 8192];
        h[0..4].copy_from_slice(&BLOCK_MAGIC.to_le_bytes());
        h[8..10].copy_from_slice(&1i16.to_le_bytes()); // this_file
        h[12..16].copy_from_slice(&256i32.to_le_bytes()); // entry_size
        h
    }

    /// Set allocation-map bit `block` (mark it allocated / live).
    fn alloc(h: &mut [u8], block: usize) {
        let off = 80 + (block / 32) * 4;
        let mut w = u32::from_le_bytes([h[off], h[off + 1], h[off + 2], h[off + 3]]);
        w |= 1u32 << (block % 32);
        h[off..off + 4].copy_from_slice(&w.to_le_bytes());
    }

    /// A 256-byte `EntryStore` block pointing at stream-0/stream-1 addresses.
    fn entry_store(key: &str, s0_addr: u32, s0_len: i32, s1_addr: u32, s1_len: i32) -> Vec<u8> {
        let mut e = vec![0u8; 256];
        e[24..32].copy_from_slice(&13_350_000_000_000_000u64.to_le_bytes()); // creation
        e[32..36].copy_from_slice(&(key.len() as i32).to_le_bytes());
        e[40..44].copy_from_slice(&s0_len.to_le_bytes());
        e[44..48].copy_from_slice(&s1_len.to_le_bytes());
        e[56..60].copy_from_slice(&s0_addr.to_le_bytes());
        e[60..64].copy_from_slice(&s1_addr.to_le_bytes());
        let kb = key.as_bytes();
        let n = kb.len().min(160);
        e[96..96 + n].copy_from_slice(&kb[..n]);
        e
    }

    fn write_block(data: &mut Vec<u8>, block: usize, bytes: &[u8]) {
        let off = 8192 + 256 * block;
        if data.len() < off + 256 {
            data.resize(off + 256, 0);
        }
        data[off..off + bytes.len()].copy_from_slice(bytes);
    }

    #[test]
    fn recovers_free_blockfile_entry_not_live_one() {
        let dir = TempDir::new().unwrap();
        // block 0: LIVE entry (allocated). block 3: FREE entry (evicted).
        // blocks 4/5: the free entry's headers/body (allocated, not reused).
        let addr = |b: u32| 0xA001_0000u32 | b; // init|BLOCK_256|selector1|block
        let live = entry_store("https://live.example/keep", addr(1), 4, addr(2), 4);
        let headers = b"HTTP/1.1 200 OK\0Content-Type: text/plain\0\0";
        let body = b"evicted-body";
        let evicted = entry_store(
            "https://evicted.example/gone",
            addr(4),
            headers.len() as i32,
            addr(5),
            body.len() as i32,
        );

        let mut data1 = block256_header();
        alloc(&mut data1, 0); // live entry
        alloc(&mut data1, 1); // live headers/body blocks
        alloc(&mut data1, 2);
        alloc(&mut data1, 4); // evicted entry's still-intact headers
        alloc(&mut data1, 5); // ...and body
                              // block 3 deliberately left FREE
        write_block(&mut data1, 0, &live);
        write_block(&mut data1, 1, b"HTTP/1.1 200 OK\0\0");
        write_block(&mut data1, 2, b"live");
        write_block(&mut data1, 3, &evicted);
        write_block(&mut data1, 4, headers);
        write_block(&mut data1, 5, body);
        std::fs::write(dir.path().join("data_1"), &data1).unwrap();

        let recovered = carve_blockfile_free(dir.path());
        assert!(
            recovered
                .iter()
                .any(|r| r.resource.url == "https://evicted.example/gone"
                    && r.mechanism == RecoveryMechanism::BlockfileFreeIntact),
            "the FREE evicted entry must be recovered: {recovered:?}"
        );
        assert!(
            recovered
                .iter()
                .all(|r| r.resource.url != "https://live.example/keep"),
            "an allocated (live) entry must NOT be carved: {recovered:?}"
        );
    }

    // -- signature carve from raw bytes -------------------------------------

    #[test]
    fn signature_carve_recovers_embedded_entry() {
        let entry = build_entry("https://carved.example/a.js", b"carved-body", HEADERS);
        let mut buf = vec![0x41u8; 37]; // junk prefix
        buf.extend_from_slice(&entry);
        buf.extend_from_slice(&[0xEE; 19]); // junk suffix
        let recovered = carve_signature(&buf, Path::new("slack.bin"));
        assert_eq!(recovered.len(), 1, "one entry carved: {recovered:?}");
        let r = &recovered[0];
        assert_eq!(r.resource.url, "https://carved.example/a.js");
        assert_eq!(r.resource.raw_body, b"carved-body");
        assert_eq!(r.mechanism, RecoveryMechanism::SignatureCarve);
    }

    #[test]
    fn signature_carve_recovers_two_back_to_back() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&build_entry("https://one.example/1", b"b1", HEADERS));
        buf.extend_from_slice(&build_entry("https://two.example/2", b"body-two", HEADERS));
        let mut urls: Vec<String> = carve_signature(&buf, Path::new("buf"))
            .into_iter()
            .map(|r| r.resource.url)
            .collect();
        urls.sort();
        assert_eq!(urls, ["https://one.example/1", "https://two.example/2"]);
    }

    #[test]
    fn signature_carve_garbage_magic_no_panic() {
        // header magic present, but no valid entry follows → nothing recovered.
        let mut buf = HEADER_MAGIC.to_le_bytes().to_vec();
        buf.extend_from_slice(&[0xABu8; 200]);
        let recovered = carve_signature(&buf, Path::new("g"));
        assert!(
            recovered.is_empty(),
            "garbage after magic must not carve: {recovered:?}"
        );
    }

    #[test]
    fn signature_carve_lying_key_length_no_panic() {
        let mut entry = build_entry("https://a.example/x", b"body", HEADERS);
        // overwrite key_length (offset 12) with a huge value
        entry[12..16].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        let recovered = carve_signature(&entry, Path::new("l"));
        assert!(recovered.is_empty(), "a lying key_length must be skipped");
    }

    #[test]
    fn carve_cache_dir_combines_orphan_and_free() {
        let dir = TempDir::new().unwrap();
        // an orphaned SimpleCache _0
        let orphan_hash: u64 = 0x00000000_1234abcd;
        std::fs::write(
            dir.path().join(format!("{orphan_hash:016x}_0")),
            build_entry("https://orphan.example/o", b"ob", HEADERS),
        )
        .unwrap();
        write_index(dir.path(), &build_real_index(&[]));
        // a free Blockfile entry
        let addr = |b: u32| 0xA001_0000u32 | b;
        let evicted = entry_store("https://evicted.example/e", addr(2), 17, addr(3), 4);
        let mut data1 = block256_header();
        alloc(&mut data1, 2);
        alloc(&mut data1, 3);
        write_block(&mut data1, 0, &evicted); // block 0 FREE
        write_block(&mut data1, 2, b"HTTP/1.1 200 OK\0\0");
        write_block(&mut data1, 3, b"body");
        std::fs::write(dir.path().join("data_1"), &data1).unwrap();

        let all = carve_cache_dir(dir.path());
        assert!(all
            .iter()
            .any(|r| r.mechanism == RecoveryMechanism::OrphanedSimpleEntry));
        assert!(all
            .iter()
            .any(|r| r.mechanism == RecoveryMechanism::BlockfileFreeIntact));
    }

    #[test]
    fn free_body_block_not_a_false_entry() {
        let dir = TempDir::new().unwrap();
        // A FREE block that is a former body (no URL key) must not be carved.
        let mut data1 = block256_header();
        write_block(
            &mut data1,
            0,
            b"just some freed body bytes, no url here at all",
        );
        std::fs::write(dir.path().join("data_1"), &data1).unwrap();
        let recovered = carve_blockfile_free(dir.path());
        assert!(
            recovered.is_empty(),
            "a keyless freed block must not become a phantom entry: {recovered:?}"
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
        assert!(recovered.iter().all(|r| !r.resource.url.is_empty()));
    }
}
