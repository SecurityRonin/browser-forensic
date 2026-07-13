//! Chromium legacy **Blockfile** disk-cache backend.
//!
//! Reads the classic `index` + `data_0..3` + `f_######` on-disk cache
//! (older Chromium HTTP caches; still emitted for `GPUCache`, `ShaderCache`,
//! `GraphiteDawnCache`, and — on some builds — `Code Cache`). It walks the
//! index hash table, follows every `next` chain to enumerate `EntryStore`
//! records, recovers each key (the request URL, inline or long-key/external),
//! and rebuilds the cached response: stream 0 (the pickled `HttpResponseInfo`)
//! is decoded with [`parse_http_meta`](crate::parse_http_meta) — the *same*
//! metadata format SimpleCache uses — and stream 1 (the body) is transparently
//! decompressed with [`decode_body`](crate::decode_body).
//!
//! Layout facts: Chromium `net/disk_cache/blockfile/{disk_format,
//! disk_format_base,addr}.h`, cross-checked against the CCL reverse-engineered
//! reference `ccl_chromium_reader/ccl_chromium_cache.py`:
//!
//! ```text
//! index:  IndexHeader (368 bytes) then table_len × CacheAddr (u32 LE)
//! data_N: BlockFileHeader (8192 bytes) then entry_size-byte blocks
//! EntryStore (256 bytes): hash4 next4 rankings4 reuse4 refetch4 state4
//!   creation8 key_len4 long_key4 data_sizes[4]×4 data_addrs[4]×4 flags4
//!   pad16 self_hash4 | key[160]  (inline, or long_key for >160-byte keys)
//! CacheAddr (u32): [init:1][type:3][reserved:2][num_blocks:2][file:8][block:16]
//! ```
//!
//! Untrusted-input posture: every `CacheAddr`, `key_len`, block offset and file
//! length is bounds-checked before use; table/chain/entry/file caps guard
//! allocation bombs; a visited-set breaks cyclic `next` chains; malformed input
//! degrades to a skipped entry, never a panic.

use std::path::Path;

use crate::decompress::{decode_body, DecompressLimits};
use crate::error::CacheError;
use crate::http_meta::parse_http_meta;
use crate::resource::CachedResource;

/// `index` file magic (`kIndexMagic`, `disk_format.h`).
pub const INDEX_MAGIC: u32 = 0xC103_CAC3;
/// Block-file (`data_N`) magic (`kBlockMagic`, `disk_format_base.h`).
pub const BLOCK_MAGIC: u32 = 0xC104_CAC3;

/// On-disk size of `IndexHeader` (through the `LruData` block); the `CacheAddr`
/// hash table begins here. Verified against real `index` files (default table
/// 0x10000 entries → 368 + 65536*4 = 262512 bytes).
const INDEX_HEADER_SIZE: usize = 368;
/// Fixed block-file header size (`kBlockHeaderSize`, `disk_format_base.h`).
pub(crate) const BLOCK_HEADER_SIZE: usize = 8192;
/// Byte offset of `BlockFileHeader.allocation_map` (`disk_format_base.h`).
pub(crate) const ALLOC_MAP_OFFSET: usize = 80;
/// `kMaxBlocks = (kBlockHeaderSize - 80) * 8` — bits the allocation map covers.
pub(crate) const MAX_BLOCKS_IN_BITMAP: usize = (BLOCK_HEADER_SIZE - ALLOC_MAP_OFFSET) * 8;
/// `EntryStore` block size (`BLOCK_256`); only these blocks hold entries.
pub(crate) const ENTRY_BLOCK_SIZE: usize = 256;
/// Bytes of `EntryStore` before the inline `key[]` (fields hash..self_hash).
const ENTRY_META_SIZE: usize = 96;
/// Default hash-table length when the header's `table_len` is 0.
const DEFAULT_TABLE_LEN: usize = 0x1_0000;

// Robustness caps — each bounds an attacker-controlled length/offset/count.
const MAX_TABLE_LEN: usize = 8 * 1024 * 1024;
const MAX_ENTRIES: usize = 4_000_000;
const MAX_CHAIN: usize = 250_000;
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_STREAM_BYTES: usize = 256 * 1024 * 1024;
/// Microseconds between the Windows/Chrome epoch (1601) and Unix epoch (1970).
const CHROME_EPOCH_DELTA_US: i64 = 11_644_473_600_000_000;

/// Block-file file types (`addr.h` `FileType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileType {
    External,
    Rankings,
    Block256,
    Block1k,
    Block4k,
    Other(u8),
}

/// A decoded `CacheAddr` (`addr.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Addr(pub(crate) u32);

impl Addr {
    pub(crate) fn is_initialized(self) -> bool {
        self.0 & 0x8000_0000 != 0
    }

    fn file_type_raw(self) -> u32 {
        (self.0 & 0x7000_0000) >> 28
    }

    pub(crate) fn file_type(self) -> FileType {
        match self.file_type_raw() {
            0 => FileType::External,
            1 => FileType::Rankings,
            2 => FileType::Block256,
            3 => FileType::Block1k,
            4 => FileType::Block4k,
            n => FileType::Other(n as u8),
        }
    }

    /// `1 + num_blocks` (`kNumBlocksMask`); 1..=4 for a block-file address.
    pub(crate) fn contiguous_blocks(self) -> u32 {
        1 + ((self.0 & 0x0300_0000) >> 24)
    }

    /// Which `data_N` file (`kFileSelectorMask`).
    pub(crate) fn file_selector(self) -> u32 {
        (self.0 & 0x00ff_0000) >> 16
    }

    /// Starting block within the block file (`kStartBlockMask`).
    pub(crate) fn block_number(self) -> u32 {
        self.0 & 0x0000_ffff
    }

    /// `f_######` number for an EXTERNAL address (`kFileNameMask`).
    pub(crate) fn external_file_number(self) -> u32 {
        self.0 & 0x0fff_ffff
    }

    fn reserved_bits(self) -> u32 {
        self.0 & 0x0c00_0000
    }

    /// Port of `addr.cc` `SanityCheck`: known file type, no reserved bits on a
    /// block-file address.
    fn sanity_check(self) -> bool {
        if self.file_type_raw() > 4 {
            return false;
        }
        if self.file_type() != FileType::External && self.reserved_bits() != 0 {
            return false;
        }
        true
    }

    /// An entry is stored as a 256-byte (`BLOCK_256`) block.
    pub(crate) fn sanity_check_for_entry(self) -> bool {
        self.sanity_check() && self.file_type() == FileType::Block256
    }
}

// -- bounded little-endian readers (never index out of bounds) ----------------

fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let s = b.get(off..end)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn rd_i32(b: &[u8], off: usize) -> Option<i32> {
    rd_u32(b, off).map(|v| v as i32)
}

fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let s = b.get(off..end)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}

/// Chrome/Windows microseconds → Unix nanoseconds; 0 on under/overflow.
fn chrome_us_to_unix_ns(us: u64) -> i64 {
    let us = i64::try_from(us).unwrap_or(0);
    us.checked_sub(CHROME_EPOCH_DELTA_US)
        .and_then(|v| v.checked_mul(1000))
        .unwrap_or(0)
}

/// The `index` file header + hash table.
#[derive(Debug, Clone)]
pub struct BlockfileIndex {
    /// `num_entries` from the header (entries the writer believes are stored).
    pub num_entries: i32,
    /// The hash-table slots (raw `CacheAddr` values, initialized or not).
    pub table: Vec<u32>,
}

/// Parse an `index` file's header and hash table.
///
/// # Errors
///
/// [`CacheError::TooSmall`] if shorter than the header, or
/// [`CacheError::BadHeaderMagic`] if the leading `kIndexMagic` is wrong.
pub fn parse_blockfile_index(index: &[u8]) -> Result<BlockfileIndex, CacheError> {
    if index.len() < INDEX_HEADER_SIZE {
        return Err(CacheError::TooSmall {
            found: index.len(),
            need: INDEX_HEADER_SIZE,
        });
    }
    let magic = rd_u32(index, 0).unwrap_or(0);
    if magic != INDEX_MAGIC {
        return Err(CacheError::BadHeaderMagic {
            found: u64::from(magic),
            expected: u64::from(INDEX_MAGIC),
        });
    }
    let num_entries = rd_i32(index, 8).unwrap_or(0);
    let mut table_len = match rd_i32(index, 28).unwrap_or(0) {
        n if n <= 0 => DEFAULT_TABLE_LEN,
        n => n as usize,
    };
    table_len = table_len.min(MAX_TABLE_LEN);
    let available = (index.len() - INDEX_HEADER_SIZE) / 4;
    table_len = table_len.min(available);

    let mut table = Vec::with_capacity(table_len);
    for slot in 0..table_len {
        table.push(rd_u32(index, INDEX_HEADER_SIZE + slot * 4).unwrap_or(0));
    }
    Ok(BlockfileIndex { num_entries, table })
}

/// Is Blockfile allocation-map bit `block` set (i.e. the block is allocated /
/// live)? A clear bit is a FREE block — a carve candidate. Bounds-checked
/// against both the header bytes and the map's bit coverage.
pub(crate) fn block_allocated(header: &[u8], block: usize) -> bool {
    if block >= MAX_BLOCKS_IN_BITMAP {
        return true; // beyond the map: treat as non-free so it is never carved
    }
    let word_off = ALLOC_MAP_OFFSET + (block / 32) * 4;
    let Some(word) = rd_u32(header, word_off) else {
        return true;
    };
    word & (1u32 << (block % 32)) != 0
}

/// The `EntryStore` fields we need (`disk_format.h`).
pub(crate) struct EntryStore {
    next: Addr,
    creation_us: u64,
    key_len: i32,
    long_key: Addr,
    data_sizes: [i32; 4],
    data_addrs: [Addr; 4],
}

pub(crate) fn parse_entry_store(b: &[u8]) -> Option<EntryStore> {
    if b.len() < ENTRY_META_SIZE {
        return None;
    }
    Some(EntryStore {
        next: Addr(rd_u32(b, 4)?),
        creation_us: rd_u64(b, 24)?,
        key_len: rd_i32(b, 32)?,
        long_key: Addr(rd_u32(b, 36)?),
        data_sizes: [
            rd_i32(b, 40)?,
            rd_i32(b, 44)?,
            rd_i32(b, 48)?,
            rd_i32(b, 52)?,
        ],
        data_addrs: [
            Addr(rd_u32(b, 56)?),
            Addr(rd_u32(b, 60)?),
            Addr(rd_u32(b, 64)?),
            Addr(rd_u32(b, 68)?),
        ],
    })
}

/// A loaded `data_N` block file: its per-block size plus raw bytes.
pub(crate) struct BlockData {
    entry_size: usize,
    bytes: Vec<u8>,
}

/// Lazily-loaded set of `data_N` block files, keyed by file selector.
pub(crate) struct BlockFiles<'a> {
    dir: &'a Path,
    files: std::collections::HashMap<u32, Option<BlockData>>,
}

impl<'a> BlockFiles<'a> {
    pub(crate) fn new(dir: &'a Path) -> Self {
        Self {
            dir,
            files: std::collections::HashMap::new(),
        }
    }

    fn block_file(&mut self, selector: u32) -> Option<&BlockData> {
        if !self.files.contains_key(&selector) {
            let loaded = load_block_file(self.dir, selector);
            self.files.insert(selector, loaded);
        }
        self.files.get(&selector).and_then(Option::as_ref)
    }

    /// Read the raw bytes an address points at (block-file span or whole
    /// external file). Bounds-checked; `None` if unreadable/out of range.
    fn read_addr(&mut self, addr: Addr) -> Option<Vec<u8>> {
        match addr.file_type() {
            FileType::External => read_capped_file(
                &self
                    .dir
                    .join(format!("f_{:06x}", addr.external_file_number())),
            ),
            FileType::Block256 | FileType::Block1k | FileType::Block4k => {
                let block_number = addr.block_number() as usize;
                let blocks = addr.contiguous_blocks() as usize;
                let bd = self.block_file(addr.file_selector())?;
                let entry_size = bd.entry_size;
                let start = BLOCK_HEADER_SIZE.checked_add(entry_size.checked_mul(block_number)?)?;
                let len = entry_size.checked_mul(blocks)?;
                let end = start.checked_add(len)?;
                bd.bytes.get(start..end).map(<[u8]>::to_vec)
            }
            FileType::Rankings | FileType::Other(_) => None,
        }
    }

    /// Recover stream `i` (`data_addr[i]`, trimmed to `data_size[i]`); empty
    /// when the stream is absent.
    fn read_stream(&mut self, es: &EntryStore, i: usize) -> Vec<u8> {
        let addr = es.data_addrs[i];
        if !addr.is_initialized() {
            return Vec::new();
        }
        let Some(data) = self.read_addr(addr) else {
            return Vec::new();
        };
        let want = usize::try_from(es.data_sizes[i])
            .unwrap_or(0)
            .min(MAX_STREAM_BYTES)
            .min(data.len());
        data.get(..want).map(<[u8]>::to_vec).unwrap_or_default()
    }
}

pub(crate) fn load_block_file(dir: &Path, selector: u32) -> Option<BlockData> {
    let bytes = read_capped_file(&dir.join(format!("data_{selector}")))?;
    if bytes.len() < BLOCK_HEADER_SIZE || rd_u32(&bytes, 0)? != BLOCK_MAGIC {
        return None;
    }
    let entry_size = rd_i32(&bytes, 12)?;
    if entry_size <= 0 {
        return None;
    }
    Some(BlockData {
        entry_size: entry_size as usize,
        bytes,
    })
}

/// Read a whole file, refusing anything larger than [`MAX_FILE_BYTES`].
fn read_capped_file(path: &Path) -> Option<Vec<u8>> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_FILE_BYTES {
        return None;
    }
    std::fs::read(path).ok()
}

/// Recover an entry's key (the request URL): inline in the `EntryStore`, or via
/// the long-key address for keys too long to store inline.
pub(crate) fn resolve_key(es: &EntryStore, entry_block: &[u8], cache: &mut BlockFiles) -> Option<String> {
    let key_len = usize::try_from(es.key_len).ok()?;
    if es.long_key.is_initialized() {
        let data = cache.read_addr(es.long_key)?;
        let n = key_len.min(data.len());
        Some(std::str::from_utf8(data.get(..n)?).ok()?.to_string())
    } else {
        let avail = entry_block.len().saturating_sub(ENTRY_META_SIZE);
        let n = key_len.min(avail);
        let bytes = entry_block.get(ENTRY_META_SIZE..ENTRY_META_SIZE + n)?;
        Some(std::str::from_utf8(bytes).ok()?.to_string())
    }
}

/// Enumerate every recoverable [`CachedResource`] in a legacy Blockfile cache
/// directory, using default decompression limits. Best-effort: a directory that
/// is not a Blockfile cache (or is unreadable) yields an empty vec.
#[must_use]
pub fn parse_blockfile_cache_dir(cache_dir: &Path) -> Vec<CachedResource> {
    parse_blockfile_cache_dir_with(cache_dir, &DecompressLimits::default())
}

/// Enumerate every recoverable [`CachedResource`], with explicit limits.
#[must_use]
pub fn parse_blockfile_cache_dir_with(
    cache_dir: &Path,
    limits: &DecompressLimits,
) -> Vec<CachedResource> {
    let index_path = cache_dir.join("index");
    let Ok(index_bytes) = std::fs::read(&index_path) else {
        return Vec::new();
    };
    // A bad/short index means "not a Blockfile cache" at this probe layer — the
    // caller tries every backend against many paths, so degrade to empty rather
    // than erroring on a directory this backend simply does not own.
    let Ok(index) = parse_blockfile_index(&index_bytes) else {
        return Vec::new();
    };

    let mut cache = BlockFiles::new(cache_dir);
    let mut out = Vec::new();
    let mut visited: std::collections::HashSet<u32> = std::collections::HashSet::new();

    'table: for raw in index.table {
        let mut cur = Addr(raw);
        let mut chain = 0usize;
        while cur.is_initialized() {
            if out.len() >= MAX_ENTRIES {
                break 'table;
            }
            if chain >= MAX_CHAIN || !visited.insert(cur.0) || !cur.sanity_check_for_entry() {
                break;
            }
            let block = match cache.read_addr(cur) {
                Some(b) if b.len() >= ENTRY_META_SIZE => b,
                _ => break,
            };
            let es = match parse_entry_store(&block) {
                Some(e) => e,
                None => break,
            };
            if let Some(url) = resolve_key(&es, &block, &mut cache) {
                if !url.is_empty() {
                    out.push(build_resource(&es, url, &index_path, &mut cache, limits));
                }
            }
            cur = es.next;
            chain += 1;
        }
    }
    out
}

/// Build a [`CachedResource`] from an entry: stream 0 → [`parse_http_meta`],
/// stream 1 → raw body → [`decode_body`]. A decode failure keeps the raw body
/// and records the reason (fail-loud, no data loss).
pub(crate) fn build_resource(
    es: &EntryStore,
    url: String,
    index_path: &Path,
    cache: &mut BlockFiles,
    limits: &DecompressLimits,
) -> CachedResource {
    let stream0 = cache.read_stream(es, 0);
    let raw_body = cache.read_stream(es, 1);

    let meta = parse_http_meta(&stream0);
    let content_type = meta.content_type().map(str::to_string);
    let content_encoding = meta.content_encoding().map(str::to_string);
    let creation_ns = chrome_us_to_unix_ns(es.creation_us);

    let (decoded_body, body_decoded, decode_note) =
        match decode_body(content_encoding.as_deref(), &raw_body, limits) {
            Ok(outcome) => (outcome.bytes, outcome.decoded, outcome.note),
            Err(e) => (raw_body.clone(), false, Some(format!("decode failed: {e}"))),
        };

    CachedResource {
        url,
        http_status: meta.http_status,
        status_line: meta.status_line,
        headers: meta.headers,
        content_type,
        content_encoding,
        // Blockfile stores one creation time per entry, not the separate
        // request/response times SimpleCache's pickle carries.
        request_time_ns: meta.request_time_ns.or(Some(creation_ns)),
        response_time_ns: meta.response_time_ns.or(Some(creation_ns)),
        raw_body,
        decoded_body,
        body_decoded,
        decode_note,
        source_file: index_path.to_path_buf(),
        sparse_file: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    const CHROME_US_2024: u64 = 13_350_000_000_000_000;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    // -- Addr decoding -------------------------------------------------------

    #[test]
    fn addr_initialized_bit() {
        assert!(!Addr(0x2001_0000).is_initialized());
        assert!(Addr(0xA001_0000).is_initialized());
    }

    #[test]
    fn addr_decodes_block256_entry_fields() {
        let a = Addr(0xA001_0000);
        assert_eq!(a.file_type(), FileType::Block256);
        assert_eq!(a.file_selector(), 1);
        assert_eq!(a.block_number(), 0);
        assert_eq!(a.contiguous_blocks(), 1);
        assert!(a.sanity_check_for_entry());
    }

    #[test]
    fn addr_decodes_multiblock_and_block_number() {
        let a = Addr(0xA000_0000 | 0x0200_0000 | 0x0001_0000 | 0x1234);
        assert_eq!(a.contiguous_blocks(), 3);
        assert_eq!(a.block_number(), 0x1234);
    }

    #[test]
    fn addr_external_file_number() {
        let a = Addr(0x8000_0000 | 0x0000_002A);
        assert_eq!(a.file_type(), FileType::External);
        assert_eq!(a.external_file_number(), 0x2A);
    }

    #[test]
    fn addr_entry_sanity_rejects_non_block256_and_reserved() {
        assert!(!Addr(0xB001_0000).sanity_check_for_entry()); // BLOCK_1K
        assert!(!Addr(0xA001_0000 | 0x0400_0000).sanity_check_for_entry()); // reserved bit
    }

    // -- index parsing -------------------------------------------------------

    fn u32b(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    fn build_index(magic: u32, table: &[u32]) -> Vec<u8> {
        let mut index = vec![0u8; 368];
        index[0..4].copy_from_slice(&u32b(magic));
        index[4..8].copy_from_slice(&u32b(0x3_0000)); // version
        index[8..12].copy_from_slice(&(table.len() as i32).to_le_bytes()); // num_entries
        index[28..32].copy_from_slice(&(table.len() as i32).to_le_bytes()); // table_len
        for a in table {
            index.extend_from_slice(&u32b(*a));
        }
        index
    }

    #[test]
    fn parse_index_valid() {
        let idx = parse_blockfile_index(&build_index(INDEX_MAGIC, &[0xA001_0000, 0])).unwrap();
        assert_eq!(idx.num_entries, 2);
        assert_eq!(idx.table.len(), 2);
        assert_eq!(idx.table[0], 0xA001_0000);
    }

    #[test]
    fn parse_index_bad_magic_errs() {
        let err = parse_blockfile_index(&build_index(0xDEAD_BEEF, &[0])).unwrap_err();
        assert!(matches!(err, CacheError::BadHeaderMagic { .. }), "{err}");
    }

    #[test]
    fn parse_index_too_short_errs() {
        let err = parse_blockfile_index(&[0u8; 16]).unwrap_err();
        assert!(matches!(err, CacheError::TooSmall { .. }), "{err}");
    }

    // -- end-to-end backend --------------------------------------------------

    fn block_header(this_file: i16, entry_size: i32) -> Vec<u8> {
        let mut h = vec![0u8; 8192];
        h[0..4].copy_from_slice(&u32b(BLOCK_MAGIC));
        h[8..10].copy_from_slice(&this_file.to_le_bytes());
        h[12..16].copy_from_slice(&entry_size.to_le_bytes());
        h
    }

    /// 256-byte EntryStore pointing at stream-0 (headers) and stream-1 (body).
    fn entry_store(
        next: u32,
        key: &str,
        s0_addr: u32,
        s0_len: i32,
        s1_addr: u32,
        s1_len: i32,
    ) -> Vec<u8> {
        let mut e = vec![0u8; 256];
        e[4..8].copy_from_slice(&u32b(next));
        e[12..16].copy_from_slice(&1i32.to_le_bytes()); // reuse
        e[16..20].copy_from_slice(&2i32.to_le_bytes()); // refetch
        e[24..32].copy_from_slice(&CHROME_US_2024.to_le_bytes());
        e[32..36].copy_from_slice(&(key.len() as i32).to_le_bytes());
        e[40..44].copy_from_slice(&s0_len.to_le_bytes()); // data_size[0]
        e[44..48].copy_from_slice(&s1_len.to_le_bytes()); // data_size[1]
        e[56..60].copy_from_slice(&u32b(s0_addr)); // data_addr[0]
        e[60..64].copy_from_slice(&u32b(s1_addr)); // data_addr[1]
        let kb = key.as_bytes();
        let n = kb.len().min(160);
        e[96..96 + n].copy_from_slice(&kb[..n]);
        e
    }

    fn write_block(data1: &mut Vec<u8>, block: usize, bytes: &[u8]) {
        let off = 8192 + 256 * block;
        if data1.len() < off + 256 {
            data1.resize(off + 256, 0);
        }
        data1[off..off + bytes.len()].copy_from_slice(bytes);
    }

    /// Assemble a one-entry blockfile cache: entry at block 0, headers at block
    /// 1, body at block 2 (all in data_1, BLOCK_256).
    fn build_cache(dir: &Path, url: &str, headers: &[u8], body: &[u8], index_magic: u32) {
        let entry = entry_store(
            0,
            url,
            0xA001_0001,
            headers.len() as i32,
            0xA001_0002,
            body.len() as i32,
        );
        fs::write(dir.join("index"), build_index(index_magic, &[0xA001_0000])).unwrap();
        fs::write(dir.join("data_0"), block_header(0, 36)).unwrap();
        let mut data1 = block_header(1, 256);
        write_block(&mut data1, 0, &entry);
        write_block(&mut data1, 1, headers);
        write_block(&mut data1, 2, body);
        fs::write(dir.join("data_1"), &data1).unwrap();
    }

    #[test]
    fn backend_rebuilds_resource_with_headers_and_gzip_body() {
        let dir = TempDir::new().unwrap();
        let html = b"<html>hi</html>";
        let body = gzip(html);
        let headers = b"HTTP/1.1 200 OK\0Content-Type: text/html\0Content-Encoding: gzip\0\0";
        build_cache(
            dir.path(),
            "https://example.com/app.js",
            headers,
            &body,
            INDEX_MAGIC,
        );

        let res = parse_blockfile_cache_dir(dir.path());
        assert_eq!(res.len(), 1);
        let r = &res[0];
        assert_eq!(r.url, "https://example.com/app.js");
        assert_eq!(r.http_status, Some(200));
        assert_eq!(r.content_type.as_deref(), Some("text/html"));
        assert_eq!(r.content_encoding.as_deref(), Some("gzip"));
        assert_eq!(r.raw_body, body);
        assert_eq!(r.decoded_body, html);
        assert!(r.body_decoded);
    }

    #[test]
    fn backend_bad_index_magic_yields_empty() {
        let dir = TempDir::new().unwrap();
        build_cache(
            dir.path(),
            "https://e.com/x",
            b"HTTP/1.1 200 OK\0\0",
            b"x",
            0xDEAD_BEEF,
        );
        assert!(parse_blockfile_cache_dir(dir.path()).is_empty());
    }

    #[test]
    fn backend_addr_out_of_range_skips() {
        let dir = TempDir::new().unwrap();
        // point the table slot at a block far past the data_1 file
        let entry = entry_store(0, "https://e.com/x", 0, 0, 0, 0);
        fs::write(
            dir.path().join("index"),
            build_index(INDEX_MAGIC, &[0xA001_FFFF]),
        )
        .unwrap();
        fs::write(dir.path().join("data_0"), block_header(0, 36)).unwrap();
        let mut data1 = block_header(1, 256);
        write_block(&mut data1, 0, &entry);
        fs::write(dir.path().join("data_1"), &data1).unwrap();
        assert!(parse_blockfile_cache_dir(dir.path()).is_empty());
    }

    #[test]
    fn backend_cyclic_next_terminates() {
        let dir = TempDir::new().unwrap();
        let entry = entry_store(0xA001_0000, "https://e.com/a", 0, 0, 0, 0);
        fs::write(
            dir.path().join("index"),
            build_index(INDEX_MAGIC, &[0xA001_0000]),
        )
        .unwrap();
        fs::write(dir.path().join("data_0"), block_header(0, 36)).unwrap();
        let mut data1 = block_header(1, 256);
        write_block(&mut data1, 0, &entry);
        fs::write(dir.path().join("data_1"), &data1).unwrap();
        assert_eq!(parse_blockfile_cache_dir(dir.path()).len(), 1);
    }

    #[test]
    fn backend_lying_key_len_does_not_panic() {
        let dir = TempDir::new().unwrap();
        let mut entry = entry_store(0, "https://e.com/x", 0, 0, 0, 0);
        entry[32..36].copy_from_slice(&1_000_000i32.to_le_bytes());
        fs::write(
            dir.path().join("index"),
            build_index(INDEX_MAGIC, &[0xA001_0000]),
        )
        .unwrap();
        fs::write(dir.path().join("data_0"), block_header(0, 36)).unwrap();
        let mut data1 = block_header(1, 256);
        write_block(&mut data1, 0, &entry);
        fs::write(dir.path().join("data_1"), &data1).unwrap();
        let _ = parse_blockfile_cache_dir(dir.path());
    }

    #[test]
    fn backend_non_blockfile_dir_yields_empty() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("random"), b"not a cache").unwrap();
        assert!(parse_blockfile_cache_dir(dir.path()).is_empty());
    }

    /// Tier-1 validation against a real Chromium Blockfile cache, cross-checked
    /// against the CCL `ccl_chromium_reader` oracle. Env-gated: skips cleanly
    /// when `BF_BLOCKFILE_CACHE_DIR` is unset.
    #[test]
    fn real_blockfile_cache_matches_oracle() {
        let Ok(dir) = std::env::var("BF_BLOCKFILE_CACHE_DIR") else {
            return;
        };
        let res = parse_blockfile_cache_dir(Path::new(&dir));
        assert!(!res.is_empty(), "expected entries from {dir}");
        if let Ok(expect) = std::env::var("BF_BLOCKFILE_EXPECT") {
            assert_eq!(res.len(), expect.parse::<usize>().unwrap());
        }
        if let Ok(out) = std::env::var("BF_BLOCKFILE_KEYS_OUT") {
            let mut keys: Vec<&str> = res.iter().map(|r| r.url.as_str()).collect();
            keys.sort_unstable();
            fs::write(out, keys.join("\n")).unwrap();
        }
    }
}
