//! `snss` — a read-only decoder for Chromium/Brave SNSS session files.
//!
//! The crate is a pure decoder: it reads bytes and returns a typed model. It has
//! no UI, performs no clipboard or launch side effects, and exposes **no write
//! path** — mutating Brave's store is structurally impossible through this API.
//!
//! Milestone 1 (this module) covers the container framing only: validate the
//! `SNSS` header and split the command stream into [`Record`]s. Higher layers
//! (Pickle decode, replay) build on top of these records.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The 4-byte magic every SNSS file begins with.
pub const MAGIC: [u8; 4] = *b"SNSS";

/// The only container version observed in the wild (and the only one supported).
pub const SUPPORTED_VERSION: i32 = 3;

/// One command record from the append-only stream.
///
/// `payload` is the raw bytes following the command id — for navigation commands
/// this is a Chromium `Pickle` (including its own 4-byte length header), decoded
/// in a later milestone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The command id (e.g. 6 = `UpdateTabNavigation` in the `Session_*` dialect).
    pub id: u8,
    /// Raw payload bytes (everything after the id, `size - 1` bytes long).
    pub payload: Vec<u8>,
}

/// A non-fatal decode anomaly. The model is still usable; warnings record where
/// and why something was skipped so nothing fails silently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    /// The stream ended early at this byte offset: a zero size marker or a record
    /// whose declared size runs past EOF. Normal — Brave appends to live files, so
    /// the final record can be half-written. Parsing stops cleanly here.
    TruncatedTail { offset: u64 },
    /// A navigation record (at this index in the stream) failed to decode and was
    /// skipped during replay. Surfaced, never silently dropped.
    BadNavigation { record: usize, error: PickleError },
    /// A session file in the profile directory could not be read or decoded. The
    /// other sources remain usable; this records which file and why.
    UnreadableSource { path: String, reason: String },
}

/// The result of reading a record stream: the container version, every decoded
/// [`Record`] in stream order, and any non-fatal [`Warning`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordStream {
    /// Container version from the header (always [`SUPPORTED_VERSION`] today).
    pub version: i32,
    /// Records in stream (append) order.
    pub records: Vec<Record>,
    /// Non-fatal anomalies encountered while decoding.
    pub warnings: Vec<Warning>,
}

/// A fatal error that prevents producing any model at all.
#[derive(Debug)]
pub enum SnssError {
    /// The first four bytes were not `SNSS`.
    BadMagic([u8; 4]),
    /// The header declared a container version this decoder does not support.
    UnsupportedVersion(i32),
    /// An I/O error reading the header (record-stream truncation is *not* an
    /// error — it is reported as a [`WarningKind::TruncatedTail`]).
    Io(std::io::Error),
}

impl std::fmt::Display for SnssError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnssError::BadMagic(got) => {
                write!(f, "not an SNSS file: expected magic {MAGIC:?}, got {got:?}")
            }
            SnssError::UnsupportedVersion(v) => {
                write!(
                    f,
                    "unsupported SNSS version {v} (only {SUPPORTED_VERSION} is supported)"
                )
            }
            SnssError::Io(e) => write!(f, "I/O error reading SNSS header: {e}"),
        }
    }
}

impl std::error::Error for SnssError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SnssError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SnssError {
    fn from(e: std::io::Error) -> Self {
        SnssError::Io(e)
    }
}

/// Read an SNSS command stream from any byte source.
///
/// The reader is consumed fully into memory first by the caller's `reader`; this
/// function validates the `SNSS` header, then splits the remaining bytes into
/// [`Record`]s. A truncated tail (zero size marker or a length that overruns EOF)
/// terminates parsing gracefully and is reported as a [`Warning`], never an error.
///
/// # Errors
/// Returns [`SnssError::BadMagic`] / [`SnssError::UnsupportedVersion`] for a header
/// that is not a supported SNSS file, or [`SnssError::Io`] if the header cannot be
/// read.
pub fn read_records<R: Read>(mut reader: R) -> Result<RecordStream, SnssError> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;

    // Header: 4-byte magic + int32 LE version.
    if buf.len() < 8 {
        let mut got = [0u8; 4];
        let n = buf.len().min(4);
        got[..n].copy_from_slice(&buf[..n]);
        return Err(SnssError::BadMagic(got));
    }
    let magic: [u8; 4] = buf[0..4].try_into().expect("4 bytes");
    if magic != MAGIC {
        return Err(SnssError::BadMagic(magic));
    }
    let version = i32::from_le_bytes(buf[4..8].try_into().expect("4 bytes"));
    if version != SUPPORTED_VERSION {
        return Err(SnssError::UnsupportedVersion(version));
    }

    let mut records = Vec::new();
    let mut warnings = Vec::new();
    let mut off = 8usize;
    let len = buf.len();

    loop {
        // Need a full 2-byte size field to continue.
        if off + 2 > len {
            if off < len {
                // A stray partial byte that is not a complete size field.
                warnings.push(Warning::TruncatedTail { offset: off as u64 });
            }
            break;
        }
        let size = u16::from_le_bytes([buf[off], buf[off + 1]]) as usize;
        let body = off + 2;
        // A zero size marker, or a record whose body runs past EOF, is the
        // normal half-written tail Brave leaves behind. Stop cleanly.
        if size == 0 || body + size > len {
            warnings.push(Warning::TruncatedTail { offset: off as u64 });
            break;
        }
        // size counts id (1 byte) + payload (size - 1 bytes).
        let id = buf[body];
        let payload = buf[body + 1..body + size].to_vec();
        records.push(Record { id, payload });
        off = body + size;
    }

    Ok(RecordStream {
        version,
        records,
        warnings,
    })
}

// ----------------------------------------------------------------------------
// Milestone 2 — Pickle decode of the UpdateTabNavigation payload (DESIGN.md §1.3)
// ----------------------------------------------------------------------------

/// A decoded `UpdateTabNavigation` command: which tab, which back/forward
/// position, and the URL + title recorded at that position.
///
/// `tab_id` groups entries into a tab (the replay engine uses it in a later
/// milestone); `index` is the position within that tab's history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavCommand {
    /// SessionID grouping entries into one tab.
    pub tab_id: i32,
    /// Position in the tab's back/forward history.
    pub index: i32,
    /// The page URL (lossily decoded UTF-8; never panics on bad bytes).
    pub url: String,
    /// The page title (lossily decoded UTF-16-LE; never panics on bad bytes).
    pub title: String,
}

/// A malformed navigation payload. Surfaced as a typed error so the caller can
/// count it as a warning rather than crash or emit a silently-wrong row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickleError {
    /// The payload is too short to even hold the 4-byte Pickle length header.
    TooShort,
    /// The Pickle's declared payload size exceeds the bytes actually present.
    BadHeader { declared: usize, actual: usize },
    /// A field's length runs past the end of the Pickle.
    Overrun,
    /// A length prefix was negative (corrupt).
    BadLength(i32),
}

impl std::fmt::Display for PickleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PickleError::TooShort => write!(f, "payload too short for a Pickle header"),
            PickleError::BadHeader { declared, actual } => {
                write!(
                    f,
                    "Pickle declares {declared} payload bytes but only {actual} present"
                )
            }
            PickleError::Overrun => write!(f, "a Pickle field runs past the end of the payload"),
            PickleError::BadLength(n) => write!(f, "negative Pickle length prefix: {n}"),
        }
    }
}

impl std::error::Error for PickleError {}

/// Decode an `UpdateTabNavigation` payload into a [`NavCommand`].
///
/// `payload` is the raw bytes after the command id (i.e. the [`Record::payload`]),
/// which begin with the Chromium Pickle's own 4-byte length header. Fields are
/// 4-byte aligned; `string16` lengths are UTF-16 code-unit counts, not bytes.
///
/// Malformed input yields a [`PickleError`] — never a panic — so a single bad
/// record degrades to a counted warning, not a crash or a wrong value.
///
/// # Errors
/// See [`PickleError`].
pub fn decode_navigation(payload: &[u8]) -> Result<NavCommand, PickleError> {
    let mut p = Pickle::new(payload)?;
    let tab_id = p.read_i32()?;
    let index = p.read_i32()?;
    let url = p.read_string()?;
    let title = p.read_string16()?;
    Ok(NavCommand {
        tab_id,
        index,
        url,
        title,
    })
}

/// A cursor over a Chromium `Pickle`: a 4-byte LE length header followed by
/// 4-byte-aligned fields. Internal: the only public entry point is the
/// type-safe [`decode_navigation`], so a caller cannot read fields in the wrong
/// order or forget the alignment rule. Every read is bounds-checked — reads
/// never panic, they return [`PickleError`].
struct Pickle<'a> {
    data: &'a [u8],
    /// Cursor measured from the start of `data` (i.e. including the 4-byte
    /// header), so alignment is relative to the Pickle start, as Chromium does.
    cursor: usize,
}

impl<'a> Pickle<'a> {
    fn new(payload: &'a [u8]) -> Result<Self, PickleError> {
        if payload.len() < 4 {
            return Err(PickleError::TooShort);
        }
        let declared = u32::from_le_bytes(payload[0..4].try_into().expect("4 bytes")) as usize;
        let actual = payload.len() - 4;
        if declared > actual {
            return Err(PickleError::BadHeader { declared, actual });
        }
        Ok(Pickle {
            data: payload,
            cursor: 4,
        })
    }

    /// Advance the cursor to the next 4-byte boundary (Chromium aligns every
    /// variable-length read up to a 4-byte multiple).
    fn align(&mut self) {
        let rem = self.cursor % 4;
        if rem != 0 {
            self.cursor += 4 - rem;
        }
    }

    fn read_i32(&mut self) -> Result<i32, PickleError> {
        let end = self.cursor.checked_add(4).ok_or(PickleError::Overrun)?;
        if end > self.data.len() {
            return Err(PickleError::Overrun);
        }
        let v = i32::from_le_bytes(self.data[self.cursor..end].try_into().expect("4 bytes"));
        self.cursor = end; // i32 reads are inherently 4-aligned
        Ok(v)
    }

    /// A length-prefixed UTF-8 string, padded to a 4-byte boundary. Decoded
    /// lossily so invalid bytes become U+FFFD rather than crashing or hiding.
    fn read_string(&mut self) -> Result<String, PickleError> {
        let len = self.read_len()?;
        let end = self.cursor.checked_add(len).ok_or(PickleError::Overrun)?;
        if end > self.data.len() {
            return Err(PickleError::Overrun);
        }
        let s = String::from_utf8_lossy(&self.data[self.cursor..end]).into_owned();
        self.cursor = end;
        self.align();
        Ok(s)
    }

    /// A length-prefixed UTF-16-LE string. The prefix counts code *units*, not
    /// bytes; the byte run is padded to a 4-byte boundary. Decoded lossily.
    fn read_string16(&mut self) -> Result<String, PickleError> {
        let units = self.read_len()?;
        let nbytes = units.checked_mul(2).ok_or(PickleError::Overrun)?;
        let end = self
            .cursor
            .checked_add(nbytes)
            .ok_or(PickleError::Overrun)?;
        if end > self.data.len() {
            return Err(PickleError::Overrun);
        }
        let u16s: Vec<u16> = self.data[self.cursor..end]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        self.cursor = end;
        self.align();
        Ok(String::from_utf16_lossy(&u16s))
    }

    /// Read a non-negative length prefix.
    fn read_len(&mut self) -> Result<usize, PickleError> {
        let n = self.read_i32()?;
        if n < 0 {
            return Err(PickleError::BadLength(n));
        }
        Ok(n as usize)
    }
}

// ----------------------------------------------------------------------------
// Milestone 3 — replay the command log into a Window/Tab/Nav tree (DESIGN.md §1.4)
// ----------------------------------------------------------------------------

/// Which command-id mapping a file uses. `Session_*`/`Apps_*` files and the
/// recently-closed `Tabs_*` files number their commands differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// Live/last windows and PWA apps (`Session_*`, `Apps_*`): nav = cmd 6.
    Session,
    /// Recently-closed restore list (`Tabs_*`): nav = cmd 1.
    Tabs,
}

impl Dialect {
    /// Command id of `UpdateTabNavigation` in this dialect.
    fn nav_id(self) -> u8 {
        match self {
            Dialect::Session => 6,
            Dialect::Tabs => 1,
        }
    }
    /// Command id carrying the selected navigation index in this dialect.
    fn selected_id(self) -> u8 {
        match self {
            Dialect::Session => 7,
            Dialect::Tabs => 4,
        }
    }
}

/// One back/forward history entry of a tab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nav {
    /// Position in the tab's history (as stored on disk).
    pub index: i32,
    /// Page URL.
    pub url: String,
    /// Page title.
    pub title: String,
}

/// A reconstructed tab: its history and which entry is current.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tab {
    /// SessionID for this tab.
    pub id: i32,
    /// Whether the tab is pinned (Chrome shows pinned tabs first).
    pub pinned: bool,
    /// Position **within [`Tab::history`]** of the current entry (already
    /// resolved from the selected-navigation-index command, or the last entry).
    pub current: usize,
    /// History entries in ascending on-disk index order, deduplicated so only the
    /// latest append for each index survives.
    pub history: Vec<Nav>,
}

impl Tab {
    /// The current navigation entry (never panics; `history` is always non-empty
    /// for tabs the replay emits, and `current` is always in range).
    pub fn current_nav(&self) -> &Nav {
        &self.history[self.current]
    }
}

/// A reconstructed window holding ordered tabs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    /// SessionID for this window (0 for the synthetic window holding closed tabs).
    pub id: i32,
    /// Tabs in left-to-right order (pinned tabs sort first, as on disk).
    pub tabs: Vec<Tab>,
    /// Most recent tab activity in this window, if any timestamps were present.
    pub last_active: Option<SystemTime>,
}

/// The result of replaying one file's command log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replayed {
    /// Windows in ascending id order.
    pub windows: Vec<Window>,
    /// Non-fatal anomalies (e.g. a navigation record that failed to decode).
    pub warnings: Vec<Warning>,
}

// Raw POD command ids that are identical across the Session/Apps dialect.
const CMD_SET_TAB_WINDOW: u8 = 0;
const CMD_TAB_INDEX_IN_WINDOW: u8 = 2;
const CMD_SET_PINNED_STATE: u8 = 12;
const CMD_LAST_ACTIVE_TIME: u8 = 21;

/// Seconds between the Windows epoch (1601-01-01) and the Unix epoch (1970-01-01).
const WINDOWS_EPOCH_OFFSET_SECS: i64 = 11_644_473_600;

/// Replay an append-only command [`RecordStream`] into the logical
/// [`Window`]/[`Tab`]/[`Nav`] tree, applying last-write-wins per `(tab, index)`
/// and resolving each tab's current entry and pinned state.
pub fn replay(stream: &RecordStream, dialect: Dialect) -> Replayed {
    let nav_id = dialect.nav_id();
    let selected_id = dialect.selected_id();

    // tab_id -> (index -> Nav). BTreeMap on the inner key keeps history sorted and
    // gives last-write-wins: a later append for the same index overwrites.
    let mut histories: BTreeMap<i32, BTreeMap<i32, Nav>> = BTreeMap::new();
    let mut tab_window: HashMap<i32, i32> = HashMap::new();
    let mut tab_order: HashMap<i32, i32> = HashMap::new();
    let mut tab_selected: HashMap<i32, i32> = HashMap::new();
    let mut tab_pinned: HashMap<i32, bool> = HashMap::new();
    let mut tab_time: HashMap<i32, i64> = HashMap::new();
    let mut warnings = Vec::new();

    for (i, rec) in stream.records.iter().enumerate() {
        if rec.id == nav_id {
            match decode_navigation(&rec.payload) {
                Ok(n) => {
                    histories.entry(n.tab_id).or_default().insert(
                        n.index,
                        Nav {
                            index: n.index,
                            url: n.url,
                            title: n.title,
                        },
                    );
                }
                Err(error) => warnings.push(Warning::BadNavigation { record: i, error }),
            }
            continue;
        }
        if rec.id == selected_id {
            if let Some((tab, idx)) = pod_pair(&rec.payload) {
                tab_selected.insert(tab, idx);
            }
            continue;
        }
        // The remaining commands only carry meaning in the Session/Apps dialect;
        // the Tabs dialect reuses these ids for unrelated commands.
        if dialect == Dialect::Session {
            match rec.id {
                CMD_SET_TAB_WINDOW => {
                    if let Some((window, tab)) = pod_pair(&rec.payload) {
                        tab_window.insert(tab, window);
                    }
                }
                CMD_TAB_INDEX_IN_WINDOW => {
                    if let Some((tab, idx)) = pod_pair(&rec.payload) {
                        tab_order.insert(tab, idx);
                    }
                }
                CMD_SET_PINNED_STATE => {
                    if let Some((tab, pinned)) = pod_pinned(&rec.payload) {
                        tab_pinned.insert(tab, pinned);
                    }
                }
                CMD_LAST_ACTIVE_TIME => {
                    if let Some((tab, time)) = pod_last_active(&rec.payload) {
                        tab_time.insert(tab, time);
                    }
                }
                _ => {}
            }
        }
    }

    // Build tabs, grouped into windows. The Tabs dialect has no window mapping, so
    // every closed tab lands in a single synthetic window (id 0).
    let mut window_tabs: BTreeMap<i32, Vec<(i32, Tab)>> = BTreeMap::new();
    for (tab_id, idx_map) in histories {
        let history: Vec<Nav> = idx_map.into_values().collect();
        if history.is_empty() {
            continue;
        }
        let current = match tab_selected.get(&tab_id) {
            Some(sel) => history
                .iter()
                .position(|n| n.index == *sel)
                .unwrap_or(history.len() - 1),
            None => history.len() - 1,
        };
        let tab = Tab {
            id: tab_id,
            pinned: tab_pinned.get(&tab_id).copied().unwrap_or(false),
            current,
            history,
        };
        let window_id = tab_window.get(&tab_id).copied().unwrap_or(0);
        let order = tab_order.get(&tab_id).copied().unwrap_or(i32::MAX);
        window_tabs.entry(window_id).or_default().push((order, tab));
    }

    let windows = window_tabs
        .into_iter()
        .map(|(id, mut ordered)| {
            // Order tabs by TabIndexInWindow, then tab id for stability.
            ordered.sort_by_key(|(order, tab)| (*order, tab.id));
            let tabs: Vec<Tab> = ordered.into_iter().map(|(_, t)| t).collect();
            let last_active = tabs
                .iter()
                .filter_map(|t| tab_time.get(&t.id).copied())
                .max()
                .and_then(windows_micros_to_system_time);
            Window {
                id,
                tabs,
                last_active,
            }
        })
        .collect();

    Replayed { windows, warnings }
}

/// Read a raw two-`i32` POD payload (SetTabWindow, TabIndexInWindow, selected nav).
fn pod_pair(payload: &[u8]) -> Option<(i32, i32)> {
    if payload.len() < 8 {
        return None;
    }
    let a = i32::from_le_bytes(payload[0..4].try_into().ok()?);
    let b = i32::from_le_bytes(payload[4..8].try_into().ok()?);
    Some((a, b))
}

/// Read a SetPinnedState payload: `{tab_id: i32, pinned: bool}`.
fn pod_pinned(payload: &[u8]) -> Option<(i32, bool)> {
    if payload.len() < 5 {
        return None;
    }
    let tab = i32::from_le_bytes(payload[0..4].try_into().ok()?);
    Some((tab, payload[4] != 0))
}

/// Read a LastActiveTime payload: `{tab_id: i32, _pad: i32, time: i64}` where
/// `time` is microseconds since the Windows epoch.
fn pod_last_active(payload: &[u8]) -> Option<(i32, i64)> {
    if payload.len() < 16 {
        return None;
    }
    let tab = i32::from_le_bytes(payload[0..4].try_into().ok()?);
    let time = i64::from_le_bytes(payload[8..16].try_into().ok()?);
    Some((tab, time))
}

/// Convert Windows-epoch microseconds to a [`SystemTime`], or `None` for a zero
/// or pre-Unix-epoch value (which would be meaningless as a last-active stamp).
fn windows_micros_to_system_time(micros: i64) -> Option<SystemTime> {
    let unix_micros = micros.checked_sub(WINDOWS_EPOCH_OFFSET_SECS.checked_mul(1_000_000)?)?;
    if unix_micros <= 0 {
        return None;
    }
    Some(UNIX_EPOCH + Duration::from_micros(unix_micros as u64))
}

// ----------------------------------------------------------------------------
// Source discovery — glob the profile dir into typed sources (DESIGN.md §2.2)
// ----------------------------------------------------------------------------

/// Which on-disk file family a [`Source`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// The newest `Session_*` file — the live/last windows.
    Current,
    /// An older `Session_*` file — the previous session.
    Last,
    /// The newest `Tabs_*` file — the recently-closed restore list.
    RecentlyClosed,
    /// An `Apps_*` file — PWA/app windows.
    Apps,
}

impl SourceKind {
    /// A short human label for the UI.
    pub fn label(self) -> &'static str {
        match self {
            SourceKind::Current => "Current Session",
            SourceKind::Last => "Last Session",
            SourceKind::RecentlyClosed => "Recently Closed",
            SourceKind::Apps => "Apps",
        }
    }
    fn dialect(self) -> Dialect {
        match self {
            SourceKind::RecentlyClosed => Dialect::Tabs,
            _ => Dialect::Session,
        }
    }
}

/// One decoded session file: its kind, path, and reconstructed windows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// Which file family this came from.
    pub kind: SourceKind,
    /// Absolute path to the file it was decoded from.
    pub path: PathBuf,
    /// Windows reconstructed from this file.
    pub windows: Vec<Window>,
}

/// A read-only, in-memory snapshot of a Brave profile's `Sessions` directory.
///
/// Discovery globs `Session_*`/`Tabs_*`/`Apps_*` (filenames rotate while Brave
/// runs, so never hardcode a name), snapshots each file's bytes, and decodes them
/// into [`Source`]s. There is **no write path**: this type cannot mutate Brave's
/// store. A file that fails to decode becomes a [`Warning::UnreadableSource`]
/// while the other sources stay usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStore {
    sources: Vec<Source>,
    warnings: Vec<Warning>,
}

impl SessionStore {
    /// Open the default macOS Brave profile's `Sessions` directory (read-only).
    ///
    /// # Errors
    /// [`SnssError::Io`] if the home directory cannot be resolved or the
    /// directory cannot be listed.
    pub fn open_default_profile() -> Result<Self, SnssError> {
        Self::open_dir(&default_sessions_dir()?)
    }

    /// Open an explicit `Sessions` directory (other profiles, forensic copies).
    ///
    /// # Errors
    /// [`SnssError::Io`] if the directory cannot be listed.
    pub fn open_dir(dir: &Path) -> Result<Self, SnssError> {
        // Group files by family, newest first. Recency comes from the numeric
        // filename suffix (Brave's Windows-epoch stamp), not mtime — copying a
        // profile (fixtures, forensic images) resets mtime but keeps the name.
        let mut by_family: HashMap<&str, Vec<(u64, PathBuf)>> = HashMap::new();
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            for family in ["Session", "Tabs", "Apps"] {
                if let Some(suffix) = name.strip_prefix(family).and_then(|s| s.strip_prefix('_')) {
                    let rank = suffix.parse::<u64>().unwrap_or(0);
                    by_family
                        .entry(family)
                        .or_default()
                        .push((rank, path.clone()));
                }
            }
        }
        for files in by_family.values_mut() {
            files.sort_by(|a, b| b.0.cmp(&a.0)); // newest (largest suffix) first
        }

        // Assign kinds: newest Session = Current, next = Last; newest Tabs =
        // Recently-Closed; newest Apps = Apps. Order is fixed for the UI.
        let sessions = by_family.get("Session").map(Vec::as_slice).unwrap_or(&[]);
        let mut plan: Vec<(SourceKind, &PathBuf)> = Vec::new();
        if let Some((_, p)) = sessions.first() {
            plan.push((SourceKind::Current, p));
        }
        if let Some((_, p)) = sessions.get(1) {
            plan.push((SourceKind::Last, p));
        }
        if let Some((_, p)) = by_family.get("Tabs").and_then(|v| v.first()) {
            plan.push((SourceKind::RecentlyClosed, p));
        }
        if let Some((_, p)) = by_family.get("Apps").and_then(|v| v.first()) {
            plan.push((SourceKind::Apps, p));
        }

        let mut sources = Vec::new();
        let mut warnings = Vec::new();
        for (kind, path) in plan {
            match decode_source(kind, path) {
                Ok((source, source_warnings)) => {
                    sources.push(source);
                    warnings.extend(source_warnings);
                }
                Err(e) => warnings.push(Warning::UnreadableSource {
                    path: path.display().to_string(),
                    reason: e.to_string(),
                }),
            }
        }
        Ok(SessionStore { sources, warnings })
    }

    /// The decoded sources, ordered Current, Last, Recently-Closed, Apps.
    pub fn sources(&self) -> &[Source] {
        &self.sources
    }

    /// Non-fatal anomalies gathered across all sources.
    pub fn warnings(&self) -> &[Warning] {
        &self.warnings
    }
}

/// Snapshot a session file's bytes and decode it into a [`Source`], returning any
/// per-file [`Warning`]s (e.g. truncated tail, bad navigation) alongside it.
fn decode_source(kind: SourceKind, path: &Path) -> Result<(Source, Vec<Warning>), SnssError> {
    // Read fully into memory first so a concurrent Brave rewrite can't tear the
    // decode; the model is immutable once built.
    let bytes = std::fs::read(path)?;
    let stream = read_records(&bytes[..])?;
    let mut warnings = stream.warnings.clone();
    let replayed = replay(&stream, kind.dialect());
    warnings.extend(replayed.warnings);
    let source = Source {
        kind,
        path: path.to_path_buf(),
        windows: replayed.windows,
    };
    Ok((source, warnings))
}

/// Resolve the default macOS Brave `Sessions` directory from `$HOME`.
fn default_sessions_dir() -> Result<PathBuf, SnssError> {
    let home = std::env::var_os("HOME").ok_or_else(|| {
        SnssError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "HOME is not set",
        ))
    })?;
    Ok(PathBuf::from(home)
        .join("Library/Application Support/BraveSoftware/Brave-Browser/Default/Sessions"))
}
