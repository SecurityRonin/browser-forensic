#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Disk-image ingest for browser-forensic — a thin, read-only adapter over the
//! [`forensic_vfs`] `FileSystem` contract.
//!
//! # Architecture: zero disk code here
//!
//! browser-forensic owns **no** container / partition / filesystem parsing. All
//! disk work is delegated to the `forensic-vfs` fleet. This crate speaks only the
//! published [`forensic_vfs::FileSystem`] trait: given an already-mounted,
//! read-only filesystem it walks the tree, locates browser profiles across every
//! user using the [`forensicnomicon::browser_profiles`] markers, reads each
//! profile's artifact files **through the trait**, materializes them to a temp
//! directory, and runs the existing browser-forensic parsers via
//! [`browser_forensic_triage::triage_profile`]. Recovered [`BrowserEvent`]s are
//! stamped with image / volume / user provenance.
//!
//! # The one disk seam: opening an image from a path
//!
//! Turning an `E01` / raw / `dmg` **path** into mounted filesystems (detecting
//! and composing the container → partition → filesystem stack) is the job of the
//! `forensic-vfs` **engine** (`forensic_vfs_engine::Vfs::open`). That engine is
//! not yet published to crates.io (it is `publish = false` and path-bound to the
//! fleet's per-format readers), so [`ingest_image_path`] currently fails **loud**
//! rather than silently returning nothing. The generic [`ingest_image`] takes the
//! opener as a parameter, so the moment the engine publishes, wiring is a
//! one-function change and every test here already covers the pipeline behind it.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use forensicnomicon::browser_profiles::{
    attribute_container, chromium_profile_markers, firefox_profile_markers, MarkerKind,
    ProfileMarker, FIREFOX_PROFILE_MARKER_SUFFIXES,
};

use browser_forensic_core::{BrowserEvent, BrowserFamily};
use browser_forensic_triage::triage_profile;

use forensic_vfs::{FileId, NodeKind, StreamId, VfsResult};

/// Re-exported so a downstream binary (the `br4n6` CLI) can name an opener's
/// return type without taking its own direct dependency on `forensic-vfs`.
pub use forensic_vfs::{DynFs, FileSystem};

/// Directory-recursion cap for [`walk_fs`] — a filesystem-loop guard mirroring
/// the engine's own walk bound.
const WALK_MAX_DEPTH: usize = 256;

/// Per-artifact read cap (allocation-bomb guard). A single browser artifact far
/// exceeding this is not materialized past the cap; parsing degrades on that one
/// file rather than letting a lying size field exhaust memory/disk.
const MAX_ARTIFACT_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB

/// Streaming read chunk.
const READ_CHUNK: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Walk — trait-only traversal of a mounted filesystem
// ---------------------------------------------------------------------------

/// One node discovered by [`walk_fs`]. Names are raw bytes (a filesystem name is
/// not guaranteed UTF-8), so the path is a vector of byte components.
#[derive(Clone)]
struct Node {
    path: Vec<Vec<u8>>,
    id: FileId,
    is_dir: bool,
    size: u64,
}

/// Recursively enumerate every node of a mounted filesystem from the root, using
/// only the [`FileSystem`] trait. Depth-capped and visited-guarded against
/// directory loops; `.`/`..` entries are skipped. A per-node read error aborts
/// loud (never a silent partial tree).
fn walk_fs(fs: &dyn FileSystem) -> VfsResult<Vec<Node>> {
    let mut out = Vec::new();
    let mut visited: HashSet<FileId> = HashSet::new();
    let mut stack: Vec<(Vec<Vec<u8>>, FileId, usize)> = vec![(Vec::new(), fs.root(), 0)];
    while let Some((prefix, dir_id, depth)) = stack.pop() {
        if depth > WALK_MAX_DEPTH || !visited.insert(dir_id) {
            continue;
        }
        for entry in fs.read_dir(dir_id)? {
            let entry = entry?;
            if matches!(entry.name.as_slice(), b"." | b"..") {
                continue;
            }
            let mut path = prefix.clone();
            path.push(entry.name);
            let meta = fs.meta(entry.id)?;
            let is_dir = matches!(meta.kind, NodeKind::Dir);
            out.push(Node {
                path: path.clone(),
                id: entry.id,
                is_dir,
                size: meta.size,
            });
            if is_dir {
                stack.push((path, entry.id, depth + 1));
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Locate — browser profiles across an image's users, via forensicnomicon markers
// ---------------------------------------------------------------------------

/// A browser profile located in the walked tree: its directory path (byte
/// components) and the engine family to route it to.
#[derive(Clone)]
struct Located {
    dir: Vec<Vec<u8>>,
    browser: BrowserFamily,
}

/// A filesystem path as raw byte components (names are not guaranteed UTF-8).
type BytePath = Vec<Vec<u8>>;
/// A directory's immediate children: `(name, is_dir)` pairs.
type ChildList = Vec<(Vec<u8>, bool)>;

/// Index over a walk: which paths exist (and whether each is a directory).
struct PathIndex {
    /// path -> is_dir
    kinds: HashMap<BytePath, bool>,
    /// parent path -> its immediate children (name, is_dir)
    children: HashMap<BytePath, ChildList>,
}

impl PathIndex {
    fn build(nodes: &[Node]) -> Self {
        let mut kinds = HashMap::new();
        let mut children: HashMap<BytePath, ChildList> = HashMap::new();
        for n in nodes {
            kinds.insert(n.path.clone(), n.is_dir);
            if let Some((name, parent)) = n.path.split_last() {
                children
                    .entry(parent.to_vec())
                    .or_default()
                    .push((name.clone(), n.is_dir));
            }
        }
        Self { kinds, children }
    }

    /// Does a marker resolve, relative to `dir`, to an existing node of the right
    /// kind? Nested markers (`Network/Cookies`, `Local Storage/leveldb`) resolve
    /// component by component.
    fn marker_present(&self, dir: &[Vec<u8>], marker: &ProfileMarker) -> bool {
        let mut candidate = dir.to_vec();
        for seg in marker.relative_path.split('/') {
            candidate.push(seg.as_bytes().to_vec());
        }
        match self.kinds.get(&candidate) {
            Some(&is_dir) => match marker.kind {
                MarkerKind::Dir => is_dir,
                MarkerKind::File => !is_dir,
            },
            None => false,
        }
    }

    /// Does `dir` hold a direct child file whose name ends with any Firefox
    /// mozLz4 marker suffix (`.jsonlz4` / `.baklz4`)?
    fn has_firefox_suffix_child(&self, dir: &[Vec<u8>]) -> bool {
        self.children.get(dir).is_some_and(|kids| {
            kids.iter().any(|(name, is_dir)| {
                !is_dir && {
                    let n = String::from_utf8_lossy(name);
                    FIREFOX_PROFILE_MARKER_SUFFIXES
                        .iter()
                        .any(|s| n.ends_with(s))
                }
            })
        })
    }

    /// Does `dir` hold a direct child file named `name` (case-sensitive)?
    fn has_child_file(&self, dir: &[Vec<u8>], name: &[u8]) -> bool {
        self.children.get(dir).is_some_and(|kids| {
            kids.iter()
                .any(|(child, is_dir)| !is_dir && child.as_slice() == name)
        })
    }
}

/// Locate every browser profile in the walked tree.
///
/// A directory is a profile if it carries any Chromium or Firefox signature
/// marker (see [`forensicnomicon::browser_profiles`]), matched over the walked
/// paths rather than the local disk — so an unknown-named embedded-Chromium
/// container is still found. Safari is matched structurally by a `Safari`
/// directory holding `History.db` (mirroring the local discovery path, which the
/// marker set does not cover). Chromium is tested first, then Firefox, then
/// Safari; a directory is emitted at most once.
fn locate_profiles(nodes: &[Node], index: &PathIndex) -> Vec<Located> {
    let mut out = Vec::new();
    for n in nodes {
        if !n.is_dir {
            continue;
        }
        let dir = &n.path;
        if chromium_profile_markers()
            .iter()
            .any(|m| index.marker_present(dir, m))
        {
            out.push(Located {
                dir: dir.clone(),
                browser: BrowserFamily::Chromium,
            });
            continue;
        }
        if firefox_profile_markers()
            .iter()
            .any(|m| index.marker_present(dir, m))
            || index.has_firefox_suffix_child(dir)
        {
            out.push(Located {
                dir: dir.clone(),
                browser: BrowserFamily::Firefox,
            });
            continue;
        }
        // Safari: a `Safari` directory holding `History.db`.
        let is_safari_dir = dir
            .last()
            .is_some_and(|name| name.eq_ignore_ascii_case(b"Safari"));
        if is_safari_dir && index.has_child_file(dir, b"History.db") {
            out.push(Located {
                dir: dir.clone(),
                browser: BrowserFamily::Safari,
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Materialize — read profile artifacts through the trait into a temp directory
// ---------------------------------------------------------------------------

/// Reject a name component that could escape the destination directory. Filesystem
/// names in an image are attacker-controllable; a component containing a path
/// separator, a NUL, or `.`/`..` is refused so materialization can never write
/// outside the temp tree (secure-by-construction, not by convention).
fn safe_component(name: &[u8]) -> Option<PathBuf> {
    if name.is_empty() || name == b"." || name == b".." {
        return None;
    }
    let s = String::from_utf8_lossy(name);
    if s.contains('/') || s.contains('\\') || s.contains('\0') {
        return None;
    }
    Some(PathBuf::from(s.into_owned()))
}

/// Stream a file's bytes (default stream) into `out`, chunked and capped. Returns
/// the number of bytes written.
fn stream_file(fs: &dyn FileSystem, id: FileId, size: u64, out: &mut File) -> Result<u64> {
    let cap = size.min(MAX_ARTIFACT_BYTES);
    let mut off = 0u64;
    let mut buf = vec![0u8; READ_CHUNK];
    while off < cap {
        let want = usize::try_from((cap - off).min(READ_CHUNK as u64)).unwrap_or(READ_CHUNK);
        let n = fs
            .read_at(id, StreamId::Default, off, &mut buf[..want])
            .map_err(|e| anyhow!("read_at failed at offset {off}: {e:?}"))?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])
            .with_context(|| "writing materialized artifact")?;
        off += n as u64;
    }
    Ok(off)
}

/// Materialize the file subtree rooted at `dir` into `dest`, mirroring the
/// relative layout. Directories are created lazily from each file's parent chain.
/// A single unreadable / unsafe file degrades that one artifact (skipped) rather
/// than aborting the profile.
fn materialize_profile(
    fs: &dyn FileSystem,
    nodes: &[Node],
    dir: &[Vec<u8>],
    dest: &Path,
) -> Result<()> {
    for n in nodes {
        if n.is_dir || n.path.len() <= dir.len() || !n.path.starts_with(dir) {
            continue;
        }
        let rel = &n.path[dir.len()..];
        let mut target = dest.to_path_buf();
        let mut safe = true;
        for comp in rel {
            let Some(p) = safe_component(comp) else {
                safe = false;
                break;
            };
            target.push(p);
        }
        if !safe {
            continue;
        }
        if let Some(parent) = target.parent() {
            if fs::create_dir_all(parent).is_err() {
                continue;
            }
        }
        let mut file = match File::create(&target) {
            Ok(f) => f,
            Err(_) => continue,
        };
        // Per-file degrade: a read failure skips this artifact, not the profile.
        let _ = stream_file(fs, n.id, n.size, &mut file);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/// Derive the owning user from a profile directory path — the component after a
/// `Users` (Windows/macOS) or `home` (Linux) segment, if any.
fn user_of(dir: &[Vec<u8>]) -> Option<String> {
    dir.iter().enumerate().find_map(|(i, comp)| {
        let c = String::from_utf8_lossy(comp);
        if (c.eq_ignore_ascii_case("Users") || c.eq_ignore_ascii_case("home")) && i + 1 < dir.len()
        {
            Some(String::from_utf8_lossy(&dir[i + 1]).into_owned())
        } else {
            None
        }
    })
}

/// Render a byte-component path as a display string (lossy).
fn path_string(dir: &[Vec<u8>]) -> String {
    dir.iter()
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn stamp(ev: &mut BrowserEvent, image: &str, volume: &str, user: Option<&str>, profile: &str) {
    ev.attrs
        .insert("br4n6:image".into(), image.to_string().into());
    ev.attrs
        .insert("br4n6:volume".into(), volume.to_string().into());
    ev.attrs
        .insert("br4n6:profile_path".into(), profile.to_string().into());
    if let Some(u) = user {
        ev.attrs.insert("br4n6:user".into(), u.to_string().into());
    }
    if let Some(app) = attribute_container(profile) {
        ev.attrs
            .insert("br4n6:app".into(), app.name.to_string().into());
    }
}

// ---------------------------------------------------------------------------
// Ingest
// ---------------------------------------------------------------------------

/// Ingest one mounted filesystem: locate every browser profile, read its artifact
/// files through the trait, run the existing parsers, and stamp each recovered
/// [`BrowserEvent`] with `image` / `volume` / `user` provenance. Returns the
/// events plus the number of profiles located (for the caller's loud
/// no-profiles-found check).
fn ingest_fs_counted(
    fs: &dyn FileSystem,
    image: &str,
    volume: &str,
) -> Result<(Vec<BrowserEvent>, usize)> {
    let nodes = walk_fs(fs).map_err(|e| anyhow!("walking filesystem {volume}: {e:?}"))?;
    let index = PathIndex::build(&nodes);
    let profiles = locate_profiles(&nodes, &index);

    let mut events = Vec::new();
    for prof in &profiles {
        let temp = tempfile::tempdir().context("creating temp dir for profile materialization")?;
        let name = prof
            .dir
            .last()
            .and_then(|n| safe_component(n))
            .unwrap_or_else(|| PathBuf::from("profile"));
        let dest = temp.path().join(&name);
        if fs::create_dir_all(&dest).is_err() {
            continue;
        }
        materialize_profile(fs, &nodes, &prof.dir, &dest)?;

        let user = user_of(&prof.dir);
        let profile_path = path_string(&prof.dir);
        // Per-profile degrade: a parse failure on one profile does not sink the
        // volume — its events are simply absent.
        if let Ok(report) = triage_profile(&dest, prof.browser.clone()) {
            for mut ev in report.events {
                stamp(&mut ev, image, volume, user.as_deref(), &profile_path);
                events.push(ev);
            }
        }
    }
    events.sort_by_key(|e| e.timestamp_ns);
    Ok((events, profiles.len()))
}

/// Ingest one already-mounted [`FileSystem`] into provenance-stamped
/// [`BrowserEvent`]s. This is the tested core of the adapter — generic over any
/// `FileSystem` implementation (the fleet's real readers, or a test mock).
///
/// `image` and `volume` are provenance labels stamped onto every event.
pub fn ingest_filesystem(
    fs: &dyn FileSystem,
    image: &str,
    volume: &str,
) -> Result<Vec<BrowserEvent>> {
    ingest_fs_counted(fs, image, volume).map(|(events, _)| events)
}

/// Ingest a disk image into provenance-stamped [`BrowserEvent`]s, given an
/// `open` function that mounts the image's filesystem(s).
///
/// The opener is the single disk seam: it maps an image path (+ optional APFS
/// snapshot xid) to mounted, read-only filesystems. `forensic_vfs_engine::Vfs`
/// provides exactly such an opener (`open` / `open_snapshot`); until it is
/// published, [`ingest_image_path`] supplies a loud-failing one.
///
/// Fails **loud** on every bootstrap problem — the opener erroring, mounting zero
/// filesystems, or finding zero browser profiles — always naming the offending
/// image path, never returning a silent empty result.
pub fn ingest_image<O>(path: &Path, snapshot: Option<u64>, open: O) -> Result<Vec<BrowserEvent>>
where
    O: FnOnce(&Path, Option<u64>) -> Result<Vec<DynFs>>,
{
    let filesystems =
        open(path, snapshot).with_context(|| format!("opening disk image {}", path.display()))?;
    if filesystems.is_empty() {
        return Err(anyhow!(
            "no filesystem detected in disk image {} (snapshot: {snapshot:?}) — cannot ingest",
            path.display()
        ));
    }

    let image = path.display().to_string();
    let mut all = Vec::new();
    let mut profiles_total = 0usize;
    for (i, fs) in filesystems.iter().enumerate() {
        let volume = format!("{:?}#{i}", fs.kind());
        let (events, n) = ingest_fs_counted(fs.as_ref(), &image, &volume)?;
        profiles_total += n;
        all.extend(events);
    }

    if profiles_total == 0 {
        return Err(anyhow!(
            "no browser profiles found across {} filesystem(s) in disk image {} — nothing to ingest",
            filesystems.len(),
            image
        ));
    }

    all.sort_by_key(|e| e.timestamp_ns);
    Ok(all)
}

/// Open a disk image from a path and ingest it, using the built-in opener.
///
/// The built-in opener delegates image opening to the `forensic-vfs` engine
/// (`forensic_vfs_engine::Vfs::open`), which detects and composes the
/// container → partition → filesystem stack. That engine is **not yet published**
/// to crates.io, so this currently returns a loud error naming the path. The
/// ingest pipeline itself ([`ingest_filesystem`]) is complete and available now
/// against any mounted [`FileSystem`].
pub fn ingest_image_path(path: &Path, snapshot: Option<u64>) -> Result<Vec<BrowserEvent>> {
    ingest_image(path, snapshot, engine_open)
}

/// The disk-image opener seam.
///
/// To wire end-to-end once `forensic-vfs-engine` reaches crates.io: add it as a
/// dependency and replace this body with, in effect,
/// `let vfs = forensic_vfs_engine::Vfs::new();`
/// `let ev = match snapshot { Some(x) => vfs.open_snapshot(path, x)?, None => vfs.open(path)? };`
/// `Ok(ev.fs.into_iter().collect())`.
fn engine_open(path: &Path, snapshot: Option<u64>) -> Result<Vec<DynFs>> {
    Err(anyhow!(
        "cannot open disk image {}: opening an image (detecting the \
         container/partition/filesystem stack) requires the forensic-vfs engine \
         (forensic_vfs_engine::Vfs::open), and crate `forensic-vfs-engine` is not yet published \
         to crates.io. The ingest pipeline over a mounted forensic_vfs::FileSystem is available \
         now via browser_forensic_image::ingest_filesystem. (snapshot requested: {snapshot:?})",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_vfs::{
        Allocation, DirEntry, DirStream, ExtentStream, FsKind, FsMeta, MacbTimes, NodeStream,
        ResidencyKind, SectorSizes, TimeZonePolicy, VfsError,
    };

    // ---- Mock FileSystem: an in-memory tree served through the trait ---------

    struct MockNode {
        id: u64,
        parent: Option<u64>,
        name: Vec<u8>,
        kind: NodeKind,
        data: Vec<u8>,
    }

    struct MockFs {
        nodes: Vec<MockNode>,
    }

    impl MockFs {
        fn new() -> Self {
            Self {
                nodes: vec![MockNode {
                    id: 0,
                    parent: None,
                    name: Vec::new(),
                    kind: NodeKind::Dir,
                    data: Vec::new(),
                }],
            }
        }

        fn child(&self, parent: u64, name: &[u8]) -> Option<u64> {
            self.nodes
                .iter()
                .find(|n| n.parent == Some(parent) && n.name == name)
                .map(|n| n.id)
        }

        fn ensure_dir(&mut self, parent: u64, name: &[u8]) -> u64 {
            if let Some(id) = self.child(parent, name) {
                return id;
            }
            let id = self.nodes.len() as u64;
            self.nodes.push(MockNode {
                id,
                parent: Some(parent),
                name: name.to_vec(),
                kind: NodeKind::Dir,
                data: Vec::new(),
            });
            id
        }

        /// Add a file at a `/`-separated path, creating intermediate dirs.
        fn add_file(&mut self, path: &str, data: Vec<u8>) {
            let mut parent = 0u64;
            let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
            let Some((file, dirs)) = comps.split_last() else {
                return;
            };
            for d in dirs {
                parent = self.ensure_dir(parent, d.as_bytes());
            }
            let id = self.nodes.len() as u64;
            self.nodes.push(MockNode {
                id,
                parent: Some(parent),
                name: file.as_bytes().to_vec(),
                kind: NodeKind::File,
                data,
            });
        }

        fn get(&self, id: FileId) -> Option<&MockNode> {
            match id {
                FileId::Opaque(n) => self.nodes.iter().find(|x| x.id == n),
                _ => None,
            }
        }
    }

    fn boot(detail: &str) -> VfsError {
        VfsError::Bootstrap {
            stage: "mockfs",
            detail: detail.to_string(),
        }
    }

    impl FileSystem for MockFs {
        fn kind(&self) -> FsKind {
            FsKind::Other
        }
        fn root(&self) -> FileId {
            FileId::Opaque(0)
        }
        fn sector_sizes(&self) -> SectorSizes {
            SectorSizes {
                logical: 512,
                physical: 512,
                cluster_or_block: 4096,
            }
        }
        fn timestamp_zone(&self) -> TimeZonePolicy {
            TimeZonePolicy::Utc
        }
        fn read_dir(&self, ino: FileId) -> VfsResult<DirStream> {
            let FileId::Opaque(p) = ino else {
                return Err(boot("bad id"));
            };
            let kids: Vec<DirEntry> = self
                .nodes
                .iter()
                .filter(|n| n.parent == Some(p))
                .map(|n| DirEntry {
                    name: n.name.clone(),
                    id: FileId::Opaque(n.id),
                    kind: n.kind,
                })
                .collect();
            Ok(DirStream::new(kids.into_iter().map(Ok)))
        }
        fn extents(&self, _ino: FileId, _stream: StreamId) -> VfsResult<ExtentStream> {
            Ok(ExtentStream::empty())
        }
        fn lookup(&self, parent: FileId, name: &[u8]) -> VfsResult<Option<FileId>> {
            let FileId::Opaque(p) = parent else {
                return Err(boot("bad id"));
            };
            Ok(self.child(p, name).map(FileId::Opaque))
        }
        fn meta(&self, ino: FileId) -> VfsResult<FsMeta> {
            let n = self.get(ino).ok_or_else(|| boot("no node"))?;
            Ok(FsMeta {
                ino: n.id,
                kind: n.kind,
                allocated: Allocation::Allocated,
                size: n.data.len() as u64,
                nlink: 1,
                uid: None,
                gid: None,
                mode: None,
                times: MacbTimes::default(),
                streams: Vec::new(),
                residency: ResidencyKind::NonResident,
                link_target: None,
            })
        }
        fn read_at(
            &self,
            ino: FileId,
            _stream: StreamId,
            off: u64,
            buf: &mut [u8],
        ) -> VfsResult<usize> {
            let n = self.get(ino).ok_or_else(|| boot("no node"))?;
            let off = usize::try_from(off).unwrap_or(usize::MAX);
            if off >= n.data.len() {
                return Ok(0);
            }
            let end = (off + buf.len()).min(n.data.len());
            let src = &n.data[off..end];
            buf[..src.len()].copy_from_slice(src);
            Ok(src.len())
        }
        fn read_link(&self, _ino: FileId, _cap: usize) -> VfsResult<Vec<u8>> {
            Ok(Vec::new())
        }
        fn deleted(&self) -> VfsResult<NodeStream> {
            Ok(NodeStream::empty())
        }
        fn unallocated(&self) -> VfsResult<ExtentStream> {
            Ok(ExtentStream::empty())
        }
    }

    // ---- Fixtures ------------------------------------------------------------

    /// Bytes of a minimal but real Chromium `History` SQLite (urls + visits),
    /// built with rusqlite — the same shape the triage integration test uses.
    fn chrome_history_bytes() -> Vec<u8> {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        {
            let conn = rusqlite::Connection::open(tmp.path()).unwrap();
            conn.execute_batch(
                "CREATE TABLE urls (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
                 CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
                 INSERT INTO urls VALUES (1, 'https://evidence.example.com', 'Evidence Page', 3, 13300000000000000);
                 INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 0);",
            )
            .unwrap();
        }
        std::fs::read(tmp.path()).unwrap()
    }

    fn firefox_places_bytes() -> Vec<u8> {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        {
            let conn = rusqlite::Connection::open(tmp.path()).unwrap();
            conn.execute_batch(
                "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_date INTEGER);
                 CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);
                 INSERT INTO moz_places VALUES (1, 'https://firefox.example.com', 'FF', 1, 1700000000000000);
                 INSERT INTO moz_historyvisits VALUES (1, 0, 1, 1700000000000000, 1);",
            )
            .unwrap();
        }
        std::fs::read(tmp.path()).unwrap()
    }

    // ---- Tests ---------------------------------------------------------------

    #[test]
    fn locate_finds_chrome_profile_across_users() {
        let mut fs = MockFs::new();
        fs.add_file(
            "Users/alice/AppData/Local/Google/Chrome/User Data/Default/History",
            vec![1, 2, 3],
        );
        let nodes = walk_fs(&fs).unwrap();
        let index = PathIndex::build(&nodes);
        let profiles = locate_profiles(&nodes, &index);
        assert_eq!(profiles.len(), 1, "one Chromium profile located");
        assert_eq!(profiles[0].browser, BrowserFamily::Chromium);
        assert_eq!(user_of(&profiles[0].dir).as_deref(), Some("alice"));
    }

    #[test]
    fn locate_finds_firefox_and_safari() {
        let mut fs = MockFs::new();
        fs.add_file(
            "home/bob/.mozilla/firefox/x.default/places.sqlite",
            vec![0u8; 8],
        );
        fs.add_file("Users/carol/Library/Safari/History.db", vec![0u8; 8]);
        let nodes = walk_fs(&fs).unwrap();
        let index = PathIndex::build(&nodes);
        let profiles = locate_profiles(&nodes, &index);
        assert!(profiles
            .iter()
            .any(|p| p.browser == BrowserFamily::Firefox
                && user_of(&p.dir).as_deref() == Some("bob")));
        assert!(profiles
            .iter()
            .any(|p| p.browser == BrowserFamily::Safari
                && user_of(&p.dir).as_deref() == Some("carol")));
    }

    #[test]
    fn locate_empty_tree_finds_nothing() {
        let fs = MockFs::new();
        let nodes = walk_fs(&fs).unwrap();
        let index = PathIndex::build(&nodes);
        assert!(locate_profiles(&nodes, &index).is_empty());
    }

    #[test]
    fn ingest_filesystem_recovers_chrome_history_with_provenance() {
        let mut fs = MockFs::new();
        fs.add_file(
            "Users/alice/AppData/Local/Google/Chrome/User Data/Default/History",
            chrome_history_bytes(),
        );
        let events = ingest_filesystem(&fs, "case.E01", "Ntfs#0").unwrap();
        assert!(!events.is_empty(), "history events recovered end-to-end");
        let hit = events
            .iter()
            .find(|e| {
                e.attrs.get("url").and_then(|v| v.as_str()) == Some("https://evidence.example.com")
            })
            .expect("evidence URL recovered");
        assert_eq!(
            hit.attrs.get("br4n6:image").and_then(|v| v.as_str()),
            Some("case.E01")
        );
        assert_eq!(
            hit.attrs.get("br4n6:volume").and_then(|v| v.as_str()),
            Some("Ntfs#0")
        );
        assert_eq!(
            hit.attrs.get("br4n6:user").and_then(|v| v.as_str()),
            Some("alice")
        );
        assert!(hit.attrs.contains_key("br4n6:profile_path"));
    }

    #[test]
    fn ingest_filesystem_recovers_firefox_history() {
        let mut fs = MockFs::new();
        fs.add_file(
            "home/bob/.mozilla/firefox/x.default/places.sqlite",
            firefox_places_bytes(),
        );
        let events = ingest_filesystem(&fs, "case.raw", "Ext#0").unwrap();
        assert!(!events.is_empty(), "firefox history recovered");
        assert!(events
            .iter()
            .all(|e| e.attrs.get("br4n6:user").and_then(|v| v.as_str()) == Some("bob")));
    }

    #[test]
    fn ingest_image_no_filesystem_is_loud() {
        let err = ingest_image(Path::new("/case.E01"), None, |_p, _s| Ok(Vec::new()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("no filesystem detected"), "got: {err}");
        assert!(err.contains("/case.E01"), "names the image: {err}");
    }

    #[test]
    fn ingest_image_no_profiles_is_loud() {
        let opener = |_p: &Path, _s: Option<u64>| -> Result<Vec<DynFs>> {
            let empty: DynFs = std::sync::Arc::new(MockFs::new());
            Ok(vec![empty])
        };
        let err = ingest_image(Path::new("/blank.raw"), None, opener)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no browser profiles found"), "got: {err}");
        assert!(err.contains("/blank.raw"), "names the image: {err}");
    }

    #[test]
    fn ingest_image_end_to_end_via_opener() {
        let opener = |_p: &Path, _s: Option<u64>| -> Result<Vec<DynFs>> {
            let mut fs = MockFs::new();
            fs.add_file(
                "Users/alice/AppData/Local/Google/Chrome/User Data/Default/History",
                chrome_history_bytes(),
            );
            Ok(vec![std::sync::Arc::new(fs)])
        };
        let events = ingest_image(Path::new("/case.E01"), None, opener).unwrap();
        assert!(events
            .iter()
            .any(|e| e.attrs.get("url").and_then(|v| v.as_str())
                == Some("https://evidence.example.com")));
    }

    #[test]
    fn ingest_image_path_engine_unavailable_fails_loud() {
        let err = format!(
            "{:#}",
            ingest_image_path(Path::new("/evidence/disk.E01"), Some(42)).unwrap_err()
        );
        assert!(
            err.contains("forensic-vfs engine"),
            "explains the engine gap: {err}"
        );
        assert!(err.contains("/evidence/disk.E01"), "names the path: {err}");
        assert!(
            err.contains("not yet published"),
            "states unpublished: {err}"
        );
    }

    #[test]
    fn materialize_rejects_path_traversal_names() {
        assert!(safe_component(b"..").is_none());
        assert!(safe_component(b".").is_none());
        assert!(safe_component(b"a/b").is_none());
        assert!(safe_component(b"a\\b").is_none());
        assert!(safe_component(b"").is_none());
        assert!(safe_component(b"History").is_some());
    }
}
