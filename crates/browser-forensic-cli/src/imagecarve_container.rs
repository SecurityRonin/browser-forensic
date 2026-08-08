//! Opening an evidence container and carving it whole-image.
//!
//! This lives in the CLI, not in `browser-forensic-imagecarve`, because opening a
//! container is WIRING. ADR-0016 puts PARSER-layer crates on FOUNDATION only,
//! taking `Path`/`&[u8]`, and names ORCHESTRATION as the layer that wires a
//! decoder to a byte source; `disk-forensic` sits in that orchestration layer, so
//! a parser depending on it inverts the hierarchy.
//!
//! Nothing about the capability changes: `disk_forensic::container::open` still
//! sniffs the wrapper and yields a decoded, decompressed view for raw/dd, E01/EWF,
//! VMDK, VHDX, VHD, QCOW2, DMG and ISO9660 through one code path, so a compressed
//! E01 still carves its real contents. Only the layer performing the open moved.

use std::io::SeekFrom;
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Mutex;
use std::thread::JoinHandle;

use browser_forensic_imagecarve::CarvedArtifact;
use disk_forensic::container::{self, ReadSeek};
use forensic_vfs::{ImageSource, VfsResult};

/// Open `path` through the **container abstraction** and carve it (see
/// [`browser_forensic_imagecarve::carve_image`]). `disk_forensic::container::open`
/// sniffs the wrapper and
/// returns a **decoded, decompressed** `Read + Seek` view of the disk, so the
/// same carve engine runs over E01/EWF, VMDK, VHDX, VHD, QCOW2, DMG, ISO9660,
/// and raw/`dd` images through one code path with no per-format branch — a
/// compressed E01 now yields its real contents rather than compressed bytes.
///
/// # Errors
/// [`ImageCarveError::Open`] if the container cannot be sniffed/decoded (a
/// bootstrap failure — surfaced loudly, never absorbed into an empty carve).
pub fn carve_image_path(path: &Path) -> Result<Vec<CarvedArtifact>, ImageCarveError> {
    let source = ContainerSource::open(path)?;
    Ok(browser_forensic_imagecarve::carve_image(&source, path))
}

/// A whole-image carve could not open the evidence container. This is a
/// **bootstrap** failure — the prerequisite every carve step depends on — so it
/// is always loud and never degraded to an empty result.
#[derive(Debug, thiserror::Error)]
pub enum ImageCarveError {
    /// `disk_forensic::container::open` could not sniff/decode the image, or the
    /// reader thread failed to start. Carries the offending path and the
    /// underlying reason verbatim so an examiner can identify the failure.
    #[error("cannot open image {path} as a forensic container: {reason}")]
    Open {
        /// The image path that failed to open.
        path: String,
        /// The verbatim underlying failure (I/O, decode, or thread-start error).
        reason: String,
    },
}

/// One positioned-read request to the container-reader worker: fill up to `len`
/// bytes starting at absolute `offset`.
struct ReadReq {
    offset: u64,
    len: usize,
}

/// The worker's answer: the bytes read (a short/empty vec at EOF), or the I/O
/// error text if the decoded stream failed mid-read.
type ReadResp = Result<Vec<u8>, String>;

/// The request/response endpoints held behind the source's `&self` lock.
struct ReaderChannel {
    req: Sender<ReadReq>,
    resp: Receiver<ReadResp>,
}

/// A [`forensic_vfs::ImageSource`] over a `disk_forensic::container::OpenedImage`.
///
/// `container::open` hands back a `Box<dyn ReadSeek>` that is neither `Send` nor
/// `Sync` (the published `ReadSeek` trait carries no auto-trait bounds), so it
/// can neither back a `Send + Sync` `ImageSource` directly nor be moved into
/// another thread. A dedicated worker thread therefore OPENS the container
/// itself — only the `PathBuf`, which is `Send`, crosses the boundary — and owns
/// the decoded reader for its whole life, answering positioned-read requests over
/// channels. The handle every carve worker holds is a `Send + Sync` pair of
/// channel endpoints plus the known size: no `unsafe`, bounded memory (one
/// window-sized buffer per read), and the fully decoded/decompressed image behind
/// it. The one-line alternative — a `+ Send` bound on the published `ReadSeek` —
/// would let the reader be held directly; that is a follow-up for disk-forensic.
struct ContainerSource {
    len: u64,
    io: Mutex<Option<ReaderChannel>>,
    worker: Option<JoinHandle<()>>,
}

impl ContainerSource {
    /// Open `path` through `disk_forensic::container::open` and expose the decoded
    /// disk as an [`ImageSource`]. Loud on any open/decode failure.
    fn open(path: &Path) -> Result<Self, ImageCarveError> {
        let path_buf = path.to_path_buf();
        let disp = path.display().to_string();

        let (req_tx, req_rx) = mpsc::channel::<ReadReq>();
        let (resp_tx, resp_rx) = mpsc::channel::<ReadResp>();
        let (init_tx, init_rx) = mpsc::channel::<Result<u64, String>>();

        let worker = std::thread::Builder::new()
            .name("br4n6-container-reader".to_string())
            .spawn(move || reader_thread(&path_buf, &req_rx, &resp_tx, &init_tx))
            .map_err(|e| ImageCarveError::Open {
                path: disp.clone(),
                reason: format!("cannot start reader thread: {e}"),
            })?;

        match init_rx.recv() {
            Ok(Ok(len)) => Ok(Self {
                len,
                io: Mutex::new(Some(ReaderChannel {
                    req: req_tx,
                    resp: resp_rx,
                })),
                worker: Some(worker),
            }),
            Ok(Err(reason)) => {
                let _ = worker.join();
                Err(ImageCarveError::Open { path: disp, reason })
            }
            Err(e) => {
                let _ = worker.join();
                Err(ImageCarveError::Open {
                    path: disp,
                    reason: format!("reader thread exited before opening: {e}"),
                })
            }
        }
    }
}

impl ImageSource for ContainerSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        if buf.is_empty() || offset >= self.len {
            return Ok(0);
        }
        let want = usize::try_from((self.len - offset).min(buf.len() as u64)).unwrap_or(buf.len());
        // The loud failure already happened at open(); post-open the worker owns a
        // decoded file/memory-backed stream. read_at is a short-read contract
        // (0 at/after EOF, never a panic), and VfsError is a sealed non_exhaustive
        // type this crate cannot construct — so a dead-worker / mid-read failure
        // degrades to the available prefix (here 0) rather than fabricating an
        // error. The carve simply stops scanning that window; it never panics.
        let Ok(guard) = self.io.lock() else {
            return Ok(0);
        };
        let Some(chan) = guard.as_ref() else {
            return Ok(0);
        };
        if chan.req.send(ReadReq { offset, len: want }).is_err() {
            return Ok(0);
        }
        let data = match chan.resp.recv() {
            Ok(Ok(d)) => d,
            _ => return Ok(0),
        };
        let n = data.len().min(buf.len());
        if let (Some(dst), Some(src)) = (buf.get_mut(..n), data.get(..n)) {
            dst.copy_from_slice(src);
        }
        Ok(n)
    }
}

impl Drop for ContainerSource {
    fn drop(&mut self) {
        // Close the request channel FIRST (drop the Sender) so the worker's recv()
        // returns Err and it exits, THEN join — order matters to avoid a
        // join-before-close hang.
        if let Ok(slot) = self.io.get_mut() {
            slot.take();
        }
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

/// The worker body: open the container (owning the `!Send` decoded reader here,
/// never across a thread boundary), report the decoded size (or the open error)
/// once, then serve positioned reads until the source is dropped.
fn reader_thread(
    path: &Path,
    req: &Receiver<ReadReq>,
    resp: &Sender<ReadResp>,
    init: &Sender<Result<u64, String>>,
) {
    let opened = match container::open(path) {
        Ok(o) => o,
        Err(e) => {
            let _ = init.send(Err(e.to_string()));
            return;
        }
    };
    let size = opened.size;
    let mut reader = opened.reader;
    if init.send(Ok(size)).is_err() {
        return; // the constructor gave up before we finished opening
    }
    while let Ok(ReadReq { offset, len }) = req.recv() {
        let answer = read_positioned(reader.as_mut(), offset, len);
        if resp.send(answer).is_err() {
            break; // the source was dropped
        }
    }
}

/// Seek `reader` to `offset` and read up to `len` bytes, returning the bytes
/// actually read (a short/empty vec at EOF). Bounded by `len`; never panics.
fn read_positioned(reader: &mut dyn ReadSeek, offset: u64, len: usize) -> ReadResp {
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|e| format!("seek to {offset}: {e}"))?;
    let mut buf = vec![0u8; len];
    let mut done = 0usize;
    while done < len {
        let Some(dst) = buf.get_mut(done..) else {
            break; // cov:unreachable: done < len == buf.len()
        };
        match reader.read(dst) {
            Ok(0) => break,
            Ok(k) => done = done.saturating_add(k),
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("read at {offset}: {e}")),
        }
    }
    buf.truncate(done);
    Ok(buf)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    // Fixture builders mirrored from browser-forensic-imagecarve's tests. They
    // construct evidence, not behaviour, so a drift between the two copies
    // cannot make either test pass for the wrong reason.
    /// Build a Chromium-History-shaped SQLite DB carrying `url` in a `urls` row,
    /// returning the raw file bytes.
    fn build_history_db(url: &str, last_visit_time: i64) -> Vec<u8> {
        let f = NamedTempFile::new().unwrap();
        {
            let conn = Connection::open(f.path()).unwrap();
            conn.execute_batch(
                "PRAGMA auto_vacuum = NONE;
                 CREATE TABLE urls(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR,
                                   visit_count INTEGER, typed_count INTEGER,
                                   last_visit_time INTEGER, hidden INTEGER);",
            )
            .unwrap();
            // A few filler rows plus the known URL, so the row lands on a leaf page.
            for i in 0..8 {
                conn.execute(
                    "INSERT INTO urls VALUES (?1,?2,?3,?4,?5,?6,0)",
                    rusqlite::params![
                        i,
                        format!("https://filler{i}.example/path/to/page"),
                        format!("Filler {i}"),
                        i,
                        i,
                        last_visit_time + i64::from(i)
                    ],
                )
                .unwrap();
            }
            conn.execute(
                "INSERT INTO urls VALUES (100,?1,?2,5,2,?3,0)",
                rusqlite::params![url, "Planted Secret", last_visit_time],
            )
            .unwrap();
        }
        std::fs::read(f.path()).unwrap()
    }

    /// Embed `payload` at `offset` inside a `total`-byte buffer of junk.
    fn plant(payload: &[u8], offset: usize, total: usize) -> Vec<u8> {
        let mut buf = vec![0u8; total];
        // fill with non-signature junk so nothing false-carves
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        buf[offset..offset + payload.len()].copy_from_slice(payload);
        buf
    }

    use std::io::Write as _;

    /// Write `bytes` to a fresh temp file (kept alive by the returned handle).
    fn temp_file_with(bytes: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn container_source_read_at_returns_correct_bytes_and_short_eof_read() {
        // A raw byte pattern → `container::open` sniffs it as Raw → the adapter
        // serves positioned reads over the decoded (here pass-through) stream.
        let data: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let f = temp_file_with(&data);
        let src = ContainerSource::open(f.path()).expect("open raw file as container");
        assert_eq!(src.len(), data.len() as u64);

        // Exact bytes at offset 0.
        let mut buf = [0u8; 16];
        assert_eq!(src.read_at(0, &mut buf).unwrap(), 16);
        assert_eq!(&buf[..], &data[..16]);

        // Exact bytes at an arbitrary interior offset.
        let mut buf = [0u8; 32];
        assert_eq!(src.read_at(1000, &mut buf).unwrap(), 32);
        assert_eq!(&buf[..], &data[1000..1032]);

        // Oversized read straddling EOF → short count (available prefix only).
        let mut buf = [0u8; 64];
        let n = src.read_at(data.len() as u64 - 10, &mut buf).unwrap();
        assert_eq!(n, 10);
        assert_eq!(&buf[..10], &data[data.len() - 10..]);

        // At and past EOF → 0, never a panic.
        let mut buf = [0u8; 8];
        assert_eq!(src.read_at(data.len() as u64, &mut buf).unwrap(), 0);
        assert_eq!(src.read_at(data.len() as u64 + 100, &mut buf).unwrap(), 0);
    }

    #[test]
    fn container_open_path_carves_planted_sqlite_url() {
        // Proves the new open strategy: `carve_image_path` opens through
        // `container::open` (not a raw FileSource) and still recovers the plant.
        let url = "https://planted.example/via-container-open";
        let db = build_history_db(url, 13_300_000_000_000_000);
        let db_off = 2048usize;
        let img = plant(&db, db_off, db_off + db.len() + 4096);
        let f = temp_file_with(&img);

        let arts = carve_image_path(f.path()).expect("carve raw image via container::open");
        assert!(
            arts.iter().any(|a| a.url == url),
            "planted URL not recovered through the container-abstraction open path: {arts:?}"
        );
    }

    #[test]
    fn carve_image_path_errors_loudly_when_image_cannot_be_opened() {
        // A non-existent path is a bootstrap failure — surfaced loudly, never
        // absorbed into an empty carve.
        let missing = Path::new("/nonexistent/br4n6/does-not-exist.img");
        assert!(carve_image_path(missing).is_err());
    }

    #[test]
    fn truncated_ewf_container_errors_loudly_and_never_panics() {
        // EnCase EWF v1 signature ("EVF\x09\x0d\x0a\xff\x00", libewf/EWF spec)
        // followed by garbage: sniffs as EWF, but the decoder must reject the
        // truncated body loudly — never a silent Raw downgrade or a panic.
        let mut bytes = vec![0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
        bytes.extend_from_slice(&[0xffu8; 1024]);
        let f = temp_file_with(&bytes);
        assert!(carve_image_path(f.path()).is_err());
    }

    /// Env-gated real-E01 validation (tier-2): set `BR4N6_E01` to a small E01 to
    /// prove it opens **decompressed** via `container::open` and carves. Provide
    /// `BR4N6_E01_URL` to assert a specific planted URL is recovered. Skips clean
    /// when unset (like an absent oracle binary).
    #[test]
    fn env_gated_e01_carves_decompressed_via_container_open() {
        let Ok(path) = std::env::var("BR4N6_E01") else {
            eprintln!("skip env_gated_e01: set BR4N6_E01 to a small E01 to run");
            return;
        };
        let arts =
            carve_image_path(Path::new(&path)).expect("open + carve E01 via container::open");
        if let Ok(url) = std::env::var("BR4N6_E01_URL") {
            assert!(
                arts.iter().any(|a| a.url == url),
                "planted URL {url} not recovered from E01: {arts:?}"
            );
        } else {
            assert!(!arts.is_empty(), "no artifacts carved from E01 {path}");
        }
    }
}
