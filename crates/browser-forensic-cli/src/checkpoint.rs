//! RFC 0001 Phase P3b — resumable investigation checkpoints (concern 3).
//!
//! A multi-TB / many-profile `investigate` run that is killed or crashes should
//! resume from the last **completed** profile unit rather than restarting. This
//! module persists a small checkpoint file — the evidence identity, the tier, and
//! each completed unit's parsed fragment — written **atomically** (temp + rename)
//! after every unit, so an interrupted run leaves a consistent, resumable file.
//!
//! Three safety properties:
//!
//! * **Cheap identity, never a content hash.** [`fingerprint`] stats the path
//!   (size + mtime) — it must never read a multi-TB image to identify it.
//! * **A mismatch refuses to resume.** A checkpoint whose fingerprint or tier does
//!   not match the current run is not silently reused; the run restarts clean.
//! * **Corruption degrades, never crashes.** A truncated / unparseable checkpoint
//!   is reported and the run restarts, rather than panicking.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use browser_forensic_core::BrowserEvent;
use browser_forensic_integrity::IntegrityIndicator;
use serde::{Deserialize, Serialize};

/// On-disk checkpoint schema version. A file with any other version is treated as
/// unreadable (restart clean) rather than mis-parsed.
pub const CHECKPOINT_VERSION: u32 = 1;

/// A cheap identity for the evidence root: canonical path plus size and mtime.
/// Deliberately does **not** hash contents — a multi-TB image must never be read
/// merely to identify it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceFingerprint {
    /// Canonicalized path string (falls back to the given path if canonicalize
    /// fails, e.g. a broken symlink).
    pub root: String,
    /// File length in bytes, when the path is a regular file.
    pub len: Option<u64>,
    /// Modification time in Unix nanoseconds, when available.
    pub mtime_ns: Option<i64>,
}

/// Fingerprint the evidence root cheaply (one `stat`, no content read).
#[must_use]
pub fn fingerprint(path: &Path) -> EvidenceFingerprint {
    let root = std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string();
    let (len, mtime_ns) = match std::fs::metadata(path) {
        Ok(md) => {
            let len = md.is_file().then(|| md.len());
            let mtime_ns = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as i64);
            (len, mtime_ns)
        }
        Err(_) => (None, None),
    };
    EvidenceFingerprint {
        root,
        len,
        mtime_ns,
    }
}

/// One completed profile unit: its assembled events and integrity indicators (the
/// summary-relevant fragment — carving output feeds no summary finding, so it is
/// recomputed for freshly-parsed units rather than persisted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedUnit {
    /// Stable per-profile key (browser + path).
    pub key: String,
    /// The profile's assembled event stream (history, downloads, extensions, …).
    pub events: Vec<BrowserEvent>,
    /// The profile's integrity indicators.
    pub integrity: Vec<IntegrityIndicator>,
}

/// A resumable checkpoint: evidence identity, tier, and the completed units.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Schema version ([`CHECKPOINT_VERSION`]).
    pub version: u32,
    /// The evidence the checkpoint belongs to.
    pub fingerprint: EvidenceFingerprint,
    /// The tier the run was executed at (checkpoints are tier-specific).
    pub tier: String,
    /// When the checkpoint was first created (Unix nanoseconds).
    pub created_ns: i64,
    /// Completed profile units, in completion order.
    pub completed: Vec<CompletedUnit>,
}

impl Checkpoint {
    /// A fresh, empty checkpoint for `fingerprint` at `tier`.
    #[must_use]
    pub fn new(fingerprint: EvidenceFingerprint, tier: &str) -> Self {
        let created_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as i64);
        Self {
            version: CHECKPOINT_VERSION,
            fingerprint,
            tier: tier.to_string(),
            created_ns,
            completed: Vec::new(),
        }
    }

    /// Whether this checkpoint belongs to the same evidence + tier, so resuming
    /// from it is safe.
    #[must_use]
    pub fn matches(&self, fingerprint: &EvidenceFingerprint, tier: &str) -> bool {
        self.version == CHECKPOINT_VERSION && &self.fingerprint == fingerprint && self.tier == tier
    }

    /// Persist the checkpoint atomically (write a sibling temp file, then rename).
    ///
    /// # Errors
    /// Returns an error if the temp file cannot be written or the rename fails.
    pub fn write_atomic(&self, path: &Path) -> io::Result<()> {
        let data = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        // Same-directory temp keeps the rename atomic (a cross-filesystem rename
        // is not). A pid suffix avoids clobbering a concurrent writer's temp.
        let mut tmp = path.as_os_str().to_os_string();
        tmp.push(format!(".tmp.{}", std::process::id()));
        let tmp = PathBuf::from(tmp);
        std::fs::write(&tmp, &data)?;
        std::fs::rename(&tmp, path)
    }
}

/// The result of loading a checkpoint file.
#[derive(Debug)]
pub enum Load {
    /// No checkpoint file exists yet.
    Missing,
    /// A file exists but is unreadable / unparseable / wrong version.
    Corrupt(String),
    /// A valid checkpoint was loaded.
    Ok(Box<Checkpoint>),
}

/// Load a checkpoint file, classifying absence and corruption distinctly so the
/// caller can restart clean on either without crashing.
#[must_use]
pub fn load(path: &Path) -> Load {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Load::Missing,
        Err(e) => return Load::Corrupt(format!("unreadable checkpoint: {e}")),
    };
    match serde_json::from_slice::<Checkpoint>(&bytes) {
        Ok(cp) if cp.version == CHECKPOINT_VERSION => Load::Ok(Box::new(cp)),
        Ok(cp) => Load::Corrupt(format!(
            "unsupported checkpoint version {} (expected {CHECKPOINT_VERSION})",
            cp.version
        )),
        Err(e) => Load::Corrupt(format!("malformed checkpoint: {e}")),
    }
}

/// How a resume attempt resolved (drives the one-line stderr notice).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resumed {
    /// No prior checkpoint — a clean first run.
    Fresh,
    /// Resumed from a matching checkpoint with this many completed units.
    Resumed { completed: usize, created_ns: i64 },
    /// A prior checkpoint existed but could not be used; restarted clean.
    Restarted(String),
}

/// A live checkpoint session driving one investigation run: the file path, the
/// in-memory checkpoint, and a key→position index for O(1) resume lookups.
pub struct CheckpointSession {
    path: PathBuf,
    checkpoint: Checkpoint,
    index: HashMap<String, usize>,
}

impl CheckpointSession {
    /// Open a session over `checkpoint_path` for the given evidence + tier. Unless
    /// `restart` is set, a matching prior checkpoint is loaded and resumed; a
    /// mismatch or corruption restarts clean (never a silent wrong-evidence
    /// resume).
    ///
    /// # Errors
    /// Never fails today, but returns `io::Result` for future-proofing the load.
    pub fn resume_or_new(
        checkpoint_path: &Path,
        fingerprint: EvidenceFingerprint,
        tier: &str,
        restart: bool,
    ) -> io::Result<(Self, Resumed)> {
        let fresh = |resumed: Resumed| {
            (
                Self {
                    path: checkpoint_path.to_path_buf(),
                    checkpoint: Checkpoint::new(fingerprint.clone(), tier),
                    index: HashMap::new(),
                },
                resumed,
            )
        };

        if restart {
            return Ok(fresh(Resumed::Fresh));
        }

        match load(checkpoint_path) {
            Load::Missing => Ok(fresh(Resumed::Fresh)),
            Load::Corrupt(reason) => Ok(fresh(Resumed::Restarted(format!(
                "corrupt checkpoint: {reason}"
            )))),
            Load::Ok(cp) => {
                if cp.matches(&fingerprint, tier) {
                    let completed = cp.completed.len();
                    let created_ns = cp.created_ns;
                    let index = cp
                        .completed
                        .iter()
                        .enumerate()
                        .map(|(i, u)| (u.key.clone(), i))
                        .collect();
                    Ok((
                        Self {
                            path: checkpoint_path.to_path_buf(),
                            checkpoint: *cp,
                            index,
                        },
                        Resumed::Resumed {
                            completed,
                            created_ns,
                        },
                    ))
                } else {
                    Ok(fresh(Resumed::Restarted(
                        "checkpoint is for different evidence or a different tier".to_string(),
                    )))
                }
            }
        }
    }

    /// The already-completed unit for `key`, if this run resumed one.
    #[must_use]
    pub fn completed_unit(&self, key: &str) -> Option<&CompletedUnit> {
        self.index.get(key).map(|&i| &self.checkpoint.completed[i])
    }

    /// Record a freshly-completed unit and persist the checkpoint atomically.
    /// Idempotent for a key already present (the run reuses it rather than
    /// double-counting).
    ///
    /// # Errors
    /// Returns an error if the atomic write fails.
    pub fn record(
        &mut self,
        key: &str,
        events: Vec<BrowserEvent>,
        integrity: Vec<IntegrityIndicator>,
    ) -> io::Result<()> {
        if self.index.contains_key(key) {
            return Ok(());
        }
        self.index
            .insert(key.to_string(), self.checkpoint.completed.len());
        self.checkpoint.completed.push(CompletedUnit {
            key: key.to_string(),
            events,
            integrity,
        });
        self.checkpoint.write_atomic(&self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_checkpoint(fp: EvidenceFingerprint) -> Checkpoint {
        let mut cp = Checkpoint::new(fp, "standard");
        cp.completed.push(CompletedUnit {
            key: "Chromium|/ev/Default".to_string(),
            events: Vec::new(),
            integrity: Vec::new(),
        });
        cp
    }

    #[test]
    fn fingerprint_is_content_free_but_identifies_the_path() {
        let dir = TempDir::new().unwrap();
        let fp = fingerprint(dir.path());
        assert!(
            !fp.root.is_empty(),
            "the fingerprint records which path it identifies"
        );
    }

    #[test]
    fn checkpoint_roundtrips_atomically() {
        let dir = TempDir::new().unwrap();
        let cp_path = dir.path().join(".br4n6-checkpoint.json");
        let cp = sample_checkpoint(fingerprint(dir.path()));
        cp.write_atomic(&cp_path).unwrap();
        match load(&cp_path) {
            Load::Ok(loaded) => {
                assert_eq!(loaded.completed.len(), 1, "the completed unit survives");
                assert_eq!(loaded.tier, "standard");
            }
            other => panic!("expected a loaded checkpoint, got {other:?}"),
        }
    }

    #[test]
    fn corrupt_checkpoint_is_reported_not_crashed() {
        let dir = TempDir::new().unwrap();
        let cp_path = dir.path().join(".br4n6-checkpoint.json");
        std::fs::write(&cp_path, b"{ this is not valid json").unwrap();
        assert!(
            matches!(load(&cp_path), Load::Corrupt(_)),
            "a corrupt file is classified corrupt, never a panic or a false Ok"
        );
    }

    #[test]
    fn missing_checkpoint_is_missing() {
        let dir = TempDir::new().unwrap();
        assert!(matches!(load(&dir.path().join("nope.json")), Load::Missing));
    }

    #[test]
    fn matches_rejects_different_evidence() {
        let cp = sample_checkpoint(EvidenceFingerprint {
            root: "/ev/one".to_string(),
            len: Some(10),
            mtime_ns: Some(1),
        });
        let other = EvidenceFingerprint {
            root: "/ev/two".to_string(),
            len: Some(20),
            mtime_ns: Some(2),
        };
        assert!(
            cp.matches(&cp.fingerprint, "standard"),
            "same evidence + tier matches"
        );
        assert!(
            !cp.matches(&other, "standard"),
            "different evidence must NOT match (no silent wrong-evidence resume)"
        );
        assert!(
            !cp.matches(&cp.fingerprint, "deep"),
            "a different tier must NOT match"
        );
    }
}
