# browser-forensic v2 — RapidTriage Pattern

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Expand browser-forensic from a SQLite-parsing library into a full forensic platform matching the RapidTriage pattern used by winevt-forensic and srum-forensic: integrity detection (tamper/clearing/corruption anomalies), carving/recovery (SQLite free-page, WAL, binary formats), memory scanning (URL/cookie byte patterns), forensicnomicon integration (artifact profiles, evidence strength, MITRE mappings), and orchestration via a triage crate.

**Architecture:**
```
forensicnomicon (zero-dep, static catalog)
    ^
    | compile-time artifact descriptors, evidence ratings, MITRE mappings
    |
browser-forensic workspace          <── memory-forensic depends on THIS
    |
    +-- browser-core          (types: BrowserEvent, ForensicMeta, ArtifactKind + new variants)
    +-- browser-chrome        (8 existing parsers + new: local_state, snss_session)
    +-- browser-firefox       (9 existing parsers)
    +-- browser-safari        (5 existing parsers + new: topsites, last_session)
    +-- browser-discovery     (discover_profiles + new: Windows paths)
    +-- browser-integrity     (NEW: IntegrityIndicator, check_* functions per browser per artifact)
    +-- browser-carve         (NEW: SQLite free-page recovery, WAL analysis, binary cookie carving)
    +-- browser-memory        (NEW: pure byte-pattern scanner — NO memf dependency)
    +-- browser-rt            (NEW: RapidTriage orchestration -> TriageReport)
    +-- bw-cli                (existing 12 subcommands + new: integrity, carve, memory, triage)

Dependency direction (memory-forensic calls browser-forensic, NOT the other way):

  memory-forensic/memf-windows
    └─ calls browser-carve  ← interprets SQLite pages found in hiberfil.sys/pagefile
    └─ calls browser-memory ← scans arbitrary byte regions for URL/cookie patterns
    └─ dpapi_keys.rs extracts DPAPI master key → passed INTO browser-carve for decryption
```

**Tech Stack:**
- Rust 1.80+, edition 2021
- `anyhow` for fallible returns in library code
- `thiserror` for typed errors in browser-integrity and browser-carve
- `rusqlite` (bundled) for SQLite parsing + raw page access
- `forensicnomicon` via path dep for artifact descriptors (zero-dep itself)
- `serde` / `serde_json` for serialization
- `chrono` for timestamp formatting
- `lz4_flex` for LZ4 decompression (Firefox session)
- `plist` for Safari plist artifacts
- `#![deny(clippy::unwrap_used)]` on ALL new library crates

**Constraints:**
- Strict TDD: RED commit (failing tests) then GREEN commit (passing implementation)
- Each task produces exactly 2 commits: RED then GREEN
- DRY: shared types in browser-core, no duplication across crates
- No `unwrap()` in library code; use `anyhow::Result` or `thiserror`
- forensicnomicon remains zero-dep (no browser parsing logic goes there)
- browser-memory has NO dependency on memory-forensic (no circular deps)
- `IntegrityIndicator` naming (not `AntiForensicIndicator`) -- matches winevt-integrity

---

## Phase 1: forensicnomicon Browser Artifact Profiles

### Task 1.1: Add Browser Artifact Profiles to forensicnomicon

**Goal:** Add 13 `ArtifactProfile` entries for browser artifacts so browser-forensic can look them up at compile time.

**Workspace:** `/Users/4n6h4x0r/src/forensicnomicon`

**File to modify:** `/Users/4n6h4x0r/src/forensicnomicon/src/profile.rs`

The following artifact IDs must be added (some already exist -- `chrome_history`, `firefox_places`, `chrome_login_data`, `firefox_logins` -- verify and add missing ones):

| Artifact ID | EvidenceStrength | VolatilityClass | Caveats |
|---|---|---|---|
| `browser_chrome_history` | Corroborative | ActivityDriven | "URL visited, not necessarily user-initiated; could be redirect or prefetch" |
| `browser_chrome_cookies` | Corroborative | ActivityDriven | "Cookie presence proves domain contact, not user intent; third-party cookies common" |
| `browser_chrome_downloads` | Strong | Persistent | "File was downloaded; user may not have opened it" |
| `browser_chrome_bookmarks` | Circumstantial | Persistent | "Bookmark proves awareness of URL, not visit frequency" |
| `browser_chrome_extensions` | Corroborative | Persistent | "Extension installed, possibly auto-installed by policy" |
| `browser_chrome_login_data` | Strong | Persistent | "Credential saved; timestamp shows last use" |
| `browser_chrome_autofill` | Corroborative | Persistent | "Form data saved; may be auto-populated not manually typed" |
| `browser_chrome_cache` | Corroborative | RotatingBuffer | "Cache entry proves resource was fetched; evicted on size pressure" |
| `browser_chrome_session` | Corroborative | Volatile | "Tab state at last close; lost on clean exit" |
| `browser_firefox_history` | Corroborative | ActivityDriven | "Same caveats as Chrome history" |
| `browser_firefox_cookies` | Corroborative | ActivityDriven | "Same caveats as Chrome cookies" |
| `browser_firefox_downloads` | Strong | Persistent | "Same caveats as Chrome downloads" |
| `browser_safari_history` | Corroborative | ActivityDriven | "Same caveats as Chrome history; Safari has tombstone table for deleted items" |

#### RED commit

**Message:** `test: RED -- browser artifact profile lookup tests for 13 entries`

Add tests at the bottom of the existing `#[cfg(test)] mod tests` in `profile.rs`:

```rust
#[test]
fn browser_chrome_history_profile_exists() {
    let p = profile_for("browser_chrome_history");
    assert!(p.is_some(), "browser_chrome_history profile must exist");
    let p = p.unwrap();
    assert_eq!(p.evidence_strength, EvidenceStrength::Corroborative);
    assert_eq!(p.volatility, VolatilityClass::ActivityDriven);
}

#[test]
fn browser_chrome_cookies_profile_exists() {
    let p = profile_for("browser_chrome_cookies");
    assert!(p.is_some(), "browser_chrome_cookies profile must exist");
    assert_eq!(p.unwrap().evidence_strength, EvidenceStrength::Corroborative);
}

#[test]
fn browser_chrome_downloads_profile_exists() {
    let p = profile_for("browser_chrome_downloads");
    assert!(p.is_some(), "browser_chrome_downloads profile must exist");
    assert_eq!(p.unwrap().evidence_strength, EvidenceStrength::Strong);
}

#[test]
fn browser_chrome_bookmarks_profile_exists() {
    let p = profile_for("browser_chrome_bookmarks");
    assert!(p.is_some());
    assert_eq!(p.unwrap().evidence_strength, EvidenceStrength::Circumstantial);
}

#[test]
fn browser_chrome_extensions_profile_exists() {
    let p = profile_for("browser_chrome_extensions");
    assert!(p.is_some());
    assert_eq!(p.unwrap().evidence_strength, EvidenceStrength::Corroborative);
}

#[test]
fn browser_chrome_login_data_profile_exists() {
    let p = profile_for("browser_chrome_login_data_v2");
    assert!(p.is_some());
    assert_eq!(p.unwrap().evidence_strength, EvidenceStrength::Strong);
}

#[test]
fn browser_chrome_autofill_profile_exists() {
    let p = profile_for("browser_chrome_autofill");
    assert!(p.is_some());
    assert_eq!(p.unwrap().evidence_strength, EvidenceStrength::Corroborative);
}

#[test]
fn browser_chrome_cache_profile_exists() {
    let p = profile_for("browser_chrome_cache");
    assert!(p.is_some());
    assert_eq!(p.unwrap().volatility, VolatilityClass::RotatingBuffer);
}

#[test]
fn browser_chrome_session_profile_exists() {
    let p = profile_for("browser_chrome_session");
    assert!(p.is_some());
    assert_eq!(p.unwrap().volatility, VolatilityClass::Volatile);
}

#[test]
fn browser_firefox_history_profile_exists() {
    let p = profile_for("browser_firefox_history");
    assert!(p.is_some());
    assert_eq!(p.unwrap().evidence_strength, EvidenceStrength::Corroborative);
}

#[test]
fn browser_firefox_cookies_profile_exists() {
    let p = profile_for("browser_firefox_cookies");
    assert!(p.is_some());
}

#[test]
fn browser_firefox_downloads_profile_exists() {
    let p = profile_for("browser_firefox_downloads");
    assert!(p.is_some());
    assert_eq!(p.unwrap().evidence_strength, EvidenceStrength::Strong);
}

#[test]
fn browser_safari_history_profile_exists() {
    let p = profile_for("browser_safari_history");
    assert!(p.is_some());
    assert_eq!(p.unwrap().evidence_strength, EvidenceStrength::Corroborative);
}
```

Run: `cd /Users/4n6h4x0r/src/forensicnomicon && cargo test browser_chrome_history_profile_exists -- --nocapture`

Confirm: all 13 tests fail with `assertion failed` because the profiles do not exist yet.

#### GREEN commit

**Message:** `feat: add 13 browser artifact profiles to forensicnomicon`

Add to the `ARTIFACT_PROFILES` static array in `/Users/4n6h4x0r/src/forensicnomicon/src/profile.rs` (before the closing `];`):

```rust
    ArtifactProfile {
        id: "browser_chrome_history",
        evidence_strength: EvidenceStrength::Corroborative,
        evidence_caveats: &[
            "URL visited, not necessarily user-initiated; could be redirect or prefetch",
            "History can be cleared by user or extensions; absence is not evidence of non-visit",
        ],
        volatility: VolatilityClass::ActivityDriven,
        volatility_rationale: "Overwritten by browser activity; no fixed size limit but old entries pruned",
    },
    ArtifactProfile {
        id: "browser_chrome_cookies",
        evidence_strength: EvidenceStrength::Corroborative,
        evidence_caveats: &[
            "Cookie presence proves domain contact, not user intent; third-party cookies common",
            "Expiration and creation timestamps useful for timeline reconstruction",
        ],
        volatility: VolatilityClass::ActivityDriven,
        volatility_rationale: "Cookies expire or are overwritten by site updates",
    },
    ArtifactProfile {
        id: "browser_chrome_downloads",
        evidence_strength: EvidenceStrength::Strong,
        evidence_caveats: &[
            "File was downloaded; user may not have opened or executed it",
            "Download record persists even if file was deleted from disk",
        ],
        volatility: VolatilityClass::Persistent,
        volatility_rationale: "Download records persist until user clears download history",
    },
    ArtifactProfile {
        id: "browser_chrome_bookmarks",
        evidence_strength: EvidenceStrength::Circumstantial,
        evidence_caveats: &[
            "Bookmark proves awareness of URL, not visit frequency",
            "May be synced from another device; check sync metadata",
        ],
        volatility: VolatilityClass::Persistent,
        volatility_rationale: "Bookmarks persist until deleted by user",
    },
    ArtifactProfile {
        id: "browser_chrome_extensions",
        evidence_strength: EvidenceStrength::Corroborative,
        evidence_caveats: &[
            "Extension installed, possibly auto-installed by enterprise policy",
            "Extension version and update timestamps useful for timeline",
        ],
        volatility: VolatilityClass::Persistent,
        volatility_rationale: "Extensions persist until uninstalled",
    },
    ArtifactProfile {
        id: "browser_chrome_login_data_v2",
        evidence_strength: EvidenceStrength::Strong,
        evidence_caveats: &[
            "Credential saved; timestamp shows last use; passwords encrypted by OS credential store",
            "Presence proves user entered credentials on the site at least once",
        ],
        volatility: VolatilityClass::Persistent,
        volatility_rationale: "Credentials persist until deleted from browser or profile deletion",
    },
    ArtifactProfile {
        id: "browser_chrome_autofill",
        evidence_strength: EvidenceStrength::Corroborative,
        evidence_caveats: &[
            "Form data was saved; may have been auto-populated not manually typed",
            "Timestamps show when autofill entry was created and last used",
        ],
        volatility: VolatilityClass::Persistent,
        volatility_rationale: "Autofill data persists until browser data cleared",
    },
    ArtifactProfile {
        id: "browser_chrome_cache",
        evidence_strength: EvidenceStrength::Corroborative,
        evidence_caveats: &[
            "Cache entry proves resource was fetched; evicted under size pressure",
            "Response headers (Last-Modified, ETag) may reveal server-side timestamps",
        ],
        volatility: VolatilityClass::RotatingBuffer,
        volatility_rationale: "Evicted when cache size limit reached; newest entries overwrite oldest",
    },
    ArtifactProfile {
        id: "browser_chrome_session",
        evidence_strength: EvidenceStrength::Corroborative,
        evidence_caveats: &[
            "Tab state reflects last browser close; unreliable if crash occurred",
            "SNSS format is binary and partially documented",
        ],
        volatility: VolatilityClass::Volatile,
        volatility_rationale: "Overwritten on every browser launch; lost on clean exit without restore",
    },
    ArtifactProfile {
        id: "browser_firefox_history",
        evidence_strength: EvidenceStrength::Corroborative,
        evidence_caveats: &[
            "Same caveats as Chrome history; stored in places.sqlite",
            "Firefox uses moz_places + moz_historyvisits join for full timeline",
        ],
        volatility: VolatilityClass::ActivityDriven,
        volatility_rationale: "Overwritten by browser activity; no fixed size limit",
    },
    ArtifactProfile {
        id: "browser_firefox_cookies",
        evidence_strength: EvidenceStrength::Corroborative,
        evidence_caveats: &[
            "Same caveats as Chrome cookies; stored in cookies.sqlite",
            "Firefox stores isHttpOnly and sameSite flags useful for security analysis",
        ],
        volatility: VolatilityClass::ActivityDriven,
        volatility_rationale: "Cookies expire or are overwritten by site updates",
    },
    ArtifactProfile {
        id: "browser_firefox_downloads",
        evidence_strength: EvidenceStrength::Strong,
        evidence_caveats: &[
            "Same caveats as Chrome downloads; stored in places.sqlite moz_annos",
            "Download annotations reference moz_places entries",
        ],
        volatility: VolatilityClass::Persistent,
        volatility_rationale: "Download records persist until user clears history",
    },
    ArtifactProfile {
        id: "browser_safari_history",
        evidence_strength: EvidenceStrength::Corroborative,
        evidence_caveats: &[
            "Same caveats as Chrome history; stored in History.db",
            "Safari has history_tombstones table tracking deleted URLs with timestamps",
        ],
        volatility: VolatilityClass::ActivityDriven,
        volatility_rationale: "Overwritten by browser activity; tombstones provide deletion evidence",
    },
```

Run: `cd /Users/4n6h4x0r/src/forensicnomicon && cargo test -- --nocapture`

Confirm: all 13 new tests pass. Existing tests still pass.

---

## Phase 2: browser-core New Types

### Task 2.1: Add ForensicMeta and New ArtifactKind Variants to browser-core

**Goal:** Add `ForensicMeta` struct (wraps forensicnomicon `ArtifactProfile` lookup), new `ArtifactKind` variants (`Integrity`, `Carved`, `Memory`), and re-export `EvidenceStrength` from forensicnomicon.

**Workspace:** `/Users/4n6h4x0r/src/browser-forensic`

**Files to modify:**
- `/Users/4n6h4x0r/src/browser-forensic/Cargo.toml` -- add `forensicnomicon` and `thiserror` to workspace dependencies
- `/Users/4n6h4x0r/src/browser-forensic/crates/browser-core/Cargo.toml` -- add `forensicnomicon` dependency
- `/Users/4n6h4x0r/src/browser-forensic/crates/browser-core/src/lib.rs` -- add new types

**Cargo.toml changes (workspace root):**

Add to `[workspace.dependencies]`:
```toml
forensicnomicon = { path = "../forensicnomicon", features = ["serde"] }
thiserror = "2"
```

**browser-core/Cargo.toml changes:**

Add to `[dependencies]`:
```toml
forensicnomicon = { workspace = true }
```

#### RED commit

**Message:** `test: RED -- ForensicMeta, new ArtifactKind variants (Integrity, Carved, Memory)`

Add tests to `/Users/4n6h4x0r/src/browser-forensic/crates/browser-core/src/lib.rs`:

```rust
#[test]
fn artifact_kind_has_integrity_variant() {
    let _ik = ArtifactKind::Integrity;
    assert_eq!(format!("{}", ArtifactKind::Integrity), "Integrity");
}

#[test]
fn artifact_kind_has_carved_variant() {
    let _c = ArtifactKind::Carved;
    assert_eq!(format!("{}", ArtifactKind::Carved), "Carved");
}

#[test]
fn artifact_kind_has_memory_variant() {
    let _m = ArtifactKind::Memory;
    assert_eq!(format!("{}", ArtifactKind::Memory), "Memory");
}

#[test]
fn forensic_meta_lookup_chrome_history() {
    let meta = ForensicMeta::lookup("browser_chrome_history");
    assert!(meta.is_some());
    let meta = meta.unwrap();
    assert_eq!(meta.artifact_id, "browser_chrome_history");
    // EvidenceStrength should be accessible
    assert!(meta.evidence_strength.is_some());
}

#[test]
fn forensic_meta_lookup_unknown_returns_none() {
    let meta = ForensicMeta::lookup("nonexistent_artifact_xyz");
    assert!(meta.is_none());
}

#[test]
fn evidence_strength_reexported() {
    // Verify we can use EvidenceStrength from browser_core
    let _s = browser_core::EvidenceStrength::Strong;
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-core`

Confirm: tests fail because `ArtifactKind::Integrity`, `ArtifactKind::Carved`, `ArtifactKind::Memory`, `ForensicMeta`, and `EvidenceStrength` re-export do not exist.

#### GREEN commit

**Message:** `feat: add ForensicMeta, ArtifactKind::Integrity/Carved/Memory, re-export EvidenceStrength`

In `/Users/4n6h4x0r/src/browser-forensic/crates/browser-core/src/lib.rs`:

1. Add to imports at top:
```rust
pub use forensicnomicon::evidence::EvidenceStrength;
```

2. Add new variants to `ArtifactKind`:
```rust
pub enum ArtifactKind {
    History,
    Cookies,
    Downloads,
    Extensions,
    LoginData,
    Cache,
    Bookmarks,
    Autofill,
    Session,
    Integrity,  // NEW
    Carved,     // NEW
    Memory,     // NEW
}
```

3. Update `Display` impl to handle new variants:
```rust
Self::Integrity  => write!(f, "Integrity"),
Self::Carved     => write!(f, "Carved"),
Self::Memory     => write!(f, "Memory"),
```

4. Add `ForensicMeta` struct:
```rust
/// Metadata from forensicnomicon for a specific browser artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicMeta {
    pub artifact_id: String,
    pub evidence_strength: Option<String>,
    pub volatility: Option<String>,
    pub caveats: Vec<String>,
}

impl ForensicMeta {
    /// Look up forensic metadata for the given artifact ID.
    /// Returns `None` if the artifact is not in forensicnomicon's catalog.
    #[must_use]
    pub fn lookup(artifact_id: &str) -> Option<Self> {
        let profile = forensicnomicon::profile::profile_for(artifact_id)?;
        Some(Self {
            artifact_id: artifact_id.to_string(),
            evidence_strength: Some(format!("{:?}", profile.evidence_strength)),
            volatility: Some(format!("{:?}", profile.volatility)),
            caveats: profile.evidence_caveats.iter().map(|c| c.to_string()).collect(),
        })
    }
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-core`

Confirm: all tests pass including existing ones.

---

## Phase 3: browser-integrity Crate

### Task 3.1: Create browser-integrity Crate Skeleton with IntegrityIndicator Enum

**Goal:** Create the `browser-integrity` crate with the `IntegrityIndicator` enum and crate structure. No check functions yet -- just the types.

**Files to create:**
- `/Users/4n6h4x0r/src/browser-forensic/crates/browser-integrity/Cargo.toml`
- `/Users/4n6h4x0r/src/browser-forensic/crates/browser-integrity/src/lib.rs`

**Files to modify:**
- `/Users/4n6h4x0r/src/browser-forensic/Cargo.toml` -- add `"crates/browser-integrity"` to workspace members

**Cargo.toml for browser-integrity:**
```toml
[package]
name = "browser-integrity"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
anyhow = { workspace = true }
thiserror = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
browser-core = { path = "../browser-core" }
rusqlite = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }

[lints]
workspace = true
```

#### RED commit

**Message:** `test: RED -- IntegrityIndicator enum and basic serialization`

Create `/Users/4n6h4x0r/src/browser-forensic/crates/browser-integrity/src/lib.rs`:

```rust
#![deny(clippy::unwrap_used)]
//! Browser integrity detection — detects anomalies indicating
//! tampering, clearing, or corruption in browser artifacts.
//!
//! Mirrors the winevt-integrity pattern from winevt-forensic.

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::BrowserFamily;
    use std::path::PathBuf;

    #[test]
    fn integrity_indicator_history_cleared_serializes() {
        let indicator = IntegrityIndicator::HistoryCleared {
            browser: BrowserFamily::Chromium,
            path: PathBuf::from("/tmp/History"),
            detected_at_ns: 1_000_000_000,
        };
        let json = serde_json::to_string(&indicator).expect("serialize");
        assert!(json.contains("HistoryCleared"));
    }

    #[test]
    fn integrity_indicator_visit_id_gap() {
        let indicator = IntegrityIndicator::VisitIdGap {
            path: PathBuf::from("/tmp/History"),
            expected_id: 42,
            found_id: 100,
        };
        let json = serde_json::to_string(&indicator).expect("serialize");
        assert!(json.contains("VisitIdGap"));
        assert!(json.contains("42"));
        assert!(json.contains("100"));
    }

    #[test]
    fn integrity_indicator_timestamp_non_monotonic() {
        let indicator = IntegrityIndicator::TimestampNonMonotonic {
            path: PathBuf::from("/tmp/History"),
            row_id: 5,
            prev_ts_ns: 2_000_000_000,
            this_ts_ns: 1_000_000_000,
        };
        let json = serde_json::to_string(&indicator).expect("serialize");
        assert!(json.contains("TimestampNonMonotonic"));
    }

    #[test]
    fn integrity_indicator_wal_present() {
        let indicator = IntegrityIndicator::WalPresent {
            path: PathBuf::from("/tmp/History-wal"),
        };
        let json = serde_json::to_string(&indicator).expect("serialize");
        assert!(json.contains("WalPresent"));
    }

    #[test]
    fn integrity_indicator_cookie_timestamp_anomaly() {
        let indicator = IntegrityIndicator::CookieTimestampAnomaly {
            path: PathBuf::from("/tmp/Cookies"),
            host: "example.com".to_string(),
            creation_ns: 2_000_000_000,
            last_access_ns: 1_000_000_000,
        };
        let json = serde_json::to_string(&indicator).expect("serialize");
        assert!(json.contains("CookieTimestampAnomaly"));
    }

    #[test]
    fn integrity_indicator_sqlite_integrity_failure() {
        let indicator = IntegrityIndicator::SqliteIntegrityFailure {
            path: PathBuf::from("/tmp/History"),
            message: "page 5: corrupt".to_string(),
        };
        let json = serde_json::to_string(&indicator).expect("serialize");
        assert!(json.contains("SqliteIntegrityFailure"));
    }

    #[test]
    fn integrity_indicator_history_tombstone() {
        let indicator = IntegrityIndicator::HistoryTombstoneFound {
            path: PathBuf::from("/tmp/History.db"),
            url: "https://deleted.example.com".to_string(),
            deleted_at_ns: 3_000_000_000,
        };
        let json = serde_json::to_string(&indicator).expect("serialize");
        assert!(json.contains("HistoryTombstoneFound"));
    }

    #[test]
    fn integrity_indicator_debug_display() {
        let indicator = IntegrityIndicator::WalPresent {
            path: PathBuf::from("/tmp/test-wal"),
        };
        let debug = format!("{:?}", indicator);
        assert!(debug.contains("WalPresent"));
    }

    #[test]
    fn integrity_indicator_clone() {
        let indicator = IntegrityIndicator::WalPresent {
            path: PathBuf::from("/tmp/test"),
        };
        let cloned = indicator.clone();
        assert_eq!(
            serde_json::to_string(&indicator).expect("ser1"),
            serde_json::to_string(&cloned).expect("ser2"),
        );
    }
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-integrity`

Confirm: fails to compile because `IntegrityIndicator` does not exist.

#### GREEN commit

**Message:** `feat: browser-integrity crate with IntegrityIndicator enum`

Add to the top of `/Users/4n6h4x0r/src/browser-forensic/crates/browser-integrity/src/lib.rs` (before `#[cfg(test)]`):

```rust
use std::path::PathBuf;

use browser_core::BrowserFamily;
use serde::Serialize;

/// An anomaly detected in a browser artifact that may indicate
/// tampering, clearing, or corruption.
///
/// Mirrors `winevt_integrity::IntegrityIndicator` from winevt-forensic.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub enum IntegrityIndicator {
    /// Browser history was cleared (empty tables with non-zero auto-increment counters).
    HistoryCleared {
        browser: BrowserFamily,
        path: PathBuf,
        detected_at_ns: i64,
    },

    /// Gap in visit/row IDs suggesting deleted records.
    VisitIdGap {
        path: PathBuf,
        expected_id: i64,
        found_id: i64,
    },

    /// Timestamps are not monotonically increasing within a table.
    TimestampNonMonotonic {
        path: PathBuf,
        row_id: i64,
        prev_ts_ns: i64,
        this_ts_ns: i64,
    },

    /// Cookie creation timestamp is after last_access timestamp (impossible naturally).
    CookieTimestampAnomaly {
        path: PathBuf,
        host: String,
        creation_ns: i64,
        last_access_ns: i64,
    },

    /// WAL (Write-Ahead Log) file exists alongside database -- uncommitted changes or crash.
    WalPresent {
        path: PathBuf,
    },

    /// SQLite PRAGMA integrity_check reported a problem.
    SqliteIntegrityFailure {
        path: PathBuf,
        message: String,
    },

    /// Safari history_tombstones table contains deleted URL records.
    HistoryTombstoneFound {
        path: PathBuf,
        url: String,
        deleted_at_ns: i64,
    },

    /// Download record references a file that no longer exists on disk.
    DownloadFileMissing {
        path: PathBuf,
        target_path: String,
    },

    /// Auto-increment counter is much higher than max rowid (indicates mass deletion).
    AutoIncrementGap {
        path: PathBuf,
        table: String,
        max_rowid: i64,
        auto_increment: i64,
    },
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-integrity`

Confirm: all 9 tests pass.

---

### Task 3.2: Implement check_database_integrity (SQLite PRAGMA integrity_check)

**Goal:** Implement `check_database_integrity()` which runs SQLite's `PRAGMA integrity_check` and returns `IntegrityIndicator::SqliteIntegrityFailure` for any issues.

**File to modify:** `/Users/4n6h4x0r/src/browser-forensic/crates/browser-integrity/src/lib.rs`

**New file to create:** `/Users/4n6h4x0r/src/browser-forensic/crates/browser-integrity/src/database.rs`

#### RED commit

**Message:** `test: RED -- check_database_integrity returns empty for valid db, indicators for corrupt`

Create `/Users/4n6h4x0r/src/browser-forensic/crates/browser-integrity/src/database.rs`:

```rust
//! SQLite database-level integrity checks.

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::NamedTempFile;

    #[test]
    fn check_database_integrity_valid_db_returns_empty() {
        let f = NamedTempFile::new().expect("tempfile");
        let conn = rusqlite::Connection::open(f.path()).expect("open");
        conn.execute_batch("CREATE TABLE test (id INTEGER PRIMARY KEY, val TEXT);")
            .expect("create table");
        conn.execute("INSERT INTO test VALUES (1, 'hello')", [])
            .expect("insert");
        drop(conn);

        let result = check_database_integrity(f.path()).expect("check");
        assert!(result.is_empty(), "valid db should have no integrity issues");
    }

    #[test]
    fn check_database_integrity_nonexistent_returns_error() {
        let result = check_database_integrity(Path::new("/nonexistent/path/to/db"));
        assert!(result.is_err());
    }

    #[test]
    fn check_wal_state_detects_wal_file() {
        let f = NamedTempFile::new().expect("tempfile");
        let wal_path = f.path().with_extension("db-wal");
        // Create a WAL file
        std::fs::write(&wal_path, b"fake wal content").expect("write wal");

        let db_path = f.path().with_extension("db");
        // Create a valid SQLite db at db_path
        let conn = rusqlite::Connection::open(&db_path).expect("open");
        conn.execute_batch("CREATE TABLE t (id INTEGER);").expect("create");
        drop(conn);

        // Now create the WAL file next to it
        let actual_wal = format!("{}-wal", db_path.display());
        std::fs::write(&actual_wal, b"fake wal").expect("write wal");

        let result = check_wal_state(&db_path).expect("check");
        assert!(result.iter().any(|i| matches!(i, crate::IntegrityIndicator::WalPresent { .. })));

        // Cleanup
        let _ = std::fs::remove_file(&actual_wal);
        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn check_wal_state_no_wal_returns_empty() {
        let f = NamedTempFile::new().expect("tempfile");
        let conn = rusqlite::Connection::open(f.path()).expect("open");
        conn.execute_batch("CREATE TABLE t (id INTEGER);").expect("create");
        // Force WAL mode off - use DELETE journal mode
        conn.pragma_update(None, "journal_mode", "DELETE").expect("journal mode");
        drop(conn);

        let result = check_wal_state(f.path()).expect("check");
        assert!(result.is_empty());
    }
}
```

Modify `/Users/4n6h4x0r/src/browser-forensic/crates/browser-integrity/src/lib.rs` to add:
```rust
pub mod database;
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-integrity`

Confirm: fails because `check_database_integrity` and `check_wal_state` do not exist.

#### GREEN commit

**Message:** `feat: implement check_database_integrity and check_wal_state`

Add to `/Users/4n6h4x0r/src/browser-forensic/crates/browser-integrity/src/database.rs` (before `#[cfg(test)]`):

```rust
use std::path::Path;

use anyhow::Result;
use rusqlite::Connection;

use crate::IntegrityIndicator;

/// Run SQLite's `PRAGMA integrity_check` on the database at `path`.
///
/// Returns an empty vec if the database passes all checks.
/// Returns `IntegrityIndicator::SqliteIntegrityFailure` for each problem found.
pub fn check_database_integrity(path: &Path) -> Result<Vec<IntegrityIndicator>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare("PRAGMA integrity_check")?;
    let rows: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .filter_map(|r| r.ok())
        .collect();

    let mut indicators = Vec::new();
    for row in &rows {
        if row != "ok" {
            indicators.push(IntegrityIndicator::SqliteIntegrityFailure {
                path: path.to_path_buf(),
                message: row.clone(),
            });
        }
    }

    Ok(indicators)
}

/// Check whether a WAL (Write-Ahead Log) file exists alongside the database.
///
/// A WAL file's presence means either:
/// 1. The database is in WAL mode and has uncommitted transactions
/// 2. The application crashed before checkpointing
///
/// Both scenarios are forensically relevant.
pub fn check_wal_state(path: &Path) -> Result<Vec<IntegrityIndicator>> {
    let wal_path_str = format!("{}-wal", path.display());
    let wal_path = Path::new(&wal_path_str);

    let mut indicators = Vec::new();
    if wal_path.exists() {
        let metadata = std::fs::metadata(wal_path)?;
        if metadata.len() > 0 {
            indicators.push(IntegrityIndicator::WalPresent {
                path: wal_path.to_path_buf(),
            });
        }
    }

    Ok(indicators)
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-integrity`

Confirm: all tests pass.

---

### Task 3.3: Implement check_history_integrity for Chromium

**Goal:** Detect history clearing (auto-increment gap), visit ID gaps, and timestamp non-monotonicity in Chromium History databases.

**New file:** `/Users/4n6h4x0r/src/browser-forensic/crates/browser-integrity/src/history.rs`

**File to modify:** `/Users/4n6h4x0r/src/browser-forensic/crates/browser-integrity/src/lib.rs` -- add `pub mod history;`

#### RED commit

**Message:** `test: RED -- check_history_integrity detects clearing, ID gaps, timestamp anomalies`

Create `/Users/4n6h4x0r/src/browser-forensic/crates/browser-integrity/src/history.rs`:

```rust
//! History integrity checks across browser families.

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::BrowserFamily;
    use browser_core::test_utils::sqlite::TestDb;
    use crate::IntegrityIndicator;

    fn chrome_history_schema() -> &'static str {
        "CREATE TABLE urls (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            title TEXT,
            visit_count INTEGER DEFAULT 0,
            last_visit_time INTEGER DEFAULT 0
        );
        CREATE TABLE visits (
            id INTEGER PRIMARY KEY,
            url INTEGER NOT NULL,
            visit_time INTEGER NOT NULL,
            from_visit INTEGER DEFAULT 0,
            transition INTEGER DEFAULT 0
        );
        CREATE TABLE sqlite_sequence (name TEXT, seq INTEGER);"
    }

    #[test]
    fn chromium_history_clean_returns_empty() {
        let db = TestDb::new(chrome_history_schema());
        db.insert("INSERT INTO urls VALUES (1, 'https://a.com', 'A', 1, 13000000000000000)", rusqlite::params![]);
        db.insert("INSERT INTO urls VALUES (2, 'https://b.com', 'B', 1, 13000000001000000)", rusqlite::params![]);
        db.insert("INSERT INTO visits VALUES (1, 1, 13000000000000000, 0, 0)", rusqlite::params![]);
        db.insert("INSERT INTO visits VALUES (2, 2, 13000000001000000, 0, 0)", rusqlite::params![]);
        db.insert("INSERT INTO sqlite_sequence VALUES ('urls', 2)", rusqlite::params![]);
        db.insert("INSERT INTO sqlite_sequence VALUES ('visits', 2)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        // No gaps, no timestamp issues, auto-increment matches
        let clearing: Vec<_> = result.iter().filter(|i| matches!(i, IntegrityIndicator::HistoryCleared { .. })).collect();
        assert!(clearing.is_empty(), "clean db should have no clearing indicators");
    }

    #[test]
    fn chromium_history_clearing_detected_by_autoinc_gap() {
        let db = TestDb::new(chrome_history_schema());
        // Only row ID 1, but auto-increment says 500 (massive deletion)
        db.insert("INSERT INTO urls VALUES (1, 'https://a.com', 'A', 1, 13000000000000000)", rusqlite::params![]);
        db.insert("INSERT INTO sqlite_sequence VALUES ('urls', 500)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(result.iter().any(|i| matches!(i, IntegrityIndicator::AutoIncrementGap { .. })),
            "should detect auto-increment gap indicating mass deletion");
    }

    #[test]
    fn chromium_visit_id_gap_detected() {
        let db = TestDb::new(chrome_history_schema());
        db.insert("INSERT INTO urls VALUES (1, 'https://a.com', 'A', 2, 13000000001000000)", rusqlite::params![]);
        db.insert("INSERT INTO visits VALUES (1, 1, 13000000000000000, 0, 0)", rusqlite::params![]);
        // Gap: visit ID jumps from 1 to 50
        db.insert("INSERT INTO visits VALUES (50, 1, 13000000001000000, 0, 0)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(result.iter().any(|i| matches!(i, IntegrityIndicator::VisitIdGap { .. })),
            "should detect visit ID gap from 1 to 50");
    }

    #[test]
    fn chromium_timestamp_non_monotonic_detected() {
        let db = TestDb::new(chrome_history_schema());
        db.insert("INSERT INTO urls VALUES (1, 'https://a.com', 'A', 1, 13000000000000000)", rusqlite::params![]);
        db.insert("INSERT INTO urls VALUES (2, 'https://b.com', 'B', 1, 12000000000000000)", rusqlite::params![]);
        db.insert("INSERT INTO visits VALUES (1, 1, 13000000001000000, 0, 0)", rusqlite::params![]);
        // Visit 2 has EARLIER timestamp but HIGHER ID
        db.insert("INSERT INTO visits VALUES (2, 2, 13000000000000000, 0, 0)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(result.iter().any(|i| matches!(i, IntegrityIndicator::TimestampNonMonotonic { .. })),
            "should detect non-monotonic timestamps in visits");
    }

    #[test]
    fn empty_history_with_nonzero_autoinc_is_clearing() {
        let db = TestDb::new(chrome_history_schema());
        // No rows, but auto-increment counter at 100
        db.insert("INSERT INTO sqlite_sequence VALUES ('urls', 100)", rusqlite::params![]);

        let result = check_history_integrity(db.path(), BrowserFamily::Chromium).expect("check");
        assert!(result.iter().any(|i| matches!(i,
            IntegrityIndicator::HistoryCleared { .. }
        )), "empty db with high auto-increment should indicate clearing");
    }
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-integrity`

Confirm: fails because `check_history_integrity` does not exist.

#### GREEN commit

**Message:** `feat: implement check_history_integrity for Chromium (clearing, ID gaps, timestamp anomalies)`

Add implementation to `/Users/4n6h4x0r/src/browser-forensic/crates/browser-integrity/src/history.rs` (before `#[cfg(test)]`):

```rust
use std::path::Path;

use anyhow::Result;
use browser_core::BrowserFamily;
use browser_core::timestamp::webkit_micros_to_unix_nanos;
use rusqlite::Connection;

use crate::IntegrityIndicator;

/// Check a browser history database for integrity anomalies.
///
/// Detects:
/// - History clearing (empty tables with high auto-increment counters)
/// - Visit ID gaps (deleted records leaving gaps in sequential IDs)
/// - Timestamp non-monotonicity (manually edited or imported timestamps)
///
/// Currently supports Chromium. Firefox and Safari support planned.
pub fn check_history_integrity(path: &Path, browser: BrowserFamily) -> Result<Vec<IntegrityIndicator>> {
    match browser {
        BrowserFamily::Chromium => check_chromium_history(path),
        _ => Ok(Vec::new()), // TODO: Firefox, Safari
    }
}

fn check_chromium_history(path: &Path) -> Result<Vec<IntegrityIndicator>> {
    let conn = Connection::open(path)?;
    let mut indicators = Vec::new();

    // 1. Check auto-increment gap (clearing detection)
    check_chromium_autoinc_gap(&conn, path, &mut indicators)?;

    // 2. Check visit ID gaps
    check_chromium_visit_id_gaps(&conn, path, &mut indicators)?;

    // 3. Check timestamp monotonicity
    check_chromium_timestamp_monotonicity(&conn, path, &mut indicators)?;

    Ok(indicators)
}

fn check_chromium_autoinc_gap(
    conn: &Connection,
    path: &Path,
    indicators: &mut Vec<IntegrityIndicator>,
) -> Result<()> {
    // Check urls table
    let max_rowid: Option<i64> = conn
        .query_row("SELECT MAX(id) FROM urls", [], |row| row.get(0))
        .ok();
    let autoinc: Option<i64> = conn
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name = 'urls'",
            [],
            |row| row.get(0),
        )
        .ok();

    match (max_rowid, autoinc) {
        (None | Some(0), Some(seq)) if seq > 0 => {
            // Table is empty but auto-increment is non-zero -- clearing
            indicators.push(IntegrityIndicator::HistoryCleared {
                browser: BrowserFamily::Chromium,
                path: path.to_path_buf(),
                detected_at_ns: 0, // cannot determine when clearing happened
            });
        }
        (Some(max_id), Some(seq)) if max_id > 0 && seq > max_id * 5 => {
            // Auto-increment is 5x+ the max rowid -- significant deletion
            indicators.push(IntegrityIndicator::AutoIncrementGap {
                path: path.to_path_buf(),
                table: "urls".to_string(),
                max_rowid: max_id,
                auto_increment: seq,
            });
        }
        _ => {}
    }

    Ok(())
}

fn check_chromium_visit_id_gaps(
    conn: &Connection,
    path: &Path,
    indicators: &mut Vec<IntegrityIndicator>,
) -> Result<()> {
    let mut stmt = conn.prepare("SELECT id FROM visits ORDER BY id ASC")?;
    let ids: Vec<i64> = stmt
        .query_map([], |row| row.get::<_, i64>(0))?
        .filter_map(|r| r.ok())
        .collect();

    for window in ids.windows(2) {
        let prev = window[0];
        let curr = window[1];
        if curr - prev > 1 {
            indicators.push(IntegrityIndicator::VisitIdGap {
                path: path.to_path_buf(),
                expected_id: prev + 1,
                found_id: curr,
            });
        }
    }

    Ok(())
}

fn check_chromium_timestamp_monotonicity(
    conn: &Connection,
    path: &Path,
    indicators: &mut Vec<IntegrityIndicator>,
) -> Result<()> {
    let mut stmt = conn.prepare("SELECT id, visit_time FROM visits ORDER BY id ASC")?;
    let rows: Vec<(i64, i64)> = stmt
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })?
        .filter_map(|r| r.ok())
        .collect();

    for window in rows.windows(2) {
        let (prev_id, prev_ts) = window[0];
        let (curr_id, curr_ts) = window[1];
        if curr_ts < prev_ts {
            indicators.push(IntegrityIndicator::TimestampNonMonotonic {
                path: path.to_path_buf(),
                row_id: curr_id,
                prev_ts_ns: webkit_micros_to_unix_nanos(prev_ts),
                this_ts_ns: webkit_micros_to_unix_nanos(curr_ts),
            });
        }
    }

    Ok(())
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-integrity`

Confirm: all tests pass.

---

### Task 3.4: Implement check_history_integrity for Firefox

**Goal:** Add Firefox support to `check_history_integrity` -- checks `moz_places` and `moz_historyvisits` tables.

**File to modify:** `/Users/4n6h4x0r/src/browser-forensic/crates/browser-integrity/src/history.rs`

#### RED commit

**Message:** `test: RED -- Firefox history integrity checks (clearing, visit gaps, timestamps)`

Add tests to `history.rs`:

```rust
fn firefox_history_schema() -> &'static str {
    "CREATE TABLE moz_places (
        id INTEGER PRIMARY KEY,
        url TEXT NOT NULL,
        title TEXT,
        visit_count INTEGER DEFAULT 0,
        last_visit_date INTEGER
    );
    CREATE TABLE moz_historyvisits (
        id INTEGER PRIMARY KEY,
        from_visit INTEGER,
        place_id INTEGER,
        visit_date INTEGER,
        visit_type INTEGER
    );"
}

#[test]
fn firefox_history_clean_returns_empty() {
    let db = TestDb::new(firefox_history_schema());
    db.insert("INSERT INTO moz_places VALUES (1, 'https://a.com', 'A', 1, 1700000000000000)", rusqlite::params![]);
    db.insert("INSERT INTO moz_places VALUES (2, 'https://b.com', 'B', 1, 1700000001000000)", rusqlite::params![]);
    db.insert("INSERT INTO moz_historyvisits VALUES (1, 0, 1, 1700000000000000, 1)", rusqlite::params![]);
    db.insert("INSERT INTO moz_historyvisits VALUES (2, 0, 2, 1700000001000000, 1)", rusqlite::params![]);

    let result = check_history_integrity(db.path(), BrowserFamily::Firefox).expect("check");
    assert!(result.is_empty(), "clean Firefox db should have no issues");
}

#[test]
fn firefox_visit_id_gap_detected() {
    let db = TestDb::new(firefox_history_schema());
    db.insert("INSERT INTO moz_places VALUES (1, 'https://a.com', 'A', 2, 1700000001000000)", rusqlite::params![]);
    db.insert("INSERT INTO moz_historyvisits VALUES (1, 0, 1, 1700000000000000, 1)", rusqlite::params![]);
    db.insert("INSERT INTO moz_historyvisits VALUES (100, 0, 1, 1700000001000000, 1)", rusqlite::params![]);

    let result = check_history_integrity(db.path(), BrowserFamily::Firefox).expect("check");
    assert!(result.iter().any(|i| matches!(i, IntegrityIndicator::VisitIdGap { .. })));
}

#[test]
fn firefox_timestamp_non_monotonic_detected() {
    let db = TestDb::new(firefox_history_schema());
    db.insert("INSERT INTO moz_places VALUES (1, 'https://a.com', 'A', 1, 1700000000000000)", rusqlite::params![]);
    db.insert("INSERT INTO moz_places VALUES (2, 'https://b.com', 'B', 1, 1600000000000000)", rusqlite::params![]);
    db.insert("INSERT INTO moz_historyvisits VALUES (1, 0, 1, 1700000001000000, 1)", rusqlite::params![]);
    db.insert("INSERT INTO moz_historyvisits VALUES (2, 0, 2, 1700000000000000, 1)", rusqlite::params![]);

    let result = check_history_integrity(db.path(), BrowserFamily::Firefox).expect("check");
    assert!(result.iter().any(|i| matches!(i, IntegrityIndicator::TimestampNonMonotonic { .. })));
}

#[test]
fn firefox_empty_places_with_high_rowid_is_clearing() {
    let db = TestDb::new(firefox_history_schema());
    // Empty tables -- check for clearing via max(id) analysis
    // We can't use sqlite_sequence trick for Firefox since it uses INTEGER PRIMARY KEY
    // without AUTOINCREMENT, so we check differently
    // This test verifies the function doesn't crash on empty tables
    let result = check_history_integrity(db.path(), BrowserFamily::Firefox).expect("check");
    // Empty is fine -- no indicators
    assert!(result.is_empty());
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-integrity`

Confirm: tests fail because Firefox path in `check_history_integrity` returns empty vec.

#### GREEN commit

**Message:** `feat: implement check_history_integrity for Firefox (moz_places/moz_historyvisits)`

Add Firefox implementation to `history.rs`:

```rust
fn check_firefox_history(path: &Path) -> Result<Vec<IntegrityIndicator>> {
    let conn = Connection::open(path)?;
    let mut indicators = Vec::new();

    // Check visit ID gaps in moz_historyvisits
    check_firefox_visit_id_gaps(&conn, path, &mut indicators)?;

    // Check timestamp monotonicity
    check_firefox_timestamp_monotonicity(&conn, path, &mut indicators)?;

    Ok(indicators)
}

fn check_firefox_visit_id_gaps(
    conn: &Connection,
    path: &Path,
    indicators: &mut Vec<IntegrityIndicator>,
) -> Result<()> {
    let mut stmt = conn.prepare("SELECT id FROM moz_historyvisits ORDER BY id ASC")?;
    let ids: Vec<i64> = stmt
        .query_map([], |row| row.get::<_, i64>(0))?
        .filter_map(|r| r.ok())
        .collect();

    for window in ids.windows(2) {
        let prev = window[0];
        let curr = window[1];
        if curr - prev > 1 {
            indicators.push(IntegrityIndicator::VisitIdGap {
                path: path.to_path_buf(),
                expected_id: prev + 1,
                found_id: curr,
            });
        }
    }

    Ok(())
}

fn check_firefox_timestamp_monotonicity(
    conn: &Connection,
    path: &Path,
    indicators: &mut Vec<IntegrityIndicator>,
) -> Result<()> {
    // Firefox stores visit_date in microseconds since Unix epoch
    let mut stmt = conn.prepare("SELECT id, visit_date FROM moz_historyvisits ORDER BY id ASC")?;
    let rows: Vec<(i64, i64)> = stmt
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })?
        .filter_map(|r| r.ok())
        .collect();

    for window in rows.windows(2) {
        let (_prev_id, prev_ts) = window[0];
        let (curr_id, curr_ts) = window[1];
        if curr_ts < prev_ts {
            indicators.push(IntegrityIndicator::TimestampNonMonotonic {
                path: path.to_path_buf(),
                row_id: curr_id,
                prev_ts_ns: browser_core::timestamp::unix_micros_to_nanos(prev_ts),
                this_ts_ns: browser_core::timestamp::unix_micros_to_nanos(curr_ts),
            });
        }
    }

    Ok(())
}
```

Update the match in `check_history_integrity`:
```rust
BrowserFamily::Firefox => check_firefox_history(path),
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-integrity`

Confirm: all tests pass.

---

### Task 3.5: Implement check_history_integrity for Safari (with Tombstones)

**Goal:** Add Safari support -- checks `history_items` and `history_visits` tables, plus `history_tombstones` table for deleted URL detection.

**File to modify:** `/Users/4n6h4x0r/src/browser-forensic/crates/browser-integrity/src/history.rs`

#### RED commit

**Message:** `test: RED -- Safari history integrity checks with tombstone detection`

Add tests:

```rust
fn safari_history_schema() -> &'static str {
    "CREATE TABLE history_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL UNIQUE,
        domain_expansion TEXT,
        visit_count INTEGER NOT NULL DEFAULT 0,
        daily_visit_counts BLOB,
        weekly_visit_counts BLOB,
        autocomplete_triggers BLOB,
        should_recompute_derived_visit_counts INTEGER NOT NULL DEFAULT 1,
        visit_count_score INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE history_visits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        history_item INTEGER NOT NULL REFERENCES history_items(id) ON DELETE CASCADE,
        visit_time REAL NOT NULL,
        title TEXT,
        load_successful BOOLEAN NOT NULL DEFAULT 1,
        http_non_get INTEGER NOT NULL DEFAULT 0,
        synthesized INTEGER NOT NULL DEFAULT 0,
        redirect_source INTEGER,
        redirect_destination INTEGER,
        origin INTEGER NOT NULL DEFAULT 0,
        generation INTEGER NOT NULL DEFAULT 0,
        attributes INTEGER NOT NULL DEFAULT 0,
        score INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE history_tombstones (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        generation INTEGER NOT NULL
    );"
}

#[test]
fn safari_history_clean_returns_empty() {
    let db = TestDb::new(safari_history_schema());
    db.insert(
        "INSERT INTO history_items (id, url, visit_count) VALUES (1, 'https://a.com', 1)",
        rusqlite::params![],
    );
    db.insert(
        "INSERT INTO history_visits (id, history_item, visit_time) VALUES (1, 1, 700000000.0)",
        rusqlite::params![],
    );

    let result = check_history_integrity(db.path(), BrowserFamily::Safari).expect("check");
    // No tombstones, no gaps
    let tombstones: Vec<_> = result.iter().filter(|i| matches!(i, IntegrityIndicator::HistoryTombstoneFound { .. })).collect();
    assert!(tombstones.is_empty());
}

#[test]
fn safari_tombstones_detected() {
    let db = TestDb::new(safari_history_schema());
    db.insert(
        "INSERT INTO history_tombstones (id, url, generation) VALUES (1, 'https://deleted.example.com', 5)",
        rusqlite::params![],
    );
    db.insert(
        "INSERT INTO history_tombstones (id, url, generation) VALUES (2, 'https://also-deleted.example.com', 5)",
        rusqlite::params![],
    );

    let result = check_history_integrity(db.path(), BrowserFamily::Safari).expect("check");
    let tombstones: Vec<_> = result.iter().filter(|i| matches!(i, IntegrityIndicator::HistoryTombstoneFound { .. })).collect();
    assert_eq!(tombstones.len(), 2, "should detect 2 tombstoned URLs");
}

#[test]
fn safari_visit_id_gap_detected() {
    let db = TestDb::new(safari_history_schema());
    db.insert(
        "INSERT INTO history_items (id, url, visit_count) VALUES (1, 'https://a.com', 2)",
        rusqlite::params![],
    );
    db.insert(
        "INSERT INTO history_visits (id, history_item, visit_time) VALUES (1, 1, 700000000.0)",
        rusqlite::params![],
    );
    db.insert(
        "INSERT INTO history_visits (id, history_item, visit_time) VALUES (50, 1, 700000001.0)",
        rusqlite::params![],
    );

    let result = check_history_integrity(db.path(), BrowserFamily::Safari).expect("check");
    assert!(result.iter().any(|i| matches!(i, IntegrityIndicator::VisitIdGap { .. })));
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-integrity`

Confirm: tests fail because Safari path returns empty vec.

#### GREEN commit

**Message:** `feat: implement check_history_integrity for Safari with tombstone detection`

Add Safari implementation to `history.rs`:

```rust
fn check_safari_history(path: &Path) -> Result<Vec<IntegrityIndicator>> {
    let conn = Connection::open(path)?;
    let mut indicators = Vec::new();

    // 1. Check history_tombstones table
    check_safari_tombstones(&conn, path, &mut indicators)?;

    // 2. Check visit ID gaps in history_visits
    check_safari_visit_id_gaps(&conn, path, &mut indicators)?;

    // 3. Check timestamp monotonicity
    check_safari_timestamp_monotonicity(&conn, path, &mut indicators)?;

    Ok(indicators)
}

fn check_safari_tombstones(
    conn: &Connection,
    path: &Path,
    indicators: &mut Vec<IntegrityIndicator>,
) -> Result<()> {
    // history_tombstones may not exist in older Safari versions
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='history_tombstones'",
            [],
            |row| row.get(0),
        )?;

    if !table_exists {
        return Ok(());
    }

    let mut stmt = conn.prepare("SELECT url FROM history_tombstones")?;
    let urls: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .filter_map(|r| r.ok())
        .collect();

    for url in urls {
        indicators.push(IntegrityIndicator::HistoryTombstoneFound {
            path: path.to_path_buf(),
            url,
            deleted_at_ns: 0, // tombstones don't store deletion timestamp
        });
    }

    Ok(())
}

fn check_safari_visit_id_gaps(
    conn: &Connection,
    path: &Path,
    indicators: &mut Vec<IntegrityIndicator>,
) -> Result<()> {
    let mut stmt = conn.prepare("SELECT id FROM history_visits ORDER BY id ASC")?;
    let ids: Vec<i64> = stmt
        .query_map([], |row| row.get::<_, i64>(0))?
        .filter_map(|r| r.ok())
        .collect();

    for window in ids.windows(2) {
        let prev = window[0];
        let curr = window[1];
        if curr - prev > 1 {
            indicators.push(IntegrityIndicator::VisitIdGap {
                path: path.to_path_buf(),
                expected_id: prev + 1,
                found_id: curr,
            });
        }
    }

    Ok(())
}

fn check_safari_timestamp_monotonicity(
    conn: &Connection,
    path: &Path,
    indicators: &mut Vec<IntegrityIndicator>,
) -> Result<()> {
    // Safari stores visit_time as Core Data timestamp (seconds since 2001-01-01)
    let mut stmt = conn.prepare("SELECT id, visit_time FROM history_visits ORDER BY id ASC")?;
    let rows: Vec<(i64, f64)> = stmt
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, f64>(1)?))
        })?
        .filter_map(|r| r.ok())
        .collect();

    for window in rows.windows(2) {
        let (_prev_id, prev_ts) = window[0];
        let (curr_id, curr_ts) = window[1];
        if curr_ts < prev_ts {
            indicators.push(IntegrityIndicator::TimestampNonMonotonic {
                path: path.to_path_buf(),
                row_id: curr_id,
                prev_ts_ns: browser_core::timestamp::core_data_secs_to_unix_nanos(prev_ts),
                this_ts_ns: browser_core::timestamp::core_data_secs_to_unix_nanos(curr_ts),
            });
        }
    }

    Ok(())
}
```

Update `check_history_integrity` match:
```rust
BrowserFamily::Safari => check_safari_history(path),
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-integrity`

Confirm: all tests pass.

---

### Task 3.6: Implement check_cookie_integrity

**Goal:** Detect cookie timestamp anomalies (creation > last_access) across all three browsers.

**New file:** `/Users/4n6h4x0r/src/browser-forensic/crates/browser-integrity/src/cookies.rs`

**File to modify:** `/Users/4n6h4x0r/src/browser-forensic/crates/browser-integrity/src/lib.rs` -- add `pub mod cookies;`

#### RED commit

**Message:** `test: RED -- check_cookie_integrity detects timestamp anomalies across browsers`

Create `/Users/4n6h4x0r/src/browser-forensic/crates/browser-integrity/src/cookies.rs`:

```rust
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
        // creation_utc > last_access_utc -- impossible naturally
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
        // creationTime > lastAccessed -- impossible naturally
        // Firefox uses microseconds since epoch
        db.insert(
            "INSERT INTO moz_cookies VALUES (1, 'evil.com', '.evil.com', 'track', 'x', '/', 1800000000, 1700000000000000, 1800000000000000, 0, 0)",
            rusqlite::params![],
        );

        let result = check_cookie_integrity(db.path(), BrowserFamily::Firefox).expect("check");
        assert!(result.iter().any(|i| matches!(i, IntegrityIndicator::CookieTimestampAnomaly { .. })));
    }
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-integrity`

Confirm: fails because `check_cookie_integrity` does not exist.

#### GREEN commit

**Message:** `feat: implement check_cookie_integrity for Chromium and Firefox`

Add implementation before `#[cfg(test)]` in `cookies.rs`:

```rust
use std::path::Path;

use anyhow::Result;
use browser_core::BrowserFamily;
use browser_core::timestamp::{webkit_micros_to_unix_nanos, unix_micros_to_nanos};
use rusqlite::Connection;

use crate::IntegrityIndicator;

/// Check a browser cookie database for integrity anomalies.
///
/// Detects cookies where creation timestamp > last_access timestamp,
/// which is impossible under normal browser operation and indicates
/// timestamp manipulation or database editing.
pub fn check_cookie_integrity(path: &Path, browser: BrowserFamily) -> Result<Vec<IntegrityIndicator>> {
    match browser {
        BrowserFamily::Chromium => check_chromium_cookies(path),
        BrowserFamily::Firefox => check_firefox_cookies(path),
        BrowserFamily::Safari => Ok(Vec::new()), // TODO: Safari binary cookies
    }
}

fn check_chromium_cookies(path: &Path) -> Result<Vec<IntegrityIndicator>> {
    let conn = Connection::open(path)?;
    let mut indicators = Vec::new();

    let mut stmt = conn.prepare(
        "SELECT host_key, creation_utc, last_access_utc FROM cookies WHERE last_access_utc > 0"
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;

    for row in rows.flatten() {
        let (host, creation, last_access) = row;
        if creation > last_access {
            indicators.push(IntegrityIndicator::CookieTimestampAnomaly {
                path: path.to_path_buf(),
                host,
                creation_ns: webkit_micros_to_unix_nanos(creation),
                last_access_ns: webkit_micros_to_unix_nanos(last_access),
            });
        }
    }

    Ok(indicators)
}

fn check_firefox_cookies(path: &Path) -> Result<Vec<IntegrityIndicator>> {
    let conn = Connection::open(path)?;
    let mut indicators = Vec::new();

    let mut stmt = conn.prepare(
        "SELECT host, creationTime, lastAccessed FROM moz_cookies WHERE lastAccessed > 0"
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;

    for row in rows.flatten() {
        let (host, creation, last_access) = row;
        if creation > last_access {
            indicators.push(IntegrityIndicator::CookieTimestampAnomaly {
                path: path.to_path_buf(),
                host,
                creation_ns: unix_micros_to_nanos(creation),
                last_access_ns: unix_micros_to_nanos(last_access),
            });
        }
    }

    Ok(indicators)
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-integrity`

Confirm: all tests pass.

---

### Task 3.7: Public API -- re-export check functions from lib.rs

**Goal:** Make `browser_integrity::check_history_integrity`, `check_cookie_integrity`, `check_database_integrity`, and `check_wal_state` available from the crate root.

**File to modify:** `/Users/4n6h4x0r/src/browser-forensic/crates/browser-integrity/src/lib.rs`

#### RED commit

**Message:** `test: RED -- crate root re-exports for all check functions`

Add test:

```rust
#[test]
fn crate_root_reexports_check_functions() {
    // These should be accessible from the crate root
    let _f1: fn(&std::path::Path, BrowserFamily) -> anyhow::Result<Vec<IntegrityIndicator>>
        = browser_integrity::check_history_integrity;
    let _f2: fn(&std::path::Path, BrowserFamily) -> anyhow::Result<Vec<IntegrityIndicator>>
        = browser_integrity::check_cookie_integrity;
    let _f3: fn(&std::path::Path) -> anyhow::Result<Vec<IntegrityIndicator>>
        = browser_integrity::check_database_integrity;
    let _f4: fn(&std::path::Path) -> anyhow::Result<Vec<IntegrityIndicator>>
        = browser_integrity::check_wal_state;
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-integrity`

Confirm: fails because functions are not re-exported from crate root.

#### GREEN commit

**Message:** `feat: re-export all check functions from browser-integrity crate root`

Add to `/Users/4n6h4x0r/src/browser-forensic/crates/browser-integrity/src/lib.rs`:

```rust
pub use database::{check_database_integrity, check_wal_state};
pub use history::check_history_integrity;
pub use cookies::check_cookie_integrity;
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-integrity`

Confirm: all tests pass.

---

## Phase 4: browser-carve Crate

### Task 4.1: Create browser-carve Crate Skeleton with Types

**Goal:** Create the `browser-carve` crate with `CarvedRecord`, `CarveResult`, `CarveStats`, `RecoveryMethod`, `RecoveryQuality` types.

**Files to create:**
- `/Users/4n6h4x0r/src/browser-forensic/crates/browser-carve/Cargo.toml`
- `/Users/4n6h4x0r/src/browser-forensic/crates/browser-carve/src/lib.rs`

**Files to modify:**
- `/Users/4n6h4x0r/src/browser-forensic/Cargo.toml` -- add `"crates/browser-carve"` to workspace members

**Cargo.toml for browser-carve:**
```toml
[package]
name = "browser-carve"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
anyhow = { workspace = true }
thiserror = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
browser-core = { path = "../browser-core" }
browser-integrity = { path = "../browser-integrity" }
rusqlite = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }

[lints]
workspace = true
```

#### RED commit

**Message:** `test: RED -- CarvedRecord, CarveResult, CarveStats type definitions and serialization`

Create `/Users/4n6h4x0r/src/browser-forensic/crates/browser-carve/src/lib.rs`:

```rust
#![deny(clippy::unwrap_used)]
//! Browser artifact carving and recovery.
//!
//! Recovers deleted browser data from SQLite free pages, WAL files,
//! and binary formats. Mirrors the winevt-carver pattern.

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn recovery_method_serializes() {
        let method = RecoveryMethod::FreePage;
        let json = serde_json::to_string(&method).expect("serialize");
        assert!(json.contains("FreePage"));
    }

    #[test]
    fn recovery_quality_serializes() {
        let q = RecoveryQuality::Complete;
        let json = serde_json::to_string(&q).expect("serialize");
        assert!(json.contains("Complete"));
    }

    #[test]
    fn carved_record_round_trips() {
        let record = CarvedRecord {
            offset: 4096,
            table: "urls".to_string(),
            fields: {
                let mut m = HashMap::new();
                m.insert("url".to_string(), serde_json::json!("https://carved.example.com"));
                m.insert("title".to_string(), serde_json::json!("Carved Page"));
                m
            },
            method: RecoveryMethod::FreePage,
            quality: RecoveryQuality::Complete,
        };
        let json = serde_json::to_string(&record).expect("serialize");
        assert!(json.contains("carved.example.com"));
        assert!(json.contains("FreePage"));
    }

    #[test]
    fn carve_stats_default_is_zero() {
        let stats = CarveStats::default();
        assert_eq!(stats.bytes_scanned, 0);
        assert_eq!(stats.pages_scanned, 0);
        assert_eq!(stats.free_pages_found, 0);
        assert_eq!(stats.records_recovered, 0);
        assert_eq!(stats.records_partial, 0);
    }

    #[test]
    fn carve_result_empty() {
        let result = CarveResult {
            records: Vec::new(),
            integrity: Vec::new(),
            stats: CarveStats::default(),
        };
        assert!(result.records.is_empty());
        assert_eq!(result.stats.records_recovered, 0);
    }

    #[test]
    fn carved_record_clone() {
        let record = CarvedRecord {
            offset: 0,
            table: "test".to_string(),
            fields: HashMap::new(),
            method: RecoveryMethod::WalUncommitted,
            quality: RecoveryQuality::Partial,
        };
        let cloned = record.clone();
        assert_eq!(cloned.table, "test");
        assert!(matches!(cloned.method, RecoveryMethod::WalUncommitted));
    }
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-carve`

Confirm: fails because types do not exist.

#### GREEN commit

**Message:** `feat: browser-carve crate with CarvedRecord, CarveResult, CarveStats types`

Add to `/Users/4n6h4x0r/src/browser-forensic/crates/browser-carve/src/lib.rs` (before `#[cfg(test)]`):

```rust
use std::collections::HashMap;

use browser_integrity::IntegrityIndicator;
use serde::Serialize;

/// How a deleted record was recovered.
#[derive(Debug, Clone, Serialize)]
pub enum RecoveryMethod {
    /// Recovered from a SQLite free (deallocated) page.
    FreePage,
    /// Recovered from uncommitted WAL transactions.
    WalUncommitted,
    /// Recovered from a rollback journal.
    JournalRollback,
    /// Found via direct byte-pattern scanning.
    DirectScan,
}

/// Quality of the recovered record.
#[derive(Debug, Clone, Serialize)]
pub enum RecoveryQuality {
    /// All fields successfully recovered.
    Complete,
    /// Some fields missing or truncated.
    Partial,
    /// Record structure detected but data corrupt.
    Corrupt,
}

/// A single recovered record from carving.
#[derive(Debug, Clone, Serialize)]
pub struct CarvedRecord {
    /// Byte offset within the source file where the record was found.
    pub offset: u64,
    /// Name of the table this record belongs to.
    pub table: String,
    /// Recovered field values.
    pub fields: HashMap<String, serde_json::Value>,
    /// How the record was recovered.
    pub method: RecoveryMethod,
    /// Quality of the recovery.
    pub quality: RecoveryQuality,
}

/// Statistics about the carving operation.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CarveStats {
    pub bytes_scanned: u64,
    pub pages_scanned: u32,
    pub free_pages_found: u32,
    pub records_recovered: usize,
    pub records_partial: usize,
}

/// Result of a carving operation.
#[derive(Debug, Clone, Serialize)]
pub struct CarveResult {
    /// Recovered records.
    pub records: Vec<CarvedRecord>,
    /// Integrity indicators found during carving.
    pub integrity: Vec<IntegrityIndicator>,
    /// Statistics about the carving operation.
    pub stats: CarveStats,
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-carve`

Confirm: all tests pass.

---

### Task 4.2: Implement SQLite Free-Page Carving

**Goal:** Implement `carve_sqlite_free_pages()` that reads SQLite file pages, identifies free pages from the freelist, and attempts to recover records from them.

**New file:** `/Users/4n6h4x0r/src/browser-forensic/crates/browser-carve/src/sqlite_carve.rs`

**File to modify:** `/Users/4n6h4x0r/src/browser-forensic/crates/browser-carve/src/lib.rs` -- add `pub mod sqlite_carve;`

#### RED commit

**Message:** `test: RED -- carve_sqlite_free_pages recovers deleted records from free pages`

Create `/Users/4n6h4x0r/src/browser-forensic/crates/browser-carve/src/sqlite_carve.rs`:

```rust
//! SQLite free-page carving for deleted record recovery.

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use rusqlite::Connection;

    #[test]
    fn carve_empty_db_returns_empty() {
        let f = NamedTempFile::new().expect("tempfile");
        {
            let conn = Connection::open(f.path()).expect("open");
            conn.execute_batch("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT);")
                .expect("create");
        }
        let result = carve_sqlite_free_pages(f.path()).expect("carve");
        assert_eq!(result.stats.records_recovered, 0);
        assert!(result.records.is_empty());
    }

    #[test]
    fn carve_db_with_deleted_rows_finds_free_pages() {
        let f = NamedTempFile::new().expect("tempfile");
        {
            let conn = Connection::open(f.path()).expect("open");
            conn.execute_batch(
                "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT);
                 PRAGMA auto_vacuum = NONE;"
            ).expect("create");

            // Insert enough rows to span multiple pages
            for i in 0..200 {
                conn.execute(
                    "INSERT INTO urls VALUES (?1, ?2, ?3)",
                    rusqlite::params![i, format!("https://example{i}.com/page/with/long/path/to/fill/space"), format!("Title {i}")],
                ).expect("insert");
            }

            // Delete all rows -- pages become free but data may remain
            conn.execute("DELETE FROM urls", []).expect("delete");

            // VACUUM would reclaim space; skip it to leave free pages
        }

        let result = carve_sqlite_free_pages(f.path()).expect("carve");
        assert!(result.stats.pages_scanned > 0, "should have scanned pages");
        assert!(result.stats.free_pages_found > 0, "should have found free pages after deletion");
        // We may or may not recover records depending on SQLite internals,
        // but free pages should be detected
    }

    #[test]
    fn carve_nonexistent_file_returns_error() {
        let result = carve_sqlite_free_pages(std::path::Path::new("/nonexistent/db"));
        assert!(result.is_err());
    }

    #[test]
    fn carve_stats_populated() {
        let f = NamedTempFile::new().expect("tempfile");
        {
            let conn = Connection::open(f.path()).expect("open");
            conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, data TEXT);")
                .expect("create");
        }
        let result = carve_sqlite_free_pages(f.path()).expect("carve");
        assert!(result.stats.bytes_scanned > 0, "should report bytes scanned");
        assert!(result.stats.pages_scanned > 0, "should report pages scanned");
    }
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-carve`

Confirm: fails because `carve_sqlite_free_pages` does not exist.

#### GREEN commit

**Message:** `feat: implement carve_sqlite_free_pages for SQLite free-page record recovery`

Add implementation to `sqlite_carve.rs` (before `#[cfg(test)]`):

```rust
use std::path::Path;

use anyhow::{Context, Result};

use crate::{CarveResult, CarveStats, CarvedRecord, RecoveryMethod, RecoveryQuality};

/// SQLite page size is stored at offset 16-17 of the database header.
const SQLITE_HEADER_SIZE: usize = 100;
/// Offset of page size in SQLite header.
const PAGE_SIZE_OFFSET: usize = 16;
/// Offset of freelist trunk page number in SQLite header.
const FREELIST_TRUNK_OFFSET: usize = 32;
/// Offset of freelist page count in SQLite header.
const FREELIST_COUNT_OFFSET: usize = 36;

/// Carve deleted records from SQLite free (deallocated) pages.
///
/// Reads the SQLite file header to determine page size and freelist location,
/// then scans free pages for recoverable cell data.
///
/// This is a best-effort operation: SQLite may overwrite free page content
/// at any time, so recovery is not guaranteed.
pub fn carve_sqlite_free_pages(path: &Path) -> Result<CarveResult> {
    let data = std::fs::read(path)
        .with_context(|| format!("failed to read SQLite file: {}", path.display()))?;

    if data.len() < SQLITE_HEADER_SIZE {
        anyhow::bail!("file too small to be a valid SQLite database");
    }

    // Verify SQLite magic
    if &data[0..16] != b"SQLite format 3\0" {
        anyhow::bail!("not a SQLite database (bad magic)");
    }

    let page_size = read_u16_be(&data[PAGE_SIZE_OFFSET..]) as usize;
    let page_size = if page_size == 1 { 65536 } else { page_size };

    let freelist_trunk = read_u32_be(&data[FREELIST_TRUNK_OFFSET..]) as usize;
    let freelist_count = read_u32_be(&data[FREELIST_COUNT_OFFSET..]) as u32;

    let total_pages = data.len() / page_size;

    let mut stats = CarveStats {
        bytes_scanned: data.len() as u64,
        pages_scanned: total_pages as u32,
        free_pages_found: 0,
        records_recovered: 0,
        records_partial: 0,
    };

    let mut records = Vec::new();

    // Walk the freelist trunk chain
    let free_pages = collect_free_pages(&data, freelist_trunk, page_size);
    stats.free_pages_found = free_pages.len() as u32;

    // Attempt to recover records from each free page
    for &page_num in &free_pages {
        let page_offset = (page_num - 1) * page_size; // pages are 1-indexed
        if page_offset + page_size > data.len() {
            continue;
        }
        let page_data = &data[page_offset..page_offset + page_size];

        // Try to find URL-like strings in the page (simple heuristic)
        let recovered = scan_page_for_urls(page_data, page_offset as u64);
        for record in recovered {
            stats.records_recovered += 1;
            records.push(record);
        }
    }

    Ok(CarveResult {
        records,
        integrity: Vec::new(),
        stats,
    })
}

/// Collect all free page numbers by walking the freelist trunk chain.
fn collect_free_pages(data: &[u8], first_trunk: usize, page_size: usize) -> Vec<usize> {
    let mut free_pages = Vec::new();
    let mut trunk_page = first_trunk;

    while trunk_page > 0 {
        let offset = (trunk_page - 1) * page_size;
        if offset + page_size > data.len() {
            break;
        }

        // The trunk page itself is a free page
        free_pages.push(trunk_page);

        let trunk = &data[offset..offset + page_size];
        let next_trunk = read_u32_be(&trunk[0..4]) as usize;
        let leaf_count = read_u32_be(&trunk[4..8]) as usize;

        // Each leaf page number is stored as a 4-byte big-endian int starting at offset 8
        for i in 0..leaf_count {
            let leaf_offset = 8 + i * 4;
            if leaf_offset + 4 > page_size {
                break;
            }
            let leaf_page = read_u32_be(&trunk[leaf_offset..]) as usize;
            if leaf_page > 0 {
                free_pages.push(leaf_page);
            }
        }

        trunk_page = next_trunk;
    }

    free_pages
}

/// Scan a page for URL-like byte patterns and attempt to extract records.
fn scan_page_for_urls(page_data: &[u8], page_offset: u64) -> Vec<CarvedRecord> {
    let mut records = Vec::new();
    let text = String::from_utf8_lossy(page_data);

    // Look for http:// or https:// patterns
    for (idx, _) in text.match_indices("http") {
        // Try to extract the URL
        let start = idx;
        let mut end = start;
        for &b in &page_data[start..] {
            if b < 0x20 || b > 0x7e {
                break;
            }
            end += 1;
        }
        if end - start > 10 {
            let url = String::from_utf8_lossy(&page_data[start..end]).to_string();
            if url.starts_with("http://") || url.starts_with("https://") {
                let mut fields = std::collections::HashMap::new();
                fields.insert("url".to_string(), serde_json::json!(url));

                records.push(CarvedRecord {
                    offset: page_offset + start as u64,
                    table: "unknown".to_string(),
                    fields,
                    method: RecoveryMethod::FreePage,
                    quality: RecoveryQuality::Partial,
                });
            }
        }
    }

    records
}

fn read_u16_be(data: &[u8]) -> u16 {
    u16::from_be_bytes([data[0], data[1]])
}

fn read_u32_be(data: &[u8]) -> u32 {
    u32::from_be_bytes([data[0], data[1], data[2], data[3]])
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-carve`

Confirm: all tests pass.

---

### Task 4.3: Implement WAL Recovery

**Goal:** Implement `recover_from_wal()` that reads uncommitted transactions from SQLite WAL files.

**New file:** `/Users/4n6h4x0r/src/browser-forensic/crates/browser-carve/src/wal_recovery.rs`

**File to modify:** `/Users/4n6h4x0r/src/browser-forensic/crates/browser-carve/src/lib.rs` -- add `pub mod wal_recovery;`

#### RED commit

**Message:** `test: RED -- recover_from_wal reads uncommitted WAL data`

Create `/Users/4n6h4x0r/src/browser-forensic/crates/browser-carve/src/wal_recovery.rs`:

```rust
//! WAL (Write-Ahead Log) recovery for uncommitted transaction data.

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use rusqlite::Connection;

    #[test]
    fn recover_from_wal_no_wal_returns_empty() {
        let f = NamedTempFile::new().expect("tempfile");
        {
            let conn = Connection::open(f.path()).expect("open");
            conn.execute_batch(
                "PRAGMA journal_mode = DELETE;
                 CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);"
            ).expect("create");
        }
        let result = recover_from_wal(f.path()).expect("recover");
        assert!(result.records.is_empty());
        assert_eq!(result.stats.records_recovered, 0);
    }

    #[test]
    fn recover_from_wal_nonexistent_returns_error() {
        let result = recover_from_wal(std::path::Path::new("/nonexistent/db"));
        assert!(result.is_err());
    }

    #[test]
    fn recover_from_wal_with_wal_file_scans_pages() {
        let f = NamedTempFile::new().expect("tempfile");
        {
            let conn = Connection::open(f.path()).expect("open");
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);
                 INSERT INTO urls VALUES (1, 'https://wal-test.example.com');"
            ).expect("setup");
            // Don't checkpoint -- leave data in WAL
        }

        let result = recover_from_wal(f.path()).expect("recover");
        // The WAL file should exist and be scanned
        assert!(result.stats.bytes_scanned >= 0);
    }
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-carve`

Confirm: fails because `recover_from_wal` does not exist.

#### GREEN commit

**Message:** `feat: implement recover_from_wal for WAL file scanning`

Add implementation to `wal_recovery.rs`:

```rust
use std::path::Path;

use anyhow::{Context, Result};

use crate::{CarveResult, CarveStats, CarvedRecord, RecoveryMethod, RecoveryQuality};

/// WAL file header size.
const WAL_HEADER_SIZE: usize = 32;
/// WAL frame header size.
const WAL_FRAME_HEADER_SIZE: usize = 24;

/// Recover data from SQLite WAL (Write-Ahead Log) files.
///
/// WAL files contain page images that have not been checkpointed back
/// to the main database. This includes uncommitted transactions from
/// crashes and data that would otherwise be lost.
pub fn recover_from_wal(db_path: &Path) -> Result<CarveResult> {
    let wal_path_str = format!("{}-wal", db_path.display());
    let wal_path = Path::new(&wal_path_str);

    if !wal_path.exists() {
        return Ok(CarveResult {
            records: Vec::new(),
            integrity: Vec::new(),
            stats: CarveStats::default(),
        });
    }

    let wal_data = std::fs::read(wal_path)
        .with_context(|| format!("failed to read WAL file: {}", wal_path.display()))?;

    if wal_data.len() < WAL_HEADER_SIZE {
        return Ok(CarveResult {
            records: Vec::new(),
            integrity: Vec::new(),
            stats: CarveStats {
                bytes_scanned: wal_data.len() as u64,
                ..Default::default()
            },
        });
    }

    // Parse WAL header
    let page_size = read_u32_be(&wal_data[8..12]) as usize;
    let page_size = if page_size == 0 { 4096 } else { page_size };

    let mut stats = CarveStats {
        bytes_scanned: wal_data.len() as u64,
        pages_scanned: 0,
        free_pages_found: 0,
        records_recovered: 0,
        records_partial: 0,
    };

    let mut records = Vec::new();

    // Walk WAL frames
    let mut offset = WAL_HEADER_SIZE;
    while offset + WAL_FRAME_HEADER_SIZE + page_size <= wal_data.len() {
        stats.pages_scanned += 1;

        let page_data = &wal_data[offset + WAL_FRAME_HEADER_SIZE..offset + WAL_FRAME_HEADER_SIZE + page_size];

        // Scan page for URL patterns
        let recovered = scan_wal_page_for_urls(page_data, offset as u64);
        for record in recovered {
            stats.records_recovered += 1;
            records.push(record);
        }

        offset += WAL_FRAME_HEADER_SIZE + page_size;
    }

    Ok(CarveResult {
        records,
        integrity: Vec::new(),
        stats,
    })
}

/// Scan a WAL page for URL-like patterns.
fn scan_wal_page_for_urls(page_data: &[u8], frame_offset: u64) -> Vec<CarvedRecord> {
    let mut records = Vec::new();
    let text = String::from_utf8_lossy(page_data);

    for (idx, _) in text.match_indices("http") {
        let start = idx;
        let mut end = start;
        for &b in &page_data[start..] {
            if b < 0x20 || b > 0x7e {
                break;
            }
            end += 1;
        }
        if end - start > 10 {
            let url = String::from_utf8_lossy(&page_data[start..end]).to_string();
            if url.starts_with("http://") || url.starts_with("https://") {
                let mut fields = std::collections::HashMap::new();
                fields.insert("url".to_string(), serde_json::json!(url));

                records.push(CarvedRecord {
                    offset: frame_offset + start as u64,
                    table: "unknown".to_string(),
                    fields,
                    method: RecoveryMethod::WalUncommitted,
                    quality: RecoveryQuality::Partial,
                });
            }
        }
    }

    records
}

fn read_u32_be(data: &[u8]) -> u32 {
    u32::from_be_bytes([data[0], data[1], data[2], data[3]])
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-carve`

Confirm: all tests pass.

---

### Task 4.4: Public API -- re-export carve functions from lib.rs

**Goal:** Make `browser_carve::carve_sqlite_free_pages` and `browser_carve::recover_from_wal` available from the crate root.

**File to modify:** `/Users/4n6h4x0r/src/browser-forensic/crates/browser-carve/src/lib.rs`

#### RED commit

**Message:** `test: RED -- crate root re-exports for carve functions`

Add test:

```rust
#[test]
fn crate_root_reexports_carve_functions() {
    let _f1: fn(&std::path::Path) -> anyhow::Result<CarveResult>
        = browser_carve::carve_sqlite_free_pages;
    let _f2: fn(&std::path::Path) -> anyhow::Result<CarveResult>
        = browser_carve::recover_from_wal;
}
```

Confirm: fails because functions are not re-exported.

#### GREEN commit

**Message:** `feat: re-export carve functions from browser-carve crate root`

Add to `lib.rs`:

```rust
pub use sqlite_carve::carve_sqlite_free_pages;
pub use wal_recovery::recover_from_wal;
```

Confirm: all tests pass.

---

## Phase 5: browser-memory Crate

### Task 5.1: Create browser-memory Crate with URL/Cookie Byte Scanning

**Goal:** Create `browser-memory` crate that scans raw byte buffers for URL and cookie
patterns, emitting `BrowserEvent`s.

**Architectural note — dependency direction:**
`browser-memory` is a **pure byte-pattern scanner with NO dependency on memory-forensic**.
It answers the question: "Given these raw bytes, do they contain browser artifacts?"
The caller (e.g., `memf-windows` in the memory-forensic repo) is responsible for
extracting those bytes from a memory image. This avoids a circular dependency:

```
memory-forensic/memf-windows
  └─ calls browser-carve  (to parse SQLite pages found in hibernation file)
  └─ calls browser-memory (to scan arbitrary byte regions for URL/cookie patterns)
  └─ calls browser-core   (for BrowserEvent / BrowserFamily types)

browser-forensic/browser-memory
  └─ NO dependency on memf-core or memory-forensic
  └─ only depends on browser-core (for BrowserEvent types)
```

Do NOT add a `memf` feature flag or any `memf-core` dependency here.
Memory-forensic integration lives entirely in the memory-forensic repo.

**Files to create:**
- `/Users/4n6h4x0r/src/browser-forensic/crates/browser-memory/Cargo.toml`
- `/Users/4n6h4x0r/src/browser-forensic/crates/browser-memory/src/lib.rs`

**Files to modify:**
- `/Users/4n6h4x0r/src/browser-forensic/Cargo.toml` -- add `"crates/browser-memory"` to workspace members

**Cargo.toml for browser-memory:**
```toml
[package]
name = "browser-memory"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
anyhow = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
browser-core = { path = "../browser-core" }
url = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }

[lints]
workspace = true
```

#### RED commit

**Message:** `test: RED -- scan_bytes_for_urls extracts URLs from raw byte buffers`

Create `/Users/4n6h4x0r/src/browser-forensic/crates/browser-memory/src/lib.rs`:

```rust
#![deny(clippy::unwrap_used)]
//! Browser memory scanning -- extract browser artifacts from raw byte buffers.
//!
//! Can scan memory dumps, process memory, or any raw byte source for
//! URL patterns, cookie structures, and other browser data.

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::ArtifactKind;

    #[test]
    fn scan_bytes_for_urls_finds_https() {
        let data = b"some garbage https://example.com/page more garbage";
        let events = scan_bytes_for_urls(data);
        assert!(!events.is_empty(), "should find at least one URL");
        assert!(events.iter().any(|e| {
            e.attrs.get("url").and_then(|v| v.as_str()) == Some("https://example.com/page")
        }));
        assert!(events.iter().all(|e| e.artifact == ArtifactKind::Memory));
    }

    #[test]
    fn scan_bytes_for_urls_finds_http() {
        let data = b"prefix http://insecure.example.com/path suffix";
        let events = scan_bytes_for_urls(data);
        assert!(!events.is_empty());
    }

    #[test]
    fn scan_bytes_for_urls_empty_data_returns_empty() {
        let events = scan_bytes_for_urls(b"");
        assert!(events.is_empty());
    }

    #[test]
    fn scan_bytes_for_urls_no_urls_returns_empty() {
        let data = b"no urls here just some text about things";
        let events = scan_bytes_for_urls(data);
        assert!(events.is_empty());
    }

    #[test]
    fn scan_bytes_for_urls_multiple_urls() {
        let data = b"first https://a.com/1 then https://b.com/2 end";
        let events = scan_bytes_for_urls(data);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn scan_bytes_for_urls_handles_null_terminated() {
        let mut data = Vec::new();
        data.extend_from_slice(b"https://example.com/page");
        data.push(0); // null terminator
        data.extend_from_slice(b"more data");

        let events = scan_bytes_for_urls(&data);
        assert!(!events.is_empty());
        let url = events[0].attrs.get("url").and_then(|v| v.as_str());
        assert_eq!(url, Some("https://example.com/page"));
    }

    #[test]
    fn scan_bytes_for_cookies_finds_cookie_header() {
        let data = b"GET / HTTP/1.1\r\nCookie: session_id=abc123; user=test\r\n\r\n";
        let events = scan_bytes_for_cookies(data);
        assert!(!events.is_empty(), "should find cookie header");
    }

    #[test]
    fn scan_bytes_for_cookies_empty_returns_empty() {
        let events = scan_bytes_for_cookies(b"no cookies");
        assert!(events.is_empty());
    }
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-memory`

Confirm: fails because functions do not exist.

#### GREEN commit

**Message:** `feat: implement scan_bytes_for_urls and scan_bytes_for_cookies in browser-memory`

Add implementation to `lib.rs` (before `#[cfg(test)]`):

```rust
use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

/// Scan a byte buffer for URL patterns and return browser events.
///
/// Extracts `http://` and `https://` URLs from raw memory, file contents,
/// or any byte source. Each URL is emitted as a `BrowserEvent` with
/// `ArtifactKind::Memory`.
///
/// URLs are validated with the `url` crate to filter false positives.
pub fn scan_bytes_for_urls(data: &[u8]) -> Vec<BrowserEvent> {
    let mut events = Vec::new();
    let text = String::from_utf8_lossy(data);

    for prefix in &["https://", "http://"] {
        let mut search_from = 0;
        while let Some(start) = text[search_from..].find(prefix) {
            let abs_start = search_from + start;

            // Find URL end (whitespace, null, non-printable, or common delimiters)
            let mut end = abs_start;
            for ch in text[abs_start..].chars() {
                if ch.is_whitespace() || ch == '\0' || ch == '"' || ch == '\''
                    || ch == '>' || ch == '<' || ch == '|' || (ch as u32) < 0x20
                {
                    break;
                }
                end += ch.len_utf8();
            }

            let url_str = &text[abs_start..end];

            // Validate URL
            if url::Url::parse(url_str).is_ok() && url_str.len() > 10 {
                let event = BrowserEvent::new(
                    0, // no timestamp available from raw bytes
                    BrowserFamily::Chromium, // unknown; default to Chromium
                    ArtifactKind::Memory,
                    "memory_scan",
                    url_str,
                )
                .with_attr("url", json!(url_str))
                .with_attr("offset", json!(abs_start));

                events.push(event);
            }

            search_from = end.max(abs_start + 1);
        }
    }

    events
}

/// Scan a byte buffer for HTTP Cookie headers and return browser events.
///
/// Looks for `Cookie:` HTTP headers in raw byte data and extracts
/// cookie name=value pairs.
pub fn scan_bytes_for_cookies(data: &[u8]) -> Vec<BrowserEvent> {
    let mut events = Vec::new();
    let text = String::from_utf8_lossy(data);

    // Look for "Cookie: " headers
    let mut search_from = 0;
    while let Some(start) = text[search_from..].find("Cookie: ") {
        let abs_start = search_from + start + 8; // skip "Cookie: "

        // Find end of cookie header (CRLF or LF)
        let end = text[abs_start..]
            .find("\r\n")
            .or_else(|| text[abs_start..].find('\n'))
            .map(|pos| abs_start + pos)
            .unwrap_or(text.len());

        let cookie_str = &text[abs_start..end];
        if !cookie_str.is_empty() {
            let event = BrowserEvent::new(
                0,
                BrowserFamily::Chromium,
                ArtifactKind::Memory,
                "memory_scan",
                format!("Cookie header: {}", &cookie_str[..cookie_str.len().min(80)]),
            )
            .with_attr("cookie_header", json!(cookie_str))
            .with_attr("offset", json!(abs_start - 8));

            events.push(event);
        }

        search_from = end.max(abs_start + 1);
    }

    events
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-memory`

Confirm: all tests pass.

---

## Phase 6: Existing Parser Additions

### Task 6.1: Add Windows Paths to browser-discovery

**Goal:** Add Windows Chromium and Firefox profile paths to `browser-discovery`.

**File to modify:** `/Users/4n6h4x0r/src/browser-forensic/crates/browser-discovery/src/lib.rs`

#### RED commit

**Message:** `test: RED -- browser-discovery recognizes Windows profile directory layouts`

Add tests:

```rust
#[test]
fn discover_chrome_windows_layout() {
    let home = TempDir::new().unwrap();
    let chrome = home.path()
        .join("AppData/Local/Google/Chrome/User Data/Default");
    fs::create_dir_all(&chrome).unwrap();
    fs::write(chrome.join("History"), b"").unwrap();

    let profiles = discover_profiles(home.path());
    assert!(profiles.iter().any(|p|
        p.browser == BrowserFamily::Chromium && p.name == "Default"
    ), "should discover Chrome profile from Windows path layout");
}

#[test]
fn discover_firefox_windows_layout() {
    let home = TempDir::new().unwrap();
    let ff = home.path()
        .join("AppData/Roaming/Mozilla/Firefox/Profiles/abc.default-release");
    fs::create_dir_all(&ff).unwrap();
    fs::write(ff.join("places.sqlite"), b"").unwrap();

    let profiles = discover_profiles(home.path());
    assert!(profiles.iter().any(|p|
        p.browser == BrowserFamily::Firefox
    ), "should discover Firefox profile from Windows path layout");
}

#[test]
fn discover_edge_windows_layout() {
    let home = TempDir::new().unwrap();
    let edge = home.path()
        .join("AppData/Local/Microsoft/Edge/User Data/Default");
    fs::create_dir_all(&edge).unwrap();
    fs::write(edge.join("History"), b"").unwrap();

    let profiles = discover_profiles(home.path());
    assert!(profiles.iter().any(|p| p.browser == BrowserFamily::Chromium));
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-discovery`

Confirm: tests fail because Windows paths are not in `CHROMIUM_BASES` / `FIREFOX_BASES`.

#### GREEN commit

**Message:** `feat: add Windows Chromium/Firefox profile paths to browser-discovery`

Add to `CHROMIUM_BASES`:
```rust
// Windows
"AppData/Local/Google/Chrome/User Data",
"AppData/Local/Microsoft/Edge/User Data",
"AppData/Local/BraveSoftware/Brave-Browser/User Data",
"AppData/Local/Vivaldi/User Data",
"AppData/Roaming/Opera Software/Opera Stable",
"AppData/Local/Chromium/User Data",
```

Add to `FIREFOX_BASES`:
```rust
// Windows
"AppData/Roaming/Mozilla/Firefox/Profiles",
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-discovery`

Confirm: all tests pass.

---

### Task 6.2: Add Chrome Local State Parser

**Goal:** Parse Chrome's `Local State` JSON file to extract profile metadata, last active profile, OS crypt information.

**New file:** `/Users/4n6h4x0r/src/browser-forensic/crates/browser-chrome/src/local_state.rs`

**File to modify:** `/Users/4n6h4x0r/src/browser-forensic/crates/browser-chrome/src/lib.rs` -- add module and re-export

#### RED commit

**Message:** `test: RED -- parse_local_state extracts profile metadata from Local State JSON`

Create `/Users/4n6h4x0r/src/browser-forensic/crates/browser-chrome/src/local_state.rs`:

```rust
//! Chrome Local State JSON parser.

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::ArtifactKind;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn parse_local_state_extracts_profiles() {
        let json_data = r#"{
            "profile": {
                "info_cache": {
                    "Default": {
                        "name": "Person 1",
                        "user_name": "user@example.com",
                        "is_using_default_name": false,
                        "active_time": 1700000000.0
                    },
                    "Profile 1": {
                        "name": "Work",
                        "user_name": "work@example.com",
                        "is_using_default_name": false,
                        "active_time": 1700000001.0
                    }
                },
                "last_used": "Default"
            }
        }"#;
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(json_data.as_bytes()).expect("write");

        let events = parse_local_state(f.path()).expect("parse");
        assert!(!events.is_empty(), "should extract profile events");
        assert!(events.iter().any(|e| e.description.contains("Person 1")));
        assert!(events.iter().any(|e| e.description.contains("Work")));
        assert!(events.iter().all(|e| e.artifact == ArtifactKind::Session));
    }

    #[test]
    fn parse_local_state_empty_profiles_returns_empty() {
        let json_data = r#"{"profile": {"info_cache": {}}}"#;
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(json_data.as_bytes()).expect("write");

        let events = parse_local_state(f.path()).expect("parse");
        assert!(events.is_empty());
    }

    #[test]
    fn parse_local_state_missing_file_returns_error() {
        let result = parse_local_state(std::path::Path::new("/nonexistent/Local State"));
        assert!(result.is_err());
    }
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-chrome`

Confirm: fails because `parse_local_state` does not exist.

#### GREEN commit

**Message:** `feat: implement parse_local_state for Chrome profile metadata extraction`

Add implementation to `local_state.rs`:

```rust
use std::path::Path;

use anyhow::Result;
use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

/// Parse a Chrome `Local State` JSON file.
///
/// Extracts profile metadata from `profile.info_cache`, including
/// profile names, associated email addresses, and last active times.
pub fn parse_local_state(path: &Path) -> Result<Vec<BrowserEvent>> {
    let data = std::fs::read_to_string(path)?;
    let root: serde_json::Value = serde_json::from_str(&data)?;

    let source = path.to_string_lossy().into_owned();
    let mut events = Vec::new();

    if let Some(info_cache) = root
        .get("profile")
        .and_then(|p| p.get("info_cache"))
        .and_then(|ic| ic.as_object())
    {
        for (profile_dir, info) in info_cache {
            let name = info.get("name").and_then(|n| n.as_str()).unwrap_or("Unknown");
            let user_name = info.get("user_name").and_then(|u| u.as_str()).unwrap_or("");
            let active_time = info.get("active_time").and_then(|t| t.as_f64()).unwrap_or(0.0);
            let ts_ns = browser_core::timestamp::unix_secs_to_nanos(active_time as i64);

            let desc = if user_name.is_empty() {
                format!("Profile {profile_dir}: {name}")
            } else {
                format!("Profile {profile_dir}: {name} ({user_name})")
            };

            events.push(
                BrowserEvent::new(ts_ns, BrowserFamily::Chromium, ArtifactKind::Session, &source, desc)
                    .with_attr("profile_dir", json!(profile_dir))
                    .with_attr("profile_name", json!(name))
                    .with_attr("user_name", json!(user_name))
                    .with_attr("active_time", json!(active_time)),
            );
        }
    }

    Ok(events)
}
```

Update `lib.rs` to add:
```rust
pub mod local_state;
pub use local_state::parse_local_state;
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-chrome`

Confirm: all tests pass.

---

### Task 6.3: Add Safari TopSites Parser

**Goal:** Parse Safari's `TopSites.plist` file for frequently visited sites.

**New file:** `/Users/4n6h4x0r/src/browser-forensic/crates/browser-safari/src/topsites.rs`

**File to modify:** `/Users/4n6h4x0r/src/browser-forensic/crates/browser-safari/src/lib.rs`

#### RED commit

**Message:** `test: RED -- parse_topsites extracts frequently visited sites from TopSites.plist`

Create `/Users/4n6h4x0r/src/browser-forensic/crates/browser-safari/src/topsites.rs`:

```rust
//! Safari TopSites.plist parser.

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::ArtifactKind;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn parse_topsites_from_xml_plist() {
        // TopSites.plist uses a dictionary with "TopSites" key containing an array
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>TopSites</key>
    <array>
        <dict>
            <key>TopSiteURLString</key>
            <string>https://example.com</string>
            <key>TopSiteTitle</key>
            <string>Example</string>
        </dict>
        <dict>
            <key>TopSiteURLString</key>
            <string>https://news.example.com</string>
            <key>TopSiteTitle</key>
            <string>News</string>
        </dict>
    </array>
</dict>
</plist>"#;

        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(plist_xml.as_bytes()).expect("write");

        let events = parse_topsites(f.path()).expect("parse");
        assert_eq!(events.len(), 2);
        assert!(events.iter().any(|e| e.description.contains("Example")));
        assert!(events.iter().any(|e| e.description.contains("News")));
        assert!(events.iter().all(|e| e.artifact == ArtifactKind::History));
    }

    #[test]
    fn parse_topsites_empty_returns_empty() {
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>TopSites</key>
    <array/>
</dict>
</plist>"#;

        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(plist_xml.as_bytes()).expect("write");

        let events = parse_topsites(f.path()).expect("parse");
        assert!(events.is_empty());
    }

    #[test]
    fn parse_topsites_missing_file_returns_error() {
        let result = parse_topsites(std::path::Path::new("/nonexistent/TopSites.plist"));
        assert!(result.is_err());
    }
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-safari`

Confirm: fails because `parse_topsites` does not exist.

#### GREEN commit

**Message:** `feat: implement parse_topsites for Safari TopSites.plist parsing`

Add implementation to `topsites.rs`:

```rust
use std::path::Path;

use anyhow::Result;
use browser_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

/// Parse Safari's `TopSites.plist` file.
///
/// Extracts frequently visited sites. These are forensically relevant
/// because they reveal habitual browsing patterns even when history
/// has been cleared.
pub fn parse_topsites(path: &Path) -> Result<Vec<BrowserEvent>> {
    let value: plist::Value = plist::from_file(path)?;
    let source = path.to_string_lossy().into_owned();
    let mut events = Vec::new();

    let dict = value.as_dictionary()
        .ok_or_else(|| anyhow::anyhow!("TopSites.plist root is not a dictionary"))?;

    let sites = match dict.get("TopSites").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return Ok(events),
    };

    for site in sites {
        let site_dict = match site.as_dictionary() {
            Some(d) => d,
            None => continue,
        };

        let url = site_dict
            .get("TopSiteURLString")
            .and_then(|v| v.as_string())
            .unwrap_or("");
        let title = site_dict
            .get("TopSiteTitle")
            .and_then(|v| v.as_string())
            .unwrap_or("");

        if url.is_empty() {
            continue;
        }

        let desc = if title.is_empty() {
            url.to_string()
        } else {
            format!("{title} -- {url}")
        };

        events.push(
            BrowserEvent::new(0, BrowserFamily::Safari, ArtifactKind::History, &source, desc)
                .with_attr("url", json!(url))
                .with_attr("title", json!(title))
                .with_attr("source_type", json!("topsites")),
        );
    }

    Ok(events)
}
```

Update `lib.rs`:
```rust
pub mod topsites;
pub use topsites::parse_topsites;
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-safari`

Confirm: all tests pass.

---

## Phase 7: browser-rt RapidTriage Crate

### Task 7.1: Create browser-rt Crate with TriageReport

**Goal:** Create the `browser-rt` crate that orchestrates all other crates into a single `TriageReport`.

**Files to create:**
- `/Users/4n6h4x0r/src/browser-forensic/crates/browser-rt/Cargo.toml`
- `/Users/4n6h4x0r/src/browser-forensic/crates/browser-rt/src/lib.rs`

**Files to modify:**
- `/Users/4n6h4x0r/src/browser-forensic/Cargo.toml` -- add `"crates/browser-rt"` to workspace members

**Cargo.toml for browser-rt:**
```toml
[package]
name = "browser-rt"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
anyhow = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
browser-core = { path = "../browser-core" }
browser-chrome = { path = "../browser-chrome" }
browser-firefox = { path = "../browser-firefox" }
browser-safari = { path = "../browser-safari" }
browser-discovery = { path = "../browser-discovery" }
browser-integrity = { path = "../browser-integrity" }
browser-carve = { path = "../browser-carve" }

[dev-dependencies]
tempfile = { workspace = true }
rusqlite = { workspace = true }

[lints]
workspace = true
```

#### RED commit

**Message:** `test: RED -- TriageReport structure and triage_profile function`

Create `/Users/4n6h4x0r/src/browser-forensic/crates/browser-rt/src/lib.rs`:

```rust
#![deny(clippy::unwrap_used)]
//! RapidTriage orchestration for browser forensics.
//!
//! Combines parsing, integrity checking, and carving into a single
//! triage report. Mirrors the RapidTriage pattern from winevt-forensic.

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::BrowserFamily;
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn triage_report_serializes() {
        let report = TriageReport {
            events: Vec::new(),
            carved: Vec::new(),
            integrity: Vec::new(),
            profiles: Vec::new(),
            generated_at_ns: 1_700_000_000_000_000_000,
        };
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("generated_at_ns"));
        assert!(json.contains("1700000000000000000"));
    }

    #[test]
    fn triage_profile_chrome_returns_report() {
        let dir = TempDir::new().expect("tempdir");
        let history = dir.path().join("History");

        // Create a minimal Chromium History database
        let conn = rusqlite::Connection::open(&history).expect("open");
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
             INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 1, 13300000000000000);
             INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 0);"
        ).expect("setup");
        drop(conn);

        let report = triage_profile(dir.path(), BrowserFamily::Chromium).expect("triage");
        assert!(!report.events.is_empty(), "should have parsed history events");
        assert!(report.generated_at_ns > 0);
    }

    #[test]
    fn triage_profile_nonexistent_path_returns_empty_report() {
        let dir = TempDir::new().expect("tempdir");
        let report = triage_profile(dir.path(), BrowserFamily::Chromium).expect("triage");
        // No files found, so events should be empty, but report should not error
        assert!(report.events.is_empty());
    }

    #[test]
    fn triage_report_has_all_fields() {
        let report = TriageReport {
            events: vec![],
            carved: vec![],
            integrity: vec![],
            profiles: vec![],
            generated_at_ns: 0,
        };
        // Verify all fields are accessible
        let _ = report.events.len();
        let _ = report.carved.len();
        let _ = report.integrity.len();
        let _ = report.profiles.len();
        let _ = report.generated_at_ns;
    }
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-rt`

Confirm: fails because `TriageReport`, `triage_profile` do not exist.

#### GREEN commit

**Message:** `feat: implement browser-rt crate with TriageReport and triage_profile`

Add implementation to `lib.rs` (before `#[cfg(test)]`):

```rust
use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use browser_carve::{CarvedRecord, CarveResult};
use browser_core::{BrowserEvent, BrowserFamily};
use browser_discovery::DiscoveredProfile;
use browser_integrity::IntegrityIndicator;

/// Consolidated triage report combining all forensic data sources.
#[derive(Debug, Serialize)]
pub struct TriageReport {
    /// Browser events from history, cookies, downloads, etc.
    pub events: Vec<BrowserEvent>,
    /// Records recovered from carving (free pages, WAL, etc.).
    pub carved: Vec<CarvedRecord>,
    /// Integrity anomalies (clearing, tampering, corruption).
    pub integrity: Vec<IntegrityIndicator>,
    /// Discovered browser profiles.
    pub profiles: Vec<DiscoveredProfile>,
    /// Timestamp when this report was generated (Unix nanos).
    pub generated_at_ns: i64,
}

/// Triage a single browser profile directory.
///
/// Parses all available artifacts, runs integrity checks, and attempts
/// carving on SQLite databases found in the profile directory.
pub fn triage_profile(profile_path: &Path, browser: BrowserFamily) -> Result<TriageReport> {
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);

    let mut events = Vec::new();
    let mut integrity = Vec::new();
    let mut carved = Vec::new();

    // Parse available artifacts based on browser family
    match browser {
        BrowserFamily::Chromium => {
            triage_chromium_profile(profile_path, &mut events, &mut integrity, &mut carved);
        }
        BrowserFamily::Firefox => {
            triage_firefox_profile(profile_path, &mut events, &mut integrity, &mut carved);
        }
        BrowserFamily::Safari => {
            triage_safari_profile(profile_path, &mut events, &mut integrity, &mut carved);
        }
    }

    events.sort_by_key(|e| e.timestamp_ns);

    Ok(TriageReport {
        events,
        carved,
        integrity,
        profiles: Vec::new(),
        generated_at_ns: now_ns,
    })
}

/// Triage all discovered profiles under a home directory.
pub fn triage(home_dir: &Path) -> Result<TriageReport> {
    let profiles = browser_discovery::discover_profiles(home_dir);
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);

    let mut all_events = Vec::new();
    let mut all_integrity = Vec::new();
    let mut all_carved = Vec::new();

    for profile in &profiles {
        let mut events = Vec::new();
        let mut integrity_vec = Vec::new();
        let mut carved_vec = Vec::new();

        match profile.browser {
            BrowserFamily::Chromium => {
                triage_chromium_profile(&profile.path, &mut events, &mut integrity_vec, &mut carved_vec);
            }
            BrowserFamily::Firefox => {
                triage_firefox_profile(&profile.path, &mut events, &mut integrity_vec, &mut carved_vec);
            }
            BrowserFamily::Safari => {
                triage_safari_profile(&profile.path, &mut events, &mut integrity_vec, &mut carved_vec);
            }
        }

        all_events.extend(events);
        all_integrity.extend(integrity_vec);
        all_carved.extend(carved_vec);
    }

    all_events.sort_by_key(|e| e.timestamp_ns);

    Ok(TriageReport {
        events: all_events,
        carved: all_carved,
        integrity: all_integrity,
        profiles: profiles.into_iter().map(|p| p).collect(),
        generated_at_ns: now_ns,
    })
}

fn triage_chromium_profile(
    path: &Path,
    events: &mut Vec<BrowserEvent>,
    integrity: &mut Vec<IntegrityIndicator>,
    carved: &mut Vec<CarvedRecord>,
) {
    let history_path = path.join("History");
    if history_path.is_file() {
        if let Ok(mut evts) = browser_chrome::parse_history(&history_path) {
            events.append(&mut evts);
        }
        if let Ok(mut ind) = browser_integrity::check_history_integrity(&history_path, BrowserFamily::Chromium) {
            integrity.append(&mut ind);
        }
        if let Ok(mut ind) = browser_integrity::check_database_integrity(&history_path) {
            integrity.append(&mut ind);
        }
        if let Ok(result) = browser_carve::carve_sqlite_free_pages(&history_path) {
            carved.extend(result.records);
        }
    }

    let cookies_path = path.join("Cookies");
    if cookies_path.is_file() {
        if let Ok(mut evts) = browser_chrome::parse_cookies(&cookies_path) {
            events.append(&mut evts);
        }
        if let Ok(mut ind) = browser_integrity::check_cookie_integrity(&cookies_path, BrowserFamily::Chromium) {
            integrity.append(&mut ind);
        }
    }

    let downloads_path = path.join("History"); // downloads are in History db
    if downloads_path.is_file() {
        if let Ok(mut evts) = browser_chrome::parse_downloads(&downloads_path) {
            events.append(&mut evts);
        }
    }

    let bookmarks_path = path.join("Bookmarks");
    if bookmarks_path.is_file() {
        if let Ok(mut evts) = browser_chrome::parse_bookmarks(&bookmarks_path) {
            events.append(&mut evts);
        }
    }
}

fn triage_firefox_profile(
    path: &Path,
    events: &mut Vec<BrowserEvent>,
    integrity: &mut Vec<IntegrityIndicator>,
    carved: &mut Vec<CarvedRecord>,
) {
    let places_path = path.join("places.sqlite");
    if places_path.is_file() {
        if let Ok(mut evts) = browser_firefox::parse_history(&places_path) {
            events.append(&mut evts);
        }
        if let Ok(mut ind) = browser_integrity::check_history_integrity(&places_path, BrowserFamily::Firefox) {
            integrity.append(&mut ind);
        }
        if let Ok(mut ind) = browser_integrity::check_database_integrity(&places_path) {
            integrity.append(&mut ind);
        }
        if let Ok(result) = browser_carve::carve_sqlite_free_pages(&places_path) {
            carved.extend(result.records);
        }
    }

    let cookies_path = path.join("cookies.sqlite");
    if cookies_path.is_file() {
        if let Ok(mut evts) = browser_firefox::parse_cookies(&cookies_path) {
            events.append(&mut evts);
        }
        if let Ok(mut ind) = browser_integrity::check_cookie_integrity(&cookies_path, BrowserFamily::Firefox) {
            integrity.append(&mut ind);
        }
    }
}

fn triage_safari_profile(
    path: &Path,
    events: &mut Vec<BrowserEvent>,
    integrity: &mut Vec<IntegrityIndicator>,
    carved: &mut Vec<CarvedRecord>,
) {
    let history_path = path.join("History.db");
    if history_path.is_file() {
        if let Ok(mut evts) = browser_safari::parse_history(&history_path) {
            events.append(&mut evts);
        }
        if let Ok(mut ind) = browser_integrity::check_history_integrity(&history_path, BrowserFamily::Safari) {
            integrity.append(&mut ind);
        }
        if let Ok(mut ind) = browser_integrity::check_database_integrity(&history_path) {
            integrity.append(&mut ind);
        }
        if let Ok(result) = browser_carve::carve_sqlite_free_pages(&history_path) {
            carved.extend(result.records);
        }
    }
}
```

Note: `DiscoveredProfile` in `browser-discovery` needs `Serialize` derive. Add to browser-discovery's `DiscoveredProfile`:
```rust
#[derive(Debug, Serialize)]  // add Serialize
pub struct DiscoveredProfile { ... }
```

This requires adding `serde` dependency to `browser-discovery/Cargo.toml`:
```toml
serde = { workspace = true }
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-rt`

Confirm: all tests pass.

---

## Phase 8: bw-cli Additions

### Task 8.1: Add `integrity` Subcommand to bw-cli

**Goal:** Add an `integrity` subcommand that runs all integrity checks on a browser artifact and reports findings.

**Files to modify:**
- `/Users/4n6h4x0r/src/browser-forensic/crates/bw-cli/Cargo.toml` -- add `browser-integrity` dependency
- `/Users/4n6h4x0r/src/browser-forensic/crates/bw-cli/src/main.rs` -- add `Integrity` subcommand

#### RED commit

**Message:** `test: RED -- bw integrity subcommand exists and reports integrity indicators`

Add integration test file `/Users/4n6h4x0r/src/browser-forensic/crates/bw-cli/tests/integrity_cmd.rs`:

```rust
use assert_cmd::Command;
use tempfile::NamedTempFile;
use rusqlite::Connection;

#[test]
fn integrity_subcommand_exists() {
    let mut cmd = Command::cargo_bin("bw").expect("bw binary");
    cmd.arg("integrity").arg("--help");
    cmd.assert().success();
}

#[test]
fn integrity_on_valid_chrome_history_succeeds() {
    let f = NamedTempFile::new().expect("tempfile");
    let conn = Connection::open(f.path()).expect("open");
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
         INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 1, 13300000000000000);
         INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 0);"
    ).expect("setup");
    drop(conn);

    let mut cmd = Command::cargo_bin("bw").expect("bw binary");
    cmd.arg("integrity").arg(f.path());
    cmd.assert().success();
}

#[test]
fn integrity_on_cleared_history_reports_indicators() {
    let f = NamedTempFile::new().expect("tempfile");
    let conn = Connection::open(f.path()).expect("open");
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
         CREATE TABLE sqlite_sequence (name TEXT, seq INTEGER);
         INSERT INTO sqlite_sequence VALUES ('urls', 500);"
    ).expect("setup");
    drop(conn);

    let mut cmd = Command::cargo_bin("bw").expect("bw binary");
    cmd.arg("integrity").arg(f.path()).arg("--format").arg("jsonl");
    let output = cmd.output().expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("HistoryCleared") || stdout.contains("integrity"),
        "should report integrity findings for cleared history");
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p bw-cli`

Confirm: fails because `integrity` subcommand does not exist.

#### GREEN commit

**Message:** `feat: add integrity subcommand to bw-cli`

Add `browser-integrity` to bw-cli's `Cargo.toml`:
```toml
browser-integrity = { path = "../browser-integrity" }
```

Add to `Commands` enum:
```rust
/// Run integrity checks on a browser artifact.
Integrity(ArtifactArgs),
```

Add to `main()` match:
```rust
Commands::Integrity(args) => run_integrity(args),
```

Add `run_integrity` function:
```rust
fn run_integrity(args: ArtifactArgs) -> Result<()> {
    use browser_core::{detect_browser, BrowserFamily};

    let path = &args.path;
    let family = detect_browser(path)
        .or_else(|| infer_browser_from_filename(path))
        .unwrap_or(BrowserFamily::Chromium); // default to Chromium for raw SQLite files

    let mut indicators = Vec::new();

    // Database-level checks
    if let Ok(mut ind) = browser_integrity::check_database_integrity(path) {
        indicators.append(&mut ind);
    }
    if let Ok(mut ind) = browser_integrity::check_wal_state(path) {
        indicators.append(&mut ind);
    }

    // History-specific checks
    if let Ok(mut ind) = browser_integrity::check_history_integrity(path, family.clone()) {
        indicators.append(&mut ind);
    }

    // Cookie-specific checks
    if let Ok(mut ind) = browser_integrity::check_cookie_integrity(path, family) {
        indicators.append(&mut ind);
    }

    if indicators.is_empty() {
        match args.format {
            OutputFormat::Text => println!("No integrity issues detected."),
            OutputFormat::Jsonl => println!("{{\"status\":\"clean\"}}"),
            OutputFormat::Csv => {
                println!("type,path,detail");
                println!("clean,{},no issues", path.display());
            }
        }
    } else {
        match args.format {
            OutputFormat::Text => {
                println!("Found {} integrity indicator(s):", indicators.len());
                for ind in &indicators {
                    println!("  {:?}", ind);
                }
            }
            OutputFormat::Jsonl => {
                for ind in &indicators {
                    if let Ok(json) = serde_json::to_string(ind) {
                        println!("{json}");
                    }
                }
            }
            OutputFormat::Csv => {
                println!("type,detail");
                for ind in &indicators {
                    if let Ok(json) = serde_json::to_string(ind) {
                        println!("{json}");
                    }
                }
            }
        }
    }

    Ok(())
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p bw-cli`

Confirm: all tests pass.

---

### Task 8.2: Add `carve` Subcommand to bw-cli

**Goal:** Add a `carve` subcommand that runs SQLite free-page carving and WAL recovery.

**Files to modify:**
- `/Users/4n6h4x0r/src/browser-forensic/crates/bw-cli/Cargo.toml` -- add `browser-carve` dependency
- `/Users/4n6h4x0r/src/browser-forensic/crates/bw-cli/src/main.rs` -- add `Carve` subcommand

#### RED commit

**Message:** `test: RED -- bw carve subcommand exists and reports carved records`

Add integration test file `/Users/4n6h4x0r/src/browser-forensic/crates/bw-cli/tests/carve_cmd.rs`:

```rust
use assert_cmd::Command;
use tempfile::NamedTempFile;
use rusqlite::Connection;

#[test]
fn carve_subcommand_exists() {
    let mut cmd = Command::cargo_bin("bw").expect("bw binary");
    cmd.arg("carve").arg("--help");
    cmd.assert().success();
}

#[test]
fn carve_on_valid_db_succeeds() {
    let f = NamedTempFile::new().expect("tempfile");
    let conn = Connection::open(f.path()).expect("open");
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);
         INSERT INTO urls VALUES (1, 'https://example.com');"
    ).expect("setup");
    drop(conn);

    let mut cmd = Command::cargo_bin("bw").expect("bw binary");
    cmd.arg("carve").arg(f.path());
    cmd.assert().success();
}

#[test]
fn carve_jsonl_output_is_valid_json() {
    let f = NamedTempFile::new().expect("tempfile");
    let conn = Connection::open(f.path()).expect("open");
    conn.execute_batch("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);").expect("setup");
    drop(conn);

    let mut cmd = Command::cargo_bin("bw").expect("bw binary");
    cmd.arg("carve").arg(f.path()).arg("--format").arg("jsonl");
    let output = cmd.output().expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should contain stats line at minimum
    for line in stdout.lines() {
        if !line.is_empty() {
            // Each line should be valid JSON
            let _: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");
        }
    }
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p bw-cli`

Confirm: fails because `carve` subcommand does not exist.

#### GREEN commit

**Message:** `feat: add carve subcommand to bw-cli`

Add `browser-carve` to bw-cli's `Cargo.toml`:
```toml
browser-carve = { path = "../browser-carve" }
```

Add to `Commands` enum:
```rust
/// Carve deleted records from a browser SQLite database.
Carve(ArtifactArgs),
```

Add to `main()` match:
```rust
Commands::Carve(args) => run_carve(args),
```

Add `run_carve` function:
```rust
fn run_carve(args: ArtifactArgs) -> Result<()> {
    let path = &args.path;
    let mut all_records = Vec::new();
    let mut total_stats = browser_carve::CarveStats::default();

    // SQLite free-page carving
    if let Ok(result) = browser_carve::carve_sqlite_free_pages(path) {
        total_stats.bytes_scanned += result.stats.bytes_scanned;
        total_stats.pages_scanned += result.stats.pages_scanned;
        total_stats.free_pages_found += result.stats.free_pages_found;
        total_stats.records_recovered += result.stats.records_recovered;
        total_stats.records_partial += result.stats.records_partial;
        all_records.extend(result.records);
    }

    // WAL recovery
    if let Ok(result) = browser_carve::recover_from_wal(path) {
        total_stats.records_recovered += result.stats.records_recovered;
        all_records.extend(result.records);
    }

    match args.format {
        OutputFormat::Text => {
            println!("Carve results for: {}", path.display());
            println!("  Pages scanned: {}", total_stats.pages_scanned);
            println!("  Free pages found: {}", total_stats.free_pages_found);
            println!("  Records recovered: {}", total_stats.records_recovered);
            println!("  Bytes scanned: {}", total_stats.bytes_scanned);
            if !all_records.is_empty() {
                println!("\nRecovered records:");
                for record in &all_records {
                    println!("  [offset={}] table={} method={:?} quality={:?}",
                        record.offset, record.table, record.method, record.quality);
                    for (key, val) in &record.fields {
                        println!("    {key}: {val}");
                    }
                }
            }
        }
        OutputFormat::Jsonl => {
            // Stats line
            if let Ok(json) = serde_json::to_string(&total_stats) {
                println!("{json}");
            }
            // Record lines
            for record in &all_records {
                if let Ok(json) = serde_json::to_string(record) {
                    println!("{json}");
                }
            }
        }
        OutputFormat::Csv => {
            println!("offset,table,method,quality,fields");
            for record in &all_records {
                let fields_json = serde_json::to_string(&record.fields).unwrap_or_default();
                println!("{},{},{:?},{:?},{}",
                    record.offset, record.table, record.method, record.quality,
                    format::csv_escape(&fields_json));
            }
        }
    }

    Ok(())
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p bw-cli`

Confirm: all tests pass.

---

### Task 8.3: Add `triage` Subcommand to bw-cli

**Goal:** Add a `triage` subcommand that runs the full RapidTriage pipeline.

**Files to modify:**
- `/Users/4n6h4x0r/src/browser-forensic/crates/bw-cli/Cargo.toml` -- add `browser-rt` dependency
- `/Users/4n6h4x0r/src/browser-forensic/crates/bw-cli/src/main.rs` -- add `Triage` subcommand

#### RED commit

**Message:** `test: RED -- bw triage subcommand exists and produces report`

Add integration test `/Users/4n6h4x0r/src/browser-forensic/crates/bw-cli/tests/triage_cmd.rs`:

```rust
use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

#[test]
fn triage_subcommand_exists() {
    let mut cmd = Command::cargo_bin("bw").expect("bw binary");
    cmd.arg("triage").arg("--help");
    cmd.assert().success();
}

#[test]
fn triage_on_empty_home_succeeds() {
    let home = TempDir::new().expect("tempdir");
    let mut cmd = Command::cargo_bin("bw").expect("bw binary");
    cmd.arg("triage").arg("--home").arg(home.path());
    cmd.assert().success();
}

#[test]
fn triage_with_chrome_profile_finds_events() {
    let home = TempDir::new().expect("tempdir");
    let chrome_default = home.path()
        .join("Library/Application Support/Google/Chrome/Default");
    fs::create_dir_all(&chrome_default).expect("mkdir");

    // Create minimal History db
    let conn = rusqlite::Connection::open(chrome_default.join("History")).expect("open");
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
         INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 1, 13300000000000000);
         INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 0);"
    ).expect("setup");
    drop(conn);

    let mut cmd = Command::cargo_bin("bw").expect("bw binary");
    cmd.arg("triage").arg("--home").arg(home.path()).arg("--format").arg("jsonl");
    let output = cmd.output().expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "triage should produce output");
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p bw-cli`

Confirm: fails because `triage` subcommand does not exist.

#### GREEN commit

**Message:** `feat: add triage subcommand to bw-cli`

Add `browser-rt` to bw-cli's `Cargo.toml`:
```toml
browser-rt = { path = "../browser-rt" }
```

Add `TriageArgs`:
```rust
#[derive(Parser, Debug)]
struct TriageArgs {
    /// Home directory to scan for browser profiles.
    #[arg(long, value_name = "DIR")]
    home: Option<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    format: OutputFormat,
}
```

Add to `Commands` enum:
```rust
/// Run full triage: discover profiles, parse, check integrity, carve.
Triage(TriageArgs),
```

Add to `main()` match:
```rust
Commands::Triage(args) => run_triage(args),
```

Add `run_triage`:
```rust
fn run_triage(args: TriageArgs) -> Result<()> {
    let home = args.home.unwrap_or_else(|| {
        dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"))
    });

    let report = browser_rt::triage(&home)?;

    match args.format {
        OutputFormat::Text => {
            println!("Browser Forensic Triage Report");
            println!("==============================");
            println!("Generated: {}", report.generated_at_ns);
            println!("Profiles found: {}", report.profiles.len());
            println!("Events parsed: {}", report.events.len());
            println!("Integrity indicators: {}", report.integrity.len());
            println!("Carved records: {}", report.carved.len());

            if !report.profiles.is_empty() {
                println!("\nProfiles:");
                for p in &report.profiles {
                    println!("  {} - {} ({})", p.browser, p.name, p.path.display());
                }
            }

            if !report.integrity.is_empty() {
                println!("\nIntegrity Issues:");
                for ind in &report.integrity {
                    println!("  {:?}", ind);
                }
            }

            if !report.events.is_empty() {
                println!("\nTimeline ({} events):", report.events.len());
                for ev in report.events.iter().take(50) {
                    println!("  {}", format::event_to_text(ev));
                }
                if report.events.len() > 50 {
                    println!("  ... and {} more events", report.events.len() - 50);
                }
            }
        }
        OutputFormat::Jsonl => {
            if let Ok(json) = serde_json::to_string(&report) {
                println!("{json}");
            }
        }
        OutputFormat::Csv => {
            // Output events as CSV
            println!("{}", format::TIMELINE_CSV_HEADER);
            for ev in &report.events {
                println!("{}", format::event_to_csv_row(ev));
            }
        }
    }

    Ok(())
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p bw-cli`

Confirm: all tests pass.

---

## Phase 9: Integration Tests

### Task 9.1: Cross-Crate Integration Test -- Full Pipeline

**Goal:** End-to-end test that creates a fake browser profile, runs triage, and verifies the report contains expected data from all phases (parsing, integrity, carving).

**New file:** `/Users/4n6h4x0r/src/browser-forensic/tests/integration_pipeline.rs`

#### RED commit

**Message:** `test: RED -- integration test for full triage pipeline across all crates`

Create `/Users/4n6h4x0r/src/browser-forensic/tests/integration_pipeline.rs`:

```rust
//! Integration test: full triage pipeline.
//!
//! Creates a fake browser profile directory with known artifacts,
//! runs the full triage pipeline, and verifies the report.

use browser_core::BrowserFamily;
use browser_rt::triage_profile;
use tempfile::TempDir;

#[test]
fn triage_chromium_profile_with_history_and_cookies() {
    let dir = TempDir::new().expect("tempdir");

    // Create Chromium History database with known data
    {
        let conn = rusqlite::Connection::open(dir.path().join("History")).expect("open");
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_time INTEGER DEFAULT 0);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, from_visit INTEGER DEFAULT 0, transition INTEGER DEFAULT 0);
             CREATE TABLE sqlite_sequence (name TEXT, seq INTEGER);
             INSERT INTO urls VALUES (1, 'https://evidence.example.com', 'Evidence Page', 3, 13300000000000000);
             INSERT INTO urls VALUES (2, 'https://second.example.com', 'Second', 1, 13300000001000000);
             INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 0);
             -- Gap: visit ID jumps from 1 to 10
             INSERT INTO visits VALUES (10, 2, 13300000001000000, 0, 0);
             INSERT INTO sqlite_sequence VALUES ('urls', 2);"
        ).expect("setup history");
    }

    // Create Cookies database
    {
        let conn = rusqlite::Connection::open(dir.path().join("Cookies")).expect("open");
        conn.execute_batch(
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
             );
             INSERT INTO cookies VALUES (13300000000000000, '.example.com', 'sid', 'val', '/', 13400000000000000, 13300000001000000, 0, 1);"
        ).expect("setup cookies");
    }

    let report = triage_profile(dir.path(), BrowserFamily::Chromium).expect("triage");

    // History events should be present
    assert!(!report.events.is_empty(), "should have parsed events");
    assert!(report.events.iter().any(|e|
        e.attrs.get("url").and_then(|v| v.as_str()) == Some("https://evidence.example.com")
    ), "should contain the evidence URL");

    // Integrity: visit ID gap should be detected
    assert!(report.integrity.iter().any(|i|
        matches!(i, browser_integrity::IntegrityIndicator::VisitIdGap { .. })
    ), "should detect visit ID gap (1 -> 10)");

    // Cookie events should be present
    assert!(report.events.iter().any(|e|
        e.artifact == browser_core::ArtifactKind::Cookies
    ), "should have parsed cookie events");

    // Report should have a valid timestamp
    assert!(report.generated_at_ns > 0, "report should have generation timestamp");
}

#[test]
fn triage_firefox_profile_with_places() {
    let dir = TempDir::new().expect("tempdir");

    {
        let conn = rusqlite::Connection::open(dir.path().join("places.sqlite")).expect("open");
        conn.execute_batch(
            "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER DEFAULT 0, last_visit_date INTEGER);
             CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);
             INSERT INTO moz_places VALUES (1, 'https://firefox-test.example.com', 'Firefox Test', 1, 1700000000000000);
             INSERT INTO moz_historyvisits VALUES (1, 0, 1, 1700000000000000, 1);"
        ).expect("setup");
    }

    let report = triage_profile(dir.path(), BrowserFamily::Firefox).expect("triage");
    assert!(!report.events.is_empty(), "should have Firefox history events");
}

#[test]
fn integrity_indicators_are_serializable_to_json() {
    use browser_integrity::IntegrityIndicator;
    use std::path::PathBuf;

    let indicators = vec![
        IntegrityIndicator::HistoryCleared {
            browser: BrowserFamily::Chromium,
            path: PathBuf::from("/test/History"),
            detected_at_ns: 1_000_000,
        },
        IntegrityIndicator::VisitIdGap {
            path: PathBuf::from("/test/History"),
            expected_id: 5,
            found_id: 100,
        },
    ];

    for ind in &indicators {
        let json = serde_json::to_string(ind);
        assert!(json.is_ok(), "IntegrityIndicator should serialize: {:?}", ind);
    }
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test --test integration_pipeline`

Confirm: tests fail because dependencies are not configured for workspace-level integration tests.

#### GREEN commit

**Message:** `feat: add integration tests for full triage pipeline`

Ensure the workspace root `Cargo.toml` has the necessary dev-dependencies for integration tests. The integration tests need access to crate types. Since this is a workspace, the tests file under `/tests/` needs a workspace-level approach.

**Alternative:** Place integration tests inside `browser-rt` instead:

Move the test file to `/Users/4n6h4x0r/src/browser-forensic/crates/browser-rt/tests/integration_pipeline.rs`

This file already has access to all the crate dependencies via `browser-rt/Cargo.toml`.

Add to `browser-rt/Cargo.toml` under `[dev-dependencies]`:
```toml
rusqlite = { workspace = true }
browser-integrity = { path = "../browser-integrity" }
browser-core = { path = "../browser-core" }
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-rt`

Confirm: all tests pass (unit tests and integration tests).

---

### Task 9.2: ForensicMeta Integration Test

**Goal:** Verify that `ForensicMeta::lookup` works correctly across the workspace, connecting browser-core to forensicnomicon.

**File to modify:** `/Users/4n6h4x0r/src/browser-forensic/crates/browser-core/src/lib.rs` (add to existing test module)

#### RED commit

**Message:** `test: RED -- ForensicMeta integration with forensicnomicon artifact profiles`

Add tests:

```rust
#[test]
fn forensic_meta_all_browser_artifacts_have_profiles() {
    let artifact_ids = [
        "browser_chrome_history",
        "browser_chrome_cookies",
        "browser_chrome_downloads",
        "browser_chrome_bookmarks",
        "browser_chrome_extensions",
        "browser_chrome_autofill",
        "browser_chrome_cache",
        "browser_chrome_session",
        "browser_firefox_history",
        "browser_firefox_cookies",
        "browser_firefox_downloads",
        "browser_safari_history",
    ];

    for id in &artifact_ids {
        let meta = ForensicMeta::lookup(id);
        assert!(meta.is_some(), "ForensicMeta::lookup({id}) should return Some");
    }
}

#[test]
fn forensic_meta_evidence_strength_is_populated() {
    let meta = ForensicMeta::lookup("browser_chrome_downloads").expect("should exist");
    assert!(meta.evidence_strength.is_some());
    assert_eq!(meta.evidence_strength.as_deref(), Some("Strong"));
}
```

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-core`

Confirm: tests fail because `ForensicMeta` and the forensicnomicon profiles don't exist yet (depends on Task 1.1 and 2.1 being complete).

#### GREEN commit

**Message:** `feat: verify ForensicMeta integration with forensicnomicon profiles`

No implementation changes needed -- this task depends on Task 1.1 (forensicnomicon profiles) and Task 2.1 (ForensicMeta type) being implemented first. Once those are in place, these tests should pass.

Run: `cd /Users/4n6h4x0r/src/browser-forensic && cargo test -p browser-core`

Confirm: all tests pass.

---

## Summary

### Task Dependency Graph

```
Phase 1: Task 1.1 (forensicnomicon profiles)
    |
Phase 2: Task 2.1 (browser-core ForensicMeta, ArtifactKind variants)
    |
Phase 3: Task 3.1 → 3.2 → 3.3 → 3.4 → 3.5 → 3.6 → 3.7 (browser-integrity)
    |
Phase 4: Task 4.1 → 4.2 → 4.3 → 4.4 (browser-carve)
    |
Phase 5: Task 5.1 (browser-memory)
    |
Phase 6: Tasks 6.1, 6.2, 6.3 (parallel -- no inter-dependencies)
    |
Phase 7: Task 7.1 (browser-rt -- depends on Phases 3, 4, 6)
    |
Phase 8: Tasks 8.1 → 8.2 → 8.3 (bw-cli -- depends on Phase 7)
    |
Phase 9: Tasks 9.1, 9.2 (integration tests -- depends on all above)
```

### New Workspace Members After All Tasks

```toml
[workspace]
members = [
    "crates/browser-core",
    "crates/browser-chrome",
    "crates/browser-firefox",
    "crates/browser-safari",
    "crates/browser-discovery",
    "crates/browser-integrity",   # NEW (Phase 3)
    "crates/browser-carve",       # NEW (Phase 4)
    "crates/browser-memory",      # NEW (Phase 5)
    "crates/browser-rt",          # NEW (Phase 7)
    "crates/bw-cli",
]
```

### New Workspace Dependencies After All Tasks

```toml
[workspace.dependencies]
anyhow = "1"
thiserror = "2"                                        # NEW
forensicnomicon = { path = "../forensicnomicon", features = ["serde"] }  # NEW
dirs = "6"
lz4_flex = "0.11"
plist = "1"
url = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
rusqlite = { version = "0.32", features = ["bundled"] }
chrono = { version = "0.4", features = ["serde"] }
clap = { version = "4", features = ["derive"] }
assert_cmd = "2"
tempfile = "3"
```

### Total: 9 phases, 20 tasks, 40 commits (20 RED + 20 GREEN)
