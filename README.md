[![Stars](https://img.shields.io/github/stars/SecurityRonin/browser-forensic?style=flat-square)](https://github.com/SecurityRonin/browser-forensic/stargazers)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/browser-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/browser-forensic/actions/workflows/ci.yml)
[![Rust 1.80+](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue.svg)](#install)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

# browser-forensic

**Parse Chrome, Firefox, and Safari artifacts. Detect history clearing. Carve deleted records. No runtime deps.**

Browser artifacts are present in almost every investigation — they reconstruct the user's timeline, expose credential exposure, and often reveal the delivery mechanism for an attack. The problem is tooling: most parsers require Python, lock you to Windows, or ignore the forensically interesting question of whether the evidence was tampered with.

`bw` is a single static Rust binary. Point it at a browser database and get JSON. Point it at a profile directory and get a full triage report with integrity indicators and carved deleted records.

```bash
cargo install --git https://github.com/SecurityRonin/browser-forensic bw-cli
bw history /path/to/Chrome/Default/History --format jsonl | jq 'select(.attrs.url | test("google.com"))'
```

**[Full documentation →](https://securityronin.github.io/browser-forensic/)**

---

## Install

**From source**
```bash
git clone https://github.com/SecurityRonin/browser-forensic.git
cd browser-forensic
cargo build --release
./target/release/bw --help
```

---

## Three Things You Do With This

### Reconstruct the full browser timeline

```bash
# Chrome history — last 30 days, sorted by time
bw history /path/to/Chrome/Default/History --format jsonl \
  | jq -r '[.timestamp_ns, .attrs.url, .attrs.title] | @tsv' \
  | sort | tail -100

# Firefox — same command, different path
bw history /path/to/Firefox/Profiles/abc.default/places.sqlite --format jsonl
```

All three browsers produce the same `BrowserEvent` JSON schema. Your downstream analysis pipeline doesn't need to know which browser produced the data.

### Detect history clearing and tampering

```bash
bw integrity /path/to/Chrome/Default/History --format jsonl
```

```json
{"HistoryCleared":{"browser":"Chromium","path":"/path/to/History","detected_at_ns":1700000000000000000}}
{"AutoIncrementGap":{"path":"/path/to/History","table":"urls","max_rowid":2,"auto_increment":847}}
{"VisitIdGap":{"path":"/path/to/History","expected_id":3,"found_id":851}}
```

Three indicators in under 100ms. The `sqlite_sequence` table recorded 847 URL insertions; only 2 rows remain. IDs jump from 2 to 851. The user cleared their history — and this database says exactly when the last visible record was written.

### Carve deleted records from SQLite free pages

```bash
bw carve /path/to/Chrome/Default/History --format jsonl
```

SQLite marks deleted rows as free pages rather than overwriting them immediately. `bw carve` walks the freelist chain, scans each free page for URL patterns, and returns whatever survived. Combine with `bw integrity` to establish what was deleted and what was recovered.

---

## What's Different

| | browser-forensic | Hindsight | BrowsingHistoryView | plaso |
|--|:-:|:-:|:-:|:-:|
| Runs on Linux / macOS | ✓ | ✓ | — | ✓ |
| Single static binary | ✓ | — | — | — |
| No Python runtime | ✓ | — | ✓ | — |
| Chrome + Firefox + Safari | ✓ | ✓ | ✓ | ✓ |
| Integrity / tampering checks | ✓ | — | — | — |
| SQLite free-page carving | ✓ | — | — | — |
| WAL recovery | ✓ | — | — | — |
| Memory byte-pattern scanning | ✓ | — | — | — |
| Embeddable Rust library | ✓ | — | — | — |
| JSON / JSONL / CSV output | ✓ | — | ✓ | partial |

---

## Browser Coverage

| Artifact | Chrome / Edge / Brave | Firefox | Safari |
|---|:-:|:-:|:-:|
| History | ✓ | ✓ | ✓ |
| Cookies | ✓ | ✓ | ✓ |
| Downloads | ✓ | ✓ | ✓ |
| Bookmarks | ✓ | ✓ | ✓ |
| Extensions / Add-ons | ✓ | ✓ | — |
| Autofill | ✓ | — | — |
| Login Data (no passwords) | ✓ | ✓ | — |
| Cache | ✓ | — | — |
| Session State | ✓ | ✓ | — |
| Top Sites | — | — | ✓ |
| Profile Metadata (Local State) | ✓ | — | — |
| Integrity indicators | ✓ | ✓ | ✓ |
| SQLite free-page carving | ✓ | ✓ | ✓ |
| WAL recovery | ✓ | ✓ | ✓ |

---

## Integrity Checks

`bw integrity` detects raw structural anomalies — observable facts about the database, not forensic conclusions:

**HistoryCleared / AutoIncrementGap** — `sqlite_sequence` recorded N insertions; fewer than N rows remain. The auto-increment counter is the shadow of everything that was ever inserted, including what was deleted.

**VisitIdGap** — visit IDs must be monotonically assigned. A gap of 840 IDs between row 2 and row 851 means 840 visit records were inserted and then deleted.

**TimestampNonMonotonic** — visit timestamps must not go backward within a session. A timestamp earlier than the preceding visit indicates record injection or manual table manipulation.

**CookieTimestampAnomaly** — a cookie whose `creation_utc` is later than its `last_access_utc` cannot exist naturally. The access timestamp predates the cookie's creation — the record was fabricated or the timestamps were edited.

**WalPresent** — a `-wal` file alongside the database means unflushed writes exist that are not reflected in the main file. The WAL contains the most recent state; ignoring it produces an incomplete picture.

**SqliteIntegrityFailure** — `PRAGMA integrity_check` reports structural corruption. This ranges from benign (interrupted write) to deliberate (anti-forensic page manipulation).

**HistoryTombstoneFound** *(Safari)* — Safari maintains a `history_tombstones` table for deleted history items. Tombstones are direct evidence that history was deleted, with the deletion timestamp preserved in the schema.

**DownloadFileMissing** — a download record exists with a local target path, but the file is absent. The download completed; the file was removed.

---

## Full Triage

```bash
# Discover all browser profiles under the user's home directory,
# parse every artifact, run integrity checks, and carve free pages
bw triage --home /mnt/evidence/Users/jsmith --format jsonl > report.jsonl
```

The triage report includes:
- All parsed browser events across Chrome, Firefox, and Safari
- Integrity indicators from every database found
- Carved records from SQLite free pages and WAL files
- A manifest of discovered profiles (browser, name, path)
- Generation timestamp for chain-of-custody documentation

---

## Output Schema

All commands share the same `BrowserEvent` envelope:

```json
{
  "timestamp_ns": 1700000000000000000,
  "browser": "Chromium",
  "artifact": "History",
  "source": "/path/to/History",
  "description": "https://example.com — Example Domain",
  "attrs": {
    "url": "https://example.com",
    "title": "Example Domain",
    "visit_count": 3
  }
}
```

`timestamp_ns` is always Unix nanoseconds. `artifact` is the artifact kind (`History`, `Cookies`, `Downloads`, `Bookmarks`, `Autofill`, `LoginData`, `Extensions`, `Cache`, `Session`, `Integrity`, `Carved`, `Memory`).

---

## Crate Architecture

The workspace is layered — each crate has a single responsibility:

```
forensicnomicon          format constants, epoch offsets, SQLite magic, artifact profiles
      |
browser-core             BrowserEvent, BrowserFamily, ArtifactKind, ForensicMeta, timestamp conversions
      |
  ┌───┴──────────────────────────────────────────┐
  │                                              │
browser-chrome           Chrome/Chromium/Edge/   browser-discovery    cross-platform profile
browser-firefox          Brave/Firefox/Safari    (macOS/Linux/Win)    discovery
browser-safari           artifact parsers
  │
  ├── browser-integrity  history clearing, visit ID gaps, WAL detection, timestamp anomalies
  ├── browser-carve      SQLite free-page walking, WAL frame recovery
  └── browser-memory     byte-pattern URL/cookie scanning (no CONTAINER dependency)
      |
browser-rt               TriageReport orchestration — wires all crates into a single report
      |
bw-cli                   `bw` — history / cookies / downloads / bookmarks / integrity / carve / triage
```

Each library crate is independently usable in your own Rust tooling. `browser-integrity`, `browser-carve`, and `browser-memory` accept `Path` or `&[u8]` — they are medium-agnostic and have no dependency on any image format or memory dump layer.

| Crate | Description |
|---|---|
| `browser-core` | Domain types, timestamp conversions, ForensicMeta lookups |
| `browser-chrome` | Chrome history, cookies, downloads, bookmarks, autofill, login data, extensions, cache, session, Local State |
| `browser-firefox` | Firefox history, cookies, downloads, bookmarks, extensions, session (mozLz4), login data |
| `browser-safari` | Safari history, cookies, downloads, bookmarks, TopSites |
| `browser-discovery` | Finds all browser profiles under a home directory (macOS, Linux, Windows) |
| `browser-integrity` | Detects history clearing, visit ID gaps, timestamp anomalies, WAL presence, tombstones |
| `browser-carve` | SQLite free-page carving, WAL frame recovery |
| `browser-memory` | Byte-pattern URL/cookie scanning for memory forensics — no runtime dependencies below this layer |
| `browser-rt` | RapidTriage orchestration — `triage_profile()` + `triage()` → `TriageReport` |
| `bw-cli` | `bw` CLI binary |

---

## Using as a Library

```toml
[dependencies]
browser-chrome    = { git = "https://github.com/SecurityRonin/browser-forensic" }
browser-integrity = { git = "https://github.com/SecurityRonin/browser-forensic" }
browser-carve     = { git = "https://github.com/SecurityRonin/browser-forensic" }
```

```rust
use browser_chrome::parse_history;
use browser_integrity::{check_history_integrity, IntegrityIndicator};
use browser_core::BrowserFamily;

let events = parse_history(path)?;
let indicators = check_history_integrity(path, BrowserFamily::Chromium)?;

for ind in &indicators {
    match ind {
        IntegrityIndicator::HistoryCleared { detected_at_ns, .. } => {
            eprintln!("History was cleared at {detected_at_ns}");
        }
        IntegrityIndicator::VisitIdGap { expected_id, found_id, .. } => {
            eprintln!("Visit ID gap: expected {expected_id}, found {found_id}");
        }
        _ => {}
    }
}
```

---

## RapidTriage Ecosystem

browser-forensic is one parser library in the [RapidTriage](https://github.com/SecurityRonin/rapidtriage) DFIR toolkit:

| Crate | Artifact family |
|---|---|
| [browser-forensic](https://github.com/SecurityRonin/browser-forensic) | Chrome / Firefox / Safari |
| [winevt-forensic](https://github.com/SecurityRonin/winevt-forensic) | Windows Event Logs (EVTX) |
| [srum-forensic](https://github.com/SecurityRonin/srum-forensic) | Windows SRUM / ESE |
| [memory-forensic](https://github.com/SecurityRonin/memory-forensic) | Process memory, page tables |
| [forensicnomicon](https://github.com/SecurityRonin/forensicnomicon) | Artifact catalog, format constants |

---

[Privacy Policy](https://securityronin.github.io/browser-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/browser-forensic/terms/) · © 2026 Security Ronin Ltd.
