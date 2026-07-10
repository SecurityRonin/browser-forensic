[![Docs](https://img.shields.io/badge/docs-securityronin.github.io-blue.svg)](https://securityronin.github.io/browser-forensic/)
[![Rust 1.80+](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue.svg)](#install)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/browser-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/browser-forensic/actions/workflows/ci.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](#trust-but-verify)
[![security: cargo-deny](https://img.shields.io/badge/security-cargo--deny-success.svg)](deny.toml)

# browser-forensic

**Parse Chrome, Edge, Firefox, and Safari artifacts. Detect history clearing. Carve deleted records. No runtime deps.**

Browser artifacts are present in almost every investigation — they reconstruct the user's timeline, expose credential exposure, and often reveal the delivery mechanism for an attack. The problem is tooling: most parsers require Python, lock you to Windows, or ignore the forensically interesting question of whether the evidence was tampered with.

`br4n6` is a single static Rust binary. Point it at a browser database and get JSON. Point it at a profile directory and get a full triage report with integrity indicators and carved deleted records.

```bash
cargo install --git https://github.com/SecurityRonin/browser-forensic browser-tui
br4n6 history /path/to/Chrome/Default/History --format jsonl | jq 'select(.attrs.url | test("google.com"))'
```

---

## Install

**From source**
```bash
git clone https://github.com/SecurityRonin/browser-forensic.git
cd browser-forensic
cargo build --release
./target/release/br4n6 --help
```

---

## Three Things You Do With This

### Reconstruct the full browser timeline

```bash
# Chrome history — last 30 days, sorted by time
br4n6 history /path/to/Chrome/Default/History --format jsonl \
  | jq -r '[.timestamp_ns, .attrs.url, .attrs.title] | @tsv' \
  | sort | tail -100

# Firefox — same command, different path
br4n6 history /path/to/Firefox/Profiles/abc.default/places.sqlite --format jsonl
```

Every supported browser produces the same `BrowserEvent` JSON schema. Your downstream analysis pipeline doesn't need to know which browser produced the data.

### Detect history clearing and tampering

```bash
br4n6 integrity /path/to/Chrome/Default/History --format jsonl
```

```json
{"HistoryCleared":{"browser":"Chromium","path":"/path/to/History","detected_at_ns":1700000000000000000}}
{"AutoIncrementGap":{"path":"/path/to/History","table":"urls","max_rowid":2,"auto_increment":847}}
{"VisitIdGap":{"path":"/path/to/History","expected_id":3,"found_id":851}}
```

Three indicators in under 100ms. The `sqlite_sequence` table recorded 847 URL insertions; only 2 rows remain. IDs jump from 2 to 851. The user cleared their history — and this database says exactly when the last visible record was written.

### Carve deleted records from SQLite free pages

```bash
br4n6 carve /path/to/Chrome/Default/History --format jsonl
```

SQLite marks deleted rows as free pages rather than overwriting them immediately. `br4n6 carve` walks the freelist chain, scans each free page for URL patterns, and returns whatever survived. Combine with `br4n6 integrity` to establish what was deleted and what was recovered.

---

## What's Different

| | browser-forensic | Hindsight | BrowsingHistoryView | plaso |
|--|:-:|:-:|:-:|:-:|
| Runs on Linux / macOS | ✅ | ✅ | — | ✅ |
| Single static binary | ✅ | — | — | — |
| No Python runtime | ✅ | — | ✅ | — |
| Chrome + Firefox + Safari | ✅ | ✅ | ✅ | ✅ |
| Integrity / tampering checks | ✅ | — | — | — |
| SQLite free-page carving | ✅ | — | — | — |
| WAL recovery | ✅ | — | — | — |
| Memory byte-pattern scanning | ✅ | — | — | — |
| Embeddable Rust library | ✅ | — | — | — |
| URL / cookie interpretation | ✅ | ✅ | — | — |
| Preferences parsing | ✅ | ✅ | — | ✅ |
| Correlated XLSX / SQLite export | ✅ | ✅ | — | partial |
| JSON / JSONL / CSV output | ✅ | ✅ | ✅ | partial |

---

## Browser Coverage

| Artifact | Chrome / Edge / Brave | Firefox | Safari |
|---|:-:|:-:|:-:|
| History | ✅ | ✅ | ✅ |
| Cookies | ✅ | ✅ | ✅ |
| Downloads | ✅ | ✅ | ✅ |
| Bookmarks | ✅ | ✅ | ✅ |
| Extensions / Add-ons | ✅ | ✅ | — |
| Autofill | ✅ | — | — |
| Login Data (no passwords) | ✅ | ✅ | — |
| Cache | ✅ | — | — |
| Session State | ✅ | ✅ | — |
| Top Sites | — | — | ✅ |
| Profile Metadata (Local State) | ✅ | — | — |
| Preferences | ✅ | ✅ | — |
| Integrity indicators | ✅ | ✅ | ✅ |
| SQLite free-page carving | ✅ | ✅ | ✅ |
| WAL recovery | ✅ | ✅ | ✅ |

---

## Integrity Checks

`br4n6 integrity` detects raw structural anomalies — observable facts about the database, not forensic conclusions:

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
br4n6 triage --home /mnt/evidence/Users/jsmith --format jsonl > report.jsonl
```

The triage report includes:
- All parsed browser events across Chrome, Edge, Firefox, and Safari
- Integrity indicators from every database found
- Carved records from SQLite free pages and WAL files
- A manifest of discovered profiles (browser, name, path)
- Generation timestamp for chain-of-custody documentation

---

## Interpretation

`--interpret` adds a human-readable interpretation to each event, decoding the
artifacts that carry hidden structure:

- **Google searches** — extracts the query and search options from
  `google.*/search` URLs (`Searched for "how to wipe a disk"`).
- **Query strings** — decodes any URL's parameters into `key: value` pairs.
- **Google Analytics cookies** — `__utma` / `__utmb` / `__utmc` / `__utmv` /
  `__utmz` / `_ga` (visitor IDs, first/last visit times, campaign sources).
- **Tracking / infrastructure cookies** — F5 BIG-IP `BIGipServer*` (decodes the
  backend `IP:port`), Quantcast `__qca`, and a generic embedded-timestamp scan.

Timestamps are inferred by magnitude (Unix seconds/millis/micros or WebKit),
matching the ground truth without the caller declaring units. Cookie
interpretation runs where a plaintext value is available (Firefox); Chrome cookie
values stay encrypted and are never surfaced.

```bash
br4n6 export /mnt/evidence/Users/jsmith --interpret --format jsonl \
  | jq 'select(.interpretation | test("Searched for"))'
```

## Correlated Export

`br4n6 export` collects a single correlated timeline from a profile or home
directory and writes it in the format an analyst wants:

```bash
# XLSX workbook (one Timeline sheet), timestamps in the examiner's timezone
br4n6 export /mnt/evidence/Users/jsmith \
  --format xlsx -o timeline.xlsx --timezone America/New_York --interpret

# SQLite database with a single `timeline` table for ad-hoc SQL
br4n6 export /mnt/evidence/Users/jsmith --format sqlite -o timeline.sqlite
```

Formats: `xlsx`, `sqlite` (both require `-o FILE`), and streaming `jsonl` / `csv`
/ `text`. `--timezone` accepts any IANA name for human-facing timestamps.

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

`timestamp_ns` is always Unix nanoseconds. `artifact` is the artifact kind (`History`, `Cookies`, `Downloads`, `Bookmarks`, `Autofill`, `LoginData`, `Extensions`, `Cache`, `Session`, `Preferences`, `LocalStorage`, `Integrity`, `Carved`, `Memory`).

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
browser-tui              `br4n6` — dual-mode binary: scriptable CLI (history / cookies /
                         downloads / bookmarks / integrity / carve / triage) + interactive TUI
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
| `browser-tui` | `br4n6` — dual-mode binary: scriptable JSON/JSONL/CSV CLI (history / cookies / downloads / bookmarks / integrity / carve / triage) plus an interactive vi-keyed terminal viewer (`br4n6 tui`) |

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

## Trust but verify

Browser databases are evidence. This suite is built to read them without altering them and without trusting their contents:

- **Read-only on evidence** — SQLite databases are opened read-only; the tool never writes back to the artifact, so timestamps and free pages stay intact for re-examination.
- **`forbid(unsafe)`** — the entire workspace denies `unsafe` code at compile time. Malformed, attacker-controlled artifacts cannot reach a raw pointer path.
- **CI on Linux, macOS, and Windows** — every push runs `cargo fmt --check`, `cargo clippy -D warnings`, build, and the full test suite on all three platforms.
- **Supply-chain gate** — `cargo-deny` checks licenses, RustSec advisories, and banned dependencies on every push (`deny.toml`).

Honest gaps (tracked, not hidden): the suite is **not yet fuzzed** and has **no line-coverage gate** — both are planned to bring it level with the rest of the fleet's Paranoid-Gatekeeper bar.

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
