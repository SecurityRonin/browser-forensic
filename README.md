[![Docs](https://img.shields.io/badge/docs-securityronin.github.io-blue.svg)](https://securityronin.github.io/browser-forensic/)
[![Rust 1.80+](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue.svg)](#install)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/browser-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/browser-forensic/actions/workflows/ci.yml)
[![Fuzz](https://github.com/SecurityRonin/browser-forensic/actions/workflows/fuzz.yml/badge.svg)](https://github.com/SecurityRonin/browser-forensic/actions/workflows/fuzz.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](#trust-but-verify)
[![security: cargo-deny](https://img.shields.io/badge/security-cargo--deny-success.svg)](deny.toml)

# browser-forensic

**One command turns a seized profile — Chrome, Firefox, Safari, or an embedded-Chromium app — into a ranked, court-safe answer. Detect history clearing. Recover deleted records. No runtime deps.**

At 2am you shouldn't have to remember a tool's vocabulary before you can ask it a question. `br4n6` is a single static Rust binary built around the **six questions an examiner actually asks** — point it at a profile, a home directory, or an evidence tree and it does the classifying for you.

```bash
cargo install --git https://github.com/SecurityRonin/browser-forensic browser-forensic-cli

# The golden path: what happened here?
br4n6 investigate /mnt/evidence/Users/jsmith
#   or just:  br4n6 /mnt/evidence/Users/jsmith
```

`investigate` runs a bounded, standard-tier triage and prints a ranked, provenance-tagged summary — then always ends by naming what it did *not* do (deep carving, memory, cache reconstruction), so nothing is silently skipped and a clean result never poses as a complete one.

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

## The six questions

Each verb is a question, not a format's noun. Everything else is `--help` away.

| Ask | Verb | Example |
|---|---|---|
| **What happened?** | `investigate` | `br4n6 investigate <PATH>` (or bare `br4n6 <PATH>`) |
| **Did they visit / download / search X?** | `find` | `br4n6 find evil.com <PATH>` |
| **When — the chronology?** | `timeline` | `br4n6 timeline <PATH> --around 2026-07-01T14:00Z` |
| **What was deleted / carved / evicted?** | `recover` | `br4n6 recover <PATH>` |
| **What did a cached page look like?** | `reconstruct` | `br4n6 reconstruct https://evil.com <PATH> --out ./recon` |
| **What do I hand the lawyer?** | `report` | `br4n6 report <PATH> --bundle -o ./case-42` |

Under the six verbs sit the 46 primitives — every per-artifact parser — in one discoverable namespace:

```bash
br4n6 artifact --list                            # name · browser family · what it proves
br4n6 artifact history <PATH> --format jsonl      # one parser, machine output
```

> **Upgrading from the old flat commands** (`br4n6 history`, `chains`, `carve`, …)? They were removed in a clean break at 0.3.0. See **[docs/migration-v2.md](docs/migration-v2.md)** for every old command mapped to its new form.

---

## Provenance, not homogenized hits

`find` is one front door over distinct evidence classes — but it never merges them. A live history visit, a cached string, and a carved deleted record carry different courtroom value, so each is a separate row with its own axes:

```text
TERM       SOURCE    STATE     CONF  TIME BASIS    USER-ACTION       MATCH
evil.com   history   live      high  explicit      visited           https://evil.com/a
evil.com   cache     live      med   surrounding   observed-string   https://evil.com/a.js
evil.com   carved    deleted   low   none          unknown           <fragment>
```

An empty result proves it looked: `no hits in live history/downloads/bookmarks; skipped: encrypted cookies, memory, carving`.

## Priority ≠ confidence ≠ proof

Every finding renders **three separate axes**, enforced by the data model so no renderer can emit a bare "HIGH" that reads as *high confidence of wrongdoing*:

```text
Priority:       High            (look here first — a triage attention cue)
Confidence:     Medium          (rule investigate.exec_download.v1)
Interpretation: consistent with an executable downloaded via the browser; a download
                does not by itself establish execution
Next:           br4n6 artifact downloads <PATH>
```

Priority is where to look first, never a finding of malice. Interpretations are *consistent-with* statements — the evidence is shown; the conclusion is not asserted.

## Recover deleted evidence — one orchestrator

`recover` runs every applicable recovery over a profile, a single database, or a memory image and ranks the results — you never choose carve-vs-WAL-vs-memory. Recovered items are *consistent-with* eviction or clearing, never asserted as a deliberate user deletion.

```bash
br4n6 recover /mnt/evidence/Users/jsmith          # deleted SQLite/WAL, evicted cache, tamper indicators
br4n6 recover /path/to/History                     # a single database: carve + tamper
br4n6 recover /path/to/memory.raw                  # process-attributed RAM carve
```

## Decrypting cookies and passwords — one flag

Encrypted material is always **counted and reported**, never silently dropped. To read it, add `--keys <PATH>`: key material is auto-located **within the evidence root** (never outside it), every key file is hashed into the manifest, and secrets are file-oriented — never printed to the terminal.

```bash
# Chromium cookies — key auto-located in the root; Windows logon password via stdin
br4n6 artifact cookies /mnt/evidence/Users/jsmith --keys /mnt/evidence/Users/jsmith --password-stdin

# Firefox logins — usernames show; passwords materialize to a FILE only
br4n6 artifact logins /path/to/profile --keys /path/to/profile --reveal-secrets ./secrets.txt
```

Without `--keys`, you still get the count: `1,022 cookies encrypted — add --keys <path>`.

## The court/exam bundle

`report --bundle` writes a reproducible, self-verifying deliverable to a directory:

```bash
br4n6 report /mnt/evidence/Users/jsmith --bundle -o ./case-42
```

- `report.html` — the ranked, court-safe findings + timeline
- `timeline.xlsx` / `timeline.jsonl` — the machine timeline (spreadsheet + round-trippable)
- `manifest.json` — chain of custody: every input's SHA-256/MD5, the exact command line, detection basis, rule + tool versions, timezone rule
- `SHA256SUMS.txt` — a sidecar hashing the bundle's own outputs (`sha256sum -c SHA256SUMS.txt`)

Single-file interop still works too: `br4n6 report <PATH> --format bodyfile|l2t|html`.

---

## What's Different

browser-forensic now matches the artifact breadth of the mainstream browser-history tools — including web storage (Local / Session Storage, IndexedDB) and embedded-Chromium container discovery — and adds forensic depth those tools do not carry: integrity/tampering detection, free-page carving, WAL recovery, memory scanning, and an embeddable Rust library.

| Capability | browser-forensic | [Hindsight](https://github.com/obsidianforensics/hindsight) | [Browser-Reviewer](https://github.com/gustavoparedes/Browser-Reviewer) |
|--|:-:|:-:|:-:|
| Chrome / Chromium | ✅ | ✅ | ✅ |
| Firefox | ✅ | ✅ | ✅ |
| Safari | ✅ | — | — |
| Web storage (Local / Session / IndexedDB) | ✅ | ✅ | ✅ |
| URL / cookie interpretation | ✅ | ✅ | — |
| Embedded-Chromium container discovery | ✅ | — | ✅ |
| Integrity / tampering detection | ✅ | — | — |
| SQLite free-page carving | ✅ | — | — |
| WAL recovery | ✅ | — | — |
| Memory byte-pattern scanning | ✅ | — | — |
| Correlated XLSX / SQLite export | ✅ | ✅ | — |
| Embeddable library | ✅ | — | — |
| Runs on Linux / macOS / Windows | ✅ | ✅ | Windows only |

*Reflects each tool's documented feature set as of mid-2026. Hindsight parses Chromium (and, more recently, Firefox) profiles in Python; Browser-Reviewer is a portable Windows GUI/CLI for Firefox and Chromium.*

---

## Browser Coverage

| Artifact | Chrome / Chromium¹ | Firefox | Safari |
|---|:-:|:-:|:-:|
| History | ✅ | ✅ | ✅ |
| Cookies | ✅ | ✅ | ✅ |
| Downloads | ✅ | ✅ | ✅ |
| Bookmarks | ✅ | ✅ | ✅ |
| Extensions / Add-ons | ✅ | ✅ | ✅ |
| Autofill | ✅ | ✅ | — |
| Login Data (no passwords) | ✅ | ✅ | — |
| Cache | ✅ | ✅ | — |
| Session State | ✅ | ✅ | — |
| Preferences | ✅ | ✅ | — |
| Top Sites | — | — | ✅ |
| Profile Metadata (Local State) | ✅ | — | — |
| Web Storage (Local / Session / IndexedDB) | ✅ | ✅ | — |
| Integrity indicators | ✅ | ✅ | ✅ |
| SQLite free-page carving | ✅ | ✅ | ✅ |
| WAL recovery | ✅ | ✅ | ✅ |

¹ Chromium-family covers Chrome, Edge, Brave, Opera, Vivaldi, and Arc — one engine, one set of parsers.

---

## Web Storage

`br4n6 artifact storage` reads the three web-storage backends the browsers use, emitting the same `BrowserEvent` schema as every other artifact:

```bash
br4n6 artifact storage /path/to/Chrome/Default --format jsonl
```

- **Chromium Local / Session Storage** — LevelDB, decoded through the published [`leveldb-forensic`](https://github.com/SecurityRonin/leveldb-forensic) crate.
- **Chromium IndexedDB** — LevelDB-backed; values are Blink/v8-serialized and surfaced as opaque raw records rather than a fabricated decode.
- **Firefox web storage** — plain SQLite (`webappsstore.sqlite` and `storage/default/*/idb/*.sqlite`).

Each event carries a `storage_type` attr (`local_storage`, `session_storage`, `indexeddb`) so downstream filtering stays simple.

---

## Container Discovery

Modern desktop apps embed Chromium — Slack, Teams, OneDrive, and hundreds of Electron / WebView2 / CEF apps keep the same history, cookies, and web-storage databases a browser does. `br4n6 browsers --sweep` recursively walks an evidence tree, identifies each container by its structural profile markers (backed by `forensicnomicon::browser_profiles`), and attributes it to the owning app:

```bash
br4n6 browsers --sweep /mnt/evidence/Users/jsmith --format jsonl
```

The sweep reports every browser profile and embedded-Chromium container found, with the app name, vendor, and how it embeds Chromium (`Browser` / `Electron` / `WebView2` / `Cef`). A profile-shaped directory that matches no catalog entry is still reported, generically labelled — nothing is silently dropped.

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
- All parsed browser events across Chromium, Firefox, and Safari
- Integrity indicators from every database found
- Carved records from SQLite free pages and WAL files
- A manifest of discovered profiles (browser, name, path, container attribution)
- Generation timestamp for chain-of-custody documentation

---

## Interpretation

`--interpret` adds a human-readable interpretation to each event, decoding the
artifacts that carry hidden structure. The interpretation engine is a clean-room
reimplementation of the Hindsight interpretation plugins:

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

`timestamp_ns` is always Unix nanoseconds. `artifact` is the artifact kind (`History`, `Cookies`, `Downloads`, `Bookmarks`, `Autofill`, `LoginData`, `Extensions`, `Cache`, `Session`, `Preferences`, `LocalStorage`, `Integrity`, `Carved`, `Memory`). Web-storage events use `LocalStorage` with a `storage_type` attr distinguishing Local Storage, Session Storage, and IndexedDB.

---

## Crate Architecture

The workspace is layered — each crate has a single responsibility:

```
forensicnomicon              format constants, epoch offsets, SQLite magic,
                             artifact + embedded-Chromium container catalog
      |
browser-forensic-core        BrowserEvent, BrowserFamily, ArtifactKind, timestamp conversions
      |
  ┌───┴───────────────────────────────────────────────────┐
  │                                                        │
browser-forensic-chrome      Chromium / Firefox / Safari   browser-forensic-discovery
browser-forensic-firefox     artifact parsers              profile discovery + embedded-
browser-forensic-safari                                    Chromium container sweep
  │
  ├── browser-forensic-storage    Local / Session Storage, IndexedDB (reuses leveldb-forensic)
  ├── browser-forensic-integrity  history clearing, visit-ID gaps, WAL detection, timestamp anomalies
  ├── browser-forensic-carve      SQLite free-page + WAL recovery (delegates to sqlite-forensic)
  ├── browser-forensic-interpret  search-term / tracking-cookie / query-string interpretation
  └── browser-forensic-memory     byte-pattern URL/cookie scanning
      |
browser-forensic-triage      TriageReport orchestration — wires all crates into one report
      |
browser-forensic-cli         `br4n6` — dual-mode binary: scriptable CLI + interactive TUI
browser-forensic-mcp         `browser-forensic-mcp` — history/state MCP server for AI agents
                             (PII-redacted; never reads cookies, passwords, or autofill)
```

Each library crate is independently usable in your own Rust tooling. `browser-forensic-integrity`, `browser-forensic-carve`, and `browser-forensic-memory` accept `Path` or `&[u8]` — they are medium-agnostic and have no dependency on any image format or memory-dump layer.

| Crate | Description |
|---|---|
| `browser-forensic-core` | Domain types, timestamp conversions, `ForensicMeta` lookups |
| `browser-forensic-chrome` | Chromium history, cookies, downloads, bookmarks, autofill, login data, extensions, cache, session, Local State, preferences |
| `browser-forensic-firefox` | Firefox history, cookies, downloads, bookmarks, autofill, extensions, session (mozLz4), login data, preferences |
| `browser-forensic-safari` | Safari history, cookies, downloads, bookmarks, extensions, TopSites |
| `browser-forensic-discovery` | Browser profile discovery plus embedded-Chromium container sweep (macOS, Linux, Windows) |
| `browser-forensic-storage` | Web storage — Local / Session Storage and IndexedDB (Chromium via `leveldb-forensic`, Firefox via SQLite) |
| `browser-forensic-integrity` | History clearing, visit-ID gaps, timestamp anomalies, WAL presence, tombstones |
| `browser-forensic-carve` | SQLite free-page carving and WAL frame recovery (via `sqlite-forensic`) |
| `browser-forensic-interpret` | Google-search, tracking-cookie, and query-string interpretation |
| `browser-forensic-memory` | Byte-pattern URL/cookie scanning for memory forensics |
| `browser-forensic-triage` | `triage_profile()` + `triage()` → `TriageReport` |
| `browser-forensic-cli` | `br4n6` — scriptable text/JSONL/CSV CLI plus an interactive vi-keyed terminal viewer (`br4n6 tui`) |
| `browser-forensic-mcp` | `browser-forensic-mcp` — an MCP server exposing history/state to AI agents, with PII redaction and no secret readers |

---

## Using as a Library

```toml
[dependencies]
browser-forensic-chrome    = { git = "https://github.com/SecurityRonin/browser-forensic" }
browser-forensic-integrity = { git = "https://github.com/SecurityRonin/browser-forensic" }
browser-forensic-carve     = { git = "https://github.com/SecurityRonin/browser-forensic" }
```

```rust
use browser_forensic_chrome::parse_history;
use browser_forensic_integrity::{check_history_integrity, IntegrityIndicator};
use browser_forensic_core::BrowserFamily;

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
- **Panic-free parsers** — `clippy::unwrap_used` / `expect_used` are denied in production code; length and offset fields from the artifact are bounds-checked before use.
- **Fuzzed** — `cargo-fuzz` targets cover the Firefox session, SQLite history, carving, integrity, and forensic-catalog paths; every target is built and smoke-run in CI (`fuzz.yml`).
- **Coverage gate** — CI enforces a line-coverage floor via `cargo llvm-cov`; the uncovered remainder is the irreducible imperative shell of the binaries.
- **CI on Linux, macOS, and Windows** — every push runs `cargo fmt --check`, `cargo clippy -D warnings`, build, and the full test suite on all three platforms.
- **Supply-chain gate** — `cargo-deny` checks licenses, RustSec advisories, and banned dependencies on every push (`deny.toml`).

---

## RapidTriage Ecosystem

browser-forensic is one parser library in the [RapidTriage](https://github.com/SecurityRonin/rapidtriage) DFIR toolkit:

| Crate | Artifact family |
|---|---|
| [browser-forensic](https://github.com/SecurityRonin/browser-forensic) | Chrome / Firefox / Safari + embedded Chromium |
| [winevt-forensic](https://github.com/SecurityRonin/winevt-forensic) | Windows Event Logs (EVTX) |
| [srum-forensic](https://github.com/SecurityRonin/srum-forensic) | Windows SRUM / ESE |
| [memory-forensic](https://github.com/SecurityRonin/memory-forensic) | Process memory, page tables |
| [forensicnomicon](https://github.com/SecurityRonin/forensicnomicon) | Artifact catalog, format constants |

---

[Privacy Policy](https://securityronin.github.io/browser-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/browser-forensic/terms/) · © 2026 Security Ronin Ltd
