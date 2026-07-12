# browser-forensic — Product Requirements

## Executive Summary

browser-forensic is a single static Rust binary, `br4n6`, that turns browser
evidence into one normalized JSON timeline. Point it at a database and get JSON;
point it at a profile and get a triage report with integrity indicators and
carved deleted records; point it at an evidence tree and it sweeps out every
browser and every embedded-Chromium app it can structurally identify.

The target user is a DFIR analyst or incident responder who needs browser
artifacts parsed the same way regardless of which browser produced them, with no
Python runtime, no Windows lock-in, and no need to trust that the evidence was
untampered. Every supported browser emits the same `BrowserEvent` schema, so a
downstream pipeline never branches on the source browser.

```bash
br4n6 triage --home /mnt/evidence/Users/jsmith --format jsonl > report.jsonl
```

One command discovers every profile under a home directory, parses every
artifact, runs integrity checks, and carves free pages — into a single JSON
stream.

## Personas and use cases

**DFIR analyst reconstructing a timeline.** Parses history, downloads, and
sessions across Chrome, Firefox, and Safari into one chronological event stream,
correlated and exportable to XLSX or SQLite for review in the examiner's
timezone.

**Incident responder triaging a host image.** Sweeps an evidence tree for every
browser profile and every embedded-Chromium container (Slack, Teams, OneDrive,
and other Electron / WebView2 / CEF apps), then runs a full triage in a single
pass.

**Examiner testing for anti-forensics.** Runs integrity checks that surface
history clearing, visit-ID gaps, timestamp anomalies, and WAL presence, and
carves deleted records from SQLite free pages and WAL frames to establish what
was removed and what survived.

**Rust tool author.** Embeds the library crates directly. The parser, integrity,
carve, and memory crates accept a `Path` or `&[u8]` and carry no dependency on an
image format or memory-dump layer.

**AI-agent operator.** Runs the `browser-forensic-mcp` server to give an agent
bounded, allow-listed, PII-redacted browsing context — history and open-tab state
only, never cookies, passwords, or autofill.

## Supported browsers

| Family | Members |
|---|---|
| Chromium | Chrome, Edge, Brave, Opera, Vivaldi, Arc — one engine, one parser set |
| Firefox | Firefox |
| Safari | Safari |

**Embedded-Chromium apps.** Modern desktop apps embed Chromium and keep the same
history, cookies, and web-storage databases a browser does. The container sweep
identifies Electron, WebView2, and CEF containers by their structural profile
markers and attributes each to its owning app where the catalog recognizes it. A
profile-shaped directory that matches no catalog entry is still reported,
generically labelled.

## Artifacts parsed

| Artifact | Chromium | Firefox | Safari |
|---|:-:|:-:|:-:|
| History | yes | yes | yes |
| Cookies | yes | yes | yes |
| Downloads | yes | yes | yes |
| Bookmarks | yes | yes | yes |
| Extensions / Add-ons | yes | yes | yes |
| Autofill | yes | yes | — |
| Login Data (passwords never exposed) | yes | yes | — |
| Cache | yes | yes | — |
| Session state | yes | yes | — |
| Preferences | yes | yes | — |
| Top Sites | — | — | yes |
| Profile metadata (Local State) | yes | — | — |
| Web Storage (Local / Session / IndexedDB) | yes | yes | — |
| Integrity indicators | yes | yes | yes |
| SQLite free-page carving | yes | yes | yes |
| WAL recovery | yes | yes | yes |

**Login data** is parsed for record metadata; stored passwords are never
decrypted or surfaced. **Chrome cookie values** stay encrypted and are never
surfaced; cookie interpretation runs only where a plaintext value exists
(Firefox). **Web storage** covers Chromium Local and Session Storage (LevelDB)
and IndexedDB (LevelDB-backed), plus Firefox SQLite web storage; IndexedDB values
are Blink/v8-serialized and surfaced as opaque raw records rather than a
fabricated decode.

**Container discovery** walks an evidence tree and reports every browser profile
and embedded-Chromium container found, with app name, vendor, and embedding kind.

## Integrity indicators

`br4n6 integrity` reports observable structural anomalies, not forensic
conclusions: `HistoryCleared` / `AutoIncrementGap` (the `sqlite_sequence` counter
recorded more insertions than rows remain), `VisitIdGap` (non-contiguous visit
IDs), `TimestampNonMonotonic`, `CookieTimestampAnomaly` (access predates
creation), `WalPresent`, `SqliteIntegrityFailure` (`PRAGMA integrity_check`),
`HistoryTombstoneFound` (Safari deleted-history tombstones), and
`DownloadFileMissing`. Each names the offending value and location.

## Interpretation engine

`--interpret` adds a human-readable interpretation to each event — a clean-room
reimplementation of the Hindsight interpretation plugins. It extracts Google
search terms and options, decodes any URL's query string into key/value pairs,
and decodes tracking cookies (Google Analytics `__utm*` / `_ga`, Quantcast
`__qca`, F5 BIG-IP `BIGipServer*` backend `IP:port`), plus a generic
embedded-timestamp scan. Timestamp units (Unix seconds / millis / micros or
WebKit) are inferred from magnitude, not declared by the caller.

## Forensic guarantees

- **Read-only on evidence.** SQLite is opened read-only; when a `-wal` sidecar is
  present the database and WAL are copied to a temporary location and the copy is
  opened, so the original file, its timestamps, and its free pages stay intact for
  re-examination. The tool never writes back to an artifact.
- **`forbid(unsafe)`.** The entire workspace denies `unsafe` at compile time.
- **Panic-free parsers.** `clippy::unwrap_used` / `expect_used` are denied in
  production code; length and offset fields from the artifact are bounds-checked
  before use. Every untrusted-input parser has a `cargo-fuzz` target built and
  smoke-run in CI.
- **Reproducible.** `timestamp_ns` is always Unix nanoseconds in UTC; the same
  input yields the same output.
- **Timezone-explicit.** Human-facing timestamps render in an IANA timezone the
  examiner names with `--timezone`; the machine timestamp stays UTC nanoseconds.
- **Supply-chain gate.** `cargo-deny` checks licenses, advisories, and banned
  dependencies; CI runs on Linux, macOS, and Windows.

## Outputs

Every command shares the `BrowserEvent` envelope: `timestamp_ns` (Unix
nanoseconds), `browser`, `artifact`, `source`, `description`, and an `attrs` map.

| Format | Availability |
|---|---|
| `text` | all commands — human-readable, one line per record |
| `jsonl` | all commands — newline-delimited JSON, one object per line |
| `csv` | all commands — header row plus escaped rows |
| `xlsx` | `br4n6 export` — one Timeline sheet, timezone-rendered |
| `sqlite` | `br4n6 export` — one `timeline` table for ad-hoc SQL |

`br4n6 export` collects a single correlated timeline from a profile or home
directory; `xlsx` and `sqlite` require `-o FILE`, while `text` / `jsonl` / `csv`
stream.

## Interfaces

- **`br4n6`** — the scriptable CLI (subcommands for each artifact plus
  `browsers`, `history`, `sessions`, `storage`, `export`, `profiles`, `analyze`,
  `integrity`, `carve`, `triage`) and, with no subcommand or `br4n6 tui`, an
  interactive vi-keyed terminal viewer for session state.
- **Library crates** — each of the thirteen crates is independently usable in
  Rust tooling.
- **`browser-forensic-mcp`** — an MCP server exposing history and open-tab state
  to AI agents, allow-listed and PII-redacted, with no secret readers.

## Non-goals and not built

- **No password or encrypted-value decryption.** Login-data passwords and
  Chrome-encrypted cookie values are never decrypted or surfaced, by design.
- **No IndexedDB value decode.** IndexedDB values are surfaced as opaque
  Blink/v8-serialized records, not decoded into structured fields.
- **Safari artifact gaps.** Safari autofill, login data, cache, preferences, and
  web storage are not parsed.
- **MCP surface is bounded to three tools.** `browsing_context`,
  `did_user_visit`, and `list_browsers` ship today; there is no unbounded
  history dump and no cookie/password/autofill tool.
- **No cross-device or cloud-sync correlation**, and no evidence acquisition or
  imaging — the suite reads artifacts already on disk (or in memory) and leaves
  acquisition to the tools built for it.
