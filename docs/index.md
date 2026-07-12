# browser-forensic

**Parse Chrome, Firefox, and Safari — and embedded-Chromium apps — into one JSON timeline. Detect history clearing. Carve deleted records. No runtime deps.**

```bash
cargo install --git https://github.com/SecurityRonin/browser-forensic browser-forensic-cli
br4n6 triage --home ~ --format jsonl
```

**[GitHub Repository →](https://github.com/SecurityRonin/browser-forensic)**

---

## What it does

`br4n6` parses browser artifacts from Chrome, Firefox, and Safari — history, cookies, downloads, bookmarks, extensions, autofill, login metadata, cache, session state, preferences, and web storage (Local / Session Storage, IndexedDB) — and outputs a consistent JSON event stream regardless of which browser produced the data.

Beyond parsing, it detects structural integrity anomalies that indicate history was cleared or records were tampered with, carves deleted records from SQLite free pages and WAL files, interprets search terms and tracking cookies, scans raw memory byte sequences for URL and cookie patterns, and sweeps an evidence tree for embedded-Chromium containers (Electron / WebView2 / CEF apps such as Slack, Teams, and OneDrive).

---

## Quick start

```bash
# Parse Chrome history
br4n6 history /path/to/Chrome/Default/History --format jsonl

# Parse web storage (Local / Session Storage, IndexedDB)
br4n6 storage /path/to/Chrome/Default --format jsonl

# Detect tampering indicators
br4n6 integrity /path/to/Chrome/Default/History --format jsonl

# Carve deleted records
br4n6 carve /path/to/Chrome/Default/History --format jsonl

# Sweep an evidence tree for browsers AND embedded-Chromium apps
br4n6 browsers --sweep /mnt/evidence/Users/jsmith --format jsonl

# Full triage — discovers all profiles, parses all artifacts, checks integrity
br4n6 triage --home /mnt/evidence/Users/jsmith --format jsonl > report.jsonl
```

---

## Browser coverage

| Artifact | Chrome / Chromium¹ | Firefox | Safari |
|---|:-:|:-:|:-:|
| History | ✓ | ✓ | ✓ |
| Cookies | ✓ | ✓ | ✓ |
| Downloads | ✓ | ✓ | ✓ |
| Bookmarks | ✓ | ✓ | ✓ |
| Extensions / Add-ons | ✓ | ✓ | ✓ |
| Autofill | ✓ | ✓ | — |
| Login Data (no passwords) | ✓ | ✓ | — |
| Cache | ✓ | ✓ | — |
| Session State | ✓ | ✓ | — |
| Preferences | ✓ | ✓ | — |
| Top Sites | — | — | ✓ |
| Profile Metadata | ✓ | — | — |
| Web Storage (Local / Session / IndexedDB) | ✓ | ✓ | — |
| Integrity indicators | ✓ | ✓ | ✓ |
| SQLite free-page carving | ✓ | ✓ | ✓ |
| WAL recovery | ✓ | ✓ | ✓ |

¹ Chromium-family covers Chrome, Edge, Brave, Opera, Vivaldi, and Arc — one engine, one set of parsers.

---

## Crate map

| Crate | Description |
|---|---|
| `browser-forensic-core` | Domain types, timestamp conversions, ForensicMeta |
| `browser-forensic-chrome` | Chromium artifact parsers (Chrome, Edge, Brave, Opera, Vivaldi, Arc) |
| `browser-forensic-firefox` | Firefox artifact parsers |
| `browser-forensic-safari` | Safari artifact parsers |
| `browser-forensic-discovery` | Profile discovery + embedded-Chromium container sweep |
| `browser-forensic-storage` | Web storage — Local / Session Storage, IndexedDB (reuses `leveldb-forensic`) |
| `browser-forensic-integrity` | Tampering and clearing detection |
| `browser-forensic-carve` | SQLite free-page and WAL recovery (via `sqlite-forensic`) |
| `browser-forensic-interpret` | Search-term / tracking-cookie / query-string interpretation |
| `browser-forensic-memory` | Byte-pattern URL/cookie scanning |
| `browser-forensic-triage` | Triage orchestration → `TriageReport` |
| `browser-forensic-cli` | `br4n6` dual-mode CLI + TUI binary |
| `browser-forensic-mcp` | History/state MCP server for AI agents (PII-redacted, no secret readers) |

---

## RapidTriage ecosystem

browser-forensic is the browser parser in the [RapidTriage](https://github.com/SecurityRonin/rapidtriage) DFIR toolkit alongside [winevt-forensic](https://github.com/SecurityRonin/winevt-forensic), [srum-forensic](https://github.com/SecurityRonin/srum-forensic), [memory-forensic](https://github.com/SecurityRonin/memory-forensic), and [forensicnomicon](https://github.com/SecurityRonin/forensicnomicon).

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · [GitHub](https://github.com/SecurityRonin/browser-forensic) · © 2026 Security Ronin Ltd.
