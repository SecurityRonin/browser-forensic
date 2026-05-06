# browser-forensic

**Parse Chrome, Firefox, and Safari artifacts. Detect history clearing. Carve deleted records. No runtime deps.**

```bash
cargo install --git https://github.com/SecurityRonin/browser-forensic bw-cli
bw triage --home ~ --format jsonl
```

**[GitHub Repository →](https://github.com/SecurityRonin/browser-forensic)**

---

## What it does

`bw` parses browser artifacts from Chrome, Firefox, and Safari — history, cookies, downloads, bookmarks, extensions, autofill, login metadata, cache, and session state — and outputs a consistent JSON event stream regardless of which browser produced the data.

Beyond parsing, it detects structural integrity anomalies that indicate history was cleared or records were tampered with, carves deleted records from SQLite free pages and WAL files, and can scan raw memory byte sequences for URL and cookie patterns.

---

## Quick start

```bash
# Parse Chrome history
bw history /path/to/Chrome/Default/History --format jsonl

# Detect tampering indicators
bw integrity /path/to/Chrome/Default/History --format jsonl

# Carve deleted records
bw carve /path/to/Chrome/Default/History --format jsonl

# Full triage — discovers all profiles, parses all artifacts, checks integrity
bw triage --home /mnt/evidence/Users/jsmith --format jsonl > report.jsonl
```

---

## Browser coverage

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
| Profile Metadata | ✓ | — | — |
| Integrity indicators | ✓ | ✓ | ✓ |
| SQLite free-page carving | ✓ | ✓ | ✓ |
| WAL recovery | ✓ | ✓ | ✓ |

---

## Crate map

| Crate | Description |
|---|---|
| `browser-core` | Domain types, timestamp conversions, ForensicMeta |
| `browser-chrome` | Chrome/Chromium/Edge/Brave artifact parsers |
| `browser-firefox` | Firefox artifact parsers |
| `browser-safari` | Safari artifact parsers |
| `browser-discovery` | Cross-platform browser profile discovery |
| `browser-integrity` | Tampering and clearing detection |
| `browser-carve` | SQLite free-page and WAL recovery |
| `browser-memory` | Byte-pattern URL/cookie scanning |
| `browser-rt` | RapidTriage orchestration |
| `bw-cli` | `bw` CLI binary |

---

## RapidTriage ecosystem

browser-forensic is the browser parser in the [RapidTriage](https://github.com/SecurityRonin/rapidtriage) DFIR toolkit alongside [winevt-forensic](https://github.com/SecurityRonin/winevt-forensic), [srum-forensic](https://github.com/SecurityRonin/srum-forensic), [memory-forensic](https://github.com/SecurityRonin/memory-forensic), and [forensicnomicon](https://github.com/SecurityRonin/forensicnomicon).

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · [GitHub](https://github.com/SecurityRonin/browser-forensic) · © 2026 Security Ronin Ltd.
