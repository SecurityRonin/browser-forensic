# Migrating to the v2 command surface

**Applies to:** `br4n6` / `bw` CLI **0.3.0 and later** (RFC 0001 — CLI UX redesign).

## Summary

The old **flat command surface was removed outright** — a clean break at a major
version, no aliases and no compatibility shims (RFC 0001 D11). The tool now speaks
a small set of **task verbs** — the questions an examiner already thinks in — over
the same 46 primitives, which live on under an `artifact <NAME>` namespace.

If a script or SOP calls an old command such as `br4n6 history …` or `br4n6 chains
…`, it will fail on 0.3.0. This page maps **every removed command to its new
form**. There is one honest way to do each thing; migration is a one-time edit.

The six task verbs:

| Verb | The question it answers |
| --- | --- |
| `investigate` | What happened? (bounded, ranked, court-safe triage — the golden path) |
| `find` | Did they visit / download / search **X**? |
| `timeline` | When — the chronology across every artifact |
| `recover` | What was deleted / carved / evicted? |
| `reconstruct` | What did a cached page look like? |
| `report` | What do I hand the lawyer? (reproducible bundle) |

Everything the old flat commands did is still here — reachable via a verb or via
`artifact <NAME>`. Run `br4n6 artifact --list` for the full primitive table.

## Per-artifact parsers → `artifact <NAME>`

The 26 per-artifact parsers moved under the `artifact` namespace. Each keeps the
exact flags its flat command had; only the two names in **bold** were renamed to
the cleaner forensic term.

| Old flat command | New form | Note |
| --- | --- | --- |
| `br4n6 history <PATH>` | `br4n6 artifact history <PATH>` | |
| `br4n6 sessions <PATH>` | `br4n6 artifact sessions <PATH>` | |
| `br4n6 cookies <PATH>` | `br4n6 artifact cookies <PATH>` | decryption flags changed — see below |
| `br4n6 downloads <PATH>` | `br4n6 artifact downloads <PATH>` | |
| `br4n6 bookmarks <PATH>` | `br4n6 artifact bookmarks <PATH>` | |
| `br4n6 extensions <PATH>` | `br4n6 artifact extensions <PATH>` | |
| `br4n6 login-data <PATH>` | **`br4n6 artifact logins <PATH>`** | renamed `login-data` → `logins` |
| `br4n6 autofill <PATH>` | `br4n6 artifact autofill <PATH>` | |
| `br4n6 session <PATH>` | `br4n6 artifact session <PATH>` | |
| `br4n6 cache <PATH>` | `br4n6 artifact cache <PATH>` | |
| `br4n6 cachestorage <PATH>` | `br4n6 artifact cachestorage <PATH>` | |
| `br4n6 preferences <PATH>` | `br4n6 artifact preferences <PATH>` | |
| `br4n6 permissions <PATH>` | `br4n6 artifact permissions <PATH>` | |
| `br4n6 credentials <PATH>` | `br4n6 artifact credentials <PATH>` | metadata only, never decrypted |
| `br4n6 storage <PATH>` | `br4n6 artifact storage <PATH>` | |
| `br4n6 webcache <PATH>` | `br4n6 artifact webcache <PATH>` | IE / Edge-Legacy ESE |
| `br4n6 indexeddb <PATH>` | `br4n6 artifact indexeddb <PATH>` | |
| `br4n6 favicons <PATH>` | `br4n6 artifact favicons <PATH>` | |
| `br4n6 top-sites <PATH>` | `br4n6 artifact top-sites <PATH>` | |
| `br4n6 shortcuts <PATH>` | `br4n6 artifact shortcuts <PATH>` | |
| `br4n6 predictor <PATH>` | **`br4n6 artifact network-action-predictor <PATH>`** | renamed `predictor` → `network-action-predictor` |
| `br4n6 media-history <PATH>` | `br4n6 artifact media-history <PATH>` | |
| `br4n6 extension-cookies <PATH>` | `br4n6 artifact extension-cookies <PATH>` | |
| `br4n6 typed-input <PATH>` | `br4n6 artifact typed-input <PATH>` | |
| `br4n6 annotations <PATH>` | `br4n6 artifact annotations <PATH>` | |
| `br4n6 deleted-bookmarks <PATH>` | `br4n6 artifact deleted-bookmarks <PATH>` | |

## Correlation / chronology → `timeline`

`timeline` is one verb over what were three synonym commands. Correlation is
co-occurrence by URL / host / time — never proof of intent or causation.

| Old flat command | New form | Note |
| --- | --- | --- |
| `br4n6 correlate <PATH>` | `br4n6 timeline <PATH>` | the default unified chronology |
| `br4n6 chains <PATH>` | `br4n6 timeline <PATH> --chains` | referrer / redirect / inferred-session view |
| `br4n6 graph <PATH>` | `br4n6 timeline <PATH> --graph <json\|dot>` | the registrable-host entity graph |

## Search / IOC extraction → `find`

`find` is the single front door for "did they touch X?", carrying per-hit
provenance (source · state · confidence · time-basis · user-action) so a live
history hit, a carved string, and a recovered domain stay distinct rows.

| Old flat command | New form | Note |
| --- | --- | --- |
| `br4n6 search <TERM> <PATH>` | `br4n6 find <TERM> <PATH>` | TERM is auto-classified (domain / url / ip / hash / regex) |
| `br4n6 extract-iocs <PATH>` | `br4n6 find --iocs <PATH>` | enumerate all candidate IOCs, no query term |
| `br4n6 match-domains <FILE> <PATH>` | `br4n6 find @<FILE> <PATH>` | `@file` reads a term list; or `--terms-file <FILE>` |

## Deleted / carved / evicted evidence → `recover`

`recover` is one orchestrator: point it at a profile, a single SQLite database, or
a memory image and it runs every applicable recovery and ranks the results — no
submode to choose. Recovered items are *consistent-with* eviction/clearing, never
asserted as a deliberate user deletion.

| Old flat command | New form | Note |
| --- | --- | --- |
| `br4n6 carve <PATH>` | `br4n6 recover <PATH>` | deleted SQLite / WAL records |
| `br4n6 cache-carve <PATH>` | `br4n6 recover <PATH>` | orphaned / evicted cache |
| `br4n6 recovered-domains <PATH>` | `br4n6 recover <PATH>` | Network Persistent State / NEL / DIPS / HSTS domains |
| `br4n6 tamper-check <PATH>` | `br4n6 recover <PATH>` | tamper / anti-forensic indicators |
| `br4n6 memory <IMAGE>` | `br4n6 recover <IMAGE>` | process-attributed RAM carve (a memory image path) |

Specialists who want a single targeted run can still reach the primitives directly
(`br4n6 integrity`, `br4n6 image`, and the `br4n6 artifact <NAME>` parsers such as
`artifact deleted-bookmarks`); `br4n6 recover --help` points at them.

## Cached-page reconstruction → `reconstruct`

| Old flat command | New form | Note |
| --- | --- | --- |
| `br4n6 show <URL> <PATH>` | `br4n6 reconstruct <URL> <PATH>` | output is phrased "cached representations consistent with access to `<URL>`" — the cache shows what was *stored*, not what a human saw (D6) |

## Decryption flag soup → `--keys` / `--reveal-secrets` / `--password-stdin`

The platform-specific, multi-flag decryption incantations collapsed into one
evidence-root-constrained `--keys` flag (RFC 0001 D7). Key material is auto-located
**within the evidence root** (never outside it), every key file is hashed into the
manifest, and secrets are file-output-oriented — never printed to the terminal.

| Old flags | New form | Note |
| --- | --- | --- |
| `--decrypt-macos` | `br4n6 artifact cookies <PATH> --keys <PATH>` | on a live macOS host, refine with `--keychain-service "<Service> Safe Storage"` |
| `--decrypt-win --local-state <LS> --dpapi-masterkey <MK>` | `br4n6 artifact cookies <PATH> --keys <PATH> --password-stdin` | `--keys` auto-locates Local State + DPAPI masterkeys inside the root; the logon password is read from stdin, never argv |
| `--decrypt --include-passwords` (logins) | `br4n6 artifact logins <PATH> --keys <PATH> --reveal-secrets <FILE>` | usernames show; passwords materialize to `<FILE>` only, never the terminal |

Without `--keys`, encrypted material is **counted and reported**, never silently
dropped (e.g. `1,022 cookies encrypted — add --keys <path>`).

## What did *not* change

These commands kept their names: `browsers`, `profiles`, `triage`, `integrity`,
`analyze`, `image`, `export`, `manifest`, `schema`, `tui`. The `bw` short binary
name is retained as a convenience alias for `br4n6`.

## Shell completions

Regenerate your completions after upgrading so tab-completion matches the new
surface: `br4n6 completions <bash|zsh|fish>` writes a script to stdout.
