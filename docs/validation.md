# Validation

How every capability in `browser-forensic` is checked, by which independent
oracle, and at what tier. This is the trust document: it states what an examiner
can rely on, what is checked only against synthetic construction, and where the
honest gaps are.

## How to read this

Tiers follow the project's evidence standard — the axis is *who confirms the
answer*, not whether the data is synthetic:

* **Tier 1** — an independent third party authored the artifact *and* the answer
  key, or the data is real-world (a browser wrote it, the OS hashed it, an
  unrelated tool decoded it).
* **Tier 2** — real engine/tool output whose ground truth is derivable from the
  documented construction or confirmed by an independent oracle. Genuinely
  checked, but the scenario was chosen here.
* **Tier 3** — fixture and expected answer both authored here. Legitimate for
  *detection rules* (correctness is defined by the rule + spec) and robustness
  tests; never the sole check on a value-producing path that an oracle could
  cross-check.

**Env-gate philosophy.** Every check against real browser data is an env-gated
oracle test that **skips cleanly** when the artifact or the reference tool is
absent, so CI stays green on a minimal image and no personal data is committed
(fleet Test-Data Provenance Standard). The real corpora are copied to an
ephemeral location, read there, and never committed; small clearly-licensed
fixtures are committed with provenance in the owning crate's `tests/data/`. The
counts quoted below were observed during development on real artifacts; re-run
the named test with its env var set to reproduce.

## Consolidated map

| Capability | Independent oracle | Tier | Env-gate / test | Committed data |
|---|---|---|---|---|
| Chromium coverage parsers (Favicons, Top Sites, Shortcuts, Network Action Predictor, Media History, Extension Cookies) | `sqlite3` CLI row counts | 1 | `BR4N6_REAL_PROFILE` · chrome `coverage_oracle` | no |
| Chromium recovered-domain parsers (DIPS, NEL, CHIPS, Extension Cookies) | `sqlite3` + `jq` | 1 | `BR4N6_REAL_PROFILE` · chrome `recovered_domains_oracle` | no |
| Chromium credential/account metadata (Login Data, Web Data, Preferences) | independent query/walk of same source + no-secret-leak assertion | 1 | `BR4N6_LOGIN_DATA` / `BR4N6_WEB_DATA` / `BR4N6_CHROME_PREFERENCES` · cli `credentials_oracle` | no |
| **Firefox history / downloads / cookies (Milestone 10)** | **dumpzilla** (independent Python tool) + `sqlite3` bridge | 1 | `BR4N6_FIREFOX_PROFILE` + `BR4N6_DUMPZILLA` + `sqlite3` · firefox `dumpzilla_differential` | no |
| Firefox parsers, structural | real Mozilla-written `places.sqlite` | 1 | `BR4N6_FIREFOX_PROFILE` · firefox `real_profile_gated` | no |
| Navigation reconstruction (Milestone 3) | real Chrome `History` / Firefox `places.sqlite`, structural invariants | 1 | `BR4N6_CHROME_HISTORY` / `BR4N6_FIREFOX_PLACES` · cli `reconstruct_oracle` | no |
| Chromium cache decode (SimpleCache) | `curl` SHA-256 of same URL, byte-for-byte | 1 | `BFCACHE_CHROME_CACHE_DIR` · cache `chrome_oracle` | no |
| Firefox cache decode (`cache2/entries`) | `curl` SHA-256, byte-for-byte | 1 | `BFCACHE_FIREFOX_ENTRIES_DIR` · cache `firefox_oracle` | no |
| Safari / `CFURLCache` `Cache.db` | on-disk structure over 273 real DBs (15 836 bodies) | 1/2 | `BFCACHE_SAFARI_DB` · cache `safari_oracle` | no |
| Service Worker CacheStorage | on-disk structure; `protoc --decode_raw` + CCL `ccl_chromium_cache` on same bytes | 1 | `BFCACHE_CACHESTORAGE_DIR` · cache `cachestorage_oracle` | no |
| Page reconstruction from cache | real Chromium cache; sub-resources inlined, misses listed | 1 | `BFRECON_CHROME_CACHE_DIR` · reconstruct `chrome_reconstruct_oracle` | no |
| Chromium IndexedDB decode | **CCL `ccl_chromium_indexeddb`** (Alex Caithness) differential, byte-identical values | 1 | `BR4N6_IDB_DIR` + `BR4N6_IDB_EXPECT` · storage `indexeddb_oracle` | no |
| SQLite free-page / freeblock carving | real SQLite engine builds + deletes; ground truth from documented construction | 2 | carve `recovery_via_sqlite_forensic` | fixture built at runtime |
| Integrity / tampering indicators | real SQLite engine mutates a copy; detector fires on changed, silent on pristine | 2 | integrity `controlled_scenarios` | fixture built at runtime |
| Interpretation engine (Hindsight-style) | OS `date -u` for timestamps; documented provider params; Python `struct` for BIG-IP | 1/2 | interpret `plugins`, `search_query` | vectors in-test |
| File hashing (SHA-256 / MD5) | OS `shasum -a 256` / `md5` (or coreutils) | 1 | manifest `system_oracle` | no |
| DFIR-interop serializers (TSK bodyfile / mactime 3.x, plaso `l2t_csv`, XLSX) | 11-field bodyfile contract; XLSX read back with `calamine` | 1/2 | cli `report` | no |
| IOC extractors (email, IPv4/IPv6, crypto address, card) | std `Ipv4Addr`/`Ipv6Addr` parsers as oracle; documented vectors | 2/3 | search `ioc_*` | vectors in-test |
| Firefox NSS decryption (opt-in) | **firepwd** (independent) | 1 (PBES2) | decrypt fixtures — see below | yes (synthetic) |
| macOS Chromium `v10` decryption (opt-in) | live Chrome + real login-Keychain key | 1 | see below | no |
| Windows Chromium DPAPI decryption (opt-in) | **impacket** on synthetic `[MS-DPAPI]` vectors; NIST CAVP for the GCM primitive | 2 (1 primitive) | decrypt vectors — see below | yes (synthetic) |

## Parsing correctness — counts reconciled against independent tools

The core forensic claim is that browser-forensic's parsers extract the same
records an independent tool does. Each parser family is differenced against a
tool that reads the same on-disk artifact:

* **Chromium (Brave/Edge/Chrome)** — the Milestone-4 coverage parsers and the
  recovered-domain parsers (DIPS, NEL, CHIPS partitioned cookies, Extension
  Cookies) are counted against the `sqlite3` CLI (and `jq` for JSON-backed
  sources) running the equivalent query over a WAL-honoring copy of the same
  database. The CLI is the independent actor; agreement on the row count is the
  answer key.
* **Firefox — dumpzilla differential (Milestone 10).** browser-forensic's
  `parse_history`, `parse_downloads`, and `parse_cookies` are reconciled against
  [dumpzilla](https://github.com/Busindre/dumpzilla), an unrelated Python
  forensic tool that reads the same `places.sqlite` / `cookies.sqlite`. The two
  parsers apply different documented `WHERE`-clauses — an *interpretation*
  difference, not a bug — so each count reconciles against dumpzilla's total
  minus a precise bridge quantity computed by the neutral `sqlite3` CLI:

  | Count | browser-forensic emits | dumpzilla emits | bridge (never in browser-forensic) |
  |---|---|---|---|
  | history | visited places (`last_visit_date IS NOT NULL`) | all `moz_places` | places never visited (`last_visit_date IS NULL`) — bookmark/redirect/download-source URLs |
  | downloads | `moz_annos` attr `downloads/destinationFileURI` | `moz_annos` `content LIKE 'file%'` | file-content annotations that are not `destinationFileURI` |
  | cookies | `moz_cookies` `creationTime > 0` | all `moz_cookies` | cookies with `creationTime <= 0` |

  `browser-forensic + bridge == dumpzilla_total` proves the two independently
  authored parsers partition the same universe; browser-forensic emits the
  forensically-meaningful subset (an event only where a visit/download/cookie
  actually exists). Observed on a real profile: history `901 + 4 == 905`,
  downloads `0 + 0 == 0`, cookies `419 == 419` (exact — that profile's cookies
  all carry a positive creation time). The evidence is never touched: the DBs
  are copied to a temp dir and both tools run on the copy, because dumpzilla
  opens SQLite read-write.

* **Chromium credential/account metadata (Milestone 14)** — the Login Data, Web
  Data, and Preferences parsers are counted against an independent walk of the
  same source, and every event is additionally asserted to carry **no encrypted
  secret** (passwords and encrypted cookie values are never surfaced, by design).

## Cache decode — cross-checked against `curl`

Compressed cache bodies are decoded and the plaintext compared byte-for-byte to
`curl` of the same URL:

* **Chromium SimpleCache** — decoded brotli bodies for two immutable,
  content-hashed `iana.org` assets (78 748 B JS, 82 866 B CSS) matched `curl`'s
  SHA-256 exactly.
* **Firefox `cache2`** — a content-hashed `gstatic.com` SVG (688 stored bytes,
  brotli wire-compressed) decoded to the same SHA-256 as `curl`.
* **Safari / `CFURLCache`** — examined across 273 real `Cache.db` files (15 836
  bodies): `CFURLCache` usually stores the already-decoded body and occasionally
  the wire-compressed one; the oracle asserts this holds without any decode
  silently failing. Opened read-only + immutable.
* **Service Worker CacheStorage** — ground truth derived from the on-disk
  structure itself (every cache named in `index.txt` exists; recovered-resource
  count equals the parsing `_0` SimpleCache entries), with the metadata proto
  additionally cross-checked against `protoc --decode_raw` and CCL
  `ccl_chromium_cache`.

## Web storage — IndexedDB differential against CCL

Chromium IndexedDB decode is differenced against **CCL `ccl_chromium_indexeddb`**
(Alex Caithness' reverse-engineering reference). Every `{store, key, value}`
tuple CCL decodes must be present and byte-identical among browser-forensic's
events (browser-forensic may surface *more* — superseded and tombstoned records).
Observed byte-for-byte match on real stores from five Chromium/Electron apps —
WhatsApp Web (51/51), Ludwig (314/314), Reddit (2/2), LinkedIn (1/1), GoTo
(1/1): 369/369 tuples identical. IndexedDB *values* are surfaced as opaque
Blink/v8-serialized records, not decoded into structured fields (by design).

## Carving and integrity — real-engine controlled scenarios (tier 2)

* **Carving** — `carve_sqlite_free_pages` recovers a deleted history row from an
  in-page **freeblock** (the dominant deletion pattern: deleting a row frees a
  cell in place, so a free-*page* scan alone finds nothing). The fixture is built
  by the real SQLite engine via rusqlite, then rows are deleted; ground truth is
  the documented construction, not a hand-encoded fixture. The recovered row is
  attributed to its real table.
* **Integrity indicators** — a real SQLite database is built, a baseline
  recorded, then one specific anomaly applied to a copy (history clearing,
  visit-ID gap, non-monotonic timestamp, cookie access-before-creation, …). Each
  detector must **fire on the changed copy and stay silent on the pristine
  one**. The engine is the independent actor; the scenario was chosen here, so
  this is tier 2.

## Interpretation, hashing, serializers, IOCs

* **Interpretation engine** — a clean-room reimplementation of the Hindsight
  interpretation plugins. Expected timestamp renderings are cross-checked against
  the OS `date -u` oracle; search-term extraction uses the percent-decoded value
  of each provider's documented query parameter (a fact read from the URL); the
  F5 BIG-IP cookie vector is verified independently with Python `struct`.
* **File hashing** — SHA-256 / MD5 of a real file must equal the OS's own
  `shasum -a 256` / `md5` (or GNU coreutils), an independent third-party
  implementation shipped with the OS.
* **DFIR-interop serializers** — the TSK bodyfile output holds exactly 11
  pipe-delimited fields (mactime 3.x contract) with pipes in values sanitized to
  preserve the field count; plaso `l2t_csv` and the XLSX export are read back
  (XLSX via `calamine`) and reconciled against the source events.
* **IOC extractors** — email / IPv4 / IPv6 / crypto-address / card detectors are
  checked with the standard-library `Ipv4Addr`/`Ipv6Addr` parsers as the oracle
  (out-of-range octets rejected) and documented vectors. These are detection
  rules: correctness is defined by the rule + spec, legitimately tier 2/3.

## Decryption (opt-in) — per-path validation

Decryption is opt-in, never fabricates plaintext (a wrong/absent key or a failed
tag/signature/padding is always a typed `Err`), and uses audited RustCrypto
primitives only. Every path is checked as follows.

### macOS Chromium `v10` — tier 1

A throwaway cookie `br4n6probe` on host `127.0.0.1` was written by a live Chrome,
then its real `Cookies` ciphertext decrypted with the real macOS login-Keychain
"Chrome Safe Storage" key. The recovered plaintext was
`SHA-256("127.0.0.1") || "br4n6-tier1-probe-7f3a91c2"` — the planted known value
recovered exactly behind the 32-byte domain-binding prefix that Chromium cookie
schema v24+ prepends (`net/extras/sqlite/sqlite_persistent_cookie_store.cc`).
Both the value and the key material were held outside this code (Chrome + the OS
Keychain), so the answer key is independent. `strip_domain_hash_prefix` removes
and verifies that prefix; a 32-byte prefix that is not `SHA-256(host_key)` is
surfaced raw with `domain_bound=false` rather than silently stripped. The
AES-128-CBC + PBKDF2 primitive is additionally cross-checked against a Python
`hashlib` + `cryptography` oracle under an externally-fixed key (tier 2).

### Firefox NSS — tier 1 (PBES2)

The `ff3des` (legacy `pbeWithSha1AndTripleDES-CBC`) and `ffpbes2` (modern
PKCS#5 PBES2, PBKDF2-HMAC-SHA256 → AES-256-CBC) fixtures carry known credentials
and were decrypted by the unrelated **firepwd** tool. On `ffpbes2` firepwd
recovered the exact `alice@example.com` / `S3cr3t-Passw0rd!` pair. On `ff3des`
firepwd confirmed the password-check and unwrapped the master key; its `main()`
cannot complete the 3DES login loop, so the 3DES login-blob step falls back to
the shared, firepwd-confirmed ASN.1 decoder plus standard 3DES-CBC. Provenance
in `crates/browser-forensic-decrypt/tests/data/README.md`.

### Windows Chromium (DPAPI + AES-256-GCM) — tier 2 (tier 1 primitive)

**No Windows profile exists on the build host, so this path is NOT validated
end-to-end against a real Windows profile.** The DPAPI format + crypto (master-
key file KDF, blob decrypt + session-key derivation, `Local State` key) is
delegated to the audited, fuzz-hardened, impacket-validated fleet crate
`dpapi-core`; this crate keeps only thin glue plus its own AES-256-GCM `v10`/`v11`
value decryption and the `v20` App-Bound refusal.

| Path | Validation | Tier |
|---|---|---|
| `decrypt_chromium_value_win` (`v10`/`v11`) | RustCrypto `aes-gcm` decrypts a PyCryptodome-oracle value under an externally-fixed key → known plaintext; flipped tag → `Err`. | 2 |
| AES-256-GCM primitive | NIST CAVP KAT (`gcmEncryptExtIV256`, published tag `bdc1ac88…76f0`) verifies; flipped tag → `Err`. | 1 |
| `decrypt_masterkey_file` (→ `dpapi-core`) | A synthetic master-key file to the `[MS-DPAPI]` layout is decrypted by **impacket** to the same 64-byte key; `dpapi-core` recovers the same; wrong password → `WrongDpapiPassword` (rejected by impacket too). | 2 |
| `decrypt_dpapi_blob` (→ `dpapi-core`) | impacket decrypts the same synthetic blob to the same 32-byte Chromium key; `dpapi-core` recovers it independently; tampering → `Err`. | 2 |
| `decrypt_chromium_key_dpapi` (Local State, → `dpapi-core`) | End-to-end `base64("DPAPI"+blob)` → the 32-byte key, via a supplied master key and via password+SID+master-key file. | 2 |
| `v20` App-Bound detection | Refused with `AppBoundUnsupported` (needs the SYSTEM key); never fabricated. | 2 |

"Tier-2, impacket-confirmed" means: the DPAPI encoder in `tests/data/gen_win.py`
is written to the `[MS-DPAPI]` spec; impacket (unrelated third-party code)
recovering the known keys from those synthetic artifacts — and rejecting a wrong
password — confirms the artifacts are genuine DPAPI structures. It is *not* a
real-Windows-profile validation. Only the modern `CALG_SHA_512` + `CALG_AES_256`
pair is supported; other algorithm ids are refused loudly with the offending
value; legacy 3DES/SHA1 blobs are rejected with `UnsupportedAlgorithm`. The DPAPI
blob + Local State parsers are exercised by the `fuzz_decrypt_dpapi` cargo-fuzz
target (must-not-panic).

## Honest gaps

* **Windows Chromium DPAPI is not validated on a real Windows profile** — no
  Windows host is available; the path is tier-2 (impacket on synthetic
  `[MS-DPAPI]` vectors) with a tier-1 NIST CAVP check on the GCM primitive.
* **Safari coverage is partial by design** — autofill, login data, cache,
  preferences, and web storage are not parsed; the cache decode above covers the
  shared `CFURLCache` `Cache.db` only.
* **IndexedDB values are opaque** — surfaced as Blink/v8-serialized records, not
  decoded into structured fields (by design).
* **Real-data oracle tests skip in CI** — real browser data is not
  redistributable, so every count above is reproduced by re-running the named
  test with its env var set, not by CI.
* **The Milestone-10 differential covers Firefox via dumpzilla on macOS.**
  dumpzilla is the differential-parser tool exercised on this host. **Hindsight**
  (Chrome, Python) is a candidate second differential and is not run here.
  **NirSoft** (BrowsingHistoryView / ChromeCookiesView) is **Windows-only and
  unavailable on this macOS host**; it is documented here as a future
  cross-check rather than an executed one.

## The four hard rules (decryption paths)

1. **RustCrypto only** — every primitive is an audited crate (`aes`, `aes-gcm`,
   `cbc`, `des`, `pbkdf2`, `hmac`, `sha1`, `sha2`); nothing hand-rolled.
2. **Never fabricate** — a wrong/absent key or a failed tag/signature/padding is
   always a typed `Err`, never plausible-but-wrong bytes.
3. **Secure by default** — decryption requires an explicitly supplied secret;
   never silent, never on by default.
4. **Passwords double-gated** — a plaintext password needs both `--decrypt` and
   `--include-passwords`; default output never contains one.
