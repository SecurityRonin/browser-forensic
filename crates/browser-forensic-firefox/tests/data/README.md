# Firefox test-data provenance

The Firefox crate's oracle tests read **real, env-gated, uncommitted** data. No
fixture is committed here — real Firefox profiles are user data and dumpzilla is
an external tool — so this file documents the provenance of the inputs each test
consumes and how to obtain them, per the fleet Test-Data Provenance Standard.

## `dumpzilla_differential` — differential oracle vs dumpzilla

Reconciles this crate's `parse_history` / `parse_downloads` / `parse_cookies`
against the independent third-party tool **dumpzilla**. See the reconciliation
model and observed counts in `docs/validation.md`.

| Input | What | Provenance | Committed |
|---|---|---|---|
| Firefox profile | a real `places.sqlite` + `cookies.sqlite` | the examiner's / a live Firefox profile — genuine, non-redistributable user data | no — env-gated, copied to a temp dir at test time, originals never touched |
| dumpzilla | `dumpzilla.py` (`git clone https://github.com/Busindre/dumpzilla`) | independent open-source Firefox forensic tool (Busindre); GPL per dumpzilla.org. Referenced as an external oracle, **not** redistributed or committed here. | no |
| lz4 | Python `lz4` module dumpzilla imports at load | PyPI `lz4` (install into the interpreter dumpzilla runs under) | no |

The differential test is env-gated and skips cleanly unless the profile,
dumpzilla, and the `sqlite3` CLI are all present. It never writes to the profile:
the databases are copied to a temp dir and both tools run on the copy (dumpzilla
opens SQLite read-write).

### How to run

```sh
python3 -m venv /tmp/dz-venv && /tmp/dz-venv/bin/pip install lz4
git clone https://github.com/Busindre/dumpzilla /tmp/dumpzilla
BR4N6_FIREFOX_PROFILE="$HOME/Library/Application Support/Firefox/Profiles/<profile>" \
BR4N6_DUMPZILLA=/tmp/dumpzilla/dumpzilla.py \
BR4N6_DUMPZILLA_PYTHON=/tmp/dz-venv/bin/python \
  cargo test -p browser-forensic-firefox --test dumpzilla_differential -- --nocapture
```

## `real_profile_gated` — structural invariants on a real profile

Runs the typed-input, annotation, and deleted-bookmark parsers over a real
`places.sqlite` and asserts structural invariants (not hard-coded counts). Same
env-gate:

```sh
BR4N6_FIREFOX_PROFILE=/path/to/profile \
  cargo test -p browser-forensic-firefox --test real_profile_gated -- --nocapture
```

Provenance: real Mozilla-written profile, user data, never committed.
