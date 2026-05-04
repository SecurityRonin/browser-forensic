# Ralph Agent Task — browser-forensic (Rust)

You are running inside the git worktree at the current working directory.
This is a **Rust workspace** — use `cargo`, never `bun run` or `npm`.

## Workflow Per Iteration

1. Read `scripts/ralph/log.md` to understand what previous iterations completed.

2. Search `docs/user-stories/` for features with `"passes": false`.

3. If no features remain with `"passes": false`:
   - Output: <promise>FINISHED</promise>

4. Pick ONE feature — the highest-priority non-passing feature based on logical dependency order. Do not skip ahead; earlier tasks often define types needed by later ones.

5. Implement the feature following **strict TDD (Red-Green-Refactor)**:
   - **RED commit first**: Write the failing tests, run `cargo test -p <crate>` to confirm they fail, then commit with message `"RED: <description>"`.
   - **GREEN commit second**: Write the minimal implementation, run `cargo test --workspace` to confirm all pass, then commit with message `"GREEN: <description>"`.
   - Never implement before writing tests. Never combine RED and GREEN into one commit.

6. Verify after GREEN commit:
   - Run: `cargo test --workspace`
   - Run: `cargo clippy --workspace -- -D warnings` (fix any errors, warnings are ok if pre-existing)
   - Run: `cargo build --workspace`
   - All must succeed with 0 errors.

7. If verification fails, debug and fix. Keep tests green at all times.

8. Once verified:
   - Update the user story's `passes` property to `true` in the JSON file.
   - Append a short entry to `scripts/ralph/log.md`.
   - Commit the user story update: `git add docs/user-stories/ scripts/ralph/log.md && git commit -m "chore: mark <story> as passing"`

9. The iteration ends here. Output the completion summary and stop.

## Critical Rules

- Work in directory: `/Users/4n6h4x0r/src/browser-forensic/.worktrees/full-impl`
- GITSIGN_CREDENTIAL_CACHE is set in the environment — git commit will work without browser prompts.
- **Never** run multiple `cargo test` processes concurrently — system RAM constraint.
- **Never** run `cargo test` without `-p` flag or `--workspace` — always one at a time.
- **Never** write implementation before tests (TDD is mandatory, not optional).
- **Never** combine RED and GREEN commits.
- Each Rust crate's test suite uses in-memory SQLite (`:memory:`) or `NamedTempFile` — no real browser files needed.
- Tests for SQLite parsers use `rusqlite::Connection::open(f.path())` with a `NamedTempFile`.
- Tests for JSON/plist parsers write test data to a `NamedTempFile` and parse it.
- All new parsers follow the pattern: `pub fn parse_<artifact>(path: &Path) -> Result<Vec<BrowserEvent>>`.
- Export new functions from the crate's `lib.rs` with `pub mod X; pub use X::parse_X;`.
- **Security**: Never SELECT or expose `password_value` or `encrypted_value` columns — always hard-code `"ENCRYPTED"` as the attr value.

## Rust Workspace Structure

```
crates/
  browser-core/        — BrowserFamily, ArtifactKind, BrowserEvent, detect_browser
  browser-discovery/   — discover_profiles(home: &Path) -> Vec<DiscoveredProfile>
  browser-chrome/      — parse_history, parse_cookies, parse_downloads, parse_bookmarks,
                         parse_extensions, parse_login_data, parse_autofill, parse_cache
  browser-firefox/     — parse_history, parse_cookies, parse_downloads, parse_bookmarks,
                         parse_extensions, parse_login_data, parse_autofill, parse_session, parse_cache
  browser-safari/      — parse_history, parse_cookies, parse_downloads, parse_bookmarks, parse_extensions
  bw-cli/              — CLI binary `bw` with subcommands
```

## Key Technical Facts

- **Chrome timestamps**: WebKit microseconds since 1601-01-01. Use `webkit_to_unix_ns(x)` from `crate::history`. Exception: `Web Data`'s `autofill.date_created` is Unix epoch SECONDS → `ts_ns = x * 1_000_000_000`.
- **Firefox timestamps**: microseconds since Unix epoch → `ts_ns = x * 1_000`. Exception: `logins.json` `timeCreated` is milliseconds → `ts_ns = x * 1_000_000`.
- **Safari timestamps**: Core Data seconds since 2001-01-01 (f64). Offset = 978_307_200 Unix seconds. `ts_ns = (x + 978_307_200.0) * 1e9 as i64`. Function: `safari_to_unix_ns(f64)` in `browser-safari/src/history.rs`.
- **Firefox sessionstore.jsonlz4**: magic `b"mozLz40\0"` (8 bytes) + uncompressed size as `u32 LE` (4 bytes) + LZ4 block compressed JSON. Crate: `lz4_flex` (already in workspace deps after Task 19).
- **plist files**: Use the `plist` crate (already in workspace deps after Task 5).
- **New workspace dependencies**: add to root `Cargo.toml` `[workspace.dependencies]` before using in a crate.

## Completion

When ALL user stories have `"passes": true`, output:

<promise>FINISHED</promise>
