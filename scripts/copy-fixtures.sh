#!/usr/bin/env bash
# Copy the newest real Brave SNSS files into the test-fixture directory.
#
# These fixtures are gitignored on purpose: they contain your personal browsing
# history. They exist only so the parser is validated against real on-disk bytes
# (Doer-Checker), never against synthetic Pickles alone.
set -euo pipefail

SRC="${BRAVE_SESSIONS_DIR:-$HOME/Library/Application Support/BraveSoftware/Brave-Browser/Default/Sessions}"
DST="$(cd "$(dirname "$0")/.." && pwd)/crates/snss-core/tests/fixtures"

if [[ ! -d "$SRC" ]]; then
  echo "Brave Sessions dir not found: $SRC" >&2
  echo "Set BRAVE_SESSIONS_DIR to override." >&2
  exit 1
fi

mkdir -p "$DST"
newest() { ls -t "$SRC"/$1_* 2>/dev/null | head -1; }

for pair in "Session:Session_real" "Tabs:Tabs_real" "Apps:Apps_real"; do
  family="${pair%%:*}"; out="${pair##*:}"
  src="$(newest "$family" || true)"
  if [[ -n "${src:-}" ]]; then
    cp "$src" "$DST/$out"
    echo "copied $(basename "$src") -> $out"
  else
    echo "warning: no $family_* file found (skipping $out)" >&2
  fi
done
