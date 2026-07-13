"""End-to-end test for the browser_forensic Python bindings.

Env-gated: set RUN_PY_BINDINGS_TEST=1 (after `maturin develop`) to run. Left
unset, the whole module skips cleanly so a plain `pytest` in an environment
without the built wheel is green rather than erroring.

    maturin develop --features pyo3/extension-module
    RUN_PY_BINDINGS_TEST=1 pytest tests/test_bindings.py
"""

import os
import sqlite3

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_PY_BINDINGS_TEST") != "1",
    reason="set RUN_PY_BINDINGS_TEST=1 after `maturin develop` to exercise the built wheel",
)

# WebKit-epoch microseconds (2023-06-13ish) for the one seeded visit.
_LAST_VISIT_TIME = 13327626000000000


def _make_chrome_profile(tmp_path):
    """A minimal, Chrome-looking profile dir holding one History visit."""
    profile = tmp_path / "google-chrome" / "Default"
    profile.mkdir(parents=True)
    conn = sqlite3.connect(profile / "History")
    conn.executescript(
        """
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            title TEXT DEFAULT '',
            visit_count INTEGER DEFAULT 0 NOT NULL,
            last_visit_time INTEGER NOT NULL
        );
        INSERT INTO urls (url, title, visit_count, last_visit_time)
        VALUES ('https://example.com/', 'Example', 1, %d);
        """
        % _LAST_VISIT_TIME
    )
    conn.commit()
    conn.close()
    return profile


def test_module_exposes_the_binding_api():
    import browser_forensic

    assert hasattr(browser_forensic, "parse_profile")
    assert hasattr(browser_forensic, "discover_profiles")
    assert isinstance(browser_forensic.__version__, str)


def test_parse_profile_returns_browser_events(tmp_path):
    import browser_forensic

    profile = _make_chrome_profile(tmp_path)
    report = browser_forensic.parse_profile(str(profile), "chromium")

    assert isinstance(report, dict)
    events = report["events"]
    assert isinstance(events, list)
    assert events, "expected at least one BrowserEvent from the seeded History"

    event = events[0]
    for field in (
        "timestamp_ns",
        "browser",
        "artifact",
        "source",
        "description",
        "attrs",
    ):
        assert field in event, f"BrowserEvent dict missing `{field}`"

    assert event["browser"] == "Chromium"
    assert any(
        e["artifact"] == "History" and "example.com" in str(e) for e in events
    ), "expected a History event for the seeded example.com visit"


def test_unknown_browser_family_is_rejected(tmp_path):
    import browser_forensic

    profile = _make_chrome_profile(tmp_path)
    with pytest.raises(ValueError):
        browser_forensic.parse_profile(str(profile), "netscape")


def test_discover_profiles_returns_a_list(tmp_path):
    import browser_forensic

    _make_chrome_profile(tmp_path)
    profiles = browser_forensic.discover_profiles(str(tmp_path))
    assert isinstance(profiles, list)
