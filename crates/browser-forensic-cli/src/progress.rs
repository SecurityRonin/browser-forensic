//! RFC 0001 Phase P3b — progress heartbeats (concern 1).
//!
//! A silent terminal at 2am is indistinguishable from a crash. This module gives
//! `investigate` a non-spammy, **stderr-only** heartbeat — phase, the unit being
//! parsed, a completed/total count, and an extrapolated ETA — so a long run over
//! a huge image visibly makes progress.
//!
//! The reporting *seam* is the library-side [`browser_forensic_triage::TriageProgress`]
//! trait; the *rendering* lives here in the CLI. Two properties keep pipes and CI
//! clean (RFC 0001 D10): the heartbeat renders to **stderr** (never stdout/JSONL)
//! and is **disabled when stderr is not a TTY** ([`progress_enabled`]), so piped
//! and non-interactive runs behave exactly as before. `NO_COLOR` is honored — the
//! text is always plain; color is an additive TTY-only cue.

use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use browser_forensic_triage::TriageProgress;

/// Whether a stderr heartbeat should be rendered: only when stderr is a terminal.
/// A pipe / file / CI log gets no progress output so machine consumers stay clean.
#[must_use]
pub fn progress_enabled(_stderr_is_tty: bool) -> bool {
    false // RED stub
}

/// Format an extrapolated ETA from elapsed wall time and completed/total units.
///
/// * `done == 0` → unknown (`--`), no basis to extrapolate yet.
/// * `done >= total` → `0s`, work is complete.
/// * otherwise → `elapsed / done * (total - done)`, rendered compactly.
#[must_use]
pub fn format_eta(_elapsed: Duration, _done: usize, _total: usize) -> String {
    String::new() // RED stub
}

/// Render one heartbeat line: `Parsing (2/4) | Default · History | ETA 12s`.
/// The text is always plain; `color` adds an additive ANSI cue on the phase word.
#[must_use]
pub fn render_line(
    _phase: &str,
    _unit: &str,
    _done: usize,
    _total: usize,
    _elapsed: Duration,
    _color: bool,
) -> String {
    String::new() // RED stub
}

/// A stderr-rendering [`TriageProgress`]. The enclosing loop calls
/// [`StderrProgress::set_profile`] before each profile to advance the
/// completed/total count (which drives the ETA); the triage pipeline then calls
/// [`TriageProgress::on_unit`] per artifact, which re-renders the line so the
/// terminal stays live within a single large profile.
pub struct StderrProgress {
    start: Instant,
    done: AtomicUsize,
    total: AtomicUsize,
    color: bool,
}

impl StderrProgress {
    /// A fresh heartbeat renderer; `color` gates the additive ANSI cue.
    #[must_use]
    pub fn new(color: bool) -> Self {
        Self {
            start: Instant::now(),
            done: AtomicUsize::new(0),
            total: AtomicUsize::new(0),
            color,
        }
    }

    /// Advance the profile-level completed/total count (drives the ETA).
    pub fn set_profile(&self, done: usize, total: usize) {
        self.done.store(done, Ordering::Relaxed);
        self.total.store(total, Ordering::Relaxed);
    }

    /// Clear the heartbeat line (called once the run finishes).
    pub fn finish(&self) {
        let mut err = std::io::stderr();
        let _ = writeln!(err);
    }
}

impl TriageProgress for StderrProgress {
    fn on_unit(&self, _profile: &str, _artifact: &str) {
        // RED stub: no render yet.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_enabled_only_on_tty() {
        assert!(progress_enabled(true), "a terminal gets the heartbeat");
        assert!(!progress_enabled(false), "a pipe/CI log gets no heartbeat");
    }

    #[test]
    fn format_eta_unknown_when_nothing_done() {
        let s = format_eta(Duration::from_secs(5), 0, 4);
        assert!(s.contains("--"), "no basis to extrapolate yet: {s}");
    }

    #[test]
    fn format_eta_zero_when_complete() {
        let s = format_eta(Duration::from_secs(5), 4, 4);
        assert!(s.contains("0s"), "complete work has no ETA left: {s}");
    }

    #[test]
    fn format_eta_extrapolates_partial() {
        // 10s for 1 of 4 → ~30s remaining.
        let s = format_eta(Duration::from_secs(10), 1, 4);
        assert!(
            s.contains("30s") || s.contains("29s") || s.contains("31s"),
            "extrapolates remaining time from the rate: {s}"
        );
    }

    #[test]
    fn render_line_shows_phase_unit_count_and_eta() {
        let line = render_line(
            "Parsing",
            "Default · History",
            2,
            4,
            Duration::from_secs(10),
            false,
        );
        for token in ["Parsing", "Default · History", "2/4", "ETA"] {
            assert!(line.contains(token), "line names `{token}`: {line}");
        }
    }

    #[test]
    fn render_line_plain_without_color() {
        let line = render_line("Parsing", "x", 1, 2, Duration::from_secs(1), false);
        assert!(!line.contains('\u{1b}'), "no ANSI when color off: {line:?}");
    }

    #[test]
    fn render_line_colors_when_enabled() {
        let line = render_line("Parsing", "x", 1, 2, Duration::from_secs(1), true);
        assert!(line.contains('\u{1b}'), "ANSI cue when color on: {line:?}");
    }
}
