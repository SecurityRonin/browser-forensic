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
pub fn progress_enabled(stderr_is_tty: bool) -> bool {
    stderr_is_tty
}

/// Format an extrapolated ETA from elapsed wall time and completed/total units.
///
/// * `done == 0` → unknown (`--`), no basis to extrapolate yet.
/// * `done >= total` → `0s`, work is complete.
/// * otherwise → `elapsed / done * (total - done)`, rendered compactly.
#[must_use]
pub fn format_eta(elapsed: Duration, done: usize, total: usize) -> String {
    if done == 0 {
        return "--".to_string();
    }
    if done >= total {
        return "0s".to_string();
    }
    let remaining_units = (total - done) as u32;
    // elapsed / done * remaining_units — integer math on whole seconds keeps the
    // estimate coarse and stable (this is a heartbeat, not a stopwatch).
    let per_unit = elapsed / done as u32;
    let eta = per_unit * remaining_units;
    format_duration(eta)
}

/// Render a [`Duration`] compactly as `Nh`, `Nm`, or `Ns` (largest whole unit).
fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 3600 {
        format!("{}h", secs / 3600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

/// Render one heartbeat line: `Parsing (2/4) | Default · History | ETA 12s`.
/// The text is always plain; `color` adds an additive ANSI cue on the phase word.
#[must_use]
pub fn render_line(
    phase: &str,
    unit: &str,
    done: usize,
    total: usize,
    elapsed: Duration,
    color: bool,
) -> String {
    let phase_cell = crate::output::paint(phase, crate::output::ANSI_CYAN, color);
    let eta = format_eta(elapsed, done, total);
    format!("{phase_cell} ({done}/{total}) | {unit} | ETA {eta}")
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
    fn on_unit(&self, profile: &str, artifact: &str) {
        let done = self.done.load(Ordering::Relaxed);
        let total = self.total.load(Ordering::Relaxed);
        let unit = format!("{profile} · {artifact}");
        let line = render_line(
            "Parsing",
            &unit,
            done,
            total,
            self.start.elapsed(),
            self.color,
        );
        // Carriage-return overwrite keeps the heartbeat to a single live line;
        // pad to clear any longer previous line. stderr only — stdout stays clean.
        let mut err = std::io::stderr();
        let _ = write!(err, "\r{line}\u{1b}[K");
        let _ = err.flush();
    }
}

/// The CLI's investigation progress sink: an active stderr heartbeat on a TTY, or
/// an inert one on a pipe / CI log (so machine output stays byte-clean). This is
/// the concrete [`TriageProgress`] the investigate pipeline is driven with; it
/// also carries the profile-level count that drives the ETA.
pub struct Progress {
    inner: Option<StderrProgress>,
}

impl Progress {
    /// Select a sink from the terminal state: an active heartbeat only when
    /// stderr is a TTY ([`progress_enabled`]); `color` further gates the ANSI cue
    /// (the caller passes the `NO_COLOR`-aware decision).
    #[must_use]
    pub fn select(stderr_is_tty: bool, color: bool) -> Self {
        let inner = if progress_enabled(stderr_is_tty) {
            Some(StderrProgress::new(color))
        } else {
            None
        };
        Self { inner }
    }

    /// An always-inert sink (no heartbeat), for tests and non-interactive callers.
    #[must_use]
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    /// Whether this sink renders a heartbeat (true only on a TTY).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.inner.is_some()
    }

    /// Advance the profile-level completed/total count (drives the ETA).
    pub fn set_profile(&self, done: usize, total: usize) {
        if let Some(inner) = &self.inner {
            inner.set_profile(done, total);
        }
    }

    /// Clear the heartbeat line once the run finishes.
    pub fn finish(&self) {
        if let Some(inner) = &self.inner {
            inner.finish();
        }
    }
}

impl TriageProgress for Progress {
    fn on_unit(&self, profile: &str, artifact: &str) {
        if let Some(inner) = &self.inner {
            inner.on_unit(profile, artifact);
        }
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

    #[test]
    fn sink_inert_on_non_tty() {
        assert!(
            !Progress::select(false, false).is_active(),
            "a piped/CI run gets no heartbeat"
        );
        assert!(
            Progress::select(true, false).is_active(),
            "a terminal run gets a heartbeat"
        );
    }
}
