//! Browser-agnostic navigation reconstruction over per-visit [`BrowserEvent`]s.
//!
//! Chromium (`visits`) and Firefox (`moz_historyvisits`) both record each visit
//! with a `visit_id`, a `from_visit` back-reference to the visit that led to it,
//! a normalized `transition` token, and redirect flags. This module rebuilds the
//! higher-level structure those fields encode:
//!
//! - [`resolve_referrer_chains`] — follow `from_visit` to attach each visit's
//!   referrer URL and its depth in the navigation path (bounded, so cyclic or
//!   dangling links never loop or panic).
//! - [`redirect_chains`] / [`tag_redirect_chains`] — group the redirect hops
//!   between a navigation's origin and its final landing, tagging each as a
//!   client- or server-side redirect.
//! - [`sessionize`] — group visits into browsing sessions by an idle-gap
//!   threshold (a documented, configurable heuristic — sessions are *inferred*,
//!   not recorded) and by any browser-recorded `session` boundary.
//! - [`tabs_open_at`] — the set of session tabs whose window was last active at
//!   or before a given instant, reusing the SNSS/`sessionstore` reader output.
//!
//! Everything reads the attrs the visit parsers already emit and writes new attrs
//! back; missing attrs are treated as "absent" (fail-open — reconstruction never
//! drops or corrupts a visit it cannot fully link).

use std::collections::{HashMap, HashSet};

use serde_json::json;

use crate::{ArtifactKind, BrowserEvent};

/// Default idle-gap for [`sessionize`]: 30 minutes. A *heuristic* boundary
/// (sessions are inferred, not recorded by the browser); override via
/// [`SessionConfig`].
pub const DEFAULT_IDLE_GAP_MINUTES: i64 = 30;

/// Upper bound on `from_visit` graph traversal. Guards cyclic and dangling links
/// in hostile or corrupt data so reconstruction is always finite and panic-free.
const MAX_CHAIN_DEPTH: usize = 4096;

// ---------------------------------------------------------------------------
// attr accessors (fail-open)
// ---------------------------------------------------------------------------

fn attr_i64(e: &BrowserEvent, key: &str) -> Option<i64> {
    e.attrs.get(key).and_then(serde_json::Value::as_i64)
}

fn attr_str<'a>(e: &'a BrowserEvent, key: &str) -> Option<&'a str> {
    e.attrs.get(key).and_then(serde_json::Value::as_str)
}

fn attr_bool(e: &BrowserEvent, key: &str) -> Option<bool> {
    e.attrs.get(key).and_then(serde_json::Value::as_bool)
}

/// Index visits by their `visit_id` attr (first occurrence wins). Events without
/// a `visit_id` are skipped.
fn index_by_visit_id(events: &[BrowserEvent]) -> HashMap<i64, usize> {
    let mut map = HashMap::new();
    for (i, e) in events.iter().enumerate() {
        if let Some(id) = attr_i64(e, "visit_id") {
            map.entry(id).or_insert(i);
        }
    }
    map
}

// ---------------------------------------------------------------------------
// human_transition_label
// ---------------------------------------------------------------------------

/// A human-readable label for a normalized `transition` token (the tokens the
/// Chromium/Firefox visit parsers emit). Unknown tokens map to `"unknown"`; the
/// raw token stays available in the event's `transition` attr.
#[must_use]
pub fn human_transition_label(token: &str) -> &'static str {
    match token {
        "link" => "clicked link",
        "typed" => "typed URL",
        "auto_bookmark" | "bookmark" => "bookmark",
        "auto_subframe" => "subframe (auto)",
        "manual_subframe" => "subframe (manual)",
        "generated" => "generated",
        "auto_toplevel" | "start_page" => "start page",
        "form_submit" => "form submit",
        "reload" => "reload",
        "keyword" | "keyword_generated" => "keyword search",
        "embed" => "embedded object",
        "redirect_permanent" => "redirect (permanent)",
        "redirect_temporary" => "redirect (temporary)",
        "download" => "download",
        "framed_link" => "framed link",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// resolve_referrer_chains
// ---------------------------------------------------------------------------

/// Attach each visit's referrer URL and navigation-path depth by following
/// `from_visit`.
///
/// For every event with a resolvable `from_visit`, adds `referrer_url` (the URL
/// of the visit it came from) and `nav_depth` (the number of resolved referrer
/// hops back to a navigation root). Root visits (`from_visit == 0`) and visits
/// whose `from_visit` dangles get `nav_depth = 0` and no `referrer_url`.
///
/// Traversal is depth-bounded ([`MAX_CHAIN_DEPTH`]) and cycle-guarded: a cyclic
/// or dangling `from_visit` graph never loops, overflows the stack, or panics.
pub fn resolve_referrer_chains(events: &mut [BrowserEvent]) {
    // Snapshot the linkage so the per-event mutation below has no borrow conflict.
    let url_of: HashMap<i64, String> = events
        .iter()
        .filter_map(|e| {
            let id = attr_i64(e, "visit_id")?;
            Some((id, attr_str(e, "url").unwrap_or_default().to_string()))
        })
        .collect();
    let from_of: HashMap<i64, i64> = events
        .iter()
        .filter_map(|e| {
            Some((
                attr_i64(e, "visit_id")?,
                attr_i64(e, "from_visit").unwrap_or(0),
            ))
        })
        .collect();

    for e in events.iter_mut() {
        let from = attr_i64(e, "from_visit").unwrap_or(0);
        if from != 0 {
            if let Some(u) = url_of.get(&from) {
                e.attrs.insert("referrer_url".to_string(), json!(u));
            }
        }
        // Depth = resolved referrer hops back to a root, bounded and cycle-guarded.
        let mut depth: i64 = 0;
        let mut cur = from;
        let mut seen: HashSet<i64> = HashSet::new();
        while cur != 0 && (depth as usize) < MAX_CHAIN_DEPTH {
            if !url_of.contains_key(&cur) || !seen.insert(cur) {
                break; // dangling link or a cycle — stop cleanly
            }
            depth += 1;
            cur = from_of.get(&cur).copied().unwrap_or(0);
        }
        e.attrs.insert("nav_depth".to_string(), json!(depth));
    }
}

// ---------------------------------------------------------------------------
// redirect_chains
// ---------------------------------------------------------------------------

/// One hop in a reconstructed redirect chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectHop {
    /// The hop's `visit_id`.
    pub visit_id: i64,
    /// The hop's URL.
    pub url: String,
    /// `Some("client")` / `Some("server")` for a redirect hop; `None` for the
    /// non-redirect origin that started the navigation.
    pub kind: Option<String>,
    /// `"start"`, `"hop"`, or `"landing"`.
    pub role: &'static str,
}

/// A reconstructed redirect chain: the origin (when known) followed by its
/// redirect hops, ending at the landing page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectChain {
    /// Stable id assigned in reconstruction order.
    pub id: usize,
    /// Hops in navigation order (origin/start first, landing last).
    pub hops: Vec<RedirectHop>,
}

/// Reconstruct redirect chains from a per-visit event slice.
///
/// A redirect chain is a maximal run of visits linked by `from_visit` whose
/// members carry the redirect flag (`is_redirect`), plus the non-redirect origin
/// that initiated it when that origin is resolvable. Client vs server flavour is
/// read from each hop's `redirect_kind` attr. Chains are linear paths; grouping
/// is cycle-guarded and depth-bounded.
/// Role of a hop at `pos` in a chain of `total` members.
fn role_for(pos: usize, total: usize) -> &'static str {
    if total <= 1 || pos == total - 1 {
        "landing"
    } else if pos == 0 {
        "start"
    } else {
        "hop"
    }
}

#[must_use]
pub fn redirect_chains(events: &[BrowserEvent]) -> Vec<RedirectChain> {
    let id_to_idx = index_by_visit_id(events);
    let is_red = |i: usize| attr_bool(&events[i], "is_redirect") == Some(true);

    // Redirect children keyed by their parent's visit_id (from_visit).
    let mut redirect_children: HashMap<i64, Vec<usize>> = HashMap::new();
    for (i, e) in events.iter().enumerate() {
        if is_red(i) {
            let from = attr_i64(e, "from_visit").unwrap_or(0);
            redirect_children.entry(from).or_default().push(i);
        }
    }

    let hop = |idx: usize, kind: Option<String>, role: &'static str| RedirectHop {
        visit_id: attr_i64(&events[idx], "visit_id").unwrap_or(0),
        url: attr_str(&events[idx], "url")
            .unwrap_or_default()
            .to_string(),
        kind,
        role,
    };

    let mut chains: Vec<RedirectChain> = Vec::new();
    let mut assigned: HashSet<usize> = HashSet::new();
    for (i, e) in events.iter().enumerate() {
        if !is_red(i) || assigned.contains(&i) {
            continue;
        }
        let from = attr_i64(e, "from_visit").unwrap_or(0);
        let parent_idx = id_to_idx.get(&from).copied();
        // Only a redirect whose parent is not itself a redirect starts a chain;
        // any redirect with a redirect parent is reached forward from its head.
        if matches!(parent_idx, Some(pi) if is_red(pi)) {
            continue;
        }

        // Forward-follow the redirect run (linear; cycle-guarded, depth-bounded).
        let mut run: Vec<usize> = Vec::new();
        let mut cur = i;
        let mut seen: HashSet<usize> = HashSet::new();
        while run.len() < MAX_CHAIN_DEPTH && seen.insert(cur) {
            run.push(cur);
            assigned.insert(cur);
            let cur_id = attr_i64(&events[cur], "visit_id").unwrap_or(0);
            let next = redirect_children
                .get(&cur_id)
                .and_then(|kids| kids.iter().copied().find(|k| !seen.contains(k)));
            match next {
                Some(n) => cur = n,
                None => break,
            }
        }

        // Prepend the non-redirect origin when it is resolvable.
        let origin = parent_idx.filter(|&pi| !is_red(pi));
        let total = run.len() + usize::from(origin.is_some());
        let mut hops: Vec<RedirectHop> = Vec::with_capacity(total);
        let mut pos = 0;
        if let Some(oi) = origin {
            hops.push(hop(oi, None, role_for(pos, total)));
            pos += 1;
        }
        for &ri in &run {
            let kind = attr_str(&events[ri], "redirect_kind").map(str::to_string);
            hops.push(hop(ri, kind, role_for(pos, total)));
            pos += 1;
        }
        chains.push(RedirectChain {
            id: chains.len(),
            hops,
        });
    }
    chains
}

/// Tag each event that belongs to a redirect chain with `redirect_chain_id`
/// (usize) and `redirect_role` (`"start"`/`"hop"`/`"landing"`) attrs, via
/// [`redirect_chains`].
pub fn tag_redirect_chains(events: &mut [BrowserEvent]) {
    let chains = redirect_chains(events);
    let mut tag: HashMap<i64, (usize, &'static str)> = HashMap::new();
    for c in &chains {
        for h in &c.hops {
            tag.insert(h.visit_id, (c.id, h.role));
        }
    }
    for e in events.iter_mut() {
        if let Some(id) = attr_i64(e, "visit_id") {
            if let Some((cid, role)) = tag.get(&id) {
                e.attrs.insert("redirect_chain_id".to_string(), json!(cid));
                e.attrs.insert("redirect_role".to_string(), json!(role));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// sessionize
// ---------------------------------------------------------------------------

/// Configuration for [`sessionize`].
#[derive(Debug, Clone, Copy)]
pub struct SessionConfig {
    /// Idle gap, in nanoseconds, above which a new session starts.
    pub idle_gap_ns: i64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            idle_gap_ns: DEFAULT_IDLE_GAP_MINUTES * 60 * 1_000_000_000,
        }
    }
}

/// Group visits into inferred browsing sessions by idle gap.
///
/// Walking the events in time order, a new session begins whenever the gap since
/// the previous visit exceeds `cfg.idle_gap_ns`, or the browser-recorded
/// `session` attr changes. Each event gains a `session_id` attr (0-based,
/// assigned in time order). The slice is not reordered.
///
/// Sessions are *inferred* from the idle-gap heuristic, not recorded by the
/// browser: report them as "sessions inferred at an N-minute idle gap".
pub fn sessionize(events: &mut [BrowserEvent], cfg: SessionConfig) {
    if events.is_empty() {
        return;
    }
    let mut order: Vec<usize> = (0..events.len()).collect();
    order.sort_by_key(|&i| events[i].timestamp_ns);

    let mut session: i64 = 0;
    let mut prev_ts: Option<i64> = None;
    let mut prev_sess: Option<Option<i64>> = None;
    for &i in &order {
        let ts = events[i].timestamp_ns;
        let recorded = attr_i64(&events[i], "session");
        if let Some(pt) = prev_ts {
            let gap = ts.saturating_sub(pt);
            // A recorded-session change is a boundary only when both sides record one.
            let sess_changed =
                prev_sess.is_some_and(|ps| ps.is_some() && recorded.is_some() && ps != recorded);
            if gap > cfg.idle_gap_ns || sess_changed {
                session += 1;
            }
        }
        events[i]
            .attrs
            .insert("session_id".to_string(), json!(session));
        prev_ts = Some(ts);
        prev_sess = Some(recorded);
    }
}

// ---------------------------------------------------------------------------
// tabs_open_at
// ---------------------------------------------------------------------------

/// The session tabs whose window was last active at or before `t_ns`.
///
/// Reuses the SNSS / `sessionstore` reader output ([`ArtifactKind::Session`]
/// events, each timestamped with its window's last-active time): returns those
/// with `0 < timestamp_ns <= t_ns` — the tabs known open as of the latest
/// recorded activity at or before `t_ns`.
#[must_use]
pub fn tabs_open_at(session_events: &[BrowserEvent], t_ns: i64) -> Vec<&BrowserEvent> {
    session_events
        .iter()
        .filter(|e| {
            e.artifact == ArtifactKind::Session && e.timestamp_ns > 0 && e.timestamp_ns <= t_ns
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BrowserEvent, BrowserFamily};

    fn visit(id: i64, from: i64, ts_ns: i64, url: &str) -> BrowserEvent {
        BrowserEvent::new(
            ts_ns,
            BrowserFamily::Chromium,
            ArtifactKind::History,
            "src",
            url,
        )
        .with_attr("url", json!(url))
        .with_attr("visit_id", json!(id))
        .with_attr("from_visit", json!(from))
    }

    fn redirect_visit(id: i64, from: i64, ts_ns: i64, url: &str, kind: &str) -> BrowserEvent {
        visit(id, from, ts_ns, url)
            .with_attr("is_redirect", json!(true))
            .with_attr("redirect_kind", json!(kind))
    }

    // ---- human_transition_label ----

    #[test]
    fn transition_labels_are_human_readable() {
        assert_eq!(human_transition_label("typed"), "typed URL");
        assert_eq!(human_transition_label("link"), "clicked link");
        assert_eq!(human_transition_label("form_submit"), "form submit");
        assert_eq!(human_transition_label("reload"), "reload");
        assert_eq!(
            human_transition_label("redirect_permanent"),
            "redirect (permanent)"
        );
        assert_eq!(human_transition_label("auto_bookmark"), "bookmark");
        assert_eq!(human_transition_label("something_new"), "unknown");
    }

    // ---- resolve_referrer_chains ----

    #[test]
    fn referrer_chain_sets_referrer_url_and_depth() {
        // 1 (root) -> 2 -> 3
        let mut events = vec![
            visit(1, 0, 1000, "https://a.example"),
            visit(2, 1, 2000, "https://b.example"),
            visit(3, 2, 3000, "https://c.example"),
        ];
        resolve_referrer_chains(&mut events);
        assert_eq!(events[0].attrs["nav_depth"], json!(0));
        assert!(!events[0].attrs.contains_key("referrer_url"));
        assert_eq!(events[1].attrs["referrer_url"], json!("https://a.example"));
        assert_eq!(events[1].attrs["nav_depth"], json!(1));
        assert_eq!(events[2].attrs["referrer_url"], json!("https://b.example"));
        assert_eq!(events[2].attrs["nav_depth"], json!(2));
    }

    #[test]
    fn dangling_from_visit_leaves_no_referrer() {
        // from_visit 999 does not exist.
        let mut events = vec![visit(1, 999, 1000, "https://a.example")];
        resolve_referrer_chains(&mut events);
        assert!(!events[0].attrs.contains_key("referrer_url"));
        assert_eq!(events[0].attrs["nav_depth"], json!(0));
    }

    #[test]
    fn cyclic_from_visit_is_bounded_not_infinite() {
        // 1 -> 2 -> 1 : a cycle. Must terminate and cap depth.
        let mut events = vec![
            visit(1, 2, 1000, "https://a.example"),
            visit(2, 1, 2000, "https://b.example"),
        ];
        resolve_referrer_chains(&mut events);
        // referrer resolves one hop; depth stays finite and bounded.
        assert_eq!(events[0].attrs["referrer_url"], json!("https://b.example"));
        let d0 = events[0].attrs["nav_depth"].as_i64().unwrap();
        let d1 = events[1].attrs["nav_depth"].as_i64().unwrap();
        assert!(d0 <= MAX_CHAIN_DEPTH as i64);
        assert!(d1 <= MAX_CHAIN_DEPTH as i64);
    }

    // ---- redirect_chains ----

    #[test]
    fn redirect_chain_groups_origin_and_hops_with_roles() {
        // origin (typed, not redirect) -> server redirect -> client redirect (landing)
        let mut events = vec![
            visit(1, 0, 1000, "https://origin.example"),
            redirect_visit(2, 1, 2000, "https://hop.example", "server"),
            redirect_visit(3, 2, 3000, "https://landing.example", "client"),
        ];
        let chains = redirect_chains(&events);
        assert_eq!(chains.len(), 1);
        let c = &chains[0];
        assert_eq!(c.hops.len(), 3);
        assert_eq!(c.hops[0].role, "start");
        assert_eq!(c.hops[0].kind, None);
        assert_eq!(c.hops[0].url, "https://origin.example");
        assert_eq!(c.hops[1].role, "hop");
        assert_eq!(c.hops[1].kind.as_deref(), Some("server"));
        assert_eq!(c.hops[2].role, "landing");
        assert_eq!(c.hops[2].kind.as_deref(), Some("client"));

        // tagging writes the chain id + role back onto the events
        tag_redirect_chains(&mut events);
        assert_eq!(events[0].attrs["redirect_role"], json!("start"));
        assert_eq!(events[1].attrs["redirect_role"], json!("hop"));
        assert_eq!(events[2].attrs["redirect_role"], json!("landing"));
        assert_eq!(
            events[0].attrs["redirect_chain_id"],
            events[2].attrs["redirect_chain_id"]
        );
    }

    #[test]
    fn no_redirects_yields_no_chains() {
        let events = vec![
            visit(1, 0, 1000, "https://a.example"),
            visit(2, 0, 2000, "https://b.example"),
        ];
        assert!(redirect_chains(&events).is_empty());
    }

    #[test]
    fn redirect_chain_with_dangling_origin_starts_at_first_redirect() {
        // origin id 1 is absent; the redirect (id 2) is the chain head.
        let events = vec![redirect_visit(2, 1, 2000, "https://only.example", "server")];
        let chains = redirect_chains(&events);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].hops.len(), 1);
        assert_eq!(chains[0].hops[0].role, "landing");
    }

    // ---- sessionize ----

    fn min_ns(m: i64) -> i64 {
        m * 60 * 1_000_000_000
    }

    #[test]
    fn sessionize_groups_by_idle_gap() {
        let mut events = vec![
            visit(1, 0, 0, "https://a.example"),
            visit(2, 0, min_ns(5), "https://b.example"), // +5 min: same session
            visit(3, 0, min_ns(50), "https://c.example"), // +45 min: new session
        ];
        sessionize(&mut events, SessionConfig::default());
        assert_eq!(events[0].attrs["session_id"], json!(0));
        assert_eq!(events[1].attrs["session_id"], json!(0));
        assert_eq!(events[2].attrs["session_id"], json!(1));
    }

    #[test]
    fn sessionize_respects_custom_idle_gap() {
        let mut events = vec![
            visit(1, 0, 0, "https://a.example"),
            visit(2, 0, min_ns(5), "https://b.example"),
        ];
        // 2-minute gap: the 5-minute jump now splits.
        sessionize(
            &mut events,
            SessionConfig {
                idle_gap_ns: min_ns(2),
            },
        );
        assert_eq!(events[0].attrs["session_id"], json!(0));
        assert_eq!(events[1].attrs["session_id"], json!(1));
    }

    #[test]
    fn sessionize_splits_on_recorded_session_change() {
        let mut events = vec![
            visit(1, 0, 0, "https://a.example").with_attr("session", json!(7)),
            // 1 minute later but a different recorded session -> new inferred session
            visit(2, 0, min_ns(1), "https://b.example").with_attr("session", json!(8)),
        ];
        sessionize(&mut events, SessionConfig::default());
        assert_ne!(events[0].attrs["session_id"], events[1].attrs["session_id"]);
    }

    // ---- tabs_open_at ----

    fn tab_event(ts_ns: i64, url: &str) -> BrowserEvent {
        BrowserEvent::new(
            ts_ns,
            BrowserFamily::Chromium,
            ArtifactKind::Session,
            "src",
            url,
        )
        .with_attr("url", json!(url))
    }

    #[test]
    fn tabs_open_at_filters_by_time() {
        let events = vec![
            tab_event(1000, "https://early.example"),
            tab_event(5000, "https://late.example"),
        ];
        let open = tabs_open_at(&events, 2000);
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].attrs["url"], json!("https://early.example"));
    }
}
