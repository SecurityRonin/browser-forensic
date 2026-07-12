//! Entity graph over registrable hosts.
//!
//! Nodes are registrable hosts (eTLD+1). Edges are of two provenances, kept
//! distinct so an examiner can tell them apart:
//!
//! * **referrer / redirect** edges come from M3 navigation reconstruction — the
//!   `from_visit` linkage a browser's own `visits` table recorded. A `referrer`
//!   edge is a normal navigation link; a `redirect` edge is one the browser
//!   flagged as a redirect hop. These reflect what the visit table stored, not
//!   an independent proof of deliberate navigation.
//! * **co-occurrence** edges are purely temporal: two distinct hosts whose
//!   events fall within a documented time window of each other. A co-occurrence
//!   edge means only "seen within N seconds", never that one host led to the
//!   other.
//!
//! Node and edge counts are bounded so a pathological corpus cannot produce an
//! unbounded graph.

use std::collections::BTreeMap;

use browser_forensic_core::reconstruct::resolve_referrer_chains;
use browser_forensic_core::BrowserEvent;
use serde::Serialize;

use crate::host::{host_of, primary_registrable_domain, registrable_domain};

/// Default co-occurrence window: 30 seconds.
pub const DEFAULT_COOCCURRENCE_WINDOW_SECS: i64 = 30;
/// Upper bound on graph nodes retained.
pub const MAX_NODES: usize = 10_000;
/// Upper bound on graph edges retained.
pub const MAX_EDGES: usize = 50_000;
/// Upper bound on forward neighbours scanned per event when building
/// co-occurrence edges — bounds worst-case cost on a dense corpus.
const NEIGHBOR_SCAN_CAP: usize = 512;
const NANOS_PER_SEC: i64 = 1_000_000_000;

/// The provenance of a graph edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// A `from_visit` navigation link (M3 reconstruction).
    Referrer,
    /// A `from_visit` link the browser flagged as a redirect hop (M3).
    Redirect,
    /// Two hosts seen within the co-occurrence time window.
    CoOccurrence,
}

impl EdgeKind {
    /// Stable lowercase token for output.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Referrer => "referrer",
            Self::Redirect => "redirect",
            Self::CoOccurrence => "co-occurrence",
        }
    }
}

/// A graph node: one registrable host.
#[derive(Debug, Clone, Serialize)]
pub struct GraphNode {
    /// Registrable host (eTLD+1).
    pub id: String,
    /// Events attributed to this host as their primary host.
    pub event_count: usize,
    /// Browser families that referenced this host.
    pub browsers: Vec<String>,
}

/// A directed graph edge with a provenance and a weight.
#[derive(Debug, Clone, Serialize)]
pub struct GraphEdge {
    /// Source host.
    pub from: String,
    /// Destination host.
    pub to: String,
    /// Edge provenance.
    pub kind: EdgeKind,
    /// Number of underlying occurrences.
    pub weight: usize,
}

/// A bounded entity graph.
#[derive(Debug, Clone, Serialize)]
pub struct EntityGraph {
    /// Nodes, sorted by event count descending then id.
    pub nodes: Vec<GraphNode>,
    /// Edges, sorted by weight descending then endpoints.
    pub edges: Vec<GraphEdge>,
    /// Co-occurrence window used (seconds).
    pub cooccurrence_window_secs: i64,
    /// True if nodes were dropped to honour the node cap.
    pub nodes_truncated: bool,
    /// True if edges were dropped to honour the edge cap.
    pub edges_truncated: bool,
}

/// Tuning for [`entity_graph`].
#[derive(Debug, Clone, Copy)]
pub struct GraphConfig {
    /// Co-occurrence window in seconds; `<= 0` disables co-occurrence edges.
    pub cooccurrence_window_secs: i64,
    /// Maximum nodes retained.
    pub max_nodes: usize,
    /// Maximum edges retained.
    pub max_edges: usize,
}

impl Default for GraphConfig {
    fn default() -> Self {
        Self {
            cooccurrence_window_secs: DEFAULT_COOCCURRENCE_WINDOW_SECS,
            max_nodes: MAX_NODES,
            max_edges: MAX_EDGES,
        }
    }
}

/// Node accumulator: host -> (primary-event count, browser families).
type NodeMap = BTreeMap<String, (usize, std::collections::BTreeSet<String>)>;

/// Insert an endpoint host as a node with zero count if not already present.
fn ensure_node(map: &mut NodeMap, host: &str) {
    map.entry(host.to_string())
        .or_insert_with(|| (0, std::collections::BTreeSet::new()));
}

/// Nodes by primary-host attribution: each event credits its own host.
fn build_nodes(events: &[BrowserEvent]) -> NodeMap {
    let mut map: NodeMap = BTreeMap::new();
    for event in events {
        if let Some(host) = primary_registrable_domain(event) {
            let entry = map
                .entry(host)
                .or_insert_with(|| (0, std::collections::BTreeSet::new()));
            entry.0 += 1;
            entry.1.insert(event.browser.to_string());
        }
    }
    map
}

/// Referrer/redirect edges from the reconstructed `from_visit` linkage. Ensures
/// both endpoints exist as nodes.
fn build_directed_edges(
    events: &[BrowserEvent],
    nodes: &mut NodeMap,
) -> BTreeMap<(String, String, EdgeKind), usize> {
    let mut directed: BTreeMap<(String, String, EdgeKind), usize> = BTreeMap::new();
    for event in events {
        let (Some(to), Some(referrer)) = (
            primary_registrable_domain(event),
            event
                .attrs
                .get("referrer_url")
                .and_then(serde_json::Value::as_str),
        ) else {
            continue;
        };
        let Some(from) = host_of(referrer).and_then(|h| registrable_domain(&h)) else {
            continue;
        };
        if from == to {
            continue;
        }
        let is_redirect = event
            .attrs
            .get("is_redirect")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let kind = if is_redirect {
            EdgeKind::Redirect
        } else {
            EdgeKind::Referrer
        };
        ensure_node(nodes, &from);
        ensure_node(nodes, &to);
        *directed.entry((from, to, kind)).or_insert(0) += 1;
    }
    directed
}

/// Undirected co-occurrence weights: distinct hosts within `window_secs`.
fn build_cooccurrence(
    events: &[BrowserEvent],
    window_secs: i64,
) -> BTreeMap<(String, String), usize> {
    let mut cooc: BTreeMap<(String, String), usize> = BTreeMap::new();
    if window_secs <= 0 {
        return cooc;
    }
    let window_ns = window_secs.saturating_mul(NANOS_PER_SEC);
    let mut timed: Vec<(i64, String)> = events
        .iter()
        .filter(|e| e.timestamp_ns != 0)
        .filter_map(|e| primary_registrable_domain(e).map(|h| (e.timestamp_ns, h)))
        .collect();
    timed.sort_by_key(|(ts, _)| *ts);
    for i in 0..timed.len() {
        let (ti, hi) = (timed[i].0, timed[i].1.clone());
        let mut scanned = 0usize;
        let mut j = i + 1;
        while j < timed.len() && scanned < NEIGHBOR_SCAN_CAP {
            let (tj, hj) = (timed[j].0, &timed[j].1);
            if tj - ti > window_ns {
                break;
            }
            if &hi != hj {
                let key = if hi < *hj {
                    (hi.clone(), hj.clone())
                } else {
                    (hj.clone(), hi.clone())
                };
                *cooc.entry(key).or_insert(0) += 1;
            }
            j += 1;
            scanned += 1;
        }
    }
    cooc
}

/// Build a bounded [`EntityGraph`] over `events`.
///
/// Navigation reconstruction (M3 `resolve_referrer_chains`) is run on a private
/// copy so referrer/redirect edges reflect the recorded `from_visit` linkage.
#[must_use]
pub fn entity_graph(events: &[BrowserEvent], config: GraphConfig) -> EntityGraph {
    // Reconstruct referrer linkage on a private copy (input stays untouched).
    let mut work = events.to_vec();
    resolve_referrer_chains(&mut work);

    let mut node_map = build_nodes(&work);
    let directed = build_directed_edges(&work, &mut node_map);
    let cooc = build_cooccurrence(&work, config.cooccurrence_window_secs);

    // Truncate nodes by event count (deterministic order).
    let mut nodes: Vec<GraphNode> = node_map
        .into_iter()
        .map(|(id, (event_count, browsers))| GraphNode {
            id,
            event_count,
            browsers: browsers.into_iter().collect(),
        })
        .collect();
    nodes.sort_by(|a, b| {
        b.event_count
            .cmp(&a.event_count)
            .then_with(|| a.id.cmp(&b.id))
    });
    let nodes_truncated = nodes.len() > config.max_nodes;
    nodes.truncate(config.max_nodes);
    let kept: std::collections::HashSet<&str> = nodes.iter().map(|n| n.id.as_str()).collect();

    // Assemble edges, dropping any that reference a truncated node.
    let mut edges: Vec<GraphEdge> = Vec::new();
    for ((from, to, kind), weight) in directed {
        if kept.contains(from.as_str()) && kept.contains(to.as_str()) {
            edges.push(GraphEdge {
                from,
                to,
                kind,
                weight,
            });
        }
    }
    for ((a, b), weight) in cooc {
        if kept.contains(a.as_str()) && kept.contains(b.as_str()) {
            edges.push(GraphEdge {
                from: a,
                to: b,
                kind: EdgeKind::CoOccurrence,
                weight,
            });
        }
    }
    edges.sort_by(|x, y| {
        y.weight
            .cmp(&x.weight)
            .then_with(|| x.from.cmp(&y.from))
            .then_with(|| x.to.cmp(&y.to))
            .then_with(|| x.kind.label().cmp(y.kind.label()))
    });
    let edges_truncated = edges.len() > config.max_edges;
    edges.truncate(config.max_edges);

    EntityGraph {
        nodes,
        edges,
        cooccurrence_window_secs: config.cooccurrence_window_secs,
        nodes_truncated,
        edges_truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser_forensic_core::{ArtifactKind, BrowserFamily};
    use serde_json::json;

    fn visit(id: i64, from: i64, ts: i64, url: &str) -> BrowserEvent {
        BrowserEvent::new(
            ts,
            BrowserFamily::Chromium,
            ArtifactKind::History,
            "/src",
            url,
        )
        .with_attr("url", json!(url))
        .with_attr("visit_id", json!(id))
        .with_attr("from_visit", json!(from))
    }

    #[test]
    fn referrer_edge_from_m3_linkage() {
        let events = vec![
            visit(1, 0, 1000, "https://a.example/"),
            visit(2, 1, 2000, "https://b.example/"),
        ];
        let g = entity_graph(&events, GraphConfig::default());
        let e = g
            .edges
            .iter()
            .find(|e| e.kind == EdgeKind::Referrer)
            .expect("referrer edge");
        assert_eq!(e.from, "a.example");
        assert_eq!(e.to, "b.example");
        assert_eq!(e.weight, 1);
    }

    #[test]
    fn redirect_flag_marks_edge_kind() {
        let events = vec![
            visit(1, 0, 1000, "https://a.example/"),
            visit(2, 1, 2000, "https://b.example/").with_attr("is_redirect", json!(true)),
        ];
        let g = entity_graph(&events, GraphConfig::default());
        assert!(g
            .edges
            .iter()
            .any(|e| e.kind == EdgeKind::Redirect && e.from == "a.example" && e.to == "b.example"));
    }

    #[test]
    fn cooccurrence_edge_within_window_only() {
        // Two distinct hosts 5s apart -> co-occurrence with a 30s window.
        let near = vec![
            BrowserEvent::new(
                1_000_000_000,
                BrowserFamily::Chromium,
                ArtifactKind::History,
                "/s",
                "d",
            )
            .with_attr("url", json!("https://x.example/")),
            BrowserEvent::new(
                6_000_000_000,
                BrowserFamily::Chromium,
                ArtifactKind::Cookies,
                "/s",
                "d",
            )
            .with_attr("url", json!("https://y.example/")),
        ];
        let g = entity_graph(&near, GraphConfig::default());
        assert!(g.edges.iter().any(|e| e.kind == EdgeKind::CoOccurrence
            && e.from == "x.example"
            && e.to == "y.example"));

        // Same events 60s apart -> outside a 30s window, no co-occurrence.
        let far = vec![
            BrowserEvent::new(
                1_000_000_000,
                BrowserFamily::Chromium,
                ArtifactKind::History,
                "/s",
                "d",
            )
            .with_attr("url", json!("https://x.example/")),
            BrowserEvent::new(
                61_000_000_000,
                BrowserFamily::Chromium,
                ArtifactKind::Cookies,
                "/s",
                "d",
            )
            .with_attr("url", json!("https://y.example/")),
        ];
        let g2 = entity_graph(&far, GraphConfig::default());
        assert!(!g2.edges.iter().any(|e| e.kind == EdgeKind::CoOccurrence));
    }

    #[test]
    fn nodes_carry_count_and_browsers() {
        let events = vec![
            visit(1, 0, 1000, "https://a.example/"),
            BrowserEvent::new(
                2000,
                BrowserFamily::Firefox,
                ArtifactKind::Cookies,
                "/s",
                "d",
            )
            .with_attr("url", json!("https://a.example/x")),
        ];
        let g = entity_graph(&events, GraphConfig::default());
        let n = g.nodes.iter().find(|n| n.id == "a.example").expect("node");
        assert_eq!(n.event_count, 2);
        assert!(n.browsers.contains(&"Chromium".to_string()));
        assert!(n.browsers.contains(&"Firefox".to_string()));
    }

    #[test]
    fn node_cap_truncates_and_drops_dangling_edges() {
        let events = vec![
            visit(1, 0, 1000, "https://a.example/"),
            visit(2, 1, 2000, "https://b.example/"),
        ];
        let cfg = GraphConfig {
            max_nodes: 1,
            ..GraphConfig::default()
        };
        let g = entity_graph(&events, cfg);
        assert_eq!(g.nodes.len(), 1);
        assert!(g.nodes_truncated);
        // The only surviving node cannot support the a->b edge.
        assert!(g.edges.is_empty());
    }
}
