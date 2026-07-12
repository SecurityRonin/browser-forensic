//! Render an [`EntityGraph`] for external graph tooling: JSON (nodes/edges) and
//! Graphviz DOT.

use std::fmt::Write as _;

use crate::graph::{EdgeKind, EntityGraph};

/// Serialize the graph as pretty JSON with `nodes` and `edges` arrays.
#[must_use]
pub fn to_json(graph: &EntityGraph) -> String {
    let _ = graph;
    String::new()
}

/// Escape a string for use inside a double-quoted Graphviz identifier/label.
fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Render the graph as a Graphviz DOT digraph.
///
/// Referrer/redirect edges are directed; co-occurrence edges are undirected
/// (`dir=none`, dashed) since they carry no direction. Every edge label states
/// its kind and weight; co-occurrence labels also state the window.
#[must_use]
pub fn to_dot(graph: &EntityGraph) -> String {
    if graph.nodes.is_empty() || !graph.nodes.is_empty() {
        let _ = dot_escape;
        return String::new(); // RED stub — real impl restored in GREEN.
    }
    let mut out = String::new();
    out.push_str("digraph browser_entity_graph {\n");
    out.push_str("  rankdir=LR;\n");
    out.push_str("  node [shape=box, fontname=\"sans-serif\"];\n");

    for node in &graph.nodes {
        let id = dot_escape(&node.id);
        let _ = writeln!(
            out,
            "  \"{id}\" [label=\"{id}\\n{count} event(s)\"];",
            count = node.event_count
        );
    }

    for edge in &graph.edges {
        let from = dot_escape(&edge.from);
        let to = dot_escape(&edge.to);
        let attrs = match edge.kind {
            EdgeKind::CoOccurrence => format!(
                "label=\"{kind} <={window}s (x{w})\", weight={w}, dir=none, style=dashed",
                kind = edge.kind.label(),
                window = graph.cooccurrence_window_secs,
                w = edge.weight,
            ),
            EdgeKind::Referrer | EdgeKind::Redirect => format!(
                "label=\"{kind} (x{w})\", weight={w}",
                kind = edge.kind.label(),
                w = edge.weight,
            ),
        };
        let _ = writeln!(out, "  \"{from}\" -> \"{to}\" [{attrs}];");
    }

    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{entity_graph, GraphConfig, GraphEdge, GraphNode};
    use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
    use serde_json::json;

    fn sample_graph() -> EntityGraph {
        let events = vec![
            BrowserEvent::new(
                1000,
                BrowserFamily::Chromium,
                ArtifactKind::History,
                "/s",
                "a",
            )
            .with_attr("url", json!("https://a.example/"))
            .with_attr("visit_id", json!(1))
            .with_attr("from_visit", json!(0)),
            BrowserEvent::new(
                2000,
                BrowserFamily::Chromium,
                ArtifactKind::History,
                "/s",
                "b",
            )
            .with_attr("url", json!("https://b.example/"))
            .with_attr("visit_id", json!(2))
            .with_attr("from_visit", json!(1)),
        ];
        entity_graph(&events, GraphConfig::default())
    }

    #[test]
    fn json_round_trips_with_nodes_and_edges() {
        let g = sample_graph();
        let s = to_json(&g);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v.get("nodes").and_then(|n| n.as_array()).is_some());
        assert!(v.get("edges").and_then(|e| e.as_array()).is_some());
        // referrer edge is present in the serialized form
        assert!(s.contains("referrer"));
    }

    #[test]
    fn dot_has_digraph_nodes_and_labelled_edges() {
        let g = sample_graph();
        let dot = to_dot(&g);
        assert!(dot.starts_with("digraph browser_entity_graph {"));
        assert!(dot.contains("\"a.example\" [label=\"a.example"));
        assert!(dot.contains("\"a.example\" -> \"b.example\""));
        assert!(dot.contains("referrer"));
        assert!(dot.trim_end().ends_with('}'));
    }

    #[test]
    fn dot_marks_cooccurrence_undirected() {
        let g = EntityGraph {
            nodes: vec![
                GraphNode {
                    id: "x.example".to_string(),
                    event_count: 1,
                    browsers: vec!["Chromium".to_string()],
                },
                GraphNode {
                    id: "y.example".to_string(),
                    event_count: 1,
                    browsers: vec!["Chromium".to_string()],
                },
            ],
            edges: vec![GraphEdge {
                from: "x.example".to_string(),
                to: "y.example".to_string(),
                kind: EdgeKind::CoOccurrence,
                weight: 2,
            }],
            cooccurrence_window_secs: 30,
            nodes_truncated: false,
            edges_truncated: false,
        };
        let dot = to_dot(&g);
        assert!(dot.contains("dir=none"));
        assert!(dot.contains("co-occurrence <=30s (x2)"));
    }

    #[test]
    fn dot_escapes_quotes_in_host() {
        let g = EntityGraph {
            nodes: vec![GraphNode {
                id: "we\"ird.example".to_string(),
                event_count: 1,
                browsers: vec![],
            }],
            edges: vec![],
            cooccurrence_window_secs: 30,
            nodes_truncated: false,
            edges_truncated: false,
        };
        let dot = to_dot(&g);
        assert!(dot.contains("we\\\"ird.example"));
    }
}
