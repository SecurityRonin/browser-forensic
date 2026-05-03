//! Browser event analysis utilities.

use crate::BrowserEvent;

/// Count URL domains from events' `attrs["url"]` and return those with
/// `count <= cap`, sorted by count ascending.
///
/// Only events that have a valid URL in `attrs["url"]` are considered.
pub fn rare_domains(_events: &[BrowserEvent], _cap: usize) -> Vec<(String, usize)> {
    todo!("not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArtifactKind, BrowserEvent, BrowserFamily};
    use serde_json::json;

    fn make_history_event(url: &str) -> BrowserEvent {
        BrowserEvent::new(0, BrowserFamily::Chromium, ArtifactKind::History, "source", url)
            .with_attr("url", json!(url))
    }

    #[test]
    fn rare_domains_empty_events_returns_empty() {
        let result = rare_domains(&[], 5);
        assert!(result.is_empty());
    }

    #[test]
    fn rare_domains_below_cap_returned() {
        let events = vec![make_history_event("https://rare.example.com/page")];
        let result = rare_domains(&events, 5);
        assert!(result.iter().any(|(d, _)| d == "rare.example.com"));
    }

    #[test]
    fn rare_domains_above_cap_excluded() {
        // 10 visits to popular.com — count 10 > cap 5 — should be excluded
        let events: Vec<BrowserEvent> = (0..10)
            .map(|i| make_history_event(&format!("https://popular.com/page{i}")))
            .collect();
        let result = rare_domains(&events, 5);
        assert!(!result.iter().any(|(d, _)| d == "popular.com"));
    }

    #[test]
    fn rare_domains_sorted_by_count_ascending() {
        let mut events = Vec::new();
        // rare.com appears 1 time
        events.push(make_history_event("https://rare.com/page"));
        // semi-rare.com appears 2 times
        events.push(make_history_event("https://semi-rare.com/a"));
        events.push(make_history_event("https://semi-rare.com/b"));

        let result = rare_domains(&events, 5);
        let rare_pos = result.iter().position(|(d, _)| d == "rare.com");
        let semi_pos = result.iter().position(|(d, _)| d == "semi-rare.com");
        assert!(rare_pos.is_some() && semi_pos.is_some());
        assert!(rare_pos.unwrap() < semi_pos.unwrap());
    }
}
