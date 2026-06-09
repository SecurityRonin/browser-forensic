//! PII redaction — the MCP's second wall.
//!
//! History evidence is not automatically safe: URLs carry OAuth codes, password-
//! reset tokens, and API keys (usually in the query string), and titles/search
//! terms carry emails and secrets. These functions strip and mask that material
//! before it reaches an AI. Heuristic by design (defense-in-depth); the primary
//! guarantee is that secret *readers* are never called.

/// Strip the query string and fragment from a URL — where reset tokens, OAuth
/// codes, and API keys overwhelmingly live. Keeps scheme://host/path.
pub fn redact_url(url: &str) -> String {
    todo!("implemented in the GREEN step")
}

/// Mask emails and long token-like substrings in free text (titles, search
/// terms). Whitespace is normalized to single spaces.
pub fn mask_secrets(text: &str) -> String {
    todo!("implemented in the GREEN step")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_url_strips_query_and_fragment() {
        assert_eq!(
            redact_url("https://site.com/reset?token=SECRETVALUE&x=1#frag"),
            "https://site.com/reset"
        );
    }

    #[test]
    fn redact_url_keeps_plain_url() {
        assert_eq!(redact_url("https://site.com/a/b"), "https://site.com/a/b");
    }

    #[test]
    fn redact_url_strips_bare_fragment() {
        assert_eq!(redact_url("https://site.com/p#section"), "https://site.com/p");
    }

    #[test]
    fn mask_secrets_masks_email() {
        let out = mask_secrets("ping alice@example.com about it");
        assert!(out.contains("[redacted-email]"), "got: {out}");
        assert!(!out.contains("alice@example.com"));
    }

    #[test]
    fn mask_secrets_masks_long_token() {
        let out = mask_secrets("bearer deadbeefdeadbeefdeadbeef1234 ok");
        assert!(out.contains("[redacted]"), "got: {out}");
        assert!(!out.contains("deadbeefdeadbeefdeadbeef1234"));
    }

    #[test]
    fn mask_secrets_keeps_normal_words() {
        assert_eq!(mask_secrets("the quick brown fox"), "the quick brown fox");
    }
}
