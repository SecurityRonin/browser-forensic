//! Small, bounds-safe helpers shared across the reconstruction outputs.

/// Escape a string for safe inclusion in HTML text or a double-quoted
/// attribute value. Conservative: escapes `&`, `<`, `>`, `"`, and `'` so a
/// cached URL or note can never break out of the surrounding markup.
#[must_use]
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}
