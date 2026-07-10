//! Firefox `prefs.js` parser.
//!
//! Firefox stores its per-profile settings as a flat list of
//! `user_pref("key", value);` statements. Each statement becomes one
//! [`BrowserEvent`] with the key and value carried in attrs.

use std::path::Path;

use anyhow::Result;
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
use serde_json::json;

/// Parse one `user_pref("key", value);` statement into `(key, value)`.
///
/// Quoted string values are unquoted; `true`/`false`/integers are returned as
/// their literal text. Returns `None` for lines that are not `user_pref` calls
/// or are malformed.
fn parse_user_pref(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    let inner = line.strip_prefix("user_pref(")?;
    let inner = inner.trim_end();
    let inner = inner.strip_suffix(';')?.trim_end();
    let inner = inner.strip_suffix(')')?;

    // Key is the first double-quoted token.
    let rest = inner.trim_start();
    let rest = rest.strip_prefix('"')?;
    let key_end = rest.find('"')?;
    let key = &rest[..key_end];

    // Value follows the comma after the closing key quote.
    let after_key = &rest[key_end + 1..];
    let value_part = after_key.trim_start().strip_prefix(',')?.trim();
    let value = if let Some(s) = value_part.strip_prefix('"') {
        s.strip_suffix('"').unwrap_or(s).to_string()
    } else {
        value_part.to_string()
    };
    Some((key.to_string(), value))
}

/// Parse a Firefox `prefs.js` (or `user.js`) file.
///
/// Emits one [`BrowserEvent`] per `user_pref(...)` statement. Values are
/// normalised: quoted strings are unquoted; `true`/`false`/integers are kept
/// verbatim.
///
/// # Errors
///
/// Returns an error if the file cannot be read.
pub fn parse_preferences(path: &Path) -> Result<Vec<BrowserEvent>> {
    let data = std::fs::read_to_string(path)?;
    let source = path.to_string_lossy().into_owned();
    let mut events = Vec::new();
    for line in data.lines() {
        if let Some((key, value)) = parse_user_pref(line) {
            events.push(
                BrowserEvent::new(
                    0,
                    BrowserFamily::Firefox,
                    ArtifactKind::Preferences,
                    &source,
                    format!("{key} = {value}"),
                )
                .with_attr("key", json!(key))
                .with_attr("value", json!(value)),
            );
        }
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_prefs(body: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(body.as_bytes()).expect("write");
        f
    }

    #[test]
    fn parses_string_bool_and_int_prefs() {
        let f = write_prefs(concat!(
            "// Mozilla User Preferences\n",
            "user_pref(\"browser.startup.homepage\", \"https://home.example.com\");\n",
            "user_pref(\"privacy.clearOnShutdown.history\", true);\n",
            "user_pref(\"browser.download.folderList\", 2);\n",
        ));
        let events = parse_preferences(f.path()).expect("parse");
        assert_eq!(events.len(), 3);
        assert!(events
            .iter()
            .all(|e| e.artifact == ArtifactKind::Preferences));
        let home = events
            .iter()
            .find(|e| e.attrs["key"] == json!("browser.startup.homepage"))
            .expect("homepage pref");
        assert_eq!(home.attrs["value"], json!("https://home.example.com"));
        let hist = events
            .iter()
            .find(|e| e.attrs["key"] == json!("privacy.clearOnShutdown.history"))
            .expect("clear-history pref");
        assert_eq!(hist.attrs["value"], json!("true"));
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let f = write_prefs("// comment\n\n# another\nuser_pref(\"a.b\", \"c\");\n");
        let events = parse_preferences(f.path()).expect("parse");
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn missing_file_returns_error() {
        assert!(parse_preferences(Path::new("/nonexistent/prefs.js")).is_err());
    }
}
