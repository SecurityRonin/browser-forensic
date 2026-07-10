//! Firefox `prefs.js` parser.
//!
//! Firefox stores its per-profile settings as a flat list of
//! `user_pref("key", value);` statements. Each statement becomes one
//! [`BrowserEvent`] with the key and value carried in attrs.

use std::path::Path;

use anyhow::Result;
#[allow(unused_imports)]
use browser_forensic_core::{ArtifactKind, BrowserEvent, BrowserFamily};
#[allow(unused_imports)]
use serde_json::json;

/// Parse a Firefox `prefs.js` (or `user.js`) file.
///
/// Emits one [`BrowserEvent`] per `user_pref(...)` statement. Values are
/// normalised: quoted strings are unquoted; `true`/`false`/integers are kept
/// verbatim.
///
/// # Errors
///
/// Returns an error if the file cannot be read.
#[allow(unused_variables)]
pub fn parse_preferences(_path: &Path) -> Result<Vec<BrowserEvent>> {
    Ok(Vec::new())
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
