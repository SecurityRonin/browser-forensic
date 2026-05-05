//! Chrome Local State JSON parser.

#[cfg(test)]
mod tests {
    use super::*;
    use browser_core::ArtifactKind;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn parse_local_state_extracts_profiles() {
        let json_data = r#"{
            "profile": {
                "info_cache": {
                    "Default": {
                        "name": "Person 1",
                        "user_name": "user@example.com",
                        "is_using_default_name": false,
                        "active_time": 1700000000.0
                    },
                    "Profile 1": {
                        "name": "Work",
                        "user_name": "work@example.com",
                        "is_using_default_name": false,
                        "active_time": 1700000001.0
                    }
                },
                "last_used": "Default"
            }
        }"#;
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(json_data.as_bytes()).expect("write");

        let events = parse_local_state(f.path()).expect("parse");
        assert!(!events.is_empty(), "should extract profile events");
        assert!(events.iter().any(|e| e.description.contains("Person 1")));
        assert!(events.iter().any(|e| e.description.contains("Work")));
        assert!(events.iter().all(|e| e.artifact == ArtifactKind::Session));
    }

    #[test]
    fn parse_local_state_empty_profiles_returns_empty() {
        let json_data = r#"{"profile": {"info_cache": {}}}"#;
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(json_data.as_bytes()).expect("write");

        let events = parse_local_state(f.path()).expect("parse");
        assert!(events.is_empty());
    }

    #[test]
    fn parse_local_state_missing_file_returns_error() {
        let result = parse_local_state(std::path::Path::new("/nonexistent/Local State"));
        assert!(result.is_err());
    }
}
