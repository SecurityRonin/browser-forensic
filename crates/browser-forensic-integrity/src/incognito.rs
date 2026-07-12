//! Incognito-usage indicator: residue-plus-absence.
//!
//! A private/incognito session writes almost nothing to disk, yet network/state
//! artifacts (Chromium `Network Persistent State`, DNS/`Reporting and NEL`,
//! `Media History`) can still name domains the browser contacted. A domain that
//! appears in that residue but has NO corresponding `history`/`visits` entry is
//! consistent with a private session — or, equally, with normal browsing whose
//! history was later cleared. Both explanations are reported; neither is proof.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IntegrityIndicator;

    #[test]
    fn residual_domain_absent_from_history_fires() {
        let residual = vec![
            (
                "secret.example.com".to_string(),
                "Network Persistent State".to_string(),
            ),
            ("known.example.com".to_string(), "Media History".to_string()),
        ];
        let history = vec!["known.example.com".to_string()];

        let result = check_incognito_residue(&residual, &history);
        assert!(
            result.iter().any(|i| matches!(
                i,
                IntegrityIndicator::IncognitoResidue { residual_domain, .. }
                    if residual_domain == "secret.example.com"
            )),
            "a residual domain missing from history should fire, got {result:?}"
        );
        assert!(
            !result.iter().any(|i| matches!(
                i,
                IntegrityIndicator::IncognitoResidue { residual_domain, .. }
                    if residual_domain == "known.example.com"
            )),
            "a residual domain present in history must NOT fire, got {result:?}"
        );
    }

    #[test]
    fn matching_is_case_insensitive() {
        let residual = vec![(
            "Known.Example.com".to_string(),
            "Network Persistent State".to_string(),
        )];
        let history = vec!["known.example.COM".to_string()];
        let result = check_incognito_residue(&residual, &history);
        assert!(
            result.is_empty(),
            "case-insensitive domain match should suppress the finding, got {result:?}"
        );
    }

    #[test]
    fn no_residual_yields_nothing() {
        let result = check_incognito_residue(&[], &["a.com".to_string()]);
        assert!(result.is_empty());
    }
}
