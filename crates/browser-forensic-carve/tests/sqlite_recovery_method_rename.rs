//! Fleet ADR 0001 §3: the browser-forensic-carve recovery-method enum is a
//! SQLite-record *substrate* detail and must not squat the fleet-level
//! `RecoveryMethod` name (owned by the `forensic-carve` crate). It is renamed to
//! `SqliteRecoveryMethod`; the old `RecoveryMethod` name survives only as a
//! deprecated type alias for source compatibility.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use browser_forensic_carve::SqliteRecoveryMethod;

/// The renamed enum exists and carries all four recovery substrates.
#[test]
fn sqlite_recovery_method_has_four_variants() {
    let variants = [
        SqliteRecoveryMethod::FreePage,
        SqliteRecoveryMethod::WalUncommitted,
        SqliteRecoveryMethod::JournalRollback,
        SqliteRecoveryMethod::DirectScan,
    ];
    assert_eq!(variants.len(), 4);
    // Serializes under the new name's variant tags, not a wrapper.
    let json = serde_json::to_string(&SqliteRecoveryMethod::DirectScan).expect("serialize");
    assert!(json.contains("DirectScan"), "got {json}");
}

/// The deprecated alias `RecoveryMethod` still resolves to `SqliteRecoveryMethod`
/// (type identity), so existing downstream `use`s keep compiling.
#[test]
#[allow(deprecated)]
fn deprecated_alias_resolves_to_renamed_enum() {
    use browser_forensic_carve::RecoveryMethod;
    // Type-identity check: assigning an alias-typed value into the new type only
    // compiles if the alias *is* SqliteRecoveryMethod.
    let via_alias: SqliteRecoveryMethod = RecoveryMethod::FreePage;
    assert!(matches!(via_alias, SqliteRecoveryMethod::FreePage));
}
