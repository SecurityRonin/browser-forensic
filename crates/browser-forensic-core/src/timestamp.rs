// crates/browser-forensic-core/src/timestamp.rs

pub use forensicnomicon::heuristics::{CORE_DATA_EPOCH_OFFSET_SECS, WEBKIT_EPOCH_OFFSET_US};
pub use forensicnomicon::temporal::FILETIME_EPOCH_OFFSET;

// All conversions use saturating arithmetic: untrusted browser artifacts can
// carry extreme integer values, and a parser must clamp rather than panic on
// overflow (never-panic invariant — CLAUDE.md robustness).

pub fn webkit_micros_to_unix_nanos(webkit_us: i64) -> i64 {
    webkit_us
        .saturating_sub(WEBKIT_EPOCH_OFFSET_US)
        .saturating_mul(1_000)
}

pub fn core_data_secs_to_unix_nanos(core_data_secs: f64) -> i64 {
    ((core_data_secs as i64).saturating_add(CORE_DATA_EPOCH_OFFSET_SECS))
        .saturating_mul(1_000_000_000)
}

pub fn unix_micros_to_nanos(us: i64) -> i64 {
    us.saturating_mul(1_000)
}

pub fn unix_millis_to_nanos(ms: i64) -> i64 {
    ms.saturating_mul(1_000_000)
}

pub fn unix_secs_to_nanos(secs: i64) -> i64 {
    secs.saturating_mul(1_000_000_000)
}

/// Convert Unix epoch **seconds** carried as a floating-point value (Chromium's
/// `TransportSecurity` `sts_observed` / `expiry`) into Unix nanoseconds,
/// preserving sub-second precision without hand-rolling epoch math.
pub fn unix_secs_f64_to_nanos(secs: f64) -> i64 {
    let whole = secs.trunc() as i64;
    let frac_ns = (secs.fract() * 1_000_000_000.0) as i64;
    whole * 1_000_000_000 + frac_ns
}

/// Convert a Windows `FILETIME` (100 ns ticks since 1601-01-01 UTC) into Unix
/// nanoseconds. Used by the IE / Edge-Legacy WebCache (ESE) parser, whose
/// `Container_#` timestamp columns (`AccessedTime`, `ModifiedTime`,
/// `CreationTime`, `ExpiryTime`, …) are little-endian FILETIMEs.
///
/// Reuses [`FILETIME_EPOCH_OFFSET`] (forensicnomicon) rather than hand-rolling
/// the 1601→1970 epoch math. Computation is done in `i128` and clamped to
/// `i64`, so an adversarial WebCache record carrying an extreme FILETIME (or a
/// `0` "not set" value, which pre-dates 1970) clamps rather than
/// overflow-panics (never-panic invariant for parsers).
#[must_use]
pub fn filetime_to_unix_nanos(ft: u64) -> i64 {
    let ticks_since_unix = i128::from(ft) - i128::from(FILETIME_EPOCH_OFFSET);
    let nanos = ticks_since_unix * 100;
    i64::try_from(nanos).unwrap_or(if nanos.is_negative() {
        i64::MIN
    } else {
        i64::MAX
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webkit_epoch_at_unix_epoch_returns_zero() {
        // WebKit epoch value that represents 1970-01-01 00:00:00 UTC
        let webkit_us = WEBKIT_EPOCH_OFFSET_US;
        assert_eq!(webkit_micros_to_unix_nanos(webkit_us), 0);
    }

    #[test]
    fn webkit_one_second_after_unix_epoch() {
        let webkit_us = WEBKIT_EPOCH_OFFSET_US + 1_000_000;
        assert_eq!(webkit_micros_to_unix_nanos(webkit_us), 1_000_000_000);
    }

    #[test]
    fn core_data_epoch_at_unix_offset_returns_negative_secs() {
        // 0.0 in Core Data = 2001-01-01 = 978307200 seconds after Unix epoch
        assert_eq!(
            core_data_secs_to_unix_nanos(0.0),
            CORE_DATA_EPOCH_OFFSET_SECS * 1_000_000_000
        );
    }

    #[test]
    fn core_data_one_second_later() {
        assert_eq!(
            core_data_secs_to_unix_nanos(1.0),
            (CORE_DATA_EPOCH_OFFSET_SECS + 1) * 1_000_000_000
        );
    }

    #[test]
    fn unix_micros_to_nanos_multiplies_by_1000() {
        assert_eq!(unix_micros_to_nanos(1_000_000), 1_000_000_000);
        assert_eq!(unix_micros_to_nanos(0), 0);
    }

    #[test]
    fn unix_millis_to_nanos_multiplies_by_1_000_000() {
        assert_eq!(unix_millis_to_nanos(1_000), 1_000_000_000);
    }

    #[test]
    fn unix_secs_to_nanos_multiplies_by_1_000_000_000() {
        assert_eq!(unix_secs_to_nanos(1), 1_000_000_000);
    }

    #[test]
    fn conversions_saturate_on_adversarial_input_never_panic() {
        // Untrusted artifacts can carry extreme integers; conversion must clamp,
        // never overflow-panic (never-panic invariant for parsers).
        assert_eq!(webkit_micros_to_unix_nanos(i64::MAX), i64::MAX);
        assert_eq!(webkit_micros_to_unix_nanos(i64::MIN), i64::MIN);
        assert_eq!(unix_secs_to_nanos(i64::MAX), i64::MAX);
        assert_eq!(unix_millis_to_nanos(i64::MIN), i64::MIN);
        assert_eq!(unix_micros_to_nanos(i64::MAX), i64::MAX);
    }

    #[test]
    fn unix_secs_f64_preserves_subsecond() {
        assert_eq!(unix_secs_f64_to_nanos(1.0), 1_000_000_000);
        assert_eq!(
            unix_secs_f64_to_nanos(1_700_000_000.5),
            1_700_000_000_500_000_000
        );
        assert_eq!(unix_secs_f64_to_nanos(0.0), 0);
    }

    #[test]
    fn filetime_at_unix_epoch_returns_zero() {
        // FILETIME == epoch offset represents 1970-01-01 00:00:00 UTC.
        assert_eq!(filetime_to_unix_nanos(FILETIME_EPOCH_OFFSET), 0);
    }

    #[test]
    fn filetime_one_second_after_unix_epoch() {
        // +1 second = +10,000,000 ticks of 100 ns.
        let ft = FILETIME_EPOCH_OFFSET + 10_000_000;
        assert_eq!(filetime_to_unix_nanos(ft), 1_000_000_000);
    }

    #[test]
    fn filetime_preserves_100ns_precision() {
        // One 100 ns tick past the epoch = 100 ns, not truncated to a second.
        let ft = FILETIME_EPOCH_OFFSET + 1;
        assert_eq!(filetime_to_unix_nanos(ft), 100);
    }

    #[test]
    fn filetime_known_value_2023_01_01() {
        // 2023-01-01T00:00:00Z: Unix secs 1_672_531_200.
        // FILETIME = (1_672_531_200 + 11_644_473_600) * 10_000_000.
        let ft = (1_672_531_200u64 + 11_644_473_600u64) * 10_000_000;
        assert_eq!(filetime_to_unix_nanos(ft), 1_672_531_200_000_000_000);
    }

    #[test]
    fn filetime_adversarial_extremes_never_panic() {
        // Untrusted WebCache records can carry extreme FILETIMEs; conversion
        // must clamp, never overflow-panic (never-panic invariant for parsers).
        assert_eq!(filetime_to_unix_nanos(u64::MAX), i64::MAX);
        // FILETIME 0 ("not set") pre-dates 1970 by far → clamps to i64::MIN.
        assert_eq!(filetime_to_unix_nanos(0), i64::MIN);
    }
}
