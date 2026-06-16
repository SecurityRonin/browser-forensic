// crates/browser-forensic-core/src/timestamp.rs

pub use forensicnomicon::heuristics::{CORE_DATA_EPOCH_OFFSET_SECS, WEBKIT_EPOCH_OFFSET_US};

pub fn webkit_micros_to_unix_nanos(webkit_us: i64) -> i64 {
    (webkit_us - WEBKIT_EPOCH_OFFSET_US) * 1_000
}

pub fn core_data_secs_to_unix_nanos(core_data_secs: f64) -> i64 {
    ((core_data_secs as i64) + CORE_DATA_EPOCH_OFFSET_SECS) * 1_000_000_000
}

pub fn unix_micros_to_nanos(us: i64) -> i64 {
    us * 1_000
}

pub fn unix_millis_to_nanos(ms: i64) -> i64 {
    ms * 1_000_000
}

pub fn unix_secs_to_nanos(secs: i64) -> i64 {
    secs * 1_000_000_000
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
}
