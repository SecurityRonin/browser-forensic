// crates/browser-core/src/timestamp.rs

/// Offset in microseconds from 1601-01-01 to 1970-01-01 (WebKit epoch)
pub const WEBKIT_EPOCH_OFFSET_US: i64 = 11_644_473_600 * 1_000_000;

/// Offset in seconds from 2001-01-01 to 1970-01-01 (Core Data / Safari epoch)
pub const CORE_DATA_EPOCH_OFFSET_SECS: i64 = 978_307_200;

pub fn webkit_micros_to_unix_nanos(webkit_us: i64) -> i64 {
    todo!("not yet implemented")
}

pub fn core_data_secs_to_unix_nanos(core_data_secs: f64) -> i64 {
    todo!("not yet implemented")
}

pub fn unix_micros_to_nanos(us: i64) -> i64 {
    todo!("not yet implemented")
}

pub fn unix_millis_to_nanos(ms: i64) -> i64 {
    todo!("not yet implemented")
}

pub fn unix_secs_to_nanos(secs: i64) -> i64 {
    todo!("not yet implemented")
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
        assert_eq!(core_data_secs_to_unix_nanos(0.0), CORE_DATA_EPOCH_OFFSET_SECS * 1_000_000_000);
    }

    #[test]
    fn core_data_one_second_later() {
        assert_eq!(core_data_secs_to_unix_nanos(1.0), (CORE_DATA_EPOCH_OFFSET_SECS + 1) * 1_000_000_000);
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
