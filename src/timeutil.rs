//! Minimal UTC time formatting (RFC 3339) without a date-time dependency.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch (0 if the clock is before 1970).
pub fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Days since 1970-01-01 -> (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// (year, month, day) -> days since 1970-01-01.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from(if month > 2 { month - 3 } else { month + 9 });
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `2026-11-12T09:31:00Z`
pub fn format_rfc3339(time: SystemTime) -> String {
    let secs = unix_seconds(time);
    let (year, month, day) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

pub fn now_rfc3339() -> String {
    format_rfc3339(SystemTime::now())
}

/// `2026-11-12` (UTC), used as the key for daily AI budgets.
pub fn today_utc() -> String {
    now_rfc3339()[..10].to_owned()
}

/// Parses the subset of RFC 3339 this crate writes plus the common variants
/// returned by NVD and OSV: optional fractional seconds, `Z` or a numeric
/// offset, or no zone at all (treated as UTC).
pub fn parse_rfc3339(text: &str) -> Option<SystemTime> {
    let bytes = text.as_bytes();
    if bytes.len() < 19 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[13] != b':' {
        return None;
    }
    if !matches!(bytes[10], b'T' | b't' | b' ') || bytes[16] != b':' {
        return None;
    }
    let num = |range: std::ops::Range<usize>| text.get(range)?.parse::<i64>().ok();
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    let mut rest = &text[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        rest = &fraction[digits..];
    }
    let offset = match rest {
        "" | "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes()[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let (h, m) = rest[1..].split_once(':')?;
            sign * (h.parse::<i64>().ok()? * 3600 + m.parse::<i64>().ok()? * 60)
        }
    };
    let days = days_from_civil(year, month as u32, day as u32);
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second - offset;
    u64::try_from(secs)
        .ok()
        .map(|secs| UNIX_EPOCH + Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn formats_known_instants() {
        assert_eq!(format_rfc3339(at(0)), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(at(951_782_400)), "2000-02-29T00:00:00Z");
        assert_eq!(format_rfc3339(at(1_794_476_460)), "2026-11-12T09:41:00Z");
        assert_eq!(format_rfc3339(at(4_102_444_799)), "2099-12-31T23:59:59Z");
    }

    #[test]
    fn round_trips_every_day_boundary_for_a_century() {
        for day in 0..36_600u64 {
            let instant = at(day * 86_400 + 86_399);
            let text = format_rfc3339(instant);
            assert_eq!(parse_rfc3339(&text), Some(instant), "{text}");
        }
    }

    #[test]
    fn parses_variants_from_external_apis() {
        let expected = Some(at(1_794_476_460));
        for text in [
            "2026-11-12T09:41:00Z",
            "2026-11-12T09:41:00.123Z",
            "2026-11-12T09:41:00.000",
            "2026-11-12 09:41:00",
            "2026-11-12T10:41:00+01:00",
            "2026-11-12T05:11:00.5-04:30",
        ] {
            assert_eq!(parse_rfc3339(text), expected, "{text}");
        }
        for bad in [
            "",
            "2026-11-12",
            "2026-13-01T00:00:00Z",
            "not a date at all!",
            "2026-11-12T09:41:00X",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
    }

    #[test]
    fn today_is_a_date() {
        let today = today_utc();
        assert_eq!(today.len(), 10);
        assert!(parse_rfc3339(&format!("{today}T00:00:00Z")).is_some());
    }
}
