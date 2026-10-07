//! Shared WMI plumbing: connection handling and Variant extraction.

use std::collections::HashMap;

use wmi::{Variant, WMIConnection};

use crate::security::CollectorError;

pub type Row = HashMap<String, Variant>;

/// Run a WQL query against `namespace` and return the raw rows.
///
/// Rows come back as `Variant` maps rather than a serde-derived struct on
/// purpose: WMI classes vary by Windows build, and a missing or retyped
/// property should degrade one field to "unknown" rather than fail the whole
/// query with a deserialisation error.
pub fn query(namespace: &str, wql: &str) -> Result<Vec<Row>, CollectorError> {
    // The connection initialises COM for the calling thread itself and is
    // !Send, so it must be created and dropped inside this call. Callers are
    // responsible for running us on a blocking thread.
    let conn = WMIConnection::with_namespace_path(namespace)
        .map_err(|e| map_wmi_error(&format!("connecting to {namespace}"), e))?;

    conn.raw_query(wql)
        .map_err(|e| map_wmi_error(&format!("querying {wql}"), e))
}

/// Translate a WMI failure into the state the user will actually see.
fn map_wmi_error(during: &str, e: wmi::WMIError) -> CollectorError {
    let text = e.to_string();
    let lowered = text.to_ascii_lowercase();

    // 0x80041003 WBEM_E_ACCESS_DENIED / 0x80070005 E_ACCESSDENIED
    if lowered.contains("access denied")
        || lowered.contains("80041003")
        || lowered.contains("80070005")
    {
        return CollectorError::PermissionDenied(format!(
            "Windows refused access while {during}. Run SENTRY as an administrator to read this."
        ));
    }

    // 0x8004100E WBEM_E_INVALID_NAMESPACE - the feature is absent on this box.
    if lowered.contains("invalid namespace") || lowered.contains("8004100e") {
        return CollectorError::Unsupported(format!(
            "This system does not expose the WMI namespace needed while {during}."
        ));
    }

    CollectorError::Unavailable(format!("WMI failed while {during}: {text}"))
}

pub fn get_bool(row: &Row, key: &str) -> Option<bool> {
    match row.get(key)? {
        Variant::Bool(b) => Some(*b),
        // Some providers surface booleans as integers.
        Variant::I4(i) => Some(*i != 0),
        Variant::UI4(u) => Some(*u != 0),
        _ => None,
    }
}

pub fn get_string(row: &Row, key: &str) -> Option<String> {
    match row.get(key)? {
        Variant::String(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// Read a string array property.
///
/// WMI returns a single-element array as a bare string in some providers and as
/// a one-element array in others, so both shapes are accepted. An absent
/// property yields an empty list, which callers must not confuse with an
/// empty-but-present one -- see `defender_policy::read_exclusions`.
pub fn get_string_list(row: &Row, key: &str) -> Vec<String> {
    match row.get(key) {
        Some(Variant::Array(items)) => items
            .iter()
            .filter_map(|item| match item {
                Variant::String(s) if !s.is_empty() => Some(s.clone()),
                _ => None,
            })
            .collect(),
        Some(Variant::String(s)) if !s.is_empty() => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// Read an unsigned integer, rejecting the sentinel values Defender uses to
/// mean "never happened" (they arrive as u32::MAX and would otherwise render
/// as an alarming age of 4294967295 days).
pub fn get_u32(row: &Row, key: &str) -> Option<u32> {
    let raw = match row.get(key)? {
        Variant::UI4(u) => Some(*u),
        Variant::UI8(u) => u32::try_from(*u).ok(),
        Variant::I4(i) => u32::try_from(*i).ok(),
        Variant::I8(i) => u32::try_from(*i).ok(),
        Variant::UI2(u) => Some(u32::from(*u)),
        Variant::UI1(u) => Some(u32::from(*u)),
        _ => None,
    }?;

    if raw >= 0xFFFF_FFF0 {
        return None;
    }
    Some(raw)
}

/// Read a 64-bit unsigned integer.
///
/// Defender's ThreatID and DetectionID exceed 32 bits, and providers return
/// them variously as UI8, I8 or a decimal string.
pub fn get_u64(row: &Row, key: &str) -> Option<u64> {
    match row.get(key)? {
        Variant::UI8(v) => Some(*v),
        Variant::UI4(v) => Some(u64::from(*v)),
        Variant::I8(v) => u64::try_from(*v).ok(),
        Variant::I4(v) => u64::try_from(*v).ok(),
        Variant::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Parse a CIM_DATETIME (`yyyymmddHHMMSS.ffffff±UUU`) into an RFC 3339 string.
///
/// The trailing offset is minutes from UTC, not hours, and may be `***` when
/// the provider does not know it -- both cases are handled rather than assumed.
pub fn get_datetime_rfc3339(row: &Row, key: &str) -> Option<String> {
    let raw = get_string(row, key)?;
    parse_cim_datetime(&raw)
}

pub fn parse_cim_datetime(raw: &str) -> Option<String> {
    use chrono::{FixedOffset, NaiveDate, TimeZone};

    if raw.len() < 21 {
        return None;
    }

    let num = |range: std::ops::Range<usize>| raw.get(range)?.parse::<u32>().ok();

    let year = num(0..4)?;
    let month = num(4..6)?;
    let day = num(6..8)?;
    let hour = num(8..10)?;
    let minute = num(10..12)?;
    let second = num(12..14)?;
    let micros = raw
        .get(15..21)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    // Offset is in minutes; `***` means unknown, in which case treat as UTC.
    let offset_secs = match (raw.get(21..22), raw.get(22..25)) {
        (Some(sign), Some(mins)) if mins.chars().all(|c| c.is_ascii_digit()) => {
            let m: i32 = mins.parse().ok()?;
            if sign == "-" {
                -m * 60
            } else {
                m * 60
            }
        }
        _ => 0,
    };

    let naive = NaiveDate::from_ymd_opt(year as i32, month, day)?
        .and_hms_micro_opt(hour, minute, second, micros)?;

    FixedOffset::east_opt(offset_secs)?
        .from_local_datetime(&naive)
        .single()
        .map(|dt| dt.to_rfc3339())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_utc_cim_datetime() {
        let got = parse_cim_datetime("20260917143000.000000+000").unwrap();
        assert!(got.starts_with("2026-09-17T14:30:00"), "got {got}");
    }

    #[test]
    fn honours_a_positive_minute_offset() {
        // +060 is one hour east, not sixty hours.
        let got = parse_cim_datetime("20260917143000.000000+060").unwrap();
        assert!(got.ends_with("+01:00"), "got {got}");
    }

    #[test]
    fn honours_a_negative_offset() {
        let got = parse_cim_datetime("20260917143000.000000-300").unwrap();
        assert!(got.ends_with("-05:00"), "got {got}");
    }

    #[test]
    fn tolerates_an_unknown_offset() {
        assert!(parse_cim_datetime("20260917143000.000000+***").is_some());
    }

    #[test]
    fn rejects_rubbish() {
        assert!(parse_cim_datetime("").is_none());
        assert!(parse_cim_datetime("not a timestamp at all").is_none());
        assert!(
            parse_cim_datetime("20261317143000.000000+000").is_none(),
            "month 13"
        );
    }

    #[test]
    fn string_lists_accept_both_wmi_shapes() {
        let mut row = Row::new();

        row.insert(
            "ExclusionPath".into(),
            Variant::Array(vec![
                Variant::String(r"C:\Temp".into()),
                Variant::String(r"C:\Builds".into()),
            ]),
        );
        assert_eq!(get_string_list(&row, "ExclusionPath").len(), 2);

        // Some providers hand back a lone string instead of a one-element array.
        row.insert("ExclusionProcess".into(), Variant::String("a.exe".into()));
        assert_eq!(get_string_list(&row, "ExclusionProcess"), vec!["a.exe"]);

        // Absent and empty both yield nothing.
        assert!(get_string_list(&row, "Missing").is_empty());
        row.insert("Empty".into(), Variant::String(String::new()));
        assert!(get_string_list(&row, "Empty").is_empty());
    }

    #[test]
    fn string_lists_skip_non_string_elements() {
        let mut row = Row::new();
        row.insert(
            "Mixed".into(),
            Variant::Array(vec![
                Variant::String("keep".into()),
                Variant::UI4(7),
                Variant::Null,
            ]),
        );
        assert_eq!(get_string_list(&row, "Mixed"), vec!["keep"]);
    }

    #[test]
    fn reads_64_bit_ids_in_every_shape_providers_use() {
        let mut row = Row::new();

        row.insert("A".into(), Variant::UI8(2147483648000));
        assert_eq!(get_u64(&row, "A"), Some(2147483648000));

        row.insert("B".into(), Variant::UI4(42));
        assert_eq!(get_u64(&row, "B"), Some(42));

        row.insert("C".into(), Variant::String("1234567890123".into()));
        assert_eq!(get_u64(&row, "C"), Some(1234567890123));

        // A negative value is not a valid id and must not wrap around.
        row.insert("D".into(), Variant::I8(-5));
        assert_eq!(get_u64(&row, "D"), None);

        assert_eq!(get_u64(&row, "Missing"), None);
    }

    #[test]
    fn sentinel_ages_read_as_unknown() {
        let mut row = Row::new();
        row.insert("AntivirusSignatureAge".into(), Variant::UI4(u32::MAX));
        assert_eq!(get_u32(&row, "AntivirusSignatureAge"), None);

        row.insert("AntivirusSignatureAge".into(), Variant::UI4(3));
        assert_eq!(get_u32(&row, "AntivirusSignatureAge"), Some(3));
    }
}
