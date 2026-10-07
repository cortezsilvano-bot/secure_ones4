//! Version comparison for real-world Windows software.
//!
//! Vulnerability feeds express affected ranges as "< 23.01" or ">= 1.2, < 1.4",
//! and the installed version comes from whatever string a vendor chose to put
//! in the registry. Neither side is semver. `7.0.1`, `2026.5`, `1.2.3.4`,
//! `23.01`, `6.10.0.252.41` and `1.0.0-beta2` all occur in practice.
//!
//! The comparison here is therefore deliberately lenient about *shape* and
//! strict about *ordering*:
//!
//!   * Numeric segments compare numerically, so `10` sorts above `9` rather
//!     than below it as it would lexically. Getting this wrong is how a
//!     scanner declares a patched machine vulnerable, or worse, the reverse.
//!   * Missing trailing segments are treated as zero: `1.2` == `1.2.0`.
//!   * A pre-release suffix sorts *below* the same version without one, so
//!     `1.0.0-beta` < `1.0.0`.
//!   * Anything genuinely unparseable returns `None` rather than guessing,
//!     and the caller downgrades its confidence accordingly.

use std::cmp::Ordering;

/// One parsed version, as a list of comparable segments.
#[derive(Debug, Clone)]
pub struct Version {
    numbers: Vec<u64>,
    /// Text after the numeric part, e.g. "beta2". Empty for a release build.
    pre_release: String,
}

impl Version {
    /// Parse a version string, or `None` if it contains no digits at all.
    pub fn parse(raw: &str) -> Option<Version> {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }

        // Split the release part from any pre-release suffix. Both "-" and "+"
        // introduce one; a bare letter run does too ("1.0b2").
        let (release, pre) = match raw.find(['-', '+']) {
            Some(i) => (&raw[..i], raw[i + 1..].to_ascii_lowercase()),
            None => (raw, String::new()),
        };

        let mut numbers = Vec::new();
        let mut trailing_pre = String::new();

        for segment in release.split(['.', '_', ',']) {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }

            // Strip a leading alphabetic prefix such as the "v" in "v1.2.3",
            // but only before any number has been seen. After that point a
            // leading letter marks a pre-release ("1.0b2") and must not be
            // discarded, or "b2" would be read as the number 2.
            let segment = if numbers.is_empty() {
                segment.trim_start_matches(|c: char| c.is_ascii_alphabetic())
            } else {
                segment
            };
            if segment.is_empty() {
                continue;
            }

            // Take the leading digits; anything after them is a suffix.
            let digits: String = segment.chars().take_while(|c| c.is_ascii_digit()).collect();
            let rest: String = segment.chars().skip(digits.len()).collect();

            if digits.is_empty() {
                // A purely alphabetic segment before any number is noise
                // ("v", "version"); after one it is a pre-release marker.
                if !numbers.is_empty() {
                    trailing_pre = segment.to_ascii_lowercase();
                    break;
                }
                continue;
            }

            numbers.push(digits.parse::<u64>().ok()?);

            if !rest.is_empty() {
                trailing_pre = rest.to_ascii_lowercase();
                break;
            }
        }

        if numbers.is_empty() {
            return None;
        }

        let pre_release = if pre.is_empty() { trailing_pre } else { pre };

        Some(Version {
            numbers,
            pre_release,
        })
    }

    /// True when this is a pre-release build.
    pub fn is_pre_release(&self) -> bool {
        !self.pre_release.is_empty()
    }
}

// Equality is defined by the ordering, not by the raw segment lists: `1.2` and
// `1.2.0` are the same version, and a derived PartialEq would disagree with
// `cmp` about that.
impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare segment by segment, treating absent trailing segments as 0
        // so that 1.2 and 1.2.0 are equal rather than the shorter being lesser.
        let len = self.numbers.len().max(other.numbers.len());
        for i in 0..len {
            let a = self.numbers.get(i).copied().unwrap_or(0);
            let b = other.numbers.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                Ordering::Equal => continue,
                other => return other,
            }
        }

        // Equal numerically. A release outranks a pre-release of the same
        // number: 1.0.0 > 1.0.0-beta.
        match (self.pre_release.is_empty(), other.pre_release.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => self.pre_release.cmp(&other.pre_release),
        }
    }
}

/// An affected-version range from a vulnerability feed.
///
/// All bounds are optional; a range with none is unbounded and matches every
/// version, which is how feeds express "all versions are affected".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VersionRange {
    pub start_including: Option<String>,
    pub start_excluding: Option<String>,
    pub end_including: Option<String>,
    pub end_excluding: Option<String>,
}

impl VersionRange {
    pub fn is_unbounded(&self) -> bool {
        self.start_including.is_none()
            && self.start_excluding.is_none()
            && self.end_including.is_none()
            && self.end_excluding.is_none()
    }

    /// Does `version` fall inside this range?
    ///
    /// `None` means undecidable -- a bound was present but could not be
    /// parsed, so neither "affected" nor "safe" can honestly be returned.
    pub fn contains(&self, version: &Version) -> Option<bool> {
        let check = |bound: &Option<String>, ok: &dyn Fn(Ordering) -> bool| -> Option<bool> {
            match bound {
                None => Some(true),
                Some(raw) => {
                    let parsed = Version::parse(raw)?;
                    Some(ok(version.cmp(&parsed)))
                }
            }
        };

        let after_start_incl = check(&self.start_including, &|o| o != Ordering::Less)?;
        let after_start_excl = check(&self.start_excluding, &|o| o == Ordering::Greater)?;
        let before_end_incl = check(&self.end_including, &|o| o != Ordering::Greater)?;
        let before_end_excl = check(&self.end_excluding, &|o| o == Ordering::Less)?;

        Some(after_start_incl && after_start_excl && before_end_incl && before_end_excl)
    }

    /// Human-readable form for the evidence pane.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(v) = &self.start_including {
            parts.push(format!(">= {v}"));
        }
        if let Some(v) = &self.start_excluding {
            parts.push(format!("> {v}"));
        }
        if let Some(v) = &self.end_including {
            parts.push(format!("<= {v}"));
        }
        if let Some(v) = &self.end_excluding {
            parts.push(format!("< {v}"));
        }
        if parts.is_empty() {
            "all versions".to_string()
        } else {
            parts.join(", ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap_or_else(|| panic!("failed to parse {s:?}"))
    }

    #[test]
    fn parses_ordinary_shapes() {
        assert_eq!(v("1.2.3").numbers, vec![1, 2, 3]);
        assert_eq!(v("23.01").numbers, vec![23, 1]);
        assert_eq!(v("6.10.0.252.41").numbers, vec![6, 10, 0, 252, 41]);
        assert_eq!(v("140").numbers, vec![140]);
    }

    #[test]
    fn tolerates_prefixes_and_separators() {
        assert_eq!(v("v1.2.3").numbers, vec![1, 2, 3]);
        assert_eq!(v("1_2_3").numbers, vec![1, 2, 3]);
        assert_eq!(v("  4.5  ").numbers, vec![4, 5]);
    }

    #[test]
    fn rejects_strings_with_no_digits() {
        assert!(Version::parse("").is_none());
        assert!(Version::parse("   ").is_none());
        assert!(Version::parse("unknown").is_none());
        assert!(Version::parse("latest").is_none());
    }

    #[test]
    fn numeric_segments_compare_numerically() {
        // The bug that matters: lexically "9" > "10", which would mark a
        // patched install as vulnerable.
        assert!(v("1.10") > v("1.9"));
        assert!(v("23.01") > v("9.99"));
        assert!(v("140.0") > v("99.0"));
    }

    #[test]
    fn missing_trailing_segments_are_zero() {
        assert_eq!(v("1.2"), v("1.2.0"));
        assert_eq!(v("1.2"), v("1.2.0.0"));
        assert!(v("1.2.1") > v("1.2"));
    }

    #[test]
    fn pre_releases_sort_below_their_release() {
        assert!(v("1.0.0") > v("1.0.0-beta"));
        assert!(v("1.0.0") > v("1.0.0-rc1"));
        assert!(v("2.0.0-alpha") < v("2.0.0"));
        assert!(!v("1.0.0").is_pre_release());
        assert!(v("1.0.0-beta").is_pre_release());
    }

    #[test]
    fn handles_a_letter_suffix_without_a_separator() {
        let parsed = v("1.0b2");
        assert_eq!(parsed.numbers, vec![1, 0]);
        assert!(parsed.is_pre_release());
        assert!(parsed < v("1.0"));
    }

    #[test]
    fn unbounded_range_matches_everything() {
        let range = VersionRange::default();
        assert!(range.is_unbounded());
        assert_eq!(range.contains(&v("0.1")), Some(true));
        assert_eq!(range.contains(&v("999")), Some(true));
        assert_eq!(range.describe(), "all versions");
    }

    #[test]
    fn exclusive_upper_bound_excludes_the_fixed_version() {
        // The classic feed shape: "fixed in 23.01" means < 23.01 is affected.
        let range = VersionRange {
            end_excluding: Some("23.01".into()),
            ..Default::default()
        };
        assert_eq!(range.contains(&v("21.07")), Some(true));
        assert_eq!(range.contains(&v("23.00")), Some(true));
        assert_eq!(
            range.contains(&v("23.01")),
            Some(false),
            "the fixed version is not affected"
        );
        assert_eq!(range.contains(&v("24.00")), Some(false));
    }

    #[test]
    fn inclusive_upper_bound_includes_it() {
        let range = VersionRange {
            end_including: Some("23.01".into()),
            ..Default::default()
        };
        assert_eq!(range.contains(&v("23.01")), Some(true));
        assert_eq!(range.contains(&v("23.02")), Some(false));
    }

    #[test]
    fn two_sided_ranges_work() {
        let range = VersionRange {
            start_including: Some("1.2".into()),
            end_excluding: Some("1.4".into()),
            ..Default::default()
        };
        assert_eq!(range.contains(&v("1.1")), Some(false));
        assert_eq!(range.contains(&v("1.2")), Some(true));
        assert_eq!(range.contains(&v("1.3.9")), Some(true));
        assert_eq!(range.contains(&v("1.4")), Some(false));
    }

    #[test]
    fn exclusive_lower_bound_excludes_it() {
        let range = VersionRange {
            start_excluding: Some("1.2".into()),
            ..Default::default()
        };
        assert_eq!(range.contains(&v("1.2")), Some(false));
        assert_eq!(range.contains(&v("1.2.1")), Some(true));
    }

    #[test]
    fn an_unparseable_bound_is_undecidable_not_a_guess() {
        let range = VersionRange {
            end_excluding: Some("not-a-version".into()),
            ..Default::default()
        };
        assert_eq!(
            range.contains(&v("1.0")),
            None,
            "an unparseable bound must not resolve to affected or safe"
        );
    }

    #[test]
    fn describes_ranges_readably() {
        let range = VersionRange {
            start_including: Some("1.2".into()),
            end_excluding: Some("1.4".into()),
            ..Default::default()
        };
        assert_eq!(range.describe(), ">= 1.2, < 1.4");
    }
}
