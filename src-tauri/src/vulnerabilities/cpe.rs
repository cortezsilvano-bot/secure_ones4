//! CPE 2.3 names: parsing, and matching an installed program to one.
//!
//! A CPE looks like
//! `cpe:2.3:a:7-zip:7-zip:21.07:*:*:*:*:*:*:*`, with thirteen colon-separated
//! components. The two that matter for matching desktop software are the
//! vendor and the product; `*` means "any" and `-` means "not applicable".
//!
//! Matching a registry DisplayName such as "7-Zip 21.07 (x64)" to a CPE
//! product is inherently fuzzy, and this module is honest about that. It never
//! claims a match is certain on the strength of a name alone -- it returns a
//! `MatchQuality` that the finding layer turns into a confidence tier, so a
//! guess is presented to the user as a guess.

use serde::{Deserialize, Serialize};

/// The parts of a CPE 2.3 name SENTRY uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cpe {
    /// "a" application, "o" operating system, "h" hardware.
    pub part: String,
    pub vendor: String,
    pub product: String,
    pub version: String,
    /// The platform the product runs *inside*, when the advisory is scoped to
    /// one. `cpe:2.3:a:jenkins:git:...:jenkins:*:*` is the Jenkins Git plugin,
    /// not Git. Ignoring this field matches the wrong product entirely.
    pub target_sw: String,
    pub raw: String,
}

impl Cpe {
    /// Parse a formatted CPE 2.3 string.
    pub fn parse(raw: &str) -> Option<Cpe> {
        let raw = raw.trim();
        let rest = raw.strip_prefix("cpe:2.3:")?;

        // Components may contain escaped colons (`\:`), so a plain split is
        // wrong. Walk the string and honour the escape.
        let mut parts: Vec<String> = Vec::new();
        let mut current = String::new();
        let mut escaped = false;

        for c in rest.chars() {
            if escaped {
                current.push(c);
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == ':' {
                parts.push(std::mem::take(&mut current));
            } else {
                current.push(c);
            }
        }
        parts.push(current);

        // part, vendor, product, version are the first four.
        if parts.len() < 4 {
            return None;
        }

        // Component order is part, vendor, product, version, update, edition,
        // language, sw_edition, target_sw, target_hw, other.
        Some(Cpe {
            part: parts[0].clone(),
            vendor: parts[1].clone(),
            product: parts[2].clone(),
            version: parts[3].clone(),
            target_sw: parts.get(8).cloned().unwrap_or_else(|| "*".to_string()),
            raw: raw.to_string(),
        })
    }

    /// True when the version component is a wildcard, meaning the range is
    /// carried separately by the feed rather than pinned in the name.
    pub fn version_is_wildcard(&self) -> bool {
        self.version == "*" || self.version == "-" || self.version.is_empty()
    }

    /// The advisory applies only to the product running inside some other
    /// platform, e.g. a plugin.
    pub fn is_platform_scoped(&self) -> bool {
        !(self.target_sw == "*" || self.target_sw == "-" || self.target_sw.is_empty())
    }
}

/// How sure we are that an installed program is the product a CPE names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchQuality {
    /// Vendor and product both align.
    Strong,
    /// Product name aligns; the vendor could not be corroborated.
    Moderate,
    /// Only a loose name resemblance.
    Weak,
}

/// A program name reduced to comparable tokens.
///
/// Registry DisplayNames carry a lot that CPE products do not: versions,
/// architecture markers, edition words, the vendor repeated. Stripping those
/// is what makes "Mozilla Firefox 140.0 (x64 en-US)" comparable to `firefox`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedName {
    pub tokens: Vec<String>,
    pub joined: String,
}

/// Words that appear in program names but never identify a product.
///
/// Deliberately excludes "setup", "installer" and "update". Those look like
/// noise but are product-distinguishing in practice: "Visual Studio Installer"
/// is a separate program from "Visual Studio", with its own version scheme, and
/// discarding the word makes the two indistinguishable -- which reported a
/// current installer as vulnerable to a 2014 Visual Studio bug.
const NOISE: &[&str] = &[
    "x64",
    "x86",
    "win32",
    "win64",
    "32",
    "64",
    "bit",
    "32-bit",
    "64-bit",
    "edition",
    "version",
    "release",
    "build",
    "en",
    "us",
    "enus",
    "en-us",
    "english",
    "language",
    "pack",
    "the",
    "inc",
    "llc",
    "ltd",
    "corporation",
    "corp",
    "gmbh",
    "software",
    "technologies",
    "systems",
];

/// Reduce a program or product name to comparable tokens.
pub fn normalize(name: &str) -> NormalizedName {
    // Hyphens are joined rather than split on. In product names a hyphen
    // usually binds ("7-zip", "e-sword"), and splitting there strands the "7"
    // as a bare number, which the version filter below then discards -- leaving
    // "7-Zip" indistinguishable from any program called "Zip". Underscores are
    // the real word separator in CPE products ("adobe_acrobat_reader").
    let lowered = name.to_ascii_lowercase().replace('-', "");

    let tokens: Vec<String> = lowered
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        // Drop anything that is purely a number: those are versions and years.
        .filter(|t| !t.chars().all(|c| c.is_ascii_digit()))
        .filter(|t| !NOISE.contains(t))
        .map(str::to_string)
        .collect();

    let joined = tokens.join("");
    NormalizedName { tokens, joined }
}

/// Reduce a program name to a search keyword for NVD's full-text CVE search.
///
/// Deliberately *not* `normalize`. That function strips hyphens so that
/// "7-Zip" and "7-zip" compare equal, which is right for matching a CPE but
/// wrong for searching: NVD's keyword index is textual, and querying "7zip"
/// returns a different and far worse set of CVEs than "7-zip" does -- mostly
/// unrelated Linux packages rather than the product itself.
///
/// So hyphens are preserved here, versions and architecture noise are dropped,
/// and the result is capped at three words so the query stays broad enough to
/// return anything at all.
pub fn search_keyword(name: &str) -> Option<String> {
    let lowered = name.to_ascii_lowercase();

    let tokens: Vec<String> = lowered
        // Keep hyphens and dots inside tokens; split on everything else.
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '.'))
        .map(|t| t.trim_matches(|c| c == '.' || c == '-'))
        .filter(|t| !t.is_empty())
        // A token with no letters is a version or a year, never a product name.
        .filter(|t| t.chars().any(|c| c.is_ascii_alphabetic()))
        .filter(|t| !NOISE.contains(t))
        .map(str::to_string)
        .collect();

    if tokens.is_empty() {
        return None;
    }

    let keyword = tokens.into_iter().take(3).collect::<Vec<_>>().join(" ");
    (keyword.len() >= 3).then_some(keyword)
}

/// Compare an installed program's name and publisher to a CPE.
///
/// Returns `None` when there is no plausible relationship at all.
pub fn match_quality(
    installed_name: &str,
    publisher: Option<&str>,
    cpe: &Cpe,
) -> Option<MatchQuality> {
    // Only application CPEs are relevant to an installed-software inventory.
    if cpe.part != "a" {
        return None;
    }

    let installed = normalize(installed_name);
    let product = normalize(&cpe.product);

    if installed.tokens.is_empty() || product.tokens.is_empty() {
        return None;
    }

    // The product's tokens must all appear in the installed name. This is the
    // asymmetry that matters: "7-Zip 21.07" contains "7zip", but a CPE for
    // "zip" should not claim every program with "zip" in its name.
    let product_matches = product.tokens.iter().all(|t| installed.tokens.contains(t))
        || installed.joined.contains(&product.joined) && product.joined.len() >= 4;

    if !product_matches {
        return None;
    }

    let vendor = normalize(&cpe.vendor);
    let publisher_tokens = publisher.map(normalize);

    // An advisory scoped to a host platform describes that platform's plugin,
    // not the standalone program. Unless the platform is named in the
    // installed program itself, this is a different product.
    if cpe.is_platform_scoped() {
        let target = normalize(&cpe.target_sw);
        let platform_present = target.tokens.iter().any(|t| {
            installed.tokens.contains(t)
                || publisher_tokens
                    .as_ref()
                    .is_some_and(|p| p.tokens.contains(t))
        });
        if !platform_present {
            return None;
        }
    }

    // Vendor corroboration: the CPE vendor appears in the publisher string, or
    // in the program name itself ("Mozilla Firefox" vs vendor "mozilla").
    let vendor_corroborated = !vendor.tokens.is_empty()
        && (publisher_tokens
            .as_ref()
            .is_some_and(|p| vendor.tokens.iter().any(|t| p.tokens.contains(t)))
            || vendor.tokens.iter().any(|t| installed.tokens.contains(t)));

    // Words in the installed name that belong to neither the product nor the
    // vendor. "Visual Studio Code" against the CPE product "visual_studio"
    // leaves "code" over -- and that leftover word is the whole difference
    // between two unrelated products from the same vendor. Their version
    // schemes are not even comparable (VS numbers are years, VS Code is
    // semver), so a numeric comparison across them is meaningless.
    let distinguishing_extra = installed
        .tokens
        .iter()
        .any(|t| !product.tokens.contains(t) && !vendor.tokens.contains(t));

    Some(if distinguishing_extra {
        MatchQuality::Weak
    } else if vendor_corroborated {
        MatchQuality::Strong
    } else {
        MatchQuality::Moderate
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpe(s: &str) -> Cpe {
        Cpe::parse(s).unwrap_or_else(|| panic!("failed to parse {s}"))
    }

    #[test]
    fn parses_a_standard_cpe() {
        let c = cpe("cpe:2.3:a:7-zip:7-zip:21.07:*:*:*:*:*:*:*");
        assert_eq!(c.part, "a");
        assert_eq!(c.vendor, "7-zip");
        assert_eq!(c.product, "7-zip");
        assert_eq!(c.version, "21.07");
        assert!(!c.version_is_wildcard());
    }

    #[test]
    fn recognises_a_wildcard_version() {
        let c = cpe("cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*");
        assert!(c.version_is_wildcard());
    }

    #[test]
    fn handles_escaped_colons_in_components() {
        // Escaped colons appear in real CPE names and a naive split mangles them.
        let c = cpe(r"cpe:2.3:a:vendor:some\:product:1.0:*:*:*:*:*:*:*");
        assert_eq!(c.product, "some:product");
        assert_eq!(c.version, "1.0");
    }

    #[test]
    fn rejects_non_cpe_strings() {
        assert!(Cpe::parse("").is_none());
        assert!(Cpe::parse("7-zip 21.07").is_none());
        assert!(Cpe::parse("cpe:2.2:a:vendor:product").is_none());
        assert!(
            Cpe::parse("cpe:2.3:a:vendor").is_none(),
            "too few components"
        );
    }

    #[test]
    fn normalize_strips_versions_and_architecture() {
        let n = normalize("Mozilla Firefox 140.0 (x64 en-US)");
        assert_eq!(n.tokens, vec!["mozilla", "firefox"]);
    }

    #[test]
    fn normalize_splits_cpe_style_underscores() {
        assert_eq!(
            normalize("adobe_acrobat_reader").tokens,
            vec!["adobe", "acrobat", "reader"]
        );
    }

    #[test]
    fn normalize_keeps_alphanumeric_identity_tokens() {
        // "7-Zip" must survive as the single token "7zip". Reducing it to
        // "zip" would make every CPE for 7-Zip match any program with "Zip"
        // in its name.
        let n = normalize("7-Zip 21.07 (x64)");
        assert_eq!(n.tokens, vec!["7zip"]);
        assert!(
            !n.tokens.contains(&"21".to_string()),
            "version must be dropped"
        );
    }

    #[test]
    fn search_keyword_preserves_hyphens() {
        // The regression this guards: NVD's text search returns 43 CVEs for
        // "7-zip" and 9 mostly-unrelated ones for "7zip".
        assert_eq!(
            search_keyword("7-Zip 21.07 (x64)").as_deref(),
            Some("7-zip")
        );
    }

    #[test]
    fn search_keyword_strips_versions_and_noise() {
        assert_eq!(
            search_keyword("Mozilla Firefox 140.0 (x64 en-US)").as_deref(),
            Some("mozilla firefox")
        );
        assert_eq!(
            search_keyword("Adobe Photoshop 2026").as_deref(),
            Some("adobe photoshop")
        );
    }

    #[test]
    fn search_keyword_caps_at_three_words() {
        let k = search_keyword("Microsoft Visual Studio Community Preview Channel").unwrap();
        assert_eq!(k.split(' ').count(), 3);
    }

    #[test]
    fn search_keyword_rejects_nameless_entries() {
        assert_eq!(search_keyword(""), None);
        assert_eq!(search_keyword("2026 x64"), None);
    }

    #[test]
    fn an_installer_is_not_the_product_it_installs() {
        // "Visual Studio Installer" must not normalise to "Visual Studio".
        assert_ne!(
            normalize("Microsoft Visual Studio Installer").tokens,
            normalize("Microsoft Visual Studio").tokens
        );

        let vs = cpe("cpe:2.3:a:microsoft:visual_studio:*:*:*:*:*:*:*:*");
        assert_eq!(
            match_quality("Microsoft Visual Studio Installer", Some("Microsoft"), &vs),
            Some(MatchQuality::Weak),
            "a separate program in the same family is at best a weak match"
        );
    }

    #[test]
    fn a_platform_scoped_cpe_is_rejected_for_the_standalone_program() {
        let plugin = cpe("cpe:2.3:a:jenkins:git:*:*:*:*:*:jenkins:*:*");
        assert!(plugin.is_platform_scoped());
        assert_eq!(
            match_quality("Git", Some("The Git Development Community"), &plugin),
            None
        );
        assert!(match_quality("Jenkins Git plugin", Some("Jenkins"), &plugin).is_some());
    }

    #[test]
    fn an_unscoped_cpe_is_not_platform_scoped() {
        assert!(!cpe("cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*").is_platform_scoped());
        assert!(!cpe("cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:-:*:*").is_platform_scoped());
    }

    #[test]
    fn a_hyphenated_product_does_not_collapse_into_its_suffix() {
        // The regression this guards: "7-zip" and "zip" must not normalise
        // to the same thing.
        assert_ne!(normalize("7-Zip").tokens, normalize("Zip").tokens);
    }

    #[test]
    fn a_vendor_confirmed_product_matches_strongly() {
        let q = match_quality(
            "Mozilla Firefox 140.0 (x64 en-US)",
            Some("Mozilla"),
            &cpe("cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*"),
        );
        assert_eq!(q, Some(MatchQuality::Strong));
    }

    #[test]
    fn vendor_in_the_name_alone_still_corroborates() {
        let q = match_quality(
            "Mozilla Firefox",
            None,
            &cpe("cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*"),
        );
        assert_eq!(q, Some(MatchQuality::Strong));
    }

    #[test]
    fn an_unconfirmed_vendor_is_only_moderate() {
        let q = match_quality(
            "Firefox",
            Some("Some Reseller"),
            &cpe("cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*"),
        );
        assert_eq!(q, Some(MatchQuality::Moderate));
    }

    #[test]
    fn unrelated_software_does_not_match() {
        assert_eq!(
            match_quality(
                "Epson Event Manager",
                Some("Seiko Epson"),
                &cpe("cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*"),
            ),
            None
        );
    }

    #[test]
    fn a_short_generic_product_does_not_swallow_everything() {
        // A CPE product of "zip" must not claim "WinZip", "7-Zip" and
        // "Zip Utility" indiscriminately via substring matching.
        let generic = cpe("cpe:2.3:a:someone:zip:*:*:*:*:*:*:*:*");
        assert_eq!(
            match_quality("Adobe Photoshop 2026", Some("Adobe"), &generic),
            None
        );
    }

    #[test]
    fn operating_system_and_hardware_cpes_are_ignored() {
        assert_eq!(
            match_quality(
                "Windows",
                None,
                &cpe("cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*"),
            ),
            None,
            "an OS CPE must not match an entry in the application inventory"
        );
    }

    #[test]
    fn an_empty_name_matches_nothing() {
        assert_eq!(
            match_quality("", None, &cpe("cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*")),
            None
        );
    }
}
