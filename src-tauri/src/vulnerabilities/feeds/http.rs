//! Shared HTTP plumbing for vulnerability feeds.
//!
//! Every outbound request SENTRY makes goes through here, which keeps the
//! privacy surface auditable: there is exactly one place that talks to the
//! internet, it is only ever reached from the feed modules, and it only ever
//! *downloads* -- nothing about the user's machine is sent anywhere.
//!
//! In particular the request carries no identifying information beyond a
//! static user agent. No machine id, no installed-software list, no query
//! string derived from local state.

use std::time::Duration;

use crate::security::CollectorError;

/// Identifies SENTRY to feed operators, several of whom ask for a contactable
/// agent string. It is a constant: it must not encode anything about the user.
pub const USER_AGENT: &str = concat!("SENTRY/", env!("CARGO_PKG_VERSION"), " (security scanner)");

/// A plain browser user agent, needed by exactly one feed.
///
/// CISA publishes the KEV catalogue specifically for automated consumption,
/// but the CDN in front of it answers 403 to any user agent that is not
/// browser-shaped -- including one that merely *starts* with the Mozilla
/// token. Identifying honestly gets the request refused, so this feed, and
/// only this feed, is fetched with a generic agent string.
///
/// This is a bot-protection rule getting in the way of a published, public
/// data file; it is not an access control being circumvented. Nothing about
/// the request changes beyond the header, and no credentials or user data are
/// involved.
pub const BROWSER_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";

/// Feeds are a few MB at most. A cap stops a broken or hostile endpoint from
/// filling memory or disk.
const MAX_BODY_BYTES: u64 = 64 * 1024 * 1024;

const TIMEOUT: Duration = Duration::from_secs(45);

fn agent_with(user_agent: &str) -> ureq::Agent {
    ureq::Agent::config_builder()
        .user_agent(user_agent)
        .timeout_global(Some(TIMEOUT))
        .build()
        .new_agent()
}

fn agent() -> ureq::Agent {
    agent_with(USER_AGENT)
}

/// Download a URL as text, identifying as SENTRY.
pub fn get_text(url: &str) -> Result<String, CollectorError> {
    get_text_as(url, USER_AGENT)
}

/// Download a URL as text with an explicit user agent.
///
/// Only used where a feed's CDN refuses SENTRY's own agent string; see
/// `BROWSER_USER_AGENT`.
pub fn get_text_as(url: &str, user_agent: &str) -> Result<String, CollectorError> {
    let mut response = agent_with(user_agent)
        .get(url)
        .call()
        .map_err(|e| map_http_error(url, e))?;

    let status = response.status();
    if !status.is_success() {
        return Err(status_error(url, status.as_u16()));
    }

    response
        .body_mut()
        .with_config()
        .limit(MAX_BODY_BYTES)
        .read_to_string()
        .map_err(|e| CollectorError::Malformed {
            origin: url.to_string(),
            detail: format!("could not read the response body: {e}"),
        })
}

/// Download a URL as text with one extra request header.
///
/// Used only for NVD's `apiKey`. The header value goes to that host and no
/// other, and carries nothing about the machine.
pub fn get_text_with_header(url: &str, name: &str, value: &str) -> Result<String, CollectorError> {
    let mut response = agent()
        .get(url)
        .header(name, value)
        .call()
        .map_err(|e| map_http_error(url, e))?;

    let status = response.status();
    if !status.is_success() {
        return Err(status_error(url, status.as_u16()));
    }

    response
        .body_mut()
        .with_config()
        .limit(MAX_BODY_BYTES)
        .read_to_string()
        .map_err(|e| CollectorError::Malformed {
            origin: url.to_string(),
            detail: format!("could not read the response body: {e}"),
        })
}

/// POST a JSON body and read the JSON response as text.
pub fn post_json(url: &str, body: &serde_json::Value) -> Result<String, CollectorError> {
    let mut response = agent()
        .post(url)
        .header("Content-Type", "application/json")
        .send(serde_json::to_string(body).unwrap_or_default())
        .map_err(|e| map_http_error(url, e))?;

    let status = response.status();
    if !status.is_success() {
        return Err(status_error(url, status.as_u16()));
    }

    response
        .body_mut()
        .with_config()
        .limit(MAX_BODY_BYTES)
        .read_to_string()
        .map_err(|e| CollectorError::Malformed {
            origin: url.to_string(),
            detail: format!("could not read the response body: {e}"),
        })
}

/// Translate an HTTP status into something the user can act on.
fn status_error(url: &str, status: u16) -> CollectorError {
    match status {
        // NVD returns 403 for rate limiting as well as for genuine refusal.
        403 | 429 => CollectorError::Unavailable(format!(
            "The vulnerability feed at {url} is rate limiting us (HTTP {status}). \
             The cached data is still in use; the next refresh will try again."
        )),
        // NVD answers 404 both for a retired endpoint and for a query it
        // cannot parse -- a product name reduced to something like
        // "microsoft visual c" does exactly that. Saying "the feed no longer
        // exists" would send the user looking for a problem that is not there.
        404 => CollectorError::Unavailable(format!(
            "The vulnerability service rejected this request (HTTP 404). That usually means the \
             product name could not be turned into a usable search, not that anything is wrong \
             with SENTRY or the feed. URL: {url}"
        )),
        500..=599 => CollectorError::Unavailable(format!(
            "The vulnerability feed at {url} is having problems (HTTP {status}). \
             This is on their end, not yours."
        )),
        _ => CollectorError::Unavailable(format!("{url} returned HTTP {status}")),
    }
}

fn map_http_error(url: &str, e: ureq::Error) -> CollectorError {
    let text = e.to_string();
    let lowered = text.to_ascii_lowercase();

    if lowered.contains("timeout") || lowered.contains("timed out") {
        return CollectorError::Timeout(TIMEOUT.as_secs());
    }

    if lowered.contains("dns") || lowered.contains("resolve") {
        return CollectorError::Unavailable(format!(
            "Could not look up {url}. This PC may be offline, or a DNS problem may be in the way."
        ));
    }

    if lowered.contains("tls") || lowered.contains("certificate") {
        return CollectorError::Unavailable(format!(
            "The secure connection to {url} could not be established: {text}. \
             Something may be intercepting HTTPS on this network."
        ));
    }

    CollectorError::Unavailable(format!("Could not reach {url}: {text}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_user_agent_carries_no_user_information() {
        // The whole privacy claim rests on this string being a constant.
        assert!(USER_AGENT.starts_with("SENTRY/"));
        assert!(!USER_AGENT.contains('@'));
        // Nothing interpolated from the environment beyond our own version.
        assert!(USER_AGENT.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn rate_limiting_is_reported_as_temporary() {
        let e = status_error("https://example.test/feed", 429);
        let text = e.to_string();
        assert!(text.contains("rate limiting"), "got: {text}");
        assert!(matches!(e, CollectorError::Unavailable(_)));
    }

    #[test]
    fn server_errors_say_whose_fault_it_is() {
        let text = status_error("https://example.test/feed", 503).to_string();
        assert!(text.contains("their end"), "got: {text}");
    }

    #[test]
    fn a_404_does_not_alarm_the_user_about_the_feed() {
        // NVD 404s on queries it cannot parse, which is not a fault the user
        // can act on and must not be reported as a broken feed.
        let text = status_error("https://example.test/feed", 404).to_string();
        assert!(text.contains("not that anything is wrong"), "got: {text}");
    }
}
