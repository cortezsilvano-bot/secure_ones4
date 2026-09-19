//! The honesty primitive.
//!
//! A security tool that renders an unknown value as "Safe" is worse than one
//! that renders nothing at all: it converts a gap in coverage into a false
//! assurance. `Known<T>` makes that mistake unrepresentable. A collector that
//! could not determine something has no way to express "fine" -- it can only
//! return one of the explicit not-determined states, and every one of them
//! carries a reason the UI is obliged to show.

use serde::{Deserialize, Serialize};

/// A fact the backend either established, or explicitly did not.
///
/// Serialises to a discriminated union the TypeScript side can exhaustively
/// match on: `{ state: "known", data: T }`, `{ state: "permission_required",
/// data: "..." }`, and so on.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", content = "data", rename_all = "snake_case")]
pub enum Known<T> {
    /// Established from real evidence.
    Known(T),
    /// No scan has run yet for this fact.
    NotScanned,
    /// The API exists but refused us; the string says what would grant access.
    PermissionRequired(String),
    /// This machine cannot answer the question (wrong OS, feature absent).
    Unsupported(String),
    /// The source should have worked and did not; the string is the failure.
    Unavailable(String),
}

impl<T> Known<T> {
    pub fn is_known(&self) -> bool {
        matches!(self, Known::Known(_))
    }

    pub fn value(&self) -> Option<&T> {
        match self {
            Known::Known(v) => Some(v),
            _ => None,
        }
    }

    /// Map the carried value, preserving any not-determined state verbatim.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Known<U> {
        match self {
            Known::Known(v) => Known::Known(f(v)),
            Known::NotScanned => Known::NotScanned,
            Known::PermissionRequired(s) => Known::PermissionRequired(s),
            Known::Unsupported(s) => Known::Unsupported(s),
            Known::Unavailable(s) => Known::Unavailable(s),
        }
    }
}

impl<T> From<Result<T, CollectorError>> for Known<T> {
    fn from(r: Result<T, CollectorError>) -> Self {
        match r {
            Ok(v) => Known::Known(v),
            Err(e) => e.into_known(),
        }
    }
}

/// Why a collector could not produce a fact.
///
/// Deliberately not a catch-all string: each variant maps to a distinct state
/// the user sees, and the mapping lives in one place (`into_known`).
#[derive(Debug, thiserror::Error)]
pub enum CollectorError {
    #[error("permission required: {0}")]
    PermissionDenied(String),

    #[error("not supported on this system: {0}")]
    Unsupported(String),

    #[error("data source unavailable: {0}")]
    Unavailable(String),

    #[error("timed out after {0}s")]
    Timeout(u64),

    #[error("cancelled")]
    Cancelled,

    #[error("malformed response from {origin}: {detail}")]
    Malformed { origin: String, detail: String },
}

impl CollectorError {
    /// The single authoritative translation from failure to displayed state.
    pub fn into_known<T>(self) -> Known<T> {
        match self {
            CollectorError::PermissionDenied(s) => Known::PermissionRequired(s),
            CollectorError::Unsupported(s) => Known::Unsupported(s),
            other => Known::Unavailable(other.to_string()),
        }
    }
}
