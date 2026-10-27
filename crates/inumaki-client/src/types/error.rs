//! The error body of every endpoint (M6 spec §9.1; `inumakid/src/api/error.rs`).

use serde::{Deserialize, Serialize};

/// `{"error": {...}}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    /// The error.
    pub error: ErrorDetail,
}

/// One error. `message` is a fixed sentence but can name a dataset id or an
/// upstream name, so `Debug` omits it: the UI may show it, logs may not.
#[derive(Clone, Serialize, Deserialize)]
pub struct ErrorDetail {
    /// `error.type`: `bad_request`, `not_found`, `privacy_block`, …
    #[serde(rename = "type")]
    pub kind: String,
    /// Fixed message.
    pub message: String,
    /// Entity kind labels (`privacy_block`).
    pub kinds: Vec<String>,
    /// Check ids (`privacy_block`).
    pub checks: Vec<String>,
    /// `unresolved_token` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unknown_tokens: Option<u64>,
    /// `unresolved_token` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_markers: Option<u64>,
}

debug_fields!(ErrorDetail {
    kind,
    kinds,
    checks,
    unknown_tokens,
    removed_markers
});
