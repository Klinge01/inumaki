//! `POST /v1/sanitize`, `/v1/rehydrate`, `/v1/inspect`
//! (`inumakid/src/api/{sanitize,rehydrate,inspect}.rs`, `inumaki-core/src/redact.rs`).

use serde::{Deserialize, Serialize};

/// The fixed label of every inspection.
pub const DIAGNOSTIC_LABEL: &str = "local diagnostic output — not approved for transmission";

/// Outcome of an answered request (a block is `451`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Safe to send.
    Pass,
    /// Safe to send, flagged.
    PassUncertain,
    /// Must not be sent (inspection only; sanitize answers 451).
    Blocked,
}

/// What a user redaction does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RedactionAction {
    /// Replace with a token.
    Tokenize,
    /// Replace with the removed marker.
    Remove,
}

/// One user-marked span; offsets are bytes into the NFC-normalized input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Redaction {
    /// First byte.
    pub start: u64,
    /// One past the last byte.
    pub end: u64,
    /// Kind label.
    pub kind: String,
    /// Action.
    pub action: RedactionAction,
}

/// The redactions file. The input digest is not printed: it would confirm a guessed text.
#[derive(Clone, Serialize, Deserialize)]
pub struct RedactionFile {
    /// SHA-256 of the NFC input.
    pub input_sha256: String,
    /// Spans.
    pub spans: Vec<Redaction>,
}

debug_fields!(RedactionFile { spans });

/// `POST /v1/sanitize` body: exactly one of `dataset` and `session`.
#[derive(Clone, Serialize, Deserialize)]
pub struct SanitizeRequest {
    /// Dataset id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset: Option<String>,
    /// Session id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Text.
    pub text: String,
    /// User redactions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redactions: Option<RedactionFile>,
}

impl SanitizeRequest {
    /// Sanitize `text` in `dataset` with its profile.
    pub fn dataset(dataset: impl Into<String>, text: impl Into<String>) -> Self {
        SanitizeRequest {
            dataset: Some(dataset.into()),
            session: None,
            profile: None,
            text: text.into(),
            redactions: None,
        }
    }
}

impl std::fmt::Debug for SanitizeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SanitizeRequest")
            .field("has_dataset", &self.dataset.is_some())
            .field("has_session", &self.session.is_some())
            .field("profile", &self.profile)
            .field("text_len", &self.text.len())
            .field("redactions", &self.redactions)
            .finish()
    }
}

/// One reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reason {
    /// Kind label.
    pub kind: String,
    /// Check id.
    pub check: String,
}

/// `POST /v1/sanitize` answer.
#[derive(Clone, Serialize, Deserialize)]
pub struct SanitizeResponse {
    /// `pass` or `pass_uncertain`.
    pub outcome: Outcome,
    /// Sanitized text.
    pub text: String,
    /// Replacements.
    pub replacements: u64,
    /// Kind labels.
    pub kinds: Vec<String>,
    /// Reasons when uncertain.
    pub reasons: Vec<Reason>,
    /// From the cache.
    pub cached: bool,
    /// Wall time, milliseconds.
    pub latency_ms: f64,
}

debug_fields!(SanitizeResponse {
    outcome,
    replacements,
    kinds,
    reasons,
    cached,
    latency_ms
});

/// `POST /v1/rehydrate` body: exactly one of `dataset` and `session`.
#[derive(Clone, Serialize, Deserialize)]
pub struct RehydrateRequest {
    /// Dataset id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset: Option<String>,
    /// Session id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Text with tokens.
    pub text: String,
    /// Fail with `unresolved_token` instead of leaving placeholders.
    #[serde(default)]
    pub strict: bool,
}

impl RehydrateRequest {
    /// Permissive rehydration of `text` in `dataset`.
    pub fn dataset(dataset: impl Into<String>, text: impl Into<String>) -> Self {
        RehydrateRequest {
            dataset: Some(dataset.into()),
            session: None,
            text: text.into(),
            strict: false,
        }
    }
}

impl std::fmt::Debug for RehydrateRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RehydrateRequest")
            .field("has_dataset", &self.dataset.is_some())
            .field("has_session", &self.session.is_some())
            .field("text_len", &self.text.len())
            .field("strict", &self.strict)
            .finish()
    }
}

/// `POST /v1/rehydrate` answer.
#[derive(Clone, Serialize, Deserialize)]
pub struct RehydrateResponse {
    /// Rehydrated text.
    pub text: String,
    /// Tokens left as they were.
    pub unknown_tokens: u64,
    /// Removed markers left as they were.
    pub removed_markers: u64,
}

debug_fields!(RehydrateResponse {
    unknown_tokens,
    removed_markers
});

/// `POST /v1/inspect` body.
#[derive(Clone, Serialize, Deserialize)]
pub struct InspectRequest {
    /// Dataset id.
    pub dataset: String,
    /// Profile override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Text the user pasted or opened.
    pub text: String,
    /// Redactions to apply before verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redactions: Option<RedactionFile>,
    /// Include the candidate and the original excerpts.
    #[serde(default)]
    pub show_values: bool,
}

impl InspectRequest {
    /// Inspect `text` in `dataset`, without values.
    pub fn new(dataset: impl Into<String>, text: impl Into<String>) -> Self {
        InspectRequest {
            dataset: dataset.into(),
            profile: None,
            text: text.into(),
            redactions: None,
            show_values: false,
        }
    }
}

impl std::fmt::Debug for InspectRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InspectRequest")
            .field("profile", &self.profile)
            .field("text_len", &self.text.len())
            .field("redactions", &self.redactions)
            .field("show_values", &self.show_values)
            .finish_non_exhaustive()
    }
}

/// Action on an inspected span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpanAction {
    /// Tokenize.
    Tokenize,
    /// Remove.
    Remove,
    /// Preserve.
    Preserve,
    /// Escalate.
    Escalate,
    /// Block.
    Block,
}

/// One inspected span; `original` only with `show_values`.
#[derive(Clone, Serialize, Deserialize)]
pub struct InspectSpan {
    /// NFC byte offset.
    pub start: u64,
    /// One past the last byte.
    pub end: u64,
    /// Kind label.
    pub kind: String,
    /// Action.
    pub action: SpanAction,
    /// Detector name.
    pub source: String,
    /// The original excerpt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original: Option<String>,
}

debug_fields!(InspectSpan {
    start,
    end,
    kind,
    action,
    source
});

/// Expiry of the mappings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Expiry {
    /// Rotation period, days.
    pub rotation_days: u32,
    /// Grace period, days.
    pub grace_days: u32,
    /// Current epoch start.
    pub epoch_started_at: i64,
}

/// `POST /v1/inspect` answer.
#[derive(Clone, Serialize, Deserialize)]
pub struct InspectBody {
    /// Always [`DIAGNOSTIC_LABEL`].
    pub label: String,
    /// Outcome.
    pub outcome: Outcome,
    /// Profile that settled it.
    pub profile: String,
    /// Settled by the retry profile.
    pub retried: bool,
    /// Spans.
    pub spans: Vec<InspectSpan>,
    /// Document-level reasons.
    pub reasons: Vec<Reason>,
    /// Replacements.
    pub replacements: u64,
    /// Candidate text, only with `show_values`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<String>,
    /// Known limitations.
    pub limitations: Vec<String>,
    /// Expiry.
    pub expiry: Expiry,
}

debug_fields!(InspectBody {
    label,
    outcome,
    profile,
    retried,
    spans,
    reasons,
    replacements,
    limitations,
    expiry
});

/// `POST /v1/shutdown` answer (`json!`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownBody {
    /// `shutting_down`.
    pub status: String,
}
