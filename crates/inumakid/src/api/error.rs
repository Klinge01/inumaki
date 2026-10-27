//! The one error body shape (spec §10.3): `message` never carries request text.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use inumaki_core::span::EntityKind;
use inumaki_core::verify::Reason;
use inumaki_vault::VaultError;
use serde_json::json;

use crate::engines::EngineError;

/// An API error. `kinds` and `checks` are filled for `privacy_block`.
#[derive(Debug, Clone)]
pub struct ApiError {
    /// HTTP status.
    pub status: StatusCode,
    /// `error.type`.
    pub kind: &'static str,
    /// `error.message`: ids, paths, names, never text.
    pub message: String,
    /// Entity kind labels.
    pub kinds: Vec<String>,
    /// Check ids.
    pub checks: Vec<String>,
    /// `(unknown_tokens, removed_markers)` for `unresolved_token`.
    pub unresolved: Option<(usize, usize)>,
}

impl ApiError {
    /// Build.
    pub fn new(status: StatusCode, kind: &'static str, message: impl Into<String>) -> Self {
        ApiError {
            status,
            kind,
            message: message.into(),
            kinds: Vec::new(),
            checks: Vec::new(),
            unresolved: None,
        }
    }

    /// 400.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    /// 404.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    /// 404 for a session that does not exist or has expired.
    pub fn context_unavailable() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "context_unavailable",
            "the session context is missing or expired; nothing was restored",
        )
    }

    /// 500 with a fixed message (details go to the log, never to the client).
    pub fn internal(message: &'static str) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", message)
    }

    /// 451 from the engine's block reasons.
    pub fn privacy_block(kinds: &[EntityKind], reasons: &[Reason]) -> Self {
        let mut checks: Vec<String> = Vec::new();
        for r in reasons {
            let c = format!("{:?}", r.check);
            if !checks.contains(&c) {
                checks.push(c);
            }
        }
        ApiError {
            status: StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
            kind: "privacy_block",
            message: "the sanitized text did not pass verification; nothing was sent".into(),
            kinds: kinds.iter().map(|k| k.label().to_string()).collect(),
            checks,
            unresolved: None,
        }
    }

    /// 422 for strict restoration that found unresolved placeholders.
    pub fn unresolved(unknown: usize, removed: usize) -> Self {
        ApiError {
            unresolved: Some((unknown, removed)),
            ..Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "unresolved_token",
                "placeholders could not be resolved; nothing was restored",
            )
        }
    }

    /// The JSON body.
    pub fn body(&self) -> serde_json::Value {
        let mut b = json!({ "error": { "type": self.kind, "message": self.message, "kinds": self.kinds, "checks": self.checks } });
        if let Some((u, r)) = self.unresolved {
            b["error"]["unknown_tokens"] = json!(u);
            b["error"]["removed_markers"] = json!(r);
        }
        b
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body())).into_response()
    }
}

impl From<VaultError> for ApiError {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::DatasetNotFound(_) | VaultError::Closed => Self::not_found(e.to_string()),
            VaultError::DatasetExists(_) => {
                Self::new(StatusCode::CONFLICT, "conflict", e.to_string())
            }
            VaultError::InvalidDatasetId | VaultError::OutOfRange(_) => {
                Self::bad_request(e.to_string())
            }
            VaultError::TokenSpaceExhausted(_) => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "token_space_exhausted",
                e.to_string(),
            ),
            VaultError::UpstreamExists(_) => {
                Self::new(StatusCode::CONFLICT, "conflict", e.to_string())
            }
            VaultError::UpstreamNotFound(_) | VaultError::GatewayTokenNotFound(_) => {
                Self::not_found(e.to_string())
            }
            VaultError::InvalidSecretName
            | VaultError::InvalidLabel
            | VaultError::InvalidUpstreamName
            | VaultError::InvalidUpstream(_) => Self::bad_request(e.to_string()),
            // Fixed messages: a failed journal row is never shown, not even
            // its row number (M4 spec §16.3, fail closed).
            VaultError::JournalRecord(_) => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "journal_record",
                "a journal entry failed validation; nothing is shown",
            ),
            // Mailboxes (M6 §9.4): the field name is not part of the contract.
            VaultError::InvalidMailbox(_) => Self::bad_request(super::mailbox::INVALID_FIELD),
            VaultError::MailboxNotFound => Self::not_found(e.to_string()),
            VaultError::EntityNotFound => {
                Self::not_found("no entity with that token or value in this dataset")
            }
            // Only forget truncates on demand: the rows are already deleted
            // and evicted when this is returned; only the WAL purge is late.
            VaultError::CheckpointBusy => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "vault_busy",
                "the change was saved, but the vault write-ahead log stayed busy and was not truncated; the pre-delete pages stay in vault.sqlite-wal until the next TRUNCATE checkpoint (at the latest when the daemon stops)",
            ),
            other => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "vault_error",
                other.to_string(),
            ),
        }
    }
}

impl From<inumaki_core::token::StoreError> for ApiError {
    fn from(e: inumaki_core::token::StoreError) -> Self {
        use inumaki_core::token::StoreError;
        match e {
            StoreError::Closed => Self::not_found("the dataset or its epoch is gone"),
            StoreError::Unavailable => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "vault_unavailable",
                "the token vault could not complete the request; nothing was sent",
            ),
            StoreError::Exhausted(_) => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "token_space_exhausted",
                e.to_string(),
            ),
            StoreError::UnknownParent => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "surface token parent unknown",
            ),
        }
    }
}

impl From<EngineError> for ApiError {
    fn from(e: EngineError) -> Self {
        match e {
            EngineError::Unavailable { .. } => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "model_unavailable",
                e.to_string(),
            ),
            EngineError::Config(c) => Self::bad_request(c.to_string()),
        }
    }
}

impl From<crate::service::ServiceError> for ApiError {
    fn from(e: crate::service::ServiceError) -> Self {
        use crate::service::ServiceError as S;
        match e {
            S::Vault(v) => Self::from(v),
            S::Store(s) => Self::from(s),
            S::Engine(g) => Self::from(g),
            S::Unresolved { unknown, removed } => Self::unresolved(unknown, removed),
            S::Redaction(r) => Self::bad_request(r.to_string()),
            S::Unsupported(c) => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "unsupported_content",
                format!("unsupported: {c}"),
            ),
        }
    }
}

impl From<JsonRejection> for ApiError {
    /// 413 for the body limit; otherwise a fixed 400 message. serde's own
    /// message quotes the offending value (`invalid type: string "..."`),
    /// so it never reaches the client (review C1, spec §10.3).
    fn from(r: JsonRejection) -> Self {
        if r.status() == StatusCode::PAYLOAD_TOO_LARGE {
            Self::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                format!("request body exceeds {} bytes", super::BODY_LIMIT),
            )
        } else {
            Self::bad_request(
                "request body is not valid JSON for this endpoint (see the API reference)",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use inumaki_core::verify::CheckId;

    #[test]
    fn body_shape_and_no_text() {
        let e = ApiError::privacy_block(
            &[EntityKind::Iban, EntityKind::Person],
            &[
                Reason {
                    kind: EntityKind::Iban,
                    check: CheckId::Leak,
                },
                Reason {
                    kind: EntityKind::Person,
                    check: CheckId::Leak,
                },
                Reason {
                    kind: EntityKind::Person,
                    check: CheckId::Ner,
                },
            ],
        );
        assert_eq!(e.status, StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
        let b = e.body();
        assert_eq!(b["error"]["type"], "privacy_block");
        assert_eq!(b["error"]["kinds"], serde_json::json!(["IBAN", "PERSON"]));
        assert_eq!(b["error"]["checks"], serde_json::json!(["Leak", "Ner"]));
        assert!(b["error"]["message"].is_string());
        let b = ApiError::from(VaultError::DatasetNotFound("mail".into())).body();
        assert_eq!(b["error"]["type"], "not_found");
        assert_eq!(b["error"]["kinds"], serde_json::json!([]));
        assert_eq!(
            ApiError::from(VaultError::DatasetExists("mail".into())).status,
            StatusCode::CONFLICT
        );
        assert_eq!(
            ApiError::from(VaultError::TokenSpaceExhausted("PERSON".into())).kind,
            "token_space_exhausted"
        );
        assert_eq!(ApiError::from(VaultError::Decrypt).kind, "vault_error");
        let e = ApiError::from(EngineError::Unavailable {
            profile: "support-email".into(),
            reason: "run `inumaki models pull gliner-x-small`".into(),
        });
        assert_eq!(e.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(e.message.contains("inumaki models pull"));
        assert_eq!(
            ApiError::from(inumaki_core::token::StoreError::Unavailable).kind,
            "vault_unavailable"
        );
        assert_eq!(
            ApiError::from(inumaki_core::token::StoreError::Closed).status,
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn unresolved_carries_counts() {
        let e = ApiError::unresolved(2, 1);
        assert_eq!(e.status, StatusCode::UNPROCESSABLE_ENTITY);
        let b = e.body();
        assert_eq!(b["error"]["type"], "unresolved_token");
        assert_eq!(b["error"]["unknown_tokens"], 2);
        assert_eq!(b["error"]["removed_markers"], 1);
        assert_eq!(
            ApiError::from(crate::service::ServiceError::Unresolved {
                unknown: 2,
                removed: 1
            })
            .status,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
}
