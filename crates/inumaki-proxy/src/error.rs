//! Fixed errors (M8 spec §7). Messages carry kinds and check ids only.

use axum::response::{IntoResponse, Response};
use http::StatusCode;

use crate::routes::Wire;

/// `ProxyError` of `GET /v1/proxy` (M6 §9.6 closed set).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// The provider could not be reached.
    UpstreamUnreachable,
    /// The provider rejected the credentials.
    UpstreamAuth,
    /// The provider rate-limited the request.
    UpstreamRateLimited,
    /// The provider answered 5xx.
    #[serde(rename = "upstream_5xx")]
    Upstream5xx,
    /// The privacy check refused the request.
    PrivacyBlock,
    /// A size or concurrency limit.
    ResourceLimit,
    /// A stream ended abnormally.
    StreamAborted,
    /// The request was malformed or unsupported.
    BadRequest,
    /// An internal failure.
    Internal,
}

/// Why the proxy answers itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fail {
    /// `uncertain` feeds the status counter and the `Refused` verdict only (review I6).
    PrivacyBlock {
        /// Entity kind labels, never values.
        kinds: Vec<String>,
        /// Check ids, never values.
        checks: Vec<String>,
        /// Whether the block was a verifier-uncertain one; never in the message.
        uncertain: bool,
    },
    /// The model's answer held a value inumaki protects (the tripwire in
    /// block mode, spec §6.4): the sanitized request was sent, the answer
    /// is withheld. Same status, type, and class as `PrivacyBlock`.
    AnswerWithheld {
        /// Entity kind labels, never values.
        kinds: Vec<String>,
        /// Check ids, never values.
        checks: Vec<String>,
    },
    /// Detection models are not loaded.
    ModelUnavailable,
    /// The vault cannot be used.
    VaultUnavailable,
    /// The request could not be read.
    BadRequest,
    /// Content the proxy does not send.
    UnsupportedContent,
    /// Request body over the size limit.
    TooLarge,
    /// The upstream's answer is over the size limit: the sanitized request
    /// was sent, the answer is not relayed (spec §7, amendment 2026-10-05).
    ResponseTooLarge,
    /// The answer scan could not get its memory budget in time. The request
    /// was already sent upstream: the message must not say "retry" blindly.
    AnswerUnchecked,
    /// Too many requests in flight.
    Busy,
    /// Endpoint not forwarded.
    NotServed,
    /// Connection to the provider failed.
    UpstreamUnreachable,
    /// The provider did not answer in time.
    UpstreamTimeout,
    /// Anything else.
    Internal,
}

impl Fail {
    /// HTTP status.
    pub fn status(&self) -> StatusCode {
        match self {
            Fail::PrivacyBlock { .. } | Fail::AnswerWithheld { .. } => {
                StatusCode::from_u16(451).expect("451 is valid")
            }
            Fail::ModelUnavailable
            | Fail::VaultUnavailable
            | Fail::Busy
            | Fail::AnswerUnchecked => StatusCode::SERVICE_UNAVAILABLE,
            Fail::BadRequest | Fail::UnsupportedContent => StatusCode::BAD_REQUEST,
            Fail::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Fail::NotServed => StatusCode::NOT_FOUND,
            Fail::UpstreamUnreachable | Fail::ResponseTooLarge => StatusCode::BAD_GATEWAY,
            Fail::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
            Fail::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The envelope's `type` (and `code` on the OpenAI wires).
    pub fn kind(&self) -> &'static str {
        match self {
            Fail::PrivacyBlock { .. } | Fail::AnswerWithheld { .. } => "privacy_block",
            Fail::ModelUnavailable => "model_unavailable",
            Fail::VaultUnavailable => "vault_unavailable",
            Fail::BadRequest => "bad_request",
            Fail::UnsupportedContent => "unsupported_content",
            Fail::TooLarge | Fail::ResponseTooLarge | Fail::Busy | Fail::AnswerUnchecked => {
                "resource_limit"
            }
            Fail::NotServed => "not_served",
            Fail::UpstreamUnreachable | Fail::UpstreamTimeout => "upstream_unreachable",
            Fail::Internal => "internal",
        }
    }

    /// The fixed message.
    pub fn message(&self) -> String {
        match self {
            Fail::PrivacyBlock { kinds, checks, .. } => format!(
                "blocked by inumaki (kinds: {}; checks: {}). Nothing was sent. Edit or rewind the message.",
                kinds.join(", "),
                checks.join(", ")
            ),
            Fail::AnswerWithheld { kinds, checks } => format!(
                "The request was sent sanitized; the model's answer contained a value inumaki protects and was withheld (kinds: {}; checks: {}).",
                kinds.join(", "),
                checks.join(", ")
            ),
            Fail::ModelUnavailable => {
                "inumaki's detection models are not available; nothing was sent".into()
            }
            Fail::VaultUnavailable => "inumaki's vault is not available; nothing was sent".into(),
            Fail::BadRequest => "inumaki could not read this request; nothing was sent".into(),
            Fail::UnsupportedContent => "inumaki does not send this content (images, documents, or a tool definition holding a known value); nothing was sent".into(),
            Fail::TooLarge => {
                "the request is larger than inumaki accepts; nothing was sent".into()
            }
            Fail::AnswerUnchecked => "The request was sent; the answer could not be checked in time and was withheld. Retrying will resend it.".into(),
            Fail::ResponseTooLarge => "the provider's answer is larger than inumaki relays; the request was sent, the answer was not passed on".into(),
            Fail::Busy => "inumaki is busy; retry".into(),
            Fail::NotServed => "inumaki does not forward this endpoint".into(),
            Fail::UpstreamUnreachable | Fail::UpstreamTimeout => {
                "the provider could not be reached".into()
            }
            Fail::Internal => "inumaki failed internally".into(),
        }
    }

    /// The status class, or `None` for outcomes that are not route errors.
    pub fn class(&self) -> Option<ErrorClass> {
        match self {
            Fail::PrivacyBlock { .. } | Fail::AnswerWithheld { .. } => {
                Some(ErrorClass::PrivacyBlock)
            }
            Fail::ModelUnavailable | Fail::VaultUnavailable | Fail::Internal => {
                Some(ErrorClass::Internal)
            }
            Fail::BadRequest | Fail::UnsupportedContent => Some(ErrorClass::BadRequest),
            Fail::TooLarge | Fail::ResponseTooLarge | Fail::Busy | Fail::AnswerUnchecked => {
                Some(ErrorClass::ResourceLimit)
            }
            Fail::UpstreamUnreachable | Fail::UpstreamTimeout => {
                Some(ErrorClass::UpstreamUnreachable)
            }
            Fail::NotServed => None,
        }
    }

    /// The envelope of `wire` (OpenAI's when `None`).
    pub fn response(&self, wire: Option<Wire>) -> Response {
        let body = match wire {
            Some(Wire::Messages) => serde_json::json!({
                "type": "error",
                "error": { "type": self.kind(), "message": self.message() }
            }),
            _ => serde_json::json!({
                "error": { "type": self.kind(), "code": self.kind(), "message": self.message(), "param": null }
            }),
        };
        (self.status(), axum::Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn envelopes_are_fixed_per_wire() {
        let f = Fail::PrivacyBlock {
            kinds: vec!["PERSON".into()],
            checks: vec!["Leak".into()],
            uncertain: true,
        };
        assert_eq!(f.status(), http::StatusCode::from_u16(451).unwrap());
        let r = f.response(Some(Wire::Messages));
        let b = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["type"], "error");
        assert_eq!(v["error"]["type"], "privacy_block");
        assert_eq!(
            v["error"]["message"],
            "blocked by inumaki (kinds: PERSON; checks: Leak). Nothing was sent. Edit or rewind the message."
        );
        let r = Fail::ModelUnavailable.response(Some(Wire::Chat));
        assert_eq!(r.status(), 503);
        let b = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["error"]["type"], "model_unavailable");
        assert_eq!(v["error"]["code"], "model_unavailable");
        assert!(v["error"]["param"].is_null());
        assert_eq!(Fail::ModelUnavailable.class(), Some(ErrorClass::Internal));
        assert_eq!(Fail::NotServed.class(), None);
    }
}
