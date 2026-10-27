//! `GET/POST /v1/gateway/tokens`, `DELETE …/{id}` (`inumakid/src/api/gateway.rs`).

use serde::{Deserialize, Serialize};

use crate::secret::Secret;

/// `POST` body.
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenCreate {
    /// 1 to 64 printable characters; the app uses `app:<harness-id>`.
    pub label: String,
}

debug_fields!(TokenCreate {});

/// A token's metadata.
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenBody {
    /// Id for revoke.
    pub id: i64,
    /// Label.
    pub label: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Last successful verification.
    pub last_used: Option<i64>,
}

debug_fields!(TokenBody {
    id,
    created_at,
    last_used
});

/// The creation answer: the token is shown once.
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenCreated {
    /// Id.
    pub id: i64,
    /// Label.
    pub label: String,
    /// Unix seconds.
    pub created_at: i64,
    /// The bearer token.
    pub token: Secret,
}

debug_fields!(TokenCreated { id, created_at });
