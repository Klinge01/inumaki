//! Gateway endpoints (M4 spec §5.1, §8): bearer tokens, and
//! `/mcp/{dataset}` on the control socket (no token) and on the gateway's
//! TCP listener (bearer token checked on every request).

use std::sync::Arc;

use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use inumaki_vault::GatewayToken;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use zeroize::Zeroizing;

use super::{ApiError, blocking};
use crate::state::AppState;

/// `POST /v1/gateway/tokens` body.
#[derive(Debug, Deserialize)]
pub struct TokenCreateBody {
    /// Human label, 1 to 64 printable characters.
    pub label: String,
}

/// A token's metadata.
#[derive(Debug, Serialize)]
pub struct TokenBody {
    /// Id for `revoke`.
    pub id: i64,
    /// Label.
    pub label: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds of the last successful verification.
    pub last_used: Option<i64>,
}

impl From<GatewayToken> for TokenBody {
    fn from(t: GatewayToken) -> Self {
        TokenBody {
            id: t.id,
            label: t.label,
            created_at: t.created_at,
            last_used: t.last_used,
        }
    }
}

/// The creation response: metadata plus the token, shown once. `Debug` omits
/// the token; the token stays zeroized in memory until the moment it is
/// written into the response body (review M5).
pub struct TokenCreatedBody {
    /// Id for `revoke`.
    pub id: i64,
    /// Label.
    pub label: String,
    /// Unix seconds.
    pub created_at: i64,
    /// The bearer token.
    pub token: Zeroizing<String>,
}

impl std::fmt::Debug for TokenCreatedBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenCreatedBody")
            .field("id", &self.id)
            .field("label", &self.label)
            .finish()
    }
}

impl Serialize for TokenCreatedBody {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut s = serializer.serialize_struct("TokenCreatedBody", 4)?;
        s.serialize_field("id", &self.id)?;
        s.serialize_field("label", &self.label)?;
        s.serialize_field("created_at", &self.created_at)?;
        s.serialize_field("token", self.token.as_str())?;
        s.end()
    }
}

/// `GET /v1/gateway/tokens`.
pub async fn list_tokens(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<TokenBody>>, ApiError> {
    let rows = blocking(move || Ok(state.vault.gateway_tokens()?)).await?;
    Ok(Json(rows.into_iter().map(TokenBody::from).collect()))
}

/// `POST /v1/gateway/tokens` → 201 with the token.
pub async fn create_token(
    State(state): State<Arc<AppState>>,
    body: Result<Json<TokenCreateBody>, JsonRejection>,
) -> Result<(StatusCode, Json<TokenCreatedBody>), ApiError> {
    let Json(b) = body?;
    // M6 spec §8.4: `check:` labels belong to the end-to-end check, which
    // mints its tokens through the vault directly.
    if b.label.starts_with(crate::check::CHECK_TOKEN_PREFIX) {
        return Err(ApiError::bad_request(
            "token labels starting with check: are reserved",
        ));
    }
    let (info, token) = blocking(move || Ok(state.vault.create_gateway_token(&b.label)?)).await?;
    Ok((
        StatusCode::CREATED,
        Json(TokenCreatedBody {
            id: info.id,
            label: info.label,
            created_at: info.created_at,
            token,
        }),
    ))
}

/// `DELETE /v1/gateway/tokens/{id}` → 204.
pub async fn revoke_token(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    blocking(move || Ok(state.vault.revoke_gateway_token(id)?)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Serve one MCP request for `dataset` over the control socket (no
/// authentication: the socket's file mode is the authorization).
pub async fn mcp_socket(
    State(state): State<Arc<AppState>>,
    dataset: Result<Path<String>, PathRejection>,
    req: Request,
) -> Response {
    match dataset {
        Ok(Path(dataset)) => serve_mcp(&state, &dataset, req).await,
        Err(_) => no_gateway(),
    }
}

/// The bearer token of an `Authorization` header, if any.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// Serve one MCP request for `dataset` over TCP after checking the bearer
/// token against the vault (constant time, every request, so a revoked
/// token stops working at once, whatever rmcp session it opened). The
/// token is checked before the dataset is looked up, so an unauthenticated
/// caller cannot tell which datasets exist.
pub async fn mcp_tcp(
    State(state): State<Arc<AppState>>,
    dataset: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    req: Request,
) -> Response {
    let Some(token) = bearer(&headers).map(|t| Zeroizing::new(t.to_string())) else {
        return unauthorized("missing bearer token");
    };
    let s = Arc::clone(&state);
    match tokio::task::spawn_blocking(move || s.vault.verify_gateway_token(&token)).await {
        Ok(Ok(Some(_))) => match dataset {
            Ok(Path(dataset)) => serve_mcp(&state, &dataset, req).await,
            Err(_) => no_gateway(),
        },
        Ok(Ok(None)) => unauthorized("invalid bearer token"),
        Ok(Err(e)) => ApiError::from(e).into_response(),
        Err(_) => ApiError::internal("token check failed").into_response(),
    }
}

fn unauthorized(message: &'static str) -> Response {
    let mut resp = ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized", message).into_response();
    resp.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"inumaki\""),
    );
    resp
}

/// The fixed 404 for a dataset without a gateway; never names the dataset.
fn no_gateway() -> Response {
    ApiError::not_found("no gateway for this dataset").into_response()
}

async fn serve_mcp(state: &Arc<AppState>, dataset: &str, req: Request) -> Response {
    // The proxy's reserved chat dataset has no gateway (M8 spec §9).
    if dataset == inumaki_vault::CHAT_DATASET {
        return no_gateway();
    }
    let Some(gateway) = state.gateway.get() else {
        return ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "gateway_unavailable",
            "gateway not started",
        )
        .into_response();
    };
    let Some(service) = gateway.service(dataset).await else {
        return no_gateway();
    };
    service.handle(req).await.map(axum::body::Body::new)
}

/// The TCP router: `/mcp/{dataset}` with bearer auth, the documented JSON
/// error shape elsewhere, the same route-template access log as the
/// control API. `/v1/*` (including `/v1/inspect`) is never mounted here.
/// `bound` is the listener's actual bound address (its IP is the
/// "configured listen address" of M4 spec §16.8, its port the one every
/// `Host` header must carry or omit); the caller reads it right after
/// `TcpListener::bind`, before this router starts serving.
pub fn tcp_router(state: Arc<AppState>, bound: std::net::SocketAddr) -> Router {
    let routes = Router::new()
        .route("/mcp/{dataset}", axum::routing::any(mcp_tcp))
        .fallback(|| async { ApiError::not_found("no such route") })
        .layer(DefaultBodyLimit::max(super::BODY_LIMIT));
    crate::tcp_guard::layer(routes, state.cfg.gateway.allowed_origins.clone(), bound)
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            super::access_log,
        ))
        .with_state(state)
}
