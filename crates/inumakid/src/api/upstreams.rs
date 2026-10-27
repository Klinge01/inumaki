//! `GET/POST /v1/datasets/{id}/upstreams`, `DELETE …/upstreams/{name}`,
//! `POST …/upstreams/{name}/accept-schema` (M4 spec §8). Secret env and
//! headers go to the vault's secrets table; responses carry names only.
//! The content policy is validated by the gateway's contract parser
//! before anything is written.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use inumaki_gateway::contract::Contract;
use inumaki_vault::{DatasetKind, Upstream, UpstreamKind, UpstreamSpec};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{ApiError, blocking};
use crate::state::AppState;

/// Secret names for an upstream's env and headers.
pub fn secret_names(dataset: &str, upstream: &str) -> (String, String) {
    (
        format!("{dataset}/upstream/{upstream}/env"),
        format!("{dataset}/upstream/{upstream}/headers"),
    )
}

/// `POST` body. `Debug` prints names and counts.
#[derive(Deserialize)]
pub struct UpstreamCreateBody {
    /// `[a-z0-9_-]{1,64}`, unique per dataset.
    pub name: String,
    /// `stdio`, `http`, or `mail`.
    pub kind: String,
    /// `stdio`: program.
    pub command: Option<String>,
    /// `stdio`: arguments.
    #[serde(default)]
    pub args: Vec<String>,
    /// `stdio`: working directory.
    pub cwd: Option<String>,
    /// `http`: base URL.
    pub url: Option<String>,
    /// `stdio`: non-secret environment.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// `http`: non-secret headers.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// `stdio`: secret environment (stored in the vault).
    #[serde(default)]
    pub secret_env: BTreeMap<String, String>,
    /// `http`: secret headers (stored in the vault).
    #[serde(default)]
    pub secret_headers: BTreeMap<String, String>,
    /// The field contract (JSON object); `{}` when absent.
    pub content_policy: Option<Value>,
}

impl std::fmt::Debug for UpstreamCreateBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamCreateBody")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("has_command", &self.command.is_some())
            .field("args", &self.args.len())
            .field("has_url", &self.url.is_some())
            .field("env", &self.env.len())
            .field("headers", &self.headers.len())
            .field("secret_env", &self.secret_env.len())
            .field("secret_headers", &self.secret_headers.len())
            .field("has_policy", &self.content_policy.is_some())
            .finish()
    }
}

/// An upstream in responses. No secret values, only their names.
#[derive(Serialize)]
pub struct UpstreamBody {
    /// Name.
    pub name: String,
    /// Kind.
    pub kind: String,
    /// `stdio`: program.
    pub command: Option<String>,
    /// `stdio`: arguments.
    pub args: Vec<String>,
    /// `stdio`: working directory.
    pub cwd: Option<String>,
    /// `http`: base URL.
    pub url: Option<String>,
    /// Non-secret environment.
    pub env: BTreeMap<String, String>,
    /// Non-secret headers.
    pub headers: BTreeMap<String, String>,
    /// Secret name of the secret environment.
    pub env_secret: Option<String>,
    /// Secret name of the secret headers.
    pub headers_secret: Option<String>,
    /// The field contract.
    pub content_policy: Value,
    /// Reviewed schema fingerprint.
    pub schema_fingerprint: Option<String>,
    /// Enabled.
    pub enabled: bool,
    /// Unix seconds.
    pub created_at: i64,
}

impl std::fmt::Debug for UpstreamBody {
    /// Hides environment/header values, the raw URL, argument text, and
    /// secret names (review I6): a secret name embeds the dataset slug and
    /// the upstream name, and args/env/headers/url are operator-supplied
    /// data that must never reach a log through an accidental `Debug` print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamBody")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("has_command", &self.command.is_some())
            .field("args", &self.args.len())
            .field("has_cwd", &self.cwd.is_some())
            .field("has_url", &self.url.is_some())
            .field("env", &self.env.len())
            .field("headers", &self.headers.len())
            .field("has_env_secret", &self.env_secret.is_some())
            .field("has_headers_secret", &self.headers_secret.is_some())
            .field("content_policy_len", &self.content_policy.to_string().len())
            .field("has_fingerprint", &self.schema_fingerprint.is_some())
            .field("enabled", &self.enabled)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl From<Upstream> for UpstreamBody {
    fn from(u: Upstream) -> Self {
        UpstreamBody {
            name: u.spec.name,
            kind: u.spec.kind.as_str().to_string(),
            command: u.spec.command,
            args: u.spec.args,
            cwd: u.spec.cwd,
            url: u.spec.url,
            env: u.spec.env,
            headers: u.spec.headers,
            env_secret: u.spec.env_secret,
            headers_secret: u.spec.headers_secret,
            content_policy: serde_json::from_str(&u.spec.content_policy)
                .unwrap_or(Value::Object(Default::default())),
            schema_fingerprint: u.spec.schema_fingerprint,
            enabled: u.spec.enabled,
            created_at: u.created_at,
        }
    }
}

/// `POST …/accept-schema` body.
#[derive(Debug, Deserialize)]
pub struct AcceptSchemaBody {
    /// The fingerprint to record (`sha256:…`), or `null` to clear it.
    pub fingerprint: Option<String>,
}

/// `GET /v1/datasets/{id}/upstreams`.
pub async fn list(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Vec<UpstreamBody>>, ApiError> {
    let rows = blocking(move || Ok(state.vault.upstreams(&id)?)).await?;
    Ok(Json(rows.into_iter().map(UpstreamBody::from).collect()))
}

fn create_blocking(
    state: &AppState,
    id: &str,
    b: UpstreamCreateBody,
) -> Result<Upstream, ApiError> {
    let kind = UpstreamKind::parse(&b.kind)
        .ok_or_else(|| ApiError::bad_request("kind must be stdio, http, or mail"))?;
    let dataset = state.vault.dataset(id)?;
    if dataset.kind == DatasetKind::Chat {
        return Err(ApiError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "reserved",
            "the chat dataset cannot be used here",
        ));
    }
    if kind == UpstreamKind::Mail && dataset.kind != DatasetKind::Mailbox {
        return Err(ApiError::bad_request(
            "a mail upstream needs a dataset of kind mailbox",
        ));
    }
    let policy = b
        .content_policy
        .unwrap_or(Value::Object(Default::default()));
    let policy_text = serde_json::to_string(&policy)
        .map_err(|_| ApiError::internal("policy is not serializable"))?;
    // Validate the contract before writing anything (fixed codes: the
    // message names keys of the local policy, never upstream data).
    let contract =
        Contract::parse(&policy_text).map_err(|e| ApiError::bad_request(e.to_string()))?;
    // Review M3: refuse at add time, not only when the gateway later loads
    // the contract, an identifier kind the dataset's profile blocks or
    // removes (a typed field always tokenizes, overriding that action).
    let profile = state.engines.policy(&dataset.profile)?;
    contract
        .check_profile(&profile)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    let (env_name, headers_name) = secret_names(id, &b.name);
    let spec = UpstreamSpec {
        name: b.name.clone(),
        kind,
        command: b.command,
        args: b.args,
        cwd: b.cwd,
        url: b.url,
        env: b.env,
        headers: b.headers,
        env_secret: (!b.secret_env.is_empty()).then(|| env_name.clone()),
        headers_secret: (!b.secret_headers.is_empty()).then(|| headers_name.clone()),
        content_policy: policy_text,
        schema_fingerprint: None,
        enabled: true,
    };
    // Insert the upstream row before writing any secret (review I2): a
    // duplicate name fails here, before an existing upstream of the same
    // name (and so the same deterministic secret names) is ever touched.
    let upstream = state.vault.add_upstream(id, &spec)?;
    let mut written: Vec<String> = Vec::new();
    let write = (|| -> Result<(), ApiError> {
        if !b.secret_env.is_empty() {
            let json = serde_json::to_vec(&b.secret_env)
                .map_err(|_| ApiError::internal("secret env is not serializable"))?;
            state.vault.put_secret(&env_name, &json)?;
            written.push(env_name.clone());
        }
        if !b.secret_headers.is_empty() {
            let json = serde_json::to_vec(&b.secret_headers)
                .map_err(|_| ApiError::internal("secret headers are not serializable"))?;
            state.vault.put_secret(&headers_name, &json)?;
            written.push(headers_name.clone());
        }
        Ok(())
    })();
    match write {
        Ok(()) => Ok(upstream),
        Err(e) => {
            // Roll back every secret this call wrote (review M2) and the
            // upstream row itself, which would otherwise point at secret
            // names with no value.
            for name in &written {
                let _ = state.vault.delete_secret(name);
            }
            let _ = state.vault.remove_upstream(id, &b.name);
            Err(e)
        }
    }
}

/// `POST /v1/datasets/{id}/upstreams` → 201.
pub async fn create(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Result<Json<UpstreamCreateBody>, JsonRejection>,
) -> Result<(StatusCode, Json<UpstreamBody>), ApiError> {
    let Json(b) = body?;
    let s = Arc::clone(&state);
    let dataset = id.clone();
    let u = blocking(move || create_blocking(&s, &dataset, b)).await?;
    state.gateway_reload(&id).await;
    Ok((StatusCode::CREATED, Json(UpstreamBody::from(u))))
}

/// `DELETE /v1/datasets/{id}/upstreams/{name}` → 204; the upstream's secrets go with it.
pub async fn remove(
    State(state): State<Arc<AppState>>,
    Path((id, name)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let s = Arc::clone(&state);
    let (dataset, upstream) = (id.clone(), name.clone());
    blocking(move || {
        s.vault.remove_upstream(&dataset, &upstream)?;
        let (env_name, headers_name) = secret_names(&dataset, &upstream);
        s.vault.delete_secret(&env_name)?;
        s.vault.delete_secret(&headers_name)?;
        Ok(())
    })
    .await?;
    state.gateway_reload(&id).await;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/datasets/{id}/upstreams/{name}/accept-schema` → 204.
pub async fn accept_schema(
    State(state): State<Arc<AppState>>,
    Path((id, name)): Path<(String, String)>,
    body: Result<Json<AcceptSchemaBody>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let Json(b) = body?;
    if let Some(f) = &b.fingerprint {
        let valid = f.strip_prefix("sha256:").is_some_and(|hex| {
            hex.len() == 64 && hex.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
        });
        if !valid {
            return Err(ApiError::bad_request(
                "fingerprint must be sha256: followed by 64 lowercase hex digits",
            ));
        }
    }
    let s = Arc::clone(&state);
    let (dataset, upstream) = (id.clone(), name.clone());
    blocking(move || {
        Ok(s.vault
            .set_upstream_fingerprint(&dataset, &upstream, b.fingerprint.as_deref())?)
    })
    .await?;
    state.gateway_reload(&id).await;
    Ok(StatusCode::NO_CONTENT)
}
