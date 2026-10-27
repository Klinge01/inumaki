//! `GET/POST /v1/datasets/{id}/upstreams`, `DELETE …/{name}`,
//! `POST …/{name}/accept-schema` (`inumakid/src/api/upstreams.rs`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::status::UpstreamKind;
use crate::secret::SecretMap;

/// `POST` body. Only `kind` is printed.
#[derive(Clone, Serialize, Deserialize)]
pub struct UpstreamCreate {
    /// `[a-z0-9_-]{1,64}`.
    pub name: String,
    /// Kind.
    pub kind: UpstreamKind,
    /// `stdio`: program (absolute, spec §4.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// `stdio`: arguments.
    #[serde(default)]
    pub args: Vec<String>,
    /// `stdio`: working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// `http`: URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Non-secret environment.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Non-secret headers.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Secret environment (goes to the vault).
    #[serde(default)]
    pub secret_env: SecretMap,
    /// Secret headers (go to the vault).
    #[serde(default)]
    pub secret_headers: SecretMap,
    /// Field contract; `{}` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_policy: Option<Value>,
}

impl UpstreamCreate {
    /// A stdio upstream with no environment.
    pub fn stdio(name: impl Into<String>, command: impl Into<String>) -> Self {
        Self::empty(name.into(), UpstreamKind::Stdio, Some(command.into()), None)
    }

    /// An HTTP upstream with no headers.
    pub fn http(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self::empty(name.into(), UpstreamKind::Http, None, Some(url.into()))
    }

    fn empty(
        name: String,
        kind: UpstreamKind,
        command: Option<String>,
        url: Option<String>,
    ) -> Self {
        UpstreamCreate {
            name,
            kind,
            command,
            args: Vec::new(),
            cwd: None,
            url,
            env: BTreeMap::new(),
            headers: BTreeMap::new(),
            secret_env: SecretMap::new(),
            secret_headers: SecretMap::new(),
            content_policy: None,
        }
    }
}

debug_fields!(UpstreamCreate {
    kind,
    secret_env,
    secret_headers
});

/// `UpstreamBody`: secrets as their secret names only.
#[derive(Clone, Serialize, Deserialize)]
pub struct UpstreamBody {
    /// Name.
    pub name: String,
    /// Kind.
    pub kind: UpstreamKind,
    /// Program.
    pub command: Option<String>,
    /// Arguments.
    pub args: Vec<String>,
    /// Working directory.
    pub cwd: Option<String>,
    /// URL.
    pub url: Option<String>,
    /// Non-secret environment.
    pub env: BTreeMap<String, String>,
    /// Non-secret headers.
    pub headers: BTreeMap<String, String>,
    /// Secret name of the secret environment.
    pub env_secret: Option<String>,
    /// Secret name of the secret headers.
    pub headers_secret: Option<String>,
    /// Field contract.
    pub content_policy: Value,
    /// Reviewed schema fingerprint.
    pub schema_fingerprint: Option<String>,
    /// Enabled.
    pub enabled: bool,
    /// Unix seconds.
    pub created_at: i64,
}

debug_fields!(UpstreamBody {
    kind,
    schema_fingerprint,
    enabled,
    created_at
});

/// `POST …/accept-schema` body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptSchema {
    /// `sha256:<64 hex>`, or `null` to clear.
    pub fingerprint: Option<String>,
}
