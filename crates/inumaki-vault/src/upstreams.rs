//! Wrapped MCP servers per dataset (M4 spec §4.2). Non-secret env and
//! headers are stored inline as JSON; secret ones live in the secrets table
//! under the names in `env_secret` / `headers_secret`. `content_policy` is
//! the locally reviewed field contract (JSON text; the gateway parses it),
//! `schema_fingerprint` the upstream schema it was reviewed against.

use std::collections::BTreeMap;

use rusqlite::params;

use crate::error::VaultError;
use crate::vault::{Vault, is_constraint};

/// How an upstream is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamKind {
    /// A child process speaking MCP on stdio.
    Stdio,
    /// A Streamable HTTP server.
    Http,
    /// The built-in mail connector (plan 3).
    Mail,
}

impl UpstreamKind {
    /// The stored string.
    pub fn as_str(self) -> &'static str {
        match self {
            UpstreamKind::Stdio => "stdio",
            UpstreamKind::Http => "http",
            UpstreamKind::Mail => "mail",
        }
    }

    /// Parse the stored or API string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "stdio" => Some(UpstreamKind::Stdio),
            "http" => Some(UpstreamKind::Http),
            "mail" => Some(UpstreamKind::Mail),
            _ => None,
        }
    }
}

/// True for `[a-z0-9_-]{1,64}`.
pub fn valid_upstream_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// How to reach one upstream. `Debug` prints names and counts only.
#[derive(Clone, PartialEq, Eq)]
pub struct UpstreamSpec {
    /// Unique per dataset, `[a-z0-9_-]{1,64}`.
    pub name: String,
    /// Transport.
    pub kind: UpstreamKind,
    /// `stdio`: program.
    pub command: Option<String>,
    /// `stdio`: arguments.
    pub args: Vec<String>,
    /// `stdio`: working directory.
    pub cwd: Option<String>,
    /// `http`: base URL (`http://` or `https://`).
    pub url: Option<String>,
    /// `stdio`: non-secret environment.
    pub env: BTreeMap<String, String>,
    /// `http`: non-secret headers.
    pub headers: BTreeMap<String, String>,
    /// Secret name holding a JSON object of secret environment variables.
    pub env_secret: Option<String>,
    /// Secret name holding a JSON object of secret headers.
    pub headers_secret: Option<String>,
    /// The field contract, JSON text (`{}` = nothing reviewed).
    pub content_policy: String,
    /// Upstream schema fingerprint the contract was reviewed against.
    pub schema_fingerprint: Option<String>,
    /// Disabled upstreams are stored but not started.
    pub enabled: bool,
}

impl std::fmt::Debug for UpstreamSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamSpec")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("has_command", &self.command.is_some())
            .field("args", &self.args.len())
            .field("has_cwd", &self.cwd.is_some())
            .field("has_url", &self.url.is_some())
            .field("env", &self.env.len())
            .field("headers", &self.headers.len())
            .field("env_secret", &self.env_secret)
            .field("headers_secret", &self.headers_secret)
            .field("content_policy_len", &self.content_policy.len())
            .field("has_fingerprint", &self.schema_fingerprint.is_some())
            .field("enabled", &self.enabled)
            .finish()
    }
}

impl UpstreamSpec {
    fn blank(name: &str, kind: UpstreamKind) -> Self {
        UpstreamSpec {
            name: name.to_string(),
            kind,
            command: None,
            args: Vec::new(),
            cwd: None,
            url: None,
            env: BTreeMap::new(),
            headers: BTreeMap::new(),
            env_secret: None,
            headers_secret: None,
            content_policy: "{}".to_string(),
            schema_fingerprint: None,
            enabled: true,
        }
    }

    /// A child-process upstream.
    pub fn stdio(name: &str, command: &str) -> Self {
        let mut s = Self::blank(name, UpstreamKind::Stdio);
        s.command = Some(command.to_string());
        s
    }

    /// An HTTP upstream.
    pub fn http(name: &str, url: &str) -> Self {
        let mut s = Self::blank(name, UpstreamKind::Http);
        s.url = Some(url.to_string());
        s
    }

    /// The built-in mail upstream.
    pub fn mail(name: &str) -> Self {
        Self::blank(name, UpstreamKind::Mail)
    }

    fn validate(&self) -> Result<(), VaultError> {
        if !valid_upstream_name(&self.name) {
            return Err(VaultError::InvalidUpstreamName);
        }
        match self.kind {
            UpstreamKind::Stdio => {
                if self.command.as_deref().is_none_or(|c| c.trim().is_empty()) {
                    return Err(VaultError::InvalidUpstream("command"));
                }
            }
            UpstreamKind::Http => {
                let ok = self
                    .url
                    .as_deref()
                    .is_some_and(|u| u.starts_with("http://") || u.starts_with("https://"));
                if !ok {
                    return Err(VaultError::InvalidUpstream("url"));
                }
            }
            UpstreamKind::Mail => {}
        }
        for name in self.env_secret.iter().chain(self.headers_secret.iter()) {
            if !crate::secrets::valid_secret_name(name) {
                return Err(VaultError::InvalidSecretName);
            }
        }
        // The vault only checks that the policy is a JSON object; the
        // gateway validates the contract's contents.
        match serde_json::from_str::<serde_json::Value>(&self.content_policy) {
            Ok(serde_json::Value::Object(_)) => {}
            _ => return Err(VaultError::InvalidUpstream("content_policy")),
        }
        Ok(())
    }
}

/// A stored upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    /// Row id (creation order).
    pub id: i64,
    /// Owning dataset.
    pub dataset_id: String,
    /// The settings.
    pub spec: UpstreamSpec,
    /// Unix seconds.
    pub created_at: i64,
}

fn json_map(v: &BTreeMap<String, String>) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "{}".to_string())
}

fn parse_map(s: Option<String>) -> BTreeMap<String, String> {
    s.and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn parse_args(s: Option<String>) -> Vec<String> {
    s.and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

impl Vault {
    /// Add an upstream to a dataset.
    pub fn add_upstream(
        &self,
        dataset_id: &str,
        spec: &UpstreamSpec,
    ) -> Result<Upstream, VaultError> {
        spec.validate()?;
        let now = self.inner.now();
        let args = serde_json::to_string(&spec.args).unwrap_or_else(|_| "[]".into());
        let id = {
            let conn = self.inner.lock();
            let r = conn.execute(
                "INSERT INTO upstreams (dataset_id, name, kind, command, args, cwd, url, env, headers, env_secret, headers_secret, content_policy, schema_fingerprint, enabled, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    dataset_id, spec.name, spec.kind.as_str(), spec.command, args, spec.cwd, spec.url,
                    json_map(&spec.env), json_map(&spec.headers), spec.env_secret, spec.headers_secret,
                    spec.content_policy, spec.schema_fingerprint, i64::from(spec.enabled), now
                ],
            );
            match r {
                Ok(_) => conn.last_insert_rowid(),
                Err(e) if is_constraint(&e, "upstreams.dataset_id, upstreams.name") => {
                    return Err(VaultError::UpstreamExists(spec.name.clone()));
                }
                Err(rusqlite::Error::SqliteFailure(f, _))
                    if f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY =>
                {
                    return Err(VaultError::DatasetNotFound(dataset_id.to_string()));
                }
                Err(e) => return Err(e.into()),
            }
        };
        tracing::info!(dataset = %self.inner.opaque(dataset_id), upstream = %spec.name, kind = spec.kind.as_str(), "upstream added");
        Ok(Upstream {
            id,
            dataset_id: dataset_id.to_string(),
            spec: spec.clone(),
            created_at: now,
        })
    }

    /// Upstreams of a dataset in creation order. `DatasetNotFound` when the
    /// dataset does not exist.
    pub fn upstreams(&self, dataset_id: &str) -> Result<Vec<Upstream>, VaultError> {
        self.dataset_profile(dataset_id)?;
        let conn = self.inner.lock();
        let mut stmt = conn.prepare(
            "SELECT id, name, kind, command, args, cwd, url, env, headers, env_secret, headers_secret, content_policy, schema_fingerprint, enabled, created_at \
             FROM upstreams WHERE dataset_id = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![dataset_id], |r| {
            let kind: String = r.get(2)?;
            Ok(Upstream {
                id: r.get(0)?,
                dataset_id: dataset_id.to_string(),
                spec: UpstreamSpec {
                    name: r.get(1)?,
                    kind: UpstreamKind::parse(&kind).unwrap_or(UpstreamKind::Stdio),
                    command: r.get(3)?,
                    args: parse_args(r.get(4)?),
                    cwd: r.get(5)?,
                    url: r.get(6)?,
                    env: parse_map(r.get(7)?),
                    headers: parse_map(r.get(8)?),
                    env_secret: r.get(9)?,
                    headers_secret: r.get(10)?,
                    content_policy: r.get(11)?,
                    schema_fingerprint: r.get(12)?,
                    enabled: r.get::<_, i64>(13)? != 0,
                },
                created_at: r.get(14)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Remove an upstream by name.
    pub fn remove_upstream(&self, dataset_id: &str, name: &str) -> Result<(), VaultError> {
        let n = {
            let conn = self.inner.lock();
            conn.execute(
                "DELETE FROM upstreams WHERE dataset_id = ?1 AND name = ?2",
                params![dataset_id, name],
            )?
        };
        if n == 0 {
            return Err(VaultError::UpstreamNotFound(name.to_string()));
        }
        tracing::info!(dataset = %self.inner.opaque(dataset_id), upstream = %name, "upstream removed");
        Ok(())
    }

    /// Record (or clear) the schema fingerprint the contract was reviewed against.
    pub fn set_upstream_fingerprint(
        &self,
        dataset_id: &str,
        name: &str,
        fingerprint: Option<&str>,
    ) -> Result<(), VaultError> {
        let n = {
            let conn = self.inner.lock();
            conn.execute(
                "UPDATE upstreams SET schema_fingerprint = ?1 WHERE dataset_id = ?2 AND name = ?3",
                params![fingerprint, dataset_id, name],
            )?
        };
        if n == 0 {
            return Err(VaultError::UpstreamNotFound(name.to_string()));
        }
        Ok(())
    }
}
