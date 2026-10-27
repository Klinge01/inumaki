//! `GET/POST/DELETE /v1/datasets/{id}/mailbox` and `POST …/mailbox/check`
//! (M4 spec §8; the contract is M6 spec §9.4). The password goes to the
//! secrets table and is never answered; the mail upstream is installed with
//! the shipped contract; any sending configuration is refused with a fixed
//! message; every 400 is one of §9.4's fixed messages; check answers
//! counts, booleans, and classes.

use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use inumaki_mail::{CONTRACT_JSON, MailError, Preset, UPSTREAM_NAME, check_mailbox};
use inumaki_vault::{
    DatasetKind, Mailbox, MailboxSpec, UpstreamKind, UpstreamSpec, is_loopback_host,
    mail_password_secret,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use super::{ApiError, blocking};
use crate::glue::mailbox_account;
use crate::state::AppState;

/// The fixed refusal for any sending configuration.
pub const SENDING_REFUSED: &str = "mail sending is not supported; mailboxes are draft-only";

/// The fixed message for an unknown key or a malformed field (the vault's
/// `InvalidMailbox` maps here too: its field name is not part of the
/// contract).
pub const INVALID_FIELD: &str = "unknown or invalid mailbox field";

const BAD_PRESET: &str = "preset must be gmail, outlook, or generic";
const GENERIC_NEEDS_HOST: &str = "imap_host and imap_port are required for the generic preset";
const TLS_REQUIRED: &str = "imap_tls must be true for a non-loopback host";
const BAD_PASSWORD: &str = "password must be 1 to 512 printable characters";
const NOT_MAILBOX: &str = "dataset kind must be mailbox";
const NOT_CONFIGURED: &str = "mailbox not configured";

/// `POST` body. `Debug` prints the preset, port, and TLS, and lengths.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxCreateBody {
    /// `gmail`, `outlook`, or `generic`.
    pub preset: String,
    /// IMAP host (required for `generic`).
    pub imap_host: Option<String>,
    /// IMAP port (required for `generic`).
    pub imap_port: Option<u16>,
    /// Implicit TLS (default `true`; `false` only for loopback hosts).
    pub imap_tls: Option<bool>,
    /// Login name.
    pub username: String,
    /// App password (stored as a secret, never answered).
    pub password: String,
    /// Drafts folder; omit to discover it.
    pub drafts_folder: Option<String>,
    /// `From` of drafts when the login name is not an address.
    pub from_address: Option<String>,
}

impl std::fmt::Debug for MailboxCreateBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailboxCreateBody")
            .field("preset", &self.preset)
            .field("has_imap_host", &self.imap_host.is_some())
            .field("imap_port", &self.imap_port)
            .field("imap_tls", &self.imap_tls)
            .field("username_len", &self.username.len())
            .field("has_drafts_folder", &self.drafts_folder.is_some())
            .field("has_from_address", &self.from_address.is_some())
            .finish()
    }
}

/// A mailbox in responses (local socket only): no password, ever. Field
/// order and nullability are the M6 contract (`inumaki_client::MailboxBody`).
/// No `Debug`: it carries the user name.
#[derive(Serialize)]
pub struct MailboxBody {
    /// Preset.
    pub preset: String,
    /// IMAP host.
    pub imap_host: String,
    /// IMAP port.
    pub imap_port: u16,
    /// Implicit TLS.
    pub imap_tls: bool,
    /// Login name.
    pub username: String,
    /// Configured drafts folder, or `null` for discovery.
    pub drafts_folder: Option<String>,
    /// Configured From address, or `null`.
    pub from_address: Option<String>,
    /// Secrets-table name of the password.
    pub password_secret: String,
    /// Unix seconds of the configuration.
    pub created_at: i64,
    /// Mail handles held for the dataset.
    pub handles: u64,
}

/// `POST …/mailbox/check` answer (M6 `MailboxCheck`).
#[derive(Debug, Serialize)]
pub struct CheckBody {
    /// Folders the account can list.
    pub folders: u64,
    /// A drafts folder exists or can be created.
    pub drafts_folder_resolved: bool,
    /// None exists yet; `Drafts` is created on the first draft.
    pub drafts_folder_will_be_created: bool,
    /// The drafts folder was configured by name.
    pub drafts_folder_configured: bool,
}

fn body_of(m: Mailbox, handles: u64) -> MailboxBody {
    MailboxBody {
        preset: m.spec.preset,
        imap_host: m.spec.imap_host,
        imap_port: m.spec.imap_port,
        imap_tls: m.spec.imap_tls,
        username: m.spec.username,
        drafts_folder: m.spec.drafts_folder,
        from_address: m.spec.from_address,
        password_secret: m.spec.password_secret,
        created_at: m.created_at,
        handles,
    }
}

/// Any `smtp*`, `send_mode`, `send`, or `mail_send` key.
fn refuse_sending(v: &Value) -> Result<(), ApiError> {
    if let Some(o) = v.as_object() {
        if o.keys().any(|k| {
            k.starts_with("smtp") || matches!(k.as_str(), "send_mode" | "send" | "mail_send")
        }) {
            return Err(ApiError::bad_request(SENDING_REFUSED));
        }
    }
    Ok(())
}

/// A value the vault stores in a header-like field: 1 to 320 bytes, no
/// control characters (the vault's own rule, checked here first so every
/// refusal is the fixed contract message).
fn header_safe(s: &str) -> bool {
    !s.is_empty() && s.len() <= 320 && !s.chars().any(char::is_control)
}

fn valid_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
}

/// The spec to store, or the fixed 400 for the first problem found.
fn validated(id: &str, b: MailboxCreateBody) -> Result<(MailboxSpec, Zeroizing<String>), ApiError> {
    let password = Zeroizing::new(b.password);
    let preset = Preset::parse(&b.preset).ok_or_else(|| ApiError::bad_request(BAD_PRESET))?;
    let (host, port) = match (preset.imap_defaults(), b.imap_host, b.imap_port) {
        (_, Some(h), Some(p)) => (h, p),
        (Some((h, p)), host, port) => (host.unwrap_or_else(|| h.to_string()), port.unwrap_or(p)),
        (None, _, _) => return Err(ApiError::bad_request(GENERIC_NEEDS_HOST)),
    };
    if !valid_host(&host) || port == 0 {
        return Err(ApiError::bad_request(INVALID_FIELD));
    }
    let tls = b.imap_tls.unwrap_or(true);
    if !tls && !is_loopback_host(&host) {
        return Err(ApiError::bad_request(TLS_REQUIRED));
    }
    let n = password.chars().count();
    if n == 0 || n > 512 || password.chars().any(char::is_control) {
        return Err(ApiError::bad_request(BAD_PASSWORD));
    }
    let fields_ok = header_safe(&b.username)
        && b.drafts_folder.as_deref().is_none_or(header_safe)
        && b.from_address
            .as_deref()
            .is_none_or(|a| header_safe(a) && a.contains('@'));
    if !fields_ok {
        return Err(ApiError::bad_request(INVALID_FIELD));
    }
    Ok((
        MailboxSpec {
            preset: preset.as_str().to_string(),
            imap_host: host,
            imap_port: port,
            imap_tls: tls,
            username: b.username,
            password_secret: mail_password_secret(id),
            drafts_folder: b.drafts_folder,
            from_address: b.from_address,
        },
        password,
    ))
}

/// The dataset, which must be a mailbox dataset (404 / 400).
fn mailbox_dataset(state: &AppState, id: &str) -> Result<(), ApiError> {
    if state.vault.dataset(id)?.kind != DatasetKind::Mailbox {
        return Err(ApiError::bad_request(NOT_MAILBOX));
    }
    Ok(())
}

/// `GET /v1/datasets/{id}/mailbox`.
pub async fn get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<MailboxBody>, ApiError> {
    let body = blocking(move || {
        state.vault.dataset(&id)?;
        let m = state
            .vault
            .mailbox(&id)?
            .ok_or_else(|| ApiError::not_found(NOT_CONFIGURED))?;
        let handles = state.vault.mail_handle_count(&id)?;
        Ok(body_of(m, handles))
    })
    .await?;
    Ok(Json(body))
}

/// Store the row, then the password; install the mail upstream.
fn create_blocking(
    state: &AppState,
    id: &str,
    b: MailboxCreateBody,
) -> Result<MailboxBody, ApiError> {
    mailbox_dataset(state, id)?;
    let (spec, password) = validated(id, b)?;
    let upstreams = state.vault.upstreams(id)?;
    // The built-in's name is fixed; another kind of upstream holding it
    // would make the mailbox unreachable. Refused before anything is written.
    if upstreams
        .iter()
        .any(|u| u.spec.name == UPSTREAM_NAME && u.spec.kind != UpstreamKind::Mail)
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "conflict",
            "an upstream named mail already exists",
        ));
    }
    let previous = state.vault.mailbox(id)?;
    // The row first (`set_mailbox` validates every field before writing),
    // so a rejected body never overwrites the password of a working mailbox.
    let m = state.vault.set_mailbox(id, &spec)?;
    if let Err(e) = state
        .vault
        .put_secret(&spec.password_secret, password.as_bytes())
    {
        // Put the previous configuration back (its handles are gone either
        // way), or remove the new row: never a row with someone else's password.
        let restored = match &previous {
            Some(p) => state.vault.set_mailbox(id, &p.spec).map(|_| ()),
            None => state.vault.remove_mailbox(id).map(|_| ()),
        };
        if let Err(r) = restored {
            tracing::warn!(dataset = %state.vault.opaque_id(id), error = %r, "could not restore the previous mailbox after a failed password write");
        }
        return Err(e.into());
    }
    // Exactly one mail upstream, named `mail`, with the shipped contract
    // (re-installed when the contract changed, so its fingerprint is bound
    // anew on first use).
    let mut current = false;
    for u in upstreams
        .into_iter()
        .filter(|u| u.spec.kind == UpstreamKind::Mail)
    {
        if u.spec.name == UPSTREAM_NAME && u.spec.content_policy == CONTRACT_JSON && !current {
            current = true;
        } else {
            state.vault.remove_upstream(id, &u.spec.name)?;
        }
    }
    if !current {
        let mut up = UpstreamSpec::mail(UPSTREAM_NAME);
        up.content_policy = CONTRACT_JSON.to_string();
        state.vault.add_upstream(id, &up)?;
    }
    Ok(body_of(m, 0))
}

/// `POST /v1/datasets/{id}/mailbox` → 201 (also replaces an existing mailbox).
pub async fn create(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<(StatusCode, Json<MailboxBody>), ApiError> {
    let Json(v) = body?;
    refuse_sending(&v)?;
    let b: MailboxCreateBody =
        serde_json::from_value(v).map_err(|_| ApiError::bad_request(INVALID_FIELD))?;
    let (s, dataset) = (Arc::clone(&state), id.clone());
    let out = blocking(move || create_blocking(&s, &dataset, b)).await?;
    // Restarts the dataset's upstreams: the connector picks up the new
    // account and handle scope.
    state.gateway_reload(&id).await;
    Ok((StatusCode::CREATED, Json(out)))
}

/// `DELETE /v1/datasets/{id}/mailbox` → 204; the password secret, the
/// handles, and the mail upstream go with it.
pub async fn remove(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let (s, dataset) = (Arc::clone(&state), id.clone());
    blocking(move || {
        s.vault.dataset(&dataset)?;
        let m = s
            .vault
            .mailbox(&dataset)?
            .ok_or_else(|| ApiError::not_found(NOT_CONFIGURED))?;
        // The secret first: if anything below fails, a retry still finds
        // the row and finishes the job; the password never outlives it.
        s.vault.delete_secret(&m.spec.password_secret)?;
        for u in s
            .vault
            .upstreams(&dataset)?
            .into_iter()
            .filter(|u| u.spec.kind == UpstreamKind::Mail)
        {
            s.vault.remove_upstream(&dataset, &u.spec.name)?;
        }
        s.vault.remove_mailbox(&dataset)?;
        Ok(())
    })
    .await?;
    state.gateway_reload(&id).await;
    Ok(StatusCode::NO_CONTENT)
}

/// The check endpoint's status for a connector failure (M6 §9.4).
fn check_error(e: MailError, preset: Preset) -> ApiError {
    match e {
        MailError::AuthFailed => ApiError::new(
            StatusCode::UNAUTHORIZED,
            "mail_auth_failed",
            preset.auth_hint(),
        ),
        MailError::Unreachable(_) | MailError::Timeout => {
            ApiError::new(StatusCode::BAD_GATEWAY, "mail_unreachable", e.hint())
        }
        MailError::Tls(_) => ApiError::new(StatusCode::BAD_GATEWAY, "mail_tls_failed", e.hint()),
        MailError::Protocol(_) => ApiError::new(StatusCode::BAD_GATEWAY, "mail_protocol", e.hint()),
        MailError::Credentials("no_mailbox") => ApiError::not_found(NOT_CONFIGURED),
        other => ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            other.class(),
            other.hint(),
        ),
    }
}

/// `POST /v1/datasets/{id}/mailbox/check`: connect, count folders, resolve
/// the drafts folder, log out.
pub async fn check(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<CheckBody>, ApiError> {
    let (s, dataset) = (Arc::clone(&state), id.clone());
    let account = blocking(move || {
        s.vault.dataset(&dataset)?;
        // Credential failures carry preset-independent hints.
        mailbox_account(&s.vault, &dataset).map_err(|e| check_error(e, Preset::Generic))
    })
    .await?;
    let configured = account.drafts_folder.is_some();
    let preset = account.preset;
    let timeout = state.cfg.mail_config().command_timeout;
    let report = check_mailbox(&account, timeout).await;
    drop(account);
    let report = report.map_err(|e| {
        tracing::info!(dataset = %state.vault.opaque_id(&id), class = e.class(), "mailbox check failed");
        check_error(e, preset)
    })?;
    tracing::info!(dataset = %state.vault.opaque_id(&id), folders = report.folders, drafts_resolved = report.drafts_folder_resolved, "mailbox check");
    Ok(Json(CheckBody {
        folders: report.folders as u64,
        drafts_folder_resolved: report.drafts_folder_resolved,
        drafts_folder_will_be_created: report.drafts_folder_will_be_created,
        drafts_folder_configured: configured,
    }))
}
