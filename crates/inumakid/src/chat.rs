//! The model-API proxy inside the daemon (M8 spec §2, §4, §9): the
//! per-install client value, the reserved chat dataset, the chat journal
//! reveal, and the listener.

use std::net::SocketAddr;
use std::sync::Arc;

use inumaki_proxy::host::Scope;
use inumaki_proxy::{BinaryMode, ListenState, Proxy, ProxyConfig};
use inumaki_vault::{CHAT_DATASET, DatasetKind, DatasetSpec, RESERVED_PREFIX, VaultError};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

use crate::proxy_host::{DaemonHost, resolve_tokens};
use crate::state::AppState;

/// The vault secret that holds the per-install `X-Inumaki-Client` value
/// (M8 spec §2, decision 23).
pub const CLIENT_KEY_SECRET: &str = "inumaki-chat/proxy/client_key";

/// Why the chat setup failed. No payload: nothing here may carry a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChatError {
    /// The name is taken by something that is not the reserved dataset.
    #[error("conflict")]
    Conflict,
    /// The vault could not be read or written, or the stored value is not
    /// one this daemon wrote.
    #[error("vault")]
    Vault,
}

/// 32 random bytes as 64 lowercase hex digits.
fn random_value() -> Result<Zeroizing<String>, ChatError> {
    let mut b = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut b[..]).map_err(|_| ChatError::Vault)?;
    let mut s = Zeroizing::new(String::with_capacity(64));
    for x in b.iter() {
        use std::fmt::Write;
        let _ = write!(s, "{x:02x}");
    }
    Ok(s)
}

fn well_formed(v: &str) -> bool {
    v.len() == 64 && v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The per-install client value: read from the vault, or created (32 random
/// bytes as 64 lowercase hex digits) and stored on first use. A stored value
/// of any other shape is an error rather than something to overwrite.
pub fn client_value(state: &AppState) -> Result<Zeroizing<String>, ChatError> {
    match state.vault.get_secret(CLIENT_KEY_SECRET) {
        Ok(Some(bytes)) => {
            let s =
                Zeroizing::new(String::from_utf8(bytes.to_vec()).map_err(|_| ChatError::Vault)?);
            if well_formed(&s) {
                Ok(s)
            } else {
                Err(ChatError::Vault)
            }
        }
        Ok(None) => {
            let v = random_value()?;
            state
                .vault
                .put_secret(CLIENT_KEY_SECRET, v.as_bytes())
                .map_err(|_| ChatError::Vault)?;
            Ok(v)
        }
        Err(_) => Err(ChatError::Vault),
    }
}

/// Create the reserved chat dataset (kind `chat`, the proxy's profile) when
/// it is missing (M8 spec §9). `Err(Conflict)` when another dataset holds
/// the reserved prefix or the kind: the proxy then stays off.
pub fn ensure(state: &AppState) -> Result<(), ChatError> {
    let all = state.vault.dataset_heads().map_err(|_| ChatError::Vault)?;
    let reserved = |id: &str| id.starts_with(RESERVED_PREFIX);
    if all.iter().any(|d| {
        (reserved(&d.id) && d.kind != DatasetKind::Chat)
            || (d.kind == DatasetKind::Chat && d.id != CHAT_DATASET)
    }) {
        return Err(ChatError::Conflict);
    }
    if all.iter().any(|d| d.id == CHAT_DATASET) {
        return Ok(());
    }
    let mut spec = DatasetSpec::new(
        CHAT_DATASET,
        "Chat (model-API proxy)",
        &state.cfg.proxy.profile,
    );
    spec.kind = DatasetKind::Chat;
    match state.vault.create_dataset(&spec) {
        Ok(_) | Err(VaultError::DatasetExists(_)) => Ok(()),
        Err(_) => Err(ChatError::Vault),
    }
}

/// Reveal a chat journal payload locally (M8 spec §9): tokens of live user
/// datasets (not check datasets, not the chat dataset) are restored
/// through their namespaces; every other token-shaped string (a session
/// token, a removed marker, a forgotten or expired token, a check
/// dataset's token) stays as it is and is counted. One pass, so an
/// original that looks like a token is never substituted again. A vault
/// failure restores nothing and counts every token.
pub fn reveal(state: &AppState, payload: &str) -> (String, usize) {
    let r = &state.namespace_rehydrator;
    let tokens = r.tokens_in(payload);
    // Session tokens with other delimiters are unresolved too.
    let same = inumaki_core::rehydrate::Rehydrator::pattern(&state.cfg.session_tokens())
        == inumaki_core::rehydrate::Rehydrator::pattern(&state.cfg.vault_tokens());
    let session_only = if same {
        0
    } else {
        state.session_rehydrator.tokens_in(payload).len()
    };
    let resolved = match resolve_tokens(state, &tokens, &Scope::Datasets) {
        Ok(v) => v,
        Err(_) => return (payload.to_string(), tokens.len() + session_only),
    };
    let mut out = String::with_capacity(payload.len());
    let mut cursor = 0usize;
    let mut unresolved = session_only;
    for t in &tokens {
        // `tokens_in` yields leftmost, non-overlapping matches in order, so
        // the next occurrence after the cursor is this match.
        let Some(at) = payload[cursor..].find(t.as_str()).map(|i| cursor + i) else {
            continue;
        };
        out.push_str(&payload[cursor..at]);
        match resolved.iter().find(|(tok, _, _)| tok == t) {
            Some((_, _, original)) => out.push_str(original),
            None => {
                unresolved += 1;
                out.push_str(t);
            }
        }
        cursor = at + t.len();
    }
    out.push_str(&payload[cursor..]);
    (out, unresolved)
}

/// Build the proxy and bind its listener. Never fatal (spec decision 21):
/// a bind failure leaves `ListenState::BindFailed` ("not listening": bind
/// failed or serve ended; the daemon hands out no URL for it, and a harness
/// already pointed at the address reaches whatever holds it). The proxy is
/// built even when disabled, so `GET /v1/proxy` can say so. Returns `None` for the
/// proxy only when it cannot be built at all (a fixed warning is logged).
///
/// The listener is returned unserved: the caller wraps `proxy.router()` in
/// the shared guard and serves it with the other listeners.
pub async fn start(
    state: &Arc<AppState>,
    cfg: ProxyConfig,
    host: Arc<DaemonHost>,
) -> (Option<Proxy>, Option<SocketAddr>, Option<TcpListener>) {
    if cfg.enabled && cfg.binary == BinaryMode::Forward {
        tracing::warn!(
            "proxy: binary = \"forward\": images, documents, audio, and files are sent to the provider unchecked"
        );
    }
    // The proxy's `reqwest` client has no rustls provider of its own.
    inumaki_gateway::ensure_crypto_provider();
    let (value, usable) = {
        let s = Arc::clone(state);
        match tokio::task::spawn_blocking(move || client_value(&s)).await {
            Ok(Ok(v)) => (v, true),
            _ => {
                tracing::warn!("the proxy client value is unavailable; the proxy is off");
                // Never stored: it only lets the status endpoint answer.
                // Adapters must check the proxy `state` in `GET /v1/proxy`:
                // when it is `disabled`, this `client_header.value` is not
                // valid and must not be written into a harness.
                match random_value() {
                    Ok(v) => (v, false),
                    Err(_) => return (None, None, None),
                }
            }
        }
    };
    // Spec §9: the reserved dataset exists whenever the proxy runs; a
    // conflicting `inumaki-` dataset keeps the proxy off.
    let chat_ready = if cfg.enabled {
        let s = Arc::clone(state);
        match tokio::task::spawn_blocking(move || ensure(&s)).await {
            Ok(Ok(())) => true,
            Ok(Err(ChatError::Conflict)) => {
                tracing::warn!(
                    "a dataset id starts with the reserved prefix inumaki-; the proxy stays disabled"
                );
                false
            }
            _ => {
                tracing::warn!("the chat dataset could not be prepared; the proxy is off");
                false
            }
        }
    } else {
        false
    };
    let enabled = cfg.enabled && usable && chat_ready;
    let listen = cfg.listen;
    let proxy = match Proxy::new(cfg, host, value) {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!("the proxy could not be built; it is off");
            return (None, None, None);
        }
    };
    if !enabled {
        proxy.set_listen(ListenState::Disabled);
        return (Some(proxy), None, None);
    }
    let bound = match TcpListener::bind(listen).await {
        Ok(l) => l.local_addr().map(|a| (l, a)),
        Err(e) => Err(e),
    };
    match bound {
        Ok((l, addr)) => {
            proxy.set_listen(ListenState::Running(addr));
            tracing::info!(proxy = %addr, "proxy listening");
            (Some(proxy), Some(addr), Some(l))
        }
        Err(e) => {
            proxy.set_listen(ListenState::BindFailed);
            tracing::warn!(kind = ?e.kind(), "the proxy could not bind its address; it is off");
            (Some(proxy), None, None)
        }
    }
}
