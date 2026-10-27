//! Connect, Revert, Reconnect (spec §4.2, §4.5, §4.6) under the token and
//! backup rules of plan M6-2 Task 5 (review C1, C2):
//!
//! 1. Each harness has one gateway token, label `app:<harness>`. Connect
//!    mints it before writing, and only when a gateway entry carries it.
//! 2. A `CannotEditSafely` refusal keeps the token: it is inside the snippet
//!    the user adds by hand, and Revert revokes it later. Every other
//!    failure revokes the new token at once.
//! 3. Revert revokes every `app:<harness>` token, then restores the
//!    adapter's active backup (the app's or `inumaki connect`'s; a backup id
//!    `state.json` still holds without one is stale and cleared). Without a
//!    backup it still revokes and clears the harness's state. A client
//!    header the revert could not remove is an error (`client_header_left`).
//!    With the service not running (offline Revert spec D1, D5, D6) it
//!    writes a label-only pending-revocation record first, which the service
//!    applies before it serves; the summary says `revocation_pending`, and
//!    a header left then is `client_header_left_pending`. Every mint first
//!    settles such a record of its harness.
//!
//! Every operation on one harness holds `Ctx::harness_lock`, so concurrent
//! commands cannot revoke each other's token or chain backups.
//! 4. Reconnect previews the new request first, so every refusal happens
//!    before anything is written; only then does it revert the earlier
//!    backup and apply anew. The new backup holds the user's original values
//!    again, so Revert always returns the pre-inumaki configuration.
//! 5. An apply failure after that revert leaves the harness disconnected:
//!    on its original entries, or half-written when the adapter wrote some
//!    files before a later write failed (it then keeps an active backup of
//!    those). Both tokens are revoked (a file that holds the new one must not
//!    route with it), the harness is recorded in `reconnect_failed` (tray
//!    red until a Connect or Revert succeeds), and the error kind is
//!    `reconnect_failed_disconnected`.
//!
//! Tokens never reach a log, an error kind, `Debug`, or `state.json`; the
//! only copies leave through the `cannot_edit_safely` snippet and the
//! "Other client" card, both shown to the local user on their own action.

use std::collections::BTreeSet;
use std::sync::Arc;

use inumaki_client::{ClientError, DatasetKind, HarnessId, revocations};
use serde::Serialize;
use zeroize::Zeroizing;

use super::naming::mail_entry_name;
use super::ops::{
    ConnectRequest, FileChange, GatewayEntry, HarnessOps, Login, OpError, ProxyUrls, Reason,
    RevertSummary, Scope,
};
use super::{harness_key, hook_command, route_name, server_key, system_view};
use crate::ctx::Ctx;
use crate::error::CmdError;

/// Shown after Connect, Revert, and Reconnect (spec §4.2).
pub const NEXT_SESSION: &str = "Takes effect in the harness's next session.";

/// The other-client token's label.
pub const OTHER_LABEL: &str = "app:other";

/// Answer of Connect and Reconnect.
#[derive(Debug, Serialize)]
pub struct ConnectOutcome {
    /// Fixed note.
    pub note: &'static str,
    /// Fixed warning: the chat route was not written because the proxy was
    /// not running when the harness was applied. Never carries a port, PID
    /// or process name.
    pub warning: Option<&'static str>,
    /// Fixed warnings from the adapter about the harness's own settings
    /// (`codex_approval_never`) or what the apply installs
    /// (`hook_blocks_when_stopped`): closed codes with their fixed
    /// sentences, never a value or path from the harness's files.
    pub harness_warnings: Vec<Reason>,
}

/// `app:<harness>`.
pub fn token_label(h: HarnessId) -> String {
    format!("app:{}", harness_key(h))
}

fn ops(ctx: &Ctx, h: HarnessId) -> Result<Arc<dyn HarnessOps>, CmdError> {
    ctx.harnesses
        .iter()
        .find(|o| o.id() == h)
        .cloned()
        .ok_or_else(|| CmdError::new("harness_not_found"))
}

fn gateway_url(listen: &str, dataset: &str) -> String {
    format!("http://{listen}/mcp/{dataset}")
}

/// The request for `h` with `token`: its protected servers under their own
/// names (entries already pointing at the gateway, and the servers
/// `state.json` records as protected), every mailbox as `inumaki-mail…`, the
/// mirror, the proxy and its client header, the hook.
pub async fn build_request(
    ctx: &Ctx,
    h: &dyn HarnessOps,
    token: Zeroizing<String>,
) -> Result<ConnectRequest, CmdError> {
    Ok(build(ctx, h, token, Omit::default()).await?.0)
}

/// The user's chat choice for `h` (`None`: none made, or a Revert cleared it).
pub fn chat_choice(ctx: &Ctx, h: HarnessId) -> Option<bool> {
    ctx.state().prefs.chat_opt_in.get(harness_key(h)).copied()
}

/// Whether `h`'s chat route is wanted (M6 D6, generalized in M9 Task 6):
/// the user's choice when there is one; else whether the active backup
/// holds the route (the last Connect wrote it), which keeps a route written
/// before the choice existed. Read from the backup, not from the status, so
/// a proxy that is down does not turn it off. No backup (not connected) is
/// `false`.
fn chat_wanted(ctx: &Ctx, h: &dyn HarnessOps) -> bool {
    chat_choice(ctx, h.id()).unwrap_or_else(|| h.chat_route_in_backup())
}

/// [`chat_wanted`] of `h` for the prefs answer and the setter.
pub async fn chat_effective(ctx: &Ctx, h: HarnessId) -> bool {
    if let Some(on) = chat_choice(ctx, h) {
        return on;
    }
    let Ok(o) = ops(ctx, h) else {
        return false;
    };
    blocking(&o, |o| Ok(o.chat_route_in_backup()))
        .await
        .unwrap_or(false)
}

/// The pre-M9 migration of the chat choice (see `Prefs::chat_migration_pending`).
/// The app before M9 routed the chat of Codex, Hermes Agent, and OpenClaw
/// with an API-key login on every Connect. Deriving their choice from the
/// backup alone would lose that route when the last apply before the
/// upgrade ran with the proxy down (its backup holds no chat record), so
/// each such harness that is connected (`state.json` holds its backup)
/// gets the explicit choice "on". Claude Code's choice was migrated on
/// load. An existing choice is never overwritten.
///
/// The login kind comes from detection. `all_detected`: every harness was
/// just detected, so one without an installation is not installed and the
/// flag is cleared; otherwise the flag stays while a connected harness is
/// not detected yet. A state that cannot be saved keeps the flag.
pub fn migrate_pre_m9_chat(ctx: &Ctx, all_detected: bool) {
    if !ctx.state().prefs.chat_migration_pending {
        return;
    }
    let st = ctx.state();
    let mut routed = Vec::new();
    let mut unknown = false;
    for o in &ctx.harnesses {
        let key = harness_key(o.id());
        if st.backups.get(key).is_none_or(|b| b.is_empty()) {
            continue;
        }
        match o.install() {
            Some(i) => {
                if o.id() != HarnessId::ClaudeCode && matches!(i.login, Login::ApiKey) {
                    routed.push(key);
                }
            }
            None => unknown |= !all_detected,
        }
    }
    if ctx
        .update_state(|s| {
            for k in &routed {
                s.prefs.chat_opt_in.entry((*k).into()).or_insert(true);
            }
            s.prefs.chat_migration_pending = unknown;
        })
        .is_err()
    {
        crate::applog::event("state_unwritable");
    }
}

/// Entries a request leaves out: the server whose `server_key` is
/// `server_key` (Unprotect), or the entries pointing at `dataset` (a
/// mailbox just removed).
#[derive(Clone, Copy, Default)]
struct Omit<'a> {
    server_key: Option<&'a str>,
    dataset: Option<&'a str>,
    /// The caller is a data-change refresh: no user sees a refusal's
    /// snippet, so a refused preview revokes the token it minted.
    refresh: bool,
}

/// [`build_request`] leaving out the entry whose `server_key` is `omit.server_key`
/// (Unprotect: that entry, gateway-pointing or not, is not written; the
/// revert before the apply restores its original). Other entries of the
/// same name (another scope) are untouched.
async fn build(
    ctx: &Ctx,
    h: &dyn HarnessOps,
    token: Zeroizing<String>,
    omit: Omit<'_>,
) -> Result<(ConnectRequest, Option<&'static str>), CmdError> {
    // Fetched here, at apply time (never a status remembered from an earlier
    // poll): only a Running proxy owns its address. For any other state
    // whatever holds the address would get the raw conversation and the
    // harness's credentials, so neither the base URLs nor the client header
    // are written and the fixed warning says why. The CLI does the same.
    let snap = crate::poll::tick(ctx).await;
    let mut sys = system_view(ctx, &snap);
    let chat = chat_wanted(ctx, h);
    let chat_skipped = snap.proxy.ok().and_then(|p| p.state.chat_route_skipped());
    if chat_skipped.is_some() {
        sys.proxy = ProxyUrls::default();
        sys.client_header = None;
    }
    let listen = sys
        .gateway_listen
        .clone()
        .ok_or_else(CmdError::service_unreachable)?;
    let gateway_base = format!("http://{listen}");
    let prot = ctx
        .state()
        .protected
        .get(harness_key(h.id()))
        .cloned()
        .unwrap_or_default();
    let datasets = snap
        .status
        .as_ref()
        .map(|st| st.datasets.as_slice())
        .unwrap_or_default();
    let servers = h.servers(&gateway_base)?;
    // The entry of a mailbox the user just removed points at a dataset the
    // daemon no longer has: it is left out (and its name is free again), so
    // the revert that precedes the apply takes it away with the app's other
    // entries.
    let stale = |s: &super::ops::ServerEntry| {
        omit.dataset.is_some() && s.gateway_dataset.as_deref() == omit.dataset
    };
    // New mailbox entries skip every name the harness already uses,
    // including an `inumaki-mail` that points at another mailbox.
    let taken: BTreeSet<String> = servers
        .iter()
        .filter(|s| !stale(s))
        .map(|s| s.name.clone())
        .collect();
    let mut gateway: Vec<GatewayEntry> = Vec::new();
    for s in servers {
        // A recorded protection whose key cannot be computed fails closed:
        // dropping it would hand the server its original entry back. The
        // key includes the scope: a recorded protection maps only its own
        // entry, never a same-named one of another scope (another account).
        let k = if prot.is_empty() && omit.server_key.is_none() {
            None
        } else {
            Some(server_key(ctx, h.id(), &s.name, &s.scope)?)
        };
        if omit.server_key.is_some() && k.as_deref() == omit.server_key {
            continue;
        }
        let mapped = k
            .as_ref()
            .and_then(|k| prot.get(k))
            .and_then(|label| datasets.iter().find(|d| &d.label == label))
            .map(|d| d.id.clone());
        if stale(&s) {
            continue;
        }
        if let Some(ds) = s.gateway_dataset.clone().or(mapped) {
            // Read here, before Reconnect's revert takes it away, and only
            // from inumaki's own entry: a server being protected (`mapped`,
            // the user's entry) does not lend its setting to inumaki's.
            let approval_mode = s
                .gateway_dataset
                .is_some()
                .then_some(s.approval_mode)
                .flatten();
            gateway.push(GatewayEntry {
                name: s.name,
                scope: s.scope,
                url: gateway_url(&listen, &ds),
                token: token.clone(),
                approval_mode,
            });
        }
    }
    let mut mail: Vec<&str> = datasets
        .iter()
        .filter(|d| d.kind == DatasetKind::Mailbox)
        .map(|d| d.id.as_str())
        .collect();
    mail.sort_by_key(|id| {
        (
            id.strip_prefix("mail-")
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap_or(u64::MAX),
            id.to_string(),
        )
    });
    let mut fresh = 0usize;
    for ds in mail {
        let url = gateway_url(&listen, ds);
        // A mailbox the harness already has keeps its entry (and name).
        if gateway.iter().any(|g| g.url == url) {
            continue;
        }
        let name = mail_entry_name(fresh, &taken);
        fresh += 1;
        gateway.push(GatewayEntry {
            name,
            scope: Scope::User,
            url,
            token: token.clone(),
            approval_mode: None,
        });
    }
    let req = ConnectRequest {
        gateway_base,
        gateway,
        mirror_root: sys.mirror_root.clone(),
        outboxes: sys.outboxes.clone(),
        proxy: sys.proxy.clone(),
        hook_command: hook_command(ctx, h.id()),
        chat,
        client_header: sys.client_header.clone(),
    };
    Ok((req, chat_skipped))
}

/// Before an apply (Connect, Reconnect, a refresh; never a preview): with
/// no choice made, a harness whose active backup holds its chat route gets
/// the choice "on" saved. An apply while the proxy is not running skips the
/// route, and the backup it makes then holds none: without the saved choice
/// the route would be gone for good on the next apply. A choice that cannot
/// be saved stops the apply, so nothing is written.
async fn pin_chat(ctx: &Ctx, o: &Arc<dyn HarnessOps>) -> Result<(), CmdError> {
    // The apply paths detect `o` first: its login kind is known here.
    migrate_pre_m9_chat(ctx, false);
    if chat_choice(ctx, o.id()).is_some() {
        return Ok(());
    }
    if blocking(o, |o| Ok(o.chat_route_in_backup())).await? {
        let key = harness_key(o.id());
        ctx.update_state(|s| {
            s.prefs.chat_opt_in.entry(key.into()).or_insert(true);
        })?;
    }
    Ok(())
}

/// The request for `h` with a new `app:<harness>` token in every gateway
/// entry. The token is minted after the request is built (every earlier
/// failure leaves nothing to revoke) and only when an entry carries it, as
/// `inumaki connect` does: a token no file holds is never created. Used on
/// the apply paths only (see [`pin_chat`]).
async fn request_with_token(
    ctx: &Ctx,
    o: &Arc<dyn HarnessOps>,
    omit: Omit<'_>,
) -> Result<(ConnectRequest, Option<i64>, Option<&'static str>), CmdError> {
    // First, before anything is built or minted: a lingering record would
    // otherwise revoke the token minted below at the service's next sweep.
    settle_pending(ctx, o.id()).await?;
    pin_chat(ctx, o).await?;
    let (mut req, warning) = build(ctx, o.as_ref(), Zeroizing::new(String::new()), omit).await?;
    if req.gateway.is_empty() {
        return Ok((req, None, warning));
    }
    let t = ctx.client.create_token(&token_label(o.id())).await?;
    let token = Zeroizing::new(t.token.expose().to_string());
    for g in &mut req.gateway {
        g.token = token.clone();
    }
    Ok((req, Some(t.id), warning))
}

/// Best effort (a failure is logged by kind): used where the operation's
/// own error matters more, or where it already succeeded. A token that is
/// already gone (a settled record revoked it, review O4) is no failure.
async fn revoke(ctx: &Ctx, ids: impl IntoIterator<Item = i64>) {
    for id in ids {
        match ctx.client.revoke_token(id).await {
            Ok(()) => {}
            Err(e) if token_gone(&e) => {}
            Err(_) => crate::applog::event("token_revoke_failed"),
        }
    }
}

/// Nothing can be serving (spec D5): the socket file is missing or nobody
/// listens on it. A timeout, an HTTP failure, or a status error is not
/// offline: a hung or busy service accepts connections and still holds the
/// token.
fn offline(e: &ClientError) -> bool {
    matches!(
        e,
        ClientError::Connect(std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused)
    )
}

/// The service answered that the token does not exist (it was revoked
/// already). Mirrors `impl From<ClientError> for CmdError`: a `404` of the
/// router ("no such route") means a service without the route, never a
/// revocation (review R3).
fn token_gone(e: &ClientError) -> bool {
    matches!(
        e,
        ClientError::Status { status: 404, error }
            if error.as_ref().is_some_and(|d| d.message != "no such route")
    )
}

/// Revoke every token labelled `app:<h>` through the service; a token that
/// is already gone counts as revoked.
async fn revoke_label(ctx: &Ctx, h: HarnessId) -> Result<(), ClientError> {
    let label = token_label(h);
    for t in ctx.client.tokens().await? {
        if t.label != label {
            continue;
        }
        match ctx.client.revoke_token(t.id).await {
            Ok(()) => {}
            Err(e) if token_gone(&e) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Run a pending-revocation file operation off the async threads. Any
/// failure, a task that did not finish included, is `revocation_store`.
async fn on_store<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, revocations::RevocationError> + Send + 'static,
) -> Result<T, CmdError> {
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(v)) => Ok(v),
        _ => Err(CmdError::new("revocation_store")),
    }
}

/// Revert's revocation (spec D5, D6). Online it revokes as before
/// (`Ok(false)`). Only when nothing can be serving and the socket's config
/// file is usable does it write the pending record, then try once more:
/// a service that started meanwhile revokes now and the record goes; still
/// offline, the revocation is pending (`Ok(true)`), and the service applies
/// the record after binding its socket, so after the record exists. Any
/// other failure of the second try fails the Revert with the record kept
/// (review R2): the service may have read the directory before the record
/// existed, so only its sweep or the next Connect can be relied on.
async fn revoke_for_revert(ctx: &Ctx, h: HarnessId) -> Result<bool, CmdError> {
    match revoke_label(ctx, h).await {
        Ok(()) => return Ok(false),
        Err(e) if offline(&e) && ctx.paths.config_error.is_none() => {}
        Err(e) => return Err(e.into()),
    }
    let dir = ctx.paths.data_dir.clone();
    // No `clear` on a failure (ruling L5-38): a failed directory fsync after
    // the rename can leave this record visible, and clearing could drop an
    // earlier pending record of this harness. A leftover only revokes, which
    // fails closed.
    on_store(move || revocations::record(&dir, h)).await?;
    crate::applog::event("revocation_recorded");
    match revoke_label(ctx, h).await {
        Ok(()) => {
            let dir = ctx.paths.data_dir.clone();
            if on_store(move || revocations::clear(&dir, h)).await.is_err() {
                crate::applog::event("revocation_record_left");
            }
            Ok(false)
        }
        Err(e) if offline(&e) => Ok(true),
        Err(e) => Err(e.into()),
    }
}

/// Before a mint (spec D6): a pending record of `h` is applied online
/// (every `app:<h>` token revoked) and removed, so it cannot revoke the new
/// token later. A record that cannot be read, applied, or removed stops the
/// mint (`revocation_store`, or the service error).
async fn settle_pending(ctx: &Ctx, h: HarnessId) -> Result<(), CmdError> {
    let dir = ctx.paths.data_dir.clone();
    if !on_store(move || revocations::is_pending(&dir, h)).await? {
        return Ok(());
    }
    revoke_label(ctx, h).await?;
    let dir = ctx.paths.data_dir.clone();
    on_store(move || revocations::clear(&dir, h)).await?;
    crate::applog::event("revocation_settled");
    Ok(())
}

async fn tokens_labelled(ctx: &Ctx, label: &str) -> Result<Vec<i64>, CmdError> {
    Ok(ctx
        .client
        .tokens()
        .await?
        .into_iter()
        .filter(|t| t.label == label)
        .map(|t| t.id)
        .collect())
}

/// Detection spawns processes: off the async threads, and only on user actions.
async fn refresh(o: &Arc<dyn HarnessOps>) {
    let o = Arc::clone(o);
    let _ = tokio::task::spawn_blocking(move || o.refresh()).await;
}

/// Adapter file IO (preview, apply, revert, the backup store) on a blocking
/// thread. Callers hold the harness lock; its guard stays held across this
/// await, so nothing else touches the harness meanwhile. A task that did not
/// finish is `Failed("internal")`: the files are in an unknown state, which
/// every caller already treats like any other failure.
async fn blocking<T: Send + 'static>(
    o: &Arc<dyn HarnessOps>,
    f: impl FnOnce(&dyn HarnessOps) -> Result<T, OpError> + Send + 'static,
) -> Result<T, OpError> {
    let o = Arc::clone(o);
    tokio::task::spawn_blocking(move || f(o.as_ref()))
        .await
        .unwrap_or(Err(OpError::Failed("internal")))
}

/// Preview `req` off the async threads.
async fn preview_req(
    o: &Arc<dyn HarnessOps>,
    req: &Arc<ConnectRequest>,
) -> Result<Vec<FileChange>, OpError> {
    let req = Arc::clone(req);
    blocking(o, move |o| o.preview(&req)).await
}

/// The adapter's fixed warnings for `req`, off the async threads; a task
/// that did not finish gives none (the warnings never block a connect).
async fn warnings_req(o: &Arc<dyn HarnessOps>, req: &Arc<ConnectRequest>) -> Vec<Reason> {
    let req = Arc::clone(req);
    blocking(o, move |o| Ok(o.connect_warnings(&req)))
        .await
        .unwrap_or_default()
}

/// Apply `req` off the async threads.
async fn apply_req(o: &Arc<dyn HarnessOps>, req: &Arc<ConnectRequest>) -> Result<String, OpError> {
    let req = Arc::clone(req);
    blocking(o, move |o| o.apply(&req)).await
}

/// Revert `backup` off the async threads.
async fn revert_backup(o: &Arc<dyn HarnessOps>, backup: &str) -> Result<RevertSummary, OpError> {
    let b = backup.to_string();
    blocking(o, move |o| o.revert(&b)).await
}

/// [`revert_backup`] for the user's own Revert: nothing applies again after
/// it, so what the harness keeps for the connection goes too.
async fn revert_backup_final(
    o: &Arc<dyn HarnessOps>,
    backup: &str,
) -> Result<RevertSummary, OpError> {
    let b = backup.to_string();
    blocking(o, move |o| o.revert_final(&b)).await
}

/// The connect backup: the adapter's active one only (as `inumaki
/// connect`). A backup id `state.json` holds without an active backup is
/// stale (an outside revert, or a state write that failed): it is cleared,
/// and the harness counts as not connected. The backup store is read on a
/// blocking thread.
async fn current_backup(ctx: &Ctx, o: &Arc<dyn HarnessOps>) -> Result<Option<String>, CmdError> {
    let active = blocking(o, |o| Ok(o.active_backup())).await?;
    if active.is_none()
        && ctx
            .state()
            .backups
            .get(harness_key(o.id()))
            .is_some_and(|b| !b.is_empty())
        && ctx
            .update_state(|s| {
                s.backups.remove(harness_key(o.id()));
            })
            .is_err()
    {
        crate::applog::event("state_unwritable");
    }
    Ok(active)
}

/// Rule 2: a refusal keeps the token (it is in the snippet); anything else revokes it.
async fn failed(ctx: &Ctx, id: Option<i64>, e: OpError) -> CmdError {
    if !matches!(e, OpError::CannotEditSafely { .. }) {
        revoke(ctx, id).await;
    }
    e.into()
}

fn record(ctx: &Ctx, h: HarnessId, backup: String) -> Result<(), CmdError> {
    ctx.clear_reconnect_failed_mem(h);
    ctx.update_state(|s| {
        s.backups.insert(harness_key(h).into(), vec![backup]);
        s.reconnect_failed.remove(harness_key(h));
    })
}

/// Revoke this harness's tokens other than `keep` (a token pasted from an
/// earlier snippet): after a successful apply every gateway entry of the
/// harness carries `keep`.
async fn revoke_others(ctx: &Ctx, h: HarnessId, keep: Option<i64>) {
    match tokens_labelled(ctx, &token_label(h)).await {
        Ok(ids) => revoke(ctx, ids.into_iter().filter(|i| Some(*i) != keep)).await,
        Err(_) => crate::applog::event("token_list_failed"),
    }
}

/// The fixed sentence of a Revert that left the proxy client header in the
/// harness file (M6-1 §4.2: `inumaki connect revert` exits 2 then).
pub const CLIENT_HEADER_LEFT: Reason = Reason {
    code: "client_header_left",
    text: "The harness configuration still carries the inumaki client header, which now goes to the model provider. Remove the X-Inumaki-Client line by hand.",
};

/// The fixed sentence of a preview the adapter refused.
pub const PREVIEW_REFUSED: Reason = Reason {
    code: "preview_cannot_edit_safely",
    text: "inumaki cannot edit this file safely. Press Connect to get the lines to add by hand.",
};

/// Connect `h` (spec §6.3 step 4); a connected harness is reconnected.
pub async fn connect(ctx: &Ctx, h: HarnessId) -> Result<ConnectOutcome, CmdError> {
    let lock = ctx.harness_lock(h);
    let _held = lock.lock().await;
    connect_locked(ctx, h).await
}

/// [`connect`] for a caller that already holds `ctx.harness_lock(h)`
/// (Protect, Task 6); the guard is the proof. Never call [`connect`],
/// [`reconnect`], or [`revert`] while holding the lock: it is not reentrant.
pub async fn connect_held(
    ctx: &Ctx,
    h: HarnessId,
    _held: &tokio::sync::OwnedMutexGuard<()>,
) -> Result<ConnectOutcome, CmdError> {
    connect_locked(ctx, h).await
}

async fn connect_locked(ctx: &Ctx, h: HarnessId) -> Result<ConnectOutcome, CmdError> {
    let o = ops(ctx, h)?;
    if current_backup(ctx, &o).await?.is_some() {
        return reconnect_locked(ctx, h, Omit::default()).await;
    }
    refresh(&o).await;
    let (req, id, warning) = request_with_token(ctx, &o, Omit::default()).await?;
    let req = Arc::new(req);
    if let Err(e) = preview_req(&o, &req).await {
        return Err(failed(ctx, id, e).await);
    }
    let harness_warnings = warnings_req(&o, &req).await;
    let backup = match apply_req(&o, &req).await {
        Ok(b) => b,
        Err(e) => return Err(failed(ctx, id, e).await),
    };
    drop(req);
    revoke_others(ctx, h, id).await;
    // The files are written and use the token: a state that cannot be saved
    // is reported, but the token stays (Revert finds the adapter's backup).
    record(ctx, h, backup)?;
    Ok(ConnectOutcome {
        note: NEXT_SESSION,
        warning,
        harness_warnings,
    })
}

/// Revert `h` to its pre-inumaki configuration and revoke its tokens (rule 3).
pub async fn revert(ctx: &Ctx, h: HarnessId) -> Result<RevertSummary, CmdError> {
    let lock = ctx.harness_lock(h);
    let _held = lock.lock().await;
    let o = ops(ctx, h)?;
    // Revoke first (as `inumaki connect revert`): a token left in a drifted
    // file must stop working whatever the restore does. Offline, the record
    // is written before any file is touched, and a later failure keeps it.
    let revocation_pending = revoke_for_revert(ctx, h).await?;
    let summary = match current_backup(ctx, &o).await? {
        Some(b) => RevertSummary {
            revocation_pending,
            ..revert_backup_final(&o, &b).await?
        },
        None => {
            // Not "no backup": the files may still route through inumaki.
            if blocking(&o, |o| Ok(o.backup_unreadable())).await? {
                return Err(CmdError::new("backup_unreadable"));
            }
            RevertSummary {
                reverted: false,
                exact: false,
                conflicts: 0,
                client_header_left: false,
                codex_trust_left: false,
                revocation_pending,
            }
        }
    };
    ctx.clear_reconnect_failed_mem(h);
    // The user's own Revert starts the harness's chat choice over (D6): it
    // is back to "whatever the files hold", which after the revert is off.
    // Written here, never through the setter, which reconnects; also before
    // the `client_header_left` error.
    ctx.update_state(|s| {
        s.backups.remove(harness_key(h));
        s.reconnect_failed.remove(harness_key(h));
        s.prefs.chat_opt_in.remove(harness_key(h));
        s.last_check.remove(harness_key(h));
    })?;
    if summary.client_header_left {
        // The files are restored and the tokens revoked (or their revocation
        // recorded), but the per-install secret still goes to the model
        // provider: not a success.
        crate::applog::event("client_header_left");
        if summary.revocation_pending {
            // Review R1: the UI shows the header warning and the pending note.
            return Err(CmdError {
                reason: Some(CLIENT_HEADER_LEFT),
                ..CmdError::new("client_header_left_pending")
            });
        }
        return Err(CmdError {
            reason: Some(CLIENT_HEADER_LEFT),
            ..CmdError::new("client_header_left")
        });
    }
    Ok(summary)
}

/// Preview, revert, then apply with a new token (rules 4 and 5).
pub async fn reconnect(ctx: &Ctx, h: HarnessId) -> Result<ConnectOutcome, CmdError> {
    let lock = ctx.harness_lock(h);
    let held = lock.lock_owned().await;
    reconnect_held(ctx, h, &held).await
}

/// [`reconnect`] for a caller that already holds `ctx.harness_lock(h)`; the
/// guard is the proof. Protect uses [`connect_held`] and Unprotect
/// [`reconnect_without_held`].
pub async fn reconnect_held(
    ctx: &Ctx,
    h: HarnessId,
    _held: &tokio::sync::OwnedMutexGuard<()>,
) -> Result<ConnectOutcome, CmdError> {
    reconnect_locked(ctx, h, Omit::default()).await
}

/// [`reconnect_held`] that writes no entry for the server whose
/// `server_key` is `key` (Unprotect, Task 6): the revert restores the
/// original entry and the new apply leaves it alone, also when the file
/// already points it at the gateway.
pub async fn reconnect_without_held(
    ctx: &Ctx,
    h: HarnessId,
    key: &str,
    _held: &tokio::sync::OwnedMutexGuard<()>,
) -> Result<ConnectOutcome, CmdError> {
    reconnect_locked(
        ctx,
        h,
        Omit {
            server_key: Some(key),
            ..Omit::default()
        },
    )
    .await
}

async fn reconnect_locked(
    ctx: &Ctx,
    h: HarnessId,
    omit: Omit<'_>,
) -> Result<ConnectOutcome, CmdError> {
    let o = ops(ctx, h)?;
    refresh(&o).await;
    let old = tokens_labelled(ctx, &token_label(h)).await?;
    let (req, id, warning) = request_with_token(ctx, &o, omit).await?;
    // Every refusal happens here, before anything is written.
    let req = Arc::new(req);
    if let Err(e) = preview_req(&o, &req).await {
        if omit.refresh {
            // A refresh shows no snippet: nothing would ever hold the token.
            revoke(ctx, id).await;
            return Err(e.into());
        }
        return Err(failed(ctx, id, e).await);
    }
    // Read before the revert below: it never touches what they read.
    let harness_warnings = warnings_req(&o, &req).await;
    let before = match current_backup(ctx, &o).await {
        Ok(b) => b,
        Err(e) => {
            revoke(ctx, id).await;
            return Err(e);
        }
    };
    if let Some(b) = &before {
        if let Err(e) = revert_backup(&o, b).await {
            // Nothing applied: the earlier backup and its token stay in force.
            revoke(ctx, id).await;
            return Err(e.into());
        }
        if ctx
            .update_state(|s| {
                s.backups.remove(harness_key(h));
            })
            .is_err()
        {
            crate::applog::event("state_unwritable");
        }
    }
    let applied = apply_req(&o, &req).await;
    drop(req);
    match applied {
        Ok(backup) => {
            // Only now is the old token unused: the files carry the new one.
            revoke(ctx, old.into_iter().filter(|i| Some(*i) != id)).await;
            record(ctx, h, backup)?;
            Ok(ConnectOutcome {
                note: NEXT_SESSION,
                warning,
                harness_warnings,
            })
        }
        Err(e) if before.is_none() => Err(failed(ctx, id, e).await),
        Err(e) => {
            // The revert restored the original entries, but the failed apply
            // may have written some files before it stopped (the adapter then
            // keeps an active backup of them). Both tokens are revoked either
            // way: a half-written harness must not route with a live token,
            // and a refusal's snippet is dropped with its token. The mark is
            // cleared only by a Connect or Revert that succeeds.
            drop(e);
            revoke(ctx, id.into_iter().chain(old)).await;
            // Tray red even when state.json cannot be written.
            ctx.set_reconnect_failed(h);
            crate::applog::event("reconnect_failed_disconnected");
            Err(CmdError::new("reconnect_failed_disconnected"))
        }
    }
}

/// Answer of a data-source change (a mailbox or folder added or removed;
/// review C2c). The UI says "N harnesses could not be updated" when
/// `reconnect_failures` is not 0.
#[derive(Debug, Serialize)]
pub struct DataChange {
    /// Connected harnesses whose Reconnect failed.
    pub reconnect_failures: usize,
    /// Which ones: fixed harness keys (`claude-code`, `codex`, ...).
    pub failed_harnesses: Vec<&'static str>,
    /// A fixed warning code for the UI (the folder picker: `folder_needs_access`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<&'static str>,
}

impl DataChange {
    /// The answer for the harnesses [`refresh_connected`] could not update.
    pub fn from_failed(failed: Vec<&'static str>) -> DataChange {
        DataChange {
            reconnect_failures: failed.len(),
            failed_harnesses: failed,
            warning: None,
        }
    }
}

/// Reconnect every connected harness, so a new or removed mailbox or folder
/// reaches its configuration. Each harness is taken under its own lock and
/// re-checked there (a Revert that ran meanwhile is not undone by a
/// Reconnect). A Reconnect previews before it reverts (review C2), so a
/// refusal changes nothing; an apply failure after the revert is recorded
/// in `reconnect_failed` by the Reconnect itself (tray red). Returns the
/// harnesses that failed; the other harnesses are still updated.
pub async fn refresh_connected(ctx: &Ctx) -> Vec<&'static str> {
    refresh_omitting(ctx, None).await
}

/// [`refresh_connected`] after the mailbox `removed` was deleted: no harness
/// gets an entry for it back.
pub async fn refresh_after_removing(ctx: &Ctx, removed: &str) -> Vec<&'static str> {
    refresh_omitting(ctx, Some(removed)).await
}

async fn refresh_omitting(ctx: &Ctx, removed: Option<&str>) -> Vec<&'static str> {
    let connected: Vec<HarnessId> = super::detected(ctx)
        .into_iter()
        .filter(|d| d.connected)
        .map(|d| d.id)
        .collect();
    let mut failed = Vec::new();
    for h in connected {
        if refresh_one(ctx, h, removed).await {
            failed.push(harness_key(h));
        }
    }
    crate::applog::count("refresh_connected", "failed", failed.len() as u64);
    failed
}

/// Reconnect `h` only, when it is connected, under its lock (a change that
/// only `h`'s files depend on: its chat switch).
/// Returns the harness when its Reconnect failed, like [`refresh_connected`].
pub async fn refresh_harness(ctx: &Ctx, h: HarnessId) -> Vec<&'static str> {
    let failed = refresh_one(ctx, h, None).await;
    crate::applog::count("refresh_harness", "failed", u64::from(failed));
    if failed {
        vec![harness_key(h)]
    } else {
        Vec::new()
    }
}

/// One harness of a refresh: taken under its own lock and re-checked there
/// (a Revert that ran meanwhile is not undone). `true` when it failed.
async fn refresh_one(ctx: &Ctx, h: HarnessId, removed: Option<&str>) -> bool {
    let lock = ctx.harness_lock(h);
    let _held = lock.lock_owned().await;
    let still = match ops(ctx, h) {
        Ok(o) => current_backup(ctx, &o).await.is_ok_and(|b| b.is_some()),
        Err(_) => false,
    };
    let omit = Omit {
        server_key: None,
        dataset: removed,
        refresh: true,
    };
    still && reconnect_locked(ctx, h, omit).await.is_err()
}

/// The files and keys Connect would change, before writing (spec §6.3).
/// Mints no token: the request carries a placeholder, so a refusal's
/// snippet (which would carry it) is dropped and the user is told to press
/// Connect for the working one.
pub async fn preview(ctx: &Ctx, h: HarnessId) -> Result<Vec<FileChange>, CmdError> {
    let lock = ctx.harness_lock(h);
    let _held = lock.lock().await;
    let o = ops(ctx, h)?;
    refresh(&o).await;
    let req = build_request(ctx, o.as_ref(), Zeroizing::new("inumaki_gw_preview".into())).await?;
    match preview_req(&o, &Arc::new(req)).await {
        Ok(v) => Ok(v),
        Err(OpError::CannotEditSafely { .. }) => Err(CmdError {
            reason: Some(PREVIEW_REFUSED),
            ..CmdError::new("cannot_edit_safely")
        }),
        Err(e) => Err(e.into()),
    }
}

/// One gateway entry for the "Other client" card (no `Debug`: URLs carry dataset slugs).
#[derive(Serialize)]
pub struct OtherEntry {
    /// Suggested entry name, fixed and model-visible: `inumaki-mail…` for
    /// mailboxes, `inumaki-mcp…` for wrapped servers. Never a dataset's
    /// display name (often a customer's).
    pub name: String,
    /// Gateway URL.
    pub url: String,
}

/// The "Other client" card (spec §4.7, §4.3 amendment item 3). `Debug`
/// prints counts only: it can hold a token and the client header. Never
/// persisted, never logged.
#[derive(Serialize)]
pub struct OtherClient {
    /// Gateway entries.
    pub gateway: Vec<OtherEntry>,
    /// A new token, shown once; `None` when an `app:other` token exists
    /// already (revoke it to create another: tokens are never shown twice).
    pub token: Option<String>,
    /// (route, base URL).
    pub proxy: Vec<(String, String)>,
    /// The proxy client header line to add with the base URL
    /// (`X-Inumaki-Client: <value>`); `None` when the proxy serves none.
    pub client_header: Option<String>,
    /// Fixed warning instead of the two fields above: the proxy was not
    /// running when the card was opened, so its address is not offered.
    pub proxy_warning: Option<&'static str>,
}

impl std::fmt::Debug for OtherClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtherClient")
            .field("gateway", &self.gateway.len())
            .field("token", &self.token.is_some())
            .field("proxy", &self.proxy.len())
            .finish_non_exhaustive()
    }
}

/// `inumaki-mcp`, `inumaki-mcp-2`, …: the `index`-th wrapped server (0-based).
fn mcp_entry_name(index: usize) -> String {
    match index {
        0 => "inumaki-mcp".to_string(),
        n => format!("inumaki-mcp-{}", n + 1),
    }
}

/// What to paste into another client; mints `app:other` only when none
/// exists, so repeated opens do not pile up tokens.
pub async fn other_client(ctx: &Ctx) -> Result<OtherClient, CmdError> {
    // Two quick opens must not both find no token and mint two.
    let _held = OTHER_LOCK.lock().await;
    let snap = crate::poll::tick(ctx).await;
    let st = snap
        .status
        .as_ref()
        .ok_or_else(CmdError::service_unreachable)?;
    let listen = &st.gateway.listen;
    let served: BTreeSet<&str> = st.gateway.datasets.iter().map(|d| d.id.as_str()).collect();
    let (mut mail, mut mcp) = (0usize, 0usize);
    let gateway = st
        .datasets
        .iter()
        // Datasets the gateway serves (wrapped servers) and mailboxes; never
        // a check's temporary dataset, a folder, or a plain namespace.
        .filter(|d| {
            !d.id.starts_with("check-")
                && d.kind != DatasetKind::Folder
                && (d.kind == DatasetKind::Mailbox || served.contains(d.id.as_str()))
        })
        .map(|d| {
            let name = if d.kind == DatasetKind::Mailbox {
                mail += 1;
                mail_entry_name(mail - 1, &BTreeSet::new())
            } else {
                mcp += 1;
                mcp_entry_name(mcp - 1)
            };
            OtherEntry {
                name,
                url: gateway_url(listen, &d.id),
            }
        })
        .collect();
    let token = if tokens_labelled(ctx, OTHER_LABEL).await?.is_empty() {
        Some(
            ctx.client
                .create_token(OTHER_LABEL)
                .await?
                .token
                .expose()
                .to_string(),
        )
    } else {
        None
    };
    // Only a Running proxy owns its address (as in `build`): otherwise the
    // base URL and the client header would be pasted into a client that then
    // sends them to whatever holds the address.
    let proxy_warning = snap.proxy.ok().and_then(|p| p.state.chat_route_skipped());
    let p = snap.proxy.ok().filter(|_| proxy_warning.is_none());
    let proxy = p
        .map(|p| {
            p.routes
                .iter()
                .map(|r| (route_name(r.prefix).to_string(), r.base_url.clone()))
                .collect()
        })
        .unwrap_or_default();
    let client_header = p
        .filter(|p| !p.client_header.value.is_empty())
        .map(|p| format!("{}: {}", p.client_header.name, p.client_header.value));
    Ok(OtherClient {
        gateway,
        token,
        proxy,
        client_header,
        proxy_warning,
    })
}

static OTHER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Revoke the other-client token(s).
pub async fn revoke_other_client(ctx: &Ctx) -> Result<(), CmdError> {
    let _held = OTHER_LOCK.lock().await;
    for id in tokens_labelled(ctx, OTHER_LABEL).await? {
        ctx.client.revoke_token(id).await?;
    }
    Ok(())
}
