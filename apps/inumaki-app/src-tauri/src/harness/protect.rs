//! The Protect switch (spec §4.5). The wrapped server's secrets move into
//! the vault (and stay in the adapter backup until it is deleted); the
//! harness entry keeps its name and points at the gateway.
//!
//! Which dataset a definition uses is M6-1's keyed definition index
//! (`<data_dir>/adapters/definitions.json`), shared with `inumaki connect
//! --protect`: an identical definition in another harness joins the same
//! dataset, and two accounts of one server never share one. Which servers of
//! a harness are protected is `state.json` (`protected[harness][server_key]
//! = dataset label`; `server_key` is an HMAC, so no server name is stored).
//!
//! A server entry is identified by its `server_key` (harness, name, and
//! scope), never by its name alone: Claude Code lists one name once per
//! scope (user, each project), often with different accounts. The UI gets
//! the key as [`ServerRow::id`] and passes it back.
//!
//! Locks: Protect and Unprotect hold `ctx.harness_lock(h)` from before they
//! read the entry until the harness files are written, and call only the
//! `*_held` variants of `connect` (the lock is not reentrant). Protect's
//! find-or-create of a definition's dataset through its state write, and
//! `remove_dataset`, also hold [`DEFINITIONS`]: always taken after a harness
//! lock and released before any harness operation. So two harnesses
//! protecting one definition at once create one dataset, and a dataset
//! being joined is recorded before `remove_dataset` can look at it.

use std::collections::{BTreeMap, BTreeSet};

use inumaki_client::{ContractState, CreateDataset, DatasetKind, HarnessId};
use serde::Serialize;

use super::adapt::{defined_datasets, definition_dataset, record_definition, upstream_create};
use super::connect::{self, NEXT_SESSION};
use super::naming::{credential_like, dataset_id, definition_id, server_key};
use super::ops::{Reason, Scope, ServerEntry, Transport};
use super::{detected, harness_key};
use crate::ctx::Ctx;
use crate::error::CmdError;

const FALLBACK_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// The wrapped-server default profile (spec §4.5 step 3): `strict`, the
/// model-backed profile plan 2c calibrates discovery metadata for
/// (`<profile>-metadata`); the daemon's default when `strict` is not
/// available (no models yet).
pub const WRAPPED_SERVER_PROFILE: &str = "strict";

/// Serializes the definition index's find-or-create and dataset removal.
static DEFINITIONS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The warning of a Protect whose entry holds a value the credential split
/// (by name only, spec §4.5 amendment 2026-10-04) cannot move to the vault.
pub const SECRET_OUTSIDE_NAMES: Reason = Reason {
    code: "secret_outside_credential_names",
    text: "This server is protected, but its command arguments or URL look like they carry a credential. inumaki stores those as ordinary settings, not as vault secrets. Unprotect the server, move the credential into an environment variable or header with a name like TOKEN or API_KEY, then Protect it again.",
};

/// One row of the MCP servers view. Names are shown to the local user;
/// `Debug` prints flags only.
#[derive(Serialize)]
pub struct ServerRow {
    /// Opaque id of this entry (its `server_key`): what Protect, Unprotect,
    /// and "leave unprotected" take. Two entries of one name in different
    /// scopes have different ids.
    pub id: String,
    /// Harness.
    pub harness: HarnessId,
    /// Entry name.
    pub name: String,
    /// `user` or `project` (the kind only: a project directory is never
    /// shown), so two entries of one name can be told apart.
    pub scope: &'static str,
    /// Transport.
    pub transport: Transport,
    /// The harness file points this entry at the gateway.
    pub protected: bool,
    /// Protect was switched on, but the file does not point at the gateway
    /// yet (a refused Connect whose snippet was not added, a failed
    /// Reconnect): Reconnect, or add the snippet.
    pub pending: bool,
    /// Dataset, when protected or pending.
    pub dataset: Option<String>,
    /// Upstream contract state.
    pub contract: Option<ContractState>,
    /// Upstream state.
    pub upstream_state: Option<String>,
    /// Restarts.
    pub restarts: Option<u32>,
    /// Upstream name (for "Accept current schema").
    pub upstream: Option<String>,
    /// The user chose to leave it unprotected.
    pub left_unprotected: bool,
    /// Why it cannot be protected (`needs_oauth`).
    pub cannot_protect: Option<&'static str>,
}

impl std::fmt::Debug for ServerRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerRow")
            .field("scope", &self.scope)
            .field("transport", &self.transport)
            .field("protected", &self.protected)
            .field("pending", &self.pending)
            .field("contract", &self.contract)
            .field("left_unprotected", &self.left_unprotected)
            .finish_non_exhaustive()
    }
}

/// Answer of Protect. `Debug` prints flags only: the dataset id derives
/// from the server name.
#[derive(Serialize)]
pub struct ProtectOutcome {
    /// Dataset id.
    pub dataset: String,
    /// An identical definition's dataset was joined.
    pub reused: bool,
    /// Fixed note.
    pub note: &'static str,
    /// [`SECRET_OUTSIDE_NAMES`] when an argument or the URL looks like it
    /// carries a credential.
    pub warning: Option<Reason>,
    /// The connect's fixed harness warnings (`codex_approval_never`,
    /// `hook_blocks_when_stopped`): Protect
    /// often writes a harness's first gateway entry, so this is where the app
    /// usually shows them.
    pub harness_warnings: Vec<Reason>,
}

impl std::fmt::Debug for ProtectOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtectOutcome")
            .field("reused", &self.reused)
            .field("warning", &self.warning.map(|w| w.code))
            .field(
                "harness_warnings",
                &self
                    .harness_warnings
                    .iter()
                    .map(|w| w.code)
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// Answer of Unprotect. `Debug` prints whether a dataset is offered only.
#[derive(Serialize)]
pub struct UnprotectOutcome {
    /// No harness uses this dataset any more: offer to delete it (after confirmation).
    pub unreferenced_dataset: Option<String>,
    /// Fixed note.
    pub note: &'static str,
}

impl std::fmt::Debug for UnprotectOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnprotectOutcome")
            .field("unreferenced_dataset", &self.unreferenced_dataset.is_some())
            .finish_non_exhaustive()
    }
}

/// Not a failure of "nothing written": the snippet holds the new entries,
/// or the harness is already on its original entries (rule 5).
fn wrote_or_disconnected(e: &CmdError) -> bool {
    matches!(
        e.kind,
        "cannot_edit_safely" | "reconnect_failed_disconnected"
    )
}

/// A server id as [`ServerRow::id`] carries it: 64 lower-case hex digits.
/// Anything else (a name the UI passed by mistake) is never written to
/// `state.json`.
fn id_ok(id: &str) -> Result<(), CmdError> {
    if id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(CmdError::new("bad_request"))
    }
}

/// The entry of harness `h` whose `server_key` is `id`.
async fn find(ctx: &Ctx, h: HarnessId, id: &str) -> Result<ServerEntry, CmdError> {
    id_ok(id)?;
    let o = ctx
        .harnesses
        .iter()
        .find(|o| o.id() == h)
        .cloned()
        .ok_or_else(|| CmdError::new("harness_not_found"))?;
    let base = format!("http://{}", ctx.client.status().await?.gateway.listen);
    for s in o.servers(&base)? {
        if server_key(ctx, h, &s.name, &s.scope)? == id {
            return Ok(s);
        }
    }
    Err(CmdError::new("server_not_found"))
}

/// Every server entry of every detected harness, with gateway state. No
/// state key means no ids: an error (fail closed), not rows nobody can act on.
pub async fn servers(ctx: &Ctx) -> Result<Vec<ServerRow>, CmdError> {
    let st = ctx.client.status().await?;
    let base = format!("http://{}", st.gateway.listen);
    let by_label: BTreeMap<&str, &str> = st
        .datasets
        .iter()
        .map(|d| (d.label.as_str(), d.id.as_str()))
        .collect();
    let state = ctx.state();
    let mut rows = Vec::new();
    for d in detected(ctx) {
        let prot = state
            .protected
            .get(harness_key(d.id))
            .cloned()
            .unwrap_or_default();
        for s in d.ops.servers(&base).unwrap_or_default() {
            let key = server_key(ctx, d.id, &s.name, &s.scope)?;
            let mapped = prot
                .get(&key)
                .and_then(|l| by_label.get(l.as_str()))
                .map(|id| id.to_string());
            let protected = s.gateway_dataset.is_some();
            let dataset = s.gateway_dataset.clone().or(mapped);
            let up = dataset
                .as_ref()
                .and_then(|ds| st.gateway.datasets.iter().find(|g| &g.id == ds))
                .and_then(|g| g.upstreams.first());
            rows.push(ServerRow {
                harness: d.id,
                protected,
                pending: !protected && dataset.is_some(),
                contract: up.map(|u| u.contract),
                upstream_state: up.map(|u| u.state.clone()),
                restarts: up.map(|u| u.restarts),
                upstream: up.map(|u| u.name.clone()),
                left_unprotected: state.leave_unprotected.contains(&key),
                cannot_protect: s.needs_oauth.then_some("needs_oauth"),
                scope: match s.scope {
                    Scope::User => "user",
                    Scope::Local(_) => "project",
                },
                transport: s.transport,
                name: s.name,
                dataset,
                id: key,
            });
        }
    }
    Ok(rows)
}

/// `K=V` or `K: V` with a credential-like `K` and a value.
fn pair_flagged(a: &str) -> bool {
    let kv = |sep: char| {
        a.split_once(sep).is_some_and(|(k, v)| {
            let k = k.trim().trim_start_matches('-');
            !k.is_empty() && !v.trim().is_empty() && credential_like(k)
        })
    };
    kv('=') || (kv(':') && !a.contains("://"))
}

/// A URL with userinfo, or a credential-like query key with a value.
fn url_flagged(url: &str) -> bool {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        return true;
    }
    url.split_once('?')
        .map(|(_, q)| q.split('#').next().unwrap_or_default())
        .is_some_and(|q| {
            q.split('&')
                .filter_map(|p| p.split_once('='))
                .any(|(k, v)| !v.is_empty() && credential_like(k))
        })
}

/// An argument or the URL looks like it carries a credential, which the
/// split by name leaves in the non-secret fields (spec §4.5 amendment):
/// `--token=x`, `--api-key x`, `-e GITHUB_TOKEN=x`, `--header
/// "Authorization: Bearer x"`, positional `K=V` / `K: V`, a URL argument
/// or entry URL with userinfo or a credential-like query key. Never echoes
/// the value.
fn secret_outside_names(e: &ServerEntry) -> bool {
    let flag = |a: &str| {
        let a = a.trim_start_matches('-');
        !a.is_empty() && credential_like(a)
    };
    let mut args = e.args.iter().peekable();
    while let Some(a) = args.next() {
        if a.contains("://") && url_flagged(a) {
            return true;
        }
        if pair_flagged(a) {
            return true;
        }
        if a.starts_with('-')
            && !a.contains('=')
            && flag(a)
            && args.peek().is_some_and(|n| !n.starts_with('-'))
        {
            return true;
        }
    }
    e.url.as_deref().is_some_and(url_flagged)
}

/// Put back the state of `key` in harness `h` as it was before Protect.
fn restore_protect(ctx: &Ctx, h: HarnessId, key: &str, before: &Option<String>, was_left: bool) {
    let restored = ctx.update_state(|s| {
        let m = s.protected.entry(harness_key(h).into()).or_default();
        match before {
            Some(l) => m.insert(key.to_string(), l.clone()),
            None => m.remove(key),
        };
        if m.is_empty() {
            s.protected.remove(harness_key(h));
        }
        if was_left {
            s.leave_unprotected.insert(key.to_string());
        }
    });
    if restored.is_err() {
        crate::applog::event("state_unwritable");
    }
}

/// Protect the entry `id` ([`ServerRow::id`]) of harness `h`.
pub async fn protect(ctx: &Ctx, h: HarnessId, id: &str) -> Result<ProtectOutcome, CmdError> {
    let held = ctx.harness_lock(h).lock_owned().await;
    // `find` computes the key (fails closed without the state key) before
    // anything is created.
    let entry = find(ctx, h, id).await?;
    let key = id.to_string();
    if entry.gateway_dataset.is_some() {
        return Err(CmdError::new("already_protected"));
    }
    if entry.needs_oauth {
        return Err(CmdError::new("cannot_protect_yet"));
    }
    let def = definition_id(&ctx.paths.data_dir, &entry)?;
    let warning = secret_outside_names(&entry).then_some(SECRET_OUTSIDE_NAMES);
    let defs = DEFINITIONS.lock().await;
    let datasets = ctx.client.datasets().await?;
    // A recorded dataset that no longer exists is recreated.
    let existing = definition_dataset(&ctx.paths.data_dir, &def)?
        .and_then(|ds| datasets.iter().find(|d| d.id == ds))
        .map(|d| (d.id.clone(), d.label.clone()));
    let (dataset, label, reused) = match existing {
        Some((ds, label)) => (ds, label, true),
        None => {
            let taken = datasets.iter().map(|d| d.id.clone()).collect();
            let (ds, label) = create(ctx, &entry, &taken).await?;
            // Recorded at once: a later failure leaves a reusable mapping,
            // not an upstream with secrets nothing points to.
            record_definition(&ctx.paths.data_dir, def, ds.clone())?;
            (ds, label, false)
        }
    };
    drop(entry);
    let st = ctx.state();
    let before = st
        .protected
        .get(harness_key(h))
        .and_then(|m| m.get(&key))
        .cloned();
    let was_left = st.leave_unprotected.contains(&key);
    ctx.update_state(|s| {
        s.protected
            .entry(harness_key(h).into())
            .or_default()
            .insert(key.clone(), label.clone());
        s.leave_unprotected.remove(&key);
    })?;
    // The label is in `state.json` now: `remove_dataset` sees it in use.
    drop(defs);
    let connected = match connect::connect_held(ctx, h, &held).await {
        Ok(out) => out,
        Err(e) => {
            if !wrote_or_disconnected(&e) {
                // Nothing was written: the view must not show a pending
                // protection the user did not get.
                restore_protect(ctx, h, &key, &before, was_left);
            }
            return Err(e);
        }
    };
    // The apply succeeded; the file must now point this entry at `dataset`
    // (a dataset the status did not list would have been left out). A read
    // that fails says nothing about the file: its error is returned and the
    // state stays (the file may route the entry already). Only a read that
    // shows the entry elsewhere, or gone, restores the state.
    let routed = match find(ctx, h, id).await {
        Ok(e) => e.gateway_dataset.as_deref() == Some(dataset.as_str()),
        Err(e) if e.kind == "server_not_found" => false,
        Err(e) => return Err(e),
    };
    if !routed {
        restore_protect(ctx, h, &key, &before, was_left);
        return Err(CmdError::new("not_routed"));
    }
    Ok(ProtectOutcome {
        dataset,
        reused,
        note: NEXT_SESSION,
        warning,
        harness_warnings: connected.harness_warnings,
    })
}

/// Create the dataset and its upstream; delete the dataset if the upstream fails.
async fn create(
    ctx: &Ctx,
    e: &ServerEntry,
    taken: &BTreeSet<String>,
) -> Result<(String, String), CmdError> {
    // The login service starts with a minimal environment, and plan 2c
    // clears the child environment to an allowlist (spec §4.5 step 1): the
    // command is resolved with, and the upstream records, the login PATH.
    // The shell can take seconds: off the async threads (this runs under the
    // harness lock and `DEFINITIONS`).
    let path = ctx
        .login_path()
        .await
        .unwrap_or_else(|| FALLBACK_PATH.into());
    let up = upstream_create(e, Some(&path));
    if e.transport == Transport::Stdio && !up.command.as_deref().is_some_and(|c| c.starts_with('/'))
    {
        return Err(CmdError::new("command_not_found"));
    }
    if e.transport == Transport::Http && up.url.as_deref().is_none_or(str::is_empty) {
        return Err(CmdError::new("url_missing"));
    }
    let id = dataset_id(&e.name, taken);
    // Display name = server name (spec §4.5 step 3): the daemon seals it like
    // every dataset name and never logs it.
    let mut body = CreateDataset::new(id, e.name.clone());
    let strict = ctx.client.status().await.is_ok_and(|s| {
        s.profiles
            .iter()
            .any(|p| p.name == WRAPPED_SERVER_PROFILE && p.available)
    });
    body.profile = strict.then(|| WRAPPED_SERVER_PROFILE.to_string());
    let created = ctx.client.create_dataset(&body).await?;
    if let Err(err) = ctx.client.create_upstream(&created.id, &up).await {
        // Do not leave an empty dataset behind.
        let _ = ctx.client.delete_dataset(&created.id).await;
        return Err(err.into());
    }
    Ok((created.id, created.label))
}

/// Some detected harness has an entry pointing at `dataset`, other than the
/// entry of harness `h` whose key is `except`. A harness whose entries (or
/// keys) cannot be read counts as using it (fail closed: never offer to
/// delete a live dataset).
fn file_uses(ctx: &Ctx, base: &str, dataset: &str, except: Option<(HarnessId, &str)>) -> bool {
    detected(ctx).iter().any(|d| match d.ops.servers(base) {
        Ok(list) => list.iter().any(|s| {
            s.gateway_dataset.as_deref() == Some(dataset)
                && match except {
                    Some((h, key)) if h == d.id => {
                        !server_key(ctx, h, &s.name, &s.scope).is_ok_and(|k| k == key)
                    }
                    _ => true,
                }
        }),
        Err(_) => true,
    })
}

/// Unprotect the entry `id` ([`ServerRow::id`]) of harness `h`: the
/// original entry comes back; a same-named entry of another scope is untouched.
///
/// An entry the file points at the gateway counts as protected (spec §4.5)
/// also without a `state.json` record: one `inumaki connect --protect`
/// protected, or one whose record was lost (a `state.json` set aside as
/// corrupt, a regenerated `state.key` that changed every id). It is
/// restored from the adapter's backup the same way; its dataset label comes
/// from the daemon's status.
pub async fn unprotect(ctx: &Ctx, h: HarnessId, id: &str) -> Result<UnprotectOutcome, CmdError> {
    id_ok(id)?;
    let held = ctx.harness_lock(h).lock_owned().await;
    let key = id.to_string();
    let o = ctx
        .harnesses
        .iter()
        .find(|o| o.id() == h)
        .cloned()
        .ok_or_else(|| CmdError::new("harness_not_found"))?;
    // Not connected: nothing in the files is inumaki's to restore.
    let connected = o.active_backup().is_some();
    let recorded = ctx
        .state()
        .protected
        .get(harness_key(h))
        .and_then(|m| m.get(&key).cloned());
    let label = match &recorded {
        Some(l) => Some(l.clone()),
        None => {
            let ds = match find(ctx, h, id).await {
                Ok(e) => e.gateway_dataset,
                Err(e) if e.kind == "server_not_found" => None,
                Err(e) => return Err(e),
            }
            .ok_or_else(|| CmdError::new("not_protected"))?;
            let d = ctx
                .client
                .status()
                .await?
                .datasets
                .into_iter()
                .find(|d| d.id == ds);
            // A mailbox's `inumaki-mail…` entry is no wrapped server: the
            // Email view removes it, not Unprotect.
            if d.as_ref().is_some_and(|d| d.kind == DatasetKind::Mailbox) {
                return Err(CmdError::new("not_protected"));
            }
            if !connected {
                // Routed by hand (a snippet): no backup holds its original.
                return Err(CmdError::new(if o.backup_unreadable() {
                    "backup_unreadable"
                } else {
                    "not_protected"
                }));
            }
            d.map(|d| d.label)
        }
    };
    if recorded.is_some() {
        ctx.update_state(|s| {
            if let Some(m) = s.protected.get_mut(harness_key(h)) {
                m.remove(&key);
                if m.is_empty() {
                    s.protected.remove(harness_key(h));
                }
            }
        })?;
    }
    if connected {
        if let Err(e) = connect::reconnect_without_held(ctx, h, &key, &held).await {
            if let Some(l) = recorded.filter(|_| !wrote_or_disconnected(&e)) {
                let restored = ctx.update_state(|s| {
                    s.protected
                        .entry(harness_key(h).into())
                        .or_default()
                        .insert(key.clone(), l);
                });
                if restored.is_err() {
                    crate::applog::event("state_unwritable");
                }
            }
            return Err(e);
        }
    }
    drop(held);
    let still_recorded = label.as_ref().is_none_or(|label| {
        ctx.state()
            .protected
            .values()
            .any(|m| m.values().any(|l| l == label))
    });
    let dataset = if still_recorded {
        None
    } else {
        let st = ctx.client.status().await?;
        let base = format!("http://{}", st.gateway.listen);
        st.datasets
            .into_iter()
            .find(|d| Some(&d.label) == label.as_ref())
            .map(|d| d.id)
            .filter(|ds| !file_uses(ctx, &base, ds, Some((h, &key))))
    };
    Ok(UnprotectOutcome {
        unreferenced_dataset: dataset,
        note: NEXT_SESSION,
    })
}

/// Delete an unreferenced wrapped-server dataset (after the user confirmed).
/// Only a generic dataset the definition index records (one Protect or
/// `inumaki connect --protect` made): never a mailbox's or a folder's vault
/// namespace, nor a dataset the user made by hand.
pub async fn remove_dataset(ctx: &Ctx, dataset: &str) -> Result<(), CmdError> {
    let _defs = DEFINITIONS.lock().await;
    let st = ctx.client.status().await?;
    let base = format!("http://{}", st.gateway.listen);
    let d = st
        .datasets
        .into_iter()
        .find(|d| d.id == dataset)
        .ok_or_else(|| CmdError::new("not_found"))?;
    if d.kind != DatasetKind::Generic || !defined_datasets(&ctx.paths.data_dir)?.contains(&d.id) {
        return Err(CmdError::new("not_a_wrapped_server"));
    }
    if ctx
        .state()
        .protected
        .values()
        .any(|m| m.values().any(|l| *l == d.label))
        || file_uses(ctx, &base, dataset, None)
    {
        return Err(CmdError::new("still_in_use"));
    }
    for u in ctx.client.upstreams(dataset).await.unwrap_or_default() {
        let _ = ctx.client.delete_upstream(dataset, &u.name).await;
    }
    ctx.client.delete_dataset(dataset).await?;
    Ok(())
}

/// Mark or unmark "leave unprotected" (spec §4.6) for the entry `id` of
/// harness `h`. Marking needs the entry to exist; unmarking works for an
/// entry that is gone.
pub async fn leave_unprotected(
    ctx: &Ctx,
    h: HarnessId,
    id: &str,
    on: bool,
) -> Result<(), CmdError> {
    id_ok(id)?;
    // Under the harness lock, as every other write of a server's state: a
    // toggle never interleaves with a Protect that clears the mark.
    let _held = ctx.harness_lock(h).lock_owned().await;
    if on {
        find(ctx, h, id).await?;
    }
    ctx.update_state(|s| {
        if on {
            s.leave_unprotected.insert(id.to_string());
        } else {
            s.leave_unprotected.remove(id);
        }
    })
}

/// "Accept current schema" on `drift` (spec §4.5).
pub async fn accept_schema(ctx: &Ctx, dataset: &str, upstream: &str) -> Result<(), CmdError> {
    let st = ctx.client.status().await?;
    let fp = st
        .gateway
        .datasets
        .iter()
        .find(|d| d.id == dataset)
        .and_then(|d| d.upstreams.iter().find(|u| u.name == upstream))
        .and_then(|u| u.schema_fingerprint.clone());
    Ok(ctx
        .client
        .accept_schema(dataset, upstream, fp.as_deref())
        .await?)
}
