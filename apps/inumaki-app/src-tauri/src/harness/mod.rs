//! Harnesses in the app: the `HarnessOps` seam, detection, the daemon view
//! adapters need, and the tray's inputs.

pub mod adapt;
pub mod cards;
pub mod connect;
pub mod naming;
pub mod ops;
pub mod protect;
pub mod reason;
pub mod shell;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, PoisonError};

use hmac::{Hmac, Mac};
use inumaki_client::{ClientKind, HarnessId, RoutePrefix, RouteState};
use sha2::Sha256;

use crate::ctx::Ctx;
use crate::error::CmdError;
use crate::poll::Snapshot;
use crate::tray::{PathTone, Tone, TrayInput};
use cards::HarnessCard;
use ops::{HarnessOps, PathState, ProxyUrls, Scope, SystemView};

/// `claude-code`, `codex`, `hermes`, `openclaw`: the serde names of the
/// client's `HarnessId`, spelled out so no `Debug` output is ever used.
pub fn harness_key(h: HarnessId) -> &'static str {
    match h {
        HarnessId::ClaudeCode => "claude-code",
        HarnessId::Codex => "codex",
        HarnessId::Hermes => "hermes",
        HarnessId::Openclaw => "openclaw",
    }
}

/// How `state.json` and the UI refer to one server entry without its name:
/// HMAC-SHA256 under `<data_dir>/app/state.key`, hex, over the length-prefixed
/// harness id, server name, and scope (`user`, or `local` and the project
/// directory). Claude Code lists one name once per scope, often with
/// different accounts, so the scope is part of the identity; the directory
/// enters the HMAC only. Fails closed (`state_unwritable`) when there is no
/// key: the caller records nothing.
pub fn server_key(
    ctx: &Ctx,
    h: HarnessId,
    server: &str,
    scope: &Scope,
) -> Result<String, CmdError> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(ctx.state_key()?)
        .map_err(|_| CmdError::new("state_unwritable"))?;
    let mut put = |b: &[u8]| {
        m.update(&(b.len() as u64).to_be_bytes());
        m.update(b);
    };
    put(harness_key(h).as_bytes());
    put(server.as_bytes());
    match scope {
        Scope::User => put(b"user"),
        Scope::Local(dir) => {
            put(b"local");
            put(dir.as_bytes());
        }
    }
    Ok(m.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// A detected harness.
pub struct Detected {
    /// Id.
    pub id: HarnessId,
    /// Operations.
    pub ops: Arc<dyn HarnessOps>,
    /// Connected: an active adapter backup (the app's or `inumaki connect`'s).
    pub connected: bool,
    /// The harness's binary, when one was found.
    pub binary: Option<PathBuf>,
    /// `<bin>/inumaki-hook` when the latest card shows the hook installed
    /// (the end-to-end check configures it in its temporary configuration).
    pub hook_command: Option<PathBuf>,
}

/// `<bin>/inumaki-hook` of the running inumaki: the service's `bin_dir`
/// (`GET /v1/service`, as `inumaki connect` uses), else `<data_dir>/bin`.
pub fn hook_binary(ctx: &Ctx, snap: &Snapshot) -> PathBuf {
    snap.service
        .as_ref()
        .map(|s| PathBuf::from(&s.bin_dir))
        .filter(|d| d.is_absolute())
        .unwrap_or_else(|| ctx.paths.bin_dir.clone())
        .join("inumaki-hook")
}

/// `<bin>/inumaki-hook` for Claude Code and Codex (spec §5), from the
/// latest snapshot: the same program status compares against.
pub fn hook_command(ctx: &Ctx, h: HarnessId) -> Option<PathBuf> {
    matches!(h, HarnessId::ClaudeCode | HarnessId::Codex).then(|| {
        let snap = ctx.snapshot.read().unwrap_or_else(PoisonError::into_inner);
        hook_binary(ctx, &snap)
    })
}

/// Every installed or configured harness (cached detection; no process spawns).
pub fn detected(ctx: &Ctx) -> Vec<Detected> {
    ctx.harnesses
        .iter()
        .filter_map(|ops| {
            let install = ops.install()?;
            // The adapter's backup store is the truth (as `inumaki connect`):
            // a backup id left in `state.json` after an outside revert does
            // not count.
            let connected = ops.active_backup().is_some();
            let id = ops.id();
            // From the cached cards (no detection here): a hook removed
            // since the last poll can still be configured in a check's
            // temporary configuration (the check then reports what the run did).
            let hook_installed = ctx
                .cards
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .any(|c| c.id == id && c.hook == ops::HookState::Installed);
            Some(Detected {
                id,
                ops: Arc::clone(ops),
                connected,
                binary: install.binary,
                hook_command: (connected && hook_installed)
                    .then(|| hook_command(ctx, id))
                    .flatten(),
            })
        })
        .collect()
}

/// The proxy route's name as `SystemView::failing_routes` holds it.
pub fn route_name(p: RoutePrefix) -> &'static str {
    match p {
        RoutePrefix::Anthropic => "anthropic",
        RoutePrefix::Openai => "openai",
        RoutePrefix::Codex => "codex",
    }
}

/// A proxy client as a harness id; `None` for clients that are no harness.
pub fn client_harness(c: ClientKind) -> Option<&'static str> {
    match c {
        ClientKind::ClaudeCode => Some("claude-code"),
        ClientKind::Codex => Some("codex"),
        ClientKind::Hermes => Some("hermes"),
        ClientKind::Openclaw => Some("openclaw"),
        ClientKind::Other => None,
    }
}

/// What adapters need to know about the daemon.
pub fn system_view(ctx: &Ctx, snap: &Snapshot) -> SystemView {
    let state = ctx.state();
    let mut v = SystemView {
        service_up: snap.reachable,
        ..SystemView::default()
    };
    if let Some(st) = &snap.status {
        v.gateway_listen = Some(st.gateway.listen.clone());
        v.datasets = st.datasets.iter().map(|d| d.id.clone()).collect();
        v.running_datasets = st
            .gateway
            .datasets
            .iter()
            // At least one running upstream (the adapters' `SystemState`
            // contract, and what `inumaki connect` reports).
            .filter(|d| d.upstreams.iter().any(|u| u.state == "running"))
            .map(|d| d.id.clone())
            .collect();
    }
    if let Some(f) = snap.folders.ok() {
        v.mirror_root = Some(PathBuf::from(&f.mirror_root));
        // Watching folders only (as `inumaki connect`): a paused folder's
        // outbox is no write root, and status does not require it.
        let watching: Vec<_> = f
            .folders
            .iter()
            .filter(|x| x.state == inumaki_client::FolderState::Watching)
            .collect();
        v.folders_watching = watching.len();
        v.outboxes = watching.iter().map(|x| PathBuf::from(&x.outbox)).collect();
    }
    if let Some(p) = snap.proxy.ok() {
        let url = |pre: RoutePrefix| {
            p.routes
                .iter()
                .find(|r| r.prefix == pre)
                .map(|r| r.base_url.clone())
        };
        v.proxy = ProxyUrls {
            anthropic: url(RoutePrefix::Anthropic),
            openai: url(RoutePrefix::Openai),
            codex: url(RoutePrefix::Codex),
        };
        v.failing_routes = p
            .routes
            .iter()
            .filter(|r| r.state == RouteState::Failing)
            .map(|r| route_name(r.prefix).to_string())
            .collect();
        v.proxy_clients = p
            .clients
            .iter()
            .filter_map(|c| client_harness(c.client))
            .map(str::to_string)
            .collect();
        v.codex_chatgpt_verified = p.oauth.codex_chatgpt.verified_in_build;
        v.client_header =
            Some(zeroize::Zeroizing::new(p.client_header.value.clone())).filter(|h| !h.is_empty());
    }
    v.hook_command = Some(hook_binary(ctx, snap));
    // The adapters take names; state.json holds keyed hashes of them. Without
    // the key nothing can have been recorded, so there is nothing to translate.
    let base = v
        .gateway_listen
        .as_ref()
        .map(|l| format!("http://{l}"))
        .unwrap_or_default();
    let mut leave: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    if !state.leave_unprotected.is_empty() && ctx.state_key().is_ok() {
        for o in &ctx.harnesses {
            let h = o.id();
            // The adapters drop a left-alone server from `total` by name,
            // but one name can be several entries (Claude Code: one per
            // scope, often another account). A name is left alone only
            // when every non-gateway entry of that name was chosen by the
            // user; otherwise the card would count an exposed entry as
            // handled.
            let mut all: BTreeMap<String, bool> = BTreeMap::new();
            for s in o.servers(&base).unwrap_or_default() {
                if s.gateway_dataset.is_some() {
                    continue;
                }
                let left = server_key(ctx, h, &s.name, &s.scope)
                    .is_ok_and(|k| state.leave_unprotected.contains(&k));
                *all.entry(s.name).or_insert(true) &= left;
            }
            let names: BTreeSet<String> = all
                .into_iter()
                .filter(|(_, left)| *left)
                .map(|(n, _)| n)
                .collect();
            leave.insert(harness_key(h).into(), names);
        }
    }
    v.leave_unprotected = leave;
    v
}

/// The tray's inputs from `snap` and already computed `cards` (no file reads).
pub fn tray_input_from(snap: &Snapshot, cards: &[HarnessCard]) -> TrayInput {
    let mut paths = Vec::new();
    for c in cards {
        for p in &c.paths {
            let tone = match p.state {
                PathState::NotConnected => Tone::Off,
                PathState::Connected | PathState::Unverified => Tone::Ok,
                PathState::Unsupported => Tone::Unsupported,
                PathState::Broken => Tone::Broken,
            };
            paths.push(PathTone {
                harness: harness_key(c.id),
                path: p.path.as_str(),
                tone,
            });
        }
    }
    let failing_upstream = snap.status.as_ref().is_some_and(|s| {
        s.gateway
            .datasets
            .iter()
            .filter(|d| !d.id.starts_with("check-"))
            .any(|d| d.upstreams.iter().any(|u| u.state.starts_with("failed")))
    });
    let failing_route = snap
        .proxy
        .ok()
        .is_some_and(|p| p.routes.iter().any(|r| r.state == RouteState::Failing));
    TrayInput {
        reachable: snap.reachable,
        paths,
        failing: failing_upstream || failing_route,
        // Only a detected harness has a card, and with it the Reconnect and
        // Revert that clear the mark: an undetected one never keeps it red.
        disconnected: cards.iter().any(|c| c.disconnected),
        config_error: snap.config_error,
    }
}
