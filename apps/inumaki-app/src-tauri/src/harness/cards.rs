//! Overview cards (spec §6.4): per harness, the three path states with
//! reasons and counts, the hook state, acknowledgement, and the last check
//! result. Names of servers, datasets, or paths never enter a card.

use inumaki_client::{HarnessId, PathStatus};
use serde::Serialize;

use super::ops::{Detail, HookState, Login, PathKind, PathState, Reason};
use super::{detected, harness_key, system_view};
use crate::ctx::Ctx;
use crate::poll::Snapshot;

/// One path on a card.
#[derive(Debug, Clone, Serialize)]
pub struct PathView {
    /// Path.
    pub path: PathKind,
    /// State.
    pub state: PathState,
    /// Reason code and sentence.
    pub reason: Option<Reason>,
    /// Counts.
    pub detail: Option<Detail>,
    /// A red-by-design path the user acknowledged.
    pub acknowledged: bool,
    /// Last end-to-end check result of this path for this harness.
    pub last_check: Option<PathStatus>,
}

/// One harness card (product name, version, states: no user data).
#[derive(Debug, Clone, Serialize)]
pub struct HarnessCard {
    /// Id.
    pub id: HarnessId,
    /// Display name.
    pub name: &'static str,
    /// Binary found.
    pub binary_found: bool,
    /// Version.
    pub version: Option<String>,
    /// Within the tested range.
    pub tested: bool,
    /// Login kind.
    pub login: Login,
    /// Connected.
    pub connected: bool,
    /// A Reconnect failed after its revert: disconnected (spec §4.2, review C2).
    pub disconnected: bool,
    /// MCP, Files, Chat.
    pub paths: Vec<PathView>,
    /// Hook (a pending hook carries its fixed reason code).
    pub hook: HookState,
    /// Drift items.
    pub drift: usize,
    /// `ops::GRANT_NEEDED` when a configuration file of this harness exists
    /// but reading it is denied (macOS withdrew the app's access, e.g. after
    /// an ad-hoc-signed upgrade); the UI renders it when present.
    pub grant: Option<Reason>,
    /// Unix seconds of this harness's last end-to-end check (the memo's
    /// `at`); `None` without a memo. The UI decides whether it still counts
    /// (connected, not disconnected).
    pub last_check_at: Option<i64>,
}

/// Cards for every detected harness. Reads harness files: blocking.
pub fn cards(ctx: &Ctx, snap: &Snapshot) -> Vec<HarnessCard> {
    let sys = system_view(ctx, snap);
    let state = ctx.state();
    detected(ctx)
        .into_iter()
        .filter_map(|d| {
            let inst = d.ops.install()?;
            let st = d.ops.status(&sys);
            let key = harness_key(d.id);
            // Cleared only by a Connect or Revert that succeeds: a failed
            // apply can leave an active backup of the files it wrote (a
            // half-written harness), so an active backup proves nothing.
            let disconnected = state.reconnect_failed.contains(key);
            let memo = state.last_check.get(key);
            let paths = st
                .paths
                .into_iter()
                .map(|p| PathView {
                    acknowledged: p.state == PathState::Unsupported
                        && state
                            .acknowledged
                            .contains(&format!("{key}/{}", p.path.as_str())),
                    last_check: memo.map(|m| match p.path {
                        PathKind::Mcp => m.results.gateway.status,
                        PathKind::Files => m.results.mirror.status,
                        PathKind::Chat => m.results.proxy.status,
                    }),
                    path: p.path,
                    state: p.state,
                    reason: p.reason,
                    detail: p.detail,
                })
                .collect();
            Some(HarnessCard {
                id: d.id,
                name: d.ops.name(),
                binary_found: inst.binary.is_some(),
                version: inst.version,
                tested: inst.tested,
                login: inst.login,
                connected: d.connected,
                disconnected,
                paths,
                hook: st.hook,
                drift: st.drift,
                grant: st.grant.then_some(super::ops::GRANT_NEEDED),
                last_check_at: memo.map(|m| m.at),
            })
        })
        .collect()
}
