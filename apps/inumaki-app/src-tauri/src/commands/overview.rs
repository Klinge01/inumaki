//! Overview (spec §6.4): cards, acknowledgement, refresh. Card computation
//! reads harness files, so it runs on a blocking thread.

use std::sync::{Arc, PoisonError};

use inumaki_client::{HarnessId, ManagedBy};
use serde::Serialize;

use crate::appstate::{LastCheck, last_check_summary};
use crate::ctx::Ctx;
use crate::error::CmdError;
use crate::harness::cards::{HarnessCard, cards};
use crate::harness::ops::{ManualSetupView, PathKind, PathState};
use crate::harness::{harness_key, system_view};

/// The Overview view.
#[derive(Debug, Serialize)]
pub struct OverviewView {
    /// The service answers.
    pub reachable: bool,
    /// Who manages the service.
    pub managed_by: Option<ManagedBy>,
    /// The config file that names the socket cannot be read (a fixed sentence
    /// naming the file, never its content); the app does not talk to a daemon.
    pub config_error: Option<String>,
    /// Harness cards.
    pub cards: Vec<HarnessCard>,
    /// The newest check across harnesses and whether any failed.
    pub last_check: Option<LastCheck>,
}

async fn compute(ctx: &Arc<Ctx>) -> Result<Vec<HarnessCard>, CmdError> {
    let c = Arc::clone(ctx);
    tokio::task::spawn_blocking(move || {
        let snap = c
            .snapshot
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let v = cards(&c, &snap);
        *c.cards.write().unwrap_or_else(PoisonError::into_inner) = v.clone();
        v
    })
    .await
    .map_err(|_| CmdError::new("internal"))
}

/// The latest Overview (polls once when nothing was polled yet).
pub async fn overview(ctx: &Arc<Ctx>) -> Result<OverviewView, CmdError> {
    let mut snap = ctx
        .snapshot
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    if snap.at == 0 {
        snap = crate::poll::tick(ctx).await;
    }
    Ok(OverviewView {
        reachable: snap.reachable,
        managed_by: snap.service.as_ref().map(|s| s.managed_by),
        config_error: ctx.paths.config_error.clone(),
        cards: compute(ctx).await?,
        last_check: last_check_summary(&ctx.state()),
    })
}

/// Detect the harnesses again, poll, and answer the Overview.
pub async fn refresh(ctx: &Arc<Ctx>) -> Result<OverviewView, CmdError> {
    let c = Arc::clone(ctx);
    let _ = tokio::task::spawn_blocking(move || c.harnesses.iter().for_each(|o| o.refresh())).await;
    crate::harness::connect::migrate_pre_m9_chat(ctx, true);
    crate::poll::tick(ctx).await;
    overview(ctx).await
}

/// Acknowledge a red-by-design (`Unsupported`) path: the card greys it out.
/// The tray never reads this; it ignores `Unsupported` paths acknowledged or
/// not (spec §6.2 amendment 2026-10-12).
pub async fn acknowledge(
    ctx: &Arc<Ctx>,
    harness: HarnessId,
    path: PathKind,
) -> Result<(), CmdError> {
    let v = overview(ctx).await?;
    let unsupported = v
        .cards
        .iter()
        .filter(|c| c.id == harness)
        .flat_map(|c| c.paths.iter())
        .any(|p| p.path == path && p.state == PathState::Unsupported);
    if !unsupported {
        return Err(CmdError::new("not_acknowledgeable"));
    }
    ctx.update_state(|s| {
        s.acknowledged
            .insert(format!("{}/{}", harness_key(harness), path.as_str()));
    })
}

/// The lines to add by hand for a harness whose path needs them ("Show the
/// lines to add"), or `None`. On demand and never part of a card: the lines
/// hold a home-directory path or a local URL. The result is shown to the
/// local user only; the IPC wrapper logs the command name, never this.
pub async fn manual_setup(
    ctx: &Arc<Ctx>,
    harness: HarnessId,
) -> Result<Option<ManualSetupView>, CmdError> {
    let c = Arc::clone(ctx);
    tokio::task::spawn_blocking(move || {
        let snap = c
            .snapshot
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let sys = system_view(&c, &snap);
        c.harnesses
            .iter()
            .find(|o| o.id() == harness)
            .and_then(|o| o.manual_setup(&sys))
    })
    .await
    .map_err(|_| CmdError::new("internal"))
}
