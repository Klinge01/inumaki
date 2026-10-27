//! The poller (M6 spec §6.1): every 5 s while the window is visible and
//! every 30 s otherwise, fetch status, service, proxy, folders, and tokens,
//! read new activity records for notifications, recolor the tray, and tell
//! the UI to refresh (the event carries no payload). A tick makes control-API
//! calls only; it spawns no process.

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use inumaki_client::{
    ActivityQuery, ClientError, FoldersBody, ProxyBody, ServiceBody, StatusBody, TokenBody,
};
use serde::Serialize;
use tauri::{AppHandle, Emitter};

use crate::ctx::Ctx;
use crate::error::CmdError;

/// A route that may not be served yet.
#[derive(Clone, Default, Serialize)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
pub enum Avail<T> {
    /// Not fetched yet.
    #[default]
    Unknown,
    /// Served.
    Ok(T),
    /// `404 no such route`: the lane has not merged.
    NotAvailable,
    /// Another error, by kind.
    Error(&'static str),
}

impl<T> Avail<T> {
    /// The value, if served.
    pub fn ok(&self) -> Option<&T> {
        match self {
            Avail::Ok(v) => Some(v),
            _ => None,
        }
    }
}

/// Map a client result.
pub fn avail<T>(r: Result<T, ClientError>) -> Avail<T> {
    match r {
        Ok(v) => Avail::Ok(v),
        Err(e) => match CmdError::from(e) {
            e if e.kind == "not_available" => Avail::NotAvailable,
            e => Avail::Error(e.kind),
        },
    }
}

/// What the app knows about the daemon.
#[derive(Clone, Default)]
pub struct Snapshot {
    /// `GET /v1/status` answered.
    pub reachable: bool,
    /// Status.
    pub status: Option<StatusBody>,
    /// Service (M6-3's endpoint; `None` before it exists).
    pub service: Option<ServiceBody>,
    /// Proxy (M8).
    pub proxy: Avail<ProxyBody>,
    /// Folders (M5).
    pub folders: Avail<FoldersBody>,
    /// Gateway tokens.
    pub tokens: Vec<TokenBody>,
    /// The config file that names the socket cannot be read (`AppPaths::config_error`).
    pub config_error: bool,
    /// Unix seconds of the fetch.
    pub at: i64,
}

/// Unix seconds now.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Poll period.
pub fn cadence(visible: bool) -> Duration {
    if visible {
        Duration::from_secs(5)
    } else {
        Duration::from_secs(30)
    }
}

/// Fetch everything once.
pub async fn fetch(ctx: &Ctx) -> Snapshot {
    // An unreadable config file means the socket is unknown: report the
    // service as unreachable rather than guess the default.
    if ctx.paths.config_error.is_some() {
        return Snapshot {
            config_error: true,
            at: now(),
            ..Snapshot::default()
        };
    }
    let c = &ctx.client;
    let status = c.status().await.ok();
    if status.is_none() {
        return Snapshot {
            at: now(),
            ..Snapshot::default()
        };
    }
    let (service, proxy, folders, tokens) =
        tokio::join!(c.service(), c.proxy(), c.folders(), c.tokens());
    Snapshot {
        reachable: true,
        config_error: false,
        status,
        service: service.ok(),
        proxy: avail(proxy),
        folders: avail(folders),
        tokens: tokens.unwrap_or_default(),
        at: now(),
    }
}

/// Records per activity page.
pub const PAGE: u64 = 200;
/// Notification when a page was full (fixed text, spec §6.5).
pub const MORE: &str =
    "More items were blocked than can be shown here; open inumaki for all of them.";

/// Where notifications left off: the newest second seen, and the ids seen in
/// that second (a record can arrive later with the same second).
#[derive(Debug, Default)]
pub struct Cursor {
    /// Unix seconds.
    pub at: i64,
    /// Record ids already notified at `at`.
    pub seen: BTreeSet<String>,
}

/// One tick: fetch, store, notify new records.
pub async fn tick(ctx: &Ctx) -> Snapshot {
    let snap = fetch(ctx).await;
    if snap.reachable {
        let since = ctx
            .activity
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .at;
        let q = ActivityQuery {
            dataset: None,
            since: Some(since),
            limit: Some(PAGE),
        };
        if let Ok(list) = ctx.client.activity(&q).await {
            let full = list.records.len() as u64 >= PAGE;
            let fresh: Vec<_>;
            // Records older than a full page's oldest one were not returned.
            let more_beyond;
            {
                let mut c = ctx.activity.lock().unwrap_or_else(PoisonError::into_inner);
                more_beyond = full
                    && list
                        .records
                        .last()
                        .is_some_and(|r| r.at > c.at || (r.at == c.at && !c.seen.contains(&r.id)));
                fresh = list
                    .records
                    .into_iter()
                    .filter(|r| r.at > c.at || (r.at == c.at && !c.seen.contains(&r.id)))
                    .collect();
                if let Some(max) = fresh.iter().map(|r| r.at).max() {
                    if max > c.at {
                        c.at = max;
                        c.seen.clear();
                    }
                    c.seen
                        .extend(fresh.iter().filter(|r| r.at == max).map(|r| r.id.clone()));
                }
            }
            // The cursor has advanced either way; a quiet window (a check
            // running or just ended) only skips the notifications.
            if now() >= ctx.quiet_until.load(Ordering::Relaxed) {
                for body in crate::notify::render(&fresh) {
                    ctx.notifier.notify(&body);
                }
                // Newest first: when the page's oldest record is itself new,
                // older records of the burst were not returned. A full page
                // of records already seen says nothing new.
                if more_beyond {
                    ctx.notifier.notify(MORE);
                }
            }
        } else {
            crate::applog::event("activity_poll_failed");
        }
    }
    *ctx.snapshot.write().unwrap_or_else(PoisonError::into_inner) = snap.clone();
    snap
}

/// Run the poller for the app's lifetime.
pub fn spawn(app: AppHandle, ctx: Arc<Ctx>) {
    tauri::async_runtime::spawn(async move {
        let mut last = None;
        let mut last_menu: Option<crate::tray::MenuModel> = None;
        // Detection spawns processes (`--version`, the login shell): it runs
        // at start and when the window is shown, never on an ordinary tick.
        let mut detect = true;
        loop {
            tick(&ctx).await;
            // Harness status reads configuration files: off the async threads.
            let c = Arc::clone(&ctx);
            let redetect = detect;
            let done = tauri::async_runtime::spawn_blocking(move || {
                if redetect {
                    c.harnesses.iter().for_each(|o| o.refresh());
                    crate::harness::connect::migrate_pre_m9_chat(&c, true);
                }
                let snap = c
                    .snapshot
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                let cards = crate::harness::cards::cards(&c, &snap);
                *c.cards.write().unwrap_or_else(PoisonError::into_inner) = cards.clone();
                (crate::harness::tray_input_from(&snap, &cards), cards)
            })
            .await;
            if let Ok((input, cards)) = done {
                // Detection ran: do not repeat it until the next wake.
                detect = false;
                // The appearance is read every tick, so the glyph follows a
                // dark-mode switch within one poll interval.
                let st = ctx.state();
                let look = (
                    crate::tray::color(&input, &st),
                    crate::tray::dark(&app),
                    input.config_error,
                    crate::tray::hook_blocks(&cards),
                    crate::tray::any_connected(&cards),
                );
                if last != Some(look) {
                    crate::tray::set(&app, look.0, look.1, look.2, look.3, look.4);
                    last = Some(look);
                }
                let model = crate::tray::MenuModel::new(
                    look.0,
                    &input,
                    &cards,
                    crate::appstate::last_check_summary(&st),
                    now(),
                    &chrono::Local,
                );
                if last_menu.as_ref() != Some(&model) && crate::tray::set_menu(&app, &model) {
                    last_menu = Some(model);
                }
            }
            let _ = app.emit("snapshot", ());
            // Showing the window wakes the poller so it never shows a stale
            // snapshot, and re-detects the harnesses.
            tokio::select! {
                () = tokio::time::sleep(cadence(ctx.visible.load(Ordering::Relaxed))) => {}
                () = ctx.wake.notified() => { detect = true; }
            }
        }
    });
}
