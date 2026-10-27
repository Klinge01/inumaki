//! One end-to-end check: create, direct run, harness runs, delete (always).
//!
//! Harness output is synthetic canary text. It is read into memory, sent in
//! `POST /v1/check/{id}/harness`, and wiped; it never reaches the app log,
//! `state.json`, a notification, an error, or a `Debug` print (Review Focus 3).
//!
//! If the app itself is killed (SIGKILL) during a harness run, the
//! harness's process group keeps running until it ends by itself or the
//! harness's own timeout stops it. It can only reach the check's gateway
//! entry and check route, whose token and route die with the check when the
//! daemon's 10-minute TTL removes it (the app's `DELETE` never came); the
//! next app start sweeps the temporary directories.
//!
//! Likewise, a process the harness started that closed its stdout keeps
//! running after the harness itself exits normally (the group is killed only
//! at a timeout: after the leader is reaped its pid may name another group).
//! What it can reach dies with the check's `DELETE` right after the run.

use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use inumaki_adapters::{CheckPlan, Invocation};
use inumaki_client::{
    CheckCreate, CheckCreated, CheckHarnessRequest, CheckReport, ClientError, HarnessId,
};
use tokio::io::AsyncReadExt;
use zeroize::{Zeroize, Zeroizing};

use super::tmp;
use crate::appstate::CheckMemo;
use crate::ctx::Ctx;
use crate::error::CmdError;
use crate::harness::{self, Detected};

/// Harness stdout kept for the daemon's comparison; the rest is drained.
pub const MAX_OUTPUT: usize = 1 << 20;

/// `POST /v1/check`: the daemon seeds a dataset and starts a canary server
/// (up to ~15 s); longer than the default so a slow start is not given up
/// on (a given-up create leaves a live check the app never saw).
const CREATE_TIMEOUT: Duration = Duration::from_secs(60);
/// `POST /v1/check/{id}/direct` holds the daemon's check lock while it
/// probes every path (each waits up to 30 s).
const DIRECT_TIMEOUT: Duration = Duration::from_secs(120);
/// `GET /v1/check/{id}` after a direct run the app gave up on: it waits for
/// the run to finish (the daemon completes it without its caller).
const REPORT_TIMEOUT: Duration = Duration::from_secs(60);
/// Seconds notifications stay quiet after each step and after the run:
/// the slowest poll (window hidden) plus 15 s, so the check's last activity
/// records, which arrive with the first poll after the run, never notify.
pub fn quiet_after() -> i64 {
    secs(crate::poll::cadence(false)).saturating_add(15)
}

fn secs(d: Duration) -> i64 {
    i64::try_from(d.as_secs()).unwrap_or(i64::MAX)
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, secs)
}

/// A check-route error with its own kind where the UI needs to tell them
/// apart; everything else as any daemon error.
///
/// - `409` (`POST /v1/check`): another check is live. When the app gave up
///   on an earlier create, the daemon may hold a check whose id the app
///   never saw; nothing can look it up, so it blocks new checks until its
///   10-minute TTL ends (`check_running`, fixed text with the wait).
/// - `404 "no check report yet"` (`GET /v1/check/{id}`): the check is live
///   but nothing has run (`check_no_report`).
/// - `404 "no such check"`: unknown id, expired, or deleted (`check_expired`).
///
/// The daemon's message is matched against its fixed strings, never passed on.
pub fn check_error(e: ClientError) -> CmdError {
    let message = e.detail().map(|d| d.message.as_str());
    let kind = match (e.status(), message) {
        (Some(409), _) => Some("check_running"),
        (Some(404), Some("no check report yet")) => Some("check_no_report"),
        (Some(404), Some("no such check")) => Some("check_expired"),
        _ => None,
    };
    match kind {
        Some(k) => CmdError {
            status: e.status(),
            ..CmdError::new(k)
        },
        None => CmdError::from(e),
    }
}

fn key(h: Option<HarnessId>) -> &'static str {
    h.map_or("direct", harness::harness_key)
}

/// Store a report's booleans and reason codes in `state.json`.
pub fn remember(ctx: &Ctx, h: Option<HarnessId>, r: &CheckReport) -> Result<(), CmdError> {
    ctx.update_state(|s| {
        s.last_check.insert(
            key(h).to_string(),
            CheckMemo {
                at: now(),
                results: r.results.clone(),
            },
        );
    })
}

/// SIGKILL the process group `pgid` (the harness and everything it
/// started). `/bin/kill` because the crate forbids `unsafe` (no `libc`).
async fn kill_group(pgid: u32) {
    let _ = tokio::process::Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{pgid}")])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
}

/// Write the invocation's files, 0600. A path that is relative or climbs
/// with `..` is refused.
fn write_files(inv: &Invocation) -> Result<(), CmdError> {
    let bad = || CmdError::new("check_tmp_unwritable");
    for (p, content) in &inv.files {
        if !p.is_absolute() || p.components().any(|c| c == Component::ParentDir) {
            return Err(bad());
        }
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(p)
            .map_err(|_| bad())?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| bad())?;
        f.write_all(content.as_bytes()).map_err(|_| bad())?;
    }
    Ok(())
}

/// Run `inv` and collect its stdout: `(output, exit code)`, the code `-1`
/// when it could not start (or waiting failed), `-2` at its timeout, `-3`
/// when it started and was killed by a signal.
async fn collect(inv: &Invocation) -> (Zeroizing<Vec<u8>>, i64) {
    let mut cmd = tokio::process::Command::new(&inv.program);
    cmd.args(&inv.args)
        .current_dir(&inv.cwd)
        // The invocation's environment is the complete allow-list.
        .env_clear()
        .envs(inv.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        // Its own process group, so a timeout kills the harness's children too.
        .process_group(0)
        .kill_on_drop(true);
    // Full capacity up front: growing would leave unwiped copies behind.
    let mut kept = Zeroizing::new(Vec::with_capacity(MAX_OUTPUT));
    let Ok(mut child) = cmd.spawn() else {
        return (kept, -1);
    };
    let pid = child.id();
    let mut out = child.stdout.take();
    let run = async {
        if let Some(o) = out.as_mut() {
            // Keep the first MAX_OUTPUT bytes and drain the rest, so a
            // chatty harness never blocks on a full pipe.
            let mut chunk = Zeroizing::new(vec![0u8; 64 * 1024]);
            loop {
                match o.read(&mut chunk[..]).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let room = MAX_OUTPUT.saturating_sub(kept.len());
                        kept.extend_from_slice(&chunk[..n.min(room)]);
                    }
                }
            }
        }
        match child.wait().await {
            Ok(status) => status.code().map_or(-3, i64::from),
            Err(_) => -1,
        }
    };
    let done = tokio::time::timeout(inv.timeout, run).await;
    match done {
        Ok(code) => (kept, code),
        Err(_) => {
            // The leader is not reaped yet, so its pid still names its group.
            if let Some(pid) = pid {
                kill_group(pid).await;
            }
            let _ = child.start_kill();
            let _ = child.wait().await;
            kept.zeroize();
            (kept, -2)
        }
    }
}

/// How a harness run ended: a closed set that names the cause of a failed
/// run without any content. The code of `exit_nonzero` is a process status,
/// not output (127 means the shell found no interpreter or binary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExitClass {
    /// Exit code 0.
    Ok,
    /// Any other exit code.
    ExitNonzero {
        /// The process status.
        code: i64,
    },
    /// The process could not start.
    CouldNotStart,
    /// The process started and was killed by a signal (an OOM kill, a crash).
    Signaled,
    /// The run hit its timeout and was killed.
    TimedOut,
}

impl ExitClass {
    /// Classify the exit code [`collect`] returns.
    fn of(code: i64) -> ExitClass {
        match code {
            0 => ExitClass::Ok,
            -1 => ExitClass::CouldNotStart,
            -2 => ExitClass::TimedOut,
            -3 => ExitClass::Signaled,
            code => ExitClass::ExitNonzero { code },
        }
    }
}

/// One harness run's outcome, without content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct HarnessRunInfo {
    /// The harness that ran.
    pub harness: HarnessId,
    /// How it ended.
    pub exit: ExitClass,
}

/// Run `inv`, send its stdout to the daemon, return the daemon's verdict and
/// how the run ended. Exit code `-1` (sent to the daemon) when it could not
/// start, `-2` when it hit its timeout, `-3` when a signal killed it.
pub async fn run_invocation(
    ctx: &Ctx,
    check_id: &str,
    h: HarnessId,
    inv: &Invocation,
) -> Result<(CheckReport, ExitClass), CmdError> {
    write_files(inv)?;
    let (buf, exit_code) = collect(inv).await;
    crate::applog::count(
        "check_harness_run",
        "exit_code_nonzero",
        u64::from(exit_code != 0),
    );
    let mut req = CheckHarnessRequest {
        harness: h,
        output: String::from_utf8_lossy(&buf).into_owned(),
        exit_code,
    };
    drop(buf);
    let r = ctx.client.check_harness(check_id, &req).await;
    req.output.zeroize();
    r.map(|r| (r, ExitClass::of(exit_code)))
        .map_err(check_error)
}

async fn create(ctx: &Ctx) -> Result<CheckCreated, CmdError> {
    ctx.client
        .clone()
        .with_timeout(CREATE_TIMEOUT)
        .create_check(&CheckCreate::default())
        .await
        .map_err(|e| match e {
            // The daemon may have prepared it anyway: a check whose id the
            // app never saw, live until its TTL ends.
            ClientError::Timeout => CmdError::new("check_start_lost"),
            e => check_error(e),
        })
}

async fn direct(ctx: &Ctx, id: &str) -> Result<CheckReport, CmdError> {
    match ctx
        .client
        .clone()
        .with_timeout(DIRECT_TIMEOUT)
        .check_direct(id)
        .await
    {
        Ok(r) => Ok(r),
        // The daemon completes a run whose caller left and keeps its
        // report; the read waits for the run to release the check.
        Err(ClientError::Timeout) => ctx
            .client
            .clone()
            .with_timeout(REPORT_TIMEOUT)
            .check_report(id)
            .await
            .map_err(check_error),
        Err(e) => Err(check_error(e)),
    }
}

/// Shown when the proxy's status cannot be read, or its address and the
/// check's routes do not agree: fixed text, nothing of the address.
const ROUTES_UNTRUSTED: &str =
    "the proxy address could not be confirmed; the harness chat check is skipped";

/// Whether `base_url` is `http://<listen>/...` and `listen` is a loopback
/// socket address (an IP literal with a port; `localhost` is not accepted,
/// since a harness resolves it by itself). The comparison is on the whole
/// authority, so userinfo (`127.0.0.1:8787@host`), another port, another
/// host, and another scheme all differ.
fn is_listen_url(base_url: &str, listen: &str) -> bool {
    let loopback = listen
        .parse::<std::net::SocketAddr>()
        .is_ok_and(|a| a.ip().is_loopback());
    let Some(rest) = base_url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    loopback && authority == listen
}

/// Ask the daemon whether the check's proxy URLs may be handed to a
/// harness: the proxy is running, and every route is on its own loopback
/// listen address. A proxy that is not listening leaves the address to
/// whatever holds it, which would receive the conversation and the
/// harness's credentials. `Err` is the fixed warning.
async fn trust_routes(ctx: &Ctx, proxy: &inumaki_client::CheckProxy) -> Result<(), &'static str> {
    let Ok(status) = ctx.client.proxy().await else {
        return Err(ROUTES_UNTRUSTED);
    };
    if let Some(why) = status.state.check_route_skipped() {
        return Err(why);
    }
    if proxy
        .routes
        .iter()
        .all(|r| is_listen_url(&r.base_url, &status.listen))
    {
        Ok(())
    } else {
        Err(ROUTES_UNTRUSTED)
    }
}

/// What one check produced: the reports, and a fixed warning when the
/// harness runs were skipped.
#[derive(Debug, serde::Serialize)]
pub struct CheckRun {
    /// The direct run's report, then one per harness that ran.
    pub reports: Vec<CheckReport>,
    /// How each harness run ended, in run order (no output, URL or path).
    pub runs: Vec<HarnessRunInfo>,
    /// Fixed text only: never a URL, port, id, or process name.
    pub warning: Option<&'static str>,
}

async fn run_created(
    ctx: &Ctx,
    created: &CheckCreated,
    harnesses: Vec<Detected>,
) -> Result<CheckRun, CmdError> {
    ctx.set_quiet_for(secs(DIRECT_TIMEOUT + REPORT_TIMEOUT).saturating_add(quiet_after()));
    let direct = direct(ctx, &created.id).await?;
    remember(ctx, None, &direct)?;
    let mut reports = vec![direct];
    let mut runs = Vec::new();
    let (Some(gw), Some(proxy)) = (&created.gateway, &created.proxy) else {
        // Without the proxy nothing can play the model: direct checks only (spec §8.2).
        return Ok(CheckRun {
            reports,
            runs,
            warning: None,
        });
    };
    let path_env = ctx
        .login_path()
        .await
        .unwrap_or_else(|| "/usr/bin:/bin".into());
    for d in harnesses.into_iter().filter(|d| d.connected) {
        // Before every run, not once per check: a harness run takes minutes,
        // and the proxy may have stopped listening since the last one. A
        // refusal ends the check here; the runs already made keep their reports.
        if let Err(warning) = trust_routes(ctx, proxy).await {
            return Ok(CheckRun {
                reports,
                runs,
                warning: Some(warning),
            });
        }
        let dirs = tmp::create(&ctx.paths, &created.id, harness::harness_key(d.id))?;
        let plan = CheckPlan {
            workdir: dirs.work.clone(),
            config_dir: dirs.config.clone(),
            gateway_url: gw.url.clone(),
            gateway_token: Zeroizing::new(gw.token.expose().to_string()),
            server: gw.server.clone(),
            mirror_file: created.mirror.as_ref().map(|m| PathBuf::from(&m.path)),
            // The daemon's own temporary directory; anything without its
            // shape is dropped, never handed to a harness (§9.7 amendment
            // 2026-10-10).
            source_dir: created
                .mirror
                .as_ref()
                .and_then(|m| m.source_dir.as_deref())
                .map(PathBuf::from)
                .filter(|d| inumaki_adapters::check::source_dir_ok(d)),
            routes: proxy
                .routes
                .iter()
                .map(|r| (r.upstream.clone(), r.base_url.clone()))
                .collect(),
            path_env: inumaki_adapters::detect::with_binary_dir(&path_env, d.binary.as_deref()),
            hook_command: d.hook_command.clone(),
            socket: ctx.paths.socket.clone(),
        };
        let Some(inv) = d.ops.check_invocation(&plan) else {
            continue;
        };
        // The adapter writes only into the run's configuration directory.
        if inv.files.iter().any(|(p, _)| !p.starts_with(&dirs.config)) {
            return Err(CmdError::new("check_tmp_unwritable"));
        }
        ctx.set_quiet_for(secs(inv.timeout).saturating_add(quiet_after()));
        let (r, exit) = run_invocation(ctx, &created.id, d.id, &inv).await?;
        remember(ctx, Some(d.id), &r)?;
        reports.push(r);
        runs.push(HarnessRunInfo {
            harness: d.id,
            exit,
        });
        drop(dirs);
    }
    Ok(CheckRun {
        reports,
        runs,
        warning: None,
    })
}

/// Run the check with `harnesses`; the check is deleted whatever happens.
/// Notifications stay quiet for each step's longest duration and for
/// [`quiet_after`] seconds after the run (its activity records belong to the
/// check), and no longer.
pub async fn run_with(ctx: &Ctx, harnesses: Vec<Detected>) -> Result<CheckRun, CmdError> {
    let Ok(_running) = ctx.check_lock.try_lock() else {
        return Err(CmdError::new("check_in_progress"));
    };
    let r = run_locked(ctx, harnesses).await;
    ctx.set_quiet_for(quiet_after());
    r
}

async fn run_locked(ctx: &Ctx, harnesses: Vec<Detected>) -> Result<CheckRun, CmdError> {
    ctx.set_quiet_for(secs(CREATE_TIMEOUT).saturating_add(quiet_after()));
    let created = create(ctx).await?;
    let r = run_created(ctx, &created, harnesses).await;
    if ctx.client.delete_check(&created.id).await.is_err() {
        // The daemon's TTL removes it.
        crate::applog::event("check_delete_failed");
    }
    r
}

/// Run the check with every connected harness.
pub async fn run_check(ctx: &Ctx) -> Result<CheckRun, CmdError> {
    let found = harness::detected(ctx);
    run_with(ctx, found).await
}
