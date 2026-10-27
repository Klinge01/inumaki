//! Prepare, run, and remove one check (M6 spec §8). Everything created here
//! carries the reserved `check-` dataset prefix or `check:` token label.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use inumaki_core::span::EntityKind;
use inumaki_core::token::TokenStore;
use inumaki_vault::{DatasetSpec, UpstreamSpec};

use super::canary::Canary;
use super::mirror::MirrorSetup;
use super::types::*;
use super::verdict::{Evidence, not_checked, verdict};
use crate::api::ApiError;
use crate::service::{BlockInput, RehydrateMode, rehydrate_blocks};
use crate::state::AppState;

/// The canary upstream's name inside the check dataset.
const UPSTREAM: &str = "canary";
/// Its field contract: every result field is free text.
const POLICY: &str = r#"{"version":1,"tools":{"lookup_record":{"result":{"/name":"free_text","/iban":"free_text","/email":"free_text"}}}}"#;

/// The live check. No `Debug` beyond ids: it holds the canary and a token.
pub struct LiveCheck {
    /// 32 hex.
    pub id: String,
    /// `check-<first 12 hex of id>`.
    pub dataset: String,
    /// Datasets to delete on removal (the check dataset first).
    pub datasets: Vec<String>,
    /// The identity.
    pub canary: Canary,
    /// Gateway token row id.
    pub token_id: Option<i64>,
    /// Unix seconds.
    pub expires_at: i64,
    /// Monotonic deadline.
    pub deadline: Instant,
    /// `<data_dir>/check/<id>/`.
    pub dir: PathBuf,
    /// Gateway entry handed to the app.
    pub gateway: Option<GatewayEntry>,
    /// Mirror setup (Task 4).
    pub mirror: Option<MirrorSetup>,
    /// Proxy routes (Task 4): (upstream, base URL).
    pub proxy: Option<Vec<(String, String)>>,
    /// The direct run's route: (route id, (upstream, base URL) per route).
    pub proxy_direct: Option<(String, Vec<(String, String)>)>,
    /// Paths requested.
    pub requested: Vec<CheckPath>,
    /// Availability.
    pub paths: CheckPaths,
    /// Latest report.
    pub latest: Option<CheckReport>,
    /// Requests of the harness route already judged: each harness POST is
    /// judged only on the bodies recorded after the previous one (review C3).
    pub recorded_seen: usize,
    /// The same for the proxy direct run's route.
    pub direct_seen: usize,
    /// The harness route once returned fewer bodies than were judged:
    /// bodies were lost uncounted, so every later harness run fails closed.
    pub recorded_lost: bool,
    /// The same for the proxy direct run's route.
    pub direct_lost: bool,
}

impl std::fmt::Debug for LiveCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveCheck")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// 128 random bits as 32 lowercase hex, or `None` when the system RNG
/// fails: the id is the check route's protection (spec §9.6, §10), so a
/// predictable fallback is never used.
pub(crate) fn random_id() -> Option<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).ok()?;
    Some(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// A check id is 32 lowercase hex.
pub fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

fn conflict() -> ApiError {
    ApiError::new(
        axum::http::StatusCode::CONFLICT,
        "conflict",
        "a check is running",
    )
}

fn no_such_check() -> ApiError {
    ApiError::not_found("no such check")
}

/// `POST /v1/check`.
pub async fn prepare(state: &Arc<AppState>, body: CheckCreate) -> Result<CheckCreated, ApiError> {
    let slot = &state.check;
    let mut guard = slot.live.try_lock().map_err(|_| conflict())?;
    if let Some(live) = guard.as_ref() {
        if live.deadline > Instant::now() {
            return Err(conflict());
        }
        let old = guard.take();
        if let Some(old) = old {
            remove_live(state, old).await;
        }
    }
    let requested = body
        .paths
        .unwrap_or_else(|| vec![CheckPath::Gateway, CheckPath::Mirror, CheckPath::Proxy]);
    let id = random_id().ok_or_else(|| ApiError::internal("check id unavailable"))?;
    let dataset = super::check_dataset_id(&id);
    let canary = slot.take_next_canary().unwrap_or_else(Canary::generate);
    let ttl = slot.ttl();
    let dir = state.data_dir.join("check").join(&id);
    let mut live = LiveCheck {
        id: id.clone(),
        dataset: dataset.clone(),
        datasets: vec![dataset.clone()],
        canary,
        token_id: None,
        expires_at: now() + ttl.as_secs() as i64,
        deadline: Instant::now() + ttl,
        dir,
        gateway: None,
        mirror: None,
        proxy: None,
        proxy_direct: None,
        requested: requested.clone(),
        paths: CheckPaths {
            gateway: PathAvail::yes(),
            mirror: PathAvail::no(AvailReason::MirrorUnavailable),
            proxy: PathAvail::no(AvailReason::ProxyUnavailable),
        },
        latest: None,
        recorded_seen: 0,
        direct_seen: 0,
        recorded_lost: false,
        direct_lost: false,
    };
    if let Err(e) = prepare_base(state, &mut live).await {
        remove_live(state, live).await;
        return Err(e);
    }
    if requested.contains(&CheckPath::Gateway) {
        if let Err(e) = prepare_gateway(state, &mut live).await {
            remove_live(state, live).await;
            return Err(e);
        }
    }
    if requested.contains(&CheckPath::Mirror) {
        super::mirror::prepare(state, &mut live).await;
    }
    if requested.contains(&CheckPath::Proxy) {
        super::proxy::prepare(state, &mut live);
    }
    let created = CheckCreated {
        id: live.id.clone(),
        expires_at: live.expires_at,
        gateway: live.gateway.clone(),
        mirror: super::mirror::entry(&live),
        proxy: live.proxy.as_ref().map(|routes| ProxyEntry {
            routes: routes
                .iter()
                .map(|(u, b)| ProxyRouteEntry {
                    upstream: u.clone(),
                    base_url: b.clone(),
                })
                .collect(),
        }),
        paths: live.paths.clone(),
    };
    tracing::info!("check prepared");
    *guard = Some(live);
    Ok(created)
}

// Vault errors in prepare map to fixed 500s: `From<VaultError>` would put
// `Display` text (an I/O error prints a data-dir path) in the body, and its
// `DatasetExists` 409 is the contract's "a check is live".

/// The check dataset, its directory, and the canary as known entities, so
/// detection of the canary never depends on a detector (spec §8.1).
async fn prepare_base(state: &Arc<AppState>, live: &mut LiveCheck) -> Result<(), ApiError> {
    let s = Arc::clone(state);
    let (dataset, dir, canary) = (live.dataset.clone(), live.dir.clone(), live.canary.clone());
    crate::api::blocking(move || {
        std::fs::create_dir_all(&dir).map_err(|_| ApiError::internal("check directory"))?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| ApiError::internal("check directory"))?;
        s.vault
            .create_dataset(&DatasetSpec::new(&dataset, "check", "offline"))
            .map_err(|_| ApiError::internal("check dataset"))?;
        seed(&s, &dataset, &canary)
    })
    .await
}

/// Teach `dataset` the canary's name and email as known entities.
pub(crate) fn seed(state: &AppState, dataset: &str, canary: &Canary) -> Result<(), ApiError> {
    let failed = || ApiError::internal("check seeding failed");
    let ns = state.namespace(dataset).map_err(|_| failed())?;
    let mut g = ns.lock().unwrap_or_else(PoisonError::into_inner);
    g.token_for(&EntityKind::Person, &canary.full_name())
        .map_err(|_| failed())?;
    g.token_for(&EntityKind::Email, &canary.email)
        .map_err(|_| failed())?;
    g.token_for(&EntityKind::Iban, &canary.iban)
        .map_err(|_| failed())?;
    g.rebuild_detector_now().map_err(|_| failed())?;
    Ok(())
}

async fn prepare_gateway(state: &Arc<AppState>, live: &mut LiveCheck) -> Result<(), ApiError> {
    let fixture = live.dir.join("canary.json");
    let (program, prefix) = state.check.canary_program();
    let s = Arc::clone(state);
    let (dataset, canary, id) = (live.dataset.clone(), live.canary.clone(), live.id.clone());
    let (token_id, token) = crate::api::blocking(move || {
        let bytes = serde_json::to_vec(&canary).map_err(|_| ApiError::internal("check fixture"))?;
        std::fs::write(&fixture, bytes).map_err(|_| ApiError::internal("check fixture"))?;
        std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| ApiError::internal("check fixture"))?;
        let mut spec = UpstreamSpec::stdio(UPSTREAM, &program.display().to_string());
        spec.args = prefix
            .into_iter()
            .chain(["--fixture".to_string(), fixture.display().to_string()])
            .collect();
        spec.content_policy = POLICY.to_string();
        s.vault
            .add_upstream(&dataset, &spec)
            .map_err(|_| ApiError::internal("check dataset"))?;
        let (t, secret) = s
            .vault
            .create_gateway_token(&super::check_token_label(&id))
            .map_err(|_| ApiError::internal("check token"))?;
        Ok((t.id, secret))
    })
    .await?;
    live.token_id = Some(token_id);
    state.gateway_reload(&live.dataset).await;
    wait_for_canary_upstream(state, &live.dataset).await?;
    let listen = state
        .gateway_listen
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .map(|a| a.to_string())
        .unwrap_or_default();
    live.gateway = Some(GatewayEntry {
        url: format!("http://{listen}/mcp/{}", live.dataset),
        // The one place the token leaves the vault's `Zeroizing` wrapper: the answer to the local user.
        token: token.as_str().to_string(),
        server: format!("inumaki-check-{}", &live.id[..6]),
    });
    Ok(())
}

/// Wait (15 s at most) until the canary upstream runs with a discovered
/// schema; accept the schema when the contract reports `drift`.
async fn wait_for_canary_upstream(state: &Arc<AppState>, dataset: &str) -> Result<(), ApiError> {
    let Some(g) = state.gateway.get().cloned() else {
        return Err(ApiError::internal("gateway not running"));
    };
    let until = Instant::now() + Duration::from_secs(15);
    while Instant::now() < until {
        let st = g.status(String::new(), 0).await;
        if let Some(u) = st
            .datasets
            .iter()
            .find(|d| d.id == dataset)
            .and_then(|d| d.upstreams.iter().find(|u| u.name == UPSTREAM))
        {
            if u.state == "running" && u.contract == "ready" && u.schema_fingerprint.is_some() {
                return Ok(());
            }
            if u.state == "running" && u.contract == "drift" {
                let (s, ds, fp) = (
                    Arc::clone(state),
                    dataset.to_string(),
                    u.schema_fingerprint.clone(),
                );
                crate::api::blocking(move || {
                    Ok(s.vault
                        .set_upstream_fingerprint(&ds, UPSTREAM, fp.as_deref())?)
                })
                .await?;
                state.gateway_reload(dataset).await;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(ApiError::internal(
        "the check's canary server did not start",
    ))
}

/// Run `f` on the live check `id`, or `404` when there is none (or it expired).
async fn with_live<T>(
    state: &Arc<AppState>,
    id: &str,
    f: impl AsyncFnOnce(&mut LiveCheck) -> T,
) -> Result<T, ApiError> {
    if !valid_id(id) {
        return Err(no_such_check());
    }
    let mut guard = state.check.live.lock().await;
    let expired = guard.as_ref().is_some_and(|l| l.deadline <= Instant::now());
    if expired {
        if let Some(old) = guard.take() {
            remove_live(state, old).await;
        }
    }
    match guard.as_mut() {
        Some(live) if live.id == id => Ok(f(live).await),
        _ => Err(no_such_check()),
    }
}

/// Restore tokens in `text` with the check dataset; `None` on a store error.
pub(crate) async fn rehydrate(
    state: &Arc<AppState>,
    dataset: &str,
    text: String,
) -> Option<String> {
    let (s, ds) = (Arc::clone(state), dataset.to_string());
    crate::api::blocking(move || {
        rehydrate_blocks(
            &s,
            &ds,
            vec![BlockInput::text(text)],
            RehydrateMode::Permissive,
        )
        .map_err(|_| ApiError::internal("rehydrate"))
    })
    .await
    .ok()
    .and_then(|mut v| v.pop())
    .map(|r| r.text)
}

async fn gateway_direct(state: &Arc<AppState>, live: &LiveCheck) -> PathResult {
    let Some(entry) = &live.gateway else {
        return not_checked(None);
    };
    let probe = state.check.probe();
    let started = Instant::now();
    let Some(result) = probe.lookup(entry.url.clone(), entry.token.clone()).await else {
        let timed_out = started.elapsed() >= super::gateway_probe::PROBE_TIMEOUT;
        return verdict(&Evidence {
            upstream_requests: 1,
            timed_out,
            ..Evidence::default()
        });
    };
    // A store error restores nothing: it shows no tokens (never "tokens
    // seen but not restored" from comparing against an empty text).
    let restored = rehydrate(state, &live.dataset, result.clone()).await;
    verdict(&Evidence {
        upstream_requests: 1,
        canary_in_upstream: live.canary.appears_in(&result),
        tokens_seen: restored.as_ref().is_some_and(|r| *r != result),
        rehydrated_in_output: restored
            .as_deref()
            .is_some_and(|r| live.canary.restored_in(r)),
        ..Evidence::default()
    })
}

/// `POST /v1/check/{id}/direct`.
pub async fn direct(state: &Arc<AppState>, id: &str) -> Result<CheckReport, ApiError> {
    with_live(state, id, async |live: &mut LiveCheck| {
        let gateway = gateway_direct(state, live).await;
        let mirror = super::mirror::direct(state, live).await;
        let proxy = super::proxy::direct(state, &mut *live).await;
        let report = CheckReport {
            id: live.id.clone(),
            harness: None,
            results: CheckResults {
                gateway,
                mirror,
                proxy,
            },
        };
        tracing::info!(
            gateway = ?report.results.gateway.status,
            mirror = ?report.results.mirror.status,
            proxy = ?report.results.proxy.status,
            "check direct run"
        );
        live.latest = Some(report.clone());
        report
    })
    .await
}

/// `POST /v1/check/{id}/harness`: the output is compared in memory and dropped.
pub async fn harness(
    state: &Arc<AppState>,
    id: &str,
    body: CheckHarnessBody,
) -> Result<CheckReport, ApiError> {
    with_live(state, id, async |live: &mut LiveCheck| {
        let results = super::proxy::harness_results(state, &mut *live, &body).await;
        let report = CheckReport {
            id: live.id.clone(),
            harness: Some(body.harness),
            results,
        };
        tracing::info!(harness = ?body.harness, "check harness run");
        live.latest = Some(report.clone());
        report
    })
    .await
}

/// `GET /v1/check/{id}`.
pub async fn report(state: &Arc<AppState>, id: &str) -> Result<CheckReport, ApiError> {
    with_live(state, id, async |live: &mut LiveCheck| live.latest.clone())
        .await?
        .ok_or_else(|| ApiError::not_found("no check report yet"))
}

/// `DELETE /v1/check/{id}`.
pub async fn remove(state: &Arc<AppState>, id: &str) -> Result<(), ApiError> {
    if !valid_id(id) {
        return Err(no_such_check());
    }
    let mut guard = state.check.live.lock().await;
    match guard.take() {
        Some(live) if live.id == id => {
            remove_live(state, live).await;
            Ok(())
        }
        other => {
            *guard = other;
            Err(no_such_check())
        }
    }
}

/// Delete everything `live` created. Errors are logged by class and never stop the rest.
pub async fn remove_live(state: &Arc<AppState>, live: LiveCheck) {
    super::proxy::remove(state, &live);
    let s = Arc::clone(state);
    let (datasets, token_id, dir) = (live.datasets.clone(), live.token_id, live.dir.clone());
    let removing = tokio::task::spawn_blocking(move || {
        for d in &datasets {
            // A folder dataset loses its folder (watchers, mirror tree)
            // before the dataset, as in the startup sweep.
            let ok = match s.mirror.get() {
                Some(f) => f.remove_dataset(&s, d).is_ok(),
                None => s.delete_dataset(d).is_ok(),
            };
            if !ok {
                tracing::warn!("check dataset could not be deleted; the startup sweep will retry");
            }
        }
        if let Some(t) = token_id {
            let _ = s.vault.revoke_gateway_token(t);
        }
        let _ = std::fs::remove_dir_all(&dir);
    });
    // Bounded: the live-check lock is held here (TCC spike finding 2).
    if tokio::time::timeout(super::REMOVE_WAIT, removing)
        .await
        .is_err()
    {
        tracing::warn!("check removal still running; the startup sweep will retry");
    }
    super::mirror::cleanup(&live);
    for d in &live.datasets {
        state.gateway_remove(d).await;
    }
    tracing::info!("check removed");
}
