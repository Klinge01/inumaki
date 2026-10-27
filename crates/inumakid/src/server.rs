//! Bind the socket, serve, sweep, shut down (spec §10.2 steps 3 and 4).

use std::future::IntoFuture;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use inumaki_gateway::Gateway;
use tokio::net::{TcpListener, UnixListener};

use crate::api;
use crate::glue::{BlocksHandle, DaemonBuiltins};
use crate::state::{AppState, StartError};

/// Sweeper period.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// Time in-flight requests get after a shutdown request.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
/// Part of [`SHUTDOWN_GRACE`] in-flight MCP calls get before their sessions
/// end (their streams must close before the HTTP drain gives up).
const GATEWAY_DRAIN: Duration = Duration::from_secs(3);
/// How long shutdown waits for the mirror service to stop: one second more
/// than `Mirror::stop`'s own 3 s bound, so that bound ends it. A mirror
/// worker parked in a first open behind a macOS privacy prompt (TCC spike
/// finding 2) is left to the process exit.
const MIRROR_STOP_WAIT: Duration = Duration::from_secs(4);

fn io_err(path: &Path, e: &std::io::Error) -> StartError {
    StartError::Io {
        path: path.display().to_string(),
        kind: e.kind(),
    }
}

/// Refuse to start when something accepts on `path`; remove a stale file.
pub fn prepare_socket_path(path: &Path) -> Result<(), StartError> {
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => Err(StartError::AlreadyRunning(path.display().to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => {
            tracing::warn!("removing stale socket file");
            std::fs::remove_file(path).map_err(|e| io_err(path, &e))
        }
    }
}

/// Serve until `state.shutdown` becomes true, with the default sweep period.
pub async fn serve(state: Arc<AppState>) -> Result<(), StartError> {
    serve_with(state, SWEEP_INTERVAL).await
}

/// [`serve`] with a custom sweep period (tests).
pub async fn serve_with(state: Arc<AppState>, sweep_every: Duration) -> Result<(), StartError> {
    prepare_socket_path(&state.socket_path)?;
    let listener =
        UnixListener::bind(&state.socket_path).map_err(|e| io_err(&state.socket_path, &e))?;
    // Between bind and this call the socket carries the process umask; no
    // request can be served in that window (accept has not started) and the
    // data directory is the user's own, so the window is accepted rather
    // than pulling in `libc` for umask (review M7).
    std::fs::set_permissions(&state.socket_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| io_err(&state.socket_path, &e))?;
    // No path: under the home directory it names the user (ruling L110.1).
    tracing::info!("listening");
    // Offline Revert spec D6: pending revocations are applied after the
    // control socket is bound (so an app that found no socket wrote its
    // record before this read) and before the gateway listens or anything
    // is served. Failing to apply them refuses the start (D7).
    let (vault, data_dir) = (state.vault.clone(), state.data_dir.clone());
    let applied =
        tokio::task::spawn_blocking(move || crate::revocations::apply_pending(&vault, &data_dir))
            .await;
    let stage = match applied {
        Ok(Ok(_)) => None,
        Ok(Err(crate::revocations::RevocationError::Io(stage))) => Some(stage),
        Err(_) => Some("worker"),
    };
    if let Some(stage) = stage {
        // Nothing will serve the socket: do not leave its file behind.
        let _ = std::fs::remove_file(&state.socket_path);
        return Err(StartError::Revocations(stage));
    }
    // M4 spec §5.1, §11: the gateway listener (loopback, checked by the
    // config); a bind failure is fatal.
    let listen = state.cfg.gateway.listen.clone();
    let bound = match TcpListener::bind(&listen).await {
        Ok(tcp) => tcp.local_addr().map(|a| (tcp, a)),
        Err(e) => Err(e),
    };
    let (tcp, addr) = match bound {
        Ok(b) => b,
        Err(e) => {
            // Nothing will serve the socket: do not leave its file behind.
            let _ = std::fs::remove_file(&state.socket_path);
            return Err(StartError::Io {
                path: listen,
                kind: e.kind(),
            });
        }
    };
    *state
        .gateway_listen
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(addr);
    let gateway = Arc::new(Gateway::new(
        Arc::new(BlocksHandle(Arc::downgrade(&state))),
        state.vault.clone(),
        Arc::new(DaemonBuiltins {
            state: Arc::downgrade(&state),
        }),
        state.cfg.gateway_config(),
    ));
    let _ = state.gateway.set(Arc::clone(&gateway));
    // M6 spec §8.4: a check interrupted by a crash leaves artifacts behind.
    crate::check::sweep_leftovers(&state).await;
    // M5 spec §7.2: the mirror starts after the check sweep, before the gateway loads datasets.
    if let Some(f) = state.mirror.get() {
        let (f, s) = (Arc::clone(f), Arc::clone(&state));
        if let Err(e) = tokio::task::spawn_blocking(move || f.start(&s)).await {
            tracing::warn!(class = api::join_class(&e), "mirror service start failed");
        }
    }
    let _check_expiry = crate::check::spawn_expiry(Arc::downgrade(&state));
    let loaded = gateway.start().await;
    tracing::info!(gateway = %addr, datasets = loaded, "gateway listening");
    // M8: the model-API proxy. A bind failure is not fatal (spec decision 21).
    let proxy_cfg = state.cfg.proxy.clone();
    let proxy_origins = proxy_cfg.allowed_origins.clone();
    // Fails closed: a non-empty identity whose dictionary cannot be built is an
    // error, so the proxy is not started. The warning carries no value. A
    // proxy disabled by configuration never serves, so it is built without
    // the identity and its status reports `disabled` (final review M8).
    let host = if proxy_cfg.enabled {
        crate::proxy_host::DaemonHost::new(Arc::downgrade(&state))
    } else {
        crate::proxy_host::DaemonHost::with_identity(
            Arc::downgrade(&state),
            crate::identity::Identity::default(),
        )
    };
    let (proxy, proxy_addr, proxy_listener) = match host {
        Ok(host) => crate::chat::start(&state, proxy_cfg, Arc::new(host)).await,
        Err(_) => {
            tracing::warn!("the proxy identity could not be prepared; the proxy is off");
            (None, None, None)
        }
    };
    let proxy_app = proxy.as_ref().zip(proxy_addr).map(|(p, a)| {
        crate::tcp_guard::layer(p.router(), proxy_origins, a).layer(
            axum::middleware::from_fn_with_state(Arc::clone(&state), api::access_log),
        )
    });
    if let Some(p) = proxy {
        // M8-3: the check routes live on the proxy listener. With the proxy
        // disabled or unbound there is nothing to register, and the
        // end-to-end check reports `proxy_unavailable`.
        if let Some(proxy_addr) = proxy_addr {
            let check_routes = p.check_routes();
            tracing::debug!(live = check_routes.len(), listen = %proxy_addr, "proxy check routes ready");
            state
                .check
                .set_proxy_routes(Arc::new(crate::check::proxy_m8::M8Routes::new(
                    Arc::clone(&check_routes),
                    proxy_addr,
                )));
        }
        let _ = state.proxy.set(p);
    }
    let app = api::router(Arc::clone(&state));
    let tcp_app = api::gateway::tcp_router(Arc::clone(&state), addr);
    let sweeper = tokio::spawn(sweeper_task(Arc::clone(&state), sweep_every));
    let mut signal_rx = state.shutdown.subscribe();
    let mut tcp_signal_rx = state.shutdown.subscribe();
    let mut drain_rx = state.shutdown.subscribe();
    let socket_fut = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = signal_rx.wait_for(|v| *v).await;
        })
        .into_future();
    let tcp_fut = axum::serve(tcp, tcp_app)
        .with_graceful_shutdown(async move {
            let _ = tcp_signal_rx.wait_for(|v| *v).await;
        })
        .into_future();
    let mut proxy_signal_rx = state.shutdown.subscribe();
    let proxy_state = Arc::clone(&state);
    let proxy_fut = async move {
        if let Some((l, app)) = proxy_listener.zip(proxy_app) {
            let served = axum::serve(l, app)
                .with_graceful_shutdown(async move {
                    let _ = proxy_signal_rx.wait_for(|v| *v).await;
                })
                .into_future()
                .await;
            // The proxy failing must not take the daemon down (decision 21).
            proxy_serve_ended(&proxy_state, served);
        }
        Ok::<(), std::io::Error>(())
    };
    let serve_fut = async move { tokio::try_join!(socket_fut, tcp_fut, proxy_fut).map(|_| ()) };
    tokio::pin!(serve_fut);
    let result = tokio::select! {
        r = &mut serve_fut => r,
        _ = wait_true(&mut drain_rx) => {
            tracing::info!("shutdown requested; draining in-flight requests");
            // Open MCP streams would hold the HTTP drain for the whole grace
            // period: stop the gateway alongside it the way a removed dataset
            // stops (in-flight MCP calls answer, then their sessions end).
            let stopping = tokio::spawn({
                let gateway = Arc::clone(&gateway);
                async move { gateway.shutdown_within(GATEWAY_DRAIN).await }
            });
            let r = match tokio::time::timeout(SHUTDOWN_GRACE, &mut serve_fut).await {
                Ok(r) => r,
                Err(_) => {
                    tracing::warn!("shutdown grace elapsed; aborting remaining requests");
                    Ok(())
                }
            };
            let _ = stopping.await;
            r
        }
    };
    sweeper.abort();
    gateway.shutdown().await;
    if let Some(f) = state.mirror.get() {
        let f = Arc::clone(f);
        // `Mirror::stop` bounds its own wait (3 s); this bounds the rest (4 s),
        // so a worker parked behind a macOS prompt never holds the exit.
        match tokio::time::timeout(
            MIRROR_STOP_WAIT,
            tokio::task::spawn_blocking(move || f.stop()),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!(class = api::join_class(&e), "mirror service stop failed");
            }
            Err(_) => tracing::warn!("mirror service stop timed out"),
        }
    }
    if let Err(e) = state.vault.checkpoint() {
        tracing::warn!(error = %e, "vault checkpoint at shutdown failed");
    }
    if let Err(e) = std::fs::remove_file(&state.socket_path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(error = %e, "could not remove the socket file");
        }
    }
    tracing::info!("inumakid stopped");
    result.map_err(|e| io_err(&state.socket_path, &e))
}

/// Resolve once `rx` holds `true`. `watch::Receiver::wait_for` cannot be used
/// directly as a `tokio::select!` branch here: its `Ok(Ref<'_, bool>)` output
/// borrows the channel's internal lock, and `select!`'s generated output enum
/// captures every branch's `Future::Output` in one type, so a single `!Send`
/// output (the guard) makes the whole `select!` future `!Send`, which
/// `tokio::spawn` (used to run `serve_with`, see `tests/common/mod.rs`)
/// rejects. `changed()`'s output is a plain `Result<(), RecvError>`, so a
/// loop over it keeps the branch future `Send`.
async fn wait_true(rx: &mut tokio::sync::watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            break;
        }
    }
}

async fn sweeper_task(state: Arc<AppState>, every: Duration) {
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await; // the first tick completes immediately
    loop {
        tick.tick().await;
        // Offline Revert spec D6, D7: first in the tick, so a slow sweep
        // cannot delay it past the documented minute, and in its own
        // blocking task, so a panic in the sweep cannot skip it; failing (or
        // panicking) stops the service.
        let s = Arc::clone(&state);
        let applied = tokio::task::spawn_blocking(move || {
            crate::revocations::apply_pending(&s.vault, &s.data_dir)
        })
        .await;
        if !matches!(applied, Ok(Ok(_))) {
            tracing::error!("pending gateway token revocations could not be applied; stopping");
            state.shutdown.send_replace(true);
            return;
        }
        let s = Arc::clone(&state);
        match tokio::task::spawn_blocking(move || {
            if let Some(p) = s.proxy.get() {
                p.sweep();
            }
            s.sweep_once()
        })
        .await
        {
            Ok(summary) => tracing::debug!(?summary, "sweep"),
            Err(e) => tracing::warn!(class = api::join_class(&e), "sweeper worker failed"),
        }
    }
}

/// What the proxy listener's end means for the status. Whatever ended the
/// serve loop (an error, or a graceful end at shutdown), the proxy no longer
/// listens: the status (and with it the check's proxy gate) must stop saying
/// `running`, because the address is free for any other process. The daemon
/// keeps running either way (decision 21).
pub fn proxy_serve_ended(state: &AppState, served: std::io::Result<()>) {
    if let Err(e) = served {
        tracing::warn!(kind = ?e.kind(), "the proxy listener stopped");
    }
    if let Some(p) = state.proxy.get() {
        p.set_listen(inumaki_proxy::ListenState::BindFailed);
    }
}
