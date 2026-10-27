//! Foreground run: logging to stderr, startup, signal handling, serve.
//! Shared by the `inumakid` binary and `inumaki daemon`.

use std::sync::Arc;
use std::time::Duration;

use tokio::signal::unix::{SignalKind, signal};
use tracing::{Level, Metadata, Subscriber};
use tracing_subscriber::filter::{FilterExt, FilterFn, filter_fn};
use tracing_subscriber::layer::{Filter, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use crate::server;
use crate::state::{AppState, StartOptions};

/// Log targets that never emit, at any level. rmcp logs whole JSON-RPC
/// messages (requests, results, raw transport events), and the gateway's
/// upstream sessions carry rehydrated originals. `axum::rejection` is where
/// axum logs an extractor rejection, whose text can quote the request body
/// (a hook body holds tool output); the control API converts rejections
/// itself, so axum does not log them on that path today, and the entry is
/// defense in depth (pinned by `tests/hook_canary.rs`). async-imap and
/// imap-proto trace raw IMAP lines: the LOGIN command with the password,
/// folder names, headers, and message bodies. `notify`,
/// `notify_debouncer_full`, and the FSEvents and inotify backends log
/// watched paths (the folder mirror's sources and outboxes).
const SILENCED_TARGETS: &[&str] = &[
    "rmcp",
    "axum::rejection",
    "async_imap",
    "imap_proto",
    "notify",
    "notify_debouncer_full",
    "fsevent",
    "fsevent_sys",
    "inotify",
];

/// Log targets capped at `WARN`: HTTP and TLS stacks whose debug output
/// carries URIs, headers, and server names (SNI).
const WARN_CAPPED_TARGETS: &[&str] = &["hyper", "hyper_util", "h2", "reqwest", "rustls"];

/// True when `target` is `prefix` or one of its submodules (`prefix::…`).
fn under(target: &str, prefix: &str) -> bool {
    target
        .strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with("::"))
}

fn privacy_allows(meta: &Metadata<'_>) -> bool {
    let target = meta.target();
    if SILENCED_TARGETS.iter().any(|p| under(target, p)) {
        return false;
    }
    if WARN_CAPPED_TARGETS.iter().any(|p| under(target, p)) {
        return *meta.level() <= Level::WARN;
    }
    true
}

/// The filter that runs independently of `RUST_LOG`: every target in
/// `SILENCED_TARGETS` (`rmcp`, `axum::rejection`, the IMAP crates, the file
/// watcher crates) is dropped and
/// `hyper`, `hyper_util`, `h2`, `reqwest`, and `rustls` are capped at
/// `WARN`. It is a separate predicate, not an `EnvFilter` directive, so no
/// user directive (however specific, e.g. `rmcp::service=trace`) can
/// re-enable those events.
pub fn privacy_filter() -> FilterFn<fn(&Metadata<'_>) -> bool> {
    filter_fn(privacy_allows as fn(&Metadata<'_>) -> bool)
}

/// `env` combined with [`privacy_filter`]: an event or span is logged only
/// when both allow it. Every subscriber the daemon installs (and the
/// canary tests) uses this.
pub fn log_filter<S>(env: EnvFilter) -> impl Filter<S> + Send + Sync + 'static
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    env.and(privacy_filter())
}

/// Install a stderr subscriber honouring `RUST_LOG` (default `info`) under
/// [`log_filter`]. Harmless when a subscriber is already installed (tests).
pub fn init_logging() {
    let env = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_filter(log_filter(env)),
        )
        .try_init();
}

/// The fixed line [`install_panic_hook`] writes, before the location.
pub const PANIC_LINE: &str = "inumakid: internal error (panic message withheld) at ";

/// Replace the default panic hook. The default prints the panic message,
/// and std's own messages can quote content (a `str` slice out of bounds
/// prints the string); a worker's panic must not put a document line in the
/// log. This writes a fixed line with the source location (`file:line` of
/// the code that panicked, never data) to stderr. Unwinding, `catch_unwind`,
/// and the exit status are unchanged.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        use std::io::Write;
        let at = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown".to_string());
        let _ = std::io::stderr().write_all(format!("{PANIC_LINE}{at}\n").as_bytes());
    }));
}

/// Start (outside the async runtime, so secret-store access never runs on
/// a runtime thread), then serve until `SIGTERM`, `SIGINT`, or
/// `POST /v1/shutdown`. Returns the process exit code: 0 after a clean
/// stop, 2 when startup or serving failed.
pub fn run(opts: StartOptions) -> u8 {
    // One crypto provider for the process (HTTP upstreams' TLS); `Err`
    // means one is installed already.
    let _ = rustls::crypto::ring::default_provider().install_default();
    install_panic_hook();
    init_logging();
    let state = match AppState::start(&opts) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::error!(error = %e, "inumakid failed to start");
            return 2;
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "could not start the async runtime");
            return 2;
        }
    };
    let code = rt.block_on(async {
        let signals = Arc::clone(&state);
        tokio::spawn(async move {
            let mut term = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "cannot listen for SIGTERM");
                    return;
                }
            };
            let mut int = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "cannot listen for SIGINT");
                    return;
                }
            };
            tokio::select! {
                _ = term.recv() => tracing::info!("SIGTERM received"),
                _ = int.recv() => tracing::info!("SIGINT received"),
            }
            signals.shutdown.send_replace(true);
        });
        match server::serve(state).await {
            Ok(()) => 0,
            Err(e) => {
                tracing::error!(error = %e, "inumakid stopped with an error");
                2
            }
        }
    });
    // Dropping the runtime would wait for every running blocking task, and
    // one may be parked behind a macOS privacy prompt (a folder request
    // waiting on a mirror job, TCC spike finding 2): bounded instead.
    rt.shutdown_timeout(RUNTIME_SHUTDOWN_WAIT);
    code
}

/// How long the exit waits for blocking tasks still running after the
/// server has stopped.
const RUNTIME_SHUTDOWN_WAIT: Duration = Duration::from_secs(2);

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Capture {
            self.clone()
        }
    }

    #[test]
    fn rust_log_cannot_reenable_rmcp_or_verbose_http_targets() {
        let cap = Capture::default();
        let env = EnvFilter::new(
            "rmcp::service=trace,rmcp=trace,async_imap=trace,imap_proto=trace,notify=trace,notify_debouncer_full=trace,fsevent_sys=trace,inotify=trace,hyper=trace,reqwest=debug,info",
        );
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(cap.clone())
                .with_filter(log_filter(env)),
        );
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(target: "rmcp::service", "rmcp-service-canary");
            tracing::trace!(target: "rmcp", "rmcp-root-canary");
            tracing::info!(target: "rmcp::transport::streamable_http_server::tower", "rmcp-tower-canary");
            tracing::trace!(target: "async_imap::imap_stream", "imap-login-canary");
            tracing::error!(target: "imap_proto::parser", "imap-proto-canary");
            tracing::error!(target: "notify::fsevent", "notify-canary");
            tracing::trace!(target: "notify_debouncer_full", "debouncer-canary");
            tracing::error!(target: "fsevent_sys::core_foundation", "fsevent-canary");
            tracing::error!(target: "inotify::events", "inotify-canary");
            tracing::debug!(target: "hyper::proto", "hyper-debug-canary");
            tracing::debug!(target: "reqwest::connect", "reqwest-debug-canary");
            tracing::debug!(target: "rustls::client::hs", "rustls-debug-canary");
            tracing::warn!(target: "hyper::proto", "hyper-warn-passes");
            tracing::info!(target: "rmcpx", "lookalike-passes");
            tracing::info!(target: "inumakid", "inumakid-info-passes");
            tracing::debug!(target: "inumakid", "inumakid-debug-filtered-by-env");
        });
        let out = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
        for dropped in [
            "rmcp-service-canary",
            "rmcp-root-canary",
            "rmcp-tower-canary",
            "imap-login-canary",
            "imap-proto-canary",
            "notify-canary",
            "debouncer-canary",
            "fsevent-canary",
            "inotify-canary",
            "hyper-debug-canary",
            "reqwest-debug-canary",
            "rustls-debug-canary",
            "inumakid-debug-filtered-by-env",
        ] {
            assert!(!out.contains(dropped), "{dropped} leaked: {out}");
        }
        for kept in [
            "hyper-warn-passes",
            "lookalike-passes",
            "inumakid-info-passes",
        ] {
            assert!(out.contains(kept), "{kept} missing: {out}");
        }
    }
}
