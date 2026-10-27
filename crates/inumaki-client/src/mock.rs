//! A mock daemon serving the contract fixtures on a Unix socket (feature
//! `mock`), for the app's and the hook's tests (M6 spec §9.8). Every route
//! of §9 answers its fixture with the documented success status. A test can
//! replace one route's answer (status, body, delay) and read back what was
//! requested. This is a test tool: it keeps request bodies in memory.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::http::{Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodFilter, MethodRouter};
use serde_json::Value;

use crate::client::Client;
use crate::contract::fixture;

/// One route: method, axum path template, success status, fixture (`None`: empty body).
pub struct MockRoute {
    /// `GET`, `POST`, `DELETE`.
    pub method: &'static str,
    /// Path template.
    pub path: &'static str,
    /// Success status.
    pub status: u16,
    /// Fixture name.
    pub fixture: Option<&'static str>,
}

const fn r(
    method: &'static str,
    path: &'static str,
    status: u16,
    fixture: Option<&'static str>,
) -> MockRoute {
    MockRoute {
        method,
        path,
        status,
        fixture,
    }
}

/// A dataset id whose `GET`/`DELETE …/folder` answers `404 not_found`
/// `folder not configured` (M5 spec §12.3), not the fallback's `no such route`.
pub const UNCONFIGURED_FOLDER: &str = "unconfigured-folder";

/// Every route of M6 spec §9 (the MCP route `/mcp/{dataset}` is not JSON and not mocked).
pub const ROUTES: &[MockRoute] = &[
    // §9.2
    r("GET", "/v1/status", 200, Some("status")),
    r("GET", "/v1/datasets", 200, Some("datasets")),
    r("POST", "/v1/datasets", 201, Some("dataset")),
    r("DELETE", "/v1/datasets/{id}", 204, None),
    r("POST", "/v1/datasets/{id}/rotate", 200, Some("rotate")),
    r("GET", "/v1/datasets/{id}/upstreams", 200, Some("upstreams")),
    r("POST", "/v1/datasets/{id}/upstreams", 201, Some("upstream")),
    r("DELETE", "/v1/datasets/{id}/upstreams/{name}", 204, None),
    r(
        "POST",
        "/v1/datasets/{id}/upstreams/{name}/accept-schema",
        204,
        None,
    ),
    r("GET", "/v1/gateway/tokens", 200, Some("tokens")),
    r("POST", "/v1/gateway/tokens", 201, Some("token_created")),
    r("DELETE", "/v1/gateway/tokens/{id}", 204, None),
    r("GET", "/v1/activity", 200, Some("activity")),
    r("GET", "/v1/activity/verify", 200, Some("activity_verify")),
    r("POST", "/v1/inspect", 200, Some("inspect")),
    r("POST", "/v1/sanitize", 200, Some("sanitize")),
    r("POST", "/v1/rehydrate", 200, Some("rehydrate")),
    r("GET", "/v1/doctor", 200, Some("doctor")),
    r("POST", "/v1/shutdown", 202, Some("shutdown")),
    // §9.3
    r("GET", "/v1/datasets/{id}/journal", 200, Some("journal")),
    r(
        "GET",
        "/v1/datasets/{id}/journal/{record}",
        200,
        Some("journal_record"),
    ),
    r("GET", "/v1/datasets/{id}/entities", 200, Some("entities")),
    r(
        "DELETE",
        "/v1/datasets/{id}/entities/{token}",
        200,
        Some("forget"),
    ),
    r(
        "POST",
        "/v1/datasets/{id}/entities/forget",
        200,
        Some("forget"),
    ),
    // §9.4
    r("POST", "/v1/datasets/{id}/mailbox", 201, Some("mailbox")),
    r("GET", "/v1/datasets/{id}/mailbox", 200, Some("mailbox")),
    r("DELETE", "/v1/datasets/{id}/mailbox", 204, None),
    r(
        "POST",
        "/v1/datasets/{id}/mailbox/check",
        200,
        Some("mailbox_check"),
    ),
    // §9.5
    r("POST", "/v1/datasets/{id}/folder", 201, Some("folder")),
    r("GET", "/v1/datasets/{id}/folder", 200, Some("folder")),
    r("DELETE", "/v1/datasets/{id}/folder", 204, None),
    r(
        "POST",
        "/v1/datasets/{id}/folder/rescan",
        202,
        Some("folder_rescan"),
    ),
    r("GET", "/v1/folders", 200, Some("folders")),
    // §9.6
    r("GET", "/v1/proxy", 200, Some("proxy")),
    // §9.7
    r("GET", "/v1/service", 200, Some("service")),
    r("POST", "/v1/models/pull", 202, Some("models_job")),
    r("GET", "/v1/models/pull", 200, Some("models_job")),
    r("POST", "/v1/hook", 200, Some("hook_pass")),
    r("POST", "/v1/check", 201, Some("check_created")),
    r("POST", "/v1/check/{id}/direct", 200, Some("check_report")),
    r("POST", "/v1/check/{id}/harness", 200, Some("check_report")),
    r("GET", "/v1/check/{id}", 200, Some("check_report")),
    r("DELETE", "/v1/check/{id}", 204, None),
];

/// A canned answer.
#[derive(Clone)]
pub struct Canned {
    /// Status.
    pub status: u16,
    /// Body bytes; `None` for an empty body.
    pub body: Option<Vec<u8>>,
    /// `Content-Type` of the body.
    pub content_type: &'static str,
    /// Wait this long before answering.
    pub delay: Duration,
}

impl Canned {
    /// A JSON body.
    pub fn json(status: u16, body: Value) -> Self {
        Canned {
            status,
            body: Some(serde_json::to_vec(&body).expect("JSON value serializes")),
            content_type: "application/json",
            delay: Duration::ZERO,
        }
    }

    /// A contract fixture as the body.
    pub fn fixture(status: u16, name: &str) -> Self {
        Canned {
            status,
            body: Some(fixture(name).as_bytes().to_vec()),
            content_type: "application/json",
            delay: Duration::ZERO,
        }
    }

    /// No body.
    pub fn empty(status: u16) -> Self {
        Canned {
            status,
            body: None,
            content_type: "application/json",
            delay: Duration::ZERO,
        }
    }

    /// A non-JSON body (axum's plain-text `413`).
    pub fn raw(status: u16, bytes: impl Into<Vec<u8>>) -> Self {
        Canned {
            status,
            body: Some(bytes.into()),
            content_type: "text/plain",
            delay: Duration::ZERO,
        }
    }

    /// The documented error shape.
    pub fn error(status: u16, kind: &str, message: &str, kinds: &[&str]) -> Self {
        Self::json(
            status,
            serde_json::json!({ "error": { "type": kind, "message": message, "kinds": kinds, "checks": [] } }),
        )
    }

    /// The response this answer describes (the delay is not applied here).
    fn into_response_now(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        match self.body {
            Some(b) => (status, [(header::CONTENT_TYPE, self.content_type)], b).into_response(),
            None => status.into_response(),
        }
    }

    /// The same answer after `delay`.
    pub fn delayed(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

/// One request the mock received.
#[derive(Debug, Clone)]
pub struct Recorded {
    /// Method.
    pub method: String,
    /// Matched route template.
    pub route: &'static str,
    /// Raw (percent-encoded) path.
    pub path: String,
    /// Raw query string.
    pub query: Option<String>,
    /// Body as JSON, when it was JSON.
    pub body: Option<Value>,
}

#[derive(Default)]
struct MockState {
    overrides: Mutex<HashMap<(String, &'static str), Canned>>,
    requests: Mutex<Vec<Recorded>>,
    /// Tokens minted by the default `POST /v1/gateway/tokens` answer and not
    /// revoked since: (id, label).
    minted: Mutex<Vec<(i64, String)>>,
    /// Source of distinct mint ids.
    mints: AtomicU64,
}

/// Id of the first default mint: the `token_created` fixture's id, so the
/// first mint is the fixture and every later one counts up from it (the
/// `tokens` fixture lists ids 1 and 2).
const FIRST_MINT_ID: i64 = 3;

fn default_for(route: &MockRoute) -> Canned {
    match route.fixture {
        Some(name) => Canned::fixture(route.status, name),
        None => Canned::empty(route.status),
    }
}

/// The default answer of the token routes, which keep a little state: every
/// mint is distinct (id and token carry a counter), a revoke removes it, and
/// the list shows what is live next to the fixture's tokens. `None` for any
/// other route.
fn token_default(
    state: &MockState,
    route: &MockRoute,
    uri: &Uri,
    body: Option<&Value>,
) -> Option<Canned> {
    let live = || state.minted.lock().unwrap_or_else(PoisonError::into_inner);
    match (route.method, route.path) {
        ("POST", "/v1/gateway/tokens") => {
            let n = state.mints.fetch_add(1, Ordering::Relaxed);
            let id = FIRST_MINT_ID + n as i64;
            let label = body
                .and_then(|b| b.get("label"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            live().push((id, label.clone()));
            Some(Canned::json(
                route.status,
                serde_json::json!({
                    "id": id,
                    "label": label,
                    "created_at": 1_790_000_002 + n,
                    // The first mint's token is the fixture's.
                    "token": format!("inumaki_gw_qwxzvk{n:020}"),
                }),
            ))
        }
        ("DELETE", "/v1/gateway/tokens/{id}") => {
            if let Some(id) = uri
                .path()
                .rsplit('/')
                .next()
                .and_then(|s| s.parse::<i64>().ok())
            {
                live().retain(|(i, _)| *i != id);
            }
            None
        }
        ("GET", "/v1/gateway/tokens") => {
            let mut list: Vec<Value> = serde_json::from_str(fixture("tokens")).ok()?;
            list.extend(live().iter().map(|(id, label)| {
                serde_json::json!({ "id": id, "label": label, "created_at": 1_790_000_100, "last_used": null })
            }));
            Some(Canned::json(route.status, Value::Array(list)))
        }
        _ => None,
    }
}

async fn answer(
    state: Arc<MockState>,
    route: &'static MockRoute,
    uri: Uri,
    body: Bytes,
) -> Response {
    let json: Option<Value> = serde_json::from_slice(&body).ok();
    state
        .requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Recorded {
            method: route.method.to_string(),
            route: route.path,
            path: uri.path().to_string(),
            query: uri.query().map(str::to_string),
            body: json.clone(),
        });
    if route.path == "/v1/datasets/{id}/folder"
        && matches!(route.method, "GET" | "DELETE")
        && uri.path() == format!("/v1/datasets/{UNCONFIGURED_FOLDER}/folder")
    {
        return Canned::error(404, "not_found", "folder not configured", &[]).into_response_now();
    }
    let overridden = state
        .overrides
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&(route.method.to_string(), route.path))
        .cloned();
    let canned = match overridden {
        Some(c) => c,
        None => {
            token_default(&state, route, &uri, json.as_ref()).unwrap_or_else(|| default_for(route))
        }
    };
    if !canned.delay.is_zero() {
        tokio::time::sleep(canned.delay).await;
    }
    canned.into_response_now()
}

fn router(state: Arc<MockState>) -> Router {
    let mut paths: BTreeMap<&'static str, MethodRouter> = BTreeMap::new();
    for route in ROUTES {
        let st = Arc::clone(&state);
        let method = Method::from_bytes(route.method.as_bytes()).expect("route method");
        let filter = MethodFilter::try_from(method).expect("route method filter");
        let handler = move |uri: Uri, body: Bytes| answer(Arc::clone(&st), route, uri, body);
        let mr = paths
            .remove(route.path)
            .unwrap_or_else(MethodRouter::new)
            .on(filter, handler);
        paths.insert(route.path, mr);
    }
    let mut app = Router::new();
    for (path, mr) in paths {
        app = app.route(path, mr);
    }
    app.fallback(|| async {
        (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"error":{"type":"not_found","message":"no such route","kinds":[],"checks":[]}}"#,
        )
    })
}

/// A short, unique socket path (macOS limits socket paths to 104 bytes).
fn short_socket() -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("inumaki-mock-{}-{n}.sock", std::process::id()))
}

/// A running mock daemon.
pub struct MockDaemon {
    socket: PathBuf,
    state: Arc<MockState>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl MockDaemon {
    /// Start on a fresh socket in the temp directory.
    pub async fn start() -> MockDaemon {
        Self::start_at(short_socket()).await
    }

    /// Start on `socket` (an existing file there is replaced).
    pub async fn start_at(socket: impl Into<PathBuf>) -> MockDaemon {
        let socket = socket.into();
        let _ = std::fs::remove_file(&socket);
        let listener = tokio::net::UnixListener::bind(&socket).expect("mock socket binds");
        let state = Arc::new(MockState::default());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let app = router(Arc::clone(&state));
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = rx.await;
                })
                .await;
        });
        MockDaemon {
            socket,
            state,
            stop: Some(tx),
            task: Some(task),
        }
    }

    /// The socket path.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// A client for this mock.
    pub fn client(&self) -> Client {
        Client::new(&self.socket)
    }

    /// Answer `method route` with `canned` from now on. Panics on a route
    /// that is not in [`ROUTES`] (a test typo).
    pub fn set(&self, method: &str, route: &'static str, canned: Canned) {
        assert!(
            ROUTES.iter().any(|r| r.method == method && r.path == route),
            "no mock route {method} {route}"
        );
        self.state
            .overrides
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((method.to_string(), route), canned);
    }

    /// Back to the fixture answer.
    pub fn reset(&self, method: &str, route: &'static str) {
        self.state
            .overrides
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&(method.to_string(), route));
    }

    /// Ids of the tokens the default mint answered and nobody revoked since.
    pub fn live_tokens(&self) -> Vec<i64> {
        self.state
            .minted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(id, _)| *id)
            .collect()
    }

    /// Requests so far, oldest first.
    pub fn requests(&self) -> Vec<Recorded> {
        self.state
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Stop gracefully (at most 5 s for in-flight requests) and remove the socket.
    pub async fn stop(mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.task.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), t).await;
        }
        let _ = std::fs::remove_file(&self.socket);
    }
}

impl Drop for MockDaemon {
    fn drop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
        }
        let _ = std::fs::remove_file(&self.socket);
    }
}
