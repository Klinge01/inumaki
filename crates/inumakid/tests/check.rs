//! The end-to-end canary check (M6 spec §8, §9.7).

mod common;

use std::sync::Arc;
use std::time::Duration;

use hyper::Method;
use inumakid::check::canary::{Canary, iban_at, iban_valid};

#[test]
fn canary_ibans_have_valid_check_digits() {
    // The documented example IBAN of the test fixtures.
    assert!(iban_valid("AT61 1904 3002 3457 3201"));
    assert!(!iban_valid("AT62 1904 3002 3457 3201"));
    assert_eq!(
        iban_at("1904300234573201").replace(' ', ""),
        "AT611904300234573201"
    );
    for _ in 0..50 {
        let c = Canary::generate();
        assert!(iban_valid(&c.iban), "{}", c.iban_compact());
        assert!(c.email.ends_with(".example.invalid"));
    }
}

#[test]
fn canary_is_found_whole_normalized_or_by_component() {
    let c = Canary::generate();
    assert!(c.appears_in(&format!("hello {}", c.full_name())));
    assert!(c.appears_in(&format!("only {} here", c.last.to_uppercase())));
    assert!(c.appears_in(&format!("iban {}", c.iban_compact())));
    assert!(c.appears_in(&format!("iban {}", c.iban)));
    assert!(c.appears_in(&c.email.to_uppercase()));
    let acc = c.account();
    assert_eq!(acc.len(), 11);
    assert!(
        c.appears_in(&format!("Konto {} {}", &acc[..5], &acc[5..])),
        "the account digits alone are a leak"
    );
    assert!(!c.appears_in("Record: <PERSON_a7f2c1>, IBAN <IBAN_b3c4d5>, email <EMAIL_c1d2e3>"));
    assert!(c.restored_in(&format!("{} / {}", c.full_name(), c.iban)));
    assert!(
        !c.restored_in(&c.full_name()),
        "the IBAN must be restored too"
    );
    assert_eq!(format!("{c:?}"), "Canary(..)");
}

/// Review Focus 2.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reserved_check_names_are_refused() {
    let d = common::start().await;
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(serde_json::json!({ "id": "check-mine", "name": "x" })),
        )
        .await;
    assert_eq!(code, 400, "{body}");
    assert_eq!(
        body["error"]["message"],
        "dataset ids starting with check- are reserved"
    );
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/gateway/tokens",
            Some(serde_json::json!({ "label": "check:mine" })),
        )
        .await;
    assert_eq!(code, 400, "{body}");
    assert_eq!(
        body["error"]["message"],
        "token labels starting with check: are reserved"
    );
    // Near misses are ordinary names.
    let (code, _) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(serde_json::json!({ "id": "checks", "name": "x" })),
        )
        .await;
    assert_eq!(code, 201);
}

/// Review Focus 1: a daemon killed mid-check leaves `check-` datasets,
/// `check:` tokens, and `<data_dir>/check/`; the next start removes them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_sweep_removes_check_leftovers() {
    let d = common::start().await;
    d.dataset("keep-me").await;
    let st = Arc::clone(&d.state);
    tokio::task::spawn_blocking(move || {
        for id in ["check-0123456789ab", "check-0123456789ab-f"] {
            st.vault
                .create_dataset(&inumaki_vault::DatasetSpec::new(id, "check", "offline"))
                .unwrap();
        }
        st.vault.create_gateway_token("check:0123456789ab").unwrap();
        st.vault.create_gateway_token("app:codex").unwrap();
        std::fs::create_dir_all(st.data_dir.join("check").join("0123456789ab")).unwrap();
    })
    .await
    .unwrap();
    // Temporary check directories: this data directory's are swept, another daemon's are not.
    let tmp = std::env::temp_dir();
    let own = tmp.join(format!(
        "{}{}-abc",
        inumakid::check::TMP_PREFIX,
        inumakid::check::tmp_tag(&d.state.data_dir)
    ));
    let other = tmp.join(format!(
        "{}000000000000-abc-{}",
        inumakid::check::TMP_PREFIX,
        std::process::id()
    ));
    std::fs::create_dir_all(own.join("source")).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    let removed = inumakid::check::sweep_leftovers(&d.state).await;
    assert_eq!(removed.len(), 2);
    assert!(
        !own.exists(),
        "this data directory's temporary check directory is swept"
    );
    assert!(other.exists(), "another data directory's is not");
    let _ = std::fs::remove_dir_all(&other);
    let (_, list) = d.call(Method::GET, "/v1/datasets", None).await;
    let ids: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        // The proxy's reserved dataset is listed too (M8 spec §9).
        .filter(|d| d["kind"] != "chat")
        .map(|d| d["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["keep-me"]);
    let (_, tokens) = d.call(Method::GET, "/v1/gateway/tokens", None).await;
    let labels: Vec<&str> = tokens
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["label"].as_str().unwrap())
        .collect();
    assert_eq!(labels, ["app:codex"]);
    assert!(!d.state.data_dir.join("check").exists());
}

/// M5 spec §7.2: at startup the sweep runs before the mirror service starts.
/// A crash left the folder check's dataset with its folder and mirror tree:
/// the sweep removes the folder (tree behind its marker, rows, the hook's
/// guard) and the dataset; the source stays, and the service started
/// afterwards brings nothing back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_sweep_removes_a_check_folder_before_the_mirror_starts() {
    let m = common::mirror::start_state_only().await;
    let src = m.base.join("check-src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("brief.txt"), "x").unwrap();
    let (st, s2) = (Arc::clone(&m.state), src.clone());
    let mirror = tokio::task::spawn_blocking(move || {
        let mut spec = inumaki_vault::DatasetSpec::new("check-0123456789ab-f", "check", "offline");
        spec.kind = inumaki_vault::DatasetKind::Folder;
        st.vault.create_dataset(&spec).unwrap();
        let info = st
            .mirror
            .get()
            .unwrap()
            .add(&st, "check-0123456789ab-f", s2.to_str().unwrap(), None)
            .unwrap();
        // The tree an earlier run wrote, behind its marker.
        let mirror = std::path::PathBuf::from(&info.mirror);
        std::fs::create_dir_all(mirror.join("outbox")).unwrap();
        std::fs::write(mirror.join("brief.txt"), "<PERSON_a1b2c3>").unwrap();
        std::fs::write(mirror.join(".inumaki-mirror"), &info.label).unwrap();
        mirror
    })
    .await
    .unwrap();
    let removed = inumakid::check::sweep_leftovers(&m.state).await;
    assert_eq!(removed, ["check-0123456789ab-f"]);
    assert!(!mirror.exists(), "the mirror tree is removed");
    let f = Arc::clone(m.state.mirror.get().unwrap());
    assert!(f.list().is_empty(), "the hook no longer guards it");
    assert!(
        src.join("brief.txt").exists(),
        "the source is never touched"
    );
    let st = Arc::clone(&m.state);
    let f2 = Arc::clone(&f);
    tokio::task::spawn_blocking(move || f2.start(&st))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!mirror.exists(), "nothing comes back once the service runs");
    tokio::task::spawn_blocking(move || f.stop()).await.unwrap();
}

#[test]
fn canary_mcp_refuses_a_fixture_readable_by_others() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("canary.json");
    std::fs::write(&f, serde_json::to_vec(&Canary::generate()).unwrap()).unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_inumakid"))
        .args(["canary-mcp", "--fixture"])
        .arg(&f)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
}

use inumaki_client::contract::assert_bytes_round_trip;

async fn check_daemon() -> common::TestDaemon {
    let d = common::start().await;
    // In-process tests run inside the test binary: point the canary upstream
    // at the real daemon binary.
    d.state
        .check
        .set_canary_program(env!("CARGO_BIN_EXE_inumakid").into());
    d
}

async fn raw(
    d: &common::TestDaemon,
    m: inumaki_client::Method,
    p: &str,
    body: &str,
) -> (u16, Vec<u8>) {
    let r = inumaki_client::Client::new(&d.socket)
        .raw(m, p, body.as_bytes().to_vec())
        .await
        .unwrap();
    (r.status, r.body)
}

fn json(b: &[u8]) -> serde_json::Value {
    serde_json::from_slice(b).unwrap()
}

/// No `check-` dataset, no `check:` token, nothing under `<data_dir>/check/`.
async fn assert_no_check_artifacts(d: &common::TestDaemon) {
    let (_, list) = d.call(Method::GET, "/v1/datasets", None).await;
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .all(|x| !x["id"].as_str().unwrap().starts_with("check-")),
        "{list}"
    );
    let (_, tokens) = d.call(Method::GET, "/v1/gateway/tokens", None).await;
    assert!(
        tokens
            .as_array()
            .unwrap()
            .iter()
            .all(|t| !t["label"].as_str().unwrap().starts_with("check:")),
        "{tokens}"
    );
    let dir = d.state.data_dir.join("check");
    let left = std::fs::read_dir(&dir).map_or(0, |rd| rd.count());
    assert_eq!(left, 0, "nothing is left under <data_dir>/check/");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_check_at_a_time_and_delete_cleans_up() {
    let d = check_daemon().await;
    let (code, bytes) = raw(&d, inumaki_client::Method::POST, "/v1/check", "{}").await;
    assert_eq!(code, 201, "{}", String::from_utf8_lossy(&bytes));
    assert_bytes_round_trip::<inumaki_client::CheckCreated>(&bytes);
    let created = json(&bytes);
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(id.len(), 32);
    assert_eq!(created["paths"]["gateway"]["available"], true);
    assert!(
        created["gateway"]["url"]
            .as_str()
            .unwrap()
            .contains("/mcp/check-")
    );
    // M8's check routes are registered at startup (Task 9a).
    assert_eq!(created["paths"]["proxy"]["available"], true, "{created}");
    assert_eq!(created["paths"]["mirror"]["available"], true, "{created}");
    // §9.7 amendment 2026-10-10: the check's own source directory, which the
    // scripted Bash call reads, created by the daemon and removed with it.
    let source_dir = std::path::PathBuf::from(created["mirror"]["source_dir"].as_str().unwrap());
    assert!(source_dir.is_absolute() && source_dir.ends_with("source"));
    assert!(
        source_dir
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("inumaki-check-"))
    );
    assert!(source_dir.join("canary.txt").is_file());
    assert_eq!(
        source_dir,
        source_dir.canonicalize().unwrap(),
        "canonical: no /var symlink between the cat path and --add-dir"
    );
    let (code, _) = raw(&d, inumaki_client::Method::POST, "/v1/check", "{}").await;
    assert_eq!(code, 409, "one check at a time");
    let (code, _) = d
        .call(Method::DELETE, &format!("/v1/check/{id}"), None)
        .await;
    assert_eq!(code, 204);
    let (_, list) = d.call(Method::GET, "/v1/datasets", None).await;
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .all(|x| !x["id"].as_str().unwrap().starts_with("check-")),
        "{list}"
    );
    let (_, tokens) = d.call(Method::GET, "/v1/gateway/tokens", None).await;
    assert!(
        tokens
            .as_array()
            .unwrap()
            .iter()
            .all(|t| !t["label"].as_str().unwrap().starts_with("check:"))
    );
    assert!(!d.state.check.is_live());
    assert!(!source_dir.exists(), "DELETE removes the source directory");
    let (_, st) = d.call(Method::GET, "/v1/proxy", None).await;
    assert_eq!(st["check_routes"], 0, "DELETE removes both check routes");
    let (code, _) = raw(&d, inumaki_client::Method::POST, "/v1/check", "{}").await;
    assert_eq!(code, 201, "a new check can start after DELETE");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expired_check_is_removed_and_unknown_ids_are_404() {
    let d = check_daemon().await;
    d.state.check.set_ttl(Duration::from_millis(300));
    let (code, created) = d
        .call(
            Method::POST,
            "/v1/check",
            Some(serde_json::json!({ "paths": ["gateway"] })),
        )
        .await;
    assert_eq!(code, 201);
    let id = created["id"].as_str().unwrap().to_string();
    tokio::time::sleep(Duration::from_millis(500)).await;
    // An expired check is gone for every route and does not block a new one.
    let (code, _) = d
        .call(Method::POST, &format!("/v1/check/{id}/direct"), None)
        .await;
    assert_eq!(code, 404);
    assert_no_check_artifacts(&d).await;
    let (code, _) = d
        .call(Method::POST, "/v1/check", Some(serde_json::json!({})))
        .await;
    assert_eq!(code, 201);
    for bad in ["not-hex", "0123", "../../v1/status"] {
        let (code, _) = d.call(Method::GET, &format!("/v1/check/{bad}"), None).await;
        assert_eq!(code, 404, "{bad}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn check_routes_are_absent_from_the_tcp_router() {
    use tower::ServiceExt;
    let d = common::start().await;
    let tcp = inumakid::api::gateway::tcp_router(Arc::clone(&d.state), d.gateway_addr());
    let id = "0123456789abcdef0123456789abcdef";
    for (m, p) in [
        ("POST", "/v1/check".to_string()),
        ("GET", format!("/v1/check/{id}")),
        ("POST", format!("/v1/check/{id}/direct")),
        ("POST", format!("/v1/check/{id}/harness")),
        ("DELETE", format!("/v1/check/{id}")),
    ] {
        let req = axum::http::Request::builder()
            .method(m)
            .uri(&p)
            .header("host", d.gateway_addr().to_string())
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            tcp.clone().oneshot(req).await.unwrap().status(),
            404,
            "{m} {p}"
        );
    }
}

/// A prepare that fails half way (the canary server never starts, after the
/// dataset, the seeded canary, the upstream, and the token exist) answers a
/// fixed 500 and leaves nothing behind. Waits out the 15 s start deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_prepare_leaves_nothing_behind() {
    let d = common::start().await;
    let missing = d.state.data_dir.join("no-such-canary-program");
    d.state.check.set_canary_program(missing.clone());
    let (code, body) = d
        .call(Method::POST, "/v1/check", Some(serde_json::json!({})))
        .await;
    assert_eq!(code, 500, "{body}");
    assert_eq!(
        body["error"]["message"],
        "the check's canary server did not start"
    );
    let text = body.to_string();
    assert!(!text.contains(&*missing.to_string_lossy()), "{text}");
    assert!(!text.contains("check-"), "{text}");
    assert_no_check_artifacts(&d).await;
    assert!(!d.state.check.is_live());
    d.state
        .check
        .set_canary_program(env!("CARGO_BIN_EXE_inumakid").into());
    let (code, body) = d
        .call(Method::POST, "/v1/check", Some(serde_json::json!({})))
        .await;
    assert_eq!(code, 201, "{body}");
}

use inumakid::check::gateway_probe::{GatewayProbe, ProbeFuture};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_direct_check_passes_and_cleans_up() {
    let d = check_daemon().await;
    let (code, bytes) = raw(&d, inumaki_client::Method::POST, "/v1/check", "{}").await;
    assert_eq!(code, 201, "{}", String::from_utf8_lossy(&bytes));
    let created = json(&bytes);
    let id = created["id"].as_str().unwrap().to_string();
    // M5 and M8 are present: every path is available (check_full.rs pins
    // the mirror tree and the routes in detail).
    for p in ["gateway", "mirror", "proxy"] {
        assert_eq!(created["paths"][p]["available"], true, "{p}: {created}");
    }

    let (code, bytes) = raw(
        &d,
        inumaki_client::Method::POST,
        &format!("/v1/check/{id}/direct"),
        "",
    )
    .await;
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&bytes));
    assert_bytes_round_trip::<inumaki_client::CheckReport>(&bytes);
    let report = json(&bytes);
    let g = &report["results"]["gateway"];
    assert_eq!(g["status"], "passed", "{report}");
    assert_eq!(g["tokens_seen"], true);
    assert_eq!(g["rehydrated_in_output"], true);
    assert_eq!(g["canary_in_upstream"], false);
    assert_eq!(report["results"]["mirror"]["status"], "passed", "{report}");
    assert_eq!(report["results"]["proxy"]["status"], "passed", "{report}");
    let (code, latest) = d.call(Method::GET, &format!("/v1/check/{id}"), None).await;
    assert_eq!(code, 200);
    assert_eq!(latest["results"]["gateway"]["status"], "passed");

    let (code, _) = d
        .call(Method::DELETE, &format!("/v1/check/{id}"), None)
        .await;
    assert_eq!(code, 204);
}

/// Spec §11: a deliberately broken sanitizer makes the check fail.
struct Leaky(Canary);

impl GatewayProbe for Leaky {
    fn lookup(&self, _url: String, _token: String) -> ProbeFuture {
        let c = self.0.clone();
        Box::pin(async move { Some(format!("Record: {}, IBAN {}", c.full_name(), c.iban)) })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_leaking_gateway_fails_the_check() {
    let d = check_daemon().await;
    let c = Canary::generate();
    d.state.check.set_next_canary(c.clone());
    d.state.check.set_gateway_probe(Arc::new(Leaky(c)));
    let (_, created) = d
        .call(Method::POST, "/v1/check", Some(serde_json::json!({})))
        .await;
    let id = created["id"].as_str().unwrap();
    let (_, report) = d
        .call(Method::POST, &format!("/v1/check/{id}/direct"), None)
        .await;
    assert_eq!(report["results"]["gateway"]["status"], "failed");
    assert_eq!(report["results"]["gateway"]["reason"], "canary_in_upstream");
    assert_eq!(report["results"]["gateway"]["canary_in_upstream"], true);
}

use inumakid::check::proxy::{ProxyCheckRoutes, RecordedBody, ScriptStep};

type Recorded = Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>;
type Scripts = Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<ScriptStep>>>>;

/// A proxy that forwards the raw request to its "model" and records it:
/// the broken-sanitizer case for the proxy path. Its model follows M8's
/// scripted upstream as far as these tests need (spec M8 §12.1): the step
/// is the request's turn count (stateless), and a `CallTools` step whose
/// names match no advertised tool is skipped.
struct LeakyProxy {
    addr: std::net::SocketAddr,
    recorded: Recorded,
    scripts: Scripts,
    /// What `dropped` reports for every id (M8's recorder caps).
    dropped: std::sync::atomic::AtomicU64,
    /// (original, token) pairs applied to a body before it is recorded:
    /// empty is the broken sanitizer, filled a working one.
    rewrite: Rewrite,
}

type Rewrite = Arc<std::sync::Mutex<Vec<(String, String)>>>;

/// The step M8's scripted upstream answers `v` with, if `id` is registered.
fn scripted_step(steps: &[ScriptStep], v: &serde_json::Value) -> Option<ScriptStep> {
    let msgs = v["messages"].as_array().cloned().unwrap_or_default();
    let turn = msgs.iter().filter(|m| m["role"] == "assistant").count();
    let advertised: Vec<String> = v["tools"]
        .as_array()
        .map(|t| {
            t.iter()
                .filter_map(|t| t["name"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    steps
        .iter()
        .skip(turn.min(steps.len().saturating_sub(1)))
        .find(|s| match s {
            ScriptStep::CallTools(calls) => calls
                .iter()
                .any(|(suffix, _)| advertised.iter().any(|a| a.ends_with(suffix.as_str()))),
            _ => true,
        })
        .cloned()
}

impl LeakyProxy {
    async fn start() -> Arc<LeakyProxy> {
        let recorded: Recorded = Arc::default();
        let scripts: Scripts = Arc::default();
        let rewrite: Rewrite = Arc::default();
        let (rec, scr, rw) = (
            Arc::clone(&recorded),
            Arc::clone(&scripts),
            Arc::clone(&rewrite),
        );
        let app = axum::Router::new().route(
            "/check/{id}/anthropic/v1/messages",
            axum::routing::post(
                move |axum::extract::Path(id): axum::extract::Path<String>,
                      body: axum::body::Bytes| {
                    let (rec, scr, rw) = (Arc::clone(&rec), Arc::clone(&scr), Arc::clone(&rw));
                    async move {
                        let Some(steps) = scr.lock().unwrap().get(&id).cloned() else {
                            return (axum::http::StatusCode::NOT_FOUND, axum::Json(serde_json::json!({})));
                        };
                        let mut kept = String::from_utf8_lossy(&body).into_owned();
                        for (from, to) in rw.lock().unwrap().iter() {
                            kept = kept.replace(from.as_str(), to);
                        }
                        rec.lock().unwrap().push((id, kept.into_bytes()));
                        let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                        let text = match scripted_step(&steps, &v) {
                            Some(ScriptStep::EchoUserText) => v["messages"]
                                .as_array()
                                .and_then(|m| m.iter().rev().find(|m| m["role"] == "user"))
                                .and_then(|m| m["content"].as_str())
                                .unwrap_or_default()
                                .to_string(),
                            _ => "(no tool results)".to_string(),
                        };
                        (
                            axum::http::StatusCode::OK,
                            axum::Json(serde_json::json!({ "content": [{ "type": "text", "text": text }] })),
                        )
                    }
                },
            ),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        Arc::new(LeakyProxy {
            addr,
            recorded,
            scripts,
            dropped: Default::default(),
            rewrite,
        })
    }
}

impl ProxyCheckRoutes for LeakyProxy {
    fn register(
        &self,
        id: &str,
        _dataset: &str,
        script: Vec<ScriptStep>,
        _ttl: Duration,
    ) -> Vec<(String, String)> {
        self.scripts.lock().unwrap().insert(id.to_string(), script);
        vec![(
            "anthropic".into(),
            format!("http://{}/check/{id}/anthropic", self.addr),
        )]
    }
    fn recorded(&self, id: &str) -> Vec<RecordedBody> {
        self.recorded
            .lock()
            .unwrap()
            .iter()
            .filter(|(i, _)| i == id)
            .map(|(_, b)| RecordedBody {
                upstream: "anthropic".into(),
                body: b.clone(),
            })
            .collect()
    }
    fn remove(&self, id: &str) {
        self.scripts.lock().unwrap().remove(id);
    }
    fn dropped(&self, _id: &str) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_leaking_proxy_fails_the_proxy_path_and_an_unrouted_harness_is_reported() {
    let d = check_daemon().await;
    let proxy = LeakyProxy::start().await;
    d.state.check.set_proxy_routes(proxy.clone());
    let (code, created) = d
        .call(
            Method::POST,
            "/v1/check",
            Some(serde_json::json!({ "paths": ["gateway", "proxy"] })),
        )
        .await;
    assert_eq!(code, 201, "{created}");
    assert_eq!(created["paths"]["proxy"]["available"], true);
    assert!(
        created["proxy"]["routes"][0]["base_url"]
            .as_str()
            .unwrap()
            .contains("/check/")
    );
    let id = created["id"].as_str().unwrap().to_string();
    let (_, report) = d
        .call(Method::POST, &format!("/v1/check/{id}/direct"), None)
        .await;
    let p = &report["results"]["proxy"];
    assert_eq!(p["status"], "failed", "{report}");
    assert_eq!(p["reason"], "canary_in_upstream");
    assert_eq!(p["upstream_requests"], 1);
    // A second direct run is judged on its own request only.
    let (_, again) = d
        .call(Method::POST, &format!("/v1/check/{id}/direct"), None)
        .await;
    assert_eq!(again["results"]["proxy"]["upstream_requests"], 1, "{again}");
    // The harness route (the check id) saw no request: chat was not routed.
    let (_, h) = d
        .call(
            Method::POST,
            &format!("/v1/check/{id}/harness"),
            Some(serde_json::json!({ "harness": "codex", "output": "done", "exit_code": 0 })),
        )
        .await;
    assert_eq!(h["harness"], "codex");
    assert_eq!(h["results"]["proxy"]["reason"], "chat_not_routed", "{h}");
    let (_, h) = d
        .call(
            Method::POST,
            &format!("/v1/check/{id}/harness"),
            Some(serde_json::json!({ "harness": "codex", "output": "", "exit_code": 1 })),
        )
        .await;
    assert_eq!(h["results"]["gateway"]["reason"], "harness_failed", "{h}");
    // Cleanup: both routes (the harness route and the direct run's) are removed.
    let (code, _) = d
        .call(Method::DELETE, &format!("/v1/check/{id}"), None)
        .await;
    assert_eq!(code, 204);
    assert!(
        proxy.scripts.lock().unwrap().is_empty(),
        "every check route is removed"
    );
}

/// Review C3: each harness POST is judged only on the requests recorded after the previous one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_harness_run_is_judged_on_its_own_requests() {
    let d = check_daemon().await;
    let proxy = LeakyProxy::start().await;
    d.state.check.set_proxy_routes(proxy.clone());
    let (_, created) = d
        .call(
            Method::POST,
            "/v1/check",
            Some(serde_json::json!({ "paths": ["gateway", "proxy"] })),
        )
        .await;
    let id = created["id"].as_str().unwrap().to_string();
    // The first harness sent one request through the check route.
    proxy.recorded.lock().unwrap().push((
        id.clone(),
        br#"{"messages":[{"role":"user","content":"hello"}]}"#.to_vec(),
    ));
    let (_, first) = d
        .call(
            Method::POST,
            &format!("/v1/check/{id}/harness"),
            Some(serde_json::json!({ "harness": "claude-code", "output": "x", "exit_code": 0 })),
        )
        .await;
    assert_eq!(first["results"]["proxy"]["upstream_requests"], 1, "{first}");
    // The second harness sent nothing: the first one's request must not count for it.
    let (_, second) = d
        .call(
            Method::POST,
            &format!("/v1/check/{id}/harness"),
            Some(serde_json::json!({ "harness": "codex", "output": "x", "exit_code": 0 })),
        )
        .await;
    assert_eq!(
        second["results"]["proxy"]["upstream_requests"], 0,
        "{second}"
    );
    assert_eq!(second["results"]["proxy"]["reason"], "chat_not_routed");
}

/// A gateway result the check cannot rehydrate (store error) shows no
/// tokens, rather than tokens that were not restored.
struct Plain;

impl GatewayProbe for Plain {
    fn lookup(&self, _url: String, _token: String) -> ProbeFuture {
        Box::pin(async { Some("Record: <PERSON_a7f2c1>".to_string()) })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rehydrate_store_error_reports_no_tokens() {
    let d = check_daemon().await;
    d.state.check.set_gateway_probe(Arc::new(Plain));
    let (_, created) = d
        .call(
            Method::POST,
            "/v1/check",
            Some(serde_json::json!({ "paths": ["gateway"] })),
        )
        .await;
    let id = created["id"].as_str().unwrap().to_string();
    let url = created["gateway"]["url"].as_str().unwrap();
    let dataset = url.rsplit('/').next().unwrap().to_string();
    let st = Arc::clone(&d.state);
    tokio::task::spawn_blocking(move || st.delete_dataset(&dataset).unwrap())
        .await
        .unwrap();
    let (_, report) = d
        .call(Method::POST, &format!("/v1/check/{id}/direct"), None)
        .await;
    assert_eq!(
        report["results"]["gateway"]["reason"], "no_tokens",
        "{report}"
    );
}

/// A leak in a later harness run is caught after the earlier runs' requests are skipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_leak_in_a_later_harness_run_is_caught() {
    let d = check_daemon().await;
    let c = Canary::generate();
    d.state.check.set_next_canary(c.clone());
    let proxy = LeakyProxy::start().await;
    d.state.check.set_proxy_routes(proxy.clone());
    let (_, created) = d
        .call(
            Method::POST,
            "/v1/check",
            Some(serde_json::json!({ "paths": ["gateway", "proxy"] })),
        )
        .await;
    let id = created["id"].as_str().unwrap().to_string();
    let harness = |n: &str| {
        let body = serde_json::json!({ "messages": [{ "role": "user", "content": n }] });
        proxy
            .recorded
            .lock()
            .unwrap()
            .push((id.clone(), body.to_string().into_bytes()));
    };
    let route = format!("/v1/check/{id}/harness");
    let post = || {
        d.call(
            Method::POST,
            &route,
            Some(serde_json::json!({ "harness": "codex", "output": "x", "exit_code": 0 })),
        )
    };
    harness("Record: <PERSON_a7f2c1>");
    let (_, first) = post().await;
    assert_eq!(
        first["results"]["proxy"]["canary_in_upstream"], false,
        "{first}"
    );
    harness(&format!("Record: {}", c.full_name()));
    let (_, second) = post().await;
    let p = &second["results"]["proxy"];
    assert_eq!(p["reason"], "canary_in_upstream", "{second}");
    assert_eq!(p["upstream_requests"], 1);
}

/// M8's recorder dropped a body: it was never inspected, so the run fails closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_route_with_dropped_bodies_never_passes() {
    let d = check_daemon().await;
    let c = Canary::generate();
    d.state.check.set_next_canary(c.clone());
    let proxy = LeakyProxy::start().await;
    d.state.check.set_proxy_routes(proxy.clone());
    let (_, created) = d
        .call(
            Method::POST,
            "/v1/check",
            Some(serde_json::json!({ "paths": ["gateway", "proxy"] })),
        )
        .await;
    let id = created["id"].as_str().unwrap().to_string();
    proxy.recorded.lock().unwrap().push((
        id.clone(),
        br#"{"messages":[{"role":"user","content":"Record: <PERSON_a7f2c1>"}]}"#.to_vec(),
    ));
    proxy.dropped.store(1, std::sync::atomic::Ordering::SeqCst);
    let output = format!("Record: {}, IBAN {}", c.full_name(), c.iban);
    let (_, h) = d
        .call(
            Method::POST,
            &format!("/v1/check/{id}/harness"),
            Some(serde_json::json!({ "harness": "codex", "output": output, "exit_code": 0 })),
        )
        .await;
    let p = &h["results"]["proxy"];
    assert_eq!(p["status"], "failed", "{h}");
    assert_eq!(p["reason"], "harness_failed");
}

/// Review of Task 9a: a store that loses bodies without counting them
/// (`dropped` stays 0) fails the run that sees the loss, and every later
/// run too, even after it refills past the count already judged (the
/// bodies skipped then were never inspected).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_uncounted_loss_fails_every_later_run() {
    let d = check_daemon().await;
    let c = Canary::generate();
    d.state.check.set_next_canary(c.clone());
    let proxy = LeakyProxy::start().await;
    d.state.check.set_proxy_routes(proxy.clone());
    let (_, created) = d
        .call(
            Method::POST,
            "/v1/check",
            Some(serde_json::json!({ "paths": ["gateway", "proxy"] })),
        )
        .await;
    let id = created["id"].as_str().unwrap().to_string();
    // A real token of the check dataset, so a sanitized body shows tokens.
    let token = {
        use inumaki_core::token::TokenStore;
        let ns = d
            .state
            .namespace(&inumakid::check::check_dataset_id(&id))
            .unwrap();
        let mut n = ns.lock().unwrap();
        n.token_for(&inumaki_core::span::EntityKind::Person, &c.full_name())
            .unwrap()
            .as_str()
            .to_string()
    };
    let sanitized = format!(r#"{{"messages":[{{"role":"user","content":"Record: {token}"}}]}}"#);
    let push = |n: usize| {
        let mut r = proxy.recorded.lock().unwrap();
        for _ in 0..n {
            r.push((id.clone(), sanitized.clone().into_bytes()));
        }
    };
    let output = format!("Record: {}, IBAN {}", c.full_name(), c.iban);
    let path = format!("/v1/check/{id}/harness");
    let harness = || {
        d.call(
            Method::POST,
            &path,
            Some(serde_json::json!({ "harness": "codex", "output": output, "exit_code": 0 })),
        )
    };
    push(2);
    let (_, first) = harness().await;
    assert_eq!(first["results"]["proxy"]["status"], "passed", "{first}");
    // The store loses both judged bodies and counts nothing.
    proxy.recorded.lock().unwrap().clear();
    assert_eq!(proxy.dropped.load(std::sync::atomic::Ordering::SeqCst), 0);
    let (_, second) = harness().await;
    assert_eq!(
        second["results"]["proxy"]["reason"], "harness_failed",
        "{second}"
    );
    // Refilled past the old count: the loss is remembered.
    push(3);
    let (_, third) = harness().await;
    let p = &third["results"]["proxy"];
    assert_eq!(p["status"], "failed", "{third}");
    assert_eq!(p["reason"], "harness_failed");
    assert_eq!(p["tokens_seen"], true, "the new body was still inspected");
}

/// Final review of Task 9a: the direct run's route keeps its own sticky
/// loss flag. The fake records sanitized bodies (it rewrites the canary to
/// the check dataset's tokens), so the loss flag, not a leak, decides.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_uncounted_loss_on_the_direct_route_fails_every_later_direct_run() {
    let d = check_daemon().await;
    let c = Canary::generate();
    d.state.check.set_next_canary(c.clone());
    let proxy = LeakyProxy::start().await;
    d.state.check.set_proxy_routes(proxy.clone());
    let (_, created) = d
        .call(
            Method::POST,
            "/v1/check",
            Some(serde_json::json!({ "paths": ["gateway", "proxy"] })),
        )
        .await;
    let id = created["id"].as_str().unwrap().to_string();
    {
        use inumaki_core::span::EntityKind;
        use inumaki_core::token::TokenStore;
        let ns = d
            .state
            .namespace(&inumakid::check::check_dataset_id(&id))
            .unwrap();
        let mut n = ns.lock().unwrap();
        let mut rw = proxy.rewrite.lock().unwrap();
        for (kind, value) in [
            (EntityKind::Person, c.full_name()),
            (EntityKind::Iban, c.iban.clone()),
            (EntityKind::Email, c.email.clone()),
        ] {
            let token = n.token_for(&kind, &value).unwrap().as_str().to_string();
            rw.push((value, token));
        }
    }
    let direct_id = proxy
        .scripts
        .lock()
        .unwrap()
        .keys()
        .find(|k| **k != id)
        .cloned()
        .expect("the direct run's route");
    let sanitized = proxy.rewrite.lock().unwrap()[0].1.clone();
    let push = || {
        proxy.recorded.lock().unwrap().push((
            direct_id.clone(),
            format!(r#"{{"messages":[{{"role":"user","content":"Record: {sanitized}"}}]}}"#)
                .into_bytes(),
        ));
    };
    let path = format!("/v1/check/{id}/direct");
    // Run 1 judges two bodies (one pushed, one its own) and passes.
    push();
    let (_, first) = d.call(Method::POST, &path, None).await;
    let p = &first["results"]["proxy"];
    assert_eq!(p["status"], "passed", "{first}");
    assert_eq!(p["upstream_requests"], 2);
    // The store loses the direct route's bodies and counts nothing.
    proxy
        .recorded
        .lock()
        .unwrap()
        .retain(|(i, _)| *i != direct_id);
    assert_eq!(proxy.dropped.load(std::sync::atomic::Ordering::SeqCst), 0);
    let (_, second) = d.call(Method::POST, &path, None).await;
    let p = &second["results"]["proxy"];
    assert_eq!(p["canary_in_upstream"], false, "{second}");
    assert_eq!(p["reason"], "harness_failed", "{second}");
    // Refilled past the old count (3 > 2): the new body is inspected and
    // passes on its own, but the loss is remembered.
    push();
    let (_, third) = d.call(Method::POST, &path, None).await;
    let p = &third["results"]["proxy"];
    assert_eq!(p["canary_in_upstream"], false, "{third}");
    assert_eq!(p["tokens_seen"], true, "{third}");
    assert_eq!(p["rehydrated_in_output"], true, "{third}");
    assert_eq!(p["status"], "failed");
    assert_eq!(p["reason"], "harness_failed");
}

/// Check routes that register the harness route but not the direct run's.
#[derive(Default)]
struct HalfRoutes {
    registered: std::sync::Mutex<Vec<String>>,
    removed: std::sync::Mutex<Vec<String>>,
}

impl ProxyCheckRoutes for HalfRoutes {
    fn register(
        &self,
        id: &str,
        _dataset: &str,
        _script: Vec<ScriptStep>,
        _ttl: Duration,
    ) -> Vec<(String, String)> {
        let mut r = self.registered.lock().unwrap();
        r.push(id.to_string());
        if r.len() == 1 {
            vec![(
                "anthropic".into(),
                format!("http://127.0.0.1:9/check/{id}/anthropic"),
            )]
        } else {
            vec![]
        }
    }
    fn recorded(&self, _id: &str) -> Vec<RecordedBody> {
        vec![]
    }
    fn remove(&self, id: &str) {
        self.removed.lock().unwrap().push(id.to_string());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_half_registered_proxy_path_is_unavailable_and_unregistered() {
    let d = check_daemon().await;
    let routes = Arc::new(HalfRoutes::default());
    d.state.check.set_proxy_routes(routes.clone());
    let (code, created) = d
        .call(
            Method::POST,
            "/v1/check",
            Some(serde_json::json!({ "paths": ["gateway", "proxy"] })),
        )
        .await;
    assert_eq!(code, 201, "{created}");
    assert_eq!(created["paths"]["proxy"]["reason"], "proxy_unavailable");
    assert!(created["proxy"].is_null(), "{created}");
    let mut registered = routes.registered.lock().unwrap().clone();
    let mut removed = routes.removed.lock().unwrap().clone();
    registered.sort();
    removed.sort();
    assert_eq!(registered.len(), 2);
    assert_eq!(removed, registered, "both route ids are removed");
}

/// Forced routes on a daemon whose proxy is not running (disabled here; a
/// bind failure reads the same through `status().state`) hand out no URL:
/// whatever listens on that port would get the check conversation and the
/// harness's credentials. Nothing is registered either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn check_routes_are_not_offered_while_the_proxy_is_not_running() {
    let d = common::start_with(
        "",
        "[proxy]\nlisten = \"127.0.0.1:0\"\nenabled = false\n",
        Duration::from_secs(3600),
        None,
    )
    .await;
    d.state
        .check
        .set_canary_program(env!("CARGO_BIN_EXE_inumakid").into());
    let proxy = LeakyProxy::start().await;
    d.state.check.set_proxy_routes(proxy.clone());
    let (code, created) = d
        .call(
            Method::POST,
            "/v1/check",
            Some(serde_json::json!({ "paths": ["gateway", "proxy"] })),
        )
        .await;
    assert_eq!(code, 201, "{created}");
    assert_eq!(created["paths"]["proxy"]["available"], false, "{created}");
    assert_eq!(created["paths"]["proxy"]["reason"], "proxy_unavailable");
    assert!(created["proxy"].is_null(), "{created}");
    assert!(
        !created.to_string().contains("/check/"),
        "no route URL anywhere: {created}"
    );
    assert!(
        proxy.scripts.lock().unwrap().is_empty(),
        "nothing is registered"
    );
}

/// A proxy listener that ends, with an error or gracefully, stops reading as
/// `running`, and the check then hands out no proxy route (its address is
/// free for any other process).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ended_proxy_listener_is_not_running_and_offers_no_check_route() {
    for ended in [Err(std::io::Error::other("the accept loop died")), Ok(())] {
        let d = check_daemon().await;
        let create = || {
            d.call(
                Method::POST,
                "/v1/check",
                Some(serde_json::json!({ "paths": ["gateway", "proxy"] })),
            )
        };
        // While it serves: running, routes offered.
        let (_, status) = d.call(Method::GET, "/v1/proxy", None).await;
        assert_eq!(status["state"], "running", "{status}");
        let (code, created) = create().await;
        assert_eq!(code, 201, "{created}");
        assert_eq!(created["paths"]["proxy"]["available"], true, "{created}");
        let id = created["id"].as_str().unwrap().to_string();
        let (code, _) = d
            .call(Method::DELETE, &format!("/v1/check/{id}"), None)
            .await;
        assert_eq!(code, 204);
        // After the end: not running, no route.
        inumakid::server::proxy_serve_ended(&d.state, ended);
        let (_, status) = d.call(Method::GET, "/v1/proxy", None).await;
        assert_eq!(status["state"], "bind_failed", "{status}");
        let (code, created) = create().await;
        assert_eq!(code, 201, "{created}");
        assert_eq!(created["paths"]["proxy"]["available"], false, "{created}");
        assert_eq!(created["paths"]["proxy"]["reason"], "proxy_unavailable");
        assert!(created["proxy"].is_null(), "{created}");
    }
}

/// The listener ends after the check was created: the direct run sends
/// nothing to the (now free) address, reports the proxy path as not checked,
/// and the route records no new request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_direct_run_after_the_proxy_listener_ended_sends_nothing() {
    let d = check_daemon().await;
    let proxy = LeakyProxy::start().await;
    d.state.check.set_proxy_routes(proxy.clone());
    let (code, created) = d
        .call(
            Method::POST,
            "/v1/check",
            Some(serde_json::json!({ "paths": ["gateway", "proxy"] })),
        )
        .await;
    assert_eq!(code, 201, "{created}");
    assert_eq!(created["paths"]["proxy"]["available"], true, "{created}");
    let id = created["id"].as_str().unwrap().to_string();
    let direct = format!("/v1/check/{id}/direct");
    // While it serves, the direct run reaches the route.
    let (_, report) = d.call(Method::POST, &direct, None).await;
    assert_eq!(
        report["results"]["proxy"]["upstream_requests"], 1,
        "{report}"
    );
    let seen = proxy.recorded.lock().unwrap().len();
    assert!(seen > 0);
    // The listener ends; the same check is asked again.
    inumakid::server::proxy_serve_ended(&d.state, Err(std::io::Error::other("gone")));
    let (code, report) = d.call(Method::POST, &direct, None).await;
    assert_eq!(code, 200, "{report}");
    let p = &report["results"]["proxy"];
    assert_eq!(p["status"], "not_checked", "{report}");
    assert_eq!(p["reason"], "proxy_unavailable", "{report}");
    assert_eq!(
        proxy.recorded.lock().unwrap().len(),
        seen,
        "nothing new was sent to the route"
    );
}

/// A vault failure during prepare (here: the upstream row is refused) is a
/// fixed 500, never the vault's `Display` text and never the 409 the
/// contract keeps for "a check is live"; nothing is left behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_vault_failure_in_prepare_is_a_fixed_500() {
    let d = common::start().await;
    // An empty command makes `add_upstream` fail with `InvalidUpstream`.
    d.state.check.set_canary_program(std::path::PathBuf::new());
    let (code, body) = d
        .call(Method::POST, "/v1/check", Some(serde_json::json!({})))
        .await;
    assert_eq!(code, 500, "{body}");
    assert_eq!(body["error"]["message"], "check dataset");
    let text = body.to_string();
    assert!(
        !text.contains(&*d.state.data_dir.to_string_lossy()),
        "{text}"
    );
    assert!(!text.contains("check-"), "{text}");
    assert_no_check_artifacts(&d).await;
    assert!(!d.state.check.is_live());
}

/// The sweep deletes only the generated shapes (spec §8 amendment
/// 2026-10-04): a user's `check-notes` from before the reservation and a
/// non-generated `check:` label survive.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_startup_sweep_spares_user_check_names() {
    let d = common::start().await;
    let st = Arc::clone(&d.state);
    tokio::task::spawn_blocking(move || {
        for id in ["check-notes", "check-0123456789ab", "check-0123456789ab-f"] {
            st.vault
                .create_dataset(&inumaki_vault::DatasetSpec::new(id, "x", "offline"))
                .unwrap();
        }
        st.vault.create_gateway_token("check:mine").unwrap();
        st.vault.create_gateway_token("check:0123456789ab").unwrap();
    })
    .await
    .unwrap();
    let mut removed = inumakid::check::sweep_leftovers(&d.state).await;
    removed.sort();
    assert_eq!(removed, ["check-0123456789ab", "check-0123456789ab-f"]);
    let (_, list) = d.call(Method::GET, "/v1/datasets", None).await;
    let ids: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .filter(|d| d["kind"] != "chat")
        .map(|d| d["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["check-notes"]);
    let (_, tokens) = d.call(Method::GET, "/v1/gateway/tokens", None).await;
    let labels: Vec<&str> = tokens
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["label"].as_str().unwrap())
        .collect();
    assert_eq!(labels, ["check:mine"]);
}
