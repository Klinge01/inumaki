//! `GET /v1/service` and `POST/GET /v1/models/pull` (M6 spec §7.2, §9.7):
//! contract shapes, one job at a time, failure classes, control socket only.

mod common;

use std::time::Duration;

use axum::Router;
use axum::routing::get;
use hyper::Method;
use inumaki_client::contract::assert_bytes_round_trip;
use inumaki_models::manifest::Manifest;
use sha2::{Digest, Sha256};

/// The three files `Manifest::parse` requires (roles model, tokenizer, config).
const FILES: [(&str, &str, &[u8]); 3] = [
    ("model.onnx", "model", b"tiny-model-bytes"),
    ("tokenizer.json", "tokenizer", b"{\"tiny\":\"tokenizer\"}"),
    ("config.json", "config", b"{\"tiny\":\"config\"}"),
];
const GOOD: &[u8] = FILES[0].2;

fn hex(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// A manifest with one model `tiny` of three files (the model file's pinned
/// hash is wrong when `bad_hash`).
fn manifest(bad_hash: bool) -> Manifest {
    let mut toml = String::from(
        "[[models]]\nname = \"tiny\"\nkind = \"gliner\"\nrepo = \"test/tiny\"\n\
         revision = \"0000000000000000000000000000000000000000\"\nlicense = \"Apache-2.0\"\n\
         license_url = \"https://example.invalid/license\"\ndefault = true\n",
    );
    for (i, (path, role, bytes)) in FILES.iter().enumerate() {
        let sha = if bad_hash && i == 0 {
            "0".repeat(64)
        } else {
            hex(bytes)
        };
        toml.push_str(&format!("[[models.files]]\npath = \"{path}\"\nrole = \"{role}\"\nsha256 = \"{sha}\"\nsize = {}\n", bytes.len()));
    }
    Manifest::parse(&toml).unwrap()
}

/// Serves the three files at `/test/tiny/resolve/<rev>/<file>` after `delay`.
async fn file_server(delay: Duration) -> String {
    let app = Router::new().route(
        "/test/tiny/resolve/{rev}/{file}",
        get(move |axum::extract::Path((_rev, file)): axum::extract::Path<(String, String)>| async move {
            tokio::time::sleep(delay).await;
            FILES.iter().find(|(p, _, _)| *p == file).map(|(_, _, b)| b.to_vec()).unwrap_or_default()
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{addr}")
}

async fn wait_job(d: &common::TestDaemon) -> serde_json::Value {
    // Adaptation: the brief's budget was 200 * 25ms = 5s, but the 409 test
    // below serves three files at a 2s artificial delay each (~6s total for
    // a sequential `pull`), so the original budget starved before the job
    // finished. 400 iterations (10s) covers that with headroom while adding
    // no latency to the fast (`Duration::ZERO`) tests, which return on the
    // first check.
    for _ in 0..400 {
        let (code, body) = d.call(Method::GET, "/v1/models/pull", None).await;
        assert_eq!(code, 200);
        if body["state"] != "running" {
            return body;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("the job did not finish");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_body_matches_the_contract() {
    let d = common::start().await;
    // The typed client's raw call returns the body bytes (M6-0 Task 1).
    let r = inumaki_client::Client::new(&d.socket)
        .raw(inumaki_client::Method::GET, "/v1/service", Vec::new())
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    assert_bytes_round_trip::<inumaki_client::ServiceBody>(&r.body);
    let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(v["restart_required"], false);
    // Tests do not set INUMAKI_MANAGED_BY.
    assert_eq!(v["managed_by"], "manual");
    assert_eq!(v["pid"], std::process::id());
}

#[test]
fn managed_by_maps_the_closed_set_and_defaults_to_manual() {
    use inumakid::api::service::{ManagedBy, managed_by_from};
    assert_eq!(managed_by_from(Some("app")), ManagedBy::App);
    assert_eq!(managed_by_from(Some("homebrew")), ManagedBy::Homebrew);
    assert_eq!(managed_by_from(Some("deb")), ManagedBy::Deb);
    assert_eq!(managed_by_from(Some("launchd")), ManagedBy::Manual);
    assert_eq!(managed_by_from(None), ManagedBy::Manual);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_download_finishes_verified_and_requires_a_restart() {
    let d = common::start().await;
    d.state
        .models_job
        .set_source(manifest(false), file_server(Duration::ZERO).await);
    let (code, body) = d
        .call(Method::POST, "/v1/models/pull", Some(serde_json::json!({})))
        .await;
    assert_eq!(code, 202, "{body}");
    let job = wait_job(&d).await;
    // Adaptation: `d.call` decodes the body into `serde_json::Value`, whose
    // `Map` is a `BTreeMap` in this workspace (no crate turns on
    // `serde_json`'s `preserve_order` feature), so re-encoding `job` always
    // sorts keys alphabetically regardless of what the daemon sent. The
    // byte-for-byte field-order check needs the actual wire bytes, the same
    // way `service_body_matches_the_contract` gets them.
    let raw = inumaki_client::Client::new(&d.socket)
        .raw(inumaki_client::Method::GET, "/v1/models/pull", Vec::new())
        .await
        .unwrap();
    assert_bytes_round_trip::<inumaki_client::ModelsJob>(&raw.body);
    assert_eq!(job["state"], "done", "{job}");
    assert_eq!(job["files"].as_array().unwrap().len(), 3);
    assert!(
        job["files"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["verified"] == true && f["bytes_done"] == f["bytes_total"]),
        "{job}"
    );
    assert_eq!(job["restart_required"], true);
    let (_, svc) = d.call(Method::GET, "/v1/service", None).await;
    assert_eq!(svc["restart_required"], true);
    let file = d.state.engines.models_dir().join("tiny").join("model.onnx");
    assert_eq!(std::fs::read(file).unwrap(), GOOD);
    // A second pull (nothing left to fetch) does not clear the pending restart:
    // only a new process loads the models.
    let (code, _) = d
        .call(Method::POST, "/v1/models/pull", Some(serde_json::json!({})))
        .await;
    assert_eq!(code, 202);
    let (_, running_or_done) = d.call(Method::GET, "/v1/models/pull", None).await;
    assert_eq!(running_or_done["restart_required"], true);
    wait_job(&d).await;
    let (_, svc) = d.call(Method::GET, "/v1/service", None).await;
    assert_eq!(svc["restart_required"], true);
}

#[test]
fn homebrew_bin_dir_is_the_stable_opt_path() {
    use inumakid::api::service::homebrew_bin_dir;
    let exe = std::path::Path::new("/opt/homebrew/Cellar/inumaki/0.1.0/bin/inumakid");
    assert_eq!(
        homebrew_bin_dir(exe).unwrap(),
        std::path::Path::new("/opt/homebrew/opt/inumaki/bin")
    );
    assert_eq!(
        homebrew_bin_dir(std::path::Path::new("/usr/local/bin/inumakid")),
        None
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_pull_while_running_is_409_and_unknown_models_are_400() {
    let d = common::start().await;
    d.state
        .models_job
        .set_source(manifest(false), file_server(Duration::from_secs(2)).await);
    let (code, _) = d
        .call(Method::POST, "/v1/models/pull", Some(serde_json::json!({})))
        .await;
    assert_eq!(code, 202);
    let (code, body) = d
        .call(Method::POST, "/v1/models/pull", Some(serde_json::json!({})))
        .await;
    assert_eq!(code, 409, "{body}");
    assert_eq!(body["error"]["type"], "conflict");
    wait_job(&d).await;
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/models/pull",
            Some(serde_json::json!({ "models": ["nope"] })),
        )
        .await;
    assert_eq!(code, 400, "{body}");
    assert!(
        !body.to_string().contains("nope"),
        "the message is fixed: {body}"
    );
}

/// Review Focus 5.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_download_reports_its_class_and_can_be_retried() {
    let d = common::start().await;
    d.state
        .models_job
        .set_source(manifest(true), file_server(Duration::ZERO).await);
    d.call(Method::POST, "/v1/models/pull", Some(serde_json::json!({})))
        .await;
    let job = wait_job(&d).await;
    assert_eq!(job["state"], "failed");
    assert_eq!(job["error"], "hash_mismatch");
    assert_eq!(job["restart_required"], false);
    let dir = d.state.engines.models_dir().join("tiny");
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .map(|r| r.filter_map(Result::ok).map(|e| e.file_name()).collect())
        .unwrap_or_default();
    assert!(
        leftovers
            .iter()
            .all(|n| !n.to_string_lossy().ends_with(".part")),
        "{leftovers:?}"
    );
    // Nothing listens on port 9 of loopback: a network failure.
    d.state
        .models_job
        .set_source(manifest(false), "http://127.0.0.1:9".to_string());
    let (code, _) = d
        .call(Method::POST, "/v1/models/pull", Some(serde_json::json!({})))
        .await;
    assert_eq!(code, 202, "a failed job does not block the next one");
    let job = wait_job(&d).await;
    assert_eq!(job["error"], "network");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_and_models_are_absent_from_the_tcp_router() {
    use tower::ServiceExt;
    let d = common::start().await;
    let tcp = inumakid::api::gateway::tcp_router(std::sync::Arc::clone(&d.state), d.gateway_addr());
    for (m, p) in [
        ("GET", "/v1/service"),
        ("GET", "/v1/models/pull"),
        ("POST", "/v1/models/pull"),
    ] {
        let req = axum::http::Request::builder()
            .method(m)
            .uri(p)
            .header("host", d.gateway_addr().to_string())
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tcp.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            404,
            "{m} {p} must not be on the TCP listener"
        );
    }
}
