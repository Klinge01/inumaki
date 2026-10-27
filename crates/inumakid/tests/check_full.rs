//! Exit criterion 5 (roadmap spec §2.1): the end-to-end check covers the
//! gateway, the mirror (M5), and the proxy (M8), all three in process, with
//! M8's real check routes registered at startup (M6-3 Task 9a).

mod common;

use std::time::Duration;

use hyper::Method;
use inumakid::check::canary::Canary;

/// A daemon whose canary upstream is the real daemon binary. The test
/// daemons listen on an ephemeral proxy port and mirror into their temp
/// directory (tests/common).
async fn daemon() -> common::TestDaemon {
    let d = common::start().await;
    d.state
        .check
        .set_canary_program(env!("CARGO_BIN_EXE_inumakid").into());
    d
}

fn no_check_folders(folders: &serde_json::Value) -> bool {
    folders["folders"]
        .as_array()
        .unwrap()
        .iter()
        .all(|f| !f["dataset"].as_str().unwrap().starts_with("check-"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_check_passes_on_all_three_paths() {
    let d = daemon().await;
    let c = Canary::generate();
    d.state.check.set_next_canary(c.clone());
    let (code, created) = d
        .call(Method::POST, "/v1/check", Some(serde_json::json!({})))
        .await;
    assert_eq!(code, 201, "{created}");
    for p in ["gateway", "mirror", "proxy"] {
        assert_eq!(created["paths"][p]["available"], true, "{p}: {created}");
    }
    let upstreams: Vec<&str> = created["proxy"]["routes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["upstream"].as_str().unwrap())
        .collect();
    assert_eq!(upstreams, ["anthropic", "openai", "openai-codex"]);
    let mirrored_path = std::path::PathBuf::from(created["mirror"]["path"].as_str().unwrap());
    let id = created["id"].as_str().unwrap().to_string();

    let (code, report) = d
        .call(Method::POST, &format!("/v1/check/{id}/direct"), None)
        .await;
    assert_eq!(code, 200, "{report}");
    for p in ["gateway", "mirror", "proxy"] {
        let r = &report["results"][p];
        assert_eq!(r["status"], "passed", "{p}: {report}");
        assert_eq!(r["canary_in_upstream"], false, "{p}");
        assert_eq!(r["tokens_seen"], true, "{p}");
        assert_eq!(r["rehydrated_in_output"], true, "{p}");
    }
    // The agent-readable file holds tokens, never the canary.
    let mirrored = std::fs::read_to_string(&mirrored_path).unwrap();
    assert!(mirrored.contains("<PERSON_"), "tokens in the mirror");
    assert!(!c.appears_in(&mirrored), "no canary in the mirror");

    // A second direct run is judged on its own requests and passes again.
    let (_, again) = d
        .call(Method::POST, &format!("/v1/check/{id}/direct"), None)
        .await;
    assert_eq!(again["results"]["proxy"]["status"], "passed", "{again}");
    assert_eq!(again["results"]["proxy"]["upstream_requests"], 1);

    let (code, folders) = d.call(Method::GET, "/v1/folders", None).await;
    assert_eq!(code, 200);
    assert!(
        !no_check_folders(&folders),
        "the check folder is listed while live"
    );
    let (code, _) = d
        .call(Method::DELETE, &format!("/v1/check/{id}"), None)
        .await;
    assert_eq!(code, 204);
    let (_, folders) = d.call(Method::GET, "/v1/folders", None).await;
    assert!(no_check_folders(&folders), "{folders}");
    let mirror_dir = mirrored_path.parent().unwrap();
    assert!(
        !mirror_dir.exists(),
        "the mirror tree went with the check's folder"
    );
    let (_, st) = d.call(Method::GET, "/v1/proxy", None).await;
    assert_eq!(st["check_routes"], 0, "both check routes are removed");
    d.stop().await;
}

/// M8-2/M8-3 review item 1: M8's drop count reaches the check through
/// `M8Routes`. 257 requests on one route: 256 are kept, one is dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropped_bodies_reach_the_check() {
    use inumakid::check::proxy::{ProxyCheckRoutes, ScriptStep};
    let d = common::start().await;
    let proxy = d.state.proxy.get().expect("the proxy started");
    let listen: std::net::SocketAddr = proxy.status().listen.parse().unwrap();
    let routes = inumakid::check::proxy_m8::M8Routes::new(proxy.check_routes(), listen);
    let id = "0123456789abcdef0123456789abcdef";
    let ds = inumakid::check::check_dataset_id(id);
    d.state
        .vault
        .create_dataset(&inumaki_vault::DatasetSpec::new(&ds, "check", "offline"))
        .unwrap();
    let urls = routes.register(
        id,
        &ds,
        vec![ScriptStep::EchoUserText],
        Duration::from_secs(600),
    );
    let base = urls
        .iter()
        .find(|(u, _)| u == "anthropic")
        .unwrap()
        .1
        .clone();
    let c = reqwest::Client::new();
    for i in 0..257 {
        let r = c
            .post(format!("{base}/v1/messages"))
            .header("anthropic-version", "2023-06-01")
            .header("x-api-key", "inumaki-check-dummy")
            .json(
                &serde_json::json!({"model": "inumaki-check", "max_tokens": 16,
                "messages": [{"role": "user", "content": format!("turn {i}")}]}),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "request {i}");
    }
    assert_eq!(routes.recorded(id).len(), 256);
    assert_eq!(routes.dropped(id), 1, "the drop count reaches the check");
    routes.remove(id);
    assert_eq!(routes.dropped(id), 0);
    d.stop().await;
}

/// A harness route re-registered mid-check loses the bodies it held: M8
/// counts them as dropped, so the next harness run fails closed even when
/// the route has recorded as many new bodies as were judged before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_re_registration_that_loses_bodies_fails_closed() {
    let d = daemon().await;
    let c = Canary::generate();
    d.state.check.set_next_canary(c.clone());
    let (code, created) = d
        .call(
            Method::POST,
            "/v1/check",
            Some(serde_json::json!({ "paths": ["gateway", "proxy"] })),
        )
        .await;
    assert_eq!(code, 201, "{created}");
    let id = created["id"].as_str().unwrap().to_string();
    let base = created["proxy"]["routes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["upstream"] == "anthropic")
        .unwrap()["base_url"]
        .as_str()
        .unwrap()
        .to_string();
    let http = reqwest::Client::new();
    let turn = || async {
        let r = http
            .post(format!("{base}/v1/messages"))
            .header("anthropic-version", "2023-06-01")
            .header("x-api-key", "inumaki-check-dummy")
            .json(
                &serde_json::json!({"model": "inumaki-check", "max_tokens": 64,
                "messages": [{"role": "user", "content": format!("Record: {}", c.full_name())}]}),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    };
    let harness_path = format!("/v1/check/{id}/harness");
    let harness = |output: String| {
        d.call(
            Method::POST,
            &harness_path,
            Some(serde_json::json!({ "harness": "codex", "output": output, "exit_code": 0 })),
        )
    };
    let output = format!("Record: {}, IBAN {}", c.full_name(), c.iban);
    turn().await;
    let (_, first) = harness(output.clone()).await;
    assert_eq!(first["results"]["proxy"]["status"], "passed", "{first}");
    // The route is re-registered: its one judged body is discarded.
    let routes = d.state.proxy.get().unwrap().check_routes();
    routes.register(
        inumaki_proxy::CheckId::from_hex(&id).unwrap(),
        &inumakid::check::check_dataset_id(&id),
        inumaki_proxy::Script(vec![inumaki_proxy::Step::EchoUserText]),
        Duration::from_secs(600),
    );
    turn().await;
    let (_, second) = harness(output).await;
    let p = &second["results"]["proxy"];
    assert_eq!(p["status"], "failed", "{second}");
    assert_eq!(p["reason"], "harness_failed");
    d.call(Method::DELETE, &format!("/v1/check/{id}"), None)
        .await;
    d.stop().await;
}

/// The startup sweep with M5 present (review item 5): a crash left a check
/// folder dataset with a mirror tree; the sweep deletes its folder first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_startup_sweep_removes_a_check_folder_and_its_mirror() {
    let d = daemon().await;
    let (code, created) = d
        .call(
            Method::POST,
            "/v1/check",
            Some(serde_json::json!({ "paths": ["mirror"] })),
        )
        .await;
    assert_eq!(code, 201, "{created}");
    assert_eq!(created["paths"]["mirror"]["available"], true, "{created}");
    let mirrored = std::path::PathBuf::from(created["mirror"]["path"].as_str().unwrap());
    let mirror_dir = mirrored.parent().unwrap().to_path_buf();
    assert!(mirror_dir.exists());
    // Simulate the crash: the live check is forgotten, its artifacts stay.
    let live = d.state.check.take_live_for_tests().expect("a live check");
    let tmp_root = live.mirror.as_ref().unwrap().tmp_root.clone();
    std::mem::forget(live);
    let removed = inumakid::check::sweep_leftovers(&d.state).await;
    assert!(removed.iter().any(|id| id.ends_with("-f")), "{removed:?}");
    assert!(!mirror_dir.exists(), "the mirror tree went with the folder");
    assert!(!tmp_root.exists(), "the temporary source went too");
    let (_, folders) = d.call(Method::GET, "/v1/folders", None).await;
    assert!(no_check_folders(&folders), "{folders}");
    let (_, list) = d.call(Method::GET, "/v1/datasets", None).await;
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .all(|x| !x["id"].as_str().unwrap().starts_with("check-")),
        "{list}"
    );
    d.stop().await;
}
