//! TCC spike finding 2: on macOS a launchd job's first read of a protected
//! folder blocks inside `open()` until the user answers the prompt. With a
//! mirror job parked in that open (the mirror's `OpenHold` test seam), the
//! daemon stays responsive and stoppable: `GET /v1/folders` answers and
//! reports `pending`, a folder removal answers `409` within its deadline
//! and finishes when retried, another dataset's folder add and remove
//! answer, `DELETE /v1/check/{id}` returns, and shutdown completes.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::mirror::start_mirror;
use hyper::Method;
use inumaki_mirror::Mirror;
use inumaki_mirror::testing::OpenHold;
use serde_json::{Value, json};

fn mirror_of(d: &common::TestDaemon) -> Arc<Mirror> {
    d.state
        .mirror
        .get()
        .and_then(|f| f.mirror_for_test())
        .expect("the mirror service runs")
}

async fn folder_dataset(d: &common::TestDaemon, id: &str, base: &std::path::Path) -> Value {
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/datasets",
            Some(json!({ "id": id, "name": "Akten", "kind": "folder" })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    let src = base.join(format!("src-{id}"));
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("a.txt"), "hallo\n").unwrap();
    let (code, body) = d
        .call(
            Method::POST,
            &format!("/v1/datasets/{id}/folder"),
            Some(json!({ "source": src })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    body
}

async fn state_of(d: &common::TestDaemon, id: &str) -> String {
    let (code, body) = d.call(Method::GET, "/v1/folders", None).await;
    assert_eq!(code, 200, "{body}");
    body["folders"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["dataset"] == id)
        .map(|f| f["state"].as_str().unwrap().to_string())
        .unwrap_or_default()
}

async fn parked(hold: &OpenHold) {
    let deadline = Instant::now() + Duration::from_secs(40);
    while !hold.wait_parked(Duration::from_millis(10)) {
        assert!(Instant::now() < deadline, "no mirror open parked");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_parked_open_keeps_the_folder_api_responsive() {
    let m = start_mirror().await;
    let hold = mirror_of(&m.d).hold_source_opens();
    folder_dataset(&m.d, "qwxzvk-akten", &m.base).await;
    parked(&hold).await;

    // GET /v1/folders answers at once and turns `pending` after 2 s.
    let t0 = Instant::now();
    let mut pending = false;
    while t0.elapsed() < Duration::from_secs(6) {
        let t = Instant::now();
        let s = state_of(&m.d, "qwxzvk-akten").await;
        assert!(
            t.elapsed() < Duration::from_secs(1),
            "GET /v1/folders blocked"
        );
        if s == "pending" {
            pending = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(pending, "the parked folder never read pending");

    // The removal of the parked folder answers 409 within its deadline,
    // while another dataset's folder add and removal answer too.
    let client = m.d.client.clone();
    let t0 = Instant::now();
    let removing = tokio::spawn(async move {
        client
            .call(Method::DELETE, "/v1/datasets/qwxzvk-akten/folder", None)
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let other = tokio::time::timeout(
        Duration::from_secs(40),
        folder_dataset(&m.d, "qwxzvk-briefe", &m.base),
    )
    .await
    .expect("another dataset's folder add hung");
    assert_eq!(other["dataset"], "qwxzvk-briefe");
    let r = tokio::time::timeout(Duration::from_secs(40), removing)
        .await
        .expect("the folder removal hung")
        .unwrap();
    assert!(t0.elapsed() < Duration::from_secs(30), "{:?}", t0.elapsed());
    assert_eq!(r.status.as_u16(), 409, "{}", r.body);
    assert_eq!(r.body["error"]["type"], "conflict", "{}", r.body);
    assert_eq!(
        r.body["error"]["message"], "the folder is busy; try again in a moment",
        "a fixed message, no path or id"
    );
    let (code, _) = tokio::time::timeout(
        Duration::from_secs(40),
        m.d.call(Method::DELETE, "/v1/datasets/qwxzvk-briefe/folder", None),
    )
    .await
    .expect("another dataset's folder removal hung");
    assert_eq!(code, 204);
    // Still connected and fenced: `stopped` until the removal finishes.
    assert_eq!(state_of(&m.d, "qwxzvk-akten").await, "stopped");
    let src_file = m.base.join("src-qwxzvk-akten").join("a.txt");
    assert!(src_file.exists(), "a busy removal never touches the source");

    // Once the user answers, the same request finishes the removal.
    hold.release();
    let (code, body) =
        m.d.call(Method::DELETE, "/v1/datasets/qwxzvk-akten/folder", None)
            .await;
    assert_eq!(code, 204, "{body}");
    assert_eq!(state_of(&m.d, "qwxzvk-akten").await, "");
    assert!(src_file.exists(), "the removal never touches the source");
    m.d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dataset_delete_with_a_parked_folder_answers_409() {
    let m = start_mirror().await;
    let hold = mirror_of(&m.d).hold_source_opens();
    folder_dataset(&m.d, "qwxzvk-akten", &m.base).await;
    parked(&hold).await;
    let t0 = Instant::now();
    let (code, body) = tokio::time::timeout(
        Duration::from_secs(40),
        m.d.call(Method::DELETE, "/v1/datasets/qwxzvk-akten", None),
    )
    .await
    .expect("the dataset removal hung");
    assert!(t0.elapsed() < Duration::from_secs(30), "{:?}", t0.elapsed());
    assert_eq!(code, 409, "{body}");
    hold.release();
    let (code, body) =
        m.d.call(Method::DELETE, "/v1/datasets/qwxzvk-akten", None)
            .await;
    assert_eq!(code, 204, "{body}");
    m.d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_check_returns_while_its_mirror_job_is_parked() {
    let d = common::start().await;
    let hold = mirror_of(&d).hold_source_opens();
    let (code, body) = d
        .call(
            Method::POST,
            "/v1/check",
            Some(json!({ "paths": ["mirror"] })),
        )
        .await;
    assert_eq!(code, 201, "{body}");
    assert_eq!(body["paths"]["mirror"]["available"], true, "{body}");
    let id = body["id"].as_str().unwrap().to_string();
    parked(&hold).await;
    let t0 = Instant::now();
    let (code, _) = tokio::time::timeout(
        Duration::from_secs(15),
        d.call(Method::DELETE, &format!("/v1/check/{id}"), None),
    )
    .await
    .expect("DELETE /v1/check hung behind the parked open");
    assert!(t0.elapsed() < Duration::from_secs(30), "{:?}", t0.elapsed());
    assert_eq!(code, 204);
    assert!(!d.state.check.is_live());
    // The live-check lock is free again.
    let (code, _) = tokio::time::timeout(
        Duration::from_secs(5),
        d.call(Method::GET, &format!("/v1/check/{id}"), None),
    )
    .await
    .expect("GET /v1/check hung");
    assert_eq!(code, 404);
    drop(hold);
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_with_a_parked_open_and_a_removal_in_flight_completes() {
    let m = start_mirror().await;
    let hold = mirror_of(&m.d).hold_source_opens();
    folder_dataset(&m.d, "qwxzvk-akten", &m.base).await;
    parked(&hold).await;
    let client = m.d.client.clone();
    let _removing = tokio::spawn(async move {
        let _ = client
            .call(Method::DELETE, "/v1/datasets/qwxzvk-akten/folder", None)
            .await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let t0 = Instant::now();
    m.d.state.shutdown.send_replace(true);
    let task = m.d.task;
    let r = tokio::time::timeout(Duration::from_secs(15), task)
        .await
        .expect("the daemon did not stop with a parked mirror job");
    assert!(r.unwrap().is_ok());
    // Request grace (5 s) plus the mirror's bounded stop (3 s).
    assert!(t0.elapsed() < Duration::from_secs(40), "{:?}", t0.elapsed());
    drop(hold);
}
