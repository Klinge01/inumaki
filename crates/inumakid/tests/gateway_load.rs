//! M4 spec §13 load bounds: with two inference slots, sixteen concurrent
//! 40 KB results on one dataset are served or refused with
//! `resource_limit`, never buffered without bound, and an unrelated
//! dataset stays responsive meanwhile.

mod common;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use common::gateway::{add_stdio, socket_client, wait_running};
use common::*;
use hyper::Method;
use rmcp::model::CallToolRequestParams;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::print_stderr)]
async fn saturation_is_bounded_and_unrelated_datasets_stay_responsive() {
    let d = start_with(
        "",
        "max_inflight = 2\nqueue_timeout = \"2s\"\n",
        Duration::from_secs(3600),
        None,
    )
    .await;
    for ds in ["busy", "quiet"] {
        d.dataset(ds).await;
        add_stdio(&d, ds, "a", BTreeMap::new(), BTreeMap::new(), true).await;
    }
    for ds in ["busy", "quiet"] {
        wait_running(&d, ds, "a").await;
    }
    let busy = socket_client(&d, "busy").await.unwrap();
    let quiet = socket_client(&d, "quiet").await.unwrap();
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let p = busy.peer().clone();
        tasks.push(tokio::spawn(async move {
            p.call_tool(
                CallToolRequestParams::new("long")
                    .with_arguments(json!({ "bytes": 40_000 }).as_object().cloned().unwrap()),
            )
            .await
        }));
    }
    let t0 = Instant::now();
    let r = quiet
        .peer()
        .call_tool(
            CallToolRequestParams::new("echo")
                .with_arguments(json!({ "query": "hi" }).as_object().cloned().unwrap()),
        )
        .await
        .unwrap();
    let quiet_latency = t0.elapsed();
    assert!(r.content[0].as_text().unwrap().text == "echo: hi");
    let (mut ok, mut limited, mut other) = (0, 0, BTreeMap::<String, usize>::new());
    for t in tasks {
        match t.await.unwrap() {
            Ok(_) => ok += 1,
            Err(rmcp::service::ServiceError::McpError(e)) if e.message == "resource_limit" => {
                limited += 1
            }
            Err(e) => *other.entry(format!("{e:?}")).or_default() += 1,
        }
    }
    assert_eq!(ok + limited, 16, "{other:?}");
    assert!(ok >= 2, "at least the slots' worth succeeded");
    assert!(
        quiet_latency < Duration::from_secs(3),
        "unrelated dataset waited {quiet_latency:?}"
    );
    let (_, st) = d.call(Method::GET, "/v1/status", None).await;
    let busy_ds = st["gateway"]["datasets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == "busy")
        .unwrap();
    assert_eq!(busy_ds["limited"].as_u64().unwrap() as usize, limited);
    eprintln!("load: ok {ok} limited {limited} quiet_latency {quiet_latency:?}");
    busy.cancel().await.ok();
    quiet.cancel().await.ok();
    d.stop().await;
}
