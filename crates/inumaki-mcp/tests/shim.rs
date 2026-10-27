//! M4 spec §13 shim: `inumaki-mcp` speaks stdio to an rmcp client and
//! relays to a running daemon without a bearer token.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hyper::Method;
use inumaki_gateway::scripted::{ScriptedUpstream, serve_scripted_http};
use inumakid::client::Client;
use inumakid::{AppState, StartOptions};
use rmcp::ServiceExt;
use rmcp::model::{
    CallToolRequestParams, ClientCapabilities, Implementation, InitializeRequestParams,
};
use rmcp::transport::TokioChildProcess;
use serde_json::json;

const BASE_CONFIG: &str = include_str!("../../../configs/default.toml");
const POLICY: &str = include_str!("../../../docs/examples/scripted-upstream.policy.json");

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shim_relays_stdio_to_the_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("inumaki.toml");
    let dict = dir.path().join("persons.txt");
    std::fs::write(&dict, format!("{}\n", inumaki_gateway::scripted::IDENTITY)).unwrap();
    let base = BASE_CONFIG.replace(
        "persons = []",
        &format!("persons = [\"{}\"]", dict.display()),
    );
    std::fs::write(
        &cfg,
        format!("{base}\n[daemon]\ndefault_profile = \"offline\"\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"127.0.0.1:0\"\n[proxy]\nlisten = \"127.0.0.1:0\"\n[mirror]\nroot = \"{d}/mirror-root\"\noutbox_root = \"{d}/mirror-outbox\"\n", d = dir.path().display()),
    )
    .unwrap();
    let models = dir.path().join("no-models");
    std::fs::create_dir_all(&models).unwrap();
    let socket: PathBuf =
        std::env::temp_dir().join(format!("inumaki-mcp-{}.sock", std::process::id()));
    let opts = StartOptions {
        config: Some(cfg),
        data_dir: Some(dir.path().join("data")),
        socket: Some(socket.clone()),
        models_dir: Some(models),
        clock: None,
    };
    let state = Arc::new(
        tokio::task::spawn_blocking(move || AppState::start(&opts))
            .await
            .unwrap()
            .unwrap(),
    );
    let task = tokio::spawn(inumakid::server::serve_with(
        Arc::clone(&state),
        Duration::from_secs(3600),
    ));
    let client = Client::new(&socket);
    for _ in 0..400 {
        if client.call(Method::GET, "/v1/status", None).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let r = client
        .call(
            Method::POST,
            "/v1/datasets",
            Some(&json!({ "id": "crm", "name": "C" })),
        )
        .await
        .unwrap();
    assert_eq!(r.status.as_u16(), 201);
    // An HTTP upstream: a child process would need another package's binary.
    let (addr, upstream) = serve_scripted_http(ScriptedUpstream::default()).await;
    let policy: serde_json::Value = serde_json::from_str(POLICY).unwrap();
    let r = client
        .call(
            Method::POST,
            "/v1/datasets/crm/upstreams",
            Some(&json!({ "name": "a", "kind": "http", "url": format!("http://{addr}/mcp"), "content_policy": policy })),
        )
        .await
        .unwrap();
    assert_eq!(r.status.as_u16(), 201);
    for _ in 0..200 {
        let st = client
            .call(Method::GET, "/v1/status", None)
            .await
            .unwrap()
            .body;
        if st["gateway"]["datasets"][0]["upstreams"][0]["schema_fingerprint"].is_string() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_inumaki-mcp"));
    cmd.arg("crm").arg("--socket").arg(&socket);
    let (proc, _stderr) = TokioChildProcess::builder(cmd).spawn().unwrap();
    let c =
        InitializeRequestParams::new(ClientCapabilities::default(), Implementation::new("t", "0"))
            .serve(proc)
            .await
            .unwrap();
    // The model sees the opaque dataset label, never the slug (review M9).
    let server_name = c
        .peer()
        .peer_info()
        .unwrap()
        .server_info
        .as_ref()
        .unwrap()
        .name
        .clone();
    assert!(
        server_name.starts_with("inumaki/")
            && server_name.len() > "inumaki/".len()
            && !server_name.contains("crm"),
        "{server_name}"
    );
    let tools = c.peer().list_all_tools().await.unwrap();
    assert!(tools.iter().any(|t| t.name == "echo"));
    let r = c
        .peer()
        .call_tool(CallToolRequestParams::new("record"))
        .await
        .unwrap();
    let text = r.content[0].as_text().unwrap().text.clone();
    assert!(
        !text.contains("Zyxwuria") && text.contains("<PERSON_"),
        "{text}"
    );
    let e = c
        .peer()
        .call_tool(CallToolRequestParams::new("nope"))
        .await
        .unwrap_err();
    assert!(
        format!("{e:?}").contains("unknown_tool"),
        "daemon errors pass through: {e:?}"
    );
    c.cancel().await.ok();
    let mut bad = tokio::process::Command::new(env!("CARGO_BIN_EXE_inumaki-mcp"));
    bad.arg("nope")
        .arg("--socket")
        .arg(&socket)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    let out = bad.output().await.unwrap();
    assert_eq!(out.status.code(), Some(2), "unknown dataset exits 2");
    assert!(String::from_utf8_lossy(&out.stderr).contains("dataset nope"));
    upstream.cancel();
    state.shutdown.send_replace(true);
    let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
}
