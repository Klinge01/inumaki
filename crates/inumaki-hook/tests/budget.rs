//! Spec §5.2 budget: the `pass` path end to end (process spawn, socket
//! round trip, one tripwire scan) for a Read of a 5 KB file. The first call
//! after start opens every namespace and is reported separately as cold
//! (review I7). Measurement, not a gate:
//! `cargo test --release -p inumaki-hook --test budget -- --ignored --nocapture`.
#![allow(clippy::print_stderr)]

use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use inumaki_core::span::EntityKind;
use inumaki_core::token::TokenStore;

fn once(socket: &Path, payload: &str) -> f64 {
    let t = Instant::now();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_inumaki-hook"))
        .args(["claude-code", "--socket", socket.to_str().unwrap()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.stdout.is_empty(), "pass prints nothing");
    t.elapsed().as_secs_f64() * 1000.0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "measurement; run with --release --ignored"]
async fn pass_path_on_a_5kb_read_cold_and_warm() {
    let dir = tempfile::tempdir().unwrap();
    let base = include_str!("../../../configs/default.toml");
    let cfg = dir.path().join("inumaki.toml");
    std::fs::write(
        &cfg,
        format!(
            "{base}\n[daemon]\ndefault_profile = \"offline\"\n[vault]\nkey_source = \"file\"\n[gateway]\nlisten = \"127.0.0.1:0\"\n[proxy]\nlisten = \"127.0.0.1:0\"\n[mirror]\nroot = \"{d}/mirror-root\"\noutbox_root = \"{d}/mirror-outbox\"\n",
            d = dir.path().display()
        ),
    )
    .unwrap();
    let models = dir.path().join("no-models");
    std::fs::create_dir_all(&models).unwrap();
    let data = dir.path().join("d");
    // macOS limits socket paths to 104 bytes: a short name in the temp dir.
    let socket =
        std::env::temp_dir().join(format!("inumaki-hook-budget-{}.sock", std::process::id()));
    let opts = inumakid::StartOptions {
        config: Some(cfg),
        data_dir: Some(data),
        socket: Some(socket.clone()),
        models_dir: Some(models),
        clock: None,
    };
    let state = Arc::new(
        tokio::task::spawn_blocking(move || inumakid::AppState::start(&opts))
            .await
            .unwrap()
            .unwrap(),
    );
    tokio::spawn(inumakid::server::serve_with(
        Arc::clone(&state),
        Duration::from_secs(3600),
    ));
    let client = inumaki_client::Client::new(&socket);
    for _ in 0..400 {
        if client.status().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    for ds in ["a", "b", "c"] {
        client
            .create_dataset(&inumaki_client::CreateDataset::new(ds, ds))
            .await
            .unwrap();
        let ns = state.namespace(ds).unwrap();
        let mut n = ns.lock().unwrap();
        n.token_for(&EntityKind::Person, "Zyxwuria Quolnath")
            .unwrap();
        n.rebuild_detector_now().unwrap();
    }
    let content: String = "fn main() { let max_results = 10; println!(\"ok\"); }\n"
        .repeat(100)
        .chars()
        .take(5 * 1024)
        .collect();
    // The Read shape of tests/fixtures/claude-code/read.payload.json.
    let payload = serde_json::json!({
        "tool_name": "Read", "cwd": "/tmp", "tool_input": { "file_path": "/tmp/main.rs" },
        "tool_response": { "type": "text", "file": { "filePath": "/tmp/main.rs", "content": content, "numLines": 100, "startLine": 1, "totalLines": 100 } }
    })
    .to_string();
    let s = socket.clone();
    let p = payload.clone();
    let cold = tokio::task::spawn_blocking(move || once(&s, &p))
        .await
        .unwrap();
    let s = socket.clone();
    let mut ms: Vec<f64> =
        tokio::task::spawn_blocking(move || (0..50).map(|_| once(&s, &payload)).collect())
            .await
            .unwrap();
    ms.sort_by(f64::total_cmp);
    eprintln!(
        "hook pass path, Read 5 KB, 3 datasets: cold {cold:.1} ms; warm p50 {:.1} ms, p95 {:.1} ms (target p50 < 15 ms)",
        ms[ms.len() / 2],
        ms[ms.len() * 95 / 100]
    );
    state.shutdown.send_replace(true);
    let _ = std::fs::remove_file(&socket);
}
