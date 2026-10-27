//! Review Focus 3: canary values in check bodies (the harness output) and
//! in the check's own traffic never reach a log line or an error body.

mod common;

use common::Capture;
use hyper::Method;
use inumakid::check::canary::Canary;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn check_bodies_never_reach_logs_or_errors() {
    let cap = Capture::new();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(cap.clone())
                .with_filter(inumakid::run::log_filter(EnvFilter::new("trace"))),
        )
        .init();
    let d = common::start().await;
    d.state
        .check
        .set_canary_program(env!("CARGO_BIN_EXE_inumakid").into());
    let c = Canary::generate();
    d.state.check.set_next_canary(c.clone());
    let (_, created) = d
        .call(Method::POST, "/v1/check", Some(serde_json::json!({})))
        .await;
    let id = created["id"].as_str().unwrap().to_string();
    let (_, direct) = d
        .call(Method::POST, &format!("/v1/check/{id}/direct"), None)
        .await;
    // The check's own gateway traffic ran, so the logs below cover it.
    assert_eq!(direct["results"]["gateway"]["status"], "passed", "{direct}");
    let output = format!(
        "The record: {}, IBAN {}, {}",
        c.full_name(),
        c.iban,
        c.email
    );
    let (code, report) = d
        .call(
            Method::POST,
            &format!("/v1/check/{id}/harness"),
            Some(serde_json::json!({ "harness": "claude-code", "output": output, "exit_code": 0 })),
        )
        .await;
    assert_eq!(code, 200, "{report}");
    // Codex bodies are not Anthropic Messages: its log line carries no bash field.
    let (code, codex) = d
        .call(
            Method::POST,
            &format!("/v1/check/{id}/harness"),
            Some(serde_json::json!({ "harness": "codex", "output": output, "exit_code": 0 })),
        )
        .await;
    assert_eq!(code, 200, "{codex}");
    let (code, err) = d
        .call(
            Method::POST,
            &format!("/v1/check/{id}/harness"),
            Some(serde_json::json!({ "harness": "claude-code", "output": output, "exit_code": "zero" })),
        )
        .await;
    assert_eq!(code, 400);
    d.call(Method::DELETE, &format!("/v1/check/{id}"), None)
        .await;
    let logs = cap.text();
    let harness_lines: Vec<&str> = logs
        .lines()
        .filter(|l| l.contains("check harness requests"))
        .collect();
    assert!(
        harness_lines
            .iter()
            .any(|l| l.contains("harness=ClaudeCode") && l.contains("bash=")),
        "Claude Code logs the bash result: {harness_lines:?}"
    );
    assert!(
        harness_lines
            .iter()
            .any(|l| l.contains("harness=Codex") && !l.contains("bash=")),
        "Codex logs no bash field: {harness_lines:?}"
    );
    assert!(
        harness_lines
            .iter()
            .all(|l| !(l.contains("harness=Codex") && l.contains("bash="))),
        "Codex logs no bash field: {harness_lines:?}"
    );
    for text in [
        err.to_string(),
        direct.to_string(),
        report.to_string(),
        codex.to_string(),
        created.to_string(),
        logs.clone(),
    ] {
        assert!(!c.appears_in(&text), "a canary value leaked: {text}");
    }
    assert!(
        logs.contains("/v1/check/{id}/harness"),
        "route templates are logged"
    );
    assert!(
        !logs.contains(&id),
        "check ids are path parameters and not logged"
    );
    let token = created["gateway"]["token"].as_str().unwrap();
    let slug = created["gateway"]["url"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap();
    assert!(
        !logs.contains(token) && !logs.contains(slug),
        "the check's bearer token and dataset slug are not logged"
    );
}
