//! Plan M8-3 Task 4 (user-gated, never in CI): what each installed harness
//! sends (paths, query strings, `User-Agent`, header names, upgrade
//! attempts), first against the scripted upstream directly, then through
//! the daemon's proxy. Temporary configuration, dummy credentials,
//! synthetic text, loopback only.
//!
//! INUMAKI_RECORD_HARNESS=1 cargo test -p inumakid --test harness_record -- --ignored --nocapture --test-threads 1

mod common;

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Output;
use std::sync::Arc;
use std::time::Duration;

use hyper::Method;
use inumaki_proxy::scripted::{RequestLine, spawn_http};
use inumaki_proxy::{Script, ScriptedUpstream, Step};

const PROMPT: &str = "Repeat exactly: Kontakt zyx.quolnath@example.invalid";
const EMAIL: &str = "zyx.quolnath@example.invalid";

fn gated() -> bool {
    std::env::var_os("INUMAKI_RECORD_HARNESS").is_some()
}

#[allow(clippy::print_stdout)]
fn report(harness: &str, phase: &str, out: &Output, lines: &[RequestLine]) {
    println!("== {harness} / {phase}: exit {:?}", out.status.code());
    for l in lines {
        println!(
            "  {} {} query={:?} ua={:?} upgrade={} headers={:?}",
            l.method, l.path, l.query, l.user_agent, l.upgrade, l.header_names
        );
    }
}

/// Hop-by-hop names the proxy never forwards (RFC 9110 §7.6.1).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Spec §20 amendment of 2026-10-12 (4e): the header allowlist must lose
/// nothing the harness sends. The names seen directly minus the names seen
/// through the proxy, leaving out the three the proxy sets itself, the
/// hop-by-hop names, and `x-inumaki-*`, may only be `x-codex-turn-metadata`
/// (ruling L58). Prints the difference so a new
/// harness release that adds a header shows up here, not in a user's chat.
#[allow(clippy::print_stdout)]
fn assert_allowlist_lost_nothing(harness: &str, direct: &[RequestLine], proxied: &[RequestLine]) {
    let names = |lines: &[RequestLine]| -> BTreeSet<String> {
        lines
            .iter()
            .flat_map(|l| l.header_names.iter().cloned())
            .filter(|n| {
                !["host", "content-length", "accept-encoding"].contains(&n.as_str())
                    && !HOP_BY_HOP.contains(&n.as_str())
                    && !n.starts_with("x-inumaki-")
            })
            .collect()
    };
    let (direct, proxied) = (names(direct), names(proxied));
    let lost: BTreeSet<_> = direct.difference(&proxied).cloned().collect();
    println!("  {harness}: names lost through the proxy: {lost:?}");
    assert!(
        lost.iter().all(|n| n == "x-codex-turn-metadata"),
        "{harness}: the allowlist dropped {lost:?}"
    );
}

async fn run(cmd: &mut tokio::process::Command) -> Output {
    tokio::time::timeout(Duration::from_secs(180), cmd.output())
        .await
        .expect("finished within 3 minutes")
        .expect("started")
}

fn claude(base: &str, dir: &Path, header: Option<&str>) -> tokio::process::Command {
    let mut c = tokio::process::Command::new("claude");
    c.arg("-p")
        .arg(PROMPT)
        .current_dir(dir)
        .env("ANTHROPIC_BASE_URL", base)
        .env("ANTHROPIC_API_KEY", "sk-ant-api03-inumaki-dummy")
        .env_remove("ANTHROPIC_AUTH_TOKEN")
        .env("CLAUDE_CONFIG_DIR", dir.join("cfg"))
        .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1");
    if let Some(v) = header {
        c.env("ANTHROPIC_CUSTOM_HEADERS", format!("X-Inumaki-Client: {v}"));
    }
    c
}

fn codex(base: &str, dir: &Path, header: Option<&str>) -> tokio::process::Command {
    let headers = header
        .map(|v| format!(", http_headers={{\"X-Inumaki-Client\"=\"{v}\"}}"))
        .unwrap_or_default();
    let mut c = tokio::process::Command::new("codex");
    c.arg("exec")
        .arg("--skip-git-repo-check")
        // Drop this override if the installed Codex refuses the key.
        .arg("-c")
        .arg("check_for_update_on_startup=false")
        .arg("-c")
        .arg("model_provider=rec")
        .arg("-c")
        .arg(format!(
            "model_providers.rec={{name=\"rec\", base_url=\"{base}\", wire_api=\"responses\", env_key=\"INUMAKI_DUMMY_KEY\"{headers}}}"
        ))
        .arg(PROMPT)
        .current_dir(dir)
        .env("CODEX_HOME", dir.join("codex-home"))
        .env("INUMAKI_DUMMY_KEY", "sk-inumaki-dummy");
    c
}

/// Phase 2 helper: a daemon whose upstream `id` points at a fresh scripted
/// server. Returns the daemon, the upstream, the proxy's listen address and
/// the per-install client header value.
async fn proxied(id: &str) -> (common::TestDaemon, Arc<ScriptedUpstream>, String, String) {
    inumaki_proxy::forward::ensure_crypto_provider();
    let (addr, up) = spawn_http(Script(vec![Step::EchoUserText])).await;
    let extra = format!(
        "[proxy]\nlisten = \"127.0.0.1:0\"\n[proxy.upstreams.{id}]\nbase_url = \"http://{addr}\"\n"
    );
    let d = common::start_with("", &extra, Duration::from_secs(3600), None).await;
    let st = d.call(Method::GET, "/v1/proxy", None).await.1;
    let (listen, value) = (
        st["listen"].as_str().unwrap().to_string(),
        st["client_header"]["value"].as_str().unwrap().to_string(),
    );
    (d, up, listen, value)
}

#[allow(clippy::print_stdout)]
async fn finish(d: common::TestDaemon, up: &ScriptedUpstream, out: &Output) {
    let st = d.call(Method::GET, "/v1/proxy", None).await.1;
    println!("  status clients={} routes={}", st["clients"], st["routes"]);
    assert!(
        out.status.success(),
        "the harness completed through the proxy"
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(EMAIL),
        "the answer was restored"
    );
    for (_, b) in up.recorded() {
        assert!(
            !String::from_utf8_lossy(&b).contains("zyx.quolnath"),
            "no original upstream"
        );
    }
    d.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "user-gated: runs the installed Claude Code (plan M8-3 Task 4)"]
async fn record_claude_code() {
    if !gated() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("cfg")).unwrap();
    let (addr, up) = spawn_http(Script(vec![Step::EchoUserText])).await;
    let out = run(&mut claude(&format!("http://{addr}"), tmp.path(), None)).await;
    report("claude-code", "direct", &out, &up.lines());
    let (d, up2, listen, value) = proxied("anthropic").await;
    let out = run(&mut claude(
        &format!("http://{listen}/anthropic"),
        tmp.path(),
        Some(&value),
    ))
    .await;
    report("claude-code", "proxy", &out, &up2.lines());
    finish(d, &up2, &out).await;
    assert_allowlist_lost_nothing("claude-code", &up.lines(), &up2.lines());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "user-gated: runs the installed Codex (plan M8-3 Task 4)"]
async fn record_codex_api_key() {
    if !gated() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("codex-home")).unwrap();
    let (addr, up) = spawn_http(Script(vec![Step::EchoUserText])).await;
    let out = run(&mut codex(&format!("http://{addr}/v1"), tmp.path(), None)).await;
    report("codex", "direct", &out, &up.lines());
    let (d, up2, listen, value) = proxied("openai").await;
    let out = run(&mut codex(
        &format!("http://{listen}/openai/v1"),
        tmp.path(),
        Some(&value),
    ))
    .await;
    report("codex", "proxy", &out, &up2.lines());
    finish(d, &up2, &out).await;
    assert_allowlist_lost_nothing("codex", &up.lines(), &up2.lines());
}
