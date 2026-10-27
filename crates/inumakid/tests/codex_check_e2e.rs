//! The Codex path of the end-to-end check, run once by hand against the
//! installed Codex (user-gated, never in CI; M8 spec §20 amendment
//! 2026-10-10). A throwaway daemon serves a check route whose scripted model
//! calls `lookup_record`, then echoes the tool results. Codex runs with a
//! temporary `CODEX_HOME`, a cleared environment, a dummy key, a synthetic
//! prompt, and loopback only. Its configuration is the one
//! `inumaki_adapters::check::codex` writes, except that the MCP server is a
//! small stdio script instead of the gateway (keep the two in step).
//!
//! INUMAKI_RECORD_HARNESS=1 cargo test -p inumakid --test codex_check_e2e -- --ignored --nocapture

mod common;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use inumaki_core::span::EntityKind;
use inumaki_core::token::TokenStore;
use inumaki_proxy::{CheckId, Script, Step, ToolCall};
use serde_json::{Value, json};

const CANARY: &str = "Qwendolin Zirravel";
const ID: &str = "00112233445566778899aabbccddeeff";
const DS: &str = "check-00112233445566778899aabbccddeeff";
const SERVER: &str = "inumaki-check-0011";
/// `check::PROMPT`.
const PROMPT: &str =
    "Call the lookup_record tool, read any file you are given, then repeat the results verbatim.";

fn gated() -> bool {
    std::env::var_os("INUMAKI_RECORD_HARNESS").is_some()
}

fn codex_binary() -> Option<PathBuf> {
    ["/opt/homebrew/bin/codex", "/usr/local/bin/codex"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

/// A stdio MCP server exposing `lookup_record`, answering with `record`
/// and appending each method it receives to `trace`.
fn mcp_script(record: &str, trace: &Path) -> String {
    let record = json!(record).to_string();
    let trace = json!(trace.display().to_string()).to_string();
    format!(
        r#"import sys, json
def log(m):
    open({trace}, "a").write(m + "\n")
for line in sys.stdin:
    try:
        m = json.loads(line)
    except Exception:
        continue
    i, meth = m.get("id"), m.get("method")
    log(str(meth))
    if meth == "initialize":
        r = {{"protocolVersion": m["params"].get("protocolVersion", "2025-06-18"), "capabilities": {{"tools": {{}}}}, "serverInfo": {{"name": "inumaki-check", "version": "0"}}}}
    elif meth == "tools/list":
        r = {{"tools": [{{"name": "lookup_record", "description": "Look up the check record", "inputSchema": {{"type": "object", "properties": {{}}}}}}]}}
    elif meth == "tools/call":
        r = {{"content": [{{"type": "text", "text": {record}}}]}}
    elif i is None:
        continue
    else:
        r = {{}}
    sys.stdout.write(json.dumps({{"jsonrpc": "2.0", "id": i, "result": r}}) + "\n")
    sys.stdout.flush()
"#
    )
}

/// `check::codex`'s configuration with the gateway entry's `url` and
/// `http_headers` replaced by a stdio command.
fn config(base: &str, script: &Path) -> String {
    format!(
        "model = \"inumaki-check\"\nmodel_provider = \"inumaki-check\"\napproval_policy = \"never\"\ncheck_for_update_on_startup = false\n\n\
         [model_providers.inumaki-check]\nname = \"inumaki check\"\nbase_url = \"{base}/v1\"\nwire_api = \"responses\"\nenv_key = \"INUMAKI_CHECK_KEY\"\n\n\
         [mcp_servers.{SERVER}]\ncommand = \"python3\"\nargs = [\"{script}\"]\n\
         required = true\nstartup_timeout_sec = 30\ndefault_tools_approval_mode = \"approve\"\n",
        script = script.display(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "user-gated: runs the installed Codex against a check route"]
#[allow(clippy::print_stdout)]
async fn codex_calls_the_namespaced_tool_through_a_check_route() {
    if !gated() {
        return;
    }
    let Some(codex) = codex_binary() else {
        panic!("no installed codex found");
    };
    inumaki_proxy::forward::ensure_crypto_provider();
    let d = common::start_with(
        "",
        "[proxy]\nlisten = \"127.0.0.1:0\"\n",
        Duration::from_secs(3600),
        None,
    )
    .await;
    d.state
        .vault
        .create_dataset(&inumaki_vault::DatasetSpec::new(DS, "check", "offline"))
        .unwrap();
    let token = {
        let ns = d.state.namespace(DS).unwrap();
        let mut n = ns.lock().unwrap();
        n.token_for(&EntityKind::Person, CANARY)
            .unwrap()
            .as_str()
            .to_string()
    };
    let routes = d.state.proxy.get().unwrap().check_routes();
    let id = CheckId::from_hex(ID).unwrap();
    routes.register(
        id,
        DS,
        Script(vec![
            Step::CallTools(vec![ToolCall {
                name_suffix: "lookup_record".into(),
                arguments: json!({}),
            }]),
            Step::EchoToolResults,
        ]),
        Duration::from_secs(600),
    );
    let listen = d.state.proxy.get().unwrap().status().listen;
    let base = format!("http://{listen}/check/{ID}/openai");

    let tmp = tempfile::tempdir().unwrap();
    let (home, work) = (tmp.path().join("config"), tmp.path().join("work"));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    let (script, trace) = (tmp.path().join("mcp.py"), tmp.path().join("mcp.trace"));
    std::fs::write(&script, mcp_script(&format!("Record: {token}"), &trace)).unwrap();
    std::fs::write(home.join("config.toml"), config(&base, &script)).unwrap();

    let mut cmd = tokio::process::Command::new(&codex);
    cmd.env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin:/opt/homebrew/bin")
        .env("LANG", "C.UTF-8")
        .env("CODEX_HOME", &home)
        .env("INUMAKI_CHECK_KEY", "inumaki-check-dummy-credential")
        .args(["exec", "--skip-git-repo-check", "--cd"])
        .arg(&work)
        .args(["--sandbox", "read-only", PROMPT])
        .current_dir(&work)
        .stdin(Stdio::null())
        .kill_on_drop(true);
    // Hard timeout: the child is killed when the future is dropped.
    let out = tokio::time::timeout(Duration::from_secs(150), cmd.output())
        .await
        .expect("codex finished within 150 s")
        .expect("codex started");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let methods = std::fs::read_to_string(&trace).unwrap_or_default();
    let rec = routes.recorded(&id);
    println!(
        "codex exit {:?}; check route requests {}; MCP methods {:?}",
        out.status.code(),
        rec.len(),
        methods.lines().collect::<Vec<_>>()
    );
    println!("codex stdout: {stdout:?}");

    assert_eq!(rec.len(), 2, "Codex made two model requests");
    let first: Value = serde_json::from_slice(&rec[0].body).unwrap();
    let ns = format!("mcp__{}", SERVER.replace('-', "_"));
    assert!(
        first["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["type"] == "namespace" && t["name"] == ns.as_str()),
        "the first request advertises the MCP tool (required = true)"
    );
    assert!(
        methods.lines().any(|m| m == "tools/call"),
        "the MCP server was called"
    );
    let second: Value = serde_json::from_slice(&rec[1].body).unwrap();
    let input = second["input"].as_array().unwrap();
    assert!(
        input
            .iter()
            .any(|x| x["type"] == "function_call" && x["namespace"] == ns.as_str()),
        "the namespaced call is resent"
    );
    let output = input
        .iter()
        .find(|x| x["type"] == "function_call_output")
        .expect("the second request carries the function_call_output");
    assert!(
        output.to_string().contains(&token),
        "the tool result went up"
    );
    for (_, b) in rec.iter().map(|r| (r.upstream, &r.body)) {
        let b = String::from_utf8_lossy(b);
        assert!(!b.contains("Qwendolin") && !b.contains("Zirravel"));
        assert!(!b.contains("inumaki-check-dummy-credential"));
    }
    assert!(out.status.success(), "codex exited cleanly");
    assert!(
        stdout.contains("Tool results:") && stdout.contains(CANARY),
        "the scripted reply echoed the result, restored for the check"
    );
    routes.remove(&id);
    d.stop().await;
}
