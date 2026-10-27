//! Spec §5.1, §11: every failure produces the block replacement and never
//! the original; replacements keep the tool's shape; keys, numbers, and
//! discriminators are guarded; stderr is fixed; block templates fit the
//! shapes in docs/harness-adapters.md §5.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use inumaki_client::Client;
use inumaki_client::mock::{Canned, MockDaemon};
use inumaki_hook::{
    BlockClass, Blocked, Harness, MAX_TOTAL, fail_closed, leaves, output, payload,
    run_with_deadline,
};
use serde_json::{Value, json};

const CANARY: &str = "Zyxwuria Quolnath";
/// The daemon's fixed error message (Task 8): never copied into a block.
const DAEMON_MESSAGE: &str = "the tool result could not be checked; it was withheld";
/// Ruling L97: the whole daemon-unreachable message, pinned. Fixed words
/// only; the recovery sentence names no socket, path, or value.
const UNREACHABLE_MESSAGE: &str = "blocked by inumaki (daemon_unreachable; kinds: none). inumaki is not running; start it to restore tool output.";

fn fixture(h: &str, name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(h)
            .join(format!("{name}.payload.json")),
    )
    .unwrap()
}

fn fixtures() -> Vec<(Harness, Vec<u8>)> {
    let mut v: Vec<(Harness, Vec<u8>)> = ["bash", "read", "grep", "mcp"]
        .iter()
        .map(|n| (Harness::ClaudeCode, fixture("claude-code", n)))
        .collect();
    v.push((Harness::Codex, fixture("codex", "shell")));
    v
}

/// Every word of the payload's output, command, and paths that a leak would carry.
const LEAK_MARKERS: &[&str] = &[
    "Zyxwuria", "Quolnath", "Termin", "Dienstag", "kunden", "Wien",
];

/// The output is exactly the block for this tool, class, and kinds: fixed
/// words only, in the tool's template (Claude Code) or as Codex's reason.
fn assert_blocked(h: Harness, p: &[u8], out: &Option<String>, class: BlockClass, kinds: &[&str]) {
    let s = out.as_deref().expect("a block is printed");
    // The tool name the hook can know: from the JSON, else the recovered one.
    let name = serde_json::from_slice::<Value>(p)
        .ok()
        .and_then(|v| v["tool_name"].as_str().map(str::to_string))
        .or_else(|| payload::recover_tool_name(p));
    let b = Blocked {
        class,
        kinds: kinds.iter().map(|k| k.to_string()).collect(),
    };
    assert_eq!(
        s,
        output::block(h, name.as_deref(), &b),
        "exact block for {name:?}"
    );
    assert!(
        s.contains(&format!("blocked by inumaki ({}", class.as_str())),
        "{s}"
    );
    // Only the daemon-unreachable class carries the recovery sentence, and
    // then as the exact pinned message.
    let unreachable = class == BlockClass::DaemonUnreachable;
    assert_eq!(
        s.contains(inumaki_hook::DAEMON_UNREACHABLE_RECOVERY),
        unreachable,
        "{s}"
    );
    if unreachable {
        assert!(kinds.is_empty());
        assert!(s.contains(UNREACHABLE_MESSAGE), "{s}");
    }
    for m in LEAK_MARKERS.iter().chain([&DAEMON_MESSAGE]) {
        assert!(
            !s.contains(m),
            "the original never reaches stdout ({m}): {s}"
        );
    }
    let v: Value = serde_json::from_str(s).unwrap();
    match h {
        Harness::ClaudeCode => {
            let u = &v["hookSpecificOutput"]["updatedToolOutput"];
            assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PostToolUse");
            // Without a tool name (stdin not JSON) no template applies.
            if name.is_some() {
                assert!(
                    !u.is_string(),
                    "a bare string is refused by built-in tools: {s}"
                );
            }
        }
        Harness::Codex => {
            assert_eq!(v["decision"], "block");
            assert!(v.get("continue").is_none());
            let reason = v["reason"].as_str().unwrap();
            assert!(reason.starts_with("blocked by inumaki ("));
            if unreachable {
                assert_eq!(reason, UNREACHABLE_MESSAGE);
            }
        }
    }
}

/// A `replace` answer for `payload`: the daemon's reply with the canary tokenized.
fn replacing(payload: &[u8]) -> Canned {
    let resp = serde_json::from_slice::<Value>(payload).unwrap()["tool_response"].clone();
    let texts: Vec<String> = leaves::texts(&resp)
        .iter()
        .map(|t| t.replace(CANARY, "<PERSON_a7f2>"))
        .collect();
    Canned::json(
        200,
        json!({ "action": "replace", "texts": texts, "kinds": ["PERSON"] }),
    )
}

fn hook_bodies(m: &MockDaemon) -> Vec<Value> {
    m.requests()
        .into_iter()
        .filter(|r| r.route == "/v1/hook")
        .filter_map(|r| r.body)
        .collect()
}

#[tokio::test]
async fn every_failure_blocks_and_never_prints_the_original() {
    let gone = Client::new(
        std::env::temp_dir().join(format!("inumaki-hook-none-{}.sock", std::process::id())),
    );
    for (h, p) in fixtures() {
        let out = run_with_deadline(h, &p, &gone, Duration::from_secs(2)).await;
        assert_blocked(h, &p, &out, BlockClass::DaemonUnreachable, &[]);
    }
    let m = MockDaemon::start().await;
    let c = m.client();
    let err = |status: u16, kind: &str| Canned::error(status, kind, DAEMON_MESSAGE, &[]);
    let cases: Vec<(Canned, BlockClass, &[&str])> = vec![
        (
            Canned::error(
                451,
                "privacy_block",
                DAEMON_MESSAGE,
                &["PERSON", "CUSTOMER_ID"],
            ),
            BlockClass::PrivacyBlock,
            &["PERSON", "CUSTOMER_ID"],
        ),
        // A kind label that is not a label is never echoed.
        (
            Canned::error(451, "privacy_block", "x", &[CANARY]),
            BlockClass::PrivacyBlock,
            &[CANARY],
        ),
        (
            Canned::raw(413, "length limit exceeded"),
            BlockClass::TooLarge,
            &[],
        ),
        (err(400, "bad_request"), BlockClass::DaemonError, &[]),
        (err(404, "not_found"), BlockClass::DaemonError, &[]),
        (err(422, "unprocessable"), BlockClass::DaemonError, &[]),
        (err(500, "internal"), BlockClass::DaemonError, &[]),
        (err(503, "unavailable"), BlockClass::DaemonError, &[]),
        (Canned::empty(500), BlockClass::DaemonError, &[]),
        // An unreadable 200, and a `replace` with a different number of texts.
        (
            Canned::raw(200, format!("{CANARY} not json")),
            BlockClass::DaemonError,
            &[],
        ),
        (
            Canned::json(
                200,
                json!({ "action": "replace", "texts": [], "kinds": ["PERSON"] }),
            ),
            BlockClass::DaemonError,
            &[],
        ),
        (
            Canned::fixture(200, "hook_pass").delayed(Duration::from_secs(3)),
            BlockClass::Timeout,
            &[],
        ),
    ];
    for (canned, class, kinds) in cases {
        m.set("POST", "/v1/hook", canned);
        for (h, p) in fixtures() {
            let out = run_with_deadline(h, &p, &c, Duration::from_millis(300)).await;
            assert_blocked(h, &p, &out, class, kinds);
        }
    }
    m.stop().await;
}

#[tokio::test]
async fn one_call_per_result_keeps_the_tool_shape_and_pass_prints_nothing() {
    let m = MockDaemon::start().await;
    let c = m.client();
    for (h, p) in fixtures() {
        assert_eq!(
            run_with_deadline(h, &p, &c, Duration::from_secs(2)).await,
            None,
            "pass: the original stays"
        );
    }
    let p = fixture("claude-code", "read");
    m.set("POST", "/v1/hook", replacing(&p));
    let out = run_with_deadline(Harness::ClaudeCode, &p, &c, Duration::from_secs(2))
        .await
        .unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    let updated = &v["hookSpecificOutput"]["updatedToolOutput"];
    let payload: Value = serde_json::from_slice(&p).unwrap();
    let mut expected = payload["tool_response"].clone();
    let file = expected["file"]["content"]
        .as_str()
        .unwrap()
        .replace(CANARY, "<PERSON_a7f2>");
    expected["file"]["content"] = Value::String(file);
    assert_eq!(
        updated, &expected,
        "same shape, only the string value changed"
    );
    assert!(
        !out.contains("Zyxwuria") && out.contains("<PERSON_a7f2>"),
        "{out}"
    );
    let sent = hook_bodies(&m);
    assert_eq!(sent.len(), 6, "one request per tool result (review I7)");
    let last = &sent[5];
    assert_eq!(last["harness"], "claude-code");
    assert_eq!(last["tool"], "read");
    assert_eq!(last["cwd"], payload["cwd"]);
    assert_eq!(
        last["paths"],
        json!([payload["tool_input"]["file_path"]]),
        "Read sends file_path"
    );
    assert_eq!(
        last["texts"],
        json!(leaves::texts(&payload["tool_response"])),
        "every key, string, and number"
    );
    // Bash sends its path-shaped words and the cwd; Codex's `Bash` is a shell tool.
    let bash = &sent[0];
    assert_eq!(bash["tool"], "bash");
    assert_eq!(
        bash["paths"],
        json!(["kunden/notiz.txt", "/Users/example/work"])
    );
    let codex = &sent[4];
    assert_eq!(
        (&codex["harness"], &codex["tool"]),
        (&json!("codex"), &json!("bash"))
    );
    assert_eq!(
        codex["texts"],
        json!(["Termin mit Zyxwuria Quolnath am Dienstag.\n"])
    );
    m.stop().await;
}

#[tokio::test]
async fn codex_replaces_through_a_non_empty_reason() {
    let m = MockDaemon::start().await;
    let c = m.client();
    let p = fixture("codex", "shell");
    m.set("POST", "/v1/hook", replacing(&p));
    let out = run_with_deadline(Harness::Codex, &p, &c, Duration::from_secs(2))
        .await
        .unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        v,
        json!({ "decision": "block", "reason": "Termin mit <PERSON_a7f2> am Dienstag.\n" }),
        "ReplaceViaReason, never continue:false"
    );
    // A sanitized text that trims to nothing still gives a non-empty reason.
    m.set(
        "POST",
        "/v1/hook",
        Canned::json(
            200,
            json!({ "action": "replace", "texts": ["  \n"], "kinds": [] }),
        ),
    );
    let out = run_with_deadline(Harness::Codex, &p, &c, Duration::from_secs(2))
        .await
        .unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    assert!(!v["reason"].as_str().unwrap().trim().is_empty());
    m.stop().await;
}

/// Review C4 and the discriminator guard.
#[tokio::test]
async fn a_changed_key_number_or_discriminator_blocks() {
    let m = MockDaemon::start().await;
    let c = m.client();
    let payload = |resp: Value| {
        json!({ "tool_name": "mcp__crm__lookup", "cwd": "/tmp", "tool_input": {}, "tool_response": resp })
            .to_string()
            .into_bytes()
    };
    let mut keyed = serde_json::Map::new();
    keyed.insert(CANARY.to_string(), json!("ok"));
    for (resp, texts) in [
        (Value::Object(keyed), json!(["<PERSON_a7f2>", "ok"])),
        (
            json!({ "customer": 8439271 }),
            json!(["customer", "<CUSTOMER_ID_b3c4>"]),
        ),
        (
            json!([{ "type": CANARY, "text": CANARY }]),
            json!(["type", "<PERSON_a7f2>", "text", "<PERSON_a7f2>"]),
        ),
        (
            json!({ "mode": "content", "content": CANARY }),
            json!(["mode", "<PERSON_a7f2>", "content", "<PERSON_a7f2>"]),
        ),
    ] {
        let p = payload(resp);
        m.set(
            "POST",
            "/v1/hook",
            Canned::json(
                200,
                json!({ "action": "replace", "texts": texts, "kinds": ["PERSON"] }),
            ),
        );
        let out = run_with_deadline(Harness::ClaudeCode, &p, &c, Duration::from_secs(2)).await;
        assert_blocked(
            Harness::ClaudeCode,
            &p,
            &out,
            BlockClass::PrivacyBlock,
            &["PERSON"],
        );
        assert!(!out.unwrap().contains("8439271"));
    }
    // An unchanged discriminator with a changed sibling is a normal replace.
    let p = payload(json!([{ "type": "text", "text": CANARY }]));
    m.set("POST", "/v1/hook", replacing(&p));
    let out = run_with_deadline(Harness::ClaudeCode, &p, &c, Duration::from_secs(2))
        .await
        .unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        v["hookSpecificOutput"]["updatedToolOutput"],
        json!([{ "type": "text", "text": "<PERSON_a7f2>" }])
    );
    m.stop().await;
}

/// Global Constraints, Review Focus 3.
#[tokio::test]
async fn unexpected_shapes_never_echo_the_original() {
    let m = MockDaemon::start().await;
    let c = m.client();
    let payload = |resp: Value| {
        json!({ "tool_name": "Bash", "cwd": "/tmp", "tool_input": { "command": "cat a.txt" }, "tool_response": resp })
            .to_string()
            .into_bytes()
    };
    // A bare string, nested arrays: replaced in place.
    for resp in [json!(CANARY), json!([[CANARY], { "x": [CANARY, 7] }])] {
        let p = payload(resp);
        m.set("POST", "/v1/hook", replacing(&p));
        let out = run_with_deadline(Harness::ClaudeCode, &p, &c, Duration::from_secs(2))
            .await
            .unwrap();
        assert!(!out.contains("Zyxwuria"), "{out}");
    }
    // Over the size cap: blocked before any call.
    let before = hook_bodies(&m).len();
    let big = payload(json!(format!("{CANARY} {}", "x".repeat(MAX_TOTAL))));
    let out = run_with_deadline(Harness::ClaudeCode, &big, &c, Duration::from_secs(2)).await;
    assert_blocked(Harness::ClaudeCode, &big, &out, BlockClass::TooLarge, &[]);
    assert_eq!(hook_bodies(&m).len(), before, "nothing was sent");
    // No tool_response, no tool_name, or not JSON: blocked.
    let missing = json!({ "tool_name": "Bash", "tool_input": { "command": CANARY } })
        .to_string()
        .into_bytes();
    let out = run_with_deadline(Harness::ClaudeCode, &missing, &c, Duration::from_secs(2)).await;
    assert_blocked(
        Harness::ClaudeCode,
        &missing,
        &out,
        BlockClass::UnparsablePayload,
        &[],
    );
    let nameless = json!({ "tool_response": CANARY }).to_string().into_bytes();
    let out = run_with_deadline(Harness::Codex, &nameless, &c, Duration::from_secs(2)).await;
    assert_blocked(
        Harness::Codex,
        &nameless,
        &out,
        BlockClass::UnparsablePayload,
        &[],
    );
    let garbage = format!("{CANARY} not json").into_bytes();
    for h in [Harness::ClaudeCode, Harness::Codex] {
        let out = run_with_deadline(h, &garbage, &c, Duration::from_secs(2)).await;
        assert_blocked(h, &garbage, &out, BlockClass::UnparsablePayload, &[]);
    }
    m.stop().await;
}

/// docs/harness-adapters.md §5: base64 output cannot be sanitized in place.
#[tokio::test]
async fn binary_output_passes_on_pass_and_blocks_on_replace() {
    let m = MockDaemon::start().await;
    let c = m.client();
    let read = |t: &str| {
        json!({ "tool_name": "Read", "cwd": "/tmp", "tool_input": { "file_path": "/tmp/scan.pdf" },
                "tool_response": { "type": t, "file": { "filePath": "/tmp/scan.pdf", "base64": "QUJD" } } })
        .to_string()
        .into_bytes()
    };
    let image = json!({ "tool_name": "Bash", "cwd": "/tmp", "tool_input": { "command": "cat x.png" },
                        "tool_response": { "stdout": "data:image/png;base64,QUJD", "stderr": "", "interrupted": false, "isImage": true } })
    .to_string()
    .into_bytes();
    for p in [read("pdf"), read("image"), read("parts"), image] {
        m.reset("POST", "/v1/hook");
        assert_eq!(
            run_with_deadline(Harness::ClaudeCode, &p, &c, Duration::from_secs(2)).await,
            None
        );
        m.set("POST", "/v1/hook", replacing(&p));
        let out = run_with_deadline(Harness::ClaudeCode, &p, &c, Duration::from_secs(2)).await;
        assert_blocked(
            Harness::ClaudeCode,
            &p,
            &out,
            BlockClass::PrivacyBlock,
            &["PERSON"],
        );
    }
    m.stop().await;
}

/// Task 8: the daemon refuses a relative `cwd`; the hook sends an absolute one.
#[tokio::test]
async fn a_missing_or_relative_cwd_becomes_the_process_directory() {
    let m = MockDaemon::start().await;
    let c = m.client();
    let here = std::env::current_dir()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    for cwd in [None, Some("work/sub")] {
        let mut v = json!({ "tool_name": "Grep", "tool_input": { "pattern": "x" }, "tool_response": { "content": "x" } });
        if let Some(cwd) = cwd {
            v["cwd"] = json!(cwd);
        }
        let p = v.to_string().into_bytes();
        assert_eq!(
            run_with_deadline(Harness::ClaudeCode, &p, &c, Duration::from_secs(2)).await,
            None
        );
        let last = hook_bodies(&m).pop().unwrap();
        assert_eq!(last["cwd"], json!(here));
        assert_eq!(
            last["paths"],
            json!([here]),
            "a Grep without a path searches cwd"
        );
    }
    m.stop().await;
}

#[test]
fn a_panic_blocks_in_the_tool_template() {
    let out = fail_closed(Harness::ClaudeCode, Some("Read"), || panic!("{}", CANARY));
    let p = json!({ "tool_name": "Read" }).to_string().into_bytes();
    assert_blocked(Harness::ClaudeCode, &p, &out, BlockClass::Internal, &[]);
    let out = fail_closed(Harness::Codex, None, || panic!("{}", CANARY));
    assert_blocked(Harness::Codex, b"", &out, BlockClass::Internal, &[]);
}

#[test]
fn walk_order_and_write_back_length() {
    let v = json!({ "a": [1, "x", { "b": null, "c": true, "d": 2.5 }], "e": "y" });
    assert_eq!(
        leaves::texts(&v),
        ["a", "1", "x", "b", "c", "d", "2.5", "e", "y"]
    );
    let t = leaves::texts(&v);
    let mut w = v.clone();
    assert!(leaves::write_back(&mut w, &t), "identity");
    assert!(
        !leaves::write_back(&mut v.clone(), &t[..t.len() - 1]),
        "too few"
    );
    let mut more = t.clone();
    more.push("z".into());
    assert!(!leaves::write_back(&mut v.clone(), &more), "too many");
}

/// Every hooked Claude Code tool has a template that fills to the tool's
/// output shape (docs/harness-adapters.md §5 table, required keys).
#[test]
fn block_templates_fit_the_tool_shapes() {
    let required: &[(&str, &[&str])] = &[
        ("Bash", &["stdout", "stderr", "interrupted"]),
        ("PowerShell", &["stdout", "stderr", "interrupted"]),
        ("Read", &["type", "file"]),
        ("Grep", &["numFiles", "filenames"]),
        (
            "Glob",
            &["durationMs", "numFiles", "filenames", "truncated"],
        ),
        (
            "Edit",
            &[
                "filePath",
                "oldString",
                "newString",
                "originalFile",
                "structuredPatch",
                "userModified",
                "replaceAll",
            ],
        ),
        (
            "WebFetch",
            &["bytes", "code", "codeText", "result", "durationMs", "url"],
        ),
        ("ReadMcpResourceTool", &["contents"]),
    ];
    assert_eq!(required.len(), payload::CLAUDE_TOOLS.len());
    let msg = "blocked by inumaki (internal; kinds: none)";
    for (tool, keys) in required {
        assert!(payload::CLAUDE_TOOLS.contains(tool));
        let v = output::claude_block(Some(tool), msg);
        let o = v.as_object().unwrap_or_else(|| panic!("{tool}: an object"));
        for k in *keys {
            assert!(o.contains_key(*k), "{tool} lacks {k}");
        }
        let s = v.to_string();
        assert!(s.contains(msg) && !s.contains("%BLOCK%"), "{tool}: {s}");
    }
    let read = output::claude_block(Some("Read"), msg);
    assert_eq!(read["type"], "text");
    for k in ["filePath", "content", "numLines", "startLine", "totalLines"] {
        assert!(read["file"].get(k).is_some(), "Read.file lacks {k}");
    }
    let mcp = output::claude_block(Some("mcp__crm__get_contact"), msg);
    assert_eq!(mcp, json!([{ "type": "text", "text": msg }]));
    let res = output::claude_block(Some("ReadMcpResourceTool"), msg);
    assert!(res["contents"][0]["uri"].is_string() && res["contents"][0]["text"] == msg);
    const { assert!(!output::BLOCK_AS_BARE_STRING) };
    assert_eq!(output::CODEX_MODE, output::CodexMode::ReplaceViaReason);
}

/// `CLAUDE_TOOLS` is the adapter's `HOOK_TOOLS` (the adapter crate is not a
/// dependency: its source text is the pin), and every listed tool has a class.
#[test]
fn claude_tools_equal_the_adapter_matcher_list() {
    let src = include_str!("../../inumaki-adapters/src/harness/claude_code.rs");
    let line = src
        .lines()
        .find(|l| l.starts_with("const HOOK_TOOLS: &str = \""))
        .expect("HOOK_TOOLS in the Claude Code adapter");
    let list = line.split('"').nth(1).unwrap();
    assert_eq!(list.split('|').collect::<Vec<_>>(), payload::CLAUDE_TOOLS);
    for t in payload::CLAUDE_TOOLS {
        assert_ne!(
            payload::claude_tool(t),
            inumaki_client::HookTool::Other,
            "{t}"
        );
    }
    assert_eq!(
        payload::claude_tool("mcp__crm__x"),
        inumaki_client::HookTool::Mcp
    );
    assert_eq!(
        payload::claude_tool("NotebookEdit"),
        inumaki_client::HookTool::Other
    );
    let codex = include_str!("../../inumaki-adapters/src/harness/codex.rs");
    assert!(codex.contains("const BASH_MATCHER: &str = \"^Bash$\";"));
    assert_eq!(payload::codex_tool("Bash"), inumaki_client::HookTool::Bash);
    assert_eq!(
        payload::codex_tool("web_search"),
        inumaki_client::HookTool::Other
    );
}

fn run_bin(args: &[&str], data: &Path, stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_inumaki-hook"))
        .args(args)
        .env("INUMAKI_DATA_DIR", data)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The hook stops reading at MAX_STDIN + 1 bytes: a broken pipe is fine.
    let _ = child.stdin.take().unwrap().write_all(stdin);
    child.wait_with_output().unwrap()
}

#[test]
fn the_binary_fails_closed_and_stderr_has_no_canary() {
    let data = tempfile::tempdir().unwrap();
    let missing = data.path().join("none.sock");
    let missing = missing.to_str().unwrap();
    let bash = fixture("claude-code", "bash");
    let shell = fixture("codex", "shell");
    let runs: [(&[&str], &Vec<u8>, BlockClass); 4] = [
        (
            &["claude-code", "--socket", missing],
            &bash,
            BlockClass::DaemonUnreachable,
        ),
        (&["codex"], &shell, BlockClass::DaemonUnreachable),
        // Malformed arguments after a known harness: blocked, exit 0.
        (&["claude-code", "--socket"], &bash, BlockClass::Internal),
        (&["codex", "--sock", missing], &shell, BlockClass::Internal),
    ];
    for (args, p, class) in runs {
        let h = Harness::parse(args[0]).unwrap();
        let out = run_bin(args, data.path(), p);
        assert!(out.status.success());
        let stdout = String::from_utf8(out.stdout).unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        let line = stdout.strip_suffix('\n').expect("one line");
        assert_blocked(h, p, &Some(line.to_string()), class, &[]);
        for m in LEAK_MARKERS {
            assert!(!stderr.contains(m), "{stderr}");
        }
    }
    // Ruling L97: the daemon-unreachable block is the same bytes whatever
    // the socket path; it never names the socket or the data directory.
    let other = data.path().join("elsewhere-qwxzvk.sock");
    for (h, p) in [("claude-code", &bash), ("codex", &shell)] {
        let a = run_bin(&[h, "--socket", missing], data.path(), p);
        let b = run_bin(&[h, "--socket", other.to_str().unwrap()], data.path(), p);
        assert!(a.status.success() && b.status.success());
        assert_eq!(a.stdout, b.stdout, "{h}");
        let out = String::from_utf8(a.stdout).unwrap();
        assert!(out.contains(UNREACHABLE_MESSAGE), "{out}");
        for leak in [
            ".sock",
            "qwxzvk",
            "none.sock",
            &*data.path().to_string_lossy(),
        ] {
            assert!(!out.contains(leak), "{leak}: {out}");
        }
    }
    // An unknown harness has no output format: usage, exit 2, nothing on stdout.
    let out = run_bin(&["hermes"], data.path(), &bash);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_binary_round_trips_through_the_socket() {
    let m = MockDaemon::start().await;
    let data = tempfile::tempdir().unwrap();
    let sock = m.socket().to_str().unwrap().to_string();
    let p = fixture("claude-code", "bash");
    let call = |p: Vec<u8>| {
        let (sock, dir) = (sock.clone(), data.path().to_path_buf());
        tokio::task::spawn_blocking(move || run_bin(&["claude-code", "--socket", &sock], &dir, &p))
    };
    let out = call(p.clone()).await.unwrap();
    assert!(
        out.status.success() && out.stdout.is_empty(),
        "pass prints nothing"
    );
    m.set("POST", "/v1/hook", replacing(&p));
    let out = call(p.clone()).await.unwrap();
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        v["hookSpecificOutput"]["updatedToolOutput"]["stdout"],
        "Termin mit <PERSON_a7f2> am Dienstag.\n"
    );
    assert!(out.stderr.is_empty());
    m.stop().await;
}

/// Review I1: Claude Code serializes a tool output cut inside an emoji with
/// a lone surrogate escape; the hook decodes it instead of answering with a
/// bare string (which Claude Code refuses for built-in tools).
#[tokio::test]
async fn a_lone_surrogate_escape_is_decoded_not_blocked_as_a_bare_string() {
    let m = MockDaemon::start().await;
    let c = m.client();
    let p = String::from_utf8(fixture("claude-code", "read"))
        .unwrap()
        .replace("Rückruf erbeten.", "Rückruf erbeten \\ud83d")
        .into_bytes();
    assert!(
        serde_json::from_slice::<Value>(&p).is_err(),
        "strict JSON refuses it"
    );
    let out = run_with_deadline(Harness::ClaudeCode, &p, &c, Duration::from_secs(2)).await;
    assert_eq!(out, None, "pass: decoded and checked");
    let resp = inumaki_hook::decode(&p).unwrap()["tool_response"].clone();
    let texts: Vec<String> = leaves::texts(&resp)
        .iter()
        .map(|t| t.replace(CANARY, "<PERSON_a7f2>"))
        .collect();
    m.set(
        "POST",
        "/v1/hook",
        Canned::json(
            200,
            json!({ "action": "replace", "texts": texts, "kinds": ["PERSON"] }),
        ),
    );
    let out = run_with_deadline(Harness::ClaudeCode, &p, &c, Duration::from_secs(2))
        .await
        .unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    let content = v["hookSpecificOutput"]["updatedToolOutput"]["file"]["content"]
        .as_str()
        .unwrap();
    assert!(
        content.contains("<PERSON_a7f2>") && content.contains('\u{FFFD}'),
        "{content}"
    );
    assert!(!out.contains("Zyxwuria"));
    assert_eq!(hook_bodies(&m).len(), 2);
    m.stop().await;
}

#[test]
fn lenient_decode_scans_escapes_pairwise() {
    let raw = br#"{"a":"\\ud83d","b":"x\ud83d","c":"\ud83d\ude00","d":"\udc00y"}"#;
    let v = inumaki_hook::decode(raw).unwrap();
    assert_eq!(v["a"], "\\ud83d", "an escaped backslash stays text");
    assert_eq!(v["b"], "x\u{FFFD}");
    assert_eq!(v["c"], "\u{1F600}", "a valid pair stays");
    assert_eq!(v["d"], "\u{FFFD}y");
    assert!(payload::fix_lone_surrogates(br#"{"a":"\\ud83d"}"#).is_none());
}

/// Review I1 backstop: stdin that still does not decode keeps the tool's
/// template when its `tool_name` can be found.
#[tokio::test]
async fn an_undecodable_payload_keeps_the_tool_template() {
    let gone = Client::new(std::env::temp_dir().join("inumaki-hook-never.sock"));
    let block = |name: Option<&str>| {
        let b = Blocked {
            class: BlockClass::UnparsablePayload,
            kinds: Vec::new(),
        };
        output::block(Harness::ClaudeCode, name, &b)
    };
    let cases: [(&[u8], Option<&str>); 5] = [
        (
            br#"{"session_id":"s","tool_name" : "Grep","tool_input":{"path":"/x/kunden"},"tool_response":{"content":"Zyxwuria Quol"#,
            Some("Grep"),
        ),
        (br#"{"tool_name":"mcp__crm-x__get","tool_response":[{"type":"text","text":"Zyx"#, Some("mcp__crm-x__get")),
        // Not a hooked tool, or only inside a string (escaped quotes): no template.
        (br#"{"tool_name":"Hermes","tool_response":"#, None),
        (br#"{"tool_response":"{\"tool_name\":\"Read\"} Zyx"#, None),
        (b"Zyxwuria not json", None),
    ];
    for (raw, name) in cases {
        let out = run_with_deadline(Harness::ClaudeCode, raw, &gone, Duration::from_secs(1)).await;
        assert_eq!(out.as_deref(), Some(block(name).as_str()));
        let v: Value = serde_json::from_str(&out.unwrap()).unwrap();
        let u = &v["hookSpecificOutput"]["updatedToolOutput"];
        assert_eq!(u.is_string(), name.is_none());
    }
}

/// Review I1 backstop: stdin over MAX_STDIN keeps the tool's template.
#[test]
fn the_binary_blocks_oversized_stdin_in_the_tool_template() {
    let data = tempfile::tempdir().unwrap();
    let missing = data.path().join("none.sock");
    let mut p = br#"{"tool_name":"Bash","cwd":"/tmp","tool_input":{"command":"cat a"},"tool_response":{"stdout":""#.to_vec();
    p.extend_from_slice(CANARY.as_bytes());
    p.resize(inumaki_hook::MAX_STDIN + 1024, b'x');
    p.extend_from_slice(br#"","stderr":"","interrupted":false}}"#);
    let out = run_bin(
        &["claude-code", "--socket", missing.to_str().unwrap()],
        data.path(),
        &p,
    );
    assert!(out.status.success());
    let line = String::from_utf8(out.stdout).unwrap();
    let line = line.strip_suffix('\n').unwrap().to_string();
    assert_blocked(
        Harness::ClaudeCode,
        &p,
        &Some(line.clone()),
        BlockClass::TooLarge,
        &[],
    );
    let v: Value = serde_json::from_str(&line).unwrap();
    let stdout = v["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        .as_str()
        .unwrap();
    assert!(
        stdout.starts_with("blocked by inumaki (too_large"),
        "the bash template: {line}"
    );
}

/// Review M2: quoted and escaped paths, option values, and `$HOME`; the
/// plain split is unioned in (re-review I1: an apostrophe in a comment or a
/// heredoc must not hide a later path).
#[test]
fn shell_paths_honour_quotes_escapes_options_and_home() {
    let home = std::env::var("HOME").unwrap();
    let paths = |tool: &str, cmd: Value| {
        let v = json!({ "tool_name": tool, "cwd": "/w", "tool_input": { "command": cmd }, "tool_response": "x" });
        payload::parse(Harness::ClaudeCode, v).unwrap().paths
    };
    let has = |got: &[String], want: &[&str]| {
        for w in want {
            assert!(got.iter().any(|g| g == w), "{w} missing from {got:?}");
        }
    };
    let cmd = r#"cat "~/Google Drive/Kunden/a.txt" Kunden\ Ordner/x --input=/Users/x/K/a.csv -f/etc/k.txt -rn $HOME/Kunden/y "${HOME}/z w" '$HOME/lit' \$HOME/esc --verbose plain && echo ok"#;
    let got = paths("Bash", json!(cmd));
    has(
        &got,
        &[
            "~/Google Drive/Kunden/a.txt",
            "Kunden Ordner/x",
            "/Users/x/K/a.csv",
            "/etc/k.txt",
            &format!("{home}/Kunden/y"),
            &format!("{home}/z w"),
            "$HOME/lit",
            "/w",
        ],
    );
    assert!(
        !got.iter()
            .any(|g| g == "plain" || g == "-rn" || g == "--verbose")
    );
    for cmd in [
        "# check the customer's file\ncat /Users/x/Kunden/a.txt",
        "cat <<EOF\nDon't forget\nEOF\ncat ~/Kunden/a.txt",
    ] {
        let got = paths("Bash", json!(cmd));
        has(
            &got,
            &[if cmd.starts_with('#') {
                "/Users/x/Kunden/a.txt"
            } else {
                "~/Kunden/a.txt"
            }],
        );
    }
    // PowerShell: a backslash separates path parts, it does not escape.
    has(
        &paths("PowerShell", json!(r"Get-Content C:\Users\x\Kunden\a.txt")),
        &[r"C:\Users\x\Kunden\a.txt", "/w"],
    );
    // An argv array: each element is one word, spaces included, and an
    // element holding a shell command is split as well.
    has(
        &paths("Bash", json!(["cat", "/x/Google Drive/a.txt"])),
        &["/x/Google Drive/a.txt", "/w"],
    );
    has(
        &paths("Bash", json!(["bash", "-lc", "cat ~/Kunden/a.txt"])),
        &["~/Kunden/a.txt"],
    );
}

/// Re-review 2: path extraction is linear. A quadratic dedupe over ~100k
/// distinct words would run past the harness's hook timeout (the harness
/// then uses the original output).
#[test]
fn many_path_words_extract_in_linear_time() {
    let words: Vec<String> = (0..100_000)
        .map(|i| format!("/x/Kunden/k{i}.txt"))
        .collect();
    let cmd = format!("cat {} {}", words.join(" "), words[..10].join(" "));
    let v = json!({ "tool_name": "Bash", "cwd": "/w", "tool_input": { "command": cmd }, "tool_response": "x" });
    let t = std::time::Instant::now();
    let call = payload::parse(Harness::ClaudeCode, v).unwrap();
    let took = t.elapsed();
    assert_eq!(
        call.paths.len(),
        100_001,
        "every distinct path once, plus cwd"
    );
    assert_eq!(call.paths[0], "/x/Kunden/k0.txt", "first-seen order");
    assert!(took < Duration::from_secs(5), "took {took:?}");
}
