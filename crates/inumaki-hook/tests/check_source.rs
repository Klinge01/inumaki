//! The end-to-end check's Claude Code hook step without Claude Code (M6-3
//! Task 9b diagnosis): a real `inumakid` in process, the check's own folder
//! dataset (`POST /v1/check {"paths": ["mirror"]}`, so the source file is
//! exactly what `check::mirror::prepare` writes), and the real
//! `inumaki-hook` binary fed `PostToolUse` payloads in the Claude Code shape
//! (docs/harness-adapters.md §5) for the two calls the check's script makes:
//! `Bash` `cat '<source>/canary.txt'` must come back as tokens with one
//! `hook`/`released` activity record, the `Read` of the mirrored file passes.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use inumaki_client::{ActivityQuery, Client, FrontDoor, Method, Verdict};
use serde_json::{Value, json};

/// Run the real hook binary on one payload; its stdout.
fn hook(socket: &Path, payload: &Value) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_inumaki-hook"))
        .args(["claude-code", "--socket", socket.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap()
}

/// A Claude Code `PostToolUse` payload with the common fields.
fn payload(cwd: &str, tool: &str, input: Value, response: Value) -> Value {
    json!({
        "session_id": "00000000-0000-4000-8000-000000000001",
        "transcript_path": format!("{cwd}/t.jsonl"),
        "cwd": cwd,
        "permission_mode": "default",
        "hook_event_name": "PostToolUse",
        "tool_name": tool,
        "tool_input": input,
        "tool_response": response,
        "tool_use_id": "toolu_01SYNTHETIC0000000000000009",
        "duration_ms": 7
    })
}

/// The check's temporary source file: `<temp>/inumaki-check-<tag>-*/source/canary.txt`.
fn check_source(data_dir: &Path) -> PathBuf {
    let prefix = format!(
        "{}{}-",
        inumakid::check::TMP_PREFIX,
        inumakid::check::tmp_tag(data_dir)
    );
    let root = std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_string_lossy().starts_with(&prefix))
        .expect("the check's temporary root")
        .path();
    root.join("source").join("canary.txt")
}

/// Removes the check's temporary root and the socket when the test ends, also
/// on a panic before `DELETE /v1/check/{id}` (which removes the root itself).
struct TempCleanup {
    socket: PathBuf,
    prefix: String,
}

impl Drop for TempCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
        if let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) {
            for e in entries.filter_map(Result::ok) {
                if e.file_name().to_string_lossy().starts_with(&self.prefix) {
                    let _ = std::fs::remove_dir_all(e.path());
                }
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bash_cat_of_the_check_source_is_tokenized_and_the_mirror_read_passes() {
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
    let socket = std::env::temp_dir().join(format!("inumaki-hook-chk-{}.sock", std::process::id()));
    let opts = inumakid::StartOptions {
        config: Some(cfg),
        data_dir: Some(data.clone()),
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
    let _cleanup = TempCleanup {
        socket: socket.clone(),
        prefix: format!(
            "{}{}-",
            inumakid::check::TMP_PREFIX,
            inumakid::check::tmp_tag(&data)
        ),
    };
    let client = Client::new(&socket);
    for _ in 0..400 {
        if client.status().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let r = client
        .raw(
            Method::POST,
            "/v1/check",
            br#"{"paths":["mirror"]}"#.to_vec(),
        )
        .await
        .unwrap();
    let created: Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(r.status, 201, "{created}");
    assert_eq!(created["paths"]["mirror"]["available"], true, "{created}");
    let mirror_file = created["mirror"]["path"].as_str().unwrap().to_string();
    let source = check_source(&state.data_dir);
    let text = std::fs::read_to_string(&source).unwrap();
    assert!(text.starts_with("Record: "), "the check's canary line");
    let canonical = std::fs::canonicalize(&source).unwrap();
    // The harness's working directory: an empty directory elsewhere.
    let work = tempfile::tempdir().unwrap();
    let work = work.path().to_str().unwrap().to_string();

    let s = socket.clone();
    let runs: Vec<(String, Value)> = [
        source.display().to_string(),
        canonical.display().to_string(),
    ]
    .into_iter()
    .map(|p| {
        let bash = payload(
            &work,
            "Bash",
            json!({ "command": format!("cat '{p}'"), "description": "Show the file" }),
            json!({ "stdout": text.trim_end(), "stderr": "", "interrupted": false,
                    "isImage": false, "noOutputExpected": false }),
        );
        (p, bash)
    })
    .collect();
    let outs: Vec<String> = tokio::task::spawn_blocking(move || {
        runs.iter().map(|(_, b)| hook(&s, b)).collect::<Vec<_>>()
    })
    .await
    .unwrap();
    for out in &outs {
        let v: Value = serde_json::from_str(out.trim_end())
            .unwrap_or_else(|_| panic!("a replacement, not a pass or a block line: {out:?}"));
        let stdout = v["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
            .as_str()
            .unwrap();
        assert!(stdout.starts_with("Record: <PERSON_"), "tokens: {stdout}");
        assert!(!stdout.contains('@'), "the email is a token: {stdout}");
    }

    // The same `cat` of the source with stdout that holds no canary value: no
    // trigger can fire, so a Replace (and a released record) comes only from
    // the command's path resolving into the dataset root.
    let plain = payload(
        &work,
        "Bash",
        json!({ "command": format!("cat '{}'", source.display()), "description": "Show the file" }),
        json!({ "stdout": "x", "stderr": "", "interrupted": false,
                "isImage": false, "noOutputExpected": false }),
    );
    let s = socket.clone();
    let out = tokio::task::spawn_blocking(move || hook(&s, &plain))
        .await
        .unwrap();
    let v: Value = serde_json::from_str(out.trim_end())
        .unwrap_or_else(|_| panic!("a replacement for a root match, not a pass: {out:?}"));
    assert!(
        v["hookSpecificOutput"]["updatedToolOutput"]["stdout"].is_string(),
        "{out}"
    );

    // The Read of the mirrored file (tokens only) passes: nothing on stdout.
    let read = payload(
        &work,
        "Read",
        json!({ "file_path": mirror_file }),
        json!({ "type": "text", "file": { "filePath": mirror_file,
                "content": "Record: <PERSON_a1b2c3>, IBAN <IBAN_d4e5f6>, email <EMAIL_a7b8c9>\n",
                "numLines": 1, "startLine": 1, "totalLines": 1 } }),
    );
    let s = socket.clone();
    let out = tokio::task::spawn_blocking(move || hook(&s, &read))
        .await
        .unwrap();
    assert_eq!(out, "", "the mirrored Read passes");

    // harness_real reads the activity after the check is deleted.
    let id = created["id"].as_str().unwrap();
    let _ = client
        .raw(Method::DELETE, &format!("/v1/check/{id}"), Vec::new())
        .await;
    let acts = client
        .activity(&ActivityQuery {
            dataset: None,
            since: None,
            limit: Some(500),
        })
        .await
        .unwrap();
    let released = acts
        .records
        .iter()
        .filter(|r| r.front_door == FrontDoor::Hook && r.verdict == Verdict::Released)
        .count();
    assert_eq!(
        released, 3,
        "one hook/released record per Bash result, the root-match run included"
    );

    state.shutdown.send_replace(true);
}
