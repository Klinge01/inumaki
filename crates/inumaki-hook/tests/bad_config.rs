//! Fail closed when the data directory's `inumaki.toml` cannot name the
//! socket: without `--socket`, the real hook binary withholds the tool
//! result (a block), never passes it through.

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::json;

fn run(data_dir: &std::path::Path) -> (String, String, bool) {
    let payload = json!({
        "session_id": "00000000-0000-4000-8000-000000000001",
        "transcript_path": "/tmp/t.jsonl",
        "cwd": "/tmp",
        "permission_mode": "default",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "cat x" },
        "tool_response": { "stdout": "TOOL-OUTPUT-MARKER", "stderr": "" },
        "tool_use_id": "toolu_01SYNTHETIC0000000000000009",
        "duration_ms": 7
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_inumaki-hook"))
        .arg("claude-code")
        .env("INUMAKI_DATA_DIR", data_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
        out.status.success(),
    )
}

#[test]
fn an_invalid_config_blocks_the_result_instead_of_passing_it() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("inumaki.toml"), "SECRET-TEXT = = [").unwrap();
    let (stdout, stderr, ok) = run(dir.path());
    assert!(ok);
    // A pass prints nothing; a block prints the replacement.
    assert!(!stdout.is_empty(), "a bad config must block, not pass");
    assert!(
        stdout.contains("block") || stdout.contains("inumaki"),
        "{stdout}"
    );
    assert!(!stdout.contains("TOOL-OUTPUT-MARKER"), "{stdout}");
    assert!(stderr.contains("config file unreadable"), "{stderr}");
    assert!(!stderr.contains("SECRET-TEXT") && !stdout.contains("SECRET-TEXT"));
}

#[test]
fn an_unknown_daemon_key_blocks_too() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("inumaki.toml"),
        "[daemon]\nsocekt = \"x\"\n",
    )
    .unwrap();
    let (stdout, _, ok) = run(dir.path());
    assert!(ok && !stdout.is_empty());
}
