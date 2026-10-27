//! What the hook prints (docs/harness-adapters.md §5, hook shapes).
//!
//! Claude Code: `hookSpecificOutput.updatedToolOutput` in the tool's output
//! shape. A replacement is the original shape with sanitized string values.
//! A block is the tool's template from `templates/`, every text field set
//! to the block message: Claude Code checks `updatedToolOutput` against the
//! built-in tool's output schema and uses the original when it does not
//! match, so a bare string would leak (`BLOCK_AS_BARE_STRING = false`). A
//! block never copies a value of the original output (review C3).
//!
//! Codex: `{"decision": "block", "reason": …}`; Codex replaces the tool
//! result with `reason` (`ReplaceViaReason`), which must be non-empty after
//! trimming or the original is used. `continue: false` is never printed.

use serde_json::{Value, json};

use crate::{BlockClass, Blocked, Harness, block_message};

/// How Codex's `PostToolUse` answer replaces a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexMode {
    /// The reason replaces the result text.
    ReplaceViaReason,
    /// Codex can only block; the reason is the block message.
    BlockOnly,
}

/// Task 1's finding (Codex 0.158.0, `core/src/tools/registry.rs`).
pub const CODEX_MODE: CodexMode = CodexMode::ReplaceViaReason;

/// Task 1's finding: Claude Code refuses a bare-string `updatedToolOutput`
/// for every built-in tool, so blocks use [`BLOCK_TEMPLATES`].
pub const BLOCK_AS_BARE_STRING: bool = false;

/// The text a Codex replacement carries when the sanitized output trims to
/// nothing (an empty `reason` would make Codex use the original).
pub const CODEX_EMPTY: &str = "(no output)";

/// Per-tool block shapes keyed by Claude Code tool name; `"mcp"` serves every
/// `mcp__…` tool. The string `"%BLOCK%"` marks where the message goes.
pub const BLOCK_TEMPLATES: &[(&str, &str)] = &[
    ("Bash", include_str!("../templates/bash.block.json")),
    (
        "PowerShell",
        include_str!("../templates/powershell.block.json"),
    ),
    ("Read", include_str!("../templates/read.block.json")),
    ("Grep", include_str!("../templates/grep.block.json")),
    ("Glob", include_str!("../templates/glob.block.json")),
    ("Edit", include_str!("../templates/edit.block.json")),
    (
        "WebFetch",
        include_str!("../templates/web_fetch.block.json"),
    ),
    (
        "ReadMcpResourceTool",
        include_str!("../templates/read_mcp_resource.block.json"),
    ),
    ("mcp", include_str!("../templates/mcp.block.json")),
];

fn claude(updated: Value) -> String {
    json!({ "hookSpecificOutput": { "hookEventName": "PostToolUse", "updatedToolOutput": updated } })
        .to_string()
}

fn codex(reason: String) -> String {
    let reason = if reason.trim().is_empty() {
        CODEX_EMPTY.to_string()
    } else {
        reason
    };
    json!({ "decision": "block", "reason": reason }).to_string()
}

/// The block value for a Claude Code tool: its template filled with `msg`,
/// or a bare string for a tool without a template (MCP output is not
/// schema-checked; an unknown built-in tool has no known shape).
pub fn claude_block(tool_name: Option<&str>, msg: &str) -> Value {
    if !BLOCK_AS_BARE_STRING {
        let key = tool_name.map(|n| if n.starts_with("mcp__") { "mcp" } else { n });
        if let Some((_, tpl)) = key.and_then(|k| BLOCK_TEMPLATES.iter().find(|(t, _)| *t == k)) {
            let filled = tpl.replace("\"%BLOCK%\"", &Value::String(msg.to_string()).to_string());
            if let Ok(v) = serde_json::from_str(&filled) {
                return v;
            }
        }
    }
    Value::String(msg.to_string())
}

/// The replacement for a sanitized result (`response` already holds the
/// sanitized string values).
pub fn replace(h: Harness, response: Value, kinds: &[String]) -> String {
    match (h, CODEX_MODE) {
        (Harness::ClaudeCode, _) => claude(response),
        (Harness::Codex, CodexMode::ReplaceViaReason) => codex(match response {
            Value::String(s) => s,
            other => other.to_string(),
        }),
        (Harness::Codex, CodexMode::BlockOnly) => codex(block_message(&Blocked {
            class: BlockClass::PrivacyBlock,
            kinds: kinds.to_vec(),
        })),
    }
}

/// The block replacement; `tool_name` is the payload's tool name when known.
pub fn block(h: Harness, tool_name: Option<&str>, b: &Blocked) -> String {
    let msg = block_message(b);
    match h {
        Harness::ClaudeCode => claude(claude_block(tool_name, &msg)),
        Harness::Codex => codex(msg),
    }
}
