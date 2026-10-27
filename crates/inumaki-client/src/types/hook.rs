//! `POST /v1/hook` (M6 spec §5, §9.7). The request and the `replace`
//! answer carry tool output that can hold originals: `Debug` prints lengths.

use serde::{Deserialize, Serialize};

/// Harness of a hook call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookHarness {
    /// Claude Code.
    ClaudeCode,
    /// Codex.
    Codex,
}

/// Tool class of a hook call (spec §9.7 tool mapping).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookTool {
    /// Shell.
    Bash,
    /// File read.
    Read,
    /// Grep.
    Grep,
    /// Glob.
    Glob,
    /// Edit or MultiEdit.
    Edit,
    /// WebFetch.
    WebFetch,
    /// An MCP tool.
    Mcp,
    /// Anything else.
    Other,
}

/// `POST /v1/hook` body.
#[derive(Clone, Serialize, Deserialize)]
pub struct HookRequest {
    /// Harness.
    pub harness: HookHarness,
    /// Tool class.
    pub tool: HookTool,
    /// Working directory of the tool call.
    pub cwd: String,
    /// Paths the tool input references (absolute or relative to `cwd`).
    pub paths: Vec<String>,
    /// The tool's output, walked in a fixed order (each object key, each
    /// string value, each number as decimal text) and handed over as the
    /// resulting strings; the daemon does the walking.
    pub texts: Vec<String>,
}

impl std::fmt::Debug for HookRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookRequest")
            .field("harness", &self.harness)
            .field("tool", &self.tool)
            .field("paths", &self.paths.len())
            .field("texts_len", &self.texts.len())
            .finish_non_exhaustive()
    }
}

/// `POST /v1/hook` answer (200). A block is `451 privacy_block`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum HookResponse {
    /// Pass the output unchanged.
    Pass,
    /// Replace the output with `texts` (same length and order as the
    /// request's `texts`).
    Replace {
        /// Sanitized texts.
        texts: Vec<String>,
        /// Kinds replaced.
        kinds: Vec<String>,
    },
}

impl std::fmt::Debug for HookResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HookResponse::Pass => f.write_str("Pass"),
            HookResponse::Replace { texts, kinds } => f
                .debug_struct("Replace")
                .field("texts_len", &texts.len())
                .field("kinds", kinds)
                .finish(),
        }
    }
}
