# Codex `PostToolUse` replacement format

Verified 2026-09-29 against the hooks guide (https://learn.chatgpt.com/docs/hooks.md,
redirected from developers.openai.com/codex/hooks) and the `openai/codex` source at
tag `rust-v0.158.0` (the installed `codex-cli 0.158.0`):
`codex-rs/hooks/src/events/post_tool_use.rs`, `codex-rs/hooks/src/engine/output_parser.rs`,
`codex-rs/core/src/tools/registry.rs`, `codex-rs/core/src/tools/context.rs`,
`codex-rs/hooks/schema/generated/post-tool-use.command.{input,output}.schema.json`.
Full record: `docs/harness-adapters.md`, section 5.

## Input (shell tools)

`tool_name` is `"Bash"` for `exec_command` (and for a `write_stdin` poll that observes
the command's completion); `tool_input` is `{"command": "<string>"}`; `tool_response`
is a JSON **string**, the model-facing (truncated) output
(`ExecCommandToolOutput::post_tool_use_response` returns
`JsonValue::String(self.truncated_output_with_policy(...))`).

## Output the hook prints (exit code 0)

Replace and block use the same shape, `CODEX_MODE = ReplaceViaReason`:

```json
{"decision": "block", "reason": "<replacement text, non-empty after trimming>"}
```

Pass: print nothing and exit 0.

From the guide: "For this event, `decision: "block"` doesn't undo the completed Bash
command. Instead, Codex records the feedback, replaces the tool result with that
feedback, and continues the model from the hook-provided message."

From `registry.rs` (0.158.0):

```rust
if outcome.should_block {
    let message = outcome.feedback_message.unwrap_or_else(|| {
        "PostToolUse hook blocked the tool result".to_string()
    });
    let err = FunctionCallError::RespondToModel(message);
```

The model receives `reason` verbatim as the call's output (several blocking hooks'
reasons are joined).

Rules the hook must keep:

- `reason` must be non-empty after `trim()`. `output_parser.rs` marks
  `decision:block` with an empty or missing reason invalid ("PostToolUse hook returned
  decision:block without a non-empty reason"), the run is `Failed`, and the
  **original** result is used. If the sanitized text trims to empty, print a fixed
  non-empty text instead.
- Do not use `continue: false` for replacement: its `PostToolUseFeedbackOutput`
  keeps the original for `code_mode_result`, so a code-mode script receives the
  original output.
- `reason` without `decision` is invalid ("PostToolUse hook returned reason without
  decision") and the original is used.
- `updatedMCPToolOutput` and `suppressOutput` are "parsed but not supported yet";
  returning them marks the run failed and the original is used.
- Any exit code other than 0 or 2, a timeout, or unparsable JSON output marks the
  run failed and the original is used.

## Not replaceable (documented limitations)

- While the command is still running, `post_tool_use_response` returns `None`
  (`if self.process_id.is_some() || self.hook_command.is_none() { return None; }`):
  the first output chunk of a long-running command, and every intermediate
  `write_stdin` poll, reaches the model with no `PostToolUse`.
- `registry.rs` runs `PostToolUse` only when `success_for_logging()` is true, so
  failed tool results (for example MCP error results) are not hooked.
- Hooks outside `~/.codex/hooks.json`'s trusted set do not run: a new or changed
  non-managed hook is skipped until the user trusts it in `/hooks`.
