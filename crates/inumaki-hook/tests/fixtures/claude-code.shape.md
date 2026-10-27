# Claude Code `PostToolUse` replacement format

Verified 2026-09-29 against the hooks reference
(https://code.claude.com/docs/en/hooks.md), the Agent SDK tool output types
(https://code.claude.com/docs/en/agent-sdk/typescript.md, "Tool Output Types"),
and the tool output schemas and hook handling inside the installed Claude Code
2.1.284 binary (read-only string inspection; no session was run). Full record:
`docs/harness-adapters.md`, section 5.

## Output the hook prints (exit code 0)

Replace:

```json
{"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": <value in the tool's output shape>}}
```

Pass: print nothing and exit 0 (Claude Code then uses the original output).

Quoted from the hooks reference, "PostToolUse decision control":

> `updatedToolOutput` | Replaces the tool's output with the provided value before it is sent to Claude. The value must match the tool's output shape

> The replacement value must match the tool's output shape. Built-in tools return structured objects rather than plain strings. For example, `Bash` returns an object with `stdout`, `stderr`, `interrupted`, and `isImage` fields. For built-in tools, a value that doesn't match the tool's output schema is ignored and the original output is used. MCP tool output is passed through without schema validation.

`decision: "block"` is not a replacement: "`"block"` adds the `reason` next to the tool result. Claude still sees the original output; to replace it, use `updatedToolOutput`".

Consequence: a bare string is **refused** for every built-in tool (it does not
match the object schema, so the original is used). `BLOCK_AS_BARE_STRING = false`.
Blocks use the per-tool templates in `crates/inumaki-hook/templates/`.

## Output shape per hooked tool (quoted from the SDK reference)

| Tool name | `/v1/hook` tool | Replacement shape (required keys) | Block template |
|---|---|---|---|
| `Bash` | `bash` | `{stdout: string, stderr: string, interrupted: boolean, isImage?: boolean, …}` | `bash.block.json` |
| `PowerShell` | `bash` | same core as `Bash` (`stdout`, `stderr`, `interrupted`; binary schema) | `powershell.block.json` |
| `Read` | `read` | `{type: "text", file: {filePath, content, numLines, startLine, totalLines}}` (union on `type`: `text`, `image`, `notebook`, `pdf`, `parts`, `file_unchanged`) | `read.block.json` |
| `Grep` | `grep` | `{mode?: "content"\|"files_with_matches"\|"count", numFiles: number, filenames: string[], content?: string, numLines?, numMatches?, …}` | `grep.block.json` |
| `Glob` | `glob` | `{durationMs: number, numFiles: number, filenames: string[], truncated: boolean, …}` | `glob.block.json` |
| `Edit` | `edit` | `{filePath, oldString, newString, originalFile: string\|null, structuredPatch: [...], userModified: boolean, replaceAll: boolean, gitDiff?}` | `edit.block.json` |
| `WebFetch` | `web_fetch` | `{bytes: number, code: number, codeText: string, result: string, durationMs: number, url: string}` | `web_fetch.block.json` |
| `ReadMcpResourceTool` | `mcp` | `{contents: [{uri: string, mimeType?, text?, blobSavedTo?}], error?}` | `read_mcp_resource.block.json` |
| `mcp__<server>__<tool>` | `mcp` | `string` or `[{type: string, ...}]` (content blocks); not schema-validated | `mcp.block.json` |

Every template sets each text field to `"%BLOCK%"` (the hook substitutes the block
message), numbers to fixed constants, booleans to `false`, and never copies a value
from a real output. The templates were checked by hand against the zod output
schemas in the 2.1.284 binary; they were not executed against a live session.

## Discriminators (a replacement that changes one of these blocks instead)

`type`, `mimeType`, `mediaType`, `role`, `kind`, `mode`, `status`, `action`, `source`.
These are enum-typed in the hooked tools' output schemas (`Read.type`,
`Read.file.type`, `Read.pages[].mediaType`, `Read.source`, `Grep.mode`,
`Edit.gitDiff.status`, `Bash.gitOperation.commit.kind`,
`Bash.gitOperation.{branch,pr}.action`, MCP content-block `type`/`mimeType`, MCP
annotations `audience` roles). A sanitizer rewrite of an enum value fails the
schema, and Claude Code then uses the original: that is a leak, so the hook blocks.

## Not replaceable (documented limitations)

- A tool call that fails (Bash/PowerShell non-zero exit that Claude Code does not
  treat as benign, MCP `isError` results) fires `PostToolUseFailure`, whose only
  output field is `additionalContext`. The error text, which carries up to about
  10,000 characters of command output, reaches the model unfiltered.
- All matching hooks run in parallel on the original output; another hook's
  `updatedToolOutput` competes last-write-wins with ours.
