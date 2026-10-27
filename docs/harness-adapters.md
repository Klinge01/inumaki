# Harness adapters: verified keys, hook shapes, and editors

This page records what `inumaki-adapters` and `inumaki-hook` may write and print for
each agent harness. Every value here was read from the harness's current
documentation or its source; quotes are verbatim. Where a fact comes from reading
source rather than documentation, or could not be exercised end to end, the row
says so. Later plan tasks (adapters, hook) implement exactly what this page says;
a change of harness behaviour is a change to this page first.

Read on 2026-09-29. Nothing here was verified by running a harness against a real
account: the installed `claude` (2.1.284) and `codex` (0.158.0) binaries were only
asked for `--version`, and the Claude Code binary's embedded JavaScript was
inspected read-only with `strings`.

Sources, all read 2026-09-29:

| Harness | Documentation | Source |
|---|---|---|
| Claude Code 2.1.284 | `code.claude.com/docs/en/{mcp,settings,settings-reference,permissions,hooks,tools-reference,env-vars,claude-directory,authentication,llm-gateway-connect,llm-gateway-protocol,managed-settings}.md`, `code.claude.com/docs/en/agent-sdk/typescript.md` | installed binary `~/.local/share/claude/versions/2.1.284` (strings only) |
| Codex CLI 0.158.0 | `learn.chatgpt.com/docs/{hooks,config-file/config-reference,config-file/config-advanced,extend/mcp,enterprise/managed-configuration}.md` (developers.openai.com/codex/… redirects there) | `github.com/openai/codex` tag `rust-v0.158.0` |
| Hermes Agent | (the repository is the documentation) | `github.com/NousResearch/hermes-agent` tag `v2026.9.24` (MIT) |
| OpenClaw | `docs.openclaw.ai/{gateway/config-extensions,concepts/model-providers/custom-providers,gateway/config-agents/models,gateway/config-agents/sandbox,gateway/sandboxing/multiple-folders-for-one-agent,gateway/authentication}.md` | `github.com/openclaw/openclaw` tag `v2026.9.6` |

## 1. Key table per harness

`<gw>` is `http://127.0.0.1:8789/mcp/<dataset>`, `<proxy X>` is the `base_url` of
route `X` from `GET /v1/proxy` (spec §9.6), `<bin>` is the stable binary directory.

### Tested version ranges

| Harness | `TESTED_MIN` | `TESTED_MAX` | Why this range |
|---|---|---|---|
| Claude Code | 2.1.284 | 2.1.284 | The binary whose tool schemas and hook handling were inspected. Several facts below are version-gated (for example `TaskOutput` removed in 2.1.277, `mcp_server` in hook input from 2.1.274). |
| Codex | 0.158.0 | 0.158.0 | The source tag read. Hooks are `Stage::Stable, default_enabled: true` in this tag. The CX-MCP keys `required`, `startup_timeout_sec`, and the user's `default_tools_approval_mode` were recorded on 0.159.2, outside this range; the range is not raised until goldens are recorded on that version. |
| Hermes Agent | 2026.9.24 | 2026.9.24 | The release tag read (`_config_version: 46`). |
| OpenClaw | 2026.9.6 | 2026.9.6 | The release tag read. |

A later golden run may widen a range; an untested version still connects and its
connection page shows an "Untested version" chip (spec §4.1; the app redesign
replaced the badge, 2026-10-12).

**Request headers and harness upgrades.** The proxy forwards a request header
only when its name is on the upstream's allowlist (M8 spec §20, amendment 2026-10-12)
or in `[proxy.upstreams.<id>] extra_headers`. A harness release that adds a header
the list does not know has that header dropped, and the proxy counts it in the log
by label. If the harness needs it, add the name to `extra_headers` (`docs/cli.md`)
until the built-in list is amended. The user-gated `harness_record` test
(`crates/inumakid/tests/harness_record.rs`) is the re-check: it runs the installed
harness once directly and once through the proxy and asserts that the allowlist
dropped no header beyond the ones that are never forwarded.

### Claude Code

| Row | Key path | Value shape | Source |
|---|---|---|---|
| CC-MCP user scope | `~/.claude.json` → `mcpServers.<name>` | `{"type": "http", "url": <gw>, "headers": {"Authorization": "Bearer <token>"}}` | mcp.md |
| CC-MCP local scope | `~/.claude.json` → `projects.<absolute dir>.mcpServers.<name>` | same shape | mcp.md |
| CC-FILES | `~/.claude/settings.json` → `permissions.additionalDirectories` | array of directory paths; append the mirror root | settings-reference.md |
| CC-CHAT | `~/.claude/settings.json` → `env.ANTHROPIC_BASE_URL` | string `<proxy anthropic>` (no `/v1`, section 3) | settings-reference.md, env-vars.md |
| CC-HOOK | `~/.claude/settings.json` → `hooks.PostToolUse[]` += one matcher group | `{"matcher": <HOOK_MATCHER>, "hooks": [{"type": "command", "command": "<bin>/inumaki-hook claude-code", "timeout": 30}]}` | hooks.md |

Quotes:

- mcp.md, local scope: "The command writes the server into the entry for your current project inside `~/.claude.json`." Example: `{"projects": {"/path/to/your/project": {"mcpServers": {"stripe": {"type": "http", "url": "https://mcp.stripe.com"}}}}}`.
- mcp.md, user scope: "User-scoped servers are stored in `~/.claude.json` and provide cross-project accessibility". Header example: `'{"type":"http","url":"https://api.weather.com/mcp","headers":{"Authorization":"Bearer token"}}'`.
- mcp.md, precedence: "When the same server is defined in more than one place, Claude Code connects to it once, using the definition from the highest-precedence source. The entire server entry from that source is used; fields are not merged across scopes. 1. Local scope 2. Project scope 3. User scope 4. Plugin-provided servers 5. claude.ai connectors". A local-scope entry therefore shadows a user-scope gateway entry of the same name.
- mcp.md: "the `type` field accepts `streamable-http` as an alias for `http`".
- settings-reference.md, `permissions.additionalDirectories`: "Give Claude file access to directories outside the one you started in, as additional working directories. … **Type**: array of directory paths".
- settings-reference.md, `env`: "**Type**: object mapping variable names to string values"; example `"ANTHROPIC_BASE_URL": "https://proxy.example.com"`.
- hooks.md, locations: "`~/.claude/settings.json` | All your projects"; "Hook entries merge across settings levels rather than replacing each other".
- hooks.md, `timeout`: "Seconds before canceling. … Defaults: 600 for `command`".

**CC-CHAT is a separate switch in the app.** `env.ANTHROPIC_BASE_URL` sits in the
user-level `settings.json`, and Claude Code hot-reloads `env` in every open
session, so writing it switches every open window, in every project, to the proxy
at once (measured 2026-10-11, Claude Code 2.1.296). So the app's Connect for
Claude Code writes MCP, Files, and the hook, and not the chat route or the client
header; the user turns Chat on with its own switch on the Claude Code connection page, after a
confirm that says what changes, and turns it off the same way. Until the user sets
the switch, it shows whether the active backup already holds the route, so a route
written earlier (by the app or the CLI) shows as on. A user Revert resets the
choice. The CLI is unchanged: `inumaki connect apply claude-code` writes the chat
route unless `--no-chat` is given, and prints the warning
`claude_code_chat_live` when it does. A connected harness whose Chat path is not
routed is shown as "Chat: off, your choice" in grey, with the sentence of
`chat_not_protected` under it (the app showed it as red "Chat: not protected"
before the 2026-10-12 redesign; the words still say the chat is not filtered). The hook is not
affected by the switch; whether open windows pick up a new `hooks.PostToolUse`
entry at once was not measured, and the app says "may".

`HOOK_MATCHER` (section 5 explains the tool list):

```
^(Bash|PowerShell|Read|Grep|Glob|Edit|WebFetch|ReadMcpResourceTool)$|^mcp__(?!(<g1>|<g2>|…)__).*
```

where `<gN>` are the MCP servers that point at the gateway after the apply
(already behind it, or protected by this apply). When there are none, the clause is
`|^mcp__.*`. So every MCP tool is hooked except the gateway's own: the gateway
already returns tokens, and a second check there would cost latency for nothing.
Excluding instead of listing also covers the servers the adapter cannot see or
that appear later: project-scope servers from `.mcp.json`, plugin servers
(`mcp__plugin_<plugin-name>_<server-name>__<tool>`, hooks.md), entries added by
hand, and servers added after the apply.

Claude Code builds an MCP tool name as `mcp__<name>__<tool>`, with every character
of the server name outside `[A-Za-z0-9_-]` replaced by `_` (read from the 2.1.289
binary: `name.replace(/[^a-zA-Z0-9_-]/g, "_")`). The adapter writes `<gN>` in that
form, so a server named `crm.intern` is excluded as `crm_intern`, and the names need
no escaping. A gateway-routed name stays hooked (is not excluded) when a server
that is not gateway-routed has the same form or a form that starts with `<gN>__`.
A server the adapter cannot see (project scope, plugin) with such a name is
excluded by mistake; that needs two servers whose names differ only in punctuation
or a `__` suffix.

hooks.md, matcher table: "Only letters, digits, `_`, `-`, spaces, `,`, and `|`" →
"Exact string, or list of exact strings"; "Contains any other character" →
"JavaScript regular expression, unanchored". The `^`, `$`, and `(` put the whole
matcher on the regular-expression path, so the anchors are required: unanchored
`Read` also matches `ReadMcpResourceDirTool`, and `Edit` matches `NotebookEdit`.
The negative lookahead `(?!…)` is valid JavaScript regular-expression syntax, but
that Claude Code compiles this matcher as written is not verified against the real
binary; the `harness-tests` run must confirm that a gateway tool is not hooked and
any other MCP tool is.

**Claude Code in the end-to-end check** (`inumaki-adapters/src/check.rs`). The
check runs `claude -p` with a temporary `CLAUDE_CONFIG_DIR` and an empty working
directory. `--allowedTools` pre-approves the check's `lookup_record` tool and
`Read`, plus `Bash` when the hook is connected; it is an approval list, not a
restriction: read-only tools such as `Grep` and `Glob` still run without approval
inside the working and added directories, and `Bash` without pre-approval is
refused in `-p` because nobody can approve it. The check's hook (written only
when the hook is connected) therefore matches `Bash|Read|Grep|Glob`, every tool
that can read the mirror or the source directory, so the hook is the single
control on their text (`inumaki-hook` maps `Grep` and `Glob`, and the daemon's
`/v1/hook` takes their payloads like any other tool's). The scripted model reads the mirrored canary with
`Read` and `cat`s the canary in the check's own source directory with `Bash`.
Both files lie outside the working directory, so the run passes each directory
with `--add-dir`: the mirror directory always (the parent of `mirror.path`), the
source directory (`mirror.source_dir`, M6 spec §9.7 amendment 2026-10-10) only
when the hook is connected. In the 9b run 4 with Claude Code 2.1.296 the `Bash`
call came back as an error and no Bash hook ran, while the `Read` of the added
mirror directory worked; the likely cause is that Claude Code's Bash refuses paths
outside the working and added directories. `--add-dir` is the mechanism the
`Read` already showed to be honoured; a scoped permission rule is not needed
because `Bash` is allowed anyway. Without the hook, `Bash` stays denied and the
source directory is not added, so the source text cannot reach the model on that
path. The app passes the directory only when it has the daemon's shape
(`<temp>/inumaki-check-…/source`, absolute, no `.` or `..` segment, no control
characters). That this makes the `Bash` call succeed is not yet confirmed by a
real run; the daemon's `bash=` diagnostic now names the error class
(`ErrorPermission`, `ErrorMissing`, `ErrorOther`) so the next run shows the cause.

### Codex

| Row | Key path | Value shape | Source |
|---|---|---|---|
| CX-MCP | `~/.codex/config.toml` → `[mcp_servers.<name>]` `url`, `http_headers`, `required`, `startup_timeout_sec` | `url = <gw>`, `http_headers = { Authorization = "Bearer <token>" }`, `required = true`, `startup_timeout_sec = 30` (see below) | config-reference.md; Codex 0.159.2 recording (M8 spec §20) |
| CX-FILES | `~/.codex/config.toml` → `sandbox_workspace_write.writable_roots` | array of strings; append each connected outbox | config-reference.md |
| CX-CHAT-KEY | `~/.codex/config.toml` → `model_provider = "inumaki"`; `[model_providers.inumaki]` `name = "inumaki"`, `base_url = "<proxy openai>/v1"`, `wire_api = "responses"`, `env_key = "OPENAI_API_KEY"` | strings | config-reference.md, config-advanced.md |
| CX-CHAT-CHATGPT | same provider table with `base_url = "<proxy codex>"`, `requires_openai_auth = true`, no `env_key` | strings, boolean | config-reference.md, `model-provider-info/src/lib.rs` |
| CX-HOOK | `~/.codex/hooks.json` → `hooks.PostToolUse[]` += `{"matcher": "^Bash$", "hooks": [{"type": "command", "command": "<bin>/inumaki-hook codex", "timeout": 30}]}`, appended **last** | JSON | hooks.md, `hooks/src/engine/discovery.rs`, `config/src/hook_config.rs` |
| CX-PROFILES | see below | | config-advanced.md |

Quotes (config-reference.md, the key table):

- `mcp_servers.<id>.url` | string | "Endpoint for an MCP streamable HTTP server."
- `mcp_servers.<id>.http_headers` | map<string,string> | "Static HTTP headers included with each MCP HTTP request."
- `sandbox_workspace_write.writable_roots` | array<string> | "Additional writable roots when `sandbox_mode = "workspace-write"`."
- `model_provider` | string | "Provider id from `model_providers` (default: `openai`)."
- `model_providers.<id>.base_url` | string | "API base URL for the model provider."
- `model_providers.<id>.env_key` | string | "Environment variable supplying the provider API key."
- `model_providers.<id>.requires_openai_auth` | boolean | "The provider uses OpenAI authentication (defaults to false)."
- `model_providers.<id>.wire_api` | responses | "Protocol used by the provider. `responses` is the only supported value, and it is the default when omitted."
- `model_providers.<id>` | table | "Custom provider definition. Built-in provider IDs (`openai`, `ollama`, and `lmstudio`) are reserved and cannot be overridden."
- `features.hooks` | boolean | "Enable lifecycle hooks loaded from `hooks.json` or inline `[hooks]` config. `features.codex_hooks` is a deprecated alias." (`features/src/lib.rs`: `key: "hooks", stage: Stage::Stable, default_enabled: true`.)
- Project config: "Codex ignores `openai_base_url`, `chatgpt_base_url`, …, `model_provider`, `model_providers`, … when they appear in a project-local `.codex/config.toml`".

hooks.json shape (`config/src/hook_config.rs`, 0.158.0):

```rust
#[serde(deny_unknown_fields)]
pub struct HooksFile {
    pub description: Option<String>,
    pub hooks: HookEventsToml,          // "PostToolUse": Vec<MatcherGroup>, …
}
pub struct MatcherGroup { pub matcher: Option<String>, pub hooks: Vec<HookHandlerConfig> }
#[serde(tag = "type")]
pub enum HookHandlerConfig {
    #[serde(rename = "command")]
    Command { command: String, #[serde(rename = "commandWindows", alias = "command_windows")] command_windows: Option<String>,
              #[serde(rename = "timeout")] timeout_sec: Option<u64>, r#async: bool,
              #[serde(rename = "statusMessage")] status_message: Option<String>,
              #[serde(rename = "additionalContextLimit")] additional_context_limit: Option<usize> },
    #[serde(rename = "mcp_tool")] McpTool { … }, #[serde(rename = "prompt")] Prompt {}, #[serde(rename = "agent")] Agent {},
}
```

Only `description` and `hooks` are allowed at the top level. Shell tool names for
the matcher: the only shell tools in 0.158.0 are `exec_command` and `write_stdin`
(unified exec; there is no separate `shell` handler), and both are reported to
hooks as `Bash` (`HookToolName::bash()`, "Match as `Bash`" in the guide's tool
coverage table). The matcher is therefore `^Bash$`.

**Hook trust.** hooks.md: "Before a non-managed hook can run, Codex requires you to
review and trust the exact hook definition. Codex records trust against the hook's
current hash, so new or changed hooks are marked for review and skipped until
trusted." The trust record lives in `config.toml` under `[hooks.state."<key>"]`
with `trusted_hash`, where `<key>` is `"{source path}:post_tool_use:{group_index}:{handler_index}"`
(`hooks/src/lib.rs::hook_key`). Consequences for the adapter:
- It appends its matcher group after every existing `PostToolUse` group. Inserting
  earlier would shift the user's group indexes and turn their trusted hooks into
  "Modified" (skipped) hooks.
- It does not write a `trusted_hash`: that would bypass Codex's review. Until the
  user trusts the hook in `/hooks`, the hook does not run; status reports it as not
  yet active (see section 7).
- A user Revert removes only our own trust record: the `[hooks.state."<key>"]` table
  at exactly the key of the handler that carries our marker (its position is read
  from `hooks.json` before the revert; the path is matched as written and in
  canonical form). Other positions, other files, and other projects keep their
  records, and an empty `hooks.state` or `hooks` table is removed only if this
  step emptied it. Codex writes the record itself while the hook is connected
  (walk of 2026-10-11), and leaving it would trust an identical hook command after
  a later Connect without a new review. `HarnessAdapter::revert_final` does this;
  only the app's Revert and `inumaki connect revert` call it. A Reconnect (revert
  then apply) calls plain `revert` and keeps the record, so the hook stays trusted.
  If the removal fails, the revert still stands and `RevertReport.codex_trust_left`
  (`CODEX_TRUST_LEFT_NOTE`) tells the user to remove the record in Codex's
  `/hooks`. Codex's model usage counters are Codex's own and stay.
- Revert succeeds for a first-time Codex config (ruling L67). When `config.toml` had
  no `mcp_servers` or `hooks` table before Connect, and Codex wrote to the file
  since (it appends the trust record), reverting `[mcp_servers.<name>]` used to
  fail because it left an empty parent table that the TOML writer drops. The backup
  now records how many parent tables an edit created (`created_parents`), and the
  key-level revert removes those that it leaves empty. A table that existed before
  Connect stays. Backups written before this field keep the old behavior (the
  revert of such a first-time config fails closed).

**CX-MCP: waiting for the gateway, and tool approval** (integrator ruling
2026-10-10, recorded from Codex 0.159.2). Every gateway entry the adapter writes
carries two keys beyond `url` and `http_headers`:

- `required = true`. `codex exec` starts its first turn before MCP servers are
  up, so without it a session can run without the inumaki tools at all, and
  nothing tells the user. With it Codex waits for the gateway and fails visibly
  when the gateway does not come up.
- `startup_timeout_sec = 30` bounds that wait. The gateway answers in
  milliseconds once `inumakid` runs; 30 seconds covers a service that is still
  starting at login, and is the value the end-to-end check uses.

These keys, and the approval behavior below, were recorded on Codex 0.159.2,
outside the golden range (`TESTED_MAX` stays 0.158.0 until goldens exist for the
newer version).

The whole entry is owned (`mcp_servers.*`), so revert removes both keys with the
entry and restores the file byte for byte when nothing else changed. Status and
drift compare each entry with what the latest apply wrote: an entry connected
before these keys existed (written without them, and recorded without them in
its backup) reads as connected, not as changed outside inumaki, and the next
connect or reconnect rewrites it with both keys. Status does not report such an
entry as outdated.

The adapter never writes `default_tools_approval_mode`. Under
`approval_policy = "never"` Codex refuses an MCP tool call ("MCP tool call
requires approval, but approval policy is never") unless the server entry sets
`default_tools_approval_mode = "approve"`, and auto-approving tool calls is the
user's security decision. Instead, when a connect writes a gateway entry and the
top-level `approval_policy` of `$CODEX_HOME/config.toml` is `"never"`, the
connect outcome carries one fixed warning (`ConnectWarning::CodexApprovalNever`,
code `codex_approval_never`), printed by `inumaki connect apply` and shown by the
app: "Codex is set to approval_policy = never and will refuse the inumaki tool
calls; to allow them, set default_tools_approval_mode on the inumaki server
entry in Codex's config." Only that key is read; profile files, an unreadable or
invalid `config.toml`, and any other value or shape of the key give no warning.
The remedy is the user's: add `default_tools_approval_mode = "approve"` to the
inumaki entry under `[mcp_servers.<name>]`, or use another approval policy.

**The hook warning (ruling L97).** A connect whose plan installs the hook gives
`ConnectWarning::HookBlocksWhenStopped` (code `hook_blocks_when_stopped`):
"While inumaki is stopped, tool output in every connected session is blocked.
Start the service to recover; Revert also needs it running." Claude Code and
Codex give it when the plan carries a hook (also when an identical Codex entry is
already in place);
Hermes Agent and OpenClaw install no hook and never give it. The golden tests pin
that the warning appears exactly when the apply writes the hook. See section 9 and
[The hook while the service is stopped](threat-model.md#the-hook-while-the-service-is-stopped).

`default_tools_approval_mode` is a **user-owned sub-key** of the otherwise owned
entry (`inumaki_adapters::harness::user_subkeys`, follow-up ruling 2026-10-10):

- Drift and status compare the entry with what inumaki wrote while ignoring
  that key, so adding, changing, or removing it does not make the MCP path
  "changed outside inumaki". Any other change to the entry still does.
- Every connect carries its value, as written (a non-string value too), into
  the rewritten entry: `inumaki connect apply` reads it from the file, and the
  app, whose Reconnect reverts before it re-applies, reads it with the server
  list before the revert and passes it in the plan (`GatewayEntry::approval_mode`).
  inumaki never adds the key on its own.
- Only inumaki's own entry lends it: an entry that already points at the gateway,
  and in the adapter's own file fallback only the entry of the same name with
  the same gateway URL. Protecting a server whose own entry has the key does not
  copy it onto the gateway entry (the warning still shows, and revert gives the
  user's entry back with it), and a stale entry for another dataset lends
  nothing.
- Revert treats the entry as unchanged when only that key differs: the entry is
  removed (or its pre-connect value restored) without a conflict, and the
  user's key goes with it. The file is then restored key by key, not byte for
  byte.
- Once a gateway entry has the key (any value), the approval warning is not
  shown for it: the user has decided.

**CX-PROFILES.** config-advanced.md: "In Codex 0.134.0 and later, `--profile` no
longer reads `[profiles.profile-name]` from `config.toml`, and the top-level
`profile = "profile-name"` selector is no longer supported." and "When you pass
`--profile profile-name`, Codex loads `~/.codex/config.toml`, then overlays
`~/.codex/profile-name.config.toml`." So `[profiles.<name>].model_provider` does
**not** override the top-level `model_provider` (the table is ignored), but a
profile file `$CODEX_HOME/<name>.config.toml` that sets `model_provider` does, for
sessions started with `--profile <name>`. Drift detection should report such files
(key names only).

**Codex in the end-to-end check** (`inumaki-adapters/src/check.rs`, recorded
from Codex 0.159.2 on 2026-10-10, M8 spec §20). The check's throwaway
`config.toml` gives its gateway entry the two CX-MCP keys `required` and
`startup_timeout_sec`, and one more:

- `required = true`. `codex exec` starts the turn before MCP servers finish
  starting, so without it the first `/v1/responses` request advertises no MCP
  tools, the check's scripted model skips the `lookup_record` call, and the run
  ends with no tokens. With it Codex waits for the server first.
- `startup_timeout_sec = 30` bounds that wait (Codex parses it as a number:
  `startup_timeout_sec = "abc"` fails with "expected f64"; unknown keys are
  ignored silently, so acceptance alone proves nothing).
- `default_tools_approval_mode = "approve"`. The check runs with
  `approval_policy = "never"`, under which an MCP call is otherwise refused
  with "MCP tool call requires approval, but approval policy is never". It
  applies to the check's own gateway entry, in a temporary `CODEX_HOME`, and
  never to the user's configuration.

Codex advertises MCP tools as a Responses `namespace` tool
(`{"type": "namespace", "name": "mcp__<server, - as _>", "tools": [...]}`) and
expects the model's call as a `function_call` with `"namespace"` and the bare
tool name; the scripted upstream and the proxy handle both shapes.

Also available, not used: top-level `openai_base_url` ("Base URL override for the
built-in `openai` model provider").

### Hermes Agent

| Row | Key path | Value shape | Source |
|---|---|---|---|
| HM-MCP | `~/.hermes/config.yaml` → `mcp_servers.<name>` | `url: <gw>`, `headers: {Authorization: "Bearer <token>"}` | `cli-config.yaml.example`, `tools/mcp_tool_transport.py` |
| HM-CHAT-KEY | `providers.inumaki` with `base_url`, `key_env`, `api_mode`; provider selection `model.provider: inumaki`; model `model.default` | strings | `cli-config.yaml.example`, `hermes_cli/runtime_provider_custom.py` |
| HM-CHAT-OAUTH (Anthropic login) | `model.base_url: <proxy anthropic>` with `model.provider: anthropic` | string | `hermes_cli/runtime_provider.py` |
| HM-CHAT-OAUTH (ChatGPT/Codex login) | environment variable `HERMES_CODEX_BASE_URL` (process env or `$HERMES_HOME/.env`); no YAML key is honoured on every path | string | `hermes_cli/auth_codex.py`, `hermes_cli/runtime_provider.py` |

Quotes (`cli-config.yaml.example`, v2026.9.24):

```yaml
# HTTP servers (connect to a URL):
#   url: the MCP server endpoint
#   headers: HTTP headers (e.g., for authentication)
```
```yaml
  # Inference provider selection:
  #   "auto"         - Auto-detect from credentials (default)
  ...
  provider: "auto"
```
```yaml
  # providers:
  #   my-proxy:
  #     base_url: "https://llm.internal.example.com/v1"
  #     key_env: "MY_PROXY_API_KEY"
```

`tools/mcp_tool_transport.py:532`: `headers = dict(config.get("headers") or {})`.

`runtime_provider_custom.py::_match_new_style_provider` resolves `model.provider`
against `providers.<name>` (skipping entries with `enabled: false`) and reads
`base_url` (aliases `api`, `url`), `key_env` (alias `api_key_env`), `api_key`,
`key_cmd`, `api_mode` (alias `transport`), `default_model`, `extra_headers`,
`extra_body`. A name equal to a built-in provider id is shadowed by the built-in
(`_shadowed_by_builtin`), so the entry must be named `inumaki`, not `openai` or
`anthropic`. `api_mode` values: `chat_completions`, `codex_responses`,
`anthropic_messages`, `bedrock_converse`, `codex_app_server`; a `base_url` whose path
ends in `/anthropic` is detected as `anthropic_messages`
(`_detect_api_mode_for_url`).

Anthropic OAuth: `_anthropic_cfg_base_url` honours `model.base_url` "only when the
configured provider is anthropic" and when `_anthropic_base_url_override_ok` holds,
which includes any URL whose path ends in `/anthropic`. It is used on the env path
and the credential-pool path. Read from source only; not exercised.

ChatGPT/Codex OAuth: `auth_codex.py`:

```python
def _codex_base_url() -> str:
    return os.getenv("HERMES_CODEX_BASE_URL", "").strip().rstrip("/") or DEFAULT_CODEX_BASE_URL
```

`_resolve_oauth_runtime` takes the base URL from these credentials, so on that path
`model.base_url` is not consulted; the pool path consults `HERMES_CODEX_BASE_URL`
first and `model.base_url` only when the pool row still carries the canonical URL.
The only override honoured on every path is the environment variable.

### OpenClaw

| Row | Key path | Value shape | Source |
|---|---|---|---|
| OC-MCP | `~/.openclaw/openclaw.json` → `mcp.servers.<name>` | `{url: <gw>, transport: "streamable-http", headers: {Authorization: "Bearer <token>"}}` | config-extensions.md, `zod-schema.mcp-server.ts` |
| OC-FILES | `agents.defaults.sandbox.docker.binds` | array of strings `"<host path>:<container path>:ro"`, e.g. `"<mirror root>:/inumaki-mirror:ro"` | config-agents/sandbox.md, sandboxing/multiple-folders-for-one-agent.md |
| OC-CHAT-KEY | `models.providers.inumaki` = `{baseUrl, api, apiKey, models: [{id, name}]}`; model selection `agents.defaults.model.primary = "inumaki/<model id>"` | see below | custom-providers.md, config-agents/models.md, `types.models.ts` |

Quotes:

- config-extensions.md: "`mcp.servers`: named stdio or remote MCP server definitions … Remote entries use `transport: "streamable-http"` or `transport: "sse"`"; example `remote: { url: "https://example.com/mcp", transport: "streamable-http", … headers: { Authorization: "Bearer ${MCP_REMOTE_TOKEN}" } }`.
- `zod-schema.mcp-server.ts`: `transport: z.union([z.literal("stdio"), z.literal("sse"), z.literal("streamable-http")]).optional()`, `headers: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()]))`.
- multiple-folders-for-one-agent.md: "Each entry maps a host folder to a container path with an explicit access mode: `host-directory:container-directory:ro`" and "Bind sources outside the workspace/agent-workspace allowlisted roots are blocked by default; override with `agents.defaults.sandbox.docker.dangerouslyAllowExternalBindSources: true`." Also: "Bind targets that shadow the reserved container mount points (`/workspace`, `/agent`) are also blocked by default".
- `types.models.ts`: `baseUrl: string; apiKey?: SecretInput; headers?: Record<string, SecretInput>; request?: …; models: ModelDefinitionConfig[];` ("Model catalog entries exposed by this provider", required).
- `packages/llm-core/src/model-data.ts`: `api` is one of `"openai-completions"`, `"openai-responses"`, `"openai-chatgpt-responses"`, `"anthropic-messages"`, `"google-generative-ai"`, `"google-vertex"`, `"github-copilot"`, `"bedrock-converse-stream"`, `"ollama"`, `"pi-messages"`, `"azure-openai-responses"`.
- custom-providers.md: examples `baseUrl: "http://127.0.0.1:17434/v1", apiKey: "${LLMMAN_API_KEY}", api: "openai-completions"` and `baseUrl: "https://api.synthetic.new/anthropic", apiKey: "${SYNTHETIC_API_KEY}", api: "anthropic-messages"`; "Custom/local provider endpoints also trust that exact configured `scheme://host:port` origin for guarded model requests, including loopback".
- config-agents/models.md: "`model`: accepts either a string (`"provider/model"`) or an object (`{ primary, fallbacks }`)."

`api` per route: OpenAI route `api: "openai-completions"`, `baseUrl: "<proxy openai>/v1"`;
Anthropic route `api: "anthropic-messages"`, `baseUrl: "<proxy anthropic>"`. Provider
fields besides `baseUrl`: `api`, `apiKey` (the user's existing key or `${ENV}`
reference, which the proxy forwards upstream), and `models` (at least the model the
user selects, `[{ id: "<model id>", name: "<model id>" }]`). `agents.defaults.model`
may be a string or an object; the adapter owns `agents.defaults.model.primary` when
it is an object and `agents.defaults.model` when it is a string.

## 2. Config-dir overrides

| Harness | Override | Effect | Source |
|---|---|---|---|
| Claude Code | `CLAUDE_CONFIG_DIR` | settings, credentials, and `~/.claude/*` move under it; the global file becomes `$CLAUDE_CONFIG_DIR/.claude.json` | claude-directory.md ("If you set `CLAUDE_CONFIG_DIR`, every `~/.claude` path on this page lives under that directory instead"); binary: `I(process.env.CLAUDE_CONFIG_DIR||Do(), ".claude"+suffix+".json")`, and a legacy `<config dir>/.config.json` wins when it exists |
| Codex | `CODEX_HOME` | default `~/.codex`; holds `config.toml`, `hooks.json`, `auth.json`, profile files | config-advanced.md ("Codex stores its local state under `CODEX_HOME` (defaults to `~/.codex`)") |
| Hermes Agent | `HERMES_HOME` | default `~/.hermes` (Windows `%LOCALAPPDATA%\hermes`); `config.yaml`, `.env`, `auth.json` live under it | `hermes_constants.py::get_hermes_home`, `hermes_cli/config.py::get_config_path` |
| OpenClaw | `OPENCLAW_CONFIG_PATH` (the file), `OPENCLAW_STATE_DIR` (the directory), `OPENCLAW_HOME`, `OPENCLAW_PROFILE` | default `~/.openclaw/openclaw.json` "(or $OPENCLAW_STATE_DIR/openclaw.json)" | `src/config/paths.ts` |

Managed configuration that can override user keys (spec §4.4): Claude Code
`/Library/Application Support/ClaudeCode/managed-settings.json` (macOS),
`/etc/claude-code/managed-settings.json` (Linux), plus MDM and server-managed
sources; Codex `/etc/codex/requirements.toml` (managed-configuration.md), with
`allow_managed_hooks_only` able to skip user hooks. Claude Code's
`allowManagedHooksOnly` and `disableAllHooks` do the same for its hooks.

## 3. Base-URL convention per harness

Given a route `base_url` from `GET /v1/proxy` such as `http://127.0.0.1:8787/openai`:

| Harness | Route | Written value | Why |
|---|---|---|---|
| Claude Code | anthropic | `<proxy anthropic>` (no `/v1`) | llm-gateway-protocol.md: `ANTHROPIC_BASE_URL` serves "`/v1/messages`"; llm-gateway-connect.md posts to `"$ANTHROPIC_BASE_URL/v1/messages"` |
| Codex, API key | openai | `<proxy openai>/v1` | `model-provider-info/src/lib.rs`: default `"https://api.openai.com/v1"`; config-advanced.md examples `base_url = "https://proxy.example.com/v1"` |
| Codex, ChatGPT | codex | `<proxy codex>` (no `/v1`) | `CHATGPT_CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex"` |
| Hermes, `providers.inumaki` OpenAI wire | openai | `<proxy openai>/v1` | example `base_url: "http://127.0.0.1:4000/v1"` |
| Hermes, Anthropic | anthropic | `<proxy anthropic>` (no `/v1`; the path must end in `/anthropic`) | `_detect_api_mode_for_url`; `_ANTHROPIC_DEFAULT_BASE_URL = "https://api.anthropic.com"` |
| Hermes, Codex OAuth | codex | `<proxy codex>` | `DEFAULT_CODEX_BASE_URL` |
| OpenClaw | openai | `<proxy openai>/v1` | custom-providers.md examples |
| OpenClaw | anthropic | `<proxy anthropic>` | custom-providers.md example `https://api.synthetic.new/anthropic` |

## 4. Login-kind signals (names only; never read a value)

| Harness | `Oauth` when | `ApiKey` when | Source |
|---|---|---|---|
| Claude Code | `<config dir>/.credentials.json` exists; or the macOS keychain generic-password item with service `Claude Code-credentials` exists (with `CLAUDE_CONFIG_DIR` set the service gets a suffix `-<first 8 hex of sha256(config dir)>`; account `$USER`); the key `oauthAccount` in `.claude.json` is a supporting signal | key `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` under `env` in a settings file; key `apiKeyHelper` in a settings file; key `primaryApiKey` in `.claude.json` (a saved Console key; binary only) | authentication.md; binary (`wN("-credentials")`) |
| Codex | `$CODEX_HOME/auth.json` has key `tokens` | `auth.json` key `OPENAI_API_KEY` with a non-null value. The key is always serialized (no `skip_serializing_if`) and is `null` for ChatGPT logins: test presence with `Option<IgnoredAny>`, not key presence. With `cli_auth_credentials_store = "keyring"`/`"auto"` there may be no file; keyring service `Codex Auth` | `login/src/auth/storage.rs` |
| Hermes Agent | `$HERMES_HOME/auth.json` keys `active_provider`, `providers.<id>`; `model.provider` is `anthropic` with no API key name in `.env`, or `openai-codex` | key names in `$HERMES_HOME/.env` (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`, …) or `key_env` names in `providers.*` | `hermes_cli/auth.py`, `cli-config.yaml.example` |
| OpenClaw | `auth.profiles.<id>.mode == "oauth"` in `openclaw.json` | `auth.profiles.<id>.mode` `"api_key"`/`"token"`, or `apiKey` present in `models.providers.<id>` | authentication.md (credentials live in each agent's `openclaw-agent.sqlite`; do not read it) |

## 5. Hook shapes

### Claude Code `PostToolUse`

Input (hooks.md, "PostToolUse input" and "Common input fields"): `session_id`,
`transcript_path`, `cwd`, `permission_mode`, `hook_event_name: "PostToolUse"`,
`tool_name`, `tool_input`, `tool_response`, `tool_use_id`, optional `duration_ms`,
`prompt_id`, `scratchpad_dir`, `effort`, `agent_id`, `agent_type`, and for MCP tools
`mcp_server: {name, source}` (2.1.274+). "File-tool `tool_input` paths arrive … always
absolute".

Output: `{"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": <value>}}`
on exit 0; nothing for pass. Quote: "For built-in tools, a value that doesn't match
the tool's output schema is ignored and the original output is used. MCP tool output
is passed through without schema validation." The binary confirms it:
`e.outputSchema?.safeParse(Do)` and on failure "PostToolUse hook returned
updatedToolOutput that does not match …'s output shape; using original output."

**`BLOCK_AS_BARE_STRING = false`.** Every built-in tool's output schema is an
object, so a bare string is refused and the original is used. Blocks use the
per-tool templates in `crates/inumaki-hook/templates/` (below).

`HOOK_TOOLS` and the `/v1/hook` tool mapping:

| Tool | Input path fields | `/v1/hook` tool | Output shape (SDK reference / binary schema) | Template |
|---|---|---|---|---|
| `Bash` | `command` (path-shaped words) | `bash` | `{stdout, stderr, interrupted, isImage?, rawOutputPath?, backgroundTaskId?, persistedOutputPath?, structuredContent?, gitOperation?, …}` | `bash.block.json` |
| `PowerShell` | `command` | `bash` | `{stdout, stderr, interrupted, returnCodeInterpretation?, isImage?, …}` (binary schema) | `powershell.block.json` |
| `Read` | `file_path` | `read` | union on `type`: `text {file: {filePath, content, numLines, startLine, totalLines}}`, `image`, `notebook`, `pdf`, `parts`, `file_unchanged` | `read.block.json` |
| `Grep` | `path` | `grep` | `{mode?, numFiles, filenames[], content?, numLines?, numMatches?, …}` | `grep.block.json` |
| `Glob` | `path` | `glob` | `{durationMs, numFiles, filenames[], truncated, …}` | `glob.block.json` |
| `Edit` | `file_path` | `edit` | `{filePath, oldString, newString, originalFile, structuredPatch[], userModified, replaceAll, gitDiff?, staged?}` | `edit.block.json` |
| `WebFetch` | none (`url` is not a path) | `web_fetch` | `{bytes, code, codeText, result, durationMs, url, artifactRead?}` | `web_fetch.block.json` |
| `ReadMcpResourceTool` | none (`server`, `uri`) | `mcp` | `{contents: [{uri, mimeType?, text?, blobSavedTo?}], error?}` | `read_mcp_resource.block.json` |
| `mcp__<server>__<tool>` | none | `mcp` | `string` or content-block array `[{type, …}]` | `mcp.block.json` |

Other Claude Code tools and why they are not hooked:

- `MultiEdit`: not a tool in 2.1.284 (permissions.md calls it "the legacy `MultiEdit` tool"; absent from the tools reference). Dropped from the matcher.
- `TaskOutput` / `BashOutput`: `TaskOutput` "Removed in Claude Code v2.1.277 … Claude reads a background task's output file with `Read` instead" (typescript.md); `BashOutput` does not exist. Background output is therefore covered by `Read`.
- `Monitor`: returns only `{taskId, timeoutMs, persistent?}`; the watched command's lines arrive as events, not as a tool result, so no `PostToolUse` carries them. Not hookable; documented limitation.
- `Write`, `NotebookEdit`: the model sees only a status line naming the path ("File created successfully at: …", "Updated cell …"); the content is the model's own.
- `WebSearch`, `Agent`, `Workflow`, `LSP`, `ReadMcpResourceDirTool`, `ListMcpResourcesTool`, the task and cron tools: web results, subagent text built from already-hooked tool results, or metadata only. Not in the hook's scope (spec §5.2: it guards connected data).

`DISCRIMINATORS` = `type`, `mimeType`, `mediaType`, `role`, `kind`, `mode`, `status`,
`action`, `source`. The spec's four plus the enum-typed keys found in the hooked
tools' schemas: `Grep.mode`, `Edit.gitDiff.status`, `Bash.gitOperation.{branch,pr}.action`,
`Bash.gitOperation.commit.kind`, `Read.pages[].mediaType`, `Read.source`. A
rewrite of any enum value fails the schema and the original is used, so the hook
blocks when one would change.

Per-tool honouring of `updatedToolOutput`: honoured for every built-in tool that has
an output schema and a result mapper (the hooks reference: "`updatedToolOutput`,
which works for all tools"). The binary drops rewrites of one class only: "PostToolUse
hook for … tried to rewrite an account memory server answer; the rewrite was
dropped" (a claude.ai account memory server, never in our matcher). No hooked tool
ignores `updatedToolOutput`.

Rules for the hook that follow from the binary:

- `Read` with `type` `image`, `pdf`, or `parts`, and `Bash` with `isImage: true`, carry base64 data. The hook asks the daemon, passes on `pass`, and blocks with the template on any `replace` (section 9). For `pdf` and `parts`, `restoreTransientForRemap` copies the original `base64`/`pages` back when the replacement keeps the same `type` and `filePath` with empty data.
- All matching hooks run in parallel on the original output, and the binary's own guidance says "an identity rewrite competes last-write-wins with sibling rewrites and can clobber a real redaction". A second `PostToolUse` hook that rewrites the same tool's output can undo ours. Documented limitation.
- Exit 0 always. Exit 2 shows stderr to Claude, and other codes are non-blocking errors that leave the original in place.

Failed tool calls are **not** covered: hooks.md, `PostToolUseFailure`: "Runs when a
tool that started executing fails: the tool threw an error, or an MCP tool returned
an error result." Its decision control has only `additionalContext`, and "The `error`
string is generally the same text Claude receives as the failed tool's result … For
Bash and PowerShell, a command that ran and exited produces a first line `Exit code N`,
then any output the command produced". tools-reference.md: a failing command's result
is "Inline up to roughly 10,000 characters". So a `Bash` command that exits non-zero
(other than the benign exit-1 list: `grep`, `rg`, `find`, `diff`, `test`, …) reaches
the model unfiltered, and so do MCP error results.

### Codex `PostToolUse`

Input (generated schema `post-tool-use.command.input.schema.json`, required):
`cwd`, `hook_event_name: "PostToolUse"`, `model`, `permission_mode`, `session_id`,
`tool_input`, `tool_name`, `tool_response`, `tool_use_id`, `transcript_path`,
`turn_id`; optional `agent_id`, `agent_type`. For the shell tools `tool_name` is
`"Bash"`, `tool_input` is `{"command": <string>}`, and `tool_response` is a JSON
string with the model-facing output.

Output: **`CODEX_MODE = ReplaceViaReason`**, with the exact response

```json
{"decision": "block", "reason": "<sanitized text or block message>"}
```

hooks.md: "For this event, `decision: "block"` doesn't undo the completed Bash
command. Instead, Codex records the feedback, replaces the tool result with that
feedback, and continues the model from the hook-provided message." Source
(`core/src/tools/registry.rs`): a blocking outcome returns
`FunctionCallError::RespondToModel(message)` with the joined reasons as the call's
output. `reason` must be non-empty after trimming, or the run is invalid and the
original result is used. Not `continue: false`: that path keeps the original for
code-mode scripts (`code_mode_result` returns `self.original`). Details and quotes:
`crates/inumaki-hook/tests/fixtures/codex.shape.md`.

Not covered: output chunks of a command that is still running
(`post_tool_use_response` returns `None` while `process_id` is set), failed tool
results (`registry.rs` runs `PostToolUse` only when `success_for_logging()`), hooks
the user has not trusted in `/hooks`, and hosted tools ("Hosted tools, such as
`WebSearch` | No | No").

Fixtures: `crates/inumaki-hook/tests/fixtures/claude-code/{bash,read,grep,mcp}.payload.json`
and `crates/inumaki-hook/tests/fixtures/codex/shell.payload.json`; each
`tool_response` text contains the canary `Zyxwuria Quolnath`.

## 6. Editor decision

All five crates pass the corpus in `crates/inumaki-adapters/tests/corpus/`
(`cargo test -p inumaki-adapters --test roundtrip`, 3 passed, 2026-09-29).

| Crate | Pinned version | License | Role |
|---|---|---|---|
| `jsonc-parser` (features `cst`, `serde_json`) | 0.34.0 | MIT | CST editor for `Format::Json` and `Format::Json5` |
| `json5` | 1.3.1 | MIT | standard parser for JSON5 |
| `toml_edit` | 0.25.15 (`+spec-1.1.0`) | MIT OR Apache-2.0 | TOML editor |
| `yaml-edit` | 0.3.2 | Apache-2.0 | YAML editor |
| `serde_yaml_ng` | 0.10.0 | MIT | standard parser for YAML (maintained fork of `serde_yaml`) |

All licenses are Apache-2.0-compatible. The standard JSON and TOML parsers
(`serde_json`, `toml`) are existing workspace dependencies.

**YAML: edit with `yaml_edit::YamlFile`, not `yaml_edit::Document`.**
`Document::from_str` rejects the corpus with "Input contains stream-level comments
outside the document. Use YamlFile::from_str() to preserve them.", and every real
Hermes `config.yaml` starts with a comment. `YamlFile::from_str` round-trips it
byte-identically. A scratch probe (not committed) also showed that `yaml-edit` edits
are semantically correct when a nested value is inserted as a parsed mapping
(`YamlFile::from_str(snippet)?.document()?.as_mapping()`): setting
`mcp_servers.<name>` to `{url, headers}`, setting `model.provider`, quoting values
such as `@a: b # x` and `yes`, and removing an entry all parsed back to the expected
value. Inserting a `BTreeMap<String, YamlValue>` directly produced mis-indented output
that changed the meaning (the semantic check would refuse it). Blank-line placement
around an inserted or removed entry can shift; that is cosmetic. "YAML: refuse" does
not apply.

Refusal samples (checked by a scratch probe on 2026-09-29; the editor tests pin them):

- `openclaw-edge.json5` (one comma missing): `jsonc-parser` CST parses it and prints it back identically; `json5` rejects it. The standard parse refuses it (`Refusal::Syntax`).
- `openclaw-infinity.json5`: `json5` parses `Infinity` as `null` in `serde_json::Value`; `parse_standard` must refuse non-finite numbers.
- `hermes-flow.yaml` and `hermes-anchor.yaml`: `yaml-edit` parses and round-trips both, and `serde_yaml_ng` parses both (the alias expands). The refusal must come from our own check of the `yaml-edit` syntax tree: `SyntaxKind::LEFT_BRACE`/`LEFT_BRACKET` (flow collections) in an edited section, and `ANCHOR`, `REFERENCE`, `ALIAS`, `MERGE_KEY`, `TAG`, or `DIRECTIVE` anywhere, or more than one document.

## 7. Deviations from spec §4.3

One line each; the M6 spec's as-built amendments carry them:

1. CC Hook matcher: `MultiEdit` removed (legacy, absent in 2.1.284); `PowerShell` and `ReadMcpResourceTool` added; the regex is anchored (`^(…)$|^mcp__(?!(…)__).*`), because the unanchored form also matches `ReadMcpResourceDirTool` and `NotebookEdit`. The MCP clause excludes the gateway-routed servers instead of listing the others (section 1), with names in Claude Code's tool-name form.
2. CC Hook: bare-string `updatedToolOutput` is refused for built-in tools (`BLOCK_AS_BARE_STRING = false`); blocks use per-tool templates.
3. CC Hook: failed tool calls (non-benign non-zero exit, MCP error results) go through `PostToolUseFailure`, which cannot replace output; their text reaches the model unfiltered. Spec §5.1's list of what the hook cannot prevent needs this line.
4. CC Hook: a sibling `PostToolUse` hook that returns `updatedToolOutput` for the same call competes last-write-wins with ours.
5. CC-MCP: a local-scope entry shadows a user-scope entry of the same name (local > project > user), so the local-scope listing is required, not optional.
6. CC global file: `~/.claude.json` is `$CLAUDE_CONFIG_DIR/.claude.json` when that variable is set, and a legacy `<config dir>/.config.json` takes precedence when it exists.
7. CX-HOOK: Codex runs a new or changed user hook only after the user trusts it in `/hooks`. The adapter appends its group last and does not write `trusted_hash`; the hook state stays "needs trust in Codex" until `[hooks.state."<key>"].trusted_hash` exists.
8. CX-HOOK: `CODEX_MODE = ReplaceViaReason` via `{"decision":"block","reason":…}` (non-empty reason). The spike's `continue: false` must not be used.
9. CX-HOOK: output of a command that is still running, and failed tool results, get no `PostToolUse`. Documented limitation.
10. CX-HOOK: the matcher is `^Bash$`; in 0.158.0 all shell tools (`exec_command`, `write_stdin`) are reported as `Bash`.
11. CX-PROFILES: `[profiles.<name>]` is ignored from Codex 0.134; a profile file `$CODEX_HOME/<name>.config.toml` can override `model_provider` and should count as drift.
12. HM-CHAT-OAUTH: an override exists for both logins: `model.base_url` with `model.provider: anthropic` for Anthropic, and the environment variable `HERMES_CODEX_BASE_URL` for ChatGPT/Codex. Spec §4.8 item 2 ("`HERMES_CODEX_BASE_URL` … was not found") is wrong for v2026.9.24: `hermes_cli/auth_codex.py` reads it. The Codex override lives in `.env`, which no adapter editor handles, so that row is `Unverified` with a manual snippet.
13. HM-CHAT-KEY: the provider entry must not be named after a built-in provider id (built-ins shadow it); `inumaki` is safe.
14. OC-FILES: a bind whose source lies outside the workspace roots needs `agents.defaults.sandbox.docker.dangerouslyAllowExternalBindSources: true`. Easy mode does not write a `dangerously*` flag, so it writes the bind only when the mirror root is inside an allowed root; otherwise the path is `Unsupported { OpenclawDockerBindsOnly }` with the snippet.
15. OC-CHAT-KEY: besides `baseUrl`, the provider needs `api`, `apiKey`, and a non-empty `models` list; model selection is `agents.defaults.model.primary` (or `agents.defaults.model` when it is a plain string).
16. OC paths: the override variables are `OPENCLAW_CONFIG_PATH` and `OPENCLAW_STATE_DIR` (plus `OPENCLAW_HOME`, `OPENCLAW_PROFILE`); the spike's `$OPENCLAW_CONFIG_DIR` does not exist.
17. Editors: the YAML editor is `yaml-edit` through `YamlFile`; flow and anchor refusals are our own syntax-kind check, not a parse failure.
18. Codex `hooks.json` accepts only the top-level keys `description` and `hooks` (`deny_unknown_fields`).

## 8. Hook latency budget

Spec §5.2 sets a target of p50 under 15 ms for the `pass` path: hook process
spawn, socket round trip, and one tripwire scan, end to end. Measured result:

| Item | Value |
|---|---|
| Date | 2026-10-04 |
| Platform | macOS 27.0, Apple M4 (arm64) |
| Commit | `b9e7b13` |
| Build and profile | `--release` (thin LTO); `offline` profile, no models |
| Scenario | `Read` of a 5 KB file, `pass` answer, 3 datasets seeded in the daemon with one known entity each, 50 warm runs |
| Cold | 218.7 ms |
| Warm p50 | 6.6 ms |
| Warm p95 | 7.7 ms |

An earlier run at `c9aca22` (`aae2cf3` after the rebase onto `main`) gave a cold
call of 221.9 ms, p50 7.0 ms, and p95 8.9 ms. The commits between that run and
`b9e7b13` changed path extraction (quote-aware shell words, deduplication) and the
handling of stdin that does not decode; the figures above are from the shipped
code.

Reproduce with `cargo test --release -p inumaki-hook --test budget -- --ignored --nocapture`.
The test spawns the real `inumaki-hook` binary for every call against an in-process
daemon on a Unix socket.

"Cold" is the first call after the three datasets were seeded in that process. It
opens each dataset's namespace, and it also includes the first execution of a
freshly linked binary on macOS (the first-launch code-signature check). It
therefore overstates a steady-state cold call and is not a regression signal. A
true cold start (daemon just started, models loaded) is measured by the
`--via-daemon` bench of M6-3. The warm p50 meets the target for this small vault. The tripwire scan's cost
grows with the number of known entities, so a vault with many entities per dataset
is slower; the figure is not a general claim. The sanitizing path
(`replace`) is not covered here: it costs one sanitization with the chosen
dataset's profile, plus a re-scan of every dataset's known entities.

## 9. What the hook cannot prevent

The hook is defense in depth behind the gateway and the mirror. It guards
connected data, and it is not a general PII filter for tool output (spec §5.2).
Within that scope it fails closed wherever the harness lets it, and the limits
below are where the harness, or the hook's own scope, does not.

Spec §5.1: a harness passes the original output through when the hook binary is
missing, is killed, or times out at the harness level, or when `updatedToolOutput`
does not match the tool's output shape. `inumaki connect status` reads the command
registered in the harness file and reports the hook as broken when the program it
names is missing or cannot be run, or when the command is not in the form inumaki
writes. It also reports it as broken ("reconnect to update it") when the command
names another program or service socket than the running inumaki uses, for example
after the binaries moved. Status cannot see a binary that is removed after it
last ran. The hook's own deadline is 10 s, and the adapters write a harness
timeout of 30 s.

While the daemon is unreachable the hook blocks every hooked result (class
`daemon_unreachable`, whose text ends with the fixed sentence "inumaki is not
running; start it to restore tool output."). It never passes a result
through and never decides from cached state, because cached state is stale the
moment the vault or a connected folder changes (ruling L97). The cost is that a
stopped service blocks hooked tool output in every session that runs the hook;
the connect warning `hook_blocks_when_stopped` and the app's tray tooltip say so.
The app's Revert removes the hook and works with the service stopped: the
service revokes the harness's gateway token at its next start, before it serves
anything. `inumaki connect revert` revokes the tokens first and needs the running
service. See
[The hook while the service is stopped](threat-model.md#the-hook-while-the-service-is-stopped).

Beyond that, recorded during M6-1:

- **Tools outside the hook.** Codex: the hook's group matches `^Bash$`, so only
  shell tools are hooked. Codex MCP tool results, `apply_patch`, and hosted tools
  are not. Claude Code: `Monitor` (the watched lines arrive as events),
  `WebSearch`, subagent output (`Agent`), the `Write` and `NotebookEdit` status
  lines, `ReadMcpResourceDirTool`, and `ListMcpResourcesTool` are not hooked
  (section 5 gives the reasons). Hermes and OpenClaw get no tool-result hook at
  all: Hermes runs hooks fail-open, and OpenClaw's tool-result hook does not fire
  in embedded runs. For those two harnesses only the gateway and the mirror
  protect tool results.
- **MCP servers in Claude Code.** The hook covers every MCP server that is not
  behind the gateway, including project-scope (`.mcp.json`) and plugin servers and
  servers added after the apply (section 1). The gateway-routed servers are
  excluded because the gateway already returns tokens. Two caveats: the negative
  lookahead in the matcher is not yet verified against the real binary (the
  `harness-tests` run must confirm it), and a server inumaki cannot see whose
  tool-name form equals a gateway-routed name, or starts with it followed by `__`,
  is excluded too.
- **Failed calls and unreplaceable results.** Claude Code runs `PostToolUseFailure`
  for a failed Bash or PowerShell command (non-zero exit, outside the benign
  exit-1 list) and for an MCP error result. That event cannot replace the output,
  and up to about 10,000 characters reach the model unfiltered. Codex runs no
  `PostToolUse` for the output of a command that is still running, nor for a failed
  tool result.
- **Sibling hooks.** Claude Code runs every matching `PostToolUse` hook in parallel
  on the original output. A second hook that returns `updatedToolOutput` for the
  same call competes with ours, and the last write wins.
- **Codex trust.** Codex does not run a new or changed user hook until the user
  trusts it in `/hooks`. inumaki never writes that trust.
- **Process death without unwinding.** The block-on-panic path relies on unwinding.
  An abort that does not unwind (out of memory) kills the process, and the harness
  then uses the original. A stack overflow is bounded by `serde_json`'s 128-level
  recursion limit.
- **Bare-string block.** A block is a per-tool template in the tool's output shape.
  It is a bare string only when no hooked tool name can be recovered from stdin
  (for example stdin that is not JSON), or when a tool outside the hook's list
  reaches it through a hand-edited matcher. Claude Code refuses a bare string for a
  built-in tool and uses the original. A real Claude Code payload is JSON and
  carries `tool_name` early, so this needs a damaged payload.
- **Template recovery.** When stdin does not decode (for example it is cut or over
  32 MiB), the hook scans it for the first raw `"tool_name"` key at any depth to
  pick the template. The scan is not anchored to the top-level object. It can only
  change which template is printed, never cause a pass.
- **Unverified templates.** The block templates were checked by hand against
  Claude Code 2.1.284's output schemas only. A wrong template fails open, so the
  `harness-tests` real-binary run must exercise each one.
- **Unknown harness name.** `inumaki-hook <other>` prints a usage line and exits 2.
  Claude Code documents that exit 2 shows stderr to the model and keeps the
  original output; for Codex the behavior is not verified, and the original is
  assumed to reach the model. The adapters always write
  `claude-code` or `codex`, so this needs a hand-edited command. Malformed arguments
  after a known harness name block instead (exit 0).
- **Binary output outside connected folders.** Image, PDF, and `parts` reads and
  Bash `isImage` outputs pass when the daemon answers `pass` and are blocked when it
  would replace anything. In a connected folder the path rule always selects a
  dataset, so these block. Outside connected folders, a binary output that
  contains an identifier the vault already knows passes, because the scan cannot
  see inside base64 data.
- **Numbers beyond `f64` precision.** The hook reads JSON numbers with
  `serde_json` without `arbitrary_precision`. An integer outside the 64-bit range
  or a decimal beyond `f64` precision reaches the daemon in its rounded form, so
  the tripwire misses a very long numeric identifier. The setting stays off
  because it changes how numbers print back.
- **Schema-constrained string fields.** A token written into a field that Claude
  Code validates as a URL or URI (`WebFetch` `url`, `ReadMcpResourceTool`
  `contents[].uri`) can fail the output schema, and the original is used.
- **Over-blocking by discriminators.** The nine discriminator keys (`type`,
  `mimeType`, `mediaType`, `role`, `kind`, `mode`, `status`, `action`, `source`)
  are never rewritten. A result in which one of them holds free text that the
  daemon would change is blocked instead of sanitized: a Jupyter `Read` carries
  cell code in `source`, and MCP structured outputs sometimes carry prose in
  `status`, `source`, or `action`.
- **Path extraction.** The hook sends the paths a tool input references so that
  the daemon can apply the connected-folder rule; the known-entity trigger runs
  regardless. Extraction does not cover `~user/` forms, `$PWD` and any variable
  other than a leading `$HOME` or `${HOME}`, a bare folder name without a slash
  (`cd Kunden && cat a.txt` run from the parent folder), or MCP tools, which send
  no paths. The rule is "under a connected root", not "contains": a command that
  names an ancestor of a connected folder (`grep -rn X ~/Documents`) does not
  select the folder's dataset. When one result references two folders, the first
  match's dataset and profile apply.
- **Scope.** A known person, organization, or street name of a single word does
  not trigger the hook (the gateway name scan's rule); a known identifier, such
  as a customer number or a known email address, triggers it even as a single
  word. A validated-regex hit alone (an email or URL in code output that the
  vault does not know) does not trigger it.
  Identifiers in no connected folder and not yet known to the vault pass. Tokens
  that the agent writes into later tool inputs are not rehydrated.

## Unverified facts and the fail-safe choice made

| Fact | Why unverified | Choice |
|---|---|---|
| Block templates are accepted by Claude Code's output schemas | No session may be run; checked by hand against the zod schemas in the 2.1.284 binary | Keep the templates; the `harness-tests` real-binary run (spec §11) must exercise each one. A wrong template fails open, so this is the first thing that run checks. |
| Hermes Anthropic OAuth honours `model.base_url` on every resolution path | Several credential paths; read, not run | Treat as `Connected` only after a check run; otherwise `Unverified`. |
| Hermes Codex OAuth `HERMES_CODEX_BASE_URL` | Lives in `.env`, outside the editors | `Unverified`, snippet only, nothing written. |
| Codex 0.158.0 accepts `model_providers.<id>.supports_websockets` (spec §4.3 amendment 2026-09-29) | Not in the documentation read and not recorded from the 0.158.0 source; only the installed 0.159.2 binary's strings (read 2026-10-04) show the name beside other provider fields. *2026-10-10:* 0.159.2 accepts it (the user-gated ChatGPT-login run passed `supports_websockets=false` as an override, M8 spec §13 amendment); 0.158.0 stays unrecorded | Not written; the proxy answers a WebSocket upgrade with `501` either way. |
| Codex hook trust state can be read from `[hooks.state]` | The hash is internal (`version_for_toml`); recomputing it is fragile | Report "needs trust" unless a `trusted_hash` exists for our key; never write one. |
| OpenClaw `models.providers.<id>.headers` carries `X-Inumaki-Client` on the request | Documentation only: `types.models.ts` has `headers?: Record<string, SecretInput>`, and a plain string is a valid `SecretInput`. Never run against a real OpenClaw | Written. The `harness-tests` run must assert the header reaches the proxy. A wrong key degrades to tokens only: chat still works and is still filtered, but values from connected sources stay tokens in answers, and nothing flags it. |
| Hermes `providers.<name>.extra_headers` carries `X-Inumaki-Client`, in both `chat_completions` and `anthropic_messages` modes | Source reading only (`runtime_provider_custom.py::_match_new_style_provider` lists `extra_headers`); that the value is applied to the request in both modes is not verified | Written. Same real-binary check, and the same failure mode as OpenClaw (tokens only). |
| OpenClaw login kind from `auth.profiles.<id>.mode` | Credentials live in SQLite; mode values beyond `oauth` and `aws-sdk` taken from prose | `Unknown` when no `mode` is present. |
| The Claude Code hook matcher's negative lookahead `^mcp__(?!(…)__).*` works as written | JavaScript regular-expression syntax supports it; that Claude Code compiles the matcher with it unchanged was not run against a real session | Written. The `harness-tests` run must show that a gateway tool is not hooked and every other MCP tool is. If Claude Code rejected the expression, the whole matcher might match nothing, and the hook would not run (fail open). |
| Claude Code applies `settings.json` `env` to the processes it spawns | Not checked. If true, a Bash tool call can read `ANTHROPIC_CUSTOM_HEADERS`, and with it the proxy client header, without reading the file | Nothing to change in the adapter; the `harness-tests` run must check whether a Bash call sees the variable, and the threat model treats the header as readable by the agent. |
