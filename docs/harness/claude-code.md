# Connecting Claude Code

This guide covers what inumaki does to Claude Code when you connect it, what each protection path reaches, what it cannot do today, and how to undo it. It describes the Claude Code CLI and its settings files. It assumes you have read the project's introduction: inumaki replaces identifying values with opaque tokens before text leaves your machine, and restores them in the answer.

Easy mode is the only mode in this release, and it has a stated limit: **Connected; an agent that deliberately goes around inumaki can succeed.** Connecting edits Claude Code's own configuration so that its traffic goes through inumaki. It does not stop Claude Code, or anything it runs, from being configured or told to talk to a provider directly.

## At a glance

| Path | What it protects | Where Connect puts it |
|---|---|---|
| MCP | Tool servers you protect: their results reach Claude Code as tokens | `~/.claude.json` |
| Files | A sanitized mirror of folders you connected, added as a readable directory | `~/.claude/settings.json` |
| Chat | The conversation Claude Code sends to Anthropic | `~/.claude/settings.json`, only when you switch it on (app) or leave `--no-chat` off (command line) |
| Hook | A tool result from one of the listed built-in tools (see the hook group below) or an unprotected MCP server is sanitized before the model sees it, but only when the tool input references a connected folder or outbox, or the output holds a multi-word or identifier-kind value the vault knows. It is not a general filter; see [The hook](#known-refusals-and-limits). | `~/.claude/settings.json` |

**Chat is off by default in the app, and today turning it on stops Claude Code from answering under the default profile (`support-email`).** Read [Chat](#chat-an-opt-in-switch-in-the-app) before you switch it on. The command line differs: `inumaki connect apply` routes chat unless you pass `--no-chat`.

## Versions

| | Version |
|---|---|
| Tested range of the adapter | 2.1.284 to 2.1.284 |
| Measured end to end | 2.1.296 (2026-10-10 and 2026-10-11) |

The adapter was built against the 2.1.284 binary's documented settings and the tool schemas and hook handling read from it. Later runs against 2.1.296 are the real-harness checks: the end-to-end canary check (gateway, mirror, and chat proxy), the hook, and the chat refusal described below. A version outside the tested range still connects. Its connection page carries an "Untested version" chip, and `inumaki connect status` prints `(untested version)` after the harness id. Today that includes 2.1.296.

## How inumaki finds Claude Code

Detection decides by names and presence only, and never logs or sends a credential value. An API key kept in `settings.json` is parsed with the rest of that file, because Connect edits it, and Connect's backup of `settings.json` contains any key that file holds. Backups are written owner-only (files 0600 in 0700 directories) under the data directory; delete old ones in Settings, under "Configuration backups" (the backup a connected harness would be restored from is kept).

- **Program.** `claude` in `/opt/homebrew/bin`, `/usr/local/bin`, `~/.local/bin`, `~/.npm-global/bin`, `~/.claude/local`, or `~/.cargo/bin`, or the first `claude` on your login shell's `PATH`. A desktop app does not inherit your shell's `PATH`, which is why these locations come first. The version is the output of `claude --version`, with a 3-second limit.
- **Configuration directory.** `~/.claude`, or the directory named by `CLAUDE_CONFIG_DIR`. The global file is `~/.claude.json`, or `$CLAUDE_CONFIG_DIR/.claude.json` when that variable is set; a legacy `.config.json` in the same place wins if it exists.
- **Detected** when the program is found, or `.claude.json` exists, or the configuration directory exists. A directory with no program is shown as "Configured, program not found".
- **Login kind** (shown on the connection page): an API key when `ANTHROPIC_API_KEY` is set in the environment, or `apiKeyHelper` or `env.ANTHROPIC_API_KEY` is set in `settings.json`; a subscription login when `<config dir>/.credentials.json` exists or the macOS keychain has an item named `Claude Code-credentials` (its existence is checked, its data is never requested); otherwise unknown. The page words the kinds "API key", "Claude account login" (inumaki sees that an account signed in, not which plan) and "Login not detected". Both kinds are routed the same way.

Managed settings (`/Library/Application Support/ClaudeCode/managed-settings.json` on macOS, `/etc/claude-code/managed-settings.json` on Linux) can override user-level keys. inumaki does not detect them yet, so on a managed machine a connected harness's page can show a path that Claude Code ignores. See [Revert and drift](../threat-model.md#revert-and-drift).

## What Connect writes

Before the first write, inumaki makes a backup. It edits only the keys listed here, and only when the file parses and prints back unchanged; otherwise it writes nothing and shows you the lines to add by hand.

| File | Key | Value | When |
|---|---|---|---|
| `~/.claude.json` | `mcpServers.<name>` | `{"type": "http", "url": "http://127.0.0.1:8789/mcp/<dataset>", "headers": {"Authorization": "Bearer <token>"}}` | For each server pointing at the gateway already, and each server you choose to protect |
| `~/.claude.json` | `projects.<directory>.mcpServers.<name>` | The same shape | Local-scope servers of a project, protected the same way |
| `~/.claude/settings.json` | `permissions.additionalDirectories` | The mirror root, appended to the list | When Files is on (`--no-files` skips it) |
| `~/.claude/settings.json` | `env.ANTHROPIC_BASE_URL` | The proxy's Anthropic route, `http://127.0.0.1:8787/anthropic` by default, without `/v1` | Chat only |
| `~/.claude/settings.json` | `env.ANTHROPIC_CUSTOM_HEADERS` | One line, `X-Inumaki-Client: <value>`, appended to whatever lines are there | Chat only |
| `~/.claude/settings.json` | `hooks.PostToolUse` | One matcher group with one `command` handler, described below | When the hook is on (`--no-hook` skips it) |

The proxy and gateway addresses above are the defaults; see [Configuration](../configuration.md#proxy).

Notes on these keys:

- **The gateway token** is a bearer token labelled `app:claude-code`. It sits in `~/.claude.json` and is revoked when you Revert (with the service stopped, at the service's next start). **Reconnect** is a button on the connection page that is offered whenever the harness is connected (it is the primary button when the harness is disconnected or something on the page needs attention): in the app it reverts the harness and applies it again with your current choices, which mints a new gateway token and revokes the old.
- **The client header** is a per-install secret. The proxy restores tokens from your connected datasets in Claude Code's answers only for requests that carry it. Without it, chat is still filtered, but values from connected sources stay tokens in answers. inumaki owns only its own line of `ANTHROPIC_CUSTOM_HEADERS`; your other lines stay as they are. See [The client header](../threat-model.md#the-client-header).
- **The hook group** is:

  ```json
  {
    "matcher": "^(Bash|PowerShell|Read|Grep|Glob|Edit|WebFetch|ReadMcpResourceTool)$|^mcp__(?!(<g1>|<g2>)__).*",
    "hooks": [{"type": "command", "command": "'<bin>/inumaki-hook' claude-code --socket '<socket>'", "timeout": 30}]
  }
  ```

  `<g1>`, `<g2>` stand for the names of the MCP servers that point at the gateway after the connect, in the form Claude Code uses in tool names (every character outside letters, digits, `_` and `-` becomes `_`). Those servers need no second check, because the gateway already returns tokens. Every other MCP server is hooked, including project-level `.mcp.json` servers, plugin servers, and servers you add later. With no gateway-routed server the clause is `^mcp__.*`. An earlier inumaki hook entry is replaced; your own hook entries are untouched.
- **Everything else in both files stays as it was.** inumaki owns exactly the keys in the table, plus the hook group it adds.

### What Connect does not do

- The app's Connect does **not** write `env.ANTHROPIC_BASE_URL` or the client header. Chat is a separate switch.
- It never copies a literal API key anywhere.
- It never changes `permissions.allow`, `permissions.deny`, your existing hooks, or any other key.
- Connect takes effect for MCP servers in the next Claude Code session. Claude Code reads `settings.json` while running, so open windows may pick up the `settings.json` changes (the hook) at once. Whether they pick up a new hook entry was not measured, which is why the app says "may".

## The paths on the connection page

The app has one page per harness, under "Connections" in the sidebar; the Overview lists the harnesses and opens it. The page shows each path as a section whose title is the path and a status word, for example "Chat: off, your choice". Each status has a glyph shape and a colour as well as the word, so it reads without colour. The colours are:

- **Grey** ("Off"): not connected, with nothing wrong. A connected harness whose Chat is not routed reads **"Chat: off, your choice"**, also grey: Chat off is the default, and the page says plainly that Claude Code talks to Anthropic directly and inumaki does not see the chat text.
- **Amber** ("On", or "On, unverified"): connected. Amber is the best state in Easy mode. Green is reserved for a stricter mode that this release does not have.
- **Red**: a broken path ("Needs attention"). A disconnected harness shows a red "Disconnected" notice and its paths read "Not filtered now" (grey). A failed check is shown under "Last check".

| Path | Reach | Colour and reason on the page |
|---|---|---|
| MCP | Yes. User-scope and local-scope servers are listed and protected the same way. A local-scope entry shadows a user-scope entry of the same name inside its own project, so both are listed. | Grey when no server points at the gateway. Amber "On", with "N of M servers protected". Red when the file changed outside inumaki ("The configuration was changed outside inumaki. Reconnect to restore it."), when the service is down ("The inumaki service is not running."), or when a protected server's dataset has no running upstream ("A protected server is not running."). |
| Files | Yes. The mirror root is added to `permissions.additionalDirectories`, so Claude Code can read the sanitized copy. inumaki does not restrict which other folders Claude Code can read; that stays with Claude Code's own permission settings. | Grey when no folder is connected ("No folder is connected."), when the mirror is not listed, or when the mirror is not available. Amber "On", with the number of watched folders. Red when the key was changed outside inumaki. |
| Chat | Yes, for both API-key and subscription logins, once the route is written and the proxy is running. | Grey "Off, your choice" while it is off, with the sentence "Chat is not protected: it goes straight to the provider, and inumaki does not see it." under the status. Amber "On" when routed; "No traffic seen yet." until the first request arrives. Red if recent requests through the route failed ("Recent requests through this route failed."), or if the route or the header drifted. |
| Hook | Yes. | A section of its own, "Tool-result hook", after the three paths. Its status reads "installed" or "not installed", or "broken" (red) with a reason: "The inumaki hook program is missing or cannot be run.", "The hook names an inumaki program or service socket that this inumaki no longer uses. Reconnect to update it.", or the changed-outside-inumaki sentence. |

A connected harness with Chat off shows grey "Off, your choice" and the tray icon stays yellow. The wording still says the chat is not filtered; only the alarm colour is gone, because Chat off is the default and your choice, and a red mark for the normal state would hide real failures.

The "Run the check" button in the toolbar of the Overview (and the one under "Last check" on the connection page) runs Claude Code non-interactively against a synthetic canary through each path you connected. It uses its own temporary configuration, so a pass says nothing about whether your real Chat route is on.

## Chat: an opt-in switch in the app

`env.ANTHROPIC_BASE_URL` lives in the user-level `settings.json`, and Claude Code applies changes to `env` in every open session without a restart. Switching Chat on therefore changes every open Claude Code window, in every project, at once. That is why the app does not do it as part of Connect.

On the Claude Code page the switch in the Chat section is labelled "Filter chat"; its full name, which a screen reader reads, is **Send Claude Code chat through inumaki**. It is disabled until the harness is connected ("Connect first"). Both directions ask for confirmation in a sheet, whose buttons are "Turn on" and "Turn off":

- **Turning it on**: "Every open Claude Code window, in every project, switches to sending chat through inumaki at once. With the support-email or strict profile, Claude Code's chat requests are refused today (measured 2026-10-11 with Claude Code 2.1.296), so open sessions stop answering until you turn Chat off again."
- **Turning it off, or a Revert while it is on**: "Every open Claude Code window switches back to talking to Anthropic directly at once, and its chat is no longer filtered by inumaki."

Chat is an explicit opt-in on the connection page of every harness, not only this one. Until you set the switch, it shows whether a chat route is already in place (written earlier by the app or by the command line), so an install that already routed chat before this change keeps it on. A Revert clears the choice.

The Connect sheet in the app says the same thing in short: Connect does not route Claude Code's chat, and open windows may pick up the `settings.json` changes (the hook) at once, while MCP servers in `~/.claude.json` take effect in the next session.

## Known refusals and limits

These are today's measured behaviour, not design goals.

- **Claude Code's chat requests are refused under `support-email` and `strict`.** Measured 2026-10-11 with Claude Code 2.1.296 under `support-email`: the proxy answered `451` with 8 `PERSON` hits and 1 `CONTRACT_ID` hit. The name model flags Claude Code's own static text (instructions, permission fragments, environment context, the system prompt) as person names, and the profile's rule for uncertain text is to block. `support-email` is the default profile, and `strict` behaves the same. With the shipped configuration (`[proxy] profile` empty, so the default profile applies), switching Chat on therefore stops Claude Code from answering. The known-limits list records that `[proxy] profile = "fast"` gets past it, with lower recall and no independent name re-scan in the verifier, and that it is not the recommended default. Both are listed in [Known limits at sign-off](../mvp-checklist.md#known-limits-at-sign-off). This stays until the planned precision work on harness text lands. See [Configuration](../configuration.md#proxy) for `proxy.profile`.
- **Images and other attachments are replaced by a placeholder and are not inspected.** By default (`proxy.binary = "placeholder"`) an image, document, audio, or file part is removed and a fixed text stands in its place, so Claude Code's model cannot read a screenshot you attach. There is no OCR. A tool result that contains an attachment is withheld whole. Setting `proxy.binary = "forward"` sends attachments with no detection on them. See [Configuration](../configuration.md#proxy).
- **Request headers pass by an allowlist.** The proxy forwards only the request header names it lists for Anthropic, and it checks the value of most of them against a shape. An unlisted header or a value that fails its shape is dropped, and the drop is counted in the daemon log by a closed label (never the name or value). A Claude Code release that adds a header the list does not know has that header dropped. If Claude Code needs it, name it in `[proxy.upstreams.anthropic] extra_headers`; that forwards the header unchanged, with no value check. **After a Claude Code upgrade, re-run the `harness_record` test** (`crates/inumakid/tests/harness_record.rs`). It runs the installed harness once directly and once through the proxy and reports any header the allowlist dropped. It is run by hand, never in CI:

  ```bash
  INUMAKI_RECORD_HARNESS=1 cargo test -p inumakid --test harness_record -- --ignored --nocapture --test-threads 1
  ```

  What a Claude Code subscription login sends was not recorded, so a header that login needs and the list lacks would be dropped.

  See the privacy note on `extra_headers` in [Configuration](../configuration.md#proxy), and the request-header item in the threat model's [known limitations](../threat-model.md#known-limitations).
- **Local paths and the login name in harness text pass unless a detector catches them.** Claude Code's system prompt holds the working directory and a git status. They are ordinary text, so they are tokenized only when a detector finds the name in them.
- **The hook is defense in depth, not a general filter.** It sanitizes a tool result only when the tool input references a connected folder or outbox, or the output holds a multi-word or identifier-kind value the vault already knows (`crates/inumakid/src/hook.rs`); an email address or URL in command output does not trigger it. It does not cover `Monitor`, `WebSearch`, subagent output, the `Write` and `NotebookEdit` status lines, `ReadMcpResourceDirTool`, or `ListMcpResourcesTool`. It cannot replace the output of a failed Bash or PowerShell command or an MCP error result, and up to about 10,000 characters of those reach the model unfiltered. A second `PostToolUse` hook that also rewrites the same output competes with ours, and the last write wins. The full list is in [What the hook cannot prevent](../harness-adapters.md#9-what-the-hook-cannot-prevent) and in the [threat model](../threat-model.md#what-the-hook-does-not-guarantee).
- **While the service is stopped, hooked tool output is blocked.** The hook fails closed: if the service is down, restarting, or the check cannot complete, a hooked tool result is replaced by `blocked by inumaki (<class>; kinds: …)`. With the service unreachable the text ends with "inumaki is not running; start it to restore tool output." This holds in every Claude Code session that runs the hook, and it is deliberate: a cached pass-through would let through whatever changed since ([The hook while the service is stopped](../threat-model.md#the-hook-while-the-service-is-stopped)). Connect warns about it ("While inumaki is stopped, tool output in every connected session is blocked. Start the service to recover; Revert also needs it running."), and the app's tray tooltip says so while the service is down.
- **The hook fails closed only while the hook program runs.** Claude Code passes the original output through if the hook program is missing, is killed, or times out, so a missing or killed program is not a block. The connection page reports a hook whose program is missing; it cannot see one removed after the last status check. See [What the hook does not guarantee](../threat-model.md#what-the-hook-does-not-guarantee).
- **The exclusion of gateway-routed servers relies on a regular-expression lookahead** (`(?!…)`) in the hook matcher. It is valid JavaScript, but it has not been confirmed against a real Claude Code session that Claude Code compiles the written matcher unchanged. The end-to-end check uses a simpler matcher of its own. If Claude Code rejected the expression, the hook might match nothing and not run.
- **Whether Claude Code passes `settings.json` `env` to the processes it starts** was not checked. If it does, a Bash tool call can read the client header from its environment. Treat the header as readable by the agent.

## The command-line equivalent

```bash
inumaki connect status claude-code
inumaki connect apply claude-code                       # MCP, Files, Chat, and the hook
inumaki connect apply claude-code --no-chat             # leave the chat route alone (what the app does)
inumaki connect apply claude-code --protect NAME        # also put the MCP server NAME behind the gateway
inumaki connect apply claude-code --no-hook --no-files  # skip the hook or the mirror directory
inumaki connect revert claude-code [--keep-backup]
```

The command line differs from the app in one way: `apply` still writes the chat route by default, so **use `--no-chat` unless you want chat routed**, and without it `apply` prints a warning on stderr: "Every open Claude Code window now sends chat through inumaki, including other projects; with the support-email or strict profile its chat requests are refused today." The exit code stays `0`. If you want the app's behaviour, use `--no-chat`. When `apply` installs the hook (without `--no-hook`), it also prints "While inumaki is stopped, tool output in every connected session is blocked. Start the service to recover; Revert also needs it running." The app shows the same warning after Connect. Chat is also only written while the proxy reports that it is running, read at the moment of the apply; if it is not, `apply` skips the route and says so (an explicit `--chat` fails instead).

`apply` also needs a running daemon. Every file is checked before the first write, so a refusal changes nothing; it prints the lines to add by hand, which contain the gateway token and client header value, so do not paste them anywhere shared. Reference: [`inumaki connect`](../cli.md#connect).

## Revert

Revert (the connection page's button, or `inumaki connect revert claude-code`) revokes the harness's gateway tokens first (the app records the revocation instead when the service is stopped, see below), then restores your files from the backup:

- `~/.claude/settings.json` is copied whole before Connect, so if nothing else touched the file it comes back byte for byte. If something did, inumaki removes the keys it added and restores the previous values of the ones it replaced, and leaves any key you changed since, counting it.
- `~/.claude.json` is restored by value, not by bytes. Claude Code rewrites it constantly and it holds session state, so inumaki keeps no copy of it. Its `mcpServers` entries get their previous definitions back; a protected server's original entry returns, with the secrets it held.
- Your own lines in `ANTHROPIC_CUSTOM_HEADERS` stay. inumaki removes only its `X-Inumaki-Client` line, and the key itself when nothing else is left in it. If it cannot, the app warns and the command exits `2`: delete that line by hand, otherwise the header would go to Anthropic.
- In the app, Revert works with the service stopped: it restores your files and records that this harness's gateway token is to be revoked, and the service revokes it before it serves anything at its next start (or within a minute, if it turns out to be running). While the service is stopped the token opens nothing, because nothing listens for it, but it is not revoked until then ([Gateway tokens in harness files](../threat-model.md#gateway-tokens-in-harness-files)). The app says so in the note after the Revert. `inumaki connect revert` still needs the running service: without it, nothing is reverted.
- If Chat was on, Revert switches every open window back to Anthropic directly at once.

## Troubleshooting

- **Chat through the proxy, measured 2026-10-28 with Claude Code 2.1.312** (an isolated headless run against a throwaway daemon, routed only by `ANTHROPIC_BASE_URL` and `ANTHROPIC_CUSTOM_HEADERS` in that one process): a plain prompt, a Bash tool call that prints the home directory, and a prompt with synthetic personal data all completed, and no synthetic value appeared in any forwarded payload. Two limits showed up with an account that has claude.ai connectors. (1) Claude Code announces connector tools mid-conversation with a `tool_addition` block that the API refuses when Claude Code talks to a custom base URL, answered `400` (its fallback retries then report a misleading `metadata.user_id: Extra inputs are not permitted`); Claude Code's own log suggests `ENABLE_TOOL_SEARCH=false`. (2) Its "MCP servers are still connecting" reminder is a user item that names the connectors, and the name model reads those names as people, so the request is refused (`451`, `PERSON`, check `Ner`). Both go away without connectors (`--strict-mcp-config`). Claude Code's first system block, the attribution line `x-anthropic-billing-header: ...`, is protected: rewritten, Anthropic answered `429` (threat model (gg)).

- **"The configuration was changed outside inumaki. Reconnect to restore it."** Something edited a key inumaki owns. A common cause is Claude Code writing back an older copy of `~/.claude.json`. Press **Reconnect** on the connection page; it is always offered while the harness is connected, and it is the primary button when a path is broken or the harness is disconnected. From a terminal, run `inumaki connect revert claude-code`, then `inumaki connect apply claude-code --no-chat` (a plain `apply` does not revert first; it adds a new backup on top of the active one). Either way a new gateway token is issued. A line you added to `ANTHROPIC_CUSTOM_HEADERS` is not drift; a missing or changed `X-Inumaki-Client` line is.
- **Hook "broken": missing, or "Reconnect to update it".** The hook command names an `inumaki-hook` program or a service socket that this inumaki no longer uses, for example after the binaries moved. Reconnect rewrites the command, and the page offers it as the primary button for a broken hook.
- **Claude Code stopped answering after you turned Chat on.** That is the refusal above. Turn the switch off in the app, or run `inumaki connect revert claude-code`. An open window returns to Anthropic at once.
- **Hooked tool results read `blocked by inumaki (…)`.** The service is down, restarting, or could not check the result. Start the service and rerun the tool call; check `inumaki status`. A text ending in "inumaki is not running; start it to restore tool output." means the hook could not reach the service at all. The app's Revert also removes the hook and works with the service stopped (the service revokes the gateway token at its next start); `inumaki connect revert` needs the running service. If the service cannot be started and you do not use the app, delete the `PostToolUse` group whose command names `inumaki-hook` from `~/.claude/settings.json` by hand, and Revert once the service runs again. See [The hook while the service is stopped](../threat-model.md#the-hook-while-the-service-is-stopped).
- **Chat is on but the page says "No traffic seen yet."** No request has gone through the proxy since the daemon started. Send a message from a new session.
- **A local-scope server is still unprotected.** `--protect NAME` protects the first matching entry that is not already behind the gateway, user scope first. The hook still covers the other one.
- **The inumaki proxy stopped, or another process took port 8787, after you turned Chat on.** Claude Code then sends its conversation, and its credentials, to whatever listens there. The route is checked once, at apply time. Revert, or restart the proxy. See [Revert and drift](../threat-model.md#revert-and-drift).
- **Managed settings.** If your organisation manages Claude Code, user-level keys may be ignored without inumaki noticing.
