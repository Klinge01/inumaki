# Connecting Codex

This guide covers what inumaki does to the Codex CLI when you connect it, what each protection path reaches, what it cannot do today, and how to undo it. It assumes you have read the project's introduction: inumaki replaces identifying values with opaque tokens before text leaves your machine, and restores them in the answer.

Easy mode is the only mode in this release, and it has a stated limit: **An agent that deliberately goes around inumaki can still succeed.** Connecting edits Codex's own configuration so that its traffic goes through inumaki. It does not stop Codex, or anything it runs, from being configured or told to talk to a provider directly. Codex has more ways around the proxy than most harnesses; see [Chat](#chat).

## At a glance

| Path | What it protects | Where Connect puts it |
|---|---|---|
| MCP | Tool servers you protect: their results reach Codex as tokens | `$CODEX_HOME/config.toml` |
| Files | Only the writable outbox. Codex has no setting that limits which folders it reads. | `$CODEX_HOME/config.toml` |
| Chat | The conversation Codex sends to OpenAI, only when you switch Chat on (one switch on the connection page). With an API key the switch gates the `openai` route; with a ChatGPT login it gates the `codex` route, which is unverified and refused today. | `$CODEX_HOME/config.toml`, only when the switch is on |
| Hook | A shell tool result is sanitized before the model sees it, but only when the tool input references a connected folder or outbox, or the output holds a multi-word or identifier-kind value the vault knows. It is not a general filter, and Codex runs the hook only after you trust it. | `$CODEX_HOME/hooks.json` |

**Chat is off by default in the app, and today turning it on stops Codex from answering under the default profile (`support-email`) and under `strict`.** Read [Chat](#chat) before you switch it on. The command line differs: `inumaki connect apply` routes chat unless you pass `--no-chat`.

`$CODEX_HOME` is `~/.codex` unless the environment variable says otherwise.

## Versions

| | Version |
|---|---|
| Tested range of the adapter | 0.158.0 to 0.158.0 |
| Measured end to end | 0.159.2 (2026-10-10) |

The adapter was built against the 0.158.0 source and documentation. Three details were recorded on 0.159.2, which is outside the range: the `required` and `startup_timeout_sec` keys on the gateway entry, Codex's handling of `default_tools_approval_mode`, and the shape of its MCP tool calls. The range stays at 0.158.0 until the adapter's reference files exist for the newer version. A version outside the range still connects. Its connection page carries an "Untested version" chip, and `inumaki connect status` prints `(untested version)` after the harness id. Today that includes 0.159.2.

Codex 0.162.1 (recorded 2026-10-21) sends its chat requests in a "responses-lite" shape (header `x-openai-internal-codex-responses-lite`): no top-level `instructions` or `tools`; the request's `input` starts with an `additional_tools` item that holds the tool definitions, followed by the base prompt and the skills, plugins and apps text as developer messages. The proxy reads that item's tools as definitions and keeps the developer messages after it in the leading system prompt, so they are read as harness text and use the static-prompt cache.

## How inumaki finds Codex

Detection reads names and presence only. It never reads a credential value.

- **Program.** `codex` in `/opt/homebrew/bin`, `/usr/local/bin`, `~/.local/bin`, `~/.npm-global/bin`, `~/.claude/local`, or `~/.cargo/bin`, or the first `codex` on your login shell's `PATH`. The version is the output of `codex --version`, with a 3-second limit. Codex is a Node script, so the app runs it with your login shell's `PATH` plus the directory holding `codex`; a Finder-launched app would otherwise not find `node`.
- **Configuration directory.** `$CODEX_HOME`, default `~/.codex`. Codex counts as detected when the program is found or the directory exists.
- **Login kind** (shown on the connection page), from the names in `auth.json`: an API key when `OPENAI_API_KEY` has a value there (or is set in the environment); a ChatGPT login when a `tokens` entry is present; otherwise unknown (the page words the kinds "API key", "ChatGPT login" and "Login not detected"). Codex always writes the `OPENAI_API_KEY` key, with `null` for ChatGPT logins, so inumaki tests for a value, not for the key. If your credentials live in the system keyring and there is no `auth.json`, the login reads as unknown, and no chat route is written.

## What Connect writes

Before the first write, inumaki backs up both files whole. It edits only the keys listed here, and only when the file parses and prints back unchanged; otherwise it writes nothing and shows you the lines to add by hand.

| File | Key | Value | When |
|---|---|---|---|
| `config.toml` | `[mcp_servers.<name>]` | `url = "http://127.0.0.1:8789/mcp/<dataset>"`, `http_headers = { Authorization = "Bearer <token>" }`, `required = true`, `startup_timeout_sec = 30` | For each server pointing at the gateway already, and each server you choose to protect |
| `config.toml` | `sandbox_workspace_write.writable_roots` | Each connected outbox directory, appended to the list | When Files is on and a folder is connected |
| `config.toml` | `model_provider` | `"inumaki"` | Chat switched on |
| `config.toml` | `[model_providers.inumaki]` | API-key login: `name = "inumaki"`, `base_url = "http://127.0.0.1:8787/openai/v1"`, `wire_api = "responses"`, `env_key = "OPENAI_API_KEY"`, `http_headers = { X-Inumaki-Client = "<value>" }`. ChatGPT login: `base_url = "http://127.0.0.1:8787/codex"`, `requires_openai_auth = true`, no `env_key`, the same `http_headers`. | Chat switched on |
| `hooks.json` | `hooks.PostToolUse` | One matcher group appended after every group already there: `{"matcher": "^Bash$", "hooks": [{"type": "command", "command": "'<bin>/inumaki-hook' codex --socket '<socket>'", "timeout": 30}]}` | When the hook is on (`--no-hook` skips it) |

The proxy and gateway addresses are the defaults; see [Configuration](../configuration.md#proxy).

Notes on these keys:

- **The gateway token** is a bearer token labelled `app:codex`. It is revoked when you Revert (with the service stopped, at the service's next start). **Reconnect** is a button on the connection page that is offered whenever the harness is connected (it is the primary button when the harness is disconnected or something on the page needs attention): in the app it reverts the harness and applies it again with your current choices, which mints a new gateway token and revokes the old.
- **`required = true` with `startup_timeout_sec = 30`.** Codex starts its first turn before MCP servers are up. Without `required`, a session can run without the inumaki tools and nothing tells you. With it, Codex waits up to 30 seconds for the gateway and fails visibly if the gateway does not come up.
- **`default_tools_approval_mode` is yours.** inumaki never writes it, because auto-approving tool calls is your decision. If you set it on the inumaki entry, every later Connect keeps your value, and Revert removes it together with the entry. See [Tool approval](#tool-approval).
- **The client header** is a per-install secret. The proxy restores tokens from your connected datasets in Codex's answers only for requests that carry it; without it chat is still filtered, but values from connected sources stay tokens. See [The client header](../threat-model.md#the-client-header).
- **The hook group goes last.** Codex records trust for a hook by its position and hash. Putting inumaki's group after yours means your groups keep their positions, and your trusted hooks stay trusted. An identical entry already in place is left where it is, so a Reconnect does not move it. inumaki never writes a trust record; see [Hook trust](#hook-trust).
- **Everything else in both files stays as it was.** `hooks.json` accepts only the top-level keys `description` and `hooks`, and inumaki writes nothing else there.

## The paths on the connection page

The app has one page per harness, under "Connections" in the sidebar; the Overview lists the harnesses and opens it. The page shows each path as a section whose title is the path and a status word, for example "Chat: off, your choice". Each status has a glyph shape and a colour as well as the word, so it reads without colour. The colours are:

- **Grey** ("Off"): not connected, with nothing wrong. A connected harness whose Chat is not routed reads **"Chat: off, your choice"**, also grey: Chat off is the default, and the page says plainly that Codex talks to its provider directly and the chat is not filtered.
- **Amber** ("On", or "On, unverified"): connected, or set up but not confirmed. Amber is the best state in Easy mode. Green is reserved for a stricter mode that this release does not have.
- **Red**: a broken path ("Needs attention"). A disconnected harness shows a red "Disconnected" notice and its paths read "Not filtered now" (grey). A failed check is shown under "Last check".

| Path | Reach | Colour and reason on the page |
|---|---|---|
| MCP | Yes, in user scope (`mcp_servers`). | Grey when no server points at the gateway. Amber "On", with "N of M servers protected". Red when the file changed outside inumaki ("The configuration was changed outside inumaki. Reconnect to restore it."), when the service is down ("The inumaki service is not running."), or when a protected server's dataset has no running upstream ("A protected server is not running."). |
| Files | Partial. inumaki can only make the outbox writable. | Amber with the note "Codex has no setting that limits which folders it reads; inumaki can only make the outbox writable.", once every connected outbox is in `writable_roots`. Grey when no folder is connected ("No folder is connected."), or the outboxes are not listed. Red when the key was changed outside inumaki. |
| Chat | Yes, once you switch Chat on: the `openai` route for an API-key login, the `codex` route (unverified, refused today) for a ChatGPT login. | See [Chat](#chat). |
| Hook | Shell tools only. | A section of its own, "Tool-result hook", after the three paths. Its status reads "installed", "not installed", **"waiting for trust" (amber)** with "Codex runs the inumaki hook only after you trust it: open /hooks in Codex and trust it.", or "broken" (red) with a reason: "The inumaki hook program is missing or cannot be run.", "The hook names an inumaki program or service socket that this inumaki no longer uses. Reconnect to update it.", or the changed-outside-inumaki sentence. |

A connected harness with Chat not routed shows grey "Off, your choice" and the tray icon stays yellow. The wording still says the chat is not filtered; only the alarm colour is gone, because that state can be your own choice, and a red mark for it would hide real failures.

The "Run the check" button in the toolbar of the Overview (and the one under "Last check" on the connection page) runs Codex non-interactively against a synthetic canary through each path you connected. It uses its own temporary configuration, so a pass says nothing about whether your real Chat route is on.

## Chat

Chat is an explicit opt-in. The Chat section of the Codex page has one switch labelled "Filter chat"; its full name, which a screen reader reads, is **Send Codex chat through inumaki** (with a ChatGPT login it is the longer text quoted below). It is disabled until the harness is connected ("Connect first"), and both directions ask for confirmation in a sheet first. Connect itself never writes a chat route in the app. What the switch routes depends on the login kind:

- **API-key login.** Switched on, the app writes the `openai` provider above while the proxy is running. The page shows amber "On", with "No traffic seen yet." until the first request arrives, and red if recent requests through the route failed ("Recent requests through this route failed."). If the proxy is not available, the page shows red with "The chat proxy is not available in this version." and nothing is written.
- **ChatGPT login.** Switched on, the app writes the `codex` route instead. That route is unverified and refused today: a run of Codex 0.159.2 against it on 2026-10-10 was refused with `privacy_block`, and it has not been verified since. The switch's label says so: **Protect chat with the ChatGPT login (unverified; refused today with privacy_block, so Codex chat stops working while this is on)**. Leave it off unless you are testing. With it on, the page can show Chat as on while Codex's requests fail. (Command line: `inumaki connect apply codex --chatgpt`.)
- **Switch off.** Nothing is written for chat. The page shows "Chat: off, your choice" in grey. With an API key, it says under that: "Chat is not protected: it goes straight to the provider, and inumaki does not see it." With a ChatGPT login, the line is "Codex with a ChatGPT login talks to ChatGPT directly and isn't filtered." and under it: "Chat is not protected: Codex with a ChatGPT login talks to ChatGPT directly. Routing it through inumaki is a separate opt-in, and it is refused today (privacy_block)." That is the default state, and your choice.

The confirmation before turning the switch on reads: "Codex sends chat through inumaki from its next session. With the support-email or strict profile, Codex's chat requests are refused today (measured 2026-10-10 with Codex 0.159.2), so Codex stops answering until you turn Chat off again." The one before turning it off reads: "Codex talks to its provider directly again from its next session, and its chat is no longer filtered by inumaki."

The switch shows the value in effect. If a chat route is already in place (written earlier by the app or the command line), an install from before this change keeps it, and the switch reads on. A Revert clears the choice. A harness that is not routed shows grey "Off, your choice", and the tray icon stays yellow: that state can be your own choice.

inumaki does not write Codex's `supports_websockets` key. If Codex attempts a WebSocket upgrade, the proxy answers `501`.

**A profile can go around the proxy.** Codex reads a profile file `$CODEX_HOME/<name>.config.toml` for `codex --profile <name>`. A profile file that sets its own `model_provider` sends that profile's chat straight to its provider. The page then shows Chat as "Off, your choice" in grey, with this sentence under it: "A Codex profile sets its own model provider; chat in that profile does not go through inumaki." (The `[profiles.<name>]` table in `config.toml` is ignored by Codex since 0.134.) inumaki does not edit profile files.

**Project configuration cannot route Chat.** Codex ignores `model_provider` and `model_providers` in a project-local `.codex/config.toml`, so only the user-level file counts.

**Today's refusal.** See [Known refusals and limits](#known-refusals-and-limits): under `support-email` and `strict`, Codex's chat requests are refused, so an API-key Codex whose Chat is routed stops answering under the default profile.

## Tool approval

If your `config.toml` has the top-level `approval_policy = "never"`, Codex refuses every MCP tool call that needs approval, including calls to the inumaki tools ("MCP tool call requires approval, but approval policy is never"). Connect then prints this warning and shows it in the app: "Codex is set to approval_policy = never and will refuse the inumaki tool calls; to allow them, set default_tools_approval_mode on the inumaki server entry in Codex's config." To allow the calls, add `default_tools_approval_mode = "approve"` to the inumaki entry under `[mcp_servers.<name>]`, or use another approval policy. Only the top-level key of `config.toml` is read for the warning, not profile files. Once the entry has the key, with any value, the warning stops.

## Hook trust

Codex runs a new or changed user hook only after you review and trust it. inumaki never writes that trust, because doing so would bypass Codex's review. After Connect, the hook section reads "waiting for trust" until you open `/hooks` in Codex and trust the inumaki hook. `inumaki connect status` shows the same as `pending: <reason>`.

- Codex stores the trust in `config.toml` under `[hooks.state."<hooks.json path>:post_tool_use:<group>:<handler>"]`, with a `trusted_hash`. inumaki checks that such a record exists for its position; it does not compute or compare the hash.
- The record is positional. If you add a group before inumaki's, or a re-apply changes the hook command (a new binary or socket path) so that the group moves, the old record points at the wrong place. Codex then treats the hook as modified and skips it, while the status may still read "installed". Trust it again in `/hooks`.
- The hook matches `^Bash$`. Codex reports its shell tools (`exec_command`, `write_stdin`) as `Bash`, so only shell tool results are checked. Codex MCP tool results, `apply_patch`, and hosted tools are not hooked, and neither is the output of a command that is still running or a failed tool result. See [What the hook cannot prevent](../harness-adapters.md#9-what-the-hook-cannot-prevent).
- While the service is stopped, hooked shell output is blocked. The hook fails closed: if the service is down, restarting, or the check cannot complete, a hooked result is replaced by `blocked by inumaki (<class>; kinds: …)`, and with the service unreachable the block text ends with "inumaki is not running; start it to restore tool output." This holds in every Codex session that runs the trusted hook, and it is deliberate ([The hook while the service is stopped](../threat-model.md#the-hook-while-the-service-is-stopped)). Connect warns about it ("While inumaki is stopped, tool output in every connected session is blocked. Start the service to recover; Revert also needs it running."), and the app's tray tooltip says so while the service is down. The hook fails closed only while the hook program runs: Codex passes the original output through if the hook program is missing, is killed, or times out, so a missing or killed program is not a block. The hook also sanitizes a result only when the tool input references a connected folder or outbox, or the output holds a multi-word or identifier-kind value the vault knows; it is not a general filter (`crates/inumakid/src/hook.rs`, and [What the hook does not guarantee](../threat-model.md#what-the-hook-does-not-guarantee)).
- If your organisation manages Codex with `requirements.toml` and `allow_managed_hooks_only`, your user hooks, including this one, may be skipped. inumaki does not detect that.

## Known refusals and limits

These are today's measured behaviour, not design goals.

- **Codex's chat requests are refused under `support-email` and `strict`.** Measured 2026-10-10 with Codex 0.159.2: the proxy refuses the request (`privacy_block`). The recorded cause is that the name model flags the harness's own static text (instructions, permission fragments, environment context) as person names, and the profile's rule for uncertain text is to block. The record of that measurement does not separate the API-key login from the ChatGPT login, so treat both Chat routes as refused. `support-email` is the default profile. With the shipped configuration (`[proxy] profile` empty, so the default profile applies), a Codex whose Chat is routed stops answering. The known-limits list records that `[proxy] profile = "fast"` gets past the refusal, with lower recall and no independent name re-scan in the verifier, and that it is not the recommended default. Both are listed in [Known limits at sign-off](../mvp-checklist.md#known-limits-at-sign-off). This stays until the planned precision work on harness text lands. See [Configuration](../configuration.md#proxy) for `proxy.profile`.
- **Codex with a ChatGPT login is unverified**, and refused today, as above.
- **Images and other attachments are replaced by a placeholder and are not inspected.** By default (`proxy.binary = "placeholder"`) an image, document, audio, or file part is removed and a fixed text stands in its place, so Codex's model cannot read a screenshot you attach. There is no OCR. A tool result that contains an attachment is withheld whole. Setting `proxy.binary = "forward"` sends attachments with no detection on them. See [Configuration](../configuration.md#proxy).
- **Request headers pass by an allowlist.** The proxy forwards only the request header names it lists for each upstream (`openai` for an API-key login, `openai-codex` for the ChatGPT route), and it checks the value of most of them against a shape. An unlisted header or a value that fails its shape is dropped, and the drop is counted in the daemon log by a closed label (never the name or value). A Codex release that adds a header the list does not know has that header dropped. If Codex needs it, name it in `[proxy.upstreams.openai] extra_headers` (or `openai-codex`); that forwards the header unchanged, with no value check. The proxy always removes `x-codex-turn-metadata`, because inside a git repository it holds the repository's absolute path (with your login name), the remotes' names, and the HEAD commit hash. **After a Codex upgrade, re-run the `harness_record` test** (`crates/inumakid/tests/harness_record.rs`). It runs the installed harness once directly and once through the proxy and reports any header the allowlist dropped. It is run by hand, never in CI:

  ```bash
  INUMAKI_RECORD_HARNESS=1 cargo test -p inumakid --test harness_record -- --ignored --nocapture --test-threads 1
  ```

  The header names the ChatGPT login sends were not recorded, so a header that route needs and the list lacks would be dropped. See the privacy note on `extra_headers` in [Configuration](../configuration.md#proxy), and the request-header item in the threat model's [known limitations](../threat-model.md#known-limitations).
- **Local paths in harness text pass unless a detector catches them.** Codex's `<environment_context>` names the working directory. It is ordinary text, so a login or project name in it is tokenized only when a detector finds it.
- **Files has no read scope.** Codex has no setting that limits which folders it reads, so inumaki can only make the outbox writable. The hook and the gateway are the controls that apply to what Codex reads.
- **The hook covers shell tools only**, and only once trusted (see [Hook trust](#hook-trust)).

## The command-line equivalent

```bash
inumaki connect status codex
inumaki connect apply codex                       # MCP, Files, Chat (routed by default here), and the hook
inumaki connect apply codex --no-chat             # leave the chat route alone (what the app does by default)
inumaki connect apply codex --chatgpt             # also route a ChatGPT login (refused today; see Chat)
inumaki connect apply codex --protect NAME        # also put the MCP server NAME behind the gateway
inumaki connect apply codex --no-hook --no-files  # skip the hook or the outbox
inumaki connect revert codex [--keep-backup]
```

Unlike the app, `apply` still routes chat by default, and prints a warning on stderr when it writes the route ("Codex sends chat through inumaki from its next session; with the support-email or strict profile its chat requests are refused today."); **use `--no-chat` unless you want chat routed.** `apply` needs a running daemon. Chat is only written while the proxy reports that it is running, read at the moment of the apply; if it is not, `apply` skips the route and says so (an explicit `--chat` fails instead). `--chatgpt` conflicts with `--no-chat`. Every file is checked before the first write, so a refusal changes nothing; it prints the lines to add by hand, which contain the gateway token and client header value, so do not paste them anywhere shared. If `approval_policy = "never"` is set, `apply` prints the approval warning after the success line and still exits `0`. When `apply` installs the hook (without `--no-hook`), it also prints "While inumaki is stopped, tool output in every connected session is blocked. Start the service to recover; Revert also needs it running." Reference: [`inumaki connect`](../cli.md#connect).

## Revert

Revert (the connection page's button, or `inumaki connect revert codex`) revokes the harness's gateway tokens first (the app records the revocation instead when the service is stopped, see below), then restores your files from the backup:

- Both files are copied whole before Connect, so if nothing else touched them they come back byte for byte. If something did, inumaki removes the keys it added and restores the previous values of the ones it replaced, and leaves any key you changed since, counting it. A `default_tools_approval_mode` you set on the inumaki entry goes with the entry, and the file is then restored key by key rather than byte for byte.
- **Codex's trust record for the hook is removed as well.** Codex wrote that record itself after you trusted the hook. Leaving it would trust an identical hook command after a later Connect without asking you. inumaki removes only the `[hooks.state."…"]` table at the exact position of its own hook, and an emptied `hooks.state` or `hooks` table. Other records and Codex's model usage counters stay. If the record cannot be removed, the revert still stands and the app (or the command, which exits `0`) says: "Codex's trust record for inumaki's hook could not be removed; remove it in Codex's /hooks."
- **Reconnect keeps the trust record.** Reconnect is a revert followed by an apply inside the app, and it keeps the record so you do not have to trust the hook again. Only your own Revert removes it.
- In the app, Revert works with the service stopped: it restores your files and records that this harness's gateway token is to be revoked, and the service revokes it before it serves anything at its next start (or within a minute, if it turns out to be running). While the service is stopped the token opens nothing, because nothing listens for it, but it is not revoked until then ([Gateway tokens in harness files](../threat-model.md#gateway-tokens-in-harness-files)). The app says so in the note after the Revert. `inumaki connect revert` still needs the running service: without it, nothing is reverted.
- Revert works on a first-time Codex configuration too: when `config.toml` had no `mcp_servers` or `hooks` table before Connect, the tables inumaki created are removed again if they are empty, and a table that existed before Connect stays.
- If you edited `[model_providers.inumaki]` after Connect, for example to point it at the real provider, Revert reports a conflict and keeps the table, client header included. Nothing flags the header. Remove the table by hand.

## Troubleshooting

- **"The configuration was changed outside inumaki. Reconnect to restore it."** Something edited a key inumaki owns. Press **Reconnect** on the connection page; it is always offered while the harness is connected, and it is the primary button when a path is broken or the harness is disconnected. From a terminal, run `inumaki connect revert codex`, then `inumaki connect apply codex --no-chat` (a plain `apply` does not revert first; it adds a new backup on top of the active one). A `default_tools_approval_mode` you added or changed is not drift. A Codex session writing its own state elsewhere in `config.toml` (the trust record, usage counters) is not drift either.
- **The hook says "waiting for trust".** Open `/hooks` in Codex and trust the inumaki hook. If it still reads waiting for trust after you trusted it, the trust record may be at an old position; see [Hook trust](#hook-trust).
- **Hook "broken": missing, or "Reconnect to update it".** The hook command names an `inumaki-hook` program or a service socket that this inumaki no longer uses, for example after the binaries moved. Reconnect rewrites the command, and the page offers it as the primary button for a broken hook. You may need to trust the hook again if its position changed.
- **Codex fails visibly at startup because an MCP server did not come up.** The gateway entry is `required`, and Codex waits up to 30 seconds for it. Start the service (`inumaki status`) and try again.
- **Codex refuses the inumaki tools.** See [Tool approval](#tool-approval).
- **Shell results read `blocked by inumaki (daemon_unreachable; kinds: none). inumaki is not running; …`.** The hook could not reach the service. Start the service and rerun the command. The app's Revert also removes the hook and works with the service stopped (the service revokes the gateway token at its next start); `inumaki connect revert` needs the running service. If the service cannot be started and you do not use the app, delete the `PostToolUse` group whose command names `inumaki-hook` from `$CODEX_HOME/hooks.json` by hand, and Revert once the service runs again. See [The hook while the service is stopped](../threat-model.md#the-hook-while-the-service-is-stopped).
- **Codex stopped answering after you switched Chat on (or after a command-line `apply` without `--no-chat`).** That is the refusal above. Turn the switch off in the app, or run `inumaki connect revert codex`, then `inumaki connect apply codex --no-chat`. Chat is the only part that stops Codex answering; the gateway, the outbox, and the hook do not.
- **Chat shows "Off, your choice" with a sentence about a profile.** A profile file sets its own `model_provider`. Remove that key from the profile file, or accept that the profile goes direct.
- **The inumaki proxy stopped, or another process took port 8787, after Connect.** Codex then sends its conversation, and its credentials, to whatever listens there. The route is checked once, at apply time. Revert, or restart the proxy. See [Revert and drift](../threat-model.md#revert-and-drift).
- **Managed configuration.** `/etc/codex/requirements.toml` can override user-level keys or skip user hooks, and inumaki does not detect it.
