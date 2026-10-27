# Connecting OpenClaw

This guide covers what inumaki does to OpenClaw when you connect it, what each protection path reaches, what it cannot do today, and how to undo it. It assumes you have read the project's introduction: inumaki replaces identifying values with opaque tokens before text leaves your machine, and restores them in the answer.

**Verification status: read this first.** The OpenClaw adapter was built from OpenClaw's published documentation and source (release tag `v2026.9.6`) and nothing else. It has never been run against a running OpenClaw, and no OpenClaw login, session, or model request has ever gone through it. Its behaviour is pinned by tests against fixture configuration files, not against the real program. Every statement below about what OpenClaw does with the keys inumaki writes is a reading of that documentation or source. [Verification status](#verification-status) lists what is unconfirmed.

Easy mode is the only mode in this release, and it has a stated limit: **An agent that deliberately goes around inumaki can still succeed.** Connecting edits OpenClaw's own configuration so that its traffic goes through inumaki. It does not stop OpenClaw, or anything it runs, from being configured or told to talk to a provider directly. An agent that can write `openclaw.json` can undo the connection; the connection page shows that as a changed setting (see [Troubleshooting](#troubleshooting)).

## At a glance

| Path | What it protects | Where Connect puts it |
|---|---|---|
| MCP | Tool servers you protect: their results reach OpenClaw as tokens | `openclaw.json` |
| Files | A sanitized mirror of folders you connected, mounted read-only into OpenClaw's Docker sandbox. Only where a sandbox is configured and the mirror lies inside an agent workspace. | `openclaw.json`, only in that case |
| Chat | The conversation OpenClaw sends to OpenAI or Anthropic, only when you switch Chat on (a switch on the connection page, shown for an API-key login). It applies when the selected model is from `openai` or `anthropic`. A subscription login is not routed and cannot be. | `openclaw.json`, only when the switch is on |
| Hook | Nothing. OpenClaw's tool-result hook does not fire in embedded runs, so inumaki installs none. | Nothing is written |

**Chat is off by default in the app. Whether turning it on stops OpenClaw from answering under `support-email` and `strict` has not been measured.** Read [Chat](#chat) before you switch it on. The command line differs: `inumaki connect apply` routes chat unless you pass `--no-chat`.

`openclaw.json` is a JSON5 file at `~/.openclaw/openclaw.json` unless an environment variable moves it (see [How inumaki finds OpenClaw](#how-inumaki-finds-openclaw)). Connect writes no other file.

## Versions

| | Version |
|---|---|
| Tested range of the adapter | 2026.9.6 to 2026.9.6 |
| Measured end to end | None. OpenClaw has not been run against inumaki. |

The range is the one release whose documentation and source were read. A version outside it still connects. Its connection page carries an "Untested version" chip, and `inumaki connect status` prints `(untested version)` after the harness id. If inumaki cannot read a version from `openclaw --version`, the version counts as untested too; the page then says "Version not detected" in place of the chip, with a note that what is filtered does not depend on it.

## How inumaki finds OpenClaw

Detection reads names and presence only. It never reads a credential value.

- **Program.** `openclaw` in `/opt/homebrew/bin`, `/usr/local/bin`, `~/.local/bin`, `~/.npm-global/bin`, `~/.claude/local`, or `~/.cargo/bin`, or the first `openclaw` on your login shell's `PATH`. The version is the first dotted number in the output of `openclaw --version`, with a 3-second limit.
- **Configuration file.** The first of these that applies: `$OPENCLAW_CONFIG_PATH` (the file itself); `$OPENCLAW_STATE_DIR/openclaw.json`; `<home>/.openclaw/openclaw.json`, where `<home>` is `$OPENCLAW_HOME` or your home directory, and the directory is `.openclaw-<profile>` when `$OPENCLAW_PROFILE` is set. The `.openclaw-<profile>` spelling is an assumption; the source read did not confirm it. OpenClaw counts as detected when the program is found or the file exists.
- **Login kind** (shown on the connection page), from `auth.profiles.<id>.mode` in `openclaw.json`, which holds names and modes only: a subscription login when any profile has the mode `oauth`; otherwise an API-key login when a profile has the mode `api_key` or `token`, or any entry in `models.providers` has an `apiKey`; otherwise unknown. OpenClaw keeps the credentials themselves in a SQLite file per agent, which inumaki does not read. A subscription mode on any profile wins over an API-key profile. The page words the kinds "Subscription login", "API key" and "Login not detected"; it does not say which provider a subscription login belongs to.

## What Connect writes

Before the first write, inumaki backs up `openclaw.json` whole. It edits only the keys listed here, and only when the file parses and prints back unchanged; otherwise it writes nothing and shows you the lines to add by hand. The editor keeps comments, trailing commas, and key order.

| Key | Value | When |
|---|---|---|
| `mcp.servers.<name>` | `url: "http://127.0.0.1:8789/mcp/<dataset>"`, `transport: "streamable-http"`, `headers: {Authorization: "Bearer <token>"}` | For each server pointing at the gateway already, and each server you choose to protect |
| `agents.defaults.sandbox.docker.binds` | One string appended: `<mirror root>:<mirror root>:ro` | Files, only when `agents.defaults.sandbox.docker` already exists and the mirror root lies inside an agent workspace (see [Files](#files)) |
| `models.providers.inumaki` | `baseUrl`, `api`, `apiKey`, `models: [{id, name}]`, and `headers: {X-Inumaki-Client: "<value>"}`. For an OpenAI selection, `baseUrl` is `http://127.0.0.1:8787/openai/v1` and `api` is `openai-completions`; for an Anthropic selection, `baseUrl` is `http://127.0.0.1:8787/anthropic` and `api` is `anthropic-messages`. | Chat |
| `agents.defaults.model` (a plain string) or `agents.defaults.model.primary` (when `model` is an object) | `inumaki/<model id>`, where `<model id>` is the model you had selected | Chat |

The proxy and gateway addresses are the defaults; see [Configuration](../configuration.md#proxy).

Notes on these keys:

- **The `apiKey` is a reference, never a copy.** If your selected provider's entry in `models.providers` already has an `apiKey` of the form `${NAME}`, inumaki reuses that reference. Otherwise it writes `${OPENAI_API_KEY}` or `${ANTHROPIC_API_KEY}`. A literal key is never copied. OpenClaw must find that variable in its environment, or requests through the new provider have no key.
- **Only one model is listed.** The `models` list holds the model you selected, with the id as its name. Any other model of the same provider is not on the `inumaki` provider.
- **Only the default selection moves.** inumaki changes `agents.defaults.model` (or its `primary`). It does not touch `fallbacks`, or an `agents.list[].model` entry of a single agent. Those still name the real provider, so requests that use them go direct. See [Chat](#chat).
- **The gateway token** is a bearer token labelled `app:openclaw`. It is revoked when you Revert (with the service stopped, at the service's next start). **Reconnect** is a button on the connection page that is offered whenever the harness is connected (it is the primary button when the harness is disconnected or something on the page needs attention): in the app it reverts the harness and applies it again with your current choices, which mints a new gateway token and revokes the old.
- **The client header** is a per-install secret. The proxy restores tokens from your connected datasets in OpenClaw's answers only for requests that carry it; without it, chat is still filtered, but values from connected sources stay tokens. See [The client header](../threat-model.md#the-client-header). Whether OpenClaw really sends the `headers` value of a provider is not confirmed; see [Verification status](#verification-status).
- **inumaki never writes a `dangerously*` flag.** See [Files](#files).
- **Everything else in the file stays as it was.**

## The paths on the connection page

The app has one page per harness, under "Connections" in the sidebar; the Overview lists the harnesses and opens it. The page shows each path as a section whose title is the path and a status word, for example "Files: not protected". Each status has a glyph shape and a colour as well as the word, so it reads without colour. The colours are:

- **Grey**: "Off" (not connected, with nothing wrong), "Off, your choice" (Chat on a connected harness that you have not routed), and "Not protected" or "Not protected, acknowledged" (a path that cannot be protected, drawn with a dashed ring). **Acknowledge** is a text button in the section of a path that cannot be protected. It records that you know the path is not protected and changes nothing in OpenClaw; the status then reads "Not protected, acknowledged".
- **Amber**: "On" or "On, unverified". Amber is the best state in Easy mode. Green is reserved for a stricter mode that this release does not have.
- **Red**: a broken path ("Needs attention"). A disconnected harness shows a red "Disconnected" notice and its paths read "Not filtered now" (grey). A failed check is shown under "Last check".

| Path | Reach | Colour and reason on the page |
|---|---|---|
| MCP | Yes. Servers under `mcp.servers` are listed and protected. | Grey when no server points at the gateway. Amber "On", with "N of M servers protected". Red when the file changed outside inumaki ("The configuration was changed outside inumaki. Reconnect to restore it."), when the service is down ("The inumaki service is not running."), or when a protected server's dataset has no running upstream ("A protected server is not running."). |
| Files | Partial. Docker sandbox binds only. | See [Files](#files). |
| Chat | API-key login with `openai` or `anthropic` selected: yes, for the default model selection. Subscription login: no. Any other selection: no. | See [Chat](#chat). |
| Hook | None. | The app shows no hook section for OpenClaw. `inumaki connect status` prints `not supported: OpenClaw's tool-result hook does not fire in embedded runs (openclaw#60209), so inumaki installs none.` |

A path that cannot be protected (an unsupported Files path, or Chat with a subscription login) does not turn the tray icon red, whether or not you acknowledged it. The tray stays yellow, and the OpenClaw line in the tray menu reads "a path is not protected" until you acknowledge it. The page keeps the path's reason. Acknowledging records only your decision and changes the status word. The tray turns red only for a broken path, a disconnected harness, a failing route or upstream, a failed check, or a configuration error. A connected harness with Chat not routed (as opposed to unsupported) shows grey "Off, your choice" on the page and leaves the tray yellow. The page still says the chat goes to the provider directly and is not filtered; that state can be your own choice, and an alarm colour for it would hide real failures.

The "Run the check" button in the toolbar of the Overview (and the one under "Last check" on the connection page) runs the gateway, mirror, and proxy checks directly. It does not start OpenClaw: there is no non-interactive OpenClaw command line in the adapter, so nothing has exercised OpenClaw itself.

## Files

OpenClaw can see the mirror only through its Docker sandbox, and only when you have a sandbox configured. The bind is read-only. It makes the mirror readable inside the sandbox; it does not stop OpenClaw from reading your real folders, and the bind applies to the sandbox only.

The Files section depends on your configuration:

| Your configuration | Files section |
|---|---|
| No `agents.defaults.sandbox.docker` table | "Files: not protected" (grey, dashed ring) with "OpenClaw has no Docker sandbox configured, so the mirror cannot be mounted." |
| A Docker table, and the mirror root is outside every agent workspace | "Files: not protected" with "OpenClaw sees the mirror through its Docker sandbox only." Nothing is written. |
| A Docker table, and the mirror root is inside an agent workspace, bind written, a folder connected | Amber "On", with the note "OpenClaw sees the mirror through its Docker sandbox only." |
| The same, but no folder connected | Grey, with "No folder is connected." |
| The same, but Files was skipped (`--no-files`), so no bind was written | Grey |

An unsupported Files path reads "Not protected" until you press **Acknowledge** on the page; then it reads "Not protected, acknowledged".

The workspace test is this: the mirror root must start with `agents.defaults.workspace` or the `workspace` of an entry in `agents.list`. Only absolute paths count. A workspace written as `~/work` is not expanded, so inumaki treats the mirror as outside it, and Files stays unsupported even when it is inside. inumaki reads `agents.defaults.sandbox.docker` only; a per-agent sandbox setting is not examined.

**Why the bind is not always written.** OpenClaw blocks a bind whose source lies outside the workspace roots unless `agents.defaults.sandbox.docker.dangerouslyAllowExternalBindSources` is `true`. Easy mode never writes a flag with that name, because it widens what the sandbox may mount. If you want the mirror inside the sandbox in that case, you can add both the bind (`<mirror root>:<mirror root>:ro` under `agents.defaults.sandbox.docker.binds`) and the flag yourself. That is your decision, and inumaki does not check it. The app and `inumaki connect status` show the bind line while Files is unsupported for this reason: in the app, press **Show the lines to add** in the Files section (it opens the line with a copy button); in a terminal, `inumaki connect status openclaw` prints it under `add by hand:`. The line holds your mirror root, which is a path, so the page itself never carries it until you ask. Both show the bind only: the `dangerously*` flag stays your own decision, and the note beside the line names it.

## Chat

Chat is an explicit opt-in. The Chat section of the OpenClaw page has a switch labelled "Filter chat"; its full name, which a screen reader reads, is **Send OpenClaw chat through inumaki**. It is shown only for an API-key login (a subscription login cannot be routed, so a switch there would do nothing). It is disabled until the harness is connected, and both directions ask for confirmation in a sheet. Turning it on reads: "OpenClaw sends chat through inumaki at the latest from its next session. Whether the support-email or strict profile refuses its chat requests is not measured; if it does, OpenClaw stops answering until you turn Chat off again." Turning it off reads: "OpenClaw talks to its provider directly again from its next session, and its chat is no longer filtered by inumaki." OpenClaw was never run against inumaki and its refusal was never measured, and when it picks up a change to `openclaw.json` is unconfirmed, so the change applies at the latest from its next session. The switch shows the value in effect: an install from before this change that already routed chat keeps it on. A Revert clears the choice.

What the switch writes depends on the login kind and on the model you selected.

**API-key login, model from `openai` or `anthropic`.** OpenClaw's selected model is a string `"provider/model"`, either as `agents.defaults.model` or as `agents.defaults.model.primary`. When the provider is `openai` or `anthropic`, the switch is on, and the proxy is running, the app writes the `inumaki` provider and changes the selection to `inumaki/<model id>`. The page shows amber "On", with "No traffic seen yet." until the first request arrives, and red if recent requests through the route failed ("Recent requests through this route failed."). The proxy recognises OpenClaw by a `User-Agent` containing `openclaw`. No real OpenClaw request has been observed, so if OpenClaw sends a different `User-Agent`, the note may never clear even though traffic flows. If the proxy is not available, the page shows red with "The chat proxy is not available in this version." and nothing is written.

**API-key login, any other provider, or a model setting that is not `provider/model`.** Nothing is written. The page shows "Chat: off, your choice" in grey with "The selected model provider has no inumaki route, so chat was left unchanged." under it, and says that OpenClaw talks to its model provider directly.

**Login kind unknown.** Nothing is written, because inumaki routes Chat only for an API-key login. If your selected model is `openai` or `anthropic`, the page shows "Chat: off, your choice" in grey with "Chat is not protected: it goes straight to the provider, and inumaki does not see it." under it.

**Subscription login: cannot be routed.** The page shows "Chat: not protected" (grey, dashed ring) with: "OpenClaw's Claude or ChatGPT subscription login runs through a command-line bridge that has no base-URL setting, so chat text is not filtered. Use an API key, or keep sensitive data in connected sources." Nothing is written. Press **Acknowledge** to change the status to "Not protected, acknowledged" (the tray is not red for this path, acknowledged or not); that records your decision and protects nothing. An agent using a subscription login is protected only for what flows through the gateway.

**What a routed OpenClaw still sends direct.**

- **Fallbacks and per-agent models.** `fallbacks` and `agents.list[].model` entries still name the real provider. Requests that use them go straight to it, and the page still says connected. The threat model also records that when the proxy or daemon is down, OpenClaw falls back direct; see [Chat paths that go around the proxy](../threat-model.md#chat-paths-that-go-around-the-proxy).
- **Anything not an `openai` or `anthropic` model.** The adapter has routes for those two only.

**Today's refusal.** See [Known refusals and limits](#known-refusals-and-limits).

## Why there is no hook

Claude Code and Codex get a tool-result hook: a command the harness runs on a tool's output before the model sees it. OpenClaw gets none. Its tool-result hook (`tool_result_persist`) does not fire in embedded agent runs; the upstream issue is openclaw#60209, recorded as open when the adapter was designed and not re-checked since. A hook that does not run cannot protect anything, and a page that said "installed" would be false, so inumaki installs none and shows none. The gateway is the only control on tool results that is specific to your connected sources. Built-in tools and MCP servers that you did not protect return their results to the model as they are; when Chat is routed, the proxy scans the request that carries them, with the profile's detectors. When Chat is not routed, nothing scans them. See [What the hook cannot prevent](../harness-adapters.md#9-what-the-hook-cannot-prevent).

## Verification status

Everything on this page about OpenClaw's behaviour comes from reading its documentation and source at tag `v2026.9.6`. Nothing was exercised against a running OpenClaw. Specifically, these are unconfirmed:

- That OpenClaw sends `models.providers.<id>.headers` on the request. The source types the key as a record of strings; the use of the value was not traced. If it does not, chat still works and is still filtered, but values from connected sources stay tokens in answers, and nothing flags it.
- That OpenClaw uses `mcp.servers.<name>` with `url`, `transport`, and `headers` as written, and when it picks up a change to `openclaw.json`.
- That the login kinds are read correctly from `auth.profiles.<id>.mode`. The modes beyond `oauth` come from prose in the documentation, and the credentials live where inumaki does not look.
- That a subscription login really has no base-URL setting.
- That a Docker bind inside a workspace root behaves as the documentation says, and the `.openclaw-<profile>` directory name.
- That `openclaw --version` prints a dotted version number inumaki can read.
- That the proxy's `User-Agent` test recognises real OpenClaw traffic.
- That openclaw#60209 is still open and still describes the behaviour.

The shared record of unconfirmed facts is [Unverified facts and the fail-safe choice made](../harness-adapters.md#unverified-facts-and-the-fail-safe-choice-made). The sign-off state of the whole release is in [`docs/mvp-checklist.md`](../mvp-checklist.md); its harness walk-through has not been completed for OpenClaw.

## Known refusals and limits

These are the limits that apply to OpenClaw today. Unlike the Claude Code and Codex guides, none of them was measured with OpenClaw.

- **Harness chat requests are refused under `support-email` and `strict` for Claude Code and Codex; OpenClaw has not been measured.** The measured cause is that the name model flags a harness's own static text (instructions, environment context) as person names, and the profile's rule for uncertain text is to block. OpenClaw sends its own system prompt and tool descriptions, and nothing says they avoid this. If you route OpenClaw's Chat with the shipped configuration (`[proxy] profile` empty, so the default `support-email` profile applies), expect that OpenClaw may stop answering. See [Known limits at sign-off](../mvp-checklist.md#known-limits-at-sign-off) and [Configuration](../configuration.md#proxy) for `proxy.profile`.
- **Images and other attachments are replaced by a placeholder and are not inspected.** By default (`proxy.binary = "placeholder"`) an image, document, audio, or file part is removed and a fixed text stands in its place, so OpenClaw's model cannot read a screenshot you attach. There is no OCR. A tool result that contains an attachment is withheld whole. Setting `proxy.binary = "forward"` sends attachments with no detection on them. See [Configuration](../configuration.md#proxy).
- **Request headers pass by an allowlist, and OpenClaw's headers were never recorded.** The proxy forwards only the request header names it lists for each upstream (`openai` or `anthropic` for OpenClaw), and checks the value of most against a shape. An unlisted header, or a value that fails its shape, is dropped, and the drop is counted in the daemon log by a closed label (never the name or value). The `harness_record` test, which runs an installed harness once directly and once through the proxy and reports any dropped header, exists for Claude Code and Codex only. Nothing re-checks OpenClaw after an upgrade. If OpenClaw needs a header the list does not know, name it in `[proxy.upstreams.openai] extra_headers` (or `anthropic`); that forwards the header unchanged, with no value check. See the privacy note on `extra_headers` in [Configuration](../configuration.md#proxy), and the request-header item in the threat model's [known limitations](../threat-model.md#known-limitations).
- **Files reaches the Docker sandbox only,** and only in the cases listed in [Files](#files).
- **Subscription logins are not filtered in chat.**
- **Fallback and per-agent models go direct** (see [Chat](#chat)).
- **There is no tool-result hook** (see [Why there is no hook](#why-there-is-no-hook)).
- **Local paths and the login name in harness text pass unless a detector catches them.** They are ordinary text, so they are tokenized only when a detector finds the name in them.

## The command-line equivalent

```bash
inumaki connect status openclaw
inumaki connect apply openclaw                    # MCP, Files (where the sandbox allows), and Chat (API-key login; routed by default here)
inumaki connect apply openclaw --no-chat          # leave the chat route alone (what the app does by default)
inumaki connect apply openclaw --no-files         # skip the Docker bind
inumaki connect apply openclaw --protect NAME     # also put the MCP server NAME behind the gateway
inumaki connect revert openclaw [--keep-backup]
```

`--no-hook` has nothing to skip for OpenClaw, and `--chatgpt` is for Codex. Unlike the app, `apply` still routes chat by default, and prints a warning on stderr when it writes the route ("OpenClaw sends chat through inumaki at the latest from its next session; whether the support-email or strict profile refuses its chat requests is not measured."); **use `--no-chat` unless you want chat routed.** `apply` needs a running daemon. Chat is only written while the proxy reports that it is running, read at the moment of the apply; if it is not, `apply` skips the route and says so (an explicit `--chat` fails instead). Every file is checked before the first write, so a refusal changes nothing; it prints the lines to add by hand, which contain the gateway token and client header value, so do not paste them anywhere shared. Reference: [`inumaki connect`](../cli.md#connect).

## Revert

Revert (the connection page's button, or `inumaki connect revert openclaw`) revokes the harness's gateway tokens first (the app records the revocation instead when the service is stopped, see below), then restores your file from the backup:

- `openclaw.json` is copied whole before Connect, so if nothing else touched it, it comes back byte for byte. If something did, inumaki removes the keys it added and restores the previous values of the ones it replaced (including your earlier model selection), and leaves any key you changed since, counting it.
- A protected server's original entry returns, with the secrets it held.
- If you edited `models.providers.inumaki` after Connect, for example to point it at the real provider, Revert reports a conflict and keeps the table, client header included. Nothing flags the header. Remove the table by hand.
- In the app, Revert works with the service stopped: it restores your file and records that this harness's gateway token is to be revoked, and the service revokes it before it serves anything at its next start (or within a minute, if it turns out to be running). While the service is stopped the token opens nothing, because nothing listens for it, but it is not revoked until then ([Gateway tokens in harness files](../threat-model.md#gateway-tokens-in-harness-files)). The app says so in the note after the Revert. `inumaki connect revert` still needs the running service: without it, nothing is reverted.
- A bind or a `dangerously*` flag you added by hand is not touched.

## Troubleshooting

- **"The configuration was changed outside inumaki. Reconnect to restore it."** Something edited a key inumaki owns, for example OpenClaw or an agent rewriting `openclaw.json`. Press **Reconnect** on the connection page; it is always offered while the harness is connected, and it is the primary button when a path is broken or the harness is disconnected. From a terminal, run `inumaki connect revert openclaw`, then `inumaki connect apply openclaw --no-chat` (a plain `apply` does not revert first; it adds a new backup on top of the active one). Either way a new gateway token is issued.
- **Connect refuses and prints lines to add by hand.** The file does not parse, or uses syntax the editor cannot keep. Add the lines by hand, or fix the file and connect again.
- **Files reads "not protected" with "OpenClaw has no Docker sandbox configured".** OpenClaw reads nothing from the mirror until a Docker sandbox exists. Configure one, then press **Reconnect**; or press **Acknowledge** to record that you accept it.
- **Files reads "not protected" with "OpenClaw sees the mirror through its Docker sandbox only".** The mirror is outside your agent workspaces, or a workspace is written with `~`. Move the workspace setting to an absolute path that contains the mirror root, or see [Files](#files) for the manual route.
- **Chat reads "not protected" for a subscription login.** It cannot be routed. Use an API key, or keep sensitive data in connected sources, as the page says.
- **Chat shows "Off, your choice" with "The selected model provider has no inumaki route".** Your selected model is not from `openai` or `anthropic`, or is not written as `provider/model`. OpenClaw goes direct for it.
- **OpenClaw stopped answering after you switched Chat on (or after a command-line `apply` without `--no-chat`).** A profile refusal is the likely cause (see [Known refusals and limits](#known-refusals-and-limits)), or the `${OPENAI_API_KEY}` or `${ANTHROPIC_API_KEY}` reference has no value in OpenClaw's environment. Run `inumaki connect revert openclaw`, then `inumaki connect apply openclaw --no-chat`. Chat is the only part that can stop OpenClaw answering; the gateway entries do not.
- **The inumaki proxy stopped, or another process took port 8787, after Connect.** OpenClaw then sends its conversation, and its credentials, to whatever listens there, or falls back direct. The route is checked once, at apply time. Revert, or restart the proxy. See [Revert and drift](../threat-model.md#revert-and-drift).
- **Chat is on but the page says "No traffic seen yet."** No request has been recognised as OpenClaw since the daemon started; see [Chat](#chat).
