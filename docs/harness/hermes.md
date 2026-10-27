# Connecting Hermes Agent

This guide covers what inumaki does to Hermes Agent when you connect it, what each protection path reaches, what it cannot do today, and how to undo it. It assumes you have read the project's introduction: inumaki replaces identifying values with opaque tokens before text leaves your machine, and restores them in the answer.

**Verification status: read this first.** The Hermes adapter was built from Hermes's published source (release tag `v2026.9.24`, `_config_version: 46`) and nothing else. It has never been run against a running Hermes, and no Hermes login, session, or model request has ever gone through it. Its behaviour is pinned by tests against fixture configuration files, not against the real program. Every statement below about what Hermes does with the keys inumaki writes is a reading of that source. [Verification status](#verification-status) lists what is unconfirmed.

Easy mode is the only mode in this release, and it has a stated limit: **An agent that deliberately goes around inumaki can still succeed.** Connecting edits Hermes's own configuration so that its traffic goes through inumaki. It does not stop Hermes, or anything it runs, from being configured or told to talk to a provider directly. An agent that can write `~/.hermes/config.yaml` can undo the connection; the connection page shows that as a changed setting (see [Troubleshooting](#troubleshooting)).

## At a glance

| Path | What it protects | Where Connect puts it |
|---|---|---|
| MCP | Tool servers you protect: their results reach Hermes as tokens | `config.yaml` |
| Files | Nothing. Hermes has no confirmed setting that limits which folders it reads. | Nothing is written |
| Chat | The conversation Hermes sends to OpenAI or Anthropic, only when you switch Chat on (a switch on the connection page, shown for an API-key login). It applies when the selected provider is `openai` or `anthropic`. A subscription login is not routed and has no switch. | `config.yaml`, only when the switch is on |
| Hook | Nothing. Hermes runs hooks fail-open, so inumaki installs none. | Nothing is written |

**Chat is off by default in the app. Whether turning it on stops Hermes from answering under `support-email` and `strict` has not been measured.** Read [Chat](#chat) before you switch it on. The command line differs: `inumaki connect apply` routes chat unless you pass `--no-chat`.

`config.yaml` is `~/.hermes/config.yaml`, or `$HERMES_HOME/config.yaml` when that environment variable is set. Connect writes no other file. It never writes Hermes's `.env`.

## Versions

| | Version |
|---|---|
| Tested range of the adapter | 2026.9.24 to 2026.9.24 |
| Measured end to end | None. Hermes has not been run against inumaki. |

The range is the one release whose source was read. A version outside it still connects. Its connection page carries an "Untested version" chip, and `inumaki connect status` prints `(untested version)` after the harness id. If inumaki cannot read a version from `hermes --version`, the version counts as untested too; the page then says "Version not detected" in place of the chip, with a note that what is filtered does not depend on it.

## How inumaki finds Hermes

Detection reads names and presence only. It never reads a credential value.

- **Configuration file.** `config.yaml` in `$HERMES_HOME`, default `~/.hermes`. Hermes counts as detected only when this file exists, because Hermes writes it during its setup and there is nothing to connect before that. A `hermes` program without the file is not detected.
- **Program.** `hermes` in `/opt/homebrew/bin`, `/usr/local/bin`, `~/.local/bin`, `~/.npm-global/bin`, `~/.claude/local`, or `~/.cargo/bin`, or the first `hermes` on your login shell's `PATH`. The version is the first dotted number in the output of `hermes --version`, with a 3-second limit. The program is optional for detection; the page shows the version only when it is found.
- **Login kind** (shown on the connection page), from names only: an API key when `$HERMES_HOME/.env` contains a variable whose name ends in `_API_KEY` (inumaki reads the file to collect the names, and keeps none of the values); otherwise a subscription login when `$HERMES_HOME/auth.json` exists; otherwise unknown. When both are present, the API key wins. The name test is a rough one: any `*_API_KEY` line, for any provider, makes the login an API-key login.

## What Connect writes

Before the first write, inumaki backs up `config.yaml` whole. It edits only the keys listed here, and only when the file parses and prints back unchanged; otherwise it writes nothing and shows you the lines to add by hand.

| Key | Value | When |
|---|---|---|
| `mcp_servers.<name>` | `url: "http://127.0.0.1:8789/mcp/<dataset>"` and `headers: {Authorization: "Bearer <token>"}` | For each server pointing at the gateway already, and each server you choose to protect |
| `providers.inumaki` | `base_url`, `key_env`, and `extra_headers: {X-Inumaki-Client: "<value>"}`. For an OpenAI selection, `base_url` is `http://127.0.0.1:8787/openai/v1` and `key_env` is `OPENAI_API_KEY`; for an Anthropic selection, `base_url` is `http://127.0.0.1:8787/anthropic` and `key_env` is `ANTHROPIC_API_KEY`. | Chat |
| `model.provider` | `inumaki` | Chat |

The proxy and gateway addresses are the defaults; see [Configuration](../configuration.md#proxy).

Notes on these keys:

- **Chat is written only when the Chat switch is on, for an API-key login whose selected provider has a route.** inumaki reads `model.provider`. If it is `openai` or `anthropic`, and the matching key name (`OPENAI_API_KEY` or `ANTHROPIC_API_KEY`) is in `$HERMES_HOME/.env`, Connect writes the two Chat keys above. If `model.provider` is anything else, including Hermes's default `auto`, OpenRouter, or a custom provider of yours, Chat is left unchanged and the page says "The selected model provider has no inumaki route, so chat was left unchanged." A key that Hermes finds some other way (your shell's environment, a `key_cmd`, an `api_key` in `providers`) does not count, because inumaki looks for the name in `.env` only.
- **The provider is named `inumaki` on purpose.** Hermes lets a built-in provider id shadow a custom entry of the same name, so an entry called `openai` or `anthropic` would be ignored. inumaki writes no model name and no `api_mode`; your `model.default` stays as it was, and Hermes picks the wire format from the `base_url` (a path ending in `/anthropic` selects the Anthropic format).
- **The gateway token** is a bearer token labelled `app:hermes`. It is revoked when you Revert (with the service stopped, at the service's next start). **Reconnect** is a button on the connection page that is offered whenever the harness is connected (it is the primary button when the harness is disconnected or something on the page needs attention): in the app it reverts the harness and applies it again with your current choices, which mints a new gateway token and revokes the old.
- **The client header** is a per-install secret. The proxy restores tokens from your connected datasets in Hermes's answers only for requests that carry it; without it, chat is still filtered, but values from connected sources stay tokens. See [The client header](../threat-model.md#the-client-header). Whether Hermes really sends the `extra_headers` value, in both of its wire formats, is not confirmed; see [Verification status](#verification-status).
- **Everything else in the file stays as it was.** The YAML editor keeps comments and key order. Blank lines near an edit can shift, which is cosmetic. It refuses, and writes nothing, when an edited section uses flow style (`{…}` or `[…]` on the path it edits), when the file has an anchor, alias, or merge key anywhere, or when the file has more than one YAML document.

## The paths on the connection page

The app has one page per harness, under "Connections" in the sidebar; the Overview lists the harnesses and opens it. The page shows each path as a section whose title is the path and a status word, for example "Files: not protected". Each status has a glyph shape and a colour as well as the word, so it reads without colour. The colours are:

- **Grey**: "Off" (not connected, with nothing wrong), "Off, your choice" (Chat on a connected harness that you have not routed), and "Not protected" or "Not protected, acknowledged" (a path that cannot be protected, drawn with a dashed ring). **Acknowledge** is a text button in the section of a path that cannot be protected. It records that you know the path is not protected and changes nothing in Hermes; the status then reads "Not protected, acknowledged".
- **Amber**: "On", "On, unverified", or "Needs one line you add" (a Chat path that is set up only after a line you add yourself). Amber is the best state in Easy mode. Green is reserved for a stricter mode that this release does not have.
- **Red**: a broken path ("Needs attention"). A disconnected harness shows a red "Disconnected" notice and its paths read "Not filtered now" (grey). A failed check is shown under "Last check".

| Path | Reach | Colour and reason on the page |
|---|---|---|
| MCP | Yes. Servers under `mcp_servers` are listed and protected. | Grey when no server points at the gateway. Amber "On", with "N of M servers protected". Red when the file changed outside inumaki ("The configuration was changed outside inumaki. Reconnect to restore it."), when the service is down ("The inumaki service is not running."), or when a protected server's dataset has no running upstream ("A protected server is not running."). |
| Files | No. | "Files: not protected" (grey, dashed ring) with "The mirror exists, but Hermes has no confirmed setting that restricts it to the mirror.", until you press **Acknowledge** on the page; then "Not protected, acknowledged". |
| Chat | API-key login with `openai` or `anthropic` selected: yes. Subscription login: no. Any other selection: no. | See [Chat](#chat). |
| Hook | None. | The app shows no hook section for Hermes. `inumaki connect status` prints `not supported: Hermes runs hooks fail-open, so inumaki installs none.` |

A path that cannot be protected does not turn the tray icon red, whether or not you acknowledged it. The tray stays yellow, and the Hermes line in the tray menu reads "a path is not protected" until you acknowledge it. The page keeps the path's reason. Acknowledging records only your decision and changes the status word. The tray turns red only for a broken path, a disconnected harness, a failing route or upstream, a failed check, or a configuration error. A connected harness with Chat not routed shows grey "Off, your choice" on the page and leaves the tray yellow. The page still says the chat goes to the provider directly and is not filtered; Chat off is the default and can be your own choice, and an alarm colour for it would hide real failures.

The "Run the check" button in the toolbar of the Overview (and the one under "Last check" on the connection page) runs the gateway, mirror, and proxy checks directly, and for Hermes it also starts `hermes chat -q` against a synthetic canary, using its own temporary `HERMES_HOME` and a dummy key. That command line has never been run against a real Hermes, and the one-shot form `chat -q` is not confirmed for 2026.9.24. The check uses its own temporary configuration, so a pass says nothing about whether your real Chat route is on.

## Chat

Chat is an explicit opt-in. The Chat section of the Hermes page has a switch labelled "Filter chat"; its full name, which a screen reader reads, is **Send Hermes Agent chat through inumaki**. It is shown only for an API-key login (inumaki writes no chat route for a subscription login, so a switch there would do nothing). It is disabled until the harness is connected, and both directions ask for confirmation in a sheet. Turning it on reads: "Hermes Agent sends chat through inumaki at the latest from its next session. Whether the support-email or strict profile refuses its chat requests is not measured; if it does, Hermes Agent stops answering until you turn Chat off again." Turning it off reads: "Hermes Agent talks to its provider directly again from its next session, and its chat is no longer filtered by inumaki." Hermes was never run against inumaki and its refusal was never measured, so the change applies at the latest from its next session; no hot reload is claimed. The switch shows the value in effect: an install from before this change that already routed chat keeps it on. A Revert clears the choice.

What the switch writes depends on the login kind and on the provider you selected.

**API-key login, `openai` or `anthropic` selected.** With the switch on, the app writes the provider above when the proxy is running. The page shows amber "On", with "No traffic seen yet." until the first request arrives, and red if recent requests through the route failed ("Recent requests through this route failed."). The proxy recognises Hermes by a `User-Agent` containing `hermes-agent`. No real Hermes request has been observed, so if Hermes sends a different `User-Agent`, the note may never clear even though traffic flows. If the proxy is not available, the page shows red with "The chat proxy is not available in this version." and nothing is written.

**API-key login, any other provider.** Nothing is written. The page shows "Chat: off, your choice" in grey with "The selected model provider has no inumaki route, so chat was left unchanged." under it. Hermes sends its conversation straight to that provider. The same reason sentence appears when the login kind is unknown.

**Subscription login (ChatGPT or Codex, or Anthropic): not routed, and shown amber.** inumaki writes nothing for a subscription login. The page shows the section as **"Chat: needs one line you add"** in amber, with the sentence: "Hermes can route this login through inumaki only with a base-URL setting that inumaki does not write yet; chat text is not filtered until you add it by hand." `inumaki connect status` prints it as `unverified: …`.

> **Amber here does not mean protected.** An unrouted Chat path on a connected harness is grey "Off, your choice" on the other pages. A Hermes subscription login is the same situation, chat going straight to the provider, but it reads amber "Needs one line you add", because the one setting that would route it is a line you add yourself and inumaki cannot tell whether you did. Until you add it, chat text is not filtered. Read the sentence, not the colour. `inumaki connect status` prints this state as `unverified: …`.

If you want to route a subscription login, you add the setting yourself. The app shows the lines on demand: press **Show the lines to add** in the Chat section, and the lines open with a copy button. In a terminal, `inumaki connect status hermes` prints them under `add by hand:`. Both need the proxy running, because the lines carry the proxy's route address, which is also why the page itself never holds them until you ask. The lines come from reading Hermes's source and have not been tried:

- **ChatGPT or Codex login.** Add `HERMES_CODEX_BASE_URL=http://127.0.0.1:8787/codex` to `$HERMES_HOME/.env`. This is the proxy's Codex route. The same route is unverified and refused today when Codex itself uses it with a ChatGPT login (see [Connecting Codex](codex.md#chat)); nothing says it behaves differently for Hermes.
- **Anthropic login.** With `model.provider: anthropic`, set `model.base_url` to `http://127.0.0.1:8787/anthropic`.

A hand-written route carries no client header, so the proxy filters the chat but values from your connected sources stay tokens in the answers. The note beside the lines says it: Hermes OAuth sends no client header, so only session tokens are restored. inumaki does not check these lines, does not report on them, and never removes them: Revert does not touch `.env` or a `model.base_url` you added. If you remove the proxy later, remove the lines too.

**Today's refusal.** See [Known refusals and limits](#known-refusals-and-limits).

## Why there is no hook

Claude Code and Codex get a tool-result hook: a command the harness runs on a tool's output before the model sees it. Hermes gets none. From Hermes's source, Hermes runs hooks fail-open: on any error in a hook, Hermes carries on with the original output. inumaki's hook is built to fail closed, replacing a result it cannot check with a block message, and under Hermes's fail-open handling that block could not be enforced: a hook that errors is exactly the case where the original output would reach the model. So for Hermes, the gateway is the only control on tool results that is specific to your connected sources. Built-in tools (the terminal, file reads) and MCP servers that you did not protect return their results to the model as they are; when Chat is routed, the proxy scans the request that carries them, with the profile's detectors. When Chat is not routed, nothing scans them. Revisit this after a Hermes release changes how it runs hooks. See [What the hook cannot prevent](../harness-adapters.md#9-what-the-hook-cannot-prevent).

## Verification status

Everything on this page about Hermes's behaviour comes from reading its source and example configuration at tag `v2026.9.24`. Nothing was exercised against a running Hermes. Specifically, these are unconfirmed:

- That Hermes applies `providers.<name>.extra_headers` to the request, in both its `chat_completions` and `anthropic_messages` formats. The source lists the key; the application of the value was not traced. If it does not, chat still works and is still filtered, but values from connected sources stay tokens in answers, and nothing flags it.
- That `mcp_servers.<name>` with `url` and `headers` is used by Hermes's HTTP MCP client as written, and that a change to `config.yaml` is picked up in the next session.
- That a subscription login honours the base-URL settings in [Chat](#chat) on every code path. The source has several credential paths; the environment variable is the one honoured on all of them.
- That `hermes --version` prints a version inumaki can read, and that `hermes chat -q` is the one-shot form.
- That the proxy's `User-Agent` test recognises real Hermes traffic.
- That Hermes runs hooks fail-open in the way described above.

The shared record of unconfirmed facts is [Unverified facts and the fail-safe choice made](../harness-adapters.md#unverified-facts-and-the-fail-safe-choice-made). The sign-off state of the whole release is in [`docs/mvp-checklist.md`](../mvp-checklist.md); its harness walk-through has not been completed for Hermes.

## Known refusals and limits

These are the limits that apply to Hermes today. Unlike the Claude Code and Codex guides, none of them was measured with Hermes.

- **Harness chat requests are refused under `support-email` and `strict` for Claude Code and Codex; Hermes has not been measured.** The measured cause is that the name model flags a harness's own static text (instructions, environment context) as person names, and the profile's rule for uncertain text is to block. Hermes sends its own system prompt and tool descriptions, and nothing says they avoid this. If you route Hermes's Chat with the shipped configuration (`[proxy] profile` empty, so the default `support-email` profile applies), expect that Hermes may stop answering. See [Known limits at sign-off](../mvp-checklist.md#known-limits-at-sign-off) and [Configuration](../configuration.md#proxy) for `proxy.profile`. If Hermes stops answering after Connect, see [Troubleshooting](#troubleshooting).
- **Images and other attachments are replaced by a placeholder and are not inspected.** By default (`proxy.binary = "placeholder"`) an image, document, audio, or file part is removed and a fixed text stands in its place, so Hermes's model cannot read a screenshot you attach. There is no OCR. A tool result that contains an attachment is withheld whole. Setting `proxy.binary = "forward"` sends attachments with no detection on them. See [Configuration](../configuration.md#proxy).
- **Request headers pass by an allowlist, and Hermes's headers were never recorded.** The proxy forwards only the request header names it lists for each upstream (`openai` or `anthropic` for Hermes), and checks the value of most against a shape. An unlisted header, or a value that fails its shape, is dropped, and the drop is counted in the daemon log by a closed label (never the name or value). The `harness_record` test, which runs an installed harness once directly and once through the proxy and reports any dropped header, exists for Claude Code and Codex only. Nothing re-checks Hermes after an upgrade. If Hermes needs a header the list does not know, name it in `[proxy.upstreams.openai] extra_headers` (or `anthropic`); that forwards the header unchanged, with no value check. See the privacy note on `extra_headers` in [Configuration](../configuration.md#proxy), and the request-header item in the threat model's [known limitations](../threat-model.md#known-limitations).
- **Files has no protection.** Hermes has no confirmed setting that restricts its reads to the mirror. The mirror exists, and Hermes can read your real folders as before. The gateway is the control that applies to what Hermes reads through MCP.
- **There is no tool-result hook** (see [Why there is no hook](#why-there-is-no-hook)).
- **Local paths and the login name in harness text pass unless a detector catches them.** They are ordinary text, so they are tokenized only when a detector finds the name in them.

## The command-line equivalent

```bash
inumaki connect status hermes
inumaki connect apply hermes                    # MCP, and Chat for an API-key login (routed by default here)
inumaki connect apply hermes --no-chat          # leave the chat route alone (what the app does by default)
inumaki connect apply hermes --protect NAME     # also put the MCP server NAME behind the gateway
inumaki connect revert hermes [--keep-backup]
```

`--no-files` and `--no-hook` have nothing to skip for Hermes, and `--chatgpt` is for Codex. Unlike the app, `apply` still routes chat by default, and prints a warning on stderr when it writes the route ("Hermes Agent sends chat through inumaki at the latest from its next session; whether the support-email or strict profile refuses its chat requests is not measured."); **use `--no-chat` unless you want chat routed.** `apply` needs a running daemon. Chat is only written while the proxy reports that it is running, read at the moment of the apply; if it is not, `apply` skips the route and says so (an explicit `--chat` fails instead). Every file is checked before the first write, so a refusal changes nothing; it prints the lines to add by hand, which contain the gateway token and client header value, so do not paste them anywhere shared. Reference: [`inumaki connect`](../cli.md#connect).

## Revert

Revert (the connection page's button, or `inumaki connect revert hermes`) revokes the harness's gateway tokens first (the app records the revocation instead when the service is stopped, see below), then restores your file from the backup:

- `config.yaml` is copied whole before Connect, so if nothing else touched it, it comes back byte for byte. If something did, inumaki removes the keys it added and restores the previous values of the ones it replaced (including your earlier `model.provider`), and leaves any key you changed since, counting it.
- A protected server's original entry returns, with the secrets it held.
- If you edited `providers.inumaki` after Connect, for example to point it at the real provider, Revert reports a conflict and keeps the table, client header included. Nothing flags the header. Remove the table by hand.
- In the app, Revert works with the service stopped: it restores your file and records that this harness's gateway token is to be revoked, and the service revokes it before it serves anything at its next start (or within a minute, if it turns out to be running). While the service is stopped the token opens nothing, because nothing listens for it, but it is not revoked until then ([Gateway tokens in harness files](../threat-model.md#gateway-tokens-in-harness-files)). The app says so in the note after the Revert. `inumaki connect revert` still needs the running service: without it, nothing is reverted.
- Lines you added by hand for a subscription login are not touched.

## Troubleshooting

- **"The configuration was changed outside inumaki. Reconnect to restore it."** Something edited a key inumaki owns, for example Hermes or an agent rewriting `config.yaml`. Press **Reconnect** on the connection page; it is always offered while the harness is connected, and it is the primary button when a path is broken or the harness is disconnected. From a terminal, run `inumaki connect revert hermes`, then `inumaki connect apply hermes --no-chat` (a plain `apply` does not revert first; it adds a new backup on top of the active one). Either way a new gateway token is issued.
- **Connect refuses and prints lines to add by hand.** The editor does not edit flow-style sections, anchors, aliases, merge keys, or multi-document files. Add the lines by hand, or rewrite that part of the file in block style and connect again.
- **Chat shows "Off, your choice" with "The selected model provider has no inumaki route".** Your `model.provider` is not `openai` or `anthropic`, or the matching key name is not in `$HERMES_HOME/.env`. inumaki will not guess. Hermes goes direct for that provider.
- **Chat shows "needs one line you add" for a subscription login.** Chat is not filtered until you add the base-URL setting by hand; see the note under [Chat](#chat).
- **Hermes stopped answering after you switched Chat on (or after a command-line `apply` without `--no-chat`).** A profile refusal is the likely cause (see [Known refusals and limits](#known-refusals-and-limits)). Run `inumaki connect revert hermes`, then `inumaki connect apply hermes --no-chat`. Chat is the only part that can stop Hermes answering; the gateway entries do not.
- **The inumaki proxy stopped, or another process took port 8787, after Connect.** Hermes then sends its conversation, and its credentials, to whatever listens there. The route is checked once, at apply time. Revert, or restart the proxy. See [Revert and drift](../threat-model.md#revert-and-drift).
- **Chat is on but the page says "No traffic seen yet."** No request has been recognised as Hermes since the daemon started; see [Chat](#chat).
