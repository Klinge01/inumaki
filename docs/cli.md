# inumaki CLI guide

`inumaki` is the command line tool for the engine and the `inumakid` service. This guide covers everyday use: which command to reach for, what the profiles detect, how to find out why something was blocked, and how to connect an agent through the MCP gateway. `inumaki --help` and `inumaki <command> --help` list every flag.

Global flags work with every command: `--config FILE` (a TOML config laid over the embedded default, so a partial file is enough; see [a partial file is enough](configuration.md#a-partial-file-is-enough); `eval` and `bench` ignore `inumaki.toml` unless `--config` is given, so their results stay reproducible; without the flag the daemon and the daemon commands read `<data_dir>/inumaki.toml` if it exists, else the embedded default, and `eval` and the local `bench` always use the embedded default unless `--config` is given; see [Configuration](configuration.md#finding-and-loading-the-file)), `--profile NAME`, `--models-dir DIR`, `--data-dir DIR`, `--socket PATH`. Commands that talk to the daemon find its socket through `--socket`, else `[daemon] socket` in the config, else `inumakid.sock` in the data directory. On macOS a Unix socket path must stay under 104 bytes; with a long data directory, set `[daemon] socket` to a shorter path.

Exit codes: `0` success, `2` usage or runtime error (the message is on stderr), `3` blocked or unresolved (`sanitize`, `rehydrate --strict`, `inspect`), `4` an eval regression against `--baseline`, `5` an eval target missed, `6` a mailbox check failed (`dataset add-mailbox`, `check-mailbox`).

## tokenize vs sanitize

| | `inumaki tokenize FILE` | `inumaki sanitize --dataset ID FILE` / `--session ID` |
|---|---|---|
| Runs | in process, loads the models itself | through the running daemon |
| Mappings | discarded when the command exits | kept in the dataset's encrypted vault namespace, or in an in-memory session |
| Restorable with `rehydrate` | no | yes |
| Typical use | a quick look at what gets replaced | anything whose output you want to restore later |

`FILE` is a path or `-` for stdin. Both print the sanitized text on stdout. When verification blocks the text, nothing is printed on stdout, stderr names the kinds and checks, and the exit code is 3.

`inumaki tokenize --map FILE` also prints the token → original mapping to stderr. That is a deliberate plaintext diagnostic for your terminal; it is not covered by the rule that originals never reach logs. Do not redirect it into files you share.

```console
$ echo "Sarah Leitner, IBAN AT61 1904 3002 3457 3201" | inumaki --profile offline tokenize --map -
Sarah Leitner, IBAN <IBAN_dcc4>
<IBAN_dcc4> => AT61 1904 3002 3457 3201
```

(The `offline` profile has no name model, so the name stays; see the next section.)

## Profiles

Profiles are defined in `configs/default.toml`. A dataset has one profile, chosen when it is created (`inumaki dataset add ID --name NAME --profile P`); `dataset upstream add` creates a missing dataset with `strict`.

| Profile | Detection | Verifier re-scan | Models |
|---|---|---|---|
| `offline` | regex with checksums, secrets, domain rules, dictionaries, the DACH street-address patterns | regex, leak check | none |
| `fast` | + token classifier | regex, leak check | mbert-ner-hrl |
| `support-email` (default) | + GLiNER | + token classifier (names only) | both |
| `strict` | as `support-email`, lower thresholds; cities, postal codes, organizations, URLs, and dates are tokenized | as `support-email` | both |
| `thorough` | + GLiNER | + GLiNER with a lower threshold and broader labels (names and addresses) | gliner-x-small |

`offline-strict`, `fast-strict`, `strict`, and `thorough-strict` are also the retry profiles: when verification fails, the text is processed once more with the retry profile over the same detected spans, and blocked if it still fails.

**Offline limits.** `offline` detects names only after a greeting, sign-off, or honorific (`Hallo Sarah`, `LG Sarah`, `Frau Leitner`; the anchor detector) and their other mentions in the same text, and addresses only through the street-address patterns, plus whatever a dictionary lists (`[dictionary] persons`, `addresses`, `organizations`). Any other name in running text passes through in clear. Use it without models only when your identifiers are structured (IBANs, emails, customer numbers) or listed.

**Model profiles and short text.** The model profiles can flag ordinary words in short texts as possible names at low confidence. Such a span is escalated and the text is blocked, which also blocks tool descriptions in gateway listings (see "Recovering from a blocked read").

**Custom kinds.** Entity kinds you name yourself, in `[[domain.labels]]` and other config tables, in a gateway contract's `{"identifier": "KIND"}`, or in a redactions file, must match `[A-Z][A-Z_]{0,31}`: letters and underscores, no digits (kinds in the TOML config are upper-cased first, so `kunden_nr` becomes `KUNDEN_NR`). `KUNDEN_NR` works; `KUNDEN_NR2` is refused.

`support-email` and `strict` each have a `<name>-metadata` profile (it declares `metadata_of = "<name>"`) that the gateway uses for listing prose — tool, prompt, and template descriptions, schema prose, enum values. It extends its base directly and may not weaken it: the same action for the default and every kind, no raised threshold or dropped escalation band on a kind that is blocked or removed, the same verifier NER, `on_uncertain`, and language, `allow_no_ner` not turned on, no raised combination threshold, its verifier retrying only into itself or into whatever the base already retries into, and the sanitizer NER kept or dropped; configuration loading refuses anything else. A metadata profile cannot be a dataset's profile or `[daemon] default_profile` and is not listed by `status` or `doctor`. `offline`, `offline-strict`, `fast`, `fast-strict`, `thorough`, and `thorough-strict` have none. To see why a description is refused, run `inumaki inspect --dataset ID --profile strict-metadata FILE` on it. A profile you add can have its own metadata profile: one profile with `metadata_of` naming it that `extends` it directly.

## The daemon and datasets

```bash
inumaki daemon                                   # foreground; or run target/release/inumakid
inumaki dataset add mail --name "Support mailbox" [--profile P] [--rotation-days 30] [--grace-days 7]
inumaki dataset list
inumaki dataset rotate mail                      # close the current epoch now
inumaki dataset remove mail                      # delete the dataset and all its tokens
inumaki status                                   # models, profiles, datasets, cache, gateway
```

## Strict restoration

`inumaki rehydrate --dataset ID FILE` (or `--session ID`) replaces every token it knows with its original. By default an unknown token or a `<KIND_REMOVED>` marker stays in place, stderr counts it (`unknown tokens: 1`), and the exit code is 0.

`--strict` fails instead: any placeholder that cannot be restored (unknown, expired, from another dataset, or a removed-value marker) prints nothing on stdout, reports counts on stderr, and exits 3.

```console
$ echo 'Hello <PERSON_abcdef>' | inumaki rehydrate --strict --dataset mail -
unresolved tokens: unknown=1 removed=0
$ echo $?
3
```

A session that does not exist or has expired is never created by `rehydrate`. It answers `context_unavailable` in both modes:

```console
$ echo 'Hello <PERSON_abcd>' | inumaki rehydrate --strict --session nosuch -
error: context_unavailable: the session context is missing or expired; nothing was restored
```

The gateway always restores strictly.

## Expiry

- **Datasets** rotate: every `rotation_days` (default 30) the current epoch closes and the same entity gets a new token when next seen. A closed epoch's tokens stay restorable for `grace_days` (default 7), then its rows are deleted. `inumaki dataset add` prints both settings, `inumaki doctor` and `inumaki inspect` show them, and `inumaki dataset list` shows when the current epoch started.
- **Sessions** live in memory and expire after `[daemon] session_ttl` of inactivity (default `15m`), or when the daemon stops.
- **Vault keys.** Dataset originals are encrypted with keys held in the OS secret store or the key file next to `vault.sqlite` (see `docs/runbook.md`, "Where the keys are"). Losing the keys makes every dataset token unrestorable; there is no recovery path.

## doctor

`inumaki doctor [--dataset ID]` asks the daemon for read-only diagnostics. It never prints originals or key material.

| Line | Meaning |
|---|---|
| `socket: ok (PATH)` | the CLI reached the daemon |
| `vault: keys from SOURCE, integrity ok\|FAILED` | where the vault keys come from (`keyring` or `file`) and SQLite's integrity check |
| `model NAME ok\|missing\|corrupt` | model files present and matching the pinned hashes |
| `profile NAME available\|unavailable unqualified` | whether the profile's models are loaded; `unqualified` until a profile passes the M4 quality gates |
| `dataset ID profile P rotation Nd grace Nd` | per dataset |
| `upstream NAME KIND contract ready\|none\|invalid secrets yes\|no` | per wrapped server: whether its contract parses and whether secrets are stored for it |
| `gateway: N tokens at ADDRESS` | bearer tokens and the TCP listener |
| `next: …` | fixed next steps, below |

The next steps come from a fixed list:

- the vault failed its integrity check: stop the daemon and restore from a copy taken while the daemon was stopped (see `docs/runbook.md`);
- `model NAME is missing|corrupt`: run `inumaki models pull`;
- no profile is qualified against the M4 quality gates yet: treat every `Pass` as reduced exposure, not a guarantee;
- `upstream NAME of dataset ID has an invalid content policy`: fix the file and add the upstream again;
- no gateway tokens: run `inumaki gateway token new LABEL` before connecting an agent over TCP.

## inspect and redactions

`inumaki inspect --dataset ID [--redactions FILE] [--show-values] FILE` shows what `sanitize` would do with a text, without doing it: detected spans with offsets, kinds, actions, and sources, the verifier's reasons for a block, known limitations, and the dataset's expiry settings. It runs through the control socket only, never sends anything anywhere, and never creates mappings: new tokens it needs for the preview live in a temporary overlay that is dropped afterwards. It exits 3 when the text would be blocked.

By default it prints metadata only. `--show-values` adds the candidate text and original excerpts; it is refused unless stdout is a terminal, and its output is labeled `local diagnostic output — not approved for transmission`. Like `tokenize --map`, it is a deliberate plaintext output.

A **redactions file** marks spans that must be transformed even though no detector found them:

```json
{
  "input_sha256": "<SHA-256, lower-case hex, of the NFC-normalized input>",
  "spans": [ { "start": 14, "end": 23, "kind": "ORGANIZATION", "action": "tokenize" } ]
}
```

Offsets are bytes into the NFC-normalized input, `end` exclusive; spans must not overlap and must fall on character boundaries. `action` is `tokenize` or `remove` (a `remove` leaves a `<KIND_REMOVED>` marker that is never restored). The digest ties the file to one exact text: if the input changes, the file is refused before anything is transformed (`bad_request: redactions: input digest does not match`, exit 2), so stale offsets can never land on the wrong words.

Redactions only add coverage and strengthen actions. They never weaken a policy block and never mark text safe: the verifier still runs, and a text that fails it stays blocked.

Worked example. The organization is left in clear by the profile, but in this business it names a family:

```console
$ printf 'Resi from the Gruberhof called about the invoice.\n' > note.txt
$ inumaki inspect --dataset mail note.txt
local diagnostic output — not approved for transmission
outcome pass  profile support-email  replacements 2
START    END      KIND             ACTION     SOURCE
0 4 PERSON           tokenize   Ner
14 23 ORGANIZATION     preserve   Ner
limitation: Pass means the configured checks passed; it is not proof that no identifying information remains
expiry: rotation every 30 days, grace 7 days, current epoch since 1790552451
$ shasum -a 256 note.txt
9b2fccaa59105f0feca6e951d2fb556c9893e09dcb7b1a3dcdaff7244455882b  note.txt
$ cat > red.json <<'EOF'
{"input_sha256":"9b2fccaa59105f0feca6e951d2fb556c9893e09dcb7b1a3dcdaff7244455882b",
 "spans":[{"start":14,"end":23,"kind":"ORGANIZATION","action":"tokenize"}]}
EOF
$ inumaki inspect --dataset mail --redactions red.json note.txt | grep ORGANIZATION
14 23 ORGANIZATION     tokenize   Redaction
$ inumaki sanitize --dataset mail --redactions red.json note.txt
<PERSON_d7d486> from the <ORGANIZATION_7d7c31> called about the invoice.
```

`shasum` hashes the bytes as they are; for text that is not already NFC-normalized (some decomposed accents), normalize it first. `sanitize` with the same file mints the tokens for real; `inspect` never does.

## Recovering from a blocked read

When a gateway call comes back as `blocked by inumaki (kinds: …; checks: …)`, or a listing fails with `unsupported_content`, nothing from that result reached the agent. To get the read through:

1. Read the block: the kinds and checks in the error, and `inumaki activity --dataset ID` for the verdict and counts.
2. Get the source text locally (run the wrapped server's tool outside inumaki, or copy the text from its own UI) and run `inumaki inspect --dataset ID FILE` on it to see which span or check caused the block.
3. Fix the cause: add a name the model misses to the dataset's dictionary, add or correct a field rule in the upstream's contract (then `inumaki dataset upstream remove` and `add` again with the new file), or add a redactions file when you sanitize the text yourself. A blocked description in a listing cannot be redacted; the dataset's profile decides it.
4. If the upstream's schema changed (`inumaki status` shows its contract as `drift`), review the contract against the new schema and run `inumaki dataset upstream accept-schema ID NAME`.
5. Restart the daemon if you changed its configuration or dictionaries, then repeat the read. A changed configuration invalidates cached verdicts, so the read is processed fresh.

inumaki does not keep blocked payloads and never repeats a call on its own: a tool with side effects runs only when the agent calls it again.

## Gateway commands

```bash
inumaki dataset upstream add DATASET NAME [--content-policy FILE] [--env K=V] [--cwd DIR] \
    [--secret-env KEY] [--secret-env-file FILE] --stdio PROGRAM [ARGS…]
inumaki dataset upstream add DATASET NAME --http URL [--content-policy FILE] [--header K=V] \
    [--secret-header NAME] [--secret-headers-file FILE]
inumaki dataset upstream list DATASET
inumaki dataset upstream remove DATASET NAME             # also deletes its secrets
inumaki dataset upstream accept-schema DATASET NAME [--fingerprint sha256:<64 hex>]
inumaki gateway token new LABEL                          # prints the token once
inumaki gateway token list
inumaki gateway token revoke ID
```

- **`--stdio` comes last.** Every word after `--stdio` is the child's command line, including words that look like flags of `inumaki` (`-y`, `--content-policy`, even `--`). A flag typed after it is silently passed to the child. Put every other flag first.
- **Secrets never go on the command line.** `--secret-env KEY` and `--secret-header NAME` prompt for the value without echo; `--secret-env-file` and `--secret-headers-file` read a JSON object of strings from a file that must not be readable or writable by group or others (`chmod 600`). Secret values are sealed in the vault and merged into the child's environment or the HTTP headers only when the upstream starts. `--env` and `--header` are for non-secret values (they are stored in clear in the vault and returned by the upstreams API); a `--header` or `--env` whose name looks like a credential (`Authorization`, `Cookie`, `Proxy-Authorization`, or a name containing `token`, `secret`, `key`, `password`, `passwd`, `credential`, `auth`, or `api`, in any case) is refused before anything is sent, with a pointer to `--secret-header` or `--secret-env`. A stdio upstream does not inherit the daemon's proxy or CA settings (`HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, …); pass the ones it needs with `--env`.
- **Contracts.** Without `--content-policy`, text results work and structured content is rejected. See `docs/architecture.md` (Gateway, contracts and fingerprints) for the rules and `docs/examples/scripted-upstream.policy.json` for an example.
- **accept-schema** records a new schema fingerprint after you have checked the contract still fits. Without `--fingerprint` it takes the one the running upstream reports (`inumaki status --json`, `schema_fingerprint`).
- **Tokens** authorize any local process that holds one; the daemon stores only a keyed hash. Revocation takes effect on the next request.

`inumaki status` ends with one connect line per dataset:

```
connect: server inumaki-3f9a0c1d2e4b5a6f at http://127.0.0.1:8789/mcp/demo with header "Authorization: Bearer <token from inumaki gateway token new>"; or run: inumaki connect apply HARNESS
```

The line names the server, its URL and the header; it does not run or prescribe a harness command. `inumaki connect apply HARNESS` registers the server for you (see the `connect` section below). The server name is `inumaki-` plus the dataset's opaque label (the `label` field of `inumaki status --json` and `GET /v1/datasets`), not the dataset id. The harness shows the server name to the model: Claude Code prefixes it to every tool name (`mcp__inumaki-3f9a0c1d2e4b5a6f__lookup`), so a server named after the dataset id would put that id, often a customer name, into every request. If you pick your own server name, never use a customer or person name.

For a harness that only speaks stdio, `inumaki-mcp DATASET [--socket PATH] [--data-dir DIR]` is an MCP server on stdio that relays to the daemon over the control socket (no bearer token; the socket's file mode is the authorization): `claude mcp add inumaki-<label> -- inumaki-mcp demo` (the same label as above).

## The model-API proxy (`[proxy]`)

`inumakid` serves the model-API proxy on `127.0.0.1:8787` by default (architecture: `docs/architecture.md`, limits: `docs/threat-model.md`). It has no command of its own: `GET /v1/proxy` on the control socket reports its state, and `inumaki connect` writes its base URLs into harness configuration. Streaming (`"stream": true`) is served on every route, and `/codex` is served. `inumaki connect apply` writes the chat route by default; `--no-chat` skips it. The default is one constant, `CHAT_ROUTE_DEFAULT` in `inumaki-adapters`, which `connect apply` reads. The desktop app does not follow it for Claude Code: there, Chat is a separate switch that is off until you turn it on (see `docs/harness-adapters.md`, CC-CHAT).

Routes: `/anthropic` (`POST /v1/messages`, `POST /v1/messages/count_tokens`, `GET /v1/models`, `GET /v1/models/{id}`), `/openai` (`POST /v1/responses`, `POST /v1/chat/completions`, `GET /v1/models`, `GET /v1/models/{id}`), and `/codex` (`POST /responses`, `GET /models`). Any other path answers `404 not_served` and is never forwarded. Harness credentials (API keys, OAuth tokens) pass through to the provider unchanged and are never stored or logged.

The `[proxy]` table of the daemon configuration holds the proxy's settings, and `[proxy.upstreams.<id>]` overrides a provider's base URL and lists extra forwarded headers. Restart the daemon after changing them. Every key, its type and default, the privacy notes for `binary`, `uncertain`, `definitions_account_values`, `base_url`, and `extra_headers`, the memory budget, and the fact that a misspelled key directly under `[proxy]` is not reported are in the [configuration reference](configuration.md#proxy).

```toml
[proxy]
max_inflight = 8                      # a small machine: fewer concurrent bodies
tripwire = "block"

[proxy.upstreams.anthropic]
base_url = "https://api.anthropic.com"
extra_headers = ["x-gateway-key"]     # forwarded to this upstream only, unchecked
```

**`inumaki status`** prints two proxy lines when the daemon serves `GET /v1/proxy`. The first:

```
proxy running 127.0.0.1:8787  sessions 2  cache hits 7 misses 3  anthropic ok 1, openai idle 0, openai-codex idle 0  codex-chatgpt unverified
```

It shows the state (`running`, `disabled`, or `bind_failed`, which means not listening), the listen address the daemon reports, live sessions, the incremental cache's hits and misses, each upstream route with its state (`ok`, `idle`, `failing`) and request count, and whether this build has verified the Codex ChatGPT login. The client header value is never printed.

The second line shows where request time went, from the `timing` and `static_cache` objects of `GET /v1/proxy` (the figures below show the format only):

```
proxy timing  last 30ms (local 10ms: engine 6ms, closure 1ms, scan 2ms, queue 1ms; provider 20ms, first byte 5ms)  p50 local 10ms provider 20ms  p95 local 10ms  static cache hits 1 misses 1 clears 0
```

`last` is the latest request's total time; in parentheses come its local time and the local stages (`engine` is detection, policy, sanitizing and verification; `closure` is the leak closure; `scan` is the rest of the request-side work; `queue` is the wait for a worker thread), then the provider's time and its time to the first byte. `p50` and `p95` are taken over the last 64 requests. The three counters belong to the static-prompt cache (`[proxy] static_cache`, see [Configuration](configuration.md#proxy)). Every duration carries an `ms` suffix, and `-` stands for a value that is `null`, such as the provider's time for a refused request that was never forwarded. When no request has been timed since the daemon started, or the daemon does not report timing, the line is `proxy timing  no requests yet`. Stages not on this line (`read_ms`, `project_ms`, `restore_ms`) are in the status body and in the daemon's `proxy served` and `proxy stream timing` log lines.

### Measuring the proxy (`bench --via-proxy`)

```bash
inumaki bench --via-proxy [--profile P] [--seed N] [--wire messages|responses|codex]
```

Drives an in-process proxy with the scripted model upstream. There is no daemon, vault, or dataset, so it measures the proxy's own detection and pipeline cost; the mails are synthetic and no value is printed. The conversation has a 20 KB system prompt and a synthetic history of about 100 000 tokens; then 50 turns of about 500 new tokens each, then 20 streamed turns. `--wire` picks the request format: `messages` (Anthropic Messages, the default), `responses` (OpenAI Responses with Codex-style input items: messages, reasoning, function and local shell calls with their outputs), or `codex` (the same body on the `/codex` route). The output:

- a header line with the wire, the profile, the history size, `(harness text)` when the system prompt is the harness text, and whether the mails were transformed;
- `cold first turn`: the first request, which scans the whole history (`refused (451)` when it is refused); with `INUMAKI_BENCH_SESSIONS=2`, also `cold first turn (session 2)`;
- an indented `proxy timing   total … local … read … queue … scan … engine … closure … project … first_byte … provider … restore … (ms)` after each cold-turn line: that turn's timing split from the in-process proxy's newest sample, in milliseconds, `-` for `first_byte` and `provider` when the request was not forwarded;
- `added per turn (n)  p50 … p95 …`: the proxy's wall time minus the scripted upstream's own time;
- `refused turns`, the first refused turn, and the first refusal's message (entity kinds and check ids only);
- `incremental cache  hits … misses …` over the 50 turns (compare misses between wires: repeated strings inflate the Responses hits);
- `first restored byte`: p50 and p95 over the streamed turns, from sending the request to the first non-empty restored text delta, minus the scripted upstream's time. A streamed turn that is refused, or that carries no restored text, is counted as refused or errored.

`--profile` defaults to `support-email`, which refuses the long synthetic history, so the bare command exits `3`; use `--profile offline` for a run that measures the pipeline. It exits `3` when no turn was served. `--via-proxy` conflicts with `--via-daemon` and `--dataset`, and `--wire` needs `--via-proxy`. `INUMAKI_BENCH_MAILS=N` sets the number of history mails, and `INUMAKI_BENCH_TRANSFORMS=1` applies the generator's noise transforms. `INUMAKI_BENCH_SYSTEM=harness` replaces the mail-text system prompt with a fixed 20 KB coding-agent instruction text, the same bytes in every session; unset or empty keeps the mail text, and any other value is an error. `INUMAKI_BENCH_SESSIONS=2` adds, after session 1, one cold turn in a fresh session with the same system text and one new mail; the default is `1`, and any value other than `1` or `2` is an error. The bench's requests carry a client header, so they use the static-prompt cache. With both knobs set, session 1 pays the full model time and session 2's cold turn can hit the cache; what the cache saves is session 2's cold turn compared with a build without it; the A/B in `docs/quality/2026-10-12-timing-and-prompt-cache.md` measured it: with the cache, session 2's cold turn costs about 10 to 13 % of what it costs without it on the `support-email` and `fast` profiles (426.8 and 418.3 ms against 3935.2 and 3133.1 ms for `support-email` `codex`), on a shared machine. The numbers are measurements, not gates.

The cold turn is what a user pays on the first request of a long conversation after a daemon restart or a session expiry: the incremental cache lives in memory, so the whole history is scanned again, which can take seconds; later turns pay only for the new text. The Responses and `/codex` wire carries about 2.5 to 2.9 times as many strings as Messages for the same text, so it costs more per turn and on the cold scan. The reference figures, experimental and due to be re-measured, are from 2026-10-05 (`offline`, Messages, release build, about 100 000 tokens of untransformed synthetic mail): cold first turn about 3.4 s, added per turn p50 52.9 ms and p95 70.4 ms, against the integration spec's target of p50 < 80 ms. At `support-email` the long synthetic history is refused (`451`); see `docs/mvp-checklist.md` ("Known limits at sign-off").

## connect

`inumaki connect` connects an agent harness (Claude Code, Codex, Hermes Agent, OpenClaw) to inumaki by editing its configuration files, and undoes it. It is the terminal front of `inumaki-adapters`; the harness's own files are edited by this command and never by the daemon. What each harness gets, and the verified versions, are in `docs/harness-adapters.md`.

```bash
inumaki connect status [HARNESS]
inumaki connect apply HARNESS [--protect NAME]... [--no-hook] [--chat | --no-chat] [--no-files] [--chatgpt]
inumaki connect revert HARNESS [--keep-backup]
```

`HARNESS` is `claude-code`, `codex`, `hermes`, or `openclaw`. `connect` finds the daemon like every daemon command (`--socket`, `--data-dir`, `--config`) and needs `HOME` to be set. The change takes effect in the harness's next session.

**`status [HARNESS]`** prints, for each detected harness (all of them when `HARNESS` is omitted; a harness that is not installed or configured prints nothing), its id (with ` (untested version)` when its version is outside the range the adapters were recorded against), then one line each for the `Mcp`, `Files`, and `Chat` paths and one for the hook. A path is `not connected`, `connected (k of n protected)` or `connected`, `unverified: <reason>`, `not supported: <reason>`, or `broken: <reason>`, with a fixed English sentence as the reason. A hook is `not installed`, `installed`, `pending: <reason>` (Codex until you trust the hook in `/hooks`), `not supported: <reason>`, or `broken: <reason>`. Status reads the command registered in the harness file: the hook is broken when the program it names is missing or cannot be run, and broken with "Reconnect to update it" when it names another program or socket than the running inumaki uses (for example after the binaries moved); run `apply` again. Under a path that needs lines added by hand (Hermes with a subscription login, OpenClaw's Docker bind outside the workspace roots), status also prints `add by hand:` with those lines and a `note:` sentence; they are the one place status prints a path or a local URL (the lines go to your terminal, never to a log). Otherwise the output holds counts and fixed sentences only, and it never prints a server name, token, or header value. It exits `0`.

**`apply HARNESS`** needs a running daemon and an installed or configured harness. It backs up the files it will change, then rewrites them:

- Every MCP server already pointing at the gateway gets the new token, and the datasets of mailboxes get entries named `inumaki-mail`, `inumaki-mail-2`, and so on.
- `--protect NAME` (repeatable) puts the unprotected server `NAME` behind the gateway: its definition becomes an upstream of a dataset `mcp-<name>` (one dataset per identical definition), credential-looking environment and header values move into the vault, and the harness entry is replaced by a gateway entry of the same name. All names are validated before anything is created. A name that does not exist or is already protected is refused, and so is a server whose entry has `"auth": "oauth"` or an `oauth` key, of any transport (it needs the MCP OAuth flow). If servers of the same name exist in more than one scope (a Claude Code user-scope entry and a local-scope entry of a project), `--protect NAME` protects the first one that is not already behind the gateway, user scope first; the other stays unprotected (the Claude Code hook still covers it). The upstream's `PATH` is the one of the `inumaki` process, so run the command from your login shell. Secrets that are not split by name (a secret inside an argument or a URL) are listed in `docs/threat-model.md`.
- Files: the mirror root is added to the harness (Claude Code `permissions.additionalDirectories`, Codex writable roots for each connected outbox, OpenClaw's Docker bind where its sandbox allows it); `--no-files` skips it.
- Chat (the default): the base URL points at the proxy's route for the harness, with the client header where the harness can send one. `--no-chat` leaves the chat path alone; `--chat` is the default spelled out, and `--chat` and `--no-chat` together are an error. For Claude Code the route goes into the user-level `settings.json`, which every open Claude Code window reads at once, so use `--no-chat` if you do not want that; the apply prints a warning when it writes the route. Codex with a ChatGPT login is routed only with `--chatgpt` (it conflicts with `--no-chat`); that route stays unverified until it has been run against the real Codex client (a user-gated step of plan M8-3, not yet done).
- Hook (Claude Code and Codex only): `PostToolUse` runs `<bin>/inumaki-hook <harness> --socket <socket>`; `--no-hook` skips it. `<bin>` is `bin_dir` from `GET /v1/service`, else the directory of the `inumaki` executable.
- When the apply writes at least one gateway entry, a new gateway token with the label `app:<harness>` is minted last, and the harness's older tokens of that label are revoked after a successful write. With no gateway entry, no token is minted and none is revoked. If revoking an older token fails after the `connected …` line was printed, the files are written but the command exits `2`; run `apply` again.

On success it prints `connected <harness> (backup <id>); the change takes effect in the next session` and exits `0`. A setting of the harness's own that keeps part of the connect from working, or a consequence of what the apply installs, is reported after that line as `warning: <fixed sentence>` on stderr; the exit code stays `0`. When the apply installs the hook (Claude Code and Codex, unless `--no-hook`), the warning is "While inumaki is stopped, tool output in every connected session is blocked. Start the service to recover; Revert also needs it running." The hook fails closed, so while the service is stopped every hooked tool result is blocked; see [The hook while the service is stopped](threat-model.md#the-hook-while-the-service-is-stopped). When the apply writes Claude Code's chat route, the warning says that every open Claude Code window, in every project, now sends chat through inumaki, and that with the `support-email` or `strict` profile its chat requests are refused today. And Codex with `approval_policy = "never"` in its `config.toml` refuses the inumaki tool calls, and the warning says to set `default_tools_approval_mode` on the inumaki server entry (inumaki never sets it for you; once you have set it on the entry, the warning is not shown, and every later `apply` keeps your value; see `docs/harness-adapters.md` CX-MCP). The warning names no path and no value from the file. A failure exits `2` with the reason on stderr, and there are two cases:

- **Refused edit.** A file does not parse, or uses syntax the editor cannot keep. Every file is checked before the first write, so nothing is written. The lines to add by hand are printed on stdout. They contain the minted gateway token and the client header value so that you can paste them; they are not logged. That token stays valid until `inumaki connect revert HARNESS` or a new `apply`.
- **Error while writing.** A file kept changing while inumaki edited it, or an I/O error. No lines are printed, and the token this apply minted is revoked. Files written before the failure (for a two-file harness, the first file) stay written, and the new backup covers them: run `inumaki connect revert HARNESS` to undo them, or fix the cause and run `apply` again.

**`revert HARNESS`** revokes every gateway token labelled `app:<harness>` first, then restores the files from the harness's active backup. Files unchanged since `apply` are restored byte for byte; otherwise inumaki removes the keys it added and restores the previous values of the ones it replaced, and a key you changed since is left alone and counted. `~/.claude.json` is restored by value, not by bytes (no copy of it is kept). It prints `reverted <harness>: N file(s) restored exactly, M key by key, K key(s) left as you changed them`, deletes the backup unless `--keep-backup` is given, and exits `0`.

- For Codex, revert also removes the trust record that Codex wrote for inumaki's hook (the `[hooks.state."…"]` table at that hook's exact position in `config.toml`), and nothing else in `hooks.state`. If that removal fails, the files are still restored, the command exits `0`, and it prints `warning: Codex's trust record for inumaki's hook could not be removed; remove it in Codex's /hooks.` Codex's own other state, such as its usage counters, stays.
- Revert needs the daemon, because the token revocation comes first. If it cannot be reached, nothing is reverted and the exit code is `2`: start the service and run it again. (The app's Revert works with the service stopped; see [Gateway tokens in harness files](threat-model.md#gateway-tokens-in-harness-files).)
- With no backup (an `apply` that was refused on its first try leaves none), it changes no file, revokes the harness's tokens, prints `<harness> has no inumaki backup, so no files were changed; its inumaki gateway tokens are revoked`, and exits `0`.
- If backups exist but none of their manifests can be read (a damaged `manifest.json`), it revokes the tokens, changes no file, and exits `2` with a message that the backup cannot be read. The harness files may still point at inumaki and hold the client header: check the backups under `<data_dir>/adapters/backups/<harness>/`, or remove inumaki's entries by hand.
- If the Claude Code client header (`X-Inumaki-Client`, in `env.ANTHROPIC_CUSTOM_HEADERS` of `settings.json`) could not be removed, the report is still printed, then the command exits `2` with a message to delete that line by hand. The header would otherwise be sent to your model provider.

Exit codes: `0` success, `2` any failure above or a usage error (the message is on stderr).

## activity

`inumaki activity [--dataset ID] [--since SECONDS] [--limit N] [--json] [--verify]` lists gateway events, newest first: age, dataset, front door, direction, verdict, the tripwire marker, entity kinds with counts, and checks. Never values, tokens, tool names, or arguments. Records written by the tool-result hook show which kinds were found; their count is always 1 per kind.

```
 12s ago  crm            gateway   result     released     PERSON×2 IBAN×1
 40s ago  crm            gateway   arguments  released     CLEAR VALUE  PERSON×1  checks: ClearValue
  3m ago  crm            gateway   result     blocked      PERSON×1  checks: Leak
```

**CLEAR VALUE** means the model wrote an identifier in clear into a tool argument instead of a token: either a value this dataset has already tokenized (a full name, for example), or a validated identifier (IBAN, card number, national id, email, IP address, URL), whether or not the dataset has seen it before. Kinds the dataset's profile preserves (for example URLs under most profiles) are not counted. The model got that value some other way: an unrouted chat, an unwrapped tool, or the user typing it. With the default `[gateway] tripwire = "notify"` the call still goes to the upstream and is only recorded; with `tripwire = "block"` it is refused with `privacy_block` before anything is sent. A name the dataset has never seen passes unflagged.

`--verify` recomputes the record chain and answers `activity chain ok: N records`, or fails when a kept record was edited or removed. Records older than `[gateway] activity_retention_days` (default 30) are swept.

## journal

```bash
inumaki journal list --dataset ID [--since SECONDS] [--limit N] [--json]
inumaki journal show --dataset ID RECORD [--show-values] [--json]
```

`list` shows journal entries newest first: record id, age, byte count, and the first 16 hex digits of the release digest that links the entry to its activity record. `show` prints one entry, labeled `released payload as sent (tokens)` by default or, with `--show-values`, `originals revealed locally — not for transmission`; the flag is refused unless stdout is a terminal, before the daemon is contacted. The payload is exactly what the agent received: if a detector missed something, it is in there in clear, because it already left; the journal only gives you a local copy to notice the miss, dictionary it, or `forget` it.

A `show` after a `forget` or a rotation reports `unresolved placeholders: N (forgotten, expired, or removed values are left in place)`; this is expected — the journal entry predates the change and its tokens no longer resolve.

## entities and forget

```bash
inumaki dataset entities ID [--show-values] [--limit N] [--json]
inumaki dataset forget ID --token TOKEN
inumaki dataset forget ID --value
```

`entities` lists what a dataset knows: `TOKEN`, `KIND`, `FIRST`/`LAST` use (age), `USES (store)`, and `EPOCH` (`*` marks a closed, grace-period epoch). `USES (store)` counts store-level uses — a mint plus every database hit — and is a lower bound: a working-set hit inside one namespace lock does not add a database write on the request path, so it is not counted. `--show-values` adds an `ORIGINAL` column and, like `journal show --show-values`, is refused unless stdout is a terminal.

`forget` removes one entity: its mapping rows in every epoch, its known-entity automaton entry, and the dataset's cached results, so a cached verdict that carried the old token is never served again. `--token TOKEN` targets a token from `entities`; `--value` takes no argument — it always prompts for the original without echo and resolves it through the HMAC index. If you type a value after `--value` anyway (`inumaki dataset forget ID --value "Sarah Leitner"`), clap rejects the flag for taking no argument and echoes the value back in its usage error, on your own terminal. Always use the prompt. This is a third deliberate plaintext path, alongside `tokenize --map` and `inspect --show-values`: the value is typed unechoed and held zeroized in the CLI, but it does cross the control socket in the forget request's body, to the same-user daemon, over the same socket every other command uses.

Forget deletes; it does not un-send. The provider already has whatever tokens it received for that entity, and a journal entry written before the forget still carries the old token — `journal show` reports it as unresolved afterwards. The next mention of the forgotten entity mints a fresh token, unlinked from the old one.

## Name linking and surface forms (`[linking]`, `[tokens] surface_form`)

After detection, a bare first name or surname (`LG Sarah`, `Herr Leitner`) is linked to the one person of the same text, or of an earlier block of the same batch, who has that name part. It gets a surface token of that person, `<PERSON_a7f2c9_3e>`: the model can see it is the same person, and it restores to its own text (`Sarah`, not `Sarah Leitner`). A part shared by two people in scope, or found with nobody in scope, gets its own token. Matching is exact after normalization (case, accents, `ä/ö/ü` written `ae/oe/ue`), never fuzzy.

```toml
[tokens]
surface_form = "derived"            # "independent": unrelated tokens, the model cannot see the link

[linking]
enabled = true
window_minutes = 30                 # how far back the two flags below may look
surnames_across_requests = false
first_names_across_requests = false
anchors = true                      # names after greetings, sign-offs, honorifics
```

`surnames_across_requests` and `first_names_across_requests` are **opt-in; they link bare names to the wrong person at the measured rates.** With either on, a bare name also links to a person the dataset saw in an earlier request within `window_minutes`, and in the labeled sequence corpus (`inumaki eval --sequences`, 2026-10-09, both `support-email` and `strict`) a single stale candidate was usually somebody else:

| Flag on | Wrong links (steps naming a different person) | Right links (steps naming the same person) |
|---|---|---|
| `surnames_across_requests` | `SurnameRecentOther`: 4 of 4 links wrong (34 steps) | `SurnameRecentSame`: 4 links (23 steps) |
| `first_names_across_requests` | `BareRecentOther`: 21 of 21 links wrong (25 steps) | `BareRecentSame`: 13 links (23 steps) |

With both off (the default) the same corpus has 0 wrong links. A wrong link never restores a wrong name (each mention restores to its own text), but the model treats two people as one. Details: `docs/quality/2026-10-09-4a-summary.md`.

## Measuring speed and quality

`inumaki bench --profile support-email` measures end-to-end latency on generated mails with an in-process engine. `bench --via-daemon` sends the same mails through the running daemon (cold and warm cache). With `--dataset ID` the generated identities are minted into that dataset's namespace for real and stay there; unlike the default temporary dataset it is not cleaned up, so use a throwaway dataset id. `eval` (next section) measures recall and leak rates.

## eval

```bash
inumaki eval --profile support-email [--held-out] [--baseline FILE] [--targets FILE] [--report-json FILE]
inumaki eval --profile strict --via-service            # through the daemon's sanitize path, one persistent dataset
inumaki eval --profile strict --sequences --targets crates/inumaki-eval/targets/sequence.toml
inumaki eval --profile strict --track tool-json --via-service
```

`eval` measures recall, leak and block rates, verifier error rates, link quality, and latency on the built-in cases plus 2 000 generated mails (seed 42), or on the 200-document held-out corpus with `--held-out`. `--baseline` exits 4 on a regression against a committed baseline, `--targets` exits 5 when an absolute target is missed. `--via-service` sanitizes through the same `sanitize_blocks` path the daemon serves, in a temporary data directory with one dataset for the whole corpus, so release-check blocks and cache hits count. `--sequences` runs labeled persistent-dataset sequences (repeated first names, restarts, a rotation, cache repeats, grace expiry; implies `--via-service`); `--sequence-steps N` (default 300) and `--sequence-seed S` (default 777) change their length and seed. `--track tool-json` evaluates MCP-shaped tool results instead of mail. `--cases-only` runs only the hand-written safety cases. `--outcomes PATH` (mail track only) writes one line per document, `id outcome` (`pass`, `uncertain`, `blocked`, with `+residue` when the released text still holds a gold value), for a per-case comparison with `scripts/harness-corpus/name-shape-outcomes.sh --compare`. `--origin {free,harness-static,file-name}` (with `--corpus` on the mail track, not with `--via-service`) evaluates the corpus as text of that origin: system-prompt text, or file and directory name stems as the folder mirror scans them; any origin other than `free` refuses `--baseline` and `--write-baseline` (baselines are measured on free text; use `--targets`), and the report's corpus family carries the origin (`file+file-name`). Reports never contain text, only counts, rates, and provenance.

## alias groups

A `persons.txt` line may list variants of one person separated by `|`, full name first:

```
Hans-Peter Gruber | HP Gruber | Hansi
```

Only persons files are split on `|`; an address or organization line that contains `|` is taken as one name whole (company names can legitimately contain `|`). Groups for those kinds, or any kind, use `[[dictionary.aliases]]` instead:

```toml
[[dictionary.aliases]]
kind = "ORGANIZATION"
names = ["Acme GmbH", "ACME"]
```

List the full name first: the first-listed name is the group's canonical entity. Every variant is a surface token of it (`<PERSON_a7f2c9_3e>`) and restores to its own text, so the model sees one person and each mention comes back as it was written.

Variants are exact after normalization, never fuzzy: `Hans Peter Gruber` is not a variant of `Hans-Peter Gruber`. A mention that extends a variant, such as an NER span `Hansi Gruber`, is a different phrase and mints its own token.

Add aliases before first use: rows minted while a variant was unknown hold the variant and stay a separate entity; the daemon logs their count when it opens the dataset, and `inumaki dataset forget ID --token <that token>` removes them so the next mention joins the group.

A name listed in two groups of the same kind, or both as a plain dictionary line and inside a group of that kind, is a configuration error. The collision is scoped to the kind: the same name under another kind is a different entity, and both may list it (a `PERSON` group naming "Acme" does not collide with an `ORGANIZATION` line for "Acme").

## Folder commands

A folder dataset keeps a sanitized copy of a directory (the **mirror**) under the mirror root, `~/Inumaki Mirror/<label>/` by default, and turns files an agent writes into the mirror's `outbox/` back into real names in a destination folder you own. Agents read the mirror instead of the source. All of these go through the daemon's control socket and print paths to your terminal only. Settings are in `[mirror]` in `configs/default.toml`.

```bash
inumaki folder add akten --name "Case files" --source ~/Documents/Cases
inumaki folder add akten --name "Case files" --source ~/Cases --outbox-destination ~/Cases-restored --profile support-email
inumaki folder list
inumaki folder status akten
inumaki folder rescan akten
inumaki folder remove akten
inumaki folder remove akten --dataset
```

- **`folder add ID --name NAME --source DIR`** creates the dataset (kind `folder`, the daemon's default profile unless `--profile`) and connects the directory, then prints the mirror and outbox paths. The restored files go to `--outbox-destination`, by default a directory under `~/Inumaki Outbox/`. If connecting is refused, the new dataset is not kept and the command can be run again. The source may not be your home directory, may not hold or sit inside the mirror root or the data directory, and may not overlap another folder's source; a symlink is resolved once, when you add the folder.
- **`folder list`** prints the mirror root, then each folder's state (`scanning`, `watching`, `pending`, `stopped`, `failed`), its error class if any, and the counts of mirrored, blocked, unsupported, and pending files. Error classes (`source_missing`, `source_not_permitted`, `outbox_unwritable`, and others) are explained in `docs/runbook.md`. `pending` is not an error: the folder's first read has waited more than 2 s, usually for a macOS privacy prompt; answer the prompt.
- **`folder status ID`** prints the folder's connection details as JSON: label, source, mirror, outbox, outbox destination.
- **`folder rescan ID`** re-checks every file now, retries blocked, unreadable, and pending files, and prints the number of files queued.
- **`folder remove ID`** disconnects the folder and deletes its mirror. The source and the outbox destination are never touched. With `--dataset` the dataset and its tokens are deleted too. If a file job is still running after 5 s (typically a first read waiting for a macOS privacy prompt), the daemon answers `the folder is busy; try again in a moment` and the command exits `2`; the folder stays stopped until you run the command again, which finishes the removal.

Only an allow-list of formats is mirrored as text (plain text and Markdown, YAML, CSV and TSV, JSON and JSON Lines, `.eml` and `.html` as Markdown); every other file gets a placeholder named `<name>.inumaki-unsupported.txt` or `<name>.inumaki-blocked.txt` that says why and nothing more. A file is released only whole: if any part of it is blocked or uncertain, none of it is mirrored. Files larger than `[mirror] max_file_bytes` (1 MiB by default) get a placeholder. A file the agent writes into `outbox/` with a placeholder inumaki cannot restore is not saved; a note `<name>.inumaki-unresolved.txt` next to it gives counts only.

After a daemon restart, every connected folder is checked and re-mirrored once when a value in the configuration file changed, even one that affects no output, when a dictionary file changed, or when the build changed (its version, its sanitizer generation, or the git revision recorded at build time). A comment, blank lines, or reordered keys do not re-mirror. See `docs/configuration.md` ("Finding and loading the file").

## Mailbox commands

*(As built, plan 3.)* A mailbox dataset gives an agent four tools to list folders, search, read, and draft a reply. It is draft-only: inumaki never sends mail, and there is no SMTP setting. See `docs/mail-providers.md` for which providers were verified (Gmail is unverified, Microsoft accounts need OAuth and do not work in this milestone).

```bash
inumaki dataset add-mailbox ID --preset gmail|outlook|generic --user LOGIN \
    [--imap-host HOST --imap-port PORT] [--imap-plaintext-loopback] \
    [--drafts-folder NAME] [--from-address ADDR] [--name NAME] [--profile P] \
    [--password-file FILE]
inumaki dataset check-mailbox ID
inumaki dataset remove-mailbox ID
```

- **`add-mailbox`** creates the dataset when it does not exist (kind `mailbox`, the daemon's default profile unless `--profile`), stores the password, installs the mail connector, and runs a check that prints `mailbox ok: N folders; drafts folder ...`. `--imap-host` and `--imap-port` are required for `generic` and override the preset otherwise. `--imap-plaintext-loopback` is for `127.0.0.1`, `::1`, and `localhost` only and is refused for any other host. Every flag the daemon would refuse is checked before anything is created.
- **The password** is never a flag. It is prompted without echo, or read from `--password-file`, which must not be readable by group or others (`chmod 600`; otherwise exit 2). It is not printed, logged, or echoed in any message.
- **`check-mailbox`** logs in, lists folders, and reports where drafts will go. A failure prints `mailbox check failed: <type>: <message>` and exits **6**; for a refused login the message is the preset's hint. The mailbox stays configured after a failed `add-mailbox` check, so you can fix the host or password and check again.
- **`remove-mailbox`** deletes the mailbox row, its password, and every handle; the dataset and its tokens stay.

### Recovering from a draft with unknown status

`draft_status_unknown` means the connection dropped after the draft was sent to the server, so inumaki cannot tell whether it was stored. Nothing is replayed automatically. Open your Drafts folder in the mail client: if the draft is there, use it; if it is not, ask the agent to draft the reply again.

### Stale handles

`context_unavailable` means the folder or message handle is unknown or stale. Ask the agent to search again. It happens after the mailbox is replaced or removed, after the server rebuilt the folder (its UIDVALIDITY changed), or when the handle was not used for `[mail] handle_retention_days` (default 30).

### `[mail]` settings

`keepalive = "5m"`, `command_timeout = "30s"`, `max_message_bytes = "4MiB"`, `snippet_chars = 200`, `handle_retention_days = 30`, `auth_retry_after = "60s"`. Restart the daemon after changing them.

### `inumaki mail-tasks`

```bash
inumaki mail-tasks --dataset ID --imap-host HOST --imap-port PORT --user LOGIN \
    --password-file FILE [--imap-plaintext-loopback] [--allow-remote] \
    [--drafts-folder Drafts] [--count N] [--seed S] [--family tuning|held-out] \
    [--report-json FILE] [--require-gate]
```

The scripted runner plays the agent against a **test** mailbox: it **wipes the INBOX and the drafts folder** of the `--user` account, seeds deterministic fixture mails (the same `--seed`, `--count`, and `--family` always give the same mailbox), searches, reads, and drafts a reply for each through the dataset's gateway, reads the Drafts folder back over IMAP, and checks every stored draft. Use a dedicated throwaway account. The runner refuses a non-loopback host without `--allow-remote`, a dataset whose mailbox has a different host, port, or login, and a drafts folder that is the INBOX or differs from the dataset's. Plaintext IMAP is allowed for loopback only, even with `--allow-remote`.

It prints a one-line summary and, with `--report-json`, a report with these keys (frozen, so later plans can rely on them): `dataset, seed, count, family, fixture_digest, provenance, tasks, completed, search_blocked, search_miss, read_blocked, read_residue, draft_failed, draft_missing, wrong_recipient, wrong_thread, wrong_restoration, unresolved_tokens, unresolved_token, privacy_block, mail_error, interventions, completion_rate, gate, per_task`. Every task has exactly one outcome and the outcome counters sum to `tasks`. `unresolved_token` (the gateway refused a call) and `unresolved_tokens` (a stored draft still holds a placeholder) are different things. `interventions` is always `null`. `gate` holds the 90 % target and whether the run met it; `--require-gate` exits 5 when it did not. The report holds counts, indices, and entity-kind labels, never mailbox text. Measuring the gate on the real profiles is the quality plan's work, not this command's claim: a run on a handful of fixtures with the `offline` profile is a smoke test, and a task can legitimately end as `privacy_block` when the verifier catches residue (for example a card number wrapped across two lines, which the sanitizer misses and the verifier blocks).

The gated GreenMail suite (`cargo test -p inumakid --features mail-tests --test mail_greenmail`, with `scripts/greenmail.sh start`) needs Docker; it passed once against GreenMail 2.1.14 on 2026-10-05 (see `docs/mail-providers.md`).

**Troubleshooting.** A date window that finds nothing on a real server: the `since` and `before` arguments of `mail_search` compare the message's received date (IMAP INTERNALDATE), not its `Date` header, so a mail imported today is found under today's date. The runner seeds each fixture with its own received date so its date windows are reproducible.
