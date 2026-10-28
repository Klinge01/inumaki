# Configuration reference

This is the reference for the configuration file of the daemon `inumakid`. It lists every table and key the daemon reads, the type, the default, what the key does, and what it means for privacy or latency where it matters. Defaults here come from the code that reads the file. The shipped file, `configs/default.toml`, is the starting point, but your file does not have to repeat it: `<data_dir>/inumaki.toml` (where the daemon and the CLI find it without a flag) is laid over the shipped file, so a file with only a `[mirror]` table is complete and every profile stays available ([how the two combine](#a-partial-file-is-enough)). The shipped file spells out the engine tables (tokens, linking, dictionaries, domain rules, models, profiles) and carries the `[proxy]` and `[mirror]` tables as commented-out blocks with their defaults. The daemon tables (`[daemon]`, `[vault]`, `[gateway]`, `[journal]`, `[mail]`) are not in it at all; a missing table means all of its defaults.

For what the commands do, see the [CLI guide](cli.md). For what the privacy boundary does and does not promise, see the [threat model](threat-model.md).

## Contents

- [Finding and loading the file](#finding-and-loading-the-file)
- [Mistakes the parser does not catch](#mistakes-the-parser-does-not-catch)
- [How errors are reported](#how-errors-are-reported)
- [Value formats](#value-formats)
- [`[daemon]`](#daemon)
- [`[vault]`](#vault)
- [`[gateway]`](#gateway)
- [`[journal]`](#journal)
- [`[mail]`](#mail)
- [`[proxy]`](#proxy)
- [Provider upstreams](#provider-upstreams)
- [`[mirror]`](#mirror)
- [`[tokens]`](#tokens)
- [`[linking]`](#linking)
- [`[dictionary]`](#dictionary)
- [`[domain]`](#domain)
- [`[ner]` and the model tables](#ner-and-the-model-tables)
- [Profiles](#profiles)

## Finding and loading the file

The daemon reads one TOML file, laid over the shipped default. There is no search path and no merge of several of your own files. The file is chosen in this order:

1. `--config PATH` (`inumakid --config PATH`, `inumaki daemon --config PATH`, or `--config` on any other `inumaki` command).
2. `<data_dir>/inumaki.toml`, when anything exists at that path.
3. The copy of `configs/default.toml` that is compiled into the binary. That is every default in this document, with no `[proxy]`, `[mirror]`, or daemon tables set.

### A partial file is enough

A file is laid over the shipped default, the copy of `configs/default.toml` compiled into the binary, when the daemon or any `inumaki` command loads it (`--config` or `<data_dir>/inumaki.toml`). You write only what you change. The rules:

- **A table the shipped file also has merges key by key**, down through nested tables. `[tokens]` with only `suffix_len = 6` changes that one key and keeps `open`, `close`, and `surface_form`. `[ner.gliner]` with only `threshold = 0.3` keeps the model and the labels.
- **A value or a list of plain values replaces the shipped one as a whole**, and so does a list the shipped file leaves empty: `[dictionary] persons`, `addresses`, and `organizations` are yours alone.
- **A list of tables the shipped file fills is extended, never replaced.** `[[domain.patterns]]` and `[[domain.labels]]` keep the shipped rules and add yours after them; a rule identical to a shipped one is not doubled. The `labels` of a model section (`[ner.gliner]`, `[ner.gliner_verifier]`, `[ner.token_classifier]`) are identified by their `label` text: an entry that restates a shipped `label` replaces that shipped entry in place, so you can raise or lower its `threshold` or change its `kind`; an entry with a new `label` text is added after the shipped ones. One added `[[domain.labels]]` therefore leaves the shipped customer, contract, and invoice rules in force, and a one-entry `[ner.gliner] labels` leaves `person` and the address labels in force. The residual: a shipped rule or label cannot be removed this way. Writing one `label` text twice in your own list is refused when the two entries differ in kind or effective threshold, naming `ner.<section>.labels[<n>].label`. An added entry only adds detection; to narrow one, restate it with the value you want. A whole edited copy of `configs/default.toml` loads with your edits for NER labels. An edited `[[domain.labels]]` or `[[domain.patterns]]` rule is not replaced: it is added beside the shipped rule, which stays in force (the safe direction).
- **Profiles merge like every other table, key by key.** `[profiles.offline]` with only `escalate_below = 0.4` changes that one setting and keeps the shipped `offline` entity rules (`SECRET = remove` among them) and verifier settings; the profiles that extend `offline` (`support-email`, `strict`, `fast`, ...) keep working on top of them. An entity entry merges too: `PERSON = { action = "tokenize" }` keeps the shipped `min_confidence` of `PERSON`. Entity kinds are matched in upper case: `person` in your file overrides the shipped `PERSON`, and a profile that spells one kind two ways (`person` and `PERSON`) is refused. To loosen a shipped rule you state it explicitly, in the key you mean (`IP_ADDRESS = { action = "preserve", min_confidence = 0.5 }`). `SECRET` is the exception: no profile may tokenize or preserve it (see [Every profile removes secrets](#every-profile-removes-secrets)), so `SECRET = { action = "tokenize", ... }` in `[profiles.offline.entities]` is refused, not merged. A profile with a new name is yours alone, and a key you leave out takes the default of its type. Since a shipped profile always merges, the only way to replace one whole is to copy it under a new name and point `default_profile` and the datasets at the copy.
- **Nothing the shipped file defines can be removed by leaving it out.** A profile, a rule inside a profile, or an entry of a shipped list of tables (see above) that you delete from a copy of the shipped file is back the next time the file is loaded. To stop using a profile, set `default_profile` and the datasets to another one; to change a rule, state its new value.
- **Tables the shipped file does not have** (`[daemon]`, `[vault]`, `[gateway]`, `[journal]`, `[mail]`, `[proxy]`, `[mirror]`) are read from your file only, each key with its own default when absent, as before.
- **A complete file is unchanged**: a copy of the shipped file overlays to itself (no list is doubled), apart from any shipped profile, rule, or list entry it leaves out, which comes back. Code that parses a whole configuration from text (`CoreConfig::from_toml`, the test and evaluation fixtures) does no overlay.
- **Errors are usually reported at your file's line; otherwise by a fixed message without one.** The file is checked on its own first, so a wrong type, an unknown daemon key, or an unknown top-level table is reported at the line where you wrote it. The check keeps only the first problem it finds in an engine table, so a second mistake behind a partly named section (`[ner.gliner] threshold`, say) can be reported as "missing or invalid value in the merged configuration", with no line. A value in an engine table that is wrong only after the merge (a threshold out of range, say) is reported by its key path, without a line; a missing key in an entry the shipped file does not have keeps the line of that entry.

- **A file that is there but unusable stops the start.** Only "no such file" falls back to the embedded default. A file with a syntax error, a wrong type, or an unknown key, a directory or a dangling symlink at `<data_dir>/inumaki.toml`, and a path the daemon is not allowed to inspect all fail the start with `config file <path>: …`. There is no silent fallback to the embedded default.
- **The data directory differs by platform**: `~/Library/Application Support/inumaki` on macOS, `$XDG_DATA_HOME/inumaki` (default `~/.local/share/inumaki`) on Linux. `--data-dir` and `INUMAKI_DATA_DIR` change it. So for the packaged services (the app's LaunchAgent, Homebrew's `brew services`, the `.deb` user unit), which start `inumakid` without `--config`, the file to create is `<data_dir>/inumaki.toml`. Restart the service after editing it.
- **`[daemon] socket` is followed by the programs that talk to the daemon.** The CLI, the app, the MCP shim (`inumaki-mcp`), and the tool-result hook all read the data directory's `inumaki.toml` and use its `[daemon] socket` (a relative value is relative to the data directory), else `inumakid.sock` there. `--socket` overrides it. If that file exists but cannot be read or parsed, the app shows an error naming the file and does not talk to a daemon, the MCP shim exits, and the hook blocks the tool result; none of them falls back to the default socket. An unknown key in `[daemon]` is refused by these clients as it is by the daemon. The app (tray red, "configuration error"), the MCP shim, and the hook read the file only when they start, so after changing `socket` restart the app and the daemon, and use Reconnect on each harness so the hook commands already written get the new `--socket`. A daemon started with `--config` pointing somewhere else is not followed by the app, the shim, or the hook, because they cannot know that file: give them `--socket` or keep the file in the data directory.
- The CLI reads the same file the daemon does, so `inumaki status` and the other daemon commands find the same socket. Two exceptions keep the embedded default unless you pass `--config`: `inumaki eval` and the local `inumaki bench` (without `--via-daemon`), because their baselines and targets are measured on the shipped configuration. `eval` and `bench` ignore `inumaki.toml` unless `--config` is given, so their results stay reproducible. `inumaki scan` and `inumaki tokenize` read only the engine tables ([`[tokens]`](#tokens), [`[linking]`](#linking), [`[dictionary]`](#dictionary), [`[domain]`](#domain), [`[ner]`](#ner-and-the-model-tables), [profiles](#profiles)), so a typo in a daemon table does not stop them; it does stop the daemon and every command that talks to it.
- **Where the active file came from.** `inumaki status`, `inumaki doctor`, and `GET /v1/status` report `config_source`: `embedded`, or the absolute path of the file. This is not the `provenance.config_source` of an eval report (`file` or `embedded`), which records whether that evaluation ran with a `--config` file; the two answer different questions.
- Relative paths inside the file are resolved against the file's own directory for the dictionary files and `[ner] models_dir`. Relative paths in `[daemon] socket` and `[vault] path` are resolved against the data directory instead.
- The data directory is `--data-dir`, else `INUMAKI_DATA_DIR`, else the platform directory above. The models directory is `--models-dir`, else `INUMAKI_MODELS_DIR`, else `[ner] models_dir`, else `<platform data dir>/inumaki/models`.
- The daemon reads the file once, at start. **Restart the daemon after every change.**
- A changed value changes the configuration fingerprint, and so does a value added, removed, or renamed, even one that affects no output (a `[gateway]` timeout, say), and stating a default of a daemon table explicitly that the file used to omit (a shipped engine value stated explicitly changes nothing, since it is merged either way). A comment, blank lines, the order of keys or tables, and the spelling of a value (`'a'` or `"a"`, `0.5` or `0.50`) do not. The fingerprint hashes the parsed values of the merged configuration (your file over the shipped default, so a changed shipped default changes it too, and a file that spells out a shipped value fingerprints as one that omits it), the bytes of every dictionary file with its category and position in the list, and the code revision: the inumaki version, the sanitizer generation (a number developers raise with every change that can change sanitized output), and the git revision the packaging scripts record at build time (`DaemonConfig::fingerprint`). It is part of every sanitization cache key. The daemon's cache and the proxy's cache live in memory and start empty at every start anyway; the folder mirror stores the fingerprint with each file, so after a change that moves it (or an upgrade to a new version) every connected folder is checked and re-mirrored once. The model files are not part of it. The mirror adds the model manifest compiled into the binary, so a build that pins other models re-mirrors, but the daemon checks only each model file's presence and size at load, not its hash. A different models directory (`--models-dir`, `INUMAKI_MODELS_DIR`, or a relative `[ner] models_dir` that now resolves elsewhere) or model files replaced in place with files of the same size do not re-mirror. A development build without a recorded git revision re-mirrors only when the version or the sanitizer generation changes.

## Mistakes the parser does not catch

**Release note: a daemon table with a typo now stops the daemon at start.** Before this release the daemon ignored an unknown key in `[daemon]`, `[vault]`, `[gateway]`, `[journal]`, `[mail]`, and `[proxy]`, and an unknown top-level table. A config file that carried such a typo started fine and the typo did nothing. It now fails the start with the table, the key, and the line. If a daemon fails to start after an upgrade, read the message and fix or remove the key.

Every daemon table refuses an unknown key: `[daemon]`, `[vault]`, `[gateway]`, `[journal]`, `[mail]`, `[proxy]`, `[mirror]`, and each `[proxy.upstreams.<id>]` (`anthropic`, `openai`, `openai-codex`). `[proxy.upstreams]` itself refuses any other id, so `[proxy.upstreams.openai_codex]` with an underscore is an error. A top-level table that is neither a daemon table nor one of the engine's tables (`tokens`, `dictionary`, `domain`, `profiles`, `ner`, `linking`) is refused as an unknown table, so `[deamon]` fails the start.

**The engine tables still ignore a key they do not know** (this is planned to change, not done): `[tokens]`, `[linking]`, `[dictionary]`, `[domain]`, `[ner]` and its model sections, and every `[profiles.*]` table. A typo there is not an error: the key is skipped and the default applies. The default is often the safe value, which hides the mistake; the reverse also happens. A misspelled `combination_threshold` leaves the stricter or looser default in force, and a misspelled table such as `[profiles.strict.verifer]` is ignored the same way. Two further cases to watch:

- An entity key under `[profiles.<name>.entities]` is not checked against the list of kinds. A misspelled kind (`PERSN`) is accepted and never matches anything, so that kind keeps the profile's default action. Spell kinds as in the table under [Profiles](#profiles).
- A value of the wrong type or an unknown value of an enumeration (`action = "tokenise"`) is an error, reported with a line number.

After any edit to the engine tables, check the spelling of your keys against the tables below, and check the effect: `inumaki status` shows the proxy state and its listen address, for example.

## How errors are reported

An invalid configuration stops the daemon at start. The message names the key path and never the value, because a value can be a path, a pattern, or a name.

- A value that is out of range or malformed is reported by key path: `proxy.max_inflight`, `vault.suffix_len`, `profiles.strict.entities.PERSON.min_confidence`, `domain.labels[0].value`, `ner.gliner.labels[2].kind`. The index is the position in the file's list, counted from zero.
- A TOML syntax error, a wrong type, or an unknown key or table is reported by position, never by the text of the line or the parser's own message (which can quote a value):
  - `toml parse error at line 12`
  - `proxy table: unknown key `binray` at line 40`, naming the table (`daemon`, `vault`, `gateway`, `journal`, `mail`, `proxy`, or `mirror`; an error in `[proxy.upstreams.<id>]` is reported as the `proxy` table);
  - `proxy table: invalid value at line 40` for a wrong type or an unknown enumeration value;
  - `unknown table `deamon` at line 3` for a top-level table the daemon does not know.

  A key or table name is printed only when it is a plain bare key (letters, digits, `_`, `-`, at most 64 characters). A quoted key prints as just `unknown key` or `unknown table`.
- Every error from a file is prefixed with the file: `config file /path/inumaki.toml: proxy table: unknown key `binray` at line 40`.
- A dictionary file that cannot be read is reported by its path; the contents are not printed.

## Value formats

| Kind | Accepted | Notes |
|---|---|---|
| Duration | `45s`, `15m`, `2h`, `1d`, or plain seconds (`30`) | No spaces between number and unit. A zero duration is refused where noted. `[mirror] debounce` also takes milliseconds (`500ms`). |
| Size, as a string | `1048576`, `512KiB`, `4MiB`, `1GiB` (binary), `10KB`, `64MB`, `2GB` (decimal) | `8MB` is 8,000,000 bytes; use `MiB` for the binary size. |
| Size, as a number | an integer count of bytes | Only `[daemon] cache_bytes`. |
| Listen address | `127.0.0.1:8787`, `[::1]:8787` | A loopback IP and a port. A host name or a non-loopback address is refused. |
| Confidence | a number from `0.0` to `1.0` | Outside that range is refused. |

## `[daemon]`

The daemon's own settings.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `daemon.socket` | path | `"inumakid.sock"` | The control socket. A relative path is relative to the data directory. `--socket` overrides it. The socket's file mode is the authorization for the control API. |
| `daemon.cache_bytes` | integer (bytes) | `67108864` (64 MiB) | Size of the sanitization cache, counted in bytes of sanitized text. A repeated block is served from the cache instead of being detected again, which is the main latency saving for repeated mail and files. Memory use grows with this value. Note that this one is a plain integer, unlike `proxy.cache_bytes`. |
| `daemon.session_ttl` | duration | `"15m"` | Idle time before a session context, and its token mappings, are destroyed. Not zero. A shorter value keeps mappings for less time; a session that expired cannot rehydrate its tokens. |
| `daemon.session_cap` | integer | `10000` | Most live session contexts; the least recently used goes first. Not zero. |
| `daemon.default_profile` | string | `"support-email"` | The profile used when a request names none and no dataset applies. It must exist and must not be a metadata profile. `proxy.profile` falls back to it. See [Profiles](#profiles). |
| `daemon.session_suffix_len` | integer | the value of `tokens.suffix_len` (`4`) | Length of the random part of a session token (`<PERSON_a7f2>`). From 4 to 12. It must differ from `vault.suffix_len`, so a token tells you at a glance whether it came from a session or from a dataset. |

## `[vault]`

The encrypted store for dataset token mappings.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `vault.path` | path | `"vault.sqlite"` | The SQLite file. A relative path is relative to the data directory. |
| `vault.key_source` | string | `"auto"` | Where the two vault keys live: `"keyring"` (the operating system's secret store), `"file"` (a file `vault.key` with mode 0600 in the data directory), or `"auto"`. `"auto"` follows what an existing vault recorded; on a first run it uses the secret store if one is reachable and otherwise writes the key file and logs one warning. Changing the source of an existing vault is refused, not migrated. See the privacy note below. |
| `vault.automaton_max_entries` | integer | `200000` | Cap on the number of known entities loaded into the in-memory matcher per dataset and epoch, most recently used first. Not zero. A stored entity beyond the cap keeps its mapping but is not matched by the vault's own known-entity detector, so the model-based detectors have to catch it again. |
| `vault.suffix_len` | integer | `6` | Length of the random part of a dataset token (`<PERSON_a7f2c9>`). From 4 to 12. It must differ from `daemon.session_suffix_len`. |

**Privacy note, `vault.key_source`.** With `"keyring"` the keys are separate from the data directory, so copying `vault.sqlite` without the secret store does not reveal any mapping. With `"file"`, the key file sits in the same directory as the vault: anyone who can read the data directory can read both. `"auto"` can end up on `"file"` without you choosing it, when no secret store is reachable (a headless server, for example); the daemon logs a warning when it does. If you need the keyring and want a failure instead of a fallback, set `"keyring"`.

## `[gateway]`

The MCP gateway: the local server that harnesses connect to for the sanitized tools, prompts, and resources of a dataset.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `gateway.listen` | string | `"127.0.0.1:8789"` | TCP address of the gateway. Loopback only; anything else is refused. |
| `gateway.upstream_restart_max_backoff` | duration | `"30s"` | Cap on the wait before a failed stdio upstream is restarted (1 s, 2 s, 4 s, and so on up to this). Not zero. |
| `gateway.upstream_call_timeout` | duration | `"60s"` | Time an upstream has to answer one call. Not zero. |
| `gateway.max_response_bytes` | size | `"4MiB"` | Largest upstream result accepted for sanitization; a larger one answers `resource_limit`. At least 64 KiB. |
| `gateway.max_inflight` | integer | `8` | Concurrent calls per dataset. Not zero. Each takes an inference slot, so this also bounds the CPU a dataset can use. |
| `gateway.queue_timeout` | duration | `"30s"` | How long a call waits for a free slot before `resource_limit`. Not zero. |
| `gateway.sanitize_descriptions` | boolean | not allowed | Obsolete. Any value, `true` or `false`, is a configuration error naming `gateway.sanitize_descriptions`. Sanitizing tool and prompt descriptions is mandatory and cannot be switched off. |
| `gateway.activity_retention_days` | integer | `30` | Days an activity record is kept. Not zero. Records hold kinds, checks, and counts, never text. |
| `gateway.tripwire` | string | `"notify"` | What happens when a model-written call argument contains a value the dataset knows in clear. `"notify"` records and counts it and the call goes ahead. `"block"` refuses the call with a `privacy_block` error. |
| `gateway.allowed_origins` | list of strings | `[]` | Browser origins allowed to reach the gateway, as `scheme://host[:port]`, lower case, no path, no wildcard, no default port (`http://localhost:80` is refused). Empty rejects every request that carries an `Origin` header. |

**Privacy note, `gateway.tripwire`.** A tripwire hit means the model wrote, in a call argument, a real value that inumaki knows and had replaced by a token. With `"notify"` that value is passed on to the tool the model is calling, which is a local tool but may be a remote service behind it. `"block"` stops it. Neither setting examines text the model did not write.

## `[journal]`

The egress journal: a local copy of every payload the gateway released, so you can notice an identifier the detectors missed.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `journal.enabled` | boolean | `true` | Store released payloads at all. `false` turns the journal off (activity records are unaffected). |
| `journal.retention` | duration | `"24h"` | How long an entry is kept. Global. Not zero. |
| `journal.max_bytes` | size | `"64MB"` | Byte budget per dataset; the oldest entries go first. At least 64 KiB. Note that `MB` is decimal. |

**Privacy note.** A journal entry is the payload exactly as it left. An identifier the detectors missed is in the journal in clear, because it already went to the provider. Entries are sealed with the vault key and are read over the control socket only. See the threat model for the full awareness note. The chat proxy writes only the blocks that missed its session cache.

## `[mail]`

The draft-only mail connector. See [mail providers](mail-providers.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `mail.keepalive` | duration | `"5m"` | IMAP NOOP interval while idle. At least 30 s. |
| `mail.command_timeout` | duration | `"30s"` | Timeout per IMAP command. Not zero. |
| `mail.max_message_bytes` | size | `"4MiB"` | Largest message the read tool fetches. At least 64 KiB. |
| `mail.snippet_chars` | integer | `200` | Length of a search snippet, in characters. From 40 to 2000. |
| `mail.handle_retention_days` | integer | `30` | Days an unused mail handle is kept. From 1 to 365. |
| `mail.auth_retry_after` | duration | `"60s"` | How long a refused login is remembered before the server is asked again. Not zero. |

## `[proxy]`

The model-API proxy. `inumakid` serves it on `127.0.0.1:8787` by default. It has no command of its own: `GET /v1/proxy` on the control socket reports its state, and `inumaki connect` writes its base URLs into a harness's configuration. The routes, the status line, and the benchmark are described in the [CLI guide](cli.md#the-model-api-proxy-proxy). Restart the daemon after changing this table.

Routes: `/anthropic` (`POST /v1/messages`, `POST /v1/messages/count_tokens`, `GET /v1/models`, `GET /v1/models/{id}`), `/openai` (`POST /v1/responses`, `POST /v1/chat/completions`, `GET /v1/models`, `GET /v1/models/{id}`), and `/codex` (`POST /responses`, `GET /models`). Any other path answers `404 not_served` and is never forwarded. Harness credentials pass through to the provider unchanged and are never stored or logged.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `proxy.enabled` | boolean | `true` | Whether the proxy listens at all. When `false`, or when the reserved `inumaki-chat` dataset cannot be created, `GET /v1/proxy` reports `state: "disabled"`. |
| `proxy.listen` | string | `"127.0.0.1:8787"` | TCP address, a loopback IP and a port. A host name or non-loopback address is refused at load, because the proxy carries every request body. If the listener cannot bind or stops serving, the daemon keeps running and reports `bind_failed`; the app and daemon then hand out no proxy URL. Whatever else holds that address receives a harness that is still pointed at it (see the chat-route note in the threat model). |
| `proxy.profile` | string | `""` | The sanitization profile for chat. Empty means `daemon.default_profile`. A metadata profile is refused. |
| `proxy.session_ttl` | duration | `"4h"` | Idle time before a session's token mappings are destroyed. Not zero. |
| `proxy.session_cap` | integer | `1000` | Most live sessions; the least recently used is evicted first. Not zero. |
| `proxy.cache_bytes` | size (string) | `"256MiB"` | Size of the incremental sanitization caches over all sessions. Not zero. A string with units, unlike `daemon.cache_bytes`. |
| `proxy.max_request_bytes` | size | `"8MiB"` | Largest request body after decompression; larger answers `413 resource_limit`. It also bounds the provider's answer the proxy reads and relays (`502 resource_limit` above it). |
| `proxy.max_inflight` | integer | `32` | Requests handled at once; more answer `503 resource_limit`. Not zero. |
| `proxy.upstream_timeout` | duration | `"600s"` | How long to wait for the provider to start answering; `504` after it. Not zero. |
| `proxy.binary` | string | `"placeholder"` | What happens to images, documents, files, audio, and video in a request. See the privacy note below. |
| `proxy.allow_binary` | boolean | unset | Deprecated alias. `true` means `binary = "forward"`; `false` changes nothing. Setting it together with `proxy.binary` is an error naming `proxy.allow_binary`. |
| `proxy.uncertain` | string | `"block"` | What the proxy does with a block the verifier is unsure about: `"block"` or `"pass"`. See the privacy note below. |
| `proxy.tripwire` | string | `"notify"` | `"notify"` records a known value the model wrote in its answer. `"block"` also refuses an answer whose tool-call arguments hold one (`451`). Visible text never blocks. |
| `proxy.harness_static_ner` | string | `"skip"` | Whether the name models read a harness's own leading prompt (the system and developer messages at the start of a request from a client that sent the install header). `"skip"` runs that text without them: the deterministic detectors, the dictionary and the verifier's other checks still run, and the models were reading capitalised words and skill names as people and refusing the request. `"scan"` lets the models read it, which restores the earlier behaviour and the static-prompt cache. See the privacy note below. |
| `proxy.allowed_origins` | list of strings | `[]` | Browser origins allowed to reach the proxy, in the form described for `gateway.allowed_origins`. Empty refuses every request that carries an `Origin` header. |
| `proxy.definitions_account_values` | string | `"allow"` | Whether the OS login name and home-directory name in a tool or schema definition refuse the request: `"allow"` or `"refuse"`. See the privacy note below. |
| `proxy.static_cache` | boolean | `true` | The static-prompt cache: the proxy reuses the NER models' output for a long system or developer text (2 KiB or more) when a new session sends the same bytes. Only requests with a valid client header (`X-Inumaki-Client`) use it; requests without it run the models. `false` turns it off. See the privacy note below. |

**Privacy note, `proxy.binary`.**

- `"placeholder"` (the default) removes each attachment and sends a fixed text part in its place (`[inumaki: an attachment (image, document, audio, or file) was removed here and not sent to the model.]`), so the session goes on and the model can tell you it did not get the attachment.
- `"refuse"` answers `400 unsupported_content` for a request that holds an attachment outside a tool result.
- `"forward"` sends the attachment **unchecked, with no detection on it.** The payload is not inspected, text inside an image or PDF is not detected, and the daemon logs one warning at start. No screen of the app turns it on.
- In `placeholder` and `refuse` modes, a tool result that holds an attachment is withheld whole and replaced by the tool-result placeholder; with `forward` it crosses unchecked like the rest. Nothing reads the text inside an attachment (there is no OCR), so inumaki makes no statement about what an attachment contained.

**Privacy note, `proxy.uncertain`.** "Uncertain" is a verifier verdict that is neither a pass nor a failure. `"block"` refuses user text (`451`) and replaces a tool result by the placeholder. `"pass"` sends the sanitized text anyway and marks the answer `X-Inumaki-Verdict: pass-uncertain`; whatever made the verifier unsure is then sent as the policy left it, which can be in clear. Text only reaches the pass-through if the profile also allows it: a profile with `verifier.on_uncertain = "block"` (every shipped profile) turns an uncertain result into a refusal before the proxy applies this key. Setting `"pass"` is a decision to trade recall for fewer interruptions.

**Privacy note, `proxy.definitions_account_values`.** Tool and schema definitions are scanned and not changed; a hit refuses the whole request (`400 unsupported_content`). The identity's full name and email always count as a hit. With `"allow"`, the OS login name and the home-directory name do not count in a definition (they are still tokenized in chat text), so a definition that contains them is sent to the provider. `"refuse"` adds them to the definition scan. `"refuse"` is recommended with the `strict` profile. This key is read by the daemon, not by the proxy library.

**Privacy note, `proxy.harness_static_ner`.** With `"skip"` (the default) an unknown name that stands in a harness's leading system or developer message is not found by the models and crosses in clear; the deterministic detectors, the dictionary, the secret scanner, the home-folder login check and your known values still apply to that text. The position rule decides what counts as leading, not the text, so a leading prompt that carries an instruction file or business data is covered too. Your own login stays in clear in a path, and a command-output header or Claude Code's attribution block is not judged (threat model (ee) to (gg)). User messages, tool results and later system messages are always read by the models. Choose `"scan"` if you put business data into the system prompt of a client that sends the install header; the harness's own text may then be refused (`451`), which is the reason for the default. With `"skip"` the static-prompt cache has nothing to serve and stays idle.

**Privacy note, `proxy.static_cache`.** A hit skips only the model inference on byte-identical text; dictionaries, the other detectors, the policy, minting with the new session's own tokens, every verifier check, and the closure run again, so what is sent is, by design, the same with the cache on or off, provided the models' inference is deterministic; a determinism test and a differential test over the eval corpora check this, and the residual if inference were not deterministic is in item (bb) of the threat model. The cache holds span offsets, kinds and scores under a keyed hash, no text, in memory only (at most 256 entries and 8 MiB). It is emptied by a daemon restart and whenever the dictionary of user datasets changes (a dataset added, removed, recreated, rotated, rebuilt, or learning an entity), so the first session after a start or such a change still pays the full model time. Because the cache is shared, a caller with the client header can tell by timing whether a given text was processed recently; the threat model's [known limitations](threat-model.md#known-limitations) describe this as item (bb).

**Memory.** A request body is buffered before it is scanned. Worst-case resident memory is `proxy.max_inflight` times up to twice `proxy.max_request_bytes` (the raw and the decoded body while a request is decoded), plus a fixed scan budget of about 1 GiB, plus `proxy.cache_bytes`. On the defaults that is 32 × 2 × 8 MiB (512 MiB) + 1 GiB + 256 MiB, so budget roughly 1.75 GiB for a proxy under full hostile load. Lower `proxy.max_inflight` and `proxy.max_request_bytes` on a small machine. The scan of an answer waits for budget for up to ten seconds or the upstream timeout, whichever is shorter; past that, the client gets `503 resource_limit` and the answer is lost although the request was sent, so a retry sends the message again. The threat model's [known limitations](threat-model.md#known-limitations) list this as the memory item.

Example, for a small machine that blocks tripwire hits:

```toml
[proxy]
max_inflight = 8
tripwire = "block"
```

## Provider upstreams

The table `proxy.upstreams.<id>` (written `[proxy.upstreams.<id>]` in the file) overrides one provider's endpoint. `<id>` is exactly one of `anthropic`, `openai`, or `openai-codex` (the upstream of `/codex`). Any other id, and any key in this table other than the two below, is refused at start.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `proxy.upstreams.<id>.base_url` | string | `anthropic`: `"https://api.anthropic.com"`; `openai`: `"https://api.openai.com"`; `openai-codex`: `"https://chatgpt.com/backend-api/codex"` | Replacement for the provider's base URL. `https`, or `http` on a loopback IP literal (`http://127.0.0.1:9999`, `http://[::1]:9999`; `http://localhost` is refused). No credentials, query, fragment, whitespace, or backslash. A trailing `/` is dropped. |
| `proxy.upstreams.<id>.extra_headers` | list of strings | `[]` | Request header names forwarded to this upstream unchanged, with no value check. See the privacy note below. |

For example, `proxy.upstreams.anthropic.base_url` and `proxy.upstreams.anthropic.extra_headers` set these for the Anthropic route:

```toml
[proxy.upstreams.anthropic]
base_url = "https://api.anthropic.com"
extra_headers = ["x-gateway-key"]     # forwarded to this upstream only, unchecked
```

**Privacy note, `base_url`.** The base URL decides where the sanitized request, and the harness's credentials, go. A base URL that points at another machine sends both there. That is the point of the setting (a gateway you operate), and also why only `https` is accepted for anything but loopback.

**Privacy note, `extra_headers`.** The proxy forwards request headers by a per-upstream allowlist of names and checks the value of every listed header except credentials against a shape (an id, a word, a list of words, a media type, a product-style `User-Agent`). An unlisted header, or a value that fails its shape, is dropped and counted in the log (`proxy dropped request headers`, by label, never by name or value). A name in `extra_headers` is forwarded unchanged, so **naming a header the proxy already lists lifts its value check.** The proxy cannot tell what such a header carries: if you list one that holds a path or a name, it leaves the machine as sent. Use the list for a gateway behind `base_url`, or for a header a new harness release needs before the built-in list is updated.

Rules for each name: 1 to 128 bytes of lowercase header-name characters (`a-z`, `0-9`, and ``! # $ % & ' * + - . ^ _ ` | ~``), at most 32 names per upstream, and not one of the names that are never forwarded: hop-by-hop headers, `host`, `content-length`, `content-encoding`, `accept-encoding`, every `x-inumaki-*`, and `x-codex-turn-metadata`. At request time, any header named by a `Connection` header is also never forwarded. A name that breaks a rule fails the load with `proxy.upstreams.<id>.extra_headers` and does not quote the value. The values are marked sensitive, so they stay out of debug output. See the request-header item in the threat model's [known limitations](threat-model.md#known-limitations).

## `[mirror]`

The folder mirror: a sanitized copy of connected directories, and an outbox that is restored on the way back. The commands are in the [CLI guide](cli.md#folder-commands). In the shipped file this table is commented out; every key is optional and the values below are the defaults. **This table refuses an unknown key.**

| Key | Type | Default | Meaning |
|---|---|---|---|
| `mirror.root` | path | `"~/Inumaki Mirror"` | The mirror root. Must be absolute; `~/` expands to the service user's home. It must be absent, empty, or a directory inumaki created (one that carries inumaki's root marker file); any other existing directory is refused as `mirror_unwritable` before anything is changed. The default differs from a checkout at `~/inumaki` even on macOS's case-insensitive file system (an earlier default, `~/Inumaki`, was the same directory as that checkout). An install that used the old default keeps its mirror by setting `root = "~/Inumaki"`. After changing `root`, Reconnect each harness so the paths Connect wrote are updated. It must not overlap `mirror.outbox_root`, and must not be inside the data directory. |
| `mirror.outbox_root` | path | `"~/Inumaki Outbox"` | Parent of the default outbox destinations, where restored files are written. Same path rules; it must not contain or sit inside `mirror.root`. |
| `mirror.debounce` | duration | `"500ms"` | Watcher debounce. Not zero, at most `10s`. |
| `mirror.max_file_bytes` | size | `"1MiB"` | Largest file mirrored or restored. Not zero, at most `16MiB`. A larger file gets a placeholder instead. |
| `mirror.workers` | integer | `1` | Worker threads, from 1 to 8. More workers mirror faster and use more CPU and memory. |
| `mirror.rescan_interval` | duration | `"1h"` | Period of the full reconcile that re-checks every file. Not zero. |

The roots are home paths and carry the user name, so error messages and debug output show counts only.

## `[tokens]`

The token format and how surface forms are tokenized. This is an engine table, so `inumaki scan` and `inumaki tokenize` read it too.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `tokens.suffix_len` | integer | `4` | Hex characters of the random part of a token, from 4 to 12. It is the default for `daemon.session_suffix_len`. Dataset tokens use `vault.suffix_len` instead. A longer suffix makes a token harder to guess and a collision rarer; it costs a few characters per token. |
| `tokens.open` | string | `"<"` | Opening delimiter of a token. |
| `tokens.close` | string | `">"` | Closing delimiter. A downstream consumer that treats `<...>` as markup may need other delimiters; rehydration looks for the configured pair. |
| `tokens.surface_form` | string | `"derived"` | How a later mention that differs from the entity's stored text is tokenized. `"derived"` shares the entity's suffix and adds a short surface component (`<PERSON_a7f2c9_3e>`), so the model can see the mentions are one entity. `"independent"` mints an unrelated token per spelling, so the model cannot see the link. |

## `[linking]`

Name linking: after detection, a bare first name or surname (`LG Sarah`, `Herr Leitner`) is linked to the one person of the same text, or of an earlier block of the same batch, who has that name part. Matching is exact after normalization, never fuzzy. A part shared by two people gets its own token.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `linking.enabled` | boolean | `true` | Run the linker after detection. |
| `linking.window_minutes` | integer | `30` | How far back the two cross-request flags may look, in minutes. At least 1. |
| `linking.surnames_across_requests` | boolean | `false` | Let a bare surname link to a person from an earlier request inside the window. See the note below. |
| `linking.first_names_across_requests` | boolean | `false` | Let a bare first name link to a person from an earlier request inside the window. See the note below. |
| `linking.anchors` | boolean | `true` | Add the anchor detector, which finds names after greetings, sign-offs, and honorifics. |

**Opt-in, and it links bare names to the wrong person at the measured rates.** On the labeled sequence corpus (`inumaki eval --sequences`, 2026-10-09), with `surnames_across_requests` on, 4 of 4 cross-request surname links to a different person with the same surname were wrong; with `first_names_across_requests` on, 21 of 21 cross-request first-name links to a person never seen in full were wrong. With both off, the same corpus has no wrong links. A wrong link never restores a wrong name (each mention restores to its own text), but the model treats two people as one. See the [4a quality summary](quality/2026-10-09-4a-summary.md).

## `[dictionary]`

Known business data as a high-confidence source: customers, employees, addresses, organizations. A match in a dictionary is detected at a high confidence and is not subject to a model's threshold. The files are plain text, one entry per line. Blank lines and lines starting with `#` are skipped. The bytes of every file, with its category and its position in the list, are part of the configuration fingerprint.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `dictionary.persons` | list of paths | `[]` | Files with one full person name per line. A line may list variants of one person separated by `\|`, the full name first (`Hans-Peter Gruber \| HP Gruber \| Hansi`); the others become surface forms of its token. |
| `dictionary.addresses` | list of paths | `[]` | Files with one street address per line, taken whole. |
| `dictionary.organizations` | list of paths | `[]` | Files with one organization name per line, taken whole. |
| `dictionary.aliases` | list of tables | `[]` | Alias groups declared in the file, for kinds other than persons. Each entry has `kind` and `names`. |
| `dictionary.aliases.kind` | string | required | The entity kind of the group (`PERSON`, `ORGANIZATION`, or a custom label). |
| `dictionary.aliases.names` | list of strings | required | Two or more spellings of one entity, the canonical one first. Matching is exact after normalization, never fuzzy. A name may appear in one group of a kind only; a collision is a configuration error. |

Example:

```toml
[dictionary]
persons = ["persons.txt"]
aliases = [{ kind = "ORGANIZATION", names = ["Acme GmbH", "Acme", "ACME Vertriebs GmbH"] }]
```

**Latency and recall.** A dictionary is the cheapest way to make a known name certain, and the only way to catch names in `offline` beyond the anchor detector. It does not find names that are not listed.

## `[domain]`

Business-specific recognizers. Two kinds of rule, both written as arrays of tables: `domain.patterns` (header `[[domain.patterns]]`) and `domain.labels` (header `[[domain.labels]]`). Both are optional; the shipped file has three label rules.

### `[[domain.patterns]]`

A regular expression that is itself the identifier, for example `K-[0-9]{6}`.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `domain.patterns.regex` | string | required | The expression, without anchors; word boundaries are added. A bad expression is reported as `domain.patterns[i].regex`. |
| `domain.patterns.kind` | string | required | The entity kind of a match. Upper-case letters and `_`, 1 to 32 characters. A custom name works. |
| `domain.patterns.confidence` | number | `0.95` | Confidence given to a match. |

### `[[domain.labels]]`

A label such as `Kundennummer:` followed by a value that starts within a window of characters. Label matching is case-insensitive with Unicode case folding, so one spelling per wording is enough.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `domain.labels.labels` | list of strings | required | The label texts. Entries that end in a letter or digit must not run into a longer word (`Invoice` does not match inside `Invoicing`). |
| `domain.labels.kind` | string | required | The entity kind of the value. |
| `domain.labels.value` | string | required | The expression the value must match. |
| `domain.labels.window` | integer | `40` | Characters after the label in which the value must start. The value itself may run past the window. |
| `domain.labels.confidence` | number | `0.92` | Confidence given to a match. |
| `domain.labels.require_digit` | boolean | `false` | Take only a value that holds at least one ASCII digit: the first such match that starts in the window (`V-12345678`, not `HTTP` after `Contract`). The three shipped rules set it, so an all-letter value after a shipped label is not detected by the label rule. |

The shipped rules cover `CUSTOMER_ID`, `CONTRACT_ID`, and `INVOICE_ID` in German and English wordings. Adding a custom kind needs no code, but unless a profile lists it under `entities`, it uses the profile's `default_action` (tokenize) and `default_min_confidence`.

## `[ner]` and the model tables

Name and address detection by small ONNX models. A profile that sets neither `ner_sanitizer` nor `ner_verifier` (or sets `"none"`) uses no model. The models are downloaded with `inumaki models pull`; no GPU is needed.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `ner.models_dir` | path | unset | Models directory, used when neither `--models-dir` nor `INUMAKI_MODELS_DIR` is set. A relative path is relative to the file. |
| `ner.threads` | integer | `0` | Intra-op threads per model. `0` selects the smaller of 4 and the CPU cores. |
| `ner.sessions` | integer | `1` | Independently loaded sessions per model, a pool. `1` means one request at a time per model. Raise it when `inumaki status` shows pool waits. Memory grows linearly with it. Not zero. |

Each model section is its own table. A profile selects them by name through `profiles.<name>.ner_sanitizer` and `profiles.<name>.ner_verifier`. If you write a section, you must set its three required keys.

| Section | Used for | Shipped model |
|---|---|---|
| `ner.gliner` | The sanitizer's detection (GLiNER, zero-shot labels) in `support-email`, `strict`, `thorough`. | `gliner-x-small` |
| `ner.gliner_verifier` | The verifier's independent re-scan in `thorough`: lower threshold, broader labels. | `gliner-x-small` |
| `ner.token_classifier` | Detection in `fast`; the verifier's re-scan in `support-email` and `strict`. | `mbert-ner-hrl` |
| `ner.kiji` | An optional PII model used for evaluation. Not in the shipped file and not a default. | `kiji-pii` |

| Key (every section) | Type | Default | Meaning |
|---|---|---|---|
| `ner.<section>.model` | string | required | The model name from the model manifest. Not empty. |
| `ner.<section>.threshold` | number | required | Default minimum score for labels that have none of their own. From 0 to 1. A lower threshold finds more (higher recall, more false positives). |
| `ner.<section>.labels` | list of tables | required | The labels given to the model and the entity kind each maps to. Not empty. Each entry has `label` (the text for the model, or the model's own type name such as `PER`), `kind` (an entity kind, upper-case letters and `_`), and an optional `threshold` that overrides the section's. A bad entry is reported as `ner.<section>.labels[i].kind` or `.threshold`. |

The calibration behind the shipped values is in the [calibration matrix](quality/2026-09-25-matrix.md): a GLiNER threshold of 0.5 measured better than 0.3 on the held-out corpus, and the person label set was widened instead. The token classifier's `LOC` label maps to a custom `LOCATION` kind, so as a verifier it catches missed names but not missed street addresses.

## Profiles

A profile is a named policy: what to do per entity kind, how sure the detectors must be, which models to use, and how the verifier behaves. A dataset has one profile, chosen when it is created. `daemon.default_profile` and `proxy.profile` name the profile for requests that have no dataset. Profiles live under `[profiles.<name>]`; a profile can inherit from another with `extends`, and it overrides only the keys it sets.

### The shipped profiles

| Profile | Extends | Detection | Verifier re-scan | Retries into |
|---|---|---|---|---|
| `offline` | none | Regex with checksums, secrets, domain rules, dictionaries, the DACH street patterns, and the anchor detector. No model. | Regex and leak check only (`allow_no_ner = true`). | `offline-strict` |
| `offline-strict` | `offline` | As `offline`; lower thresholds (0.4); cities, postal codes, organizations, URLs, and dates are tokenized. | As `offline`. | not set |
| `fast` | `offline` | Adds the token classifier. | Regex and leak check; no NER re-scan. | `fast-strict` |
| `fast-strict` | `fast` | As `fast`, retry thresholds as for `offline-strict`. | As `fast`. | not set |
| `support-email` | `offline` | Adds GLiNER. The default profile. | Adds the token classifier (names only). `allow_no_ner = false`. | `strict` |
| `strict` | `support-email` | As `support-email`, retry thresholds as for `offline-strict`. | As `support-email`. | not set |
| `thorough` | `support-email` | GLiNER. | GLiNER with a lower threshold and broader labels (names and addresses). A second GLiNER pass. | `thorough-strict` |
| `thorough-strict` | `thorough` | As `thorough`, retry thresholds as for `offline-strict`. | As `thorough`. | not set |
| `support-email-metadata` | `support-email` | See the metadata profiles below. | As `support-email`. | itself |
| `strict-metadata` | `strict` | See the metadata profiles below. | As `strict`. | itself |

**`offline` detects names only after a greeting, sign-off, or honorific** (`Hallo Sarah`, `LG Sarah`, `Frau Leitner`) and other mentions of them in the same text, plus whatever a dictionary lists. A name in running text that is in no dictionary passes through in clear. Use it without models only when your identifiers are structured (IBANs, emails, customer numbers) or listed.

A **retry profile** is used once when verification fails: the text is processed again with the retry profile over the same detected spans, and blocked if it still fails. A retry profile must name the same `ner_sanitizer` and `ner_verifier` as the profile that retries into it (a mismatch is refused at start), so `thorough` retries into `thorough-strict`, not `strict`. A retry profile must also keep every block of its primary: if the primary's `default_action` is `block`, or blocks a kind, the retry profile must block it too, or the load fails naming `profiles.<retry>.default_action` or `profiles.<retry>.entities.<KIND>.action`. A retry can only be stricter about blocks, never looser. The verifier is built once from the primary profile's `verifier` settings (`combination_threshold` and `allow_no_ner`); a retry profile's own `verifier` table is read only for `on_uncertain`.

**Metadata profiles.** A profile that sets `metadata_of = "<base>"` is the variant used to sanitize a dataset's discovery metadata (tool, prompt, and template prose, schema prose, enum values) instead of the base profile. The load refuses a metadata profile that is weaker than its base: a different action for the default or any kind, a raised threshold or dropped escalation band on a kind that is blocked or removed, a different verifier NER, language, or `on_uncertain`, `allow_no_ner` turned on, a raised combination threshold, a different sanitizer NER (it may only be kept or dropped), or a retry into a profile that is neither itself nor the base's retry. Two metadata profiles ship, one for `support-email` and one for `strict`. A metadata profile cannot be a dataset's or the daemon's profile. The other profiles have none, so a listing with a low-confidence span in its prose fails the whole listing there.

### Every profile removes secrets

A credential is removed and never restored. So after the overlay and `extends` are resolved, every profile, shipped or your own, must take `remove` or `block` for the `SECRET` kind (`block` refuses the whole text, which is stricter). `tokenize` and `preserve` are refused, and so is a profile that has no `SECRET` entry anywhere in its `extends` chain while its `default_action` is not `remove` or `block`. Its effective `min_confidence` for `SECRET` (the entry, else `default_min_confidence`) may not exceed 0.95, the fixed confidence of every secret-scanner span; above it a detected secret would escalate (sent unchanged) or be dropped, so such a profile is refused the same way. A profile that extends `offline` (or any profile that extends it) inherits `SECRET = remove` at 0.00 and needs no entry of its own. Kinds are matched in upper case, so `secret = ...` counts as `SECRET`. A configuration that breaks the rule does not load: the error names `profiles.<name>.entities.SECRET`, where `<name>` is the nearest profile in the chain that lists `SECRET`, or the profile itself when none does, and never a value. The check runs on every route into the engine configuration, a whole configuration parsed by `CoreConfig::from_toml` (tests, evaluation fixtures) included. A profile whose `extends` chain does not resolve (a missing parent or a cycle) is refused when it is used, as before.

### Profile keys

| Key | Type | Default | Meaning |
|---|---|---|---|
| `profiles.<name>.extends` | string | none | Parent profile. A cycle, or a name that does not exist, is refused. |
| `profiles.<name>.language` | string | `"auto"` | `"auto"`, `"de"`, or `"en"`. `"auto"` guesses per text from stop words; the other two force the hint passed to language-dependent detectors. |
| `profiles.<name>.default_action` | string | `"tokenize"` | The action for a kind that has no entry in `entities`. One of `tokenize`, `preserve`, `remove`, `block`, `escalate`. |
| `profiles.<name>.default_min_confidence` | number | `0.5` | The threshold for a kind that has no entry. |
| `profiles.<name>.escalate_below` | number | `0.5` | Below this confidence the detection is ignored and the span is sent unchanged, in clear. Between this and the kind's `min_confidence` it escalates. |
| `profiles.<name>.entities` | table | empty | Per-kind policies; see below. Entries merge with the parent's, per kind. |
| `profiles.<name>.entities.<KIND>.action` | string | required | What to do with a span of this kind that is at or above `min_confidence`. One of the five actions below. |
| `profiles.<name>.entities.<KIND>.min_confidence` | number | required | Minimum confidence for the action to apply. Both keys are required in an entry; an entry that sets only one is a parse error. A kind with no entry uses `default_action` and `default_min_confidence`. |
| `profiles.<name>.ner_sanitizer` | string | none | The model section used for detection: `gliner`, `gliner_verifier`, `token_classifier`, `kiji`, or `none`. The section must exist. |
| `profiles.<name>.ner_verifier` | string | none | The model section for the verifier's independent re-scan. Same values. It must differ from `ner_sanitizer` when both are set. |
| `profiles.<name>.metadata_of` | string | none | Marks this profile as the metadata variant of the named profile; see above. Read from the profile's own table only, never through `extends`. |
| `profiles.<name>.verifier.on_uncertain` | string | `"block"` | What to do when the verifier is unsure. See below. |
| `profiles.<name>.verifier.retry_profile` | string | none | The profile for the single retry after a failed verification. |
| `profiles.<name>.verifier.allow_no_ner` | boolean | `false` | Permit a profile with no verifier NER. Without it, a profile whose verifier has no NER section is refused when its engine is built, so running without the independent re-scan is always a deliberate choice. |
| `profiles.<name>.verifier.combination_threshold` | integer | `3` | Number of distinct preserved quasi-identifier kinds (city, postal code, organization, date, custom kinds) in one sentence that make the verdict uncertain. At least 2. A lower number is stricter. |

**Actions.**

- `tokenize` replaces the span with an opaque token and remembers the mapping.
- `preserve` leaves the text unchanged.
- `remove` replaces it with a `_REMOVED` marker and never restores it (used for secrets; every profile must `remove` or `block` `SECRET`).
- `block` refuses to send anything that contains it.
- `escalate` leaves the text unchanged but flags it for the verifier policy.

A span below `min_confidence` but at or above `escalate_below` is treated as `escalate`, which is how an uncertain name is held back; under `on_uncertain = "block"` an escalation refuses the text or triggers the retry, never a forward in clear. An organization span that looks like an identifier (no spaces and at least five digits, such as `K-482913`) is tokenized even where the profile would preserve it.

**Privacy note, `verifier.on_uncertain`.** The values are `"block"`, `"escalate"`, and `"pass"`. `"block"` (the default, and the value in every shipped profile) refuses the text. `"escalate"` and `"pass"` both send the text and flag it; an uncertain span is then forwarded as the policy left it, **which can be in clear**. The default is the one to keep unless you accept that trade. A metadata profile must keep its base's value.

**Retry profiles tokenize their uncertain band.** The retry profiles lower the thresholds to 0.4 and tokenize an uncertain name or street rather than forwarding it. One exception refuses: in the retry, an uncertain PERSON span that crossed a line break and has a name candidate next to it escalates, and the escalation blocks the text. The verifier can still refuse.

### Entity kinds and the `offline` policy

The kinds a profile can set are the 21 below, plus `LOCATION` (the token classifier's `LOC` label) and any custom kind from `[[domain.patterns]]`, `[[domain.labels]]`, or a model label. Keys are case-insensitive but are written in upper case. The table gives the policy `offline` sets, which every profile inherits unless it overrides the kind.

| Kind | Action | `min_confidence` | What it is |
|---|---|---|---|
| `PERSON` | tokenize | 0.60 | A person's name. |
| `EMAIL` | tokenize | 0.50 | An email address. |
| `PHONE` | tokenize | 0.50 | A phone number. |
| `STREET_ADDRESS` | tokenize | 0.60 | A street and house number. |
| `CITY` | preserve | 0.00 | A city. |
| `POSTAL_CODE` | preserve | 0.00 | A postal code. |
| `COUNTRY` | preserve | 0.00 | A country. |
| `ORGANIZATION` | preserve | 0.70 | A company or other organization. |
| `IBAN` | tokenize | 0.50 | An IBAN, checksum-validated. |
| `CREDIT_CARD` | tokenize | 0.50 | A card number, checksum-validated. |
| `IP_ADDRESS` | tokenize | 0.50 | An IPv4 or IPv6 address. |
| `URL` | preserve | 0.00 | A URL. |
| `DATE` | preserve | 0.00 | A date. |
| `DATE_OF_BIRTH` | tokenize | 0.50 | A date of birth. |
| `NATIONAL_ID` | tokenize | 0.50 | A national identity number. |
| `TAX_ID` | tokenize | 0.50 | A tax number. |
| `LICENSE_PLATE` | tokenize | 0.50 | A vehicle plate. |
| `CUSTOMER_ID` | tokenize | 0.50 | From `[[domain.labels]]` or `[[domain.patterns]]`. |
| `CONTRACT_ID` | tokenize | 0.50 | From `[[domain.labels]]` or `[[domain.patterns]]`. |
| `INVOICE_ID` | tokenize | 0.50 | From `[[domain.labels]]` or `[[domain.patterns]]`. |
| `SECRET` | remove | 0.00 | An API key, JWT, connection string, or other credential. Removed, never restored. Every profile must `remove` or `block` it. |

Kinds that keep `preserve` (cities, postal codes, countries, organizations, URLs, dates) are the quasi-identifiers that `verifier.combination_threshold` counts. In `offline-strict`, `fast-strict`, `strict`, and `thorough-strict` the five preserved kinds other than `COUNTRY` (that is `CITY`, `POSTAL_CODE`, `ORGANIZATION`, `URL`, `DATE`) are tokenized from 0.40, with `PERSON` and `STREET_ADDRESS` at 0.40. In `strict-metadata` the same kinds are tokenized from 0.60, and `PERSON` from 0.65; `support-email-metadata` sets `PERSON` to 0.65 only, and both set `escalate_below = 1.0`, so they have no escalation band. The values are measured in the [discovery metadata note](quality/2026-09-29-discovery-metadata.md).

Under `fast` and `fast-strict`, the token classifier's `LOC` label (`LOCATION`) has no entry, so it falls to `default_action` (tokenize): cities found by the model are tokenized there, unlike the regex `CITY`'s `preserve`.
