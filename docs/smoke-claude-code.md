# Manual smoke test: Claude Code through the gateway

Checks that a real agent harness can list and call wrapped tools through the gateway and sees only tokens. Synthetic data only: the upstream is `inumaki-test-upstream`, the scripted server the gateway tests use, which returns the made-up customer `Zyxwuria Quolnath`, IBAN `AT61 1904 3002 3457 3201`, and customer number `8439271`. Run it after every gateway change and record the result below.

The test fixture has tools that echo arguments and return environment variables of its process; use it only for this test, never as a real upstream. Default builds and installs do not contain it.

## Steps

Use a throwaway data directory and keep the vault key in a file there, so nothing lands in your real vault or your OS keychain. On macOS the socket path must stay under 104 bytes; if the data directory path is long, set `[daemon] socket` to a shorter path.

```bash
cargo build --release -p inumaki-cli -p inumakid --features inumakid/test-fixtures
BIN="$PWD/target/release"
SMOKE=/tmp/inumaki-smoke; mkdir -m 700 -p "$SMOKE/data"
cp configs/default.toml "$SMOKE/config.toml"
printf '\n[vault]\nkey_source = "file"\n' >> "$SMOKE/config.toml"
ink() { "$BIN/inumaki" --config "$SMOKE/config.toml" --data-dir "$SMOKE/data" "$@"; }

ink daemon 2> "$SMOKE/daemon.log" &
ink dataset upstream add demo scripted \
    --content-policy docs/examples/scripted-upstream.policy.json \
    --stdio "$BIN/inumaki-test-upstream"                   # --stdio last
ink dataset list   # the profile column must show a model-backed profile (plan 2c's wrapped-server default), not offline
TOKEN=$(ink gateway token new smoke)
# The server name is model-visible (it prefixes every tool name): use the
# opaque dataset label from the connect line, never the dataset id. The line
# reads `connect: server inumaki-<label> at http://<listen>/mcp/<id> with
# header ...`; pick the one for `demo` (POSIX awk, works with macOS awk).
SERVER=$(ink status | awk '$1 == "connect:" && $5 ~ /\/mcp\/demo$/ {print $3}')
[ -n "$SERVER" ] || echo "no connect line for demo in inumaki status" >&2
```

The test upstream is built only with the `test-fixtures` feature.

The smoke test configures the server through a throwaway file outside the working directory. The MVP procedure never runs `claude mcp add` and never edits your Claude Code configuration.

```bash
(umask 077; printf '{"mcpServers":{"%s":{"type":"http","url":"http://127.0.0.1:8789/mcp/demo","headers":{"Authorization":"Bearer %s"}}}}\n' "$SERVER" "$TOKEN" > "$SMOKE/mcp.json")
```

Then run the prompt once, from an empty directory that holds no daemon logs, configuration, or token files: the agent can read files around it and use what it finds, including a bearer token.

```bash
WORK=$(mktemp -d); cd "$WORK"
claude -p "Use the record tool and tell me the customer's name, IBAN and id exactly as returned. Then call lookup with that id." \
    --allowedTools "mcp__${SERVER}__record mcp__${SERVER}__lookup" \
    --mcp-config "$SMOKE/mcp.json" --strict-mcp-config
cd - && rmdir "$WORK"
ink status
ink activity --dataset demo
ink activity --verify
```

**Expected.** The model reports a `<PERSON_…>` token, an `<IBAN_…>` token, and a `<CUSTOMER_ID_…>` token, never the synthetic name, IBAN, or number; the `lookup` call succeeds, because the daemon restored the token to the integer `8439271`; `inumaki status` shows `calls 2`, `blocked 0` for `demo`; `activity --verify` answers `activity chain ok`. `grep -c -e Zyxwuria -e Quolnath -e 'AT61' -e 8439271 "$SMOKE/daemon.log"` is `0`.

**Cleanup.** Stop the daemon (`kill %1`); `rm -rf "$SMOKE"`.

## Observed

### 2026-10-10 run 3, inumaki 45f181a, Claude Code 2.1.296: expected result

The model reported a `<PERSON_...>` token, an `<IBAN_...>` token, and a `<CUSTOMER_ID_...>` token. The `lookup` call with the token succeeded and matched. `inumaki status` showed demo calls 2, blocked 0. `activity chain ok: 2 records`. The leak grep was 0 in the daemon log, in the model output, and in the transcript. The SERVER extraction line worked. This closes the manual smoke gate (the M4 gate and criterion 4 of `docs/mvp-checklist.md`).

### 2026-10-10 run 2 (main 782c7be): tool calls rejected by the client

Tools were visible. `record` was called twice and both results were rejected by Claude Code 2.1.296 before the model saw them: the `tools/call` result lacked `resultType`, which protocol revision 2026-07-28 requires on every result. `lookup` was never called. `status`: calls 2, blocked 0. `activity --verify`: chain ok, 2 records. Leak grep on the daemon log: 0. Fixed in 003aad0 (`resultType` on call, prompt, and read results; every 2026-07-28 reply shape is now checked in `crates/inumakid/tests/gateway_lifecycle.rs`).

### 2026-10-10 run 1 (Claude Code 2.1.296, main 1369bca-era build): no tools visible

The client speaks the 2026-07-28 lifecycle (`server/discover`, per-request `_meta` and headers, `subscriptions/listen`). List results lacked `ttlMs` and `cacheScope`, so the client rejected every list after retries, and `subscriptions/listen` answered `404`. Fixed in c285266. The model reported that no tool existed. Calls 0. Leak grep: 0.

### 2026-09-29, plan 2c: re-run was pending (closed by the 2026-10-10 run 3)

Plan 2c changed what the 2026-09-28 run hit: discovery metadata is sanitized under the dataset profile's metadata profile (`strict-metadata` for a `strict` dataset; values in `docs/quality/2026-09-29-discovery-metadata.md`), so the scripted server's descriptions and enum values list under `strict`. The model-backed test `crates/inumakid/tests/gateway_models.rs` runs this page's flow without the harness (listing, `record`, `lookup` with the token) and passes. The scripted upstream's free-text tag was changed from `vip` to `tier-2` after that run surfaced a separate false positive: until the quality lane fixes it, a real server returning such a value in a `free_text` field gets that result blocked under `support-email`/`strict`. The re-run was done on 2026-10-10 (run 3, above) and showed the expected result, so the M4 manual smoke gate is closed.

### 2026-09-28, inumaki 0df7e3f, Claude Code 2.1.283: listing refused, no tools reached the model

Form run: the `--mcp-config FILE --strict-mcp-config` variant with `--allowedTools` for the two tools and `--no-session-persistence`, one `claude -p` invocation; release build; the daemon started with an empty environment apart from `HOME` and `PATH`; config as above plus a shorter `[daemon] socket`. Unlike the steps above, `claude -p` ran in the directory that held the MCP configuration and the daemon log.

Result: **not the expected result.** `dataset upstream add` created `demo` with profile `strict`. `tools/list` was refused with `unsupported_content`: under `strict`, low-confidence PERSON spans in benign tool descriptions were blocked (check `Policy`), and one blocked description fails the whole listing. No tool calls were made, and no synthetic value appeared in the output. The model's answer began:

> I couldn't call the tool, so I have no customer name, IBAN or id to give you. The lookup call didn't happen either.

It then described what it had found by reading the daemon log and the MCP configuration file in its working directory, and reported that a `curl` against the gateway with the token from that file had been denied by its permission check. That is why the steps now run `claude -p` from an empty directory.

After the run, `inumaki status` showed:

```
  demo: calls 0 blocked 0 uncertain 0 unresolved 0 unsupported 7 limited 0 clear-value hits 0
    scripted             stdio  running      restarts 0 stderr 61 B contract ready
```

and `activity --verify` answered `activity chain ok: 0 records` (listings are not recorded). None of the synthetic values appeared in the model's output or in the daemon log.

Cause, from `inumaki inspect --dataset demo` on the scripted server's descriptions: under `strict`, GLiNER tags ordinary words in several short descriptions as possible names at low confidence, the policy escalates those spans, and the text is blocked. A single blocked description fails the whole listing by design.

| Text (tool description or enum value) | `strict` | `support-email` | `offline` |
|---|---|---|---|
| `look a customer up by number` | blocked (PERSON, Policy) | blocked after retry into `strict` | pass |
| `counts keyed by customer name` | blocked | blocked after retry | pass |
| ``a text of about `bytes` bytes naming the identity`` | blocked | blocked after retry | pass |
| `a tool whose name is a canary for log tests` | blocked | blocked after retry | pass |
| `lookup_description` (an `enum` value) | blocked | blocked after retry | pass |
| `the customer record of Zyxwuria Quolnath` | pass (name tokenized) | – | – |

`offline` would pass these descriptions, but it has no NER: a name in an upstream's description or results is only caught if a dictionary lists it (see [Profiles in the CLI guide](cli.md#profiles)). The end-to-end flow is covered by the gateway integration tests with the `offline` profile and dictionary fixtures.

False positives on discovery metadata are tracked for plan 4 (quality and calibration). The M4 manual smoke gate stayed open until listings of the scripted server passed under a model-backed profile and a run showed the expected result. Addressed by plan 2c; closed by the 2026-10-10 run 3 above.
