# Text origin for harness-static proxy leaves: measurements (lane L2)

Status: **built, final gate pending.** The proxy passes `TextOrigin::HarnessStatic` for the text leaves of the leading system prompt of trusted requests and `Free` everywhere else (M8 spec §20, amendment 2026-10-20; rulings L107, L120, L122; threat model M8 (dd)). Plan: `2026-10-20-origin-wiring`.

- Branch `l2/origin-wiring`, rebased onto main `50df663`. Head before the first docs commit: `5192049`; Task 4b fix round 1 then added `e1ed0bd`. The head of the final gate is recorded in the last section.
- Every number below comes from the lane's task reports (the implementer's own run, release build where marked, `INUMAKI_MODELS_DIR` set). They are **not** the final gate: they ran at the commit named next to them, mostly before the leading-prompt change (ruling L122), and the final gate re-runs them on the final head.
- Not measured: latency. The change adds one origin lookup per leaf and one more key part; it adds no engine stage and no second model pass. No timing was taken, so no timing claim is made here.

## Pre-rebase SHAs

The lane's reports name commits from before the rebase onto `50df663`. They map as follows.

| Pre-rebase | Rebased | Subject |
|---|---|---|
| `e327183` | `efcda58` | design: M8 amendment, threat model (dd), plan |
| `3771a54` | `fe9cafd` | Task 1: origin per leaf, cache key, engine call |
| `032d814` | `c17ea81` | Task 2: critical tests |
| `f76340d` | `42c792d` | Task 4: harness-origin gate |
| `4182230` | `46a8de9` | Task 4 fix round 1 |
| `c0483d6` | `a00dfd6` | Task 1b: leading system prompt |
| `0378393` | `9ade856` | Task 1b: plan section |
| `64903b7` | `719cdf0` | Task 3: `SANITIZER_GENERATION` 3 to 4 |
| `5b574ab` | `2364ab4` | Task 1b minors |
| `aecf03a` | `5192049` | Task 4b: role-word carry, dynamic section |
| (made after the rebase) | `e1ed0bd` | Task 4b fix round 1: names in their real positions |

## Task 4: the harness-origin gate (before the final gate)

`crates/inumaki-proxy/tests/harness_origin_models.rs`, `#[ignore]` hard gate. Command per shard `i` of 2: `INUMAKI_ORIGIN_SHARD=i/2 cargo test --release -p inumaki-proxy --features models-tests --test harness_origin_models -- --ignored --nocapture`. Ran at `46a8de9` (pre-rebase `4182230`), which is before Task 1b; the final gate re-runs it.

Inputs: the 93 documents of `crates/inumaki-eval/harness/harness-static.jsonl` (`codex/*` as Responses `instructions`, the others as Messages `system`) plus the 20 KiB `harness_system` bench text on each wire, 95 in all. Each input runs in a trusted and a restricted session, and the forwarded system leaf is compared with the engine's `HarnessStatic` (trusted) or `Free` (restricted) result on the same text, after canonical token renaming, refusals included.

| Shard | Documents (Messages / Responses) | Differ: HarnessStatic vs Free | `PERSON` tokens trusted / restricted | Refused trusted / restricted | User-turn checks | Mismatches |
|---|---|---|---|---|---|---|
| 0/2 | 48 (22 / 26) | 8 | 41 / 130 | 0 / 0 | 6 | 0 |
| 1/2 | 47 (23 / 24) | 14 | 47 / 168 | 0 / 1 | 0 | 0 |
| Total | 95 | 22 | 88 / 298 | 0 / 1 | 6 | 0 |

- Each shard took about 105 s wall.
- The `PERSON` counts are token occurrences in the forwarded system leaf, not distinct spans, so they are not comparable to lane L3's engine-level 25 against 76 spans (`docs/quality/2026-10-12-harness-static-precision.md`). The refusal shape (0 against 1) matches L3's.
- User-turn checks (shard 0): a German name in a trusted user turn is tokenized (no part of it forwarded, a `PERSON` token present); a harness document sent as a user turn equals the engine's `Free` result, and that document reads differently under `HarnessStatic`, so the check is not vacuous; a name of a dropped shape (a CamelCase surname or a lowercase surname word) sent as a user turn equals the engine's `Free` result, which tokenizes it. The short system text in these checks is "Answer in plain text.", because the first choice ("You are a helpful assistant.") mints a token in the system leaf (below).
- Hard assertions: the corpus holds at least 93 documents; at least one input differs between the origins (checked per shard when there are 2 shards or fewer); `cc-system.txt` trusted answers `200`; trusted `PERSON` tokens and refusals do not exceed restricted ones.
- Every input is sent as a top-level `system` or `instructions`, both leading positions, so the narrowing of ruling L122 does not change where a gate input sits. The gate does not exercise the leading run of `input` and `messages` items; the unit tests do (below).

## Task 4b: two pinned checks (before the final gate)

Run at `5192049` (pre-rebase `aecf03a`; the dynamic-section test again at `e1ed0bd`), these two tests alone: `cargo test --release -p inumaki-proxy --features models-tests --test harness_origin_models -- --ignored --nocapture a_role_word a_capitalized`. Result at `5192049`: 2 passed in 4.6 s; `cargo clippy -p inumaki-proxy --all-targets --features models-tests -- -D warnings` clean. The final gate runs the whole file.

- **Role word carried across leaves** (rulings L125, L126), `a_role_word_minted_in_the_system_leaf_is_carried_into_the_user_leaf`. With "You are a helpful assistant." as the system text, the engine alone gives "You are a `<PERSON#0>`." under `HarnessStatic` and under `Free`: the NER reads `assistant` as a `PERSON` and the ruling-L98 filter does not drop it. The proxy's system leaf is the same trusted and restricted. The context's referential consistency then tokenizes the word in the user leaf: the harness user text gives 11 `PERSON` tokens on a shared context against 9 on a fresh one (engine level, from the diagnosis); with "Answer in plain text." it is 9 against 9. The false positive is on main already and is origin-independent; it adds tokens and does not leak. The pinned test (Responses, trusted and restricted) asserts that the system leaf mints it and the user leaf carries a token, and that the engine does not tokenize the user text alone.
- **Dynamic section of a Claude Code-shaped prompt** (ruling L122 item 3), `a_capitalized_name_in_the_dynamic_system_section_is_tokenized`. A Claude Code-shaped prompt plus an environment block (working directory, git status, commit line), Messages, trusted. The first run at `5192049` reported a lowercase surname "dropped under `HarnessStatic`"; fix round 1 (`e1ed0bd`, controller review of Task 4b) showed that reading was vacuous: its baseline text was probably refused under `Free`, so every candidate differed between the origins. Corrected result, against a baseline prompt (the first of `cc-system` and the 6 KiB `harness_system` text whose neutral section both origins accept; each candidate word asserted absent from it):
  - a capitalized name is tokenized in each of 5 positions: the `Git user: Sarah Leitner` line, the working directory as `/Users/Leitner/project`, `/Users/Sarah.Leitner/project` and `/Users/Sarah Leitner/project`, and a commit subject. Each has no `Sarah` or `Leitner` forwarded, holds a `PERSON` token, and equals the engine's `HarnessStatic` result: no dropped capitalized name;
  - lowercase surnames in a working-directory path segment (`huber`, `miller`) and in a branch name (`rust`, `baker`): 0 of 4 tokenized as harness-static text, 0 of 4 as free text. They are left in clear under both origins, so the gap does not depend on the origin and neither `HarnessStatic` nor the ruling-L98 drop is involved. It is the "names in structured positions" gap already on main (threat model, L3 residuals), recorded in the threat model M8 (dd); lane L3's ruling L127 task (home-folder logins) is to cover it. The test reports the counts, and still runs the lowercase cases if an origin-dependent candidate ever appears.
  - Run (task report, fix round 1): `-- --ignored --nocapture a_role_word a_capitalized`, 2 passed in 69 s; clippy with `models-tests` `-D warnings` clean. The final gate runs the whole file.

## Unit tests and mutation checks (before the final gate)

Counts from the task reports, in the `inumaki-proxy` library at the named commit:

| Commit | Command | Result |
|---|---|---|
| `fe9cafd` (Task 1) | `cargo test -p inumaki-proxy --lib` / with `--features closure-shadow` | 285 / 288 passed |
| `c17ea81` (Task 2) | the same | 290 / 293 passed |
| `a00dfd6` (Task 1b) | the same | 292 / 295 passed |
| `719cdf0` (Task 3) | `cargo test -p inumakid --lib config::` | 36 passed |

The Task 1b minors (`2364ab4`) added assertions to an existing test and no test, and were not re-counted. The critical tests: `origin_tests.rs` (positions, other positions stay `Free`, same bytes under two origins never share a cache entry, the closure and the verifier keep the leaf's origin), `walk::tests::only_the_leading_system_prompt_is_leading`, `memo_tests::free_leaves_never_read_a_harness_static_entry` and `memo_tests::memo_mid_conversation_system_leaf_is_not_eligible`.

Mutation checks (applied to the working tree, targeted tests run, file restored, never committed): Task 2, 9 mutations (re-run and key sites passing `Free`, the key dropping the origin, `leaf_origin` ignoring the role or the client mode, `static_eligible` ignoring the origin), each caught by at least one test; Task 1b, 6 mutations (the leading flag not set, the run unbounded, `leaf_origin` ignoring `leading`, `system_item` ignoring `type`, top-level `system` not leading, the run not stopping at the first non-system item) plus 2 from the review (a role-less item counted as a system item, the array's parent check dropped), each caught.

## Final gate (Task 6)

Head `036d931` on `l2/origin-wiring`. Every command ran from the worktree root. The logs and the run report were kept locally and are not published.

### Command table

| Step | Command | Exit | Test counts (passed / failed / ignored) |
|---|---|---|---|
| 1 | `cargo fmt --all -- --check` | 0 | n/a |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings` | 0 | n/a |
| 3 | `cargo clippy -p inumaki-proxy -p inumaki-cli --all-targets --features closure-shadow -- -D warnings` | 0 | n/a |
| 4 | `cargo clippy -p inumaki-proxy --all-targets --features models-tests -- -D warnings` | 0 | n/a |
| 5 | `cargo test -p inumaki-proxy` | 0 | 294 / 0 / 0 |
| 6 | `cargo test -p inumakid` | 0 | 329 / 0 / 3 |
| 7 | `cargo test -p inumaki-client` | 0 | 16 / 0 / 0 |
| 8 | `cargo test -p inumaki-cli` | 0 | 70 / 0 / 1 |
| 9 | `cargo test -p inumaki-core` | 0 | 451 / 0 / 1 |
| 10 | `cargo test -p inumaki-vault` | 0 | 131 / 0 / 0 |
| 11 | `cargo test --workspace --exclude inumaki-proxy --exclude inumakid --exclude inumaki-client --exclude inumaki-cli --exclude inumaki-core --exclude inumaki-vault` | 0 | 466 / 0 / 1 |
| 12 | `cargo test -p inumaki-proxy --features closure-shadow --lib` | 0 | 296 / 0 / 0 |
| 13 | `cargo test -p inumaki-proxy --features models-tests` | 0 | 295 / 0 / 5 |
| 14 | `cargo test --release -p inumaki-proxy --features models-tests --test static_memo_models -- --ignored --nocapture` | 0 | 1 / 0 / 0 (0 rows differ) |
| 15 | `INUMAKI_MEMO_DIFF_SHARD=i/8 cargo test --release -p inumaki-proxy --features models-tests --test static_memo_differential -- --ignored --nocapture`, i = 0..7 | 0 (all eight) | 8 x 1 / 0 / 0 |
| 16 | `INUMAKI_ORIGIN_SHARD=i/2 cargo test --release -p inumaki-proxy --features models-tests --test harness_origin_models -- --ignored --nocapture`, i = 0..1 | 0 (both) | 3 / 0 / 0 per shard |
| 17 | `cargo test -p inumakid --features models-tests --lib`, then `--test` groups covering the 49 inumakid targets except `mirror_latency` | 0 (all six) | lib 84 / 0 / 0; groups 65 / 66 / 70 / 47 / 1 passed, 0 failed |
| 18 | `scripts/check-docs.sh` | 0 | "check-docs: ok" |
| 19 | `git grep -n 'TextOrigin::HarnessStatic' -- crates ':!crates/inumaki-core' ':!crates/inumaki-eval' ':!crates/inumaki-cli'` | 0 | n/a |

Step 14 prints one row per case, each reading "0 of 12 calls differ from the first". No row reports a difference. The run took 715 s and went past the 600 s foreground limit. It completed in the background, and the command was not re-run.

Step 17 ran 49 inumakid test targets: the 48 in the groups plus `models`. `mirror_latency` is excluded (ruling L2-46). `codex_check_e2e` compiled, and its only test is `#[ignore]` and user-gated, so no codex process ran.

### Per-shard differential (step 15, `static_memo_differential`)

| Shard | Documents | Requests | Refused per side | Memo hits | Diffs |
|---|---|---|---|---|---|
| 0/8 | 101 | 404 | 10 | 294 | {} |
| 1/8 | 101 | 404 | 12 | 295 | {} |
| 2/8 | 100 | 400 | 8 | 286 | {} |
| 3/8 | 100 | 400 | 8 | 292 | {} |
| 4/8 | 100 | 400 | 20 | 289 | {} |
| 5/8 | 100 | 400 | 6 | 293 | {} |
| 6/8 | 100 | 400 | 8 | 289 | {} |
| 7/8 | 100 | 400 | 16 | 290 | {} |

All eight shards report `diffs {}` and an empty `differing (input, session)` list. Each shard reports `session2_without_hit 0` and `clears 0`.

### Origin gate summary (step 16, `harness_origin_models`)

| Shard | Documents (messages / responses) | Differing harness static vs free | PERSON tokens trusted / restricted | Refused trusted / restricted | User-turn checks | Mismatches | Tests |
|---|---|---|---|---|---|---|---|
| 0/2 | 48 (22 / 26) | 8 | 41 / 130 | 0 / 0 | 6 | 0 | 3 passed |
| 1/2 | 47 (23 / 24) | 14 | 47 / 168 | 0 / 1 | 0 | 0 | 3 passed |

Mismatches are 0 in both shards.

### Grep result (step 19)

`TextOrigin::HarnessStatic` appears outside core, eval and cli only in the expected `inumaki-proxy` files:

- `crates/inumaki-proxy/src/cache.rs`
- `crates/inumaki-proxy/src/pipeline.rs`
- `crates/inumaki-proxy/tests/harness_origin_models.rs`

mirror_latency excluded (ruling L2-46).

evals not run: core unchanged.
