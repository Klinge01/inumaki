# Timing split and static-prompt cache: A/B latency measurement (Task 7)

Status: **measured**: cache gain met (B session 2 cold at about 10 to 13 % of A session 2 cold), cold-turn time is engine time
(about 99.9 %), B9 overhead target missed on the required rounds and inconclusive under noise (the A-versus-A spread is
larger than the tolerance), and an 8.6 to 17.3 % slower `offline` cold turn on B was not reproduced by the L114
follow-up (20 alternated pairs, median B/A 0.995; section "Offline cold-turn gap (L114)"). Measured
on the retry after the rebase (the evening of 2026-10-19 into the early morning of 2026-10-20, CEST).
An earlier attempt before the rebase measured nothing (see "Earlier attempt"). The equality gates also ran (section
"Equality gates").

- **A** = `6c10361` (the rebased Task 0 commit: bench harness text, second session and cold-turn status; no engine change).
- **B** = `02ef64b` (rebased branch head `l2/timing-cache`: timing split, static-prompt NER memo, `static_cache` counters,
  and the bench's `proxy timing` print). Both SHAs are post-rebase onto main `ddded82`; the SHAs of the earlier attempt
  (`de23b1d`, `a0d2717`, both pre-rebase) no longer name these builds. SHAs in this document marked "pre-rebase" map to
  the rebased commits in the table "Pre-rebase SHAs" below.
- Machine: Apple silicon Mac (`Mac16,13`), 10 logical CPUs, 32 GiB RAM, macOS 27.0.1. Shared with the other lanes.
- Builds: `cargo build -j 4 --release -p inumaki-cli` in two throwaway detached worktrees with their own target
  directories, built in parallel (4 min 59 s and 4 min 57 s wall). Both exited 0.
- Load rule: a run counts only if it started at a 1-minute load below 8; runs alternate A, B, A, B per scenario. Every run
  below started under 8 (the highest start was 7.97). Several started in the 7 to 8 range, close to the limit, and the 1-minute
  load includes the bench itself and whatever the other lanes ran, so the numbers carry noise (see the spread of the A runs
  against each other). A scenario's rounds are not always back to back: after a run ended above 8 the next run waited
  for the load to fall (the `support-email` messages scenario waited 1130 s between round 1 A and round 1 B).
- Runs are one bench process each; the p50 and p95 columns are the bench's `added per turn (50)` over turns 1 to 50
  (turn 0, the cold turn, is not in them). Status 200 on every cold turn; no refused turn in any run.

## Scenarios

Commands (from `.superpowers/sdd/2026-10-12-timing-and-prompt-cache/task0-baseline.md`; `$BIN` is `inumaki` of A or B):

```bash
export INUMAKI_MODELS_DIR="$HOME/Library/Application Support/inumaki/models"
export INUMAKI_BENCH_MAILS=0 INUMAKI_BENCH_SYSTEM=harness INUMAKI_BENCH_SESSIONS=2
$BIN bench --via-proxy --profile support-email --wire codex
$BIN bench --via-proxy --profile support-email --wire messages
$BIN bench --via-proxy --profile fast --wire codex
# control, B9 overhead:
env -u INUMAKI_BENCH_MAILS -u INUMAKI_BENCH_SYSTEM -u INUMAKI_BENCH_SESSIONS $BIN bench --via-proxy --profile offline --wire messages
```

Loads are the 1-minute load average from `sysctl -n vm.loadavg` at the start and end of each run. "n/a" in the
`static_cache` column: A has no such counter. The `offline` control has no second session.

### support-email, codex, harness text, 2 sessions

| round | build | start load | end load | s1 cold ms / status | s2 cold ms / status | turns 1-50 p50 / p95 ms | static_cache hits/misses/clears |
|---|---|---|---|---|---|---|---|
| 1 | A | 7.63 | 9.28 | 3007.1 / 200 | 3935.2 / 200 | 428.6 / 634.0 | n/a (no counter on A) |
| 1 | B | 7.94 | 8.06 | 3334.2 / 200 | 426.8 / 200 | 376.4 / 643.8 | 2/2/0 |
| 2 | A | 7.66 | 7.07 | 3628.8 / 200 | 3133.1 / 200 | 417.0 / 699.4 | n/a (no counter on A) |
| 2 | B | 7.07 | 8.27 | 3261.8 / 200 | 418.3 / 200 | 456.5 / 1054.3 | 2/2/0 |

### support-email, messages, harness text, 2 sessions

| round | build | start load | end load | s1 cold ms / status | s2 cold ms / status | turns 1-50 p50 / p95 ms | static_cache hits/misses/clears |
|---|---|---|---|---|---|---|---|
| 1 | A | 7.77 | 9.95 | 3285.1 / 200 | 8258.4 / 200 | 525.2 / 970.2 | n/a (no counter on A) |
| 1 | B | 7.96 | 14.46 | 5714.8 / 200 | 789.8 / 200 | 790.2 / 1351.6 | 2/2/0 |
| 2 | A | 7.88 | 7.31 | 4193.6 / 200 | 3798.3 / 200 | 412.4 / 701.3 | n/a (no counter on A) |
| 2 | B | 7.31 | 7.03 | 4184.6 / 200 | 462.2 / 200 | 516.9 / 935.3 | 2/2/0 |

Round 1 of this scenario is contaminated: B's round 1 ended at load 14.46 (the other lanes started work during it) and A's
round 1 session 2 cold turn, 8258.4 ms, is more than twice A's round 2 figure (3798.3 ms) at the same warm state. Use round 2 for
this scenario; round 1 is shown for completeness.

### fast, codex, harness text, 2 sessions

| round | build | start load | end load | s1 cold ms / status | s2 cold ms / status | turns 1-50 p50 / p95 ms | static_cache hits/misses/clears |
|---|---|---|---|---|---|---|---|
| 1 | A | 6.79 | 6.75 | 1011.0 / 200 | 1126.4 / 200 | 131.6 / 174.8 | n/a (no counter on A) |
| 1 | B | 6.75 | 7.93 | 1086.4 / 200 | 117.3 / 200 | 137.2 / 215.0 | 1/1/0 |
| 2 | A | 7.93 | 7.26 | 1219.6 / 200 | 1386.6 / 200 | 147.6 / 185.8 | n/a (no counter on A) |
| 2 | B | 7.26 | 7.30 | 1114.8 / 200 | 133.8 / 200 | 136.7 / 178.4 | 1/1/0 |

### offline, messages, default mail system prompt (control)

| round | build | start load | end load | s1 cold ms / status | s2 cold ms / status | turns 1-50 p50 / p95 ms | static_cache hits/misses/clears |
|---|---|---|---|---|---|---|---|
| 1 | A | 6.71 | 6.65 | 1626.0 / 200 | n/a | 36.8 / 46.8 | n/a (no counter on A) |
| 1 | B | 6.65 | 6.86 | 1765.2 / 200 | n/a | 50.7 / 265.4 | 0/0/0 |
| 2 | A | 6.86 | 6.96 | 1660.5 / 200 | n/a | 46.0 / 62.8 | n/a (no counter on A) |
| 2 | B | 6.96 | 6.96 | 1894.3 / 200 | n/a | 43.0 / 130.2 | 0/0/0 |
| 3 | A | 7.97 | 7.57 | 1302.8 / 200 | n/a | 33.9 / 48.2 | n/a (no counter on A) |
| 3 | B | 7.57 | 7.44 | 1528.2 / 200 | n/a | 37.7 / 52.9 | 0/0/0 |
| 4 | A | 7.44 | 7.57 | 1303.1 / 200 | n/a | 39.2 / 54.6 | n/a (no counter on A) |
| 4 | B | 7.57 | 7.36 | 1486.1 / 200 | n/a | 34.5 / 45.4 | 0/0/0 |

Rounds 1 and 2 are the required two rounds. Rounds 3 and 4 were added because rounds 1 and 2 were too noisy to read
(cheap runs, about a minute each; all started under 8, alternating A, B, A, B as before).

## B's timing split of the two cold turns

Printed by B's bench as `proxy timing` after each cold-turn line: the in-process proxy's own sample, in ms (the proxy's
whole request time, including the scripted upstream's time; the `cold first turn` figure subtracts the scripted upstream's
time, so the two differ by a few ms). `local = read + queue + scan + engine + closure + restore`; `project` is inside
`closure`. `first_byte` and `provider` are 0 here because the scripted upstream answers at once.

| scenario (B run) | turn | total | local | read | queue | scan | engine | closure | project | restore |
|---|---|---|---|---|---|---|---|---|---|---|
| support-email codex, r1 | session 1 cold | 3334 | 3333 | 0 | 0 | 0 | 3332 | 0 | 0 | 0 |
| support-email codex, r1 | session 2 cold | 426 | 426 | 0 | 0 | 0 | 425 | 0 | 0 | 0 |
| support-email codex, r2 | session 1 cold | 3260 | 3258 | 0 | 0 | 0 | 3257 | 0 | 0 | 0 |
| support-email codex, r2 | session 2 cold | 418 | 418 | 0 | 0 | 0 | 416 | 0 | 0 | 0 |
| support-email messages, r2 | session 1 cold | 4182 | 4181 | 0 | 0 | 0 | 4179 | 0 | 0 | 0 |
| support-email messages, r2 | session 2 cold | 462 | 462 | 0 | 0 | 0 | 460 | 0 | 0 | 0 |
| fast codex, r1 | session 1 cold | 1086 | 1086 | 0 | 0 | 0 | 1085 | 0 | 0 | 0 |
| fast codex, r1 | session 2 cold | 117 | 117 | 0 | 0 | 0 | 116 | 0 | 0 | 0 |
| fast codex, r2 | session 1 cold | 1114 | 1114 | 0 | 0 | 0 | 1113 | 0 | 0 | 0 |
| fast codex, r2 | session 2 cold | 133 | 133 | 0 | 0 | 0 | 132 | 0 | 0 | 0 |
| support-email messages, r1 (contaminated) | session 1 cold | 5713 | 5711 | 0 | 0 | 0 | 5709 | 1 | 0 | 0 |
| support-email messages, r1 (contaminated) | session 2 cold | 789 | 789 | 0 | 0 | 0 | 787 | 0 | 0 | 0 |
| offline messages, r1 | cold | 1765 | 1764 | 0 | 0 | 11 | 1607 | 129 | 0 | 16 |
| offline messages, r2 | cold | 1895 | 1893 | 0 | 0 | 10 | 1732 | 133 | 0 | 17 |
| offline messages, r3 | cold | 1526 | 1525 | 0 | 0 | 8 | 1385 | 116 | 0 | 13 |
| offline messages, r4 | cold | 1486 | 1485 | 0 | 0 | 7 | 1332 | 130 | 0 | 15 |

Reading: on the three NER profiles the cold turn's time is the engine stage (the NER calls), 99.9 % of `total`, and the
session 2 saving is entirely in that stage (`engine` 3332 to 425 ms at `support-email` codex round 1, 1085 to 116 ms at `fast` round 1). `read`, `queue` and `scan` are
under 1 ms. The `static_cache` counters are `hits 2 misses 2` (`support-email`: sanitizer and verifier NER, session 1
misses, session 2 hits) and `hits 1 misses 1` (`fast`: one NER), `clears 0`; `offline` has no NER so the memo is
untouched (`0/0/0`).

## Targets

Cache gain: B session 2 cold vs A session 2 cold (same warm state, P5: a cold start or a dictionary change pays the full
model time, so only session 2 can hit). The spec sets no numeric threshold for the gain; the ratios are the attribution.

| target | A s2 cold ms (r1, r2) | B s2 cold ms (r1, r2) | ratio B/A (r1, r2) | result |
|---|---|---|---|---|
| Cache gain, `support-email`, `codex` | 3935.2, 3133.1 | 426.8, 418.3 | 0.108, 0.134 | gain 7.5x to 9.2x: **met** (B s2 at about 12 % of A s2) |
| Cache gain, `fast`, `codex` | 1126.4, 1386.6 | 117.3, 133.8 | 0.104, 0.096 | gain 9.6x to 10.4x: **met** (about 10 %) |
| Cache gain, `support-email`, `messages` (extra) | 8258.4 (contaminated), 3798.3 | 789.8, 462.2 | 0.096, 0.122 | gain 8.2x on the clean round 2 |

The A session 2 cold turn is not cheaper than its session 1 cold turn (support-email codex: 3007.1 then 3935.2, and 3628.8
then 3133.1; fast: 1011.0 then 1126.4, and 1219.6 then 1386.6), as expected for a build with no cross-session memo.

For information, B session 2 cold vs B session 1 cold (session 1 includes ORT warm-up): support-email codex 426.8 vs
3334.2 and 418.3 vs 3261.8 (ratios 0.128 and 0.128); fast codex 117.3 vs 1086.4 and 133.8 vs 1114.8 (0.108 and 0.120);
support-email messages 789.8 vs 5714.8 and 462.2 vs 4184.6 (0.138 and 0.110).

B9 overhead (`offline`, turns 1 to 50, p50 and p95 on B within 3 % or 1 ms of A, whichever is larger). The tolerance is
about 1 to 2 ms on figures of 34 to 63 ms (3 % of the A value, never under 1 ms).

| round | p50 A | p50 B | B minus A | p95 A | p95 B | B minus A |
|---|---|---|---|---|---|---|
| 1 | 36.8 | 50.7 | +13.9 | 46.8 | 265.4 | +218.6 |
| 2 | 46.0 | 43.0 | -3.0 | 62.8 | 130.2 | +67.4 |
| 3 (extra) | 33.9 | 37.7 | +3.8 | 48.2 | 52.9 | +4.7 |
| 4 (extra) | 39.2 | 34.5 | -4.7 | 54.6 | 45.4 | -9.2 |
| mean of 4 | 39.0 | 41.5 | +2.5 (+6.4 %) | 53.1 | 123.5 | +70.4 |
| median of 4 | 38.0 | 40.4 | +2.4 | 51.4 | 91.6 | +40.2 |

Result: **missed on the two required rounds** (round 1 p50 +13.9 ms and p95 +218.6 ms; round 2 p95 +67.4 ms; only the round 2
p50 is inside the tolerance), and not confirmable either way at this noise. Likely cause, as far as the data
shows: machine contention, not a B cost. The A runs differ from each other by 12 ms in p50 (33.9 to 46.0) and 16 ms in p95
(46.8 to 62.8), ten times the tolerance, and the two B runs with the large p95 (265.4 and 130.2) are the two earliest, while
B's rounds 3 and 4 on the same binary give p95 52.9 and 45.4, in line with A. The `offline` profile has no NER, and
the memo counters stay `0/0/0`, so the memo is not on this path; B's only per-request additions there are the timing
samples (a few clock reads) and the engine fetch. A quiet-machine run with more rounds (the other lanes parked) is needed to
settle the 3 % or 1 ms bound; this document does not claim it holds.

One consistent difference outside the target: B's `offline` cold turn (turn 0) is slower than A's in all four pairs
(1765.2 vs 1626.0, 1894.3 vs 1660.5, 1528.2 vs 1302.8, 1486.1 vs 1303.1 ms; +8.6 %, +14.1 %, +17.3 %, +14.0 %). B's
split of those turns is `engine` 1332 to 1732 ms, `closure` 116 to 133 ms, `scan` 7 to 11 ms; A has no split, so where
the extra time sits is not known. Its cause is not isolated: B's bench
builds two engines (the plain one and the memo-wrapped one) before the run, and the cold turn is also where the dictionary
and leak-index work first happens; no measurement here separates these. The cold turn is not part of the B9 target.
The L114 follow-up below did not reproduce the difference; see "Offline cold-turn gap (L114)".

## Offline cold-turn gap (L114)

A time-boxed diagnosis (integrator ruling L114, 2026-10-20 01:54 to 02:25 CEST) of the slower `offline` cold turn
above. **Result: not reproduced; no code cause found, no fix.** The four pairs above are within the run-to-run noise of
this machine's cold turn, which is bimodal.

Builds: release `inumaki-cli` (`cargo build -j 4 --release`) of A = `29f9e45` (the Task 0 commit after the rebase onto
main `dec8362`, same code as `6c10361`) and B = `83d0873` (branch head; its crates are identical to `fbbebcc`, the code
the A/B above measured as `02ef64b`, plus main's `dec8362` changes, which touch no proxy or bench file), and one local,
uncommitted diagnostic variant B' of B with two environment switches in `bench_proxy.rs`: **B1** builds one engine and
hands it out as both the plain and the memo-wrapped engine (no second `Engine::from_config`), **B0** sets
`static_cache = false` (the pipeline holds no memo). Command per run: the `offline` control of `task0-baseline.md`
(`env -u INUMAKI_BENCH_MAILS -u INUMAKI_BENCH_SYSTEM -u INUMAKI_BENCH_SESSIONS ... bench --via-proxy --profile offline
--wire messages`), each started at a 1-minute load under 8; all 52 measured runs started at 1-minute load 6.48 to 7.92
and ended at 6.48 to 8.39 (5-minute load 7.36 to 8.65).

Hypotheses checked against the diff `29f9e45..83d0873`:

- *Second engine instance.* B's bench builds a plain engine and a memo-wrapped twin over the same NER `Arc`s; the
  `offline` cold turn uses only the plain one (no leaf is eligible, memo counters `0/0/0`). Neither A nor B warms its
  engine before turn 0, so both pay the same first-use costs on the same kind of instance. B1 (one engine) against A:
  6 pairs, median ratio 1.014 (0.986 to 1.111), in the noise.
- *Memo set-up and per-leaf engine choice* (`NerMemo::new`, `leaf_engine`, `memo_for`, the `static_eligible` check, the
  hoisted NFC in the closure): no memo scope opens on `offline`, and B0 (no memo in the pipeline) against A: 6 pairs,
  median ratio 0.994 (0.976 to 1.012).
- *B9 instrumentation* (`StageTimes`, `timed`, `StageGuard`, the log fields): a few clock reads and one mutex push per
  request, outside any loop over text; B against A shows no difference to attribute to it (next item).
- *B against A, 20 alternated pairs* in three orders (A B B1 B0 / B0 B1 B A for rounds 1 to 6, A B / B A for rounds 7 to
  14, A B strictly as in the A/B above for rounds 15 to 20): cold turn median A 2386.4 ms, B 2366.3 ms; median B/A
  0.995, B slower in 8 of 20 pairs. The 18 pairs where both runs sat in the same mode: median 0.995 (0.911 to 1.166).
- *Bimodal machine state.* The cold turn of both binaries jumps between about 1.25 s and about 2.4 s from one run to the
  next (rounds 15 to 18: A 2495.2, B 1334.6, A 1249.3, B 1262.1, A 1259.8, B 1254.0, A 1253.5, B 2508.4 ms; the two
  pairs inside the fast mode give B/A 1.010 and 0.995). The split moves with it (B `engine` 1131 to 1206 ms and `closure`
  101 to 103 ms in the fast mode, 2048 to 2379 ms and 184 to 207 ms in the slow one), so the whole engine runs at about
  half speed. The cause of the two modes is not known: the machine has 4 performance and 6 efficiency cores, but forcing
  the process onto background QoS (`taskpolicy -b`, 4 runs A B A B) gives a third level, 3212.2 to 3538.4 ms (B/A 0.908
  and 0.990), so the slow mode is not simply the efficiency cores. The A/B above (1302.8 to 1894.3 ms) lies between the
  modes, and an order effect shows here too: in rounds 1 to 14 the second run of an adjacent A/B pair was slower in 11 of
  14 pairs, whichever binary it was; the A/B above always ran A first within a pair.

Residual: none attributable to B. A quiet-machine run pinned to one core class would be needed to measure a cold-turn
difference under about 10 %; nothing here suggests one.

## Earlier attempt (before the rebase, nothing measured)

On 2026-10-19 the first attempt used A = `de23b1d` (pre-rebase) and B = `a0d2717` (pre-rebase) and measured nothing: the runner polled the 1-minute
load every 15 s for 59 minutes (21:34 to 22:33) and it never fell below 8 at a start. The load at the end of each wait
was 77.27, 37.14, 10.66 (lowest), 13.60, 29.68, 48.63 and 33.29. At that time the bench did not print the timing split; B
`b04a70a` (pre-rebase) and later print it.

## Pre-rebase SHAs

The branch was rebased onto main `ddded82` after the first attempt and after the equality gates ran. The subjects are the
same and the lane's code is identical; only the SHAs changed. The SHAs the gates and the earlier attempt name, and the
commits they became:

| pre-rebase | rebased | subject |
|---|---|---|
| `de23b1d` | `6c10361` | feat(bench): harness system text, second session and cold-turn status |
| `f6447b5` | `067a3e3` | test(proxy): NER results are identical across concurrent calls |
| `e1179ba` | `65c84c9` | test(proxy): memo determinism test fails on empty NER output, adds a token-dense input |
| `eded642` | `d4e4b40` | test(proxy): ignore the slow memo determinism test, document its gate command |
| `7a08bce` | `dfe807f` | feat(daemon): host the static-prompt NER memo, add the differential gate |
| `6dc6ca2` | `2a0f04d` | test(proxy): make the memo differential an ignored hard gate, report differing inputs |
| `a0d2717` | `448cbe9` | feat(proxy): timing and static_cache in GET /v1/proxy and inumaki status |
| `b04a70a` | `05b36cb` | feat(bench): print the proxy timing split of both cold turns |
| `cd288da` | `5ea4a71` | docs(quality): the bench now prints the timing split; fix load wording |

## Equality gates

These are not latency figures. They check that the static-prompt NER memo changes no output: the memo is sound only if
the NER models return the same spans for the same bytes (determinism), and the proxy must forward the same bodies and
refuse the same requests with the memo on and off (differential). Both ran under load; load does not affect what they
check.

### Determinism (plan Task 0b), at `e1179ba` (pre-rebase)

Test: `crates/inumaki-proxy/tests/static_memo_models.rs`. Backends built as the daemon builds them, 2 ORT sessions per
model, 3 rounds of 4 concurrent calls per (detector, input) pair, the cold first call included; start, end, kind and the
confidence's bit pattern compared across all 12 calls. Debug build, 1392 s. Command at that commit (the test was made
`#[ignore]` afterwards, at `eded642` (pre-rebase); the final gate runs it in release with `-- --ignored`, as its doc comment says):

```bash
INUMAKI_MODELS_DIR="$HOME/Library/Application Support/inumaki/models" \
  cargo test -p inumaki-proxy --features models-tests --test static_memo_models -- --nocapture
```

| detector | inputs | calls per pair | pairs that differ |
|---|---|---|---|
| `support-email` sanitizer NER | harness text (20 480 B), German mail (557 B), dense non-ASCII (49 238 B), token-dense ASCII (49 156 B) | 12 | 0 of 4 |
| `support-email` verifier NER | the same four | 12 | 0 of 4 |
| `fast` sanitizer NER (`fast` has no verifier NER) | the same four | 12 | 0 of 4 |

Result: 12 detector-and-input pairs, 12 calls each, 0 differ. The `InputTooLong` split path is argued pure in the test's
doc comment, not observed.

### Memo on/off differential (ruling L104 (a)), at `7a08bce` (pre-rebase)

Test: `crates/inumaki-proxy/tests/static_memo_differential.rs`. The 4d differential-harness corpus plus the bench
harness texts, each sent as a system leaf through an in-process proxy across two sessions, once with the memo on and
once off; forwarded bodies compared after canonical token renaming, refusals compared. Release build, 8 shards. Command
per shard at that commit (the test then still needed the opt-in variable `INUMAKI_MEMO_DIFF=1`):

```bash
INUMAKI_MEMO_DIFF=1 INUMAKI_MEMO_DIFF_SHARD=i/8 INUMAKI_MODELS_DIR="$HOME/Library/Application Support/inumaki/models" \
  cargo test --release -p inumaki-proxy --features models-tests --test static_memo_differential -- --nocapture
```

| shard | load at start | docs | requests | refusals per side (equal) | session-2 docs without a hit | memo hits | diffs | wall |
|---|---|---|---|---|---|---|---|---|
| 0/8 | 9.39 | 101 (bench 1, corpus 100) | 404 | 8 | 0 | 293 | none | 269 s |
| 1/8 | 9.57 | 101 (bench 1, corpus 100) | 404 | 12 | 0 | 295 | none | 257 s |
| 2/8 | 10.20 | 100 | 400 | 8 | 0 | 286 | none | 280 s |
| 3/8 | 24.52 | 100 | 400 | 8 | 0 | 292 | none | 291 s |
| 4/8 | 17.81 | 100 | 400 | 18 | 0 | 289 | none | 222 s |
| 5/8 | 11.50 | 100 | 400 | 6 | 0 | 293 | none | 181 s |
| 6/8 | 9.20 | 100 | 400 | 8 | 0 | 289 | none | 175 s |
| 7/8 | 7.11 | 100 | 400 | 14 | 0 | 290 | none | 173 s |

Totals: 802 documents (2 bench texts and 800 corpus documents, padded to the memo's 2 KiB floor), 3 208 requests,
2 327 memo hits, 0 differences in forwarded bodies, equal refusals on every shard, and no second-session document
without a hit. Every shard exited 0.

Re-run at `6dc6ca2` (pre-rebase; the test became an `#[ignore]` hard gate with no opt-in variable and prints the indices of any
differing input and session): shard 0/8 only, 101 documents, 293 memo hits, no differences.

```bash
INUMAKI_MEMO_DIFF_SHARD=i/8 INUMAKI_MODELS_DIR="$HOME/Library/Application Support/inumaki/models" \
  cargo test --release -p inumaki-proxy --features models-tests --test static_memo_differential -- --ignored --nocapture
```

The final gate (plan Task 9) re-runs both tests on the rebased head, every differential shard included, and adds its
rows below.

## Final gate

Plan Task 9 ran twice: first on the pre-rebase head `d02d9f8` (ddded82-based), then again on the rebased head
`cc15428` (main `dec8362`). Both passed; the rebased run is the gate of record.

### Gate on the rebased head (main dec8362)

Run on 2026-10-20 on head **`cc15428`** (branch `l2/timing-cache`, rebased onto main `dec8362`; the commit that records
this subsection is docs only and changes no code). Result: **PASSED**. Every command ran in the foreground; `rc` is the
exit code. Debug builds unless stated. Models directory for the gated runs:
`INUMAKI_MODELS_DIR="$HOME/Library/Application Support/inumaki/models"`.

| step | command | rc | result |
|---|---|---|---|
| format | `cargo fmt --all -- --check` | 0 | clean |
| clippy | `cargo clippy --workspace --all-targets -- -D warnings` | 0 | clean |
| clippy, closure-shadow | `cargo clippy -p inumaki-proxy -p inumaki-cli --all-targets --features closure-shadow -- -D warnings` | 0 | clean |
| tests | `cargo test -p inumaki-proxy` | 0 | 286 passed, 0 failed (285 lib, 1 `scripted_exports`) |
| tests | `cargo test -p inumakid` | 0 | 329 passed, 0 failed, 3 ignored |
| tests | `cargo test -p inumaki-client` | 0 | 16 passed |
| tests | `cargo test -p inumaki-cli` | 0 | 69 passed, 1 ignored |
| tests | `cargo test -p inumaki-core` | 0 | 402 passed |
| tests | `cargo test -p inumaki-vault` | 0 | 131 passed |
| tests | `cargo test --workspace --exclude inumaki-proxy --exclude inumakid --exclude inumaki-client --exclude inumaki-cli --exclude inumaki-core --exclude inumaki-vault` | 0 | 464 passed, 1 ignored |
| closure-shadow tests | `cargo test -p inumaki-proxy --features closure-shadow --lib` | 0 | 288 passed |
| proxy models | `cargo test -p inumaki-proxy --features models-tests` | 0 | 287 passed, 2 ignored (the two hard gates below); `projection_equivalence` ran and passed |
| determinism | `cargo test --release -p inumaki-proxy --features models-tests --test static_memo_models -- --ignored --nocapture` | 0 | ran, **0 differ**: 12 detector-and-input pairs, 12 calls each, 0 of 12 calls differ from the first in every pair; 725 s |
| differential | 8 shards, below | 0 each | 0 diffs on every shard |
| inumakid models | `cargo test -p inumakid --features models-tests`, split by `--lib` and by `--test` groups, **excluding `--test mirror_latency`** | 0 each | 333 passed, 0 failed, 5 ignored (84 lib, 249 in the 49 integration files) |
| docs | `scripts/check-docs.sh` | 0 | `check-docs: ok` |

The `inumakid` models split ran `--lib` (84 tests) and the 49 integration test files other than `mirror_latency` as two
groups of explicit `--test` arguments (files 1 to 25 in name order: 131 passed, 3 ignored; 26 to 49: 118 passed,
2 ignored), every group rc 0, including `proxy_memo` (`two_sessions_hit_the_static_prompt_memo_through_the_daemon_host`
ran and passed against the real models) and `proxy_models`. The counts above the pre-rebase run (`inumakid` 329 against
323, `inumaki-client` 16 against 14, `inumakid` models 333 against 327) are tests that main added between `ddded82` and
`dec8362`; no test of this lane changed count.

**`mirror_latency` was excluded from the debug run** (ruling L2-46): it is a release latency measurement of the folder
mirror, untouched by this lane. The controller ran it in release on the pre-rebase head: 3 passed, 447 s; it was not
re-run on the rebased head. Incident: a helper script of this run was started under macOS bash 3.2, which has no
`mapfile`, so two groups ran with no `--test` filters and therefore the whole `inumakid` suite, `mirror_latency` included,
in debug. That run stopped at `mirror_latency_20kb` (rc 101; 258 passed, 1 failed, 5 ignored; the log is kept):
`support-email: a run timed out` at `mirror_latency.rs:367`, with a support-email p50 of 7 635 ms and blocked 46 of 51 on a
debug build while other jobs shared the machine. That is the debug latency assertion the ruling excludes, not a result for
this lane; the explicit-filter groups above were then run and passed. No `mirror_latency` result is claimed for this head.

#### Differential, per shard on the rebased head (release, `-- --ignored`, `INUMAKI_MEMO_DIFF_SHARD=i/8`)

| shard | rc | docs | requests | refusals per side | session-2 docs without a hit | memo hits | diffs | differing (input, session) | test time |
|---|---|---|---|---|---|---|---|---|---|
| 0/8 | 0 | 101 (bench 1, corpus 100) | 404 | 8 | 0 | 293 | 0 | none | 141 s |
| 1/8 | 0 | 101 (bench 1, corpus 100) | 404 | 12 | 0 | 295 | 0 | none | 166 s |
| 2/8 | 0 | 100 | 400 | 8 | 0 | 286 | 0 | none | 136 s |
| 3/8 | 0 | 100 | 400 | 8 | 0 | 292 | 0 | none | 141 s |
| 4/8 | 0 | 100 | 400 | 18 | 0 | 289 | 0 | none | 134 s |
| 5/8 | 0 | 100 | 400 | 6 | 0 | 293 | 0 | none | 135 s |
| 6/8 | 0 | 100 | 400 | 8 | 0 | 289 | 0 | none | 133 s |
| 7/8 | 0 | 100 | 400 | 14 | 0 | 290 | 0 | none | 134 s |

Totals: 802 documents, 3 208 requests, 2 327 memo hits, 0 differences in forwarded bodies, equal refusals on every shard,
no second-session document without a hit; the same counts as the pre-rebase run, shard for shard.

#### Evals

Not run: `inumaki-core` is unchanged by this lane, and the eval runs the engine without the proxy memo, so the lane cannot
move its numbers.

### Pre-rebase gate (ddded82-based head d02d9f8)

Plan Task 9, run on 2026-10-20 on head **`d02d9f8`** (branch `l2/timing-cache`, rebased onto main `ddded82`; the commit
that records this section is docs only and changes no code). Result: **PASSED**. Every command ran in the foreground;
`rc` is the exit code. Debug builds unless stated. Models directory for the gated runs:
`INUMAKI_MODELS_DIR="$HOME/Library/Application Support/inumaki/models"`.

| step | command | rc | result |
|---|---|---|---|
| format | `cargo fmt --all -- --check` | 0 | clean |
| clippy | `cargo clippy --workspace --all-targets -- -D warnings` | 0 | clean |
| clippy, closure-shadow | `cargo clippy -p inumaki-proxy -p inumaki-cli --all-targets --features closure-shadow -- -D warnings` | 0 | clean |
| tests | `cargo test -p inumaki-proxy` | 0 | 286 passed, 0 failed (285 lib, 1 `scripted_exports`) |
| tests | `cargo test -p inumakid` | 0 | 323 passed, 0 failed, 3 ignored |
| tests | `cargo test -p inumaki-client` | 0 | 14 passed |
| tests | `cargo test -p inumaki-cli` | 0 | 69 passed, 1 ignored |
| tests | `cargo test -p inumaki-core` | 0 | 402 passed |
| tests | `cargo test -p inumaki-vault` | 0 | 131 passed |
| tests | `cargo test --workspace --exclude inumaki-proxy --exclude inumakid --exclude inumaki-client --exclude inumaki-cli --exclude inumaki-core --exclude inumaki-vault` (models, eval, gateway, mcp, adapters, hook, mail, mirror) | 0 | 464 passed, 1 ignored |
| closure-shadow tests | `cargo test -p inumaki-proxy --features closure-shadow --lib` | 0 | 288 passed |
| proxy models | `cargo test -p inumaki-proxy --features models-tests` | 0 | 287 passed, 2 ignored (the two hard gates below); `projection_equivalence` ran and passed |
| determinism | `cargo test --release -p inumaki-proxy --features models-tests --test static_memo_models -- --ignored --nocapture` | 0 | ran, **0 differ**: 12 detector-and-input pairs, 12 calls each, 0 of 12 calls differ from the first in every pair; 1090 s |
| differential | 8 shards, below | 0 each | 0 diffs on every shard |
| inumakid models | `cargo test -p inumakid --features models-tests`, split by `--lib` and by `--test` groups, **excluding `--test mirror_latency`** | 0 each | 327 passed, 0 failed, 5 ignored (84 lib, 243 in the 48 integration files) |
| docs | `scripts/check-docs.sh` | 0 | `check-docs: ok` |

The `inumakid` models split ran the 48 integration test files other than `mirror_latency` as groups of `--test` arguments
(`--lib` 84 tests; files 1 to 10 in name order: 63; 11 to 20: 43; 21 to 30: 43; 31 to 36: 28; 37 to 42: 27; 43 to 48: 39),
every group rc 0, including `proxy_memo` (`two_sessions_hit_the_static_prompt_memo_through_the_daemon_host` ran and
passed against the real models) and `proxy_models`.

**`mirror_latency` was excluded from the debug run** (ruling L2-46): it is a release latency measurement of the folder
mirror, untouched by this lane. A first attempt at this step passed no `--test` filters by mistake and ran the whole
`inumakid` suite, mirror latency included, in debug: it stopped at `mirror_latency` with rc 101, 258 tests passed before it and
1 failed, the log of that run was overwritten by a following mistaken run and not kept, and the failing test was not
identified from output (the count matches the targets before `mirror_latency` in order, so the failure is in it, a debug
build of a latency assertion). The groups above were then re-run correctly and all passed. No `mirror_latency` result is
claimed.

#### Differential, per shard, pre-rebase run (release, `-- --ignored`, `INUMAKI_MEMO_DIFF_SHARD=i/8`)

| shard | rc | docs | requests | refusals per side | session-2 docs without a hit | memo hits | diffs | differing (input, session) | wall |
|---|---|---|---|---|---|---|---|---|---|
| 0/8 | 0 | 101 (bench 1, corpus 100) | 404 | 8 | 0 | 293 | 0 | none | 188 s |
| 1/8 | 0 | 101 (bench 1, corpus 100) | 404 | 12 | 0 | 295 | 0 | none | 205 s |
| 2/8 | 0 | 100 | 400 | 8 | 0 | 286 | 0 | none | 157 s |
| 3/8 | 0 | 100 | 400 | 8 | 0 | 292 | 0 | none | 174 s |
| 4/8 | 0 | 100 | 400 | 18 | 0 | 289 | 0 | none | 181 s |
| 5/8 | 0 | 100 | 400 | 6 | 0 | 293 | 0 | none | 177 s |
| 6/8 | 0 | 100 | 400 | 8 | 0 | 289 | 0 | none | 177 s |
| 7/8 | 0 | 100 | 400 | 14 | 0 | 290 | 0 | none | 197 s |

Totals: 802 documents, 3 208 requests, 2 327 memo hits, 0 differences in forwarded bodies, equal refusals on every shard,
no second-session document without a hit; the same counts as the pre-rebase run above, shard for shard.

#### Evals, pre-rebase run

Not run: `inumaki-core` is unchanged by this lane, and the eval runs the engine without the proxy memo, so the lane cannot
move its numbers.
