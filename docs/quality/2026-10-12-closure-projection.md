# Closure projection (roadmap 4d): measurement and adjudicated divergences (2026-10-12)

Plan `2026-10-12-closure-projection` (lane L2), Tasks 0 to 7, measured on the reference machine (`macos-aarch64`, Apple Silicon), release builds of branch `l2/closure-projection` at head `695d13e`. The A/B baseline is `main` at `41e87d4`. After the measurements the branch was rebased onto `main` at `4ea20b3`, and `695d13e` became `6e255c2` (so `695d13e` is not an ancestor of the merged branch). The lane's code is identical: `git diff 695d13e 6e255c2` over the 23 files under `crates/` that the lane changes is empty, and `main`'s commits from `41e87d4` to `4ea20b3` touch none of those files (they change config loading, the CLI, the client types, the daemon, the harness adapters, the app, scripts and docs, none of it in the proxy pipeline or the engine). So the measurements carry over to the rebased code. `INUMAKI_MODELS_DIR` was at the pinned models; the bench uses its default seed and the harness seed 7. Raw counts, loads and exit codes are in `2026-10-12-closure-projection-raw.txt`. Nothing here is text: counts, kinds, rates, milliseconds, loads and exit codes only.

**What was built.** Step 6b of the model-API proxy no longer re-runs a cached history leaf through the whole engine when only the store grew. `Engine::project` replaces the new store values that sit in clear in the cached sanitized text with their tokens and runs only deterministic checks on the result (M8 spec §20, amendment of 2026-10-12, "As built"). Two supporting changes ship with it: the leak check reads an index that lives on the store instead of rebuilding its automaton on every call (Phase B), and the store's consistency dictionary and the session's closure dictionary are tiered so a growing store stops paying a full rebuild now and then (residual (a)).

**Result in one paragraph.** Every latency target of the spec is met. On `support-email` the turn p95 fell from 6.9 to 8.7 s to 0.87 to 1.07 s and the turn max from 25 to 64 s to 1.1 to 1.3 s; the median turn did not change. `offline` p50 and p95 halved. No turn was refused in any of the 12 A/B runs. The hard gates held: 0 clear-byte invariant violations (the production byte check, in 528 shadow-measured projections; the weaker word-set check, in 3 559 harness projections) and 0 store forms in clear; 0 leak-check diffs over 10 eval runs. The measured divergences from the full re-run (D1: words left in clear next to a token; D2: 17 harness cases where the full re-run blocks and projection forwards) are all words that were already in clear in the cached text, which already left on that route (the hit premise); they are recorded as a measured residual, not as defects. The held-out bench family refuses turn 0 on baseline and head alike; that is not caused by this item.

Every latency number below names its load: the 1-minute load average from `uptime`, at the start and end of the run.

## Before and after: the latency A/B

`bench --via-proxy --profile support-email`, `INUMAKI_BENCH_MAILS=0` and `=5`, and `--profile offline`, untransformed synthetic mails, 51 turns (1 cold turn, 50 added turns) plus 20 streamed turns. Baseline `41e87d4` and head `695d13e` were built from throwaway detached worktrees with the same print-only patch (the bench did not print a maximum), each with its own target dir. Runs alternated baseline, head, baseline, head, two rounds per scenario. Every one of the 12 runs started at a 1-minute load below 8 (6.24 to 7.88), as the plan requires. The loads drifted during the long baseline runs (one ended at 10.35), so the baseline saw more load drift than the one-to-two-minute head runs; that may inflate the baseline's tail somewhat, but not by the about 7x (p95) and at least 20x (max) seen.

Turns 1 to 50, added time per turn in ms:

| scenario | round | side | 1-min load start → end | p50 | p95 | max | cold turn | refused |
|---|---|---|---|---|---|---|---|---|
| `support-email` MAILS=0 | 1 | baseline | 7.12 → 6.68 | 678.1 | 7 083.3 | 25 215.4 | 10 828.8 | 0 |
| | 1 | head | 6.68 → 7.02 | 670.2 | 1 073.8 | 1 107.0 | 12 405.5 | 0 |
| | 2 | baseline | 7.02 → 7.88 | 742.2 | 7 322.2 | 24 997.9 | 11 071.0 | 0 |
| | 2 | head | 7.88 → 7.83 | 648.9 | 1 027.9 | 1 077.7 | 10 880.8 | 0 |
| `support-email` MAILS=5 | 1 | baseline | 7.83 → 10.35 | 872.1 | 8 690.7 | 63 950.1 | 25 929.4 | 0 |
| | 1 | head | 7.84 → 7.05 | 567.9 | 867.7 | 1 160.3 | 13 932.2 | 0 |
| | 2 | baseline | 7.05 → 6.40 | 612.0 | 6 944.2 | 51 589.6 | 16 903.6 | 0 |
| | 2 | head | 6.40 → 6.93 | 662.6 | 1 036.4 | 1 341.6 | 17 780.5 | 0 |
| `offline` | 1 | baseline | 6.93 → 6.49 | 91.3 | 119.1 | 163.0 | 7 500.4 | 0 |
| | 1 | head | 6.49 → 6.37 | 44.4 | 53.8 | 72.4 | 1 808.6 | 0 |
| | 2 | baseline | 6.37 → 6.24 | 91.7 | 132.4 | 168.1 | 7 617.8 | 0 |
| | 2 | head | 6.24 → 6.46 | 42.6 | 53.0 | 66.8 | 1 747.4 | 0 |

Ratios head over baseline, per round (p50, p95, max): `support-email` MAILS=0: 0.99x / 0.152x / 0.044x and 0.87x / 0.140x / 0.043x; MAILS=5: 0.65x / 0.100x / 0.018x and 1.08x / 0.149x / 0.026x; `offline`: 0.49x / 0.452x / 0.444x and 0.46x / 0.400x / 0.397x. First-byte time of the streamed turns, p95: baseline 30.3 to 58.8 s, head 1.0 to 1.1 s (`support-email`).

Targets of the spec (§20 merge gate) against these runs:

| target | result |
|---|---|
| `support-email` p95 at most 2 s, both runs | **met**: 0.87 to 1.07 s (baseline 6.9 to 8.7 s) |
| `support-email` max at most 5 s, both runs | **met**: 1.08 to 1.34 s (baseline 25 to 64 s) |
| `support-email` p50 within 10 % of main | **met**: 0.65x to 1.08x. The p50 is noise-level: the baseline's own p50 moved from 872 to 612 ms between two rounds of the same scenario. The median turn mints nothing that opens a cached leaf, so it re-runs nothing; the gain is the tail. |
| `offline` p50 and p95 no worse than main by 10 % | **met**, and better: p50 91 → 43 to 44 ms, p95 119 to 132 → 53 to 54 ms |

No target was missed. Two further observations:

- The `offline` gain is not from projection: `offline` has no NER and 0 projections ran there. It is the sum of Phase B (the leak automaton is no longer rebuilt per call) and the tiers (below). The two were not measured separately, because no intermediate build was timed.
- The cold turn is not a target and did not move for `support-email`: it is two NER models over a 20 KB system prompt on CPU, 10.8 to 12.4 s at MAILS=0 on both builds, and 13.9 to 25.9 s at MAILS=5 with a run-to-run spread larger than the difference. The one cold-turn gain is `offline`, 7.5 s → 1.8 s (the cold turn made 399 leak checks, each of which rebuilt the automaton before). The cold turn's remaining full re-runs are all misses the closure reopened and that have nothing to project: 1 (MAILS=0), 5 (MAILS=5) and 11 (`offline`) leaves, about 0.8 to 1.4 s each on `support-email`.

The baseline's tail is large and unstable (its max ranged 25 to 64 s over four runs), so the ratios of max are not a stable figure. Read "from tens of seconds to about one second" rather than the ratio.

### What replaced the re-runs

Cost profile of the baseline side, from Task 0 (main `182d6ed`, instrumented throwaway build, `LAT4D` counters, 1-minute load 9.5 to 16.5, so absolute times are inflated and the shares are the figure to trust): a re-run of a cached hit leaf was 79 % of a `support-email` turn's time (79.1 % at MAILS=0, 79.5 % at MAILS=5, 70 warm requests). In turns 1 to 50 there were 50 re-runs (MAILS=0, mean 1.25 s each, 62.7 s in total) and 111 (MAILS=5, mean 1.00 s each, 111.2 s in total).

The same turns on head, from the instrumented copy of `695d13e` (counts, microseconds; 1-minute load 20.5 to 31.5, so again read the shares): the same 50 and 111 leaves are projected, p50 5.8 and 4.5 ms per leaf, 784 ms and 673 ms in total, 0.94 % and 0.91 % of request time on average (28.0 % and 20.9 % in the worst turn, which projected 25 and 69 leaves). No full re-run remains in turns 1 to 50 or in the streamed turns of any scenario. Both measurements are loaded and at different loads, so the ratio (about 80x and 165x less summed time) is an order of magnitude, not a figure.

Split of one projection (turns 1 to 50, `support-email` MAILS=0 / MAILS=5, shares of the projection's own time, load 20.5 to 31.5):

| stage | MAILS=0 | MAILS=5 |
|---|---|---|
| dictionary search | 3.0 % | 2.6 % |
| dry sanitize | 0.0 % | 0.1 % |
| regex re-scan of the input (inside the dry phase) | 34.0 % | 40.7 % |
| whole deterministic verifier (leak check, its own regex re-scan, bare-identifier scan, combination) | 59.0 % | 53.3 % |
| of which the leak check alone | 6.7 % | 8.8 % |
| leak-index fetch | 2.0 % | 0.2 % |
| caller check | 0.2 % | 0.3 % |
| real sanitize (the mint) | 0.1 % | 0.1 % |

What remains of a projection is two regex scans. They are not tuned here.

## The shadow counters

`bench --via-proxy` with a release binary built with `--features closure-shadow,leak-crosscheck` (`CARGO_TARGET_DIR=target-shadow`). In this build every leaf that step 6b projects is also run through the full re-run, and the full re-run's result is forwarded (M8 spec §20, "Equivalence, measured"). The counters therefore measure projection against the full engine on the same leaf, in the same round, without changing what is sent. All runs exited 0 on the default family; stderr was empty.

The machine was at a 1-minute load of 17 to 171 throughout (other lanes were running). These are correctness runs. **No latency is quoted from them**, and the shadow build's latency must not be compared with the default build's: its extra `rerun.push` changes the round counts.

| run (`support-email` unless stated) | projections attempted | projected | abandoned | invariant violations | D1 by kind | D2 | R1 | R2 | refused turns |
|---|---|---|---|---|---|---|---|---|---|
| MAILS=0 | 237 | 237 | 0 | 0 | EMAIL 158, ORGANIZATION 432, PERSON 175, STREET_ADDRESS 48 | 0 | 0 | 0 | 0 |
| MAILS=5 | 242 | 242 | 0 | 0 | EMAIL 162, ORGANIZATION 428, PERSON 159, STREET_ADDRESS 46 | 0 | 0 | 0 | 0 |
| TRANSFORMS=1, MAILS=5 | 49 | 49 | 0 | 0 | CITY 1, EMAIL 114, INVOICE_ID 4, ORGANIZATION 202, PERSON 47, STREET_ADDRESS 13 | 0 | 0 | 0 | 29 of 51 |
| `strict` | 0 | 0 | 0 | 0 | – | – | – | – | 0 |
| `offline` | 0 | 0 | 0 | 0 | – | – | – | – | 0 |

- Together over the three `support-email` runs: **528 attempted, 528 projected, 0 abandoned, 0 invariant violations**; D1 CITY 1, EMAIL 434, INVOICE_ID 4, ORGANIZATION 1 062, PERSON 381, STREET_ADDRESS 107.
- The two untransformed runs alone: 479 attempted and projected; D1 EMAIL 320, ORGANIZATION 860, PERSON 334, STREET_ADDRESS 94.
- The transformed run refuses 29 of its 51 turns on the profile's `PERSON/Ner` verifier check (the open item recorded in `2026-10-09-l3-engine-proxy.md`); those turns never reach step 6b.
- Projection did not run on `strict` and `offline` (attempted 0). Both exited 0.
- The report prints only counters that are non-zero. D2, R1 and R2 therefore appeared as no line in any run, and the zeros above are read from that. A silent zero would void the measurement, so how far the wiring is pinned matters. R2 and the case counts (attempted, projected, abandoned) are pinned by a pipeline-run test (`pipeline_tests.rs`, `a_shadow_build_forwards_no_identity_value_in_clear`, ruling L2-12). D1 is pinned by the `shadow.rs` unit tests and by its non-zero bench counts. The D2 and R1 call sites in `shadow_compare` are not pinned from a pipeline run (a deferred minor of Task 3), so the bench's D2 = 0 and R1 = 0 rest on reading the code; the differential harness measures D2 independently (17 cases, below).
- **Held-out family.** `INUMAKI_BENCH_FAMILY=held-out` was run for all five profiles/modes. All five exit 3: the first turn is refused (451) before any projection runs, so their shadow blocks are all zero and carry no information. Section "Held-out bench" below.
- R1 and R2 come from the shadow counters only; the harness does not measure them (F24).
- Cache: `support-email` MAILS=0 hits 2 550, misses 102; MAILS=5 hits 2 989, misses 173; transformed hits 679, misses 47; `strict` and `offline` hits 21 900, misses 438.

## The differential harness

`crates/inumaki-proxy/tests/projection_equivalence.rs`, `INUMAKI_PROJECTION_HARNESS=1`, 12 shards (`INUMAKI_PROJECTION_SHARD=i/12`, i = 0 to 11), `cargo test --release -p inumaki-proxy --features models-tests --test projection_equivalence`. Every shard exited 0, so the hard asserts held in every shard (invariant 0, form in clear 0, `d2_words_outside` 0). Corpus: profile `support-email`; the tuning and held-out families, each with and without transforms, 200 documents per family-and-mode (800 documents), seed 7. Load at the end of each shard (1-minute): 44 to 171 for shards 1 to 11 (shard 0 not recorded); machine saturated by other lanes, so no timing from this run.

How a case is built (ruling L2-13, which replaced the plan's design): a fresh context; T0 is the full engine's output for the document; one value is minted into the store, as a later turn of the conversation would; `Engine::project(T0)` runs, then the full re-run of the original text on the same context with the closure's redactions; the two are compared. The plan's own design (mint the document's gold PERSON values) projects almost nothing, because T0 has already tokenized them, so it could not reach the 2 000 projected cases the gate asks for. The cases instead mint what T0 *left in clear*, which is the only thing projection exists to fix: (i) every gold span of any kind still in clear in T0 (a recall miss, or a kind the policy preserves), minted as its gold kind, a PERSON also by name part; (ii) up to 8 capitalized clear words of T0 with 4 or more letters (common and salutation words excluded), minted as PERSON, the shape of an NER false-positive mint that drives the tail; (iii) the plan's own-gold cases and 7 adversarial fixtures, kept for coverage.

| source | attempted | projected | abandoned (reason) | D1 by kind (full re-run replaced it, a word of it is clear in P) | D2 (full re-run blocks, projection forwards) |
|---|---|---|---|---|---|
| (i) gold in clear | 845 | 843 | 2 (SentenceMerge) | EMAIL 6, STREET_ADDRESS 10, CITY 6, PERSON 1, ORGANIZATION 2 | 3: Blocked `Ner/PERSON` |
| (ii) capitalized words | 2 725 | 2 716 | 9 (Regex) | EMAIL 12, ORGANIZATION 160, PERSON 34, STREET_ADDRESS 28, CITY 17, INVOICE_ID 5 | 14: Blocked `Ner/PERSON` |
| **(i) + (ii)** | **3 570** | **3 559** | **11** | EMAIL 18, ORGANIZATION 162, PERSON 35, STREET_ADDRESS 38, CITY 23, INVOICE_ID 5 | **17** |
| (iii) own gold | 3 523 | 4 | 3 519 (Empty) | – | – |
| (iii) adversarial | 21 | 2 | 19 (Empty) | URL 2 | – |

- **The gate:** at least 2 000 projected cases of (i) + (ii): **3 559**. Met.
- **Invariant violations 0; store forms left in clear 0; `d2_words_outside` 0**, over all four sources.
- `T0` did not pass in 6 documents of (i), 6 documents of (ii) and 28 own-gold cases (nothing cached to project; informational).
- Own gold projects 4 of 3 523 because the engine had already tokenized each gold PERSON in T0 (`Empty`: nothing to replace). That is the reason the case design changed.
- Abandonments among projected-able cases: 11 of 3 570, 9 on the regex re-scan (a regex span that projection created or cut, or that T0 did not carry in clear) and 2 on the sentence guard.
- R1 and R2 are not measured here; they come from the shadow counters above (F24).

**The leak check on P (final review M8, added after the 12-shard run).** The store-form check above uses `StoreDict`, the projector's own dictionary family. The harness now also runs the verifier's leak check on every projected P, built per call (`SecondPassVerifier::verify_with_leak` with no index), so it is independent of both the store's leak index and the projector's dictionary; P's real tokens are passed as protected ranges. A leak is a hard failure (`leak_in_p`, asserted 0). The same check runs on T0 after the mint (`leak_in_t0`, which still holds the minted value in clear for sources (i) and (ii)) to show the check fires at all; the test asserts it fired at least once. So far this is a smoke run only (`INUMAKI_PROJECTION_DOCS=10`, shard 0/1, exit 0): `leak_in_p` 0 in all four sources; `leak_in_t0` 208 of the 209 projections of (i) + (ii). The one exception is a value made only of greeting or sign-off vocabulary, which by design has no leak pattern (Task 7d, ruling L56). The 12-shard numbers above predate the check.

Limits of the harness, which the numbers must be read with:

- **"Projected" is an upper bound on production.** The harness's caller check always passes (`Ok(true)`); production also vetoes on host and identity dictionary matches.
- **The capitalized-word source takes the first 8 words of each document**, so it leans toward headers and greetings and has low diversity.
- **The invariant it asserts is word-set based**, weaker than production's byte-and-order check. Production's check is the gate; the harness is the cross-check.
- Every document is a synthetic one from the `inumaki-eval` generator. The harness reads that crate as a dev-dependency and changes nothing in it.

## Adjudication of the divergences

The full re-run is the reference. Projection differs from it in two ways the counters can see. Each is judged under the **hit premise** (M8 spec §20): a cache hit's bytes are inserted only after this upstream route took a request carrying them, under this session key, and a seed's bytes were written by the provider. So everything clear in T0 already crossed on that route. The premise does not bind the provider account or API key (two clients with the same first system and user text share one session under the content-fallback key), and it does not hold inside `inumakid`, where release is not a send to a provider.

### D1: a word the full re-run would tokenize stays clear in P

Counts: bench 479 projections, EMAIL 320, ORGANIZATION 860, PERSON 334, STREET_ADDRESS 94; transformed bench 49 projections, CITY 1, EMAIL 114, INVOICE_ID 4, ORGANIZATION 202, PERSON 47, STREET_ADDRESS 13; harness (i) + (ii), 3 559 projections, EMAIL 18, ORGANIZATION 162, PERSON 35, STREET_ADDRESS 38, CITY 23, INVOICE_ID 5; adversarial fixtures, URL 2.

**What it is.** The full re-run folds a store match into the detector stack's decisions with `merge_redaction`. When the match overlaps a span the detectors reported or the policy preserves, the decision becomes the union of both, and the whole union is tokenized under one token. Projection has only the store's forms. It replaces the matched slice and nothing around it. Two shapes account for the counts (ruling L2-22, integrator L77):

- a first name next to a projected surname (the PERSON class): the full re-run would tokenize the name as one span; projection tokenizes the surname and leaves the neighbour;
- a preserved span cut by a token (the ORGANIZATION, EMAIL, URL, STREET_ADDRESS, CITY and INVOICE_ID classes): `Dr. Huber und Dr. Leitner Rechtsanwälte OG` becomes `Dr. Huber und Dr. <PERSON_…> Rechtsanwälte OG`, and `www.leitner-huber.at` becomes `www.<PERSON_…>-huber.at`, where the full re-run would tokenize the whole preserved span.

The classes were counted by kind, not examined one by one. No D1 divergence is a clear byte that T0 did not already hold.

**Why it is covered.** P's clear bytes are a subset of T0's, in order. That is checked on every projection in production (the clear-byte invariant, always on, abandoning on failure), and **0 violations** were measured: the production byte invariant in the 528 shadow-measured projections, and the weaker word-set check (see the harness limits) in the 3 559 harness cases. So every word that D1 counts is clear in T0, and T0 already left on this route under this session key. The full re-run would have added a token over bytes the provider already holds.

**The direct check (integrator condition on D1, added after the 12-shard run).** The harness now also checks each D1 word: every word of a D1 replacement's slice that is clear in P must be a clear word of T0 (`d1_words_already_sent` and `d1_words_outside`, a hard assert on `d1_words_outside` = 0). Like the D2 check it is word-set based, not positional, and blind to runs of fewer than two letters. It restates the harness's word-set invariant for the D1 words only: `d1_words_outside` can be non-zero only if the invariant (every clear word of P is a clear word of T0) also fails, so it adds no independent evidence; it makes the D1 condition visible as its own count. The 12-shard numbers above predate it. A smoke run (`INUMAKI_PROJECTION_DOCS=10`, shard 0/1, 209 projections of (i) + (ii)) checked 33 D1 words in (i) + (ii) and 6 in the adversarial fixtures, 0 outside, exit 0.

**What this means, stated plainly.** Projection never reveals a byte that had not already left in clear; it does not add the tokenization the full engine would add for preserved kinds and union remnants. The remnant words stay in the resent history as they were. The newly minted value itself is always tokenized (the leak check and the proxy's `ClosureDict` re-check fail the leaf otherwise). For a leaf whose text was *never* sent, this would not be acceptable, and that is why engine-verified leaves are not projected (below).

Verdict: **not a defect** under the premise; recorded in threat model (aa) as a measured residual with these counts. It is not covered where the premise does not hold.

### D2: the full re-run blocks, projection forwards

17 harness cases (3 + 14), all `Blocked` on the verifier's NER re-scan (`Ner`) flagging a PERSON. In the full re-run the NER re-scan tags a word next to a new token, the pass fails, and the retry blocks. Projection runs no NER re-scan, so it forwards. The bench produced 0 D2.

**The check (integrator L77, ruling L2-15).** For each D2 case the harness asserts that every clear word of the full re-run's candidate is a clear word of T0. `d2_words_outside` is **0** in all 12 shards, a hard assert. 442 clear words were checked and found in T0 (110 in source (i), 332 in (ii)). A candidate that is `None` for a blocked-on-Ner case fails the assert, so a missing candidate cannot pass as a clean one.

**Blind spots of that check, to be taken as caveats and not as proof:**
- The flagged span ranges are not public (`Reason` carries only kind and check), so the check is a superset over words: it proves that the whole candidate's words are in T0, not that the flagged span itself is.
- It ignores runs of fewer than two letters (initials, digits), so a flagged initials-only span outside T0 would go unnoticed here. The production byte invariant still holds for P regardless.
- It is set-based, not positional.

Verdict: **not a defect** under the premise. A word the NER re-scan flags is a word of T0 that already left. The cost is only that a leaf the full engine would block is forwarded as it already was.

### R1, R2

R1 (a projected replacement whose slice the full re-run left in clear) and R2 (a projection abandoned where the full re-run passed) are precision measures, and a false positive costs a retry or a human review, not a leak. Both are 0 in 528 shadow projections. R2 also counts uncertain full passes (`PassUncertain`). Not measured in the harness.

### Other things the numbers do not show

- **Engine-verified leaves are never projected**, so none of the above covers text that was never sent. Cold turns and multi-leaf requests keep the full engine.
- The union class (D1) is the reason that a hit's resent text can differ from a first-time text of the same content. That is a difference in what is tokenized, not in what is disclosed.

## Residual (a): the `offline` p95

**Cause (Task 0, main `182d6ed`, stage shares, load 9.5 to 16.5, 70 warm `offline` requests).** The gap between the top decile of requests (7 requests, mean 191 ms) and the middle band (21, mean 125 ms), 66.6 ms, is base rebuilds: `StoreDictCache`'s base rebuild is 57 % of the gap, `Session::closure_dict`'s base rebuild 23 %, the leak check's per-call build 9 %, and step 6b's `from_view`, unsettled scan and `before` set 0 %. 4 of the 70 requests rebuilt the `StoreDictCache` base (4 of the top 7, none of the middle 21), and the session base rebuild hit 2 of the top 7. A base rebuild cost 60 to 71 ms at a store of 16 000 to 17 000 patterns. The earlier idea (a step 6b round dictionary) was dropped: `from_view` was 1.2 % of a turn.

**Fix (Task 6, ruling L2-07).** Both caches get a middle tier:

- `StoreDictCache` keeps a base, a middle tier and the small top layer. The top layer merges into the middle tier when it holds more than 256 values (`TOP_MAX`). The base is compiled again only (1) when there is a dead entry and the dead entries plus the writes since the first dead entry exceed `churn_limit` (unchanged, 256 to 1 024), or (2) when the middle tier's values exceed a quarter of the base, at least 1 024.
- The leak index shares these tiers.
- `Session::closure_dict` rebuilds its base only after its middle segment passes `max(b/4, 1024)` entries (the old rule was `max(64, b/8)` for the delta).
- The three tiers find the same spans as a fresh build (`a_layered_dict_answers_as_a_fresh_build`, extended to three tiers; a session equality test with probe texts naming base, middle and top values).

**Eager drop (written into engine spec §6.5).** Task 7e's rule cleared a cache whose evicted values were still in it at the next read once `churn_limit` writes had passed. The drop is now **eager**: at the write that passes the limit, every tier is dropped, so an evicted base value's forms and leak patterns leave at exactly that write. This is stricter than the read-time wording of the first §6.5 text. A consequence: for a vault working set with dead entries, the next read after that write pays a full build, as before. Pinned by `an_evicted_base_value_leaves_within_churn_limit_writes` and `an_evicted_middle_tier_value_leaves_with_the_tier`.

**Base-rebuild counts, `offline`, 71 requests (1 cold, 50 added turns, 20 streamed), head, instrumented copy at load 18.8 to 20.5:**

| builder | turns 1 to 50 | streamed turns | cold turn | whole run |
|---|---|---|---|---|
| `StoreDictCache` base rebuild | 0 | 1 (136.7 ms) | 6 | 7 (p50 62.2 ms, p99 136.7 ms) |
| `StoreDictCache` middle merge | 4 | 1 | 16 | 21 (p50 10.9 ms, p99 23.3 ms) |
| `StoreDictCache` top build | 50 | 21 | 226 | 297 (p50 2.7 ms, p99 5.7 ms) |
| `Session::closure_dict` base | 1 (54.9 ms) | 1 (69.0 ms) | 1 | 3 |
| `Session::closure_dict` middle | 4 | 1 | – | 5 (p50 7.1 ms, p99 13.8 ms) |
| `Session::closure_dict` delta | 45 | 18 | – | 63 |

In the 70 warm requests the `StoreDictCache` base is rebuilt once, against 4 at `182d6ed` (Task 0, a different load, so the counts are comparable and the milliseconds are not). The session base is rebuilt twice in the warm requests, against at least 2 at `182d6ed` (Task 0 reports only the two in the top decile); the session base rebuild is not clearly reduced by the tiers. The `support-email` runs: base rebuilds p50 22.5 and 23.2 ms (p99 39.9 and 44.4 ms, n = 3 each), middle merges p50 12.4 and 12.9 ms (p99 18.9 and 18.5 ms, n = 8 each).

**`offline` p95, A/B at load 6.2 to 6.9:** baseline `41e87d4` 119.1 and 132.4 ms, head 53.8 and 53.0 ms; p50 91.3 and 91.7 against 44.4 and 42.6 ms. The gap p95 minus p50 fell from 28 and 41 ms to 9 and 10 ms. This is the combined effect of Phase B and the tiers; the two were not timed apart. The older `offline` p95 comparison in `2026-10-09-l3-engine-proxy.md` (about 93 against 68 ms, a different session and load) is not comparable with this table.

**Merge cost, reported apart from the base rebuilds.** Each merge rebuilds the whole middle tier, at most a quarter of the base. On the bench the merge p99 is 18.9 and 18.5 ms in the two instrumented `support-email` runs and 23.3 ms in the `offline` run. The 14 007-entry session store belongs to `offline` only, measured in `2026-10-09-l3-engine-proxy.md`, "Proxy, `offline` profile, at `7a9b40c`"; this item's runs did not count entries, and Task 0 measured `offline` base rebuilds at 16 000 to 17 000 patterns. The `offline` base rebuild p99 is 136.7 ms (`support-email`: 39.9 and 44.4 ms). It grows with very large namespaces, because the middle tier grows with the base; the bench did not measure that. It is a deferred residual.

## Phase B: the leak index on the store

**Before (Task 0, `182d6ed`, load 9.5 to 16.5).** `check_leak` rebuilt the leak patterns and an Aho-Corasick automaton over the whole store on every call: 30.3 ms per call at a store of about 6 100 patterns (build linear in entries: about 1.2 ms under 500, 13 ms at 2 500, 34 ms at 6 500, 86 ms at 16 000), more than 99.8 % of `check_leak`; the search itself was under 0.1 ms. That build was **64.0 % of an `offline` turn** (84.7 % of its engine time) and 2.6 to 3.7 % of a `support-email` turn, where the full re-runs dominate. It would have been about 90 % of a projected leaf.

**After (head, instrumented copy, load 20.5 to 31.5).** The index answered **every** check: 1 172 of 1 172 `check_leak` calls (projection 237 + 242, engine side 104 + 120 + 469), **0 stale, 0 per-call fallbacks, 0 failed builds**. Per call: p50 0.1 to 0.7 ms on `support-email` (outside projection) and 0.35 to 1.44 ms on `offline`; p95 up to 1.1 ms on `support-email` and 2.2 ms on `offline`. Share of the `offline` turns 1 to 50: 61.4 ms of 1 955 ms summed request time, **3.1 %** (64.0 % before). Share of a projection: 6.7 % and 8.8 % (above). The bench line `leak index  stale N  failed M` printed `stale 0  failed 0` in every run: the 5 + 5 shadow-build bench runs (both families), the 6 head A/B runs and the head held-out run.

`leak_index_stale` is 0 in every run. Anything else would name a write path that does not note its write in `StoreDictCache`; none does. A counted failed build (`LEAK_INDEX_FAILED`) is 0 too. Both are process-wide counters, counts only.

**Where it lives (integrator L69, L72).** Inside `StoreDictCache`, reached through the defaulted `TokenStore::leak_index` hook and `Verifier::verify_with`. Not on `Engine`, in a per-request scratch, or in a static. A caller holds a `LeakIndex` for one call only. Patterns are `Zeroizing`; `Debug` prints counts.

**Freshness: ruling L2-20.** The integrator asked that the index be "invalidated by the store generation". It is satisfied by two things together: the index is cleared on every path that notes a write or clears the cache (the `note_*` and `clear` lifetime), and `LeakIndex::covers` checks the index against the store's own entries and removed values **on every call**, so a write path that misses a note costs a per-call build (counted), never a leak. There is no separate generation counter.

**Lifetime tests that pin L69.**
- Core `consistency.rs`: `a_leak_index_answers_as_check_leak`, `a_leak_index_through_aliases_answers_as_check_leak`, `a_write_the_cache_never_saw_is_still_a_leak`, `a_failed_index_build_still_checks_leaks` (asserts the failed counter rose), `the_leak_index_is_built_once_while_the_store_is_unchanged` (reuse is detected by a build counter), `a_contexts_leak_index_drops_with_the_context`, `leak_index_debug_prints_counts_only`.
- Vault `tests/namespace.rs` `the_leak_index_lives_with_the_working_set` (forget, rotation, closed dataset, an evicted value is not reported, handle drop; asserts `covers`, so the index answered, not the fallback) and `tests/epochs.rs` `an_evicted_closed_epoch_entry_leaves_no_pattern_in_the_leak_index` (closed-epoch LRU eviction).
- Proxy `session.rs`: `a_views_leak_index_covers_every_view_entry` and a reuse check by `Arc::ptr_eq` of the view's dataset layer.
- Owner hashes key on `(removed, EntityKind, value)`, not on the kind label, so `Custom("PERSON")` and `Person` cannot collide (ruling L2-18); a collision would have been a false-negative path in `covers`.
- Known limit, deferred: the view's dataset layer is keyed by entry count; a provenance switch at the same count falls back to a per-call build. Safe, costs latency only.

## L72: the canonical reason order

The leak check now returns its `Leak` reasons, one per kind as before, sorted by (first match start, end, kind) on every path, including the per-call build. The integrator allowed this on two conditions.

**Condition 1: verdict and reason set equal today's on every eval corpus.** Release build with `--features leak-crosscheck` (test-only, off by default, never in a release or default build); at every leak check the old and the new path both run and a `leak-crosscheck:` line is printed on any difference in verdict or reason set. `crosscheck_diffs` over the stderr lines:

| run | rc | diffs | wall (s) | 1-minute load at start |
|---|---|---|---|---|
| `eval --profile support-email` (with baseline) | 0 | 0 | 391 | 19.77 |
| `eval --profile strict` | 0 | 0 | 346 | 26.39 |
| `eval --profile thorough` | 0 | 0 | 454 | 22.89 |
| `eval --profile offline` | 0 | 0 | 3 | 21.69 |
| held-out `support-email` | 0 | 0 | 32 | 16.45 |
| held-out `strict` | 0 | 0 | 54 | 24.30 |
| `--cases-only` safety `support-email` | 0 | 0 | 10 | 24.35 |
| `--cases-only` safety `strict` | 0 | 0 | 12 | 24.52 |
| `--sequences` `support-email` | 0 | 0 | 24 | 21.14 |
| `--sequences` `strict` | 0 | 0 | 23 | 16.97 |

**Total: 10 runs, rc 0 each, 0 differences.** Condition 1 is met. (The first of these runs, `support-email`, was also run in Task 5; the other nine had to wait for Task 7's release session, ruling L2-16.) Wall times are load-inflated.

**Condition 2: no consumer depends on reason order.** `rg -n "reasons|\.kinds|CheckId::Leak|dedup_kinds|fn labels|checks" crates/` (429 hit lines), grouped by consumer. Only the order of multi-kind `Leak` reasons changed. A `Fail` from the second pass carries one check type, so the order of check ids does not change.

| consumer | how it uses reasons | verdict |
|---|---|---|
| core `engine.rs` `dedup_kinds`, `Outcome::Blocked { reasons, kinds }` | first-seen order, so `kinds` follows reason order | order-preserving carrier, no decision on it |
| core `engine.rs` retry decision (`settle`) | any `Fail` retries | no order dependence |
| core `engine/project.rs` phase 1 | `has(CheckId::Leak)`, a set test | no order dependence |
| proxy `pipeline.rs` `leak_only` | all checks are `Leak`, a set test | no order dependence |
| proxy `pipeline.rs` `placeholder(kinds)`, `Prepared.withheld`, `labels`, dedup | the kind list is **visible text** in a withheld tool result and in the withheld record | visible kind order can change for a multi-kind leak; privacy-neutral (the kinds are the same) |
| proxy `error.rs` refusal messages (`blocked by inumaki (kinds: …)`), `handler.rs` events, `host.rs` `ProxyEvent::{Withheld, Refused}` | print kinds | visible kind order only |
| inumakid `api/error.rs` `privacy_block` (451 body), `proxy_host.rs` `kind_counts`/`kind_ones` (activity records), `service.rs` `CachedResult`/`blocked_result`, `hook.rs` | carry or print kinds and checks | visible kind order only |
| inumakid `service.rs` `sanitize_names` | on a verifier veto of a file name's spaced variant, takes `reasons.into_iter().next()` as the single withheld reason | **the one first-element consumer.** For a multi-kind leak, *which* `Leak` kind is recorded for that name can change. The check id stays `Leak` and the name is withheld either way. Accepted by the integrator (L80) as a content-free label change; deterministic; no `inumakid` change |
| vault `activity.rs` (journal records, notifications), gateway `handler.rs`/`content.rs`/`service.rs` (`blocked_text`, `withheld_text`, MCP error data), mirror `pipeline.rs` `add_kinds`, hook `lib.rs`, cli `tokenize.rs`/`sanitize.rs`/`activity.rs`/`mail_tasks.rs`, client types | accumulate, print or carry kinds as given | visible order only |
| eval `metrics.rs` | sorts and de-duplicates checks and kinds | no order dependence |

No test asserts the order of a multi-kind `Leak` list (the matches of `rg -n "Leak" --type rust crates | rg "vec!\[|assert_eq"` are single-check lists, check-id orders from fake verifiers, or `Abandon::Leak`); no test needed an update. **Condition 2 is met**: no consumer depends on reason order other than the visible kind-list order (placeholders, refusal texts, records) and the one `sanitize_names` label.

## Held-out bench

`INUMAKI_BENCH_FAMILY=held-out` refuses turn 0 with `blocked by inumaki (kinds: CONTRACT_ID; checks: Regex)` (451) on all 51 turns, on head, for `support-email` MAILS=0 and for `offline`. The other three held-out shadow runs (MAILS=5, transformed, `strict`) refused turn 0 on `PERSON/Ner` instead; they were not diagnosed further. The first A/B attempt looked like a regression: baseline `41e87d4` served all 51 turns (rc 0) while head refused 51 of 51 (rc 3). **That comparison was invalid** and the "RESULT" line in the raw file that calls the refusal "NOT pre-existing" is superseded by the last section of the raw file: baseline `41e87d4`'s bench has no `INUMAKI_BENCH_FAMILY` knob (added in Task 3), so its "held-out" run silently ran the tuning corpus. With a throwaway patch that adds only the knob to the baseline, the baseline refuses 51 of 51 turns on turn 0 with `CONTRACT_ID; Regex`, identical to head (ruling L2-23). **Pre-existing, not caused by 4d.** The held-out corpus's system text carries a `CONTRACT_ID` that the `support-email` profile refuses. It is a residual for the integrator and lane L3. Consequence: this item has no held-out bench measurement; the held-out documents are covered by the harness (800 documents include 400 held-out).

## Deferred residuals

None of these is built here; each is recorded in M8 spec §20 and in threat model (aa).

- **Engine-verified (same-request) projection.** Cold turns and multi-leaf requests still use the full engine for leaves whose text was never sent. Projecting them needs: the settling pass's `Sanitized` (`process_detailed`) so P carries T0's real `Preserve` and `Escalate` replacements; a guard (G3) that abandons when a projected decision overlaps, or is joined by neighbour punctuation to, such a replacement (that is exactly where `merge_redaction` widens, and the D1 classes above show it); neighbour guards across one line break; and a differential harness with word-level D1 of at least about 2 000 cases showing **zero** divergences before the class is switched on. The hit premise does not cover these leaves.
- **Mirror and `inumakid` wiring of `Engine::project`.** The daemon re-runs a block through the full engine in two places, the batch-end store-form check (`settle_store_changes`, L55) and a failed cache-hit re-check (`recheck`, L54). The mirror's `support-email` latency (release p50 6.2 s, p95 12.8 s, max 56 s at load about 9; sanitize p50 9.7 s over 13 files) is not addressed by 4d: its p50 matches two NER models over about 20 KB on CPU, which is probably the base model cost. The hit premise does not hold in the daemon, so projection there would be the engine-verified case above.
- **Closed-epoch eviction rebuilds in the vault namespace.** An eviction of a closed-epoch entry still clears the cache at once (Task 7e's privacy choice) and forces a base rebuild. Only vault namespaces have epochs; the proxy's session context has none. A fix keeps closed-epoch entries in their own small layer and touches `inumaki-vault` and `consistency.rs`.
- **Merge cost at very large namespaces:** the middle tier is rebuilt whole on each merge (see residual (a)).
- **The cold turn.** Two NER models over a 20 KB system prompt on CPU, 10.8 to 25.9 s on `support-email` on both builds. The remaining full re-runs are cold-turn misses only.
- **The held-out bench family** refuses turn 0 on `CONTRACT_ID` / `Regex` on baseline and head alike.
- **The transformed bench** (`INUMAKI_BENCH_TRANSFORMS=1`) still refuses 29 of 51 turns on `PERSON/Ner` (L3's open item).

## Implementation details that fill gaps in the plan

- `minted` counts `after - before` on the raw store, not through the alias wrapper. The alias wrapper is scoped through `Engine::with_aliases`. The projection kit (the verifier and regex detector, no originals) is keyed by the profile name in the per-request `ProjectionScratch`.
- A `Projected` with zero replacements counts as abandoned `Empty`; with mints it is `Fail::Internal`.
- Phase B owner hashes key on `EntityKind` (ruling L2-18). A failed index build is counted, not silent (`LEAK_INDEX_FAILED`; the bench line prints stale and failed).
- Tier tests check each transition and run under 10 s in debug (5.0 s, 2.4 s and 7.0 s); the plan's 4 000-and-100 literals were superseded (ruling L2-19). The test shape is not part of the spec.

## Commands and exit codes

Head `695d13e` (rebased later as `6e255c2`, lane code identical; see the top of this document); baseline `main` at `41e87d4`. All exit codes are as recorded in the raw file; all 0 unless noted.

| step | command | rc |
|---|---|---|
| checks | `cargo check -p inumaki-core -p inumaki-proxy -p inumaki-cli` | 0 |
| | `cargo test -p inumaki-core --lib engine::project::` | 0 (10 passed) |
| | `cargo test -p inumaki-proxy --lib -- pipeline_tests::projection:: pipeline_tests::closure:: pipeline_tests::released:: closure::` | 0 (32 passed) |
| | `cargo test -p inumaki-proxy --features closure-shadow --lib -- shadow:: status:: pipeline_tests::projection::` | 0 (17 passed) |
| | `cargo test -p inumaki-core --lib -- consistency:: verify::` | 0 (52 passed) |
| | `cargo test -p inumaki-vault --test namespace --test epochs` | 0 (11 + 16 passed) |
| shadow and crosscheck build | `CARGO_TARGET_DIR=target-shadow cargo build --release -q -p inumaki-cli --features closure-shadow,leak-crosscheck` | 0 (8 min 35 s, load about 22) |
| crosscheck | the ten `eval` runs in the table above, with the `target-shadow` binary | 0 each |
| shadow bench | `INUMAKI_BENCH_MAILS=0`, `=5`, `INUMAKI_BENCH_TRANSFORMS=1 INUMAKI_BENCH_MAILS=5` with `bench --via-proxy --profile support-email`; `--profile strict`; `--profile offline` | 0 each |
| shadow bench, held-out | the same five with `INUMAKI_BENCH_FAMILY=held-out` | 3 each (first turn refused) |
| harness | `INUMAKI_PROJECTION_HARNESS=1 INUMAKI_PROJECTION_SHARD=i/12 cargo test --release -p inumaki-proxy --features models-tests --test projection_equivalence`, i = 0 to 11 | 0 each |
| A/B | `bench --via-proxy` as in the table above, baseline and head, 12 runs | 0 each |
| held-out baseline, head | `INUMAKI_BENCH_FAMILY=held-out INUMAKI_BENCH_MAILS=0 bench --via-proxy --profile support-email` (baseline with the knob patch) | 3 and 3 |
| per-stage | the instrumented throwaway copy of head, never committed | – |
| harness smoke, leak check on P (final review fix wave, at `550f8c7`) | `INUMAKI_PROJECTION_HARNESS=1 INUMAKI_PROJECTION_DOCS=10 cargo test -p inumaki-proxy --features models-tests --test projection_equivalence -- --nocapture` | 0 |

The full workspace gate (Task 9) runs after this document and appends its results below.

## Full workspace gate (Task 9)

Head `7644f1e` on `l2/closure-projection`, rebased on `main` at `a3a843f`. The A/B baseline is still `BASELINE_SHA`. The evals and the A/B stand from the pre-rebase gate on `e72ef01` (the engine's `process` path is unchanged, and the rebase changed only comments in `configs/default.toml` and no detection). Models: `INUMAKI_MODELS_DIR="$HOME/Library/Application Support/inumaki/models"`. The machine was shared and heavily loaded (load average about 30), so `cargo test` was split per crate to stay inside the 10-minute tool limit.

| step | command | rc |
|---|---|---|
| 1 | `bash scripts/check-docs.sh` | 0 |
| 1 | `cargo fmt --all -- --check` | 0 |
| 1 | `cargo clippy --workspace --all-targets -- -D warnings` | 0 |
| 1 | `cargo clippy -p inumaki-proxy -p inumaki-cli --all-targets --features closure-shadow -- -D warnings` | 0 |
| 1 | `cargo clippy -p inumaki-core -p inumaki-cli --all-targets --features leak-crosscheck -- -D warnings` | 0 |
| 1 | default build carries no shadow mode and no leak cross-check (both `cargo tree` counts are 0) | 0 each |
| 1 | `cargo test -p <crate>` for each of the 14 workspace crates: core 402, adapters 79, client 11, eval 63, mail 52, models 50, proxy 240, vault 131, gateway 85, mirror 104, mcp 1, hook 22 (1 ignored), cli 67 (1 ignored), inumakid 316 (3 ignored) passed, 0 failed | 0 each |
| 2 | release build and the ten eval gates | not re-run; stand from the pre-rebase gate on `e72ef01` (all exit 0) |
| 3 | `cargo test -p inumaki-models --features models-tests` | 0 (62 passed) |
| 3 | `cargo test -p inumaki-proxy --features models-tests` | 0 (241 passed; the harness skips without `INUMAKI_PROJECTION_HARNESS`) |
| 3 | `cargo test -p inumakid --features models-tests --no-fail-fast -- --skip mirror_latency_20kb` | 0 (321 passed, 5 ignored) |

`mirror_latency_20kb` was skipped: it is not lane scope (this lane changes no mirror or `inumakid` code, and the mirror uses the unchanged `Engine::process`). It is a latency measurement, not a gate. On the pre-rebase gate it failed twice with a 60 s timeout at load averages of 27 to 57. The controller runs it separately at load below 8.
