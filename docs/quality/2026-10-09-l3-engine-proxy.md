# L3 engine follow-up for the proxy: final measurement (2026-10-10)

Plan `2026-10-09-engine-proxy-followup` (lane L3, step 2), Tasks 1–9 plus the follow-ups 4b, 4c, 7b, 7c and 7d, measured on the reference machine (`macos-aarch64`, Apple Silicon), release build of commit `7a9b40c` (branch `l3/engine-proxy`, rebased on main `496f988`), seed 42, `INUMAKI_MODELS_DIR` at the pinned models. Every report is a committed `docs/quality/2026-10-09-l3-engine-proxy-*.json` (counts, rates, provenance; never text). Raw benches: `2026-10-09-l3-bench-proxy.txt` and `2026-10-09-l3-bench-offline.txt`.

**Goal of the plan:** the `support-email` profile stops refusing ordinary generated letters through the model-API proxy, without lowering recall or raising any leak count. Result: the untransformed proxy bench refuses 0 of 51 turns (31 and 51 before); every leak count fell or stayed equal in every eval run; no gated kind's recall fell, and PERSON, CITY and STREET_ADDRESS rose (ORGANIZATION too on the tuning corpus; held-out ORGANIZATION and every identifier kind are unchanged). The transformed proxy bench still refuses 29 of 51 turns (51 before), a missed target.

The evals ran one at a time while other agents' jobs loaded the machine (1-minute load 7 to 19), so their latency fields are not compared below. Timing runs were made only at a 1-minute load below 8 and carry their load.

## Before and after

Before is the plan base `afa0422`, whose engine and configuration equal plan 4a's final state, so the `2026-10-09-4a-after-*.json` reports are the before values (the plan's "Before numbers"). A cell with one value did not change. `consistency_redactions` is the number of clear store-value copies the new referential-consistency pass folded into the decisions (engine spec §6.4); it is counted on the engine path only, so the service, `tool-json` and sequence runs report 0 by construction.

| report | docs | accepted leak | block | verifier FN | verifier FP | PERSON recall | STREET recall | CITY recall | wrong restorations | coref recoverable | consistency_redactions |
|---|---|---|---|---|---|---|---|---|---|---|---|
| support-email | 2067 | 1.92% (33/1723) → 0.54% (11/2040) | 16.64% → 1.31% | 13.17% | 2.34% | 85.4% → 93.9% | 99.5% → 99.8% | 4.6% → 77.8% | 0 | 249/520 → 310/635 | 374 |
| strict | 2067 | 0.94% (16/1708) → 0.20% (4/2049) | 17.37% → 0.87% | 13.17% | 2.34% | 85.4% → 93.9% | 99.5% → 99.8% | 4.6% → 77.8% | 0 | 259/514 → 316/644 | 42 |
| held-out-support-email | 200 | 7.79% (12/154) → 0.00% (0/196) | 23.00% → 2.00% | 9.87% | 30.00% | 77.9% → 85.6% | 99.5% → 100.0% | 5.4% → 73.0% | 0 | 47/62 → 59/75 | 43 |
| held-out-strict | 200 | 4.90% (7/143) → 0.00% (0/195) | 28.50% → 2.50% | 9.87% | 30.00% | 77.9% → 85.6% | 99.5% → 100.0% | 5.4% → 73.0% | 0 | 45/58 → 58/73 | 52 |
| offline | 2067 | 23.73% (449/1892) → 19.74% (406/2057) | 8.47% → 0.48% | 35.23% | 0.44% | 65.9% → 75.0% | 99.1% → 99.4% | 0.0% → 76.3% | 0 | 38/530 → 60/648 | 736 |
| thorough | 2067 | 0.00% (0/121) → 0.00% (0/193) | 94.15% → 90.66% | 0.00% | 98.34% → 97.32% | 85.4% → 93.9% | 99.5% → 99.8% | 4.6% → 77.8% | 0 | 5/17 → 8/32 | 58 |
| service-support-email | 2067 | 0.93% (9/967) → 0.15% (3/2060) | 53.22% → 0.34% | 12.88% | 2.73% | 85.4% → 93.9% | 99.5% → 99.8% | 4.6% → 77.8% | 0 | 108/282 → 285/648 | – |
| service-strict | 2067 | 0.95% (9/952) → 0.05% (1/2060) | 53.94% → 0.34% | 12.88% | 2.73% | 85.4% → 93.9% | 99.5% → 99.8% | 4.6% → 77.8% | 0 | 105/278 → 286/648 | – |
| service-held-out-support-email | 200 | 2.13% (2/94) → 0.00% (0/199) | 53.00% → 0.50% | 9.87% | 29.50% | 77.9% → 85.6% | 99.5% → 100.0% | 5.4% → 73.0% | 0 | 30/41 → 59/78 | – |
| service-held-out-strict | 200 | 2.15% (2/93) → 0.00% (0/198) | 53.50% → 1.00% | 9.87% | 29.50% | 77.9% → 85.6% | 99.5% → 100.0% | 5.4% → 73.0% | 0 | 29/40 → 58/76 | – |
| tool-json-support-email | 300 | 0.00% (0/86) → 0.00% (0/299) | 71.33% → 0.33% | – | – | – | – | – | 0 | – | – |
| tool-json-strict | 300 | 0.00% (0/85) → 0.00% (0/297) | 71.67% → 1.00% | – | – | – | – | – | 0 | – | – |
| tool-json-held-out-support-email | 300 | 1.57% (2/127) → 0.00% (0/299) | 57.67% → 0.33% | – | – | – | – | – | 0 | – | – |
| tool-json-held-out-strict | 300 | 1.59% (2/126) → 0.00% (0/299) | 58.00% → 0.33% | – | – | – | – | – | 0 | – | – |
| sequence-support-email | 300 | 0.39% (1/256) → 0.33% (1/299) | 14.67% → 0.33% | – | – | – | – | – | 0 | 67/72 → 69/74 | – |
| sequence-strict | 300 | 0.00% (0/255) → 0.00% (0/299) | 15.00% → 0.33% | – | – | – | – | – | 0 | 67/72 → 69/74 | – |

Other numbers from the same reports:

- **Safety suite** (`--cases-only --targets crates/inumaki-eval/targets/safety.toml`, 67 hand-written cases): exit 0 on both profiles, 0 accepted leaks, 1 blocked case each.
- **Sequences** (`--targets crates/inumaki-eval/targets/sequence.toml`, 300 steps): exit 0 on both profiles. 0 wrong links in every labelled class, 0 restore errors, 0 tokens reused after rotation, every pre-rotation token resolved within the grace period (317 of 317 `support-email`, 383 of 383 `strict`). 5 of 6 expected cache repeats were served from the cache (6 of 6 in plan 4a); the target is met.
- **Verifier false positives by check**, `support-email` tuning: NER 39, leak 7, regex 2 (unchanged against plan 4a); held-out: regex 51, NER 8, leak 1. `wrong_links` stays 1 per corpus (plan 4a's diagnosed same-first-name document).
- **`tool_json`**: no accepted document with residue in any of the four runs. The plan-4a service-path residue (held-out: 2 documents per profile with partial STREET_ADDRESS residue) is gone, as Tasks 2–4 expected. The plan's engine-path `tool_json` row (1 CUSTOMER_ID residue) was not re-measured: all four runs here use `--via-service`.

### Accepted leak, integrator gate (no increase)

| corpus | profile | before | after |
|---|---|---|---|
| tuning | `support-email` | 33 docs, 1.92% | 11 docs, 0.54% |
| tuning | `strict` | 16 docs, 0.94% | 4 docs, 0.20% |
| held-out | `support-email` | 12 docs, 7.79% | 0 docs, 0.00% |
| held-out | `strict` | 7 docs, 4.90% | 0 docs, 0.00% |

Against the last numbers in the plan's ledger (Task 9 fix round 1: 11, 4, 0, 0; `offline` 406; `thorough` 0; service 3) nothing moved.

### Recall gains

PERSON recall rose from 85.4% to 93.9% on the tuning corpus and from 77.9% to 85.6% on the held-out corpus (sign-off anchors, the retry tokenizing the uncertain band, the line split, surname continuation). CITY recall rose from 4.6% to 77.8% (tuning) and from 5.4% to 73.0% (held-out), from the town-after-postal-code rule (Task 7b). ORGANIZATION recall 51.0% → 60.2%, STREET_ADDRESS 99.5% → 99.8% (tuning) and 99.5% → 100.0% (held-out). `offline` (no models): PERSON 65.9% → 75.0%, CITY 0.0% → 76.3%.

### The service path's residue

`--via-service` `support-email` releases 3 documents with residue (9 before; 5 at the plan's checkpoint A: 3 DATE_OF_BIRTH, 2 PERSON). Shapes only, from a throwaway build that printed character-class shapes of each leaked gold span and its line (never text):

- **PERSON, 1 document** (German): a one-word capitalized first name on the same line after a two-letter upper-case sign-off abbreviation (`LG`-shaped), nothing after it on the line.
- **DATE_OF_BIRTH, 2 documents** (German): a `d.d.dddd`-shaped date in the middle of a sentence, after a capitalized word with a colon and two lower-case words, followed on the same line by a comma and a street-and-number fragment. Not recognized as a date of birth; `support-email` preserves DATE. Under `strict`, which tokenizes DATE, neither leaks: `service-strict` releases 1 document, with PERSON residue only.

## Proxy bench

`inumaki bench --via-proxy`, raw output in `2026-10-09-l3-bench-proxy.txt`. Before: the plan's "Before numbers" at `afa0422` (not re-run). After: `7a9b40c`, 18:43–18:58, 1-minute load 5.3–7.1.

| run | before: refused | after: refused | after: reasons | after: cold | after: added per turn p50 / p95 |
|---|---|---|---|---|---|
| `INUMAKI_BENCH_MAILS=0`, `support-email` | 31/51 (21 PERSON/Ner, 10 PERSON/Policy) | **0/51** | – | 7.8 s | 579 ms / 6.1 s |
| `INUMAKI_BENCH_MAILS=5`, `support-email` | 51/51 (PERSON/Policy) | **0/51** | – | 14.0 s | 589 ms / 6.3 s |
| `INUMAKI_BENCH_TRANSFORMS=1 INUMAKI_BENCH_MAILS=5`, `support-email` | 51/51 (PERSON/Policy) | **29/51** | turns 0–5, 7–25: PERSON/Ner (25); turns 6, 37, 43, 48: PERSON/Leak+Policy (4) | refused | 723 ms / 10.2 s (22 served) |
| `offline` (193 mails) | 0/51; cold 9.9 s, p50 60.8 ms (load 10–12) | 0/51 | – | 12.6 s | 143 ms / 160 ms |

The plan's success criterion was at most 1 of 51 refused in each of the three `support-email` runs. Met for the two untransformed runs, **missed for the transformed run** (29/51). The per-turn reasons come from a throwaway build that printed each turn's status and refusal message (kinds and check ids only). The 25 `PERSON/Ner` turns are the verifier's mBERT NER re-scan tagging a word in the lower-cased transformed history as a person; they are not one of the shapes Tasks 6 and 9 drop (a greeting, role or label word next to a token, a town after a postal code) and were not diagnosed further. The 4 `Leak+Policy` turns are leaves whose failed verdict now also reports the pass's escalation (Task 8), so the proxy refuses them instead of deferring them.

The `offline` proxy turn got slower at `7a9b40c`; Task 7e brought it back, see "Latency" (the table row above is the `7a9b40c` measurement).

## Large-store timing (plan re-review N3)

`/usr/bin/time -p inumaki eval --profile support-email --via-service` (one dataset accumulates the whole 2 067-document corpus), main `496f988` and then head, back to back. main `496f988` stands in for the plan base `afa0422` (brief Step 3b): its core and configuration equal `afa0422` except `rehydrate.rs`, and its service differs only by the released-text record of plan M8-2 (one digest insert per passed block). Raw `time -p` and uptime output, and the attribution numbers below, are in `2026-10-09-l3-bench-proxy.txt`.

| build | wall | 1-minute load start → end | per-document `latency_ms` p50 / p95 | released / blocked | accepted leak docs |
|---|---|---|---|---|---|
| main `496f988` | 246.1 s | 5.63 → 5.78 | 68.3 / 112.2 ms | 967 / 1100 | 9 |
| head `7a9b40c` | 315.0 s | 5.64 → 4.88 | 100.6 / 161.4 ms | 2060 / 7 | 3 |

**+28% wall time, over the +20% line, reported with the cause.** A throwaway build that timed every `StoreDict` build (counts and microseconds only) showed 2 223 engine builds in one such run, median 24.9 ms at a median working set of 3 880 entries (the vault's working set holds at most 4 096), 44.9 s in total: about two thirds of the 68.9 s difference. That is the per-call consistency dictionary (ruling L58, integrator L61): one `O(store)` build per new text, shared by the primary pass and the retry. The integrator recorded it as a residual for item 4d. main's engine was also cheaper per document because it never ran the pass; it blocked 1 100 documents, which still ran the engine and the retry.

**After Task 7e (ruling L62; head `2948e24`, 2026-10-11, 1-minute load 4.9 and 5.7 at the two starts).** The dictionary now lives on the store, so a text pays only for the values written since the last build. Same command, main then head back to back, in this session:

| build | wall | 1-minute load start → end | per-document `latency_ms` p50 | released / blocked | accepted leak docs |
|---|---|---|---|---|---|
| main `496f988` | 208.5 s | 4.91 → 5.79 | 57.3 ms | 967 / 1100 | 9 |
| head `2948e24` | 234.2 s | 5.65 → 4.26 | 65.1 ms | 2060 / 7 | 3 |

+12.3% wall time, inside the +20% line (it was +28%). Released, blocked and leak-document counts equal the `7a9b40c` run. Main's wall time was lower in this session than in the first one (246.1 s) because the machine was less loaded; compare rows within a session only. The p95 values of this run are in the raw file only; no claim is made about them here.

## Latency

Docs elsewhere carry no absolute latency claim until the integrator's quiet-machine rerun; every number here names its load.

**Offline detect** (`bench --profile offline`, 200 documents, `2026-10-09-l3-bench-offline.txt`), load 5.6–6.3, A/B against main alternated: detect p50 0.2 ms and p95 0.4 ms on both builds; process p50 0.3 ms (main) and 0.4 ms (head) in both pairs, p95 0.6 and 0.7 ms. The +0.1 ms process cost is the consistency pass. The plan-4a question about `offline`'s block rate (+0.48 pt) is answered by the new block rate, 0.48% (8.47% before).

**Regex stage alone** (throwaway build timing `RegexDetector::detect` per bench document; two alternated rounds at load 5.6–5.8): p50 0.075–0.084 ms on main, 0.083–0.091 ms on head (about +10%, the new street shapes and the town rule), p95 0.15–0.17 and 0.17–0.19 ms. **No catastrophic backtracking:** one line of capitalized `-er` words and four-digit numbers with no line break and no street suffix, so `ADDRESS_PATTERN` must reject every candidate prefix. For 128 KB, 256 KB, 512 KB, 1 MB and 2 MB: main 0.2 / 0.4 / 0.8 / 1.6 / 3.0 ms (run 1) and 0.3 / 0.5 / 0.8 / 1.6 / 2.9 ms (run 2); head 0.2 / 0.4 / 0.8 / 1.5 / 3.0 ms and 0.2 / 0.4 / 0.7 / 1.6 / 3.2 ms. Linear on both builds. The whole regex detector on the same text is linear too: 1 MB in 441.7 and 482.8 ms on main, 530.9 and 554.9 ms on head (2 MB: 915.1 / 939.3 and 1045.1 / 1165.5 ms); the text yields about 15 000 spans per MB on both.

**The Task 4 latency pairs** (the plan asked for `bench --profile support-email` and `bench --profile offline` before and after Task 4; Task 4 could not measure under load). Main against head, alternated, load 5.2–6.0: `support-email` process p50 43.0 → 51.1 ms and 50.5 → 52.3 ms (detect 20.7 → 23.1 and 23.2 → 23.3 ms); `offline` as above. The bench uses a fresh store per document, so it shows the pass's fixed cost, not the store-size cost.

**Proxy, `offline` profile, at `7a9b40c`** (A/B against main, alternated, load 5.3–5.8): added per turn p50 67.7 and 69.6 ms on main, 139.9 and 146.5 ms on head; cold 10.9 and 11.8 s against 12.9 and 13.0 s. Over +20%. Cause, from the `StoreDict` timing build (one run at load 9.3 → 7.6, used for attribution only): the session store reaches 14 007 entries, and each new leaf's `StoreDict` build then takes a median 48.6 ms, about two thirds of the added per-turn time. Same residual as the large-store timing (item 4d).

**Proxy, `offline` profile, after Task 7e** (head `2948e24`, A/B against main `496f988`, alternated main, head, main, head, 21:12, 1-minute load 5.2–6.4 at each start): added per turn p50 62.2 and 62.1 ms on main, 71.2 and 71.6 ms on head (+14.7%, inside the +20% line); cold 10.3 and 10.1 s on main, 5.8 and 5.8 s on head. Refused turns 0/51 and the incremental cache (21 900 hits, 438 misses) are unchanged from `7a9b40c`. What changed: the `StoreDict` is no longer built per call but kept by the session context (and, in the service, by the namespace handle) and extended by the values written since, so the per-turn cost no longer grows with the 14 000-entry session store (the cold turn is also shorter; not diagnosed further). No claim is made about p95 here; the raw output is in `2026-10-09-l3-bench-proxy.txt`. The head `offline` p95 (about 93 against 68 ms on main) is undiagnosed and carried to item 4d. Main was faster in this session than in the first (67.7 and 69.6 ms) because the machine was less loaded.

**Proxy, `support-email` profile**, summarized from the latency diagnosis of this plan (`.superpowers/sdd/2026-10-09-engine-proxy-followup/latency-diag.md`, not committed):

- **Warm turn.** A served turn whose only miss is the new mail costs p50 0.5–0.65 s at load about 6 (head 0.62 s, main 0.51 s served, round 2). Per 2 KB leaf: GLiNER sanitizer pass 230–380 ms, verifier NER re-scan 340–560 ms (twice when the `strict` retry runs); policy, sanitize, leak check and linker under 20 ms together. Today's runs: 579 and 589 ms at load 5.9–7.1. **This is a product problem (integrator):** two NER models on CPU per leaf, not a regression of this plan; `offline` has neither pass.
- **Cold turn** (20 KB system prompt plus the first mail): 9–13 s on both builds at load 6–25 (GLiNER about 3.4 s, verifier NER about 4.3 s, plus a retry with a second verifier NER). Today: 7.8 s (`MAILS=0`) and 14.0 s (`MAILS=5`).
- **Tail.** Every turn over 2 s is a step-6b closure turn: a new mail mints a value that sits in clear in many cached history leaves, and the closure re-runs each such leaf through the whole engine (0.6–1.0 s per leaf; 75–80% of head's engine time). main has the same mechanism and tail (worst turns 21–37 s); its served p95 only looked better because it refused 31 and 51 of 51 turns. Before Task 7d the four largest tail turns were greeting words a `strict` retry had minted. After 7d (greeting-only values are no leak pattern and no closure trigger), at load 7.5–11: p95 20.1 → 9.0 s (`MAILS=0`) and 20.5 → 7.3 s (`MAILS=5`), no greeting tail turn left. Today's runs, load 5.9–7.1: p95 6.1 and 6.3 s. What remains are real values over many leaves and two template-word false positives. Re-running only the deterministic checks on a cached leaf that merely gained a token (instead of the whole engine) is the integrator's item **"4d closure projection"**; projected p95 about 1 s, not measured.
- **Branch-new per-pass cost:** the `StoreDict` build, about 6 µs per entry in that diagnosis (3.5 µs per entry in today's `offline` timing build), now once per call instead of twice per retried leaf (L58). It grows with the store; see the two sections above.

## Baselines

All six baseline gates exited 0 against the committed baselines. Compared field by field (every gated field: document count, leak rate, accepted leak rate, block rate, verifier FN rate, recall per kind), each of the six is equal or better on every field and moved, so all six were re-recorded with `--write-baseline` (the re-recording runs reproduced the gate reports' counts exactly). Fields that moved:

| baseline | leak rate | accepted leak rate | block rate | verifier FN | recall that moved |
|---|---|---|---|---|---|
| `support-email` | 1.60% → 0.53% | 1.92% → 0.54% | 16.64% → 1.31% | = | CITY 4.6 → 77.8%, ORGANIZATION 51.0 → 60.2%, PERSON 85.4 → 93.9%, STREET_ADDRESS 99.5 → 99.8% |
| `strict` | 0.77% → 0.19% | 0.94% → 0.20% | 17.37% → 0.87% | = | same four as `support-email` (PERSON 93.9%) |
| `thorough` | = (0) | = (0) | 94.15% → 90.66% | = (0) | same four |
| `offline` | 22.21% → 19.64% | 24.13% → 19.74% | 7.98% → 0.48% | 39.93% → 35.23% | CITY 0.0 → 76.3%, PERSON 65.9 → 75.0%, STREET_ADDRESS 99.1 → 99.4% |
| `held-out-support-email` | 6.00% → 0.00% | 7.79% → 0.00% | 23.00% → 2.00% | = | CITY 5.4 → 73.0%, PERSON 77.9 → 85.6%, STREET_ADDRESS 99.5 → 100.0% |
| `held-out-strict` | 3.50% → 0.00% | 4.90% → 0.00% | 28.50% → 2.50% | = | same three |

`offline.toml` was not re-recorded in plan 4a because its block rate had risen inside the tolerance; it now falls below that baseline, so the re-record locks in no worse field. `thorough`'s 90.66% block rate is locked in as an improvement, not as a target met (see "Missed targets").

## Precision costs (recorded, not fixed)

Each costs meaning or a retry; none sends an identifier in clear.

- **Surname continuation (ruling L36).** A PERSON span ending in a gazetteer first name extends over the next same-line word. Five tuning-corpus PERSON spans end one word too long. Because the function-word list lost every word that is also a plausible name (L46, L47), the extension can absorb a preposition (`Anna in Wien` tokenizes `Anna in`) or a name-like common word, and the retry guard counts the same words as name candidates, so such a word next to a guarded span escalates it.
- **Own-line name-like words (Task 1).** A name-like common word on its own line below a sign-off is a PERSON at 0.62, even when the line starts a short sentence (`Thanks,\nWill do` yields `Will`); in lower-case text a new sign-off phrase can take the following words (`vielen dank für alles`).
- **Consistency pollution (Task 4, accepted by the integrator).** Every clear copy of a store value is tokenized, of every kind. A non-identifying word a retry minted (`Madam`, `Hallo`, `Hello` as one-word PERSON values under `strict`, ruling L50; an ORGANIZATION `Support`) is then tokenized everywhere in the context, or in the dataset for the epoch; a city or date a retry tokenized stays tokenized under a profile that preserves it. The `consistency_redactions` column counts these folds. Store hygiene is a plan 4c item.
- **Container token (Task 4, accepted by the integrator).** A known full name inside a longer accepted model PERSON span takes the container's token; rehydration restores the original byte for byte (pinned by a test).
- **`sie` and `or` stay common words (L47).** The surnames Xie and Or are not name candidates.
- **Verifier false positives.** Task 9's recall fixes (names out of the role list) cost one blocked `thorough` document and one verifier false positive each on `support-email` and held-out against Task 9's first measurement; against plan 4a the `support-email` (48/2054) and held-out (60/200) counts are unchanged.

## Missed targets

- **`thorough` block rate.** Task 9 expected "well below 87%"; measured 90.66% (1 874 of 2 067; 93.18% before Task 9, 94.15% before the plan), verifier FP 97.32% (1 999 of 2 054 clean trials). The remaining false positives are not the shapes Task 9 targets: by check NER 1 990, leak 7, regex 2; by kind PERSON 1 987, STREET_ADDRESS 549, POSTAL_CODE 1, URL 1 (a trial can fail on several). Unverified hypothesis: `thorough` retries into `thorough-strict`, which tokenizes CITY and POSTAL_CODE, so the preserved-place rule cannot apply there, and a STREET_ADDRESS hit over two adjacent placeholders is not exempt. Accepted by the integrator as measured (L57); verifier calibration is a plan 4c item.
- **Transformed proxy bench:** 29 of 51 refused (criterion: at most 1). See "Proxy bench".
- **Latency:** see "Latency": `support-email` warm turns at 0.5–0.6 s, the closure tail, and, until Task 7e, the `StoreDict` build that grew with the store (now cached on the store, see "Latency").
- **Plan 4a's PERSON recall target** (95%) is still not met: 93.9% tuning, 85.6% held-out.

## Rulings that changed scope

From the plan's ledger (`.superpowers/sdd/2026-10-09-engine-proxy-followup/progress.md`, not committed).

| Ruling | Decision | Measured effect |
|---|---|---|
| L27 (plan review C1) | The consistency pass tokenizes every store value, preserved kinds included; no leak-check skip. | parity with the proxy closure (M8 §5 step 6b) |
| L29 (re-review N1–N4) | Parts link to one store original, ambiguous parts mint their own; a `StoreDict` error fails closed; large-store timing; `consistency_redactions`. | see the tables and "Large-store timing" |
| L30, L32 | A known-entity fragment yields to a same-kind container the policy tokenizes; gate: service leak docs ≤ 9. | service 47 → 5 leak docs at checkpoint A |
| L33, L34 (Task 4b) | The `Wiener Neustädter\nStraße` recall gap is a leak, fixed with a test. | – |
| L35 (Task 4c) | The leak check keeps exact NFC legs (name parts added). | – |
| L36 | Retry guard for multi-line uncertain names; surname continuation. | held-out `support-email` leak 1 → 0 at checkpoint B |
| L39, L40 | `Escalate` outranks `Tokenize` in a merge, only under `on_uncertain = "block"`. | – |
| L41–L45 | The guard escalates only with an adjacent name candidate. | proxy `MAILS=0` 51 → 7 refused |
| L46, L47 | Function words that are plausible names leave the common-word list; `sie`, `or` kept. | `support-email` leak docs 22 → 21 |
| L48 | Model ORGANIZATION spans split too; single-line greeting spans dropped; Task 7b added (town after postal code, legal forms, signature labels). | CITY recall 4.6% → 78% |
| L49 | A misspelled one-word sign-off anchors the name below it. | `strict` leak docs 5 → 4 |
| L50 | Sign-off phrases are greeting-only; one-word spans stay with policy. | proxy `MAILS=0` 15 → 0 refused |
| L51, L53 | Signature labels are not guard candidates; the regex town yields to name parts; only `an der` joins. | – |
| L54 (Task 7c) | The cache-hit re-check scans the store forms. | about 1 in 5 cached bench documents would have been replayed with a clear copy |
| L55 | Batch-end store-form check: re-run once, then withhold. | – |
| L56 (Task 7d) | Greeting-only values are no leak pattern and no closure trigger (they stay consistency forms, measured). | proxy p95 20 → 7–9 s (load 7.5–11) |
| L57, L59 | `thorough` 90.66% accepted as measured; `NNNN Surname` stays a residual. | – |
| L58 (integrator L61) | One `StoreDict` per call, shared by the primary pass and the retry. | build cost now per call; residual for 4d |
| L62 (Task 7e) | The `StoreDict` cache lives on the store (session context, namespace handle), layered over writes since the last build. | offline proxy p50 +14.7% (was +100%); via-service eval wall +12.3% (was +28%) |
| integrator L60 | Template-word NER false positives and harness static text go to the next plan, "harness-static precision". | – |

## Residuals and carried items

Residuals are recorded in `docs/threat-model.md` ("Engine follow-up residuals") and the engine spec §6.1–§6.6.

- **Plan 4c:** store hygiene (keep greeting and other non-identifying words out of a dataset); verifier calibration for `thorough`; verifier recall on lower-case surnames with diacritics after a sign-off (L36); the service residue shapes above.
- **Item 4d (integrator):** closure projection (re-run only the deterministic checks on a cached leaf that gained a token); the per-call `StoreDict` build cost that grows with the store (closed by Task 7e, ruling L62); the head `offline` proxy p95 after 7e (about 93 against 68 ms on main), undiagnosed.
- **Next plan, "harness-static precision" (L60):** identifier-shaped PERSON spans, a role-noun stoplist, dictionary-word multi-word spans, the two template-word NER false positives, and the Codex built-in instructions that `support-email` refuses.
- **Engine residuals:** a single-block batch whose own second sanitize mints a new multi-part name (not reproduced); a surname on a later line not adjacent to a guarded span; `NNNN Surname` lines; demoted dictionary fragments in a rare partial overlap; the shared-normalizer and word-list blind spots.

## Commands and exit codes

From the worktree root, `B=target/release/inumaki`, `S=docs/quality/2026-10-09-l3-engine-proxy`, `BL=crates/inumaki-eval/baselines`; one eval at a time.

| Command | Exit |
|---|---|
| `cargo build --release -q -p inumaki-cli` | 0 |
| `$B eval --profile {support-email,strict,thorough,offline} --baseline $BL/<p>.toml --json --report-json $S-<p>.json` | 0 each |
| `$B eval --profile {support-email,strict} --held-out --baseline $BL/held-out-<p>.toml --json --report-json $S-held-out-<p>.json` | 0, 0 |
| `$B eval --profile {support-email,strict} --cases-only --targets crates/inumaki-eval/targets/safety.toml --json --report-json $S-safety-<p>.json` | 0, 0 |
| `$B eval --profile {support-email,strict} --sequences --targets crates/inumaki-eval/targets/sequence.toml --json --report-json $S-sequence-<p>.json` | 0, 0 |
| `$B eval --profile {support-email,strict} [--held-out] --via-service --json --report-json $S-service-[held-out-]<p>.json` | 0 each |
| `$B eval --profile {support-email,strict} --track tool-json [--held-out] --via-service --json --report-json $S-tool-json-[held-out-]<p>.json` | 0 each |
| `$B eval --profile <p> [--held-out] --write-baseline $BL/<name>.toml` (all six) | 0 each |
| `[INUMAKI_BENCH_TRANSFORMS=1] INUMAKI_BENCH_MAILS={0,5} $B bench --via-proxy --profile support-email`; `$B bench --via-proxy --profile offline` | 0 each |
| `$B bench --profile offline`, `$B bench --profile support-email` | 0 each |
| `/usr/bin/time -p $B eval --profile support-email --via-service --json --report-json …` (main and head) | 0, 0 |
