# Harness-static precision (lane L3): final measurement (2026-10-20)

Plan `2026-10-12-harness-static-precision`, Tasks 1–6 plus the follow-ups 6a, 6b, 6c, 6d and 7r, measured on the reference machine (`macos-aarch64`, Apple M4), release build of `2f8d8ec` (branch `l3/harness-precision`, rebased on main `ddded82`, `SANITIZER_GENERATION` 3), seed 42, the pinned models. Every report is a committed `docs/quality/2026-10-12-harness-{before,after}-*.json` (counts, rates, provenance; never text). The `before` reports are Task 1's (release build of `cc0e2ab`, no rule yet, re-recorded baselines). Raw benches and span lists: `2026-10-12-harness-{before,after}-*.txt`, `2026-10-12-harness-spans-{before,after,after-free}.txt`.

**Measured base.** The `after` reports and span lists were measured on the `ddded82`-based build of `2f8d8ec`. The branch was later rebased onto main `dec8362` and then `0de40c0` (commits renamed, for example `2f8d8ec` → `d91f3bf`) without re-measuring at those steps. The final fix wave (2026-10-20, below) re-ran the measurement on its head `984460c` (main `0de40c0`, with the A1–A3 fixes): all 20 reports (18 under `block`: recall, baseline, harness, and service runs; 2 harness runs under `tokenize`) equal the committed `after` reports field by field except `latency_ms` and `provenance`, the per-id name-shape outcomes are identical, and both span lists are identical. The committed files stay the `2f8d8ec` measurement, except the four free-text harness reports (`after-corpus-free-*`, `after-tokenize-corpus-free-*`) and `spans-after-free.txt`, which round 2 (ruling L118, head `127a438`) replaced with its own measurement; round 2 left every other report equal to `after` except latency and provenance.

**Goal.** Text that an agent harness sends with every request (model instructions, tool descriptions, environment and git-status blocks, turn metadata) stops producing `PERSON` spans and refusals, without lowering recall or raising any leak count.

**Result.**

- The harness-static corpus (93 documents) went from 1004 `PERSON` spans and 7 refused documents under `support-email` (1 under `strict`) to **25 spans and 0 refusals** under both profiles, read as harness-static text. The 25 are the acknowledged per-word residual (L98, L103).
- Every leak count is equal to Task 1, and `PERSON gold_found` is equal, in every recall run: tuning, held-out, safety, sequences, `tool-json`, the service path, `thorough`, and `offline`. No baseline field moved, so no baseline was re-recorded.
- **Every recall run is free text.** The eval's default origin is `TextOrigin::Free`, `--origin harness-static` refuses `--baseline` (L109), and the name shapes run free too. The harness corpus holds no identifying value, so its runs measure precision only. **Recall on harness-static text is unmeasured.** Per the code after the final fix wave, two drops depend on the origin, and the recall runs never exercise either: a lowercase Census-surname vocabulary word or lowercase `ALSO_NAMES` word that is a span's only evidence (L98, R16, R17), and a whole-token identifier whose only name part is glued in CamelCase (`HuberMaier`; L118). Both are dropped in harness-static text and kept in free text. Every other drop applies in both origins and is exercised by the free-text recall runs: identifier shapes (hashes, UUIDs, paths, machine words with no name part), role nouns and other technical vocabulary (`user`, `reviewer`), lowercase surname words with a code cue (backticks, inside an identifier, other evidence in the span), product names and model ids, and `Claude` with a cue. The verifier's product cue (L103) is harness-static only and likewise unmeasured for recall.
- No name-shape case got worse under either profile or either `on_uncertain` mode.
- The transformed proxy bench still refuses 29 of 51 turns, the same turns for the same reasons as before. None of them is caused by a span the new rules drop.
- Latency is unchanged against main (A/B, same load).
- **The full gate's model-test command exited 101 at Task 7** on one test, `mirror_latency_20kb` (debug build, 60 s wait per file, timeouts under load). It fails on main `dec8362` too under load and passes in release on both trees (L115 measurement); the integrator accepted it as pre-existing. In the final fix wave the same test passed in debug at load 3.6–4.4 (0 timeouts).
- **The proxy passes the origin for the leading system prompt only.** Lane L2's origin wiring (L107, L120, L122; merged at `addf2c5`) gives `HarnessStatic` to text leaves of the leading system prompt of trusted requests; every other leaf and every restricted request runs as free text, where the harness corpus yields 76 spans and 1 refused document (66 before ruling L118 kept CamelCase surnames in free text, round 2 of the final fix wave). See the threat model, entry (dd).

The evals ran one at a time while other lanes loaded the machine (1-minute load 6–31), so the eval latency fields are not compared. Timing runs are A/B against main, alternated, and carry their load.

## Task 1: old and new tuning baselines (name-shape cases)

Task 1 added 12 name-shape cases to the tuning corpus (`cases/name_shapes.toml`, R12, L68) and re-recorded the four tuning baselines once. One planned case, `word-surname-csv`, was moved out because `Branch` in the first CSV column is detected by nothing (a recall gap for the next plan, L78). Columns: old (2067 docs) → new (2079 docs).

| profile | leak docs | accepted leak rate | blocked + uncertain (rate) | PERSON found/gold (recall) |
|---|---|---|---|---|
| support-email | 11 → 11 | 0.539% → 0.536% | 27 → 28 (1.306% → 1.347%) | 3906/4160 → 3918/4174 (93.89% → 93.87%) |
| strict | 4 → 4 | 0.195% → 0.194% | 18 → 19 (0.871% → 0.914%) | 3905/4160 → 3917/4174 (93.87% → 93.84%) |
| thorough | 0 → 0 | 0 → 0 | 1874 → 1883 (90.66% → 90.57%) | 3906/4160 → 3918/4174 |
| offline | 406 → 416 | 19.74% → 20.11% | 10 → 10 (0.484% → 0.481%) | 3120/4160 → 3122/4174 (75.00% → 74.80%) |

The extra blocked document is `shape-file-surname-hyphen` (`INVOICE_ID` on `2026`, blocked before any rule). The 10 extra `offline` leak documents are the new cases (`offline` has no NER). `verifier_fn_rate` moved from 0.1317 to 0.1500 with the re-record; ruling L79's proof (old corpus at Task 1 code: 0.131747) shows a per-document random-draw reshuffle plus the 12 hard cases, not a regression.

## Before and after under `block` (shipped)

Columns: docs | accepted leak docs | docs with leak | blocked | uncertain | PERSON gold found | PERSON detected | CONTRACT_ID gold found. One value means no change.

| report | before (Task 1) | after | exit |
|---|---|---|---|
| harness corpus `support-email` (harness-static) | 93 \| 0 \| 0 \| **7** \| 0 \| 0 \| **1004** \| 0 | 93 \| 0 \| 0 \| **0** \| 0 \| 0 \| **25** \| 0 | 5 → 0 |
| harness corpus `strict` (harness-static) | 93 \| 0 \| 0 \| **1** \| 0 \| 0 \| **1004** \| 0 | 93 \| 0 \| 0 \| **0** \| 0 \| 0 \| **25** \| 0 | 5 → 0 |
| tuning `support-email` | 2079 \| 11 \| 11 \| 28 \| 0 \| 3918 \| 4672 → 4668 \| 202 | | 0 |
| tuning `strict` | 2079 \| 4 \| 4 \| 19 \| 0 \| 3917 \| 4672 → 4668 \| 202 | | 0 |
| tuning `thorough` | 2079 \| 0 \| 0 \| 1883 \| 0 \| 3918 \| 4672 → 4668 \| 202 | | 0 |
| tuning `offline` | 2079 \| 416 \| 416 \| 10 \| 0 \| 3122 \| 4546 \| 202 | | 0 |
| held-out `support-email` | 200 \| 0 \| 0 \| 4 \| 0 \| 387 \| 513 \| 23 | | 0 |
| held-out `strict` | 200 \| 0 \| 0 \| 5 \| 0 \| 387 \| 513 \| 23 | | 0 |
| safety `support-email` | 79 \| 0 \| 0 \| 2 \| 0 \| 63 \| 81 → 79 \| 5 | | 0 |
| safety `strict` | 79 \| 0 \| 0 \| 2 \| 0 \| 63 \| 81 → 79 \| 5 | | 0 |
| name shapes `support-email` | 12 \| 0 \| 0 \| 1 \| 0 \| 12 \| 15 → 14 \| 0 | | 0 |
| name shapes `strict` | 12 \| 0 \| 0 \| 1 \| 0 \| 12 \| 15 → 14 \| 0 | | 0 |
| `tool-json` held-out `support-email` (service) | 300 \| 0 \| 0 \| 1 \| 0 \| 0 \| 0 \| 0 | | 0 |
| `tool-json` held-out `strict` (service) | 300 \| 0 \| 0 \| 1 \| 0 \| 0 \| 0 \| 0 | | 0 |
| held-out `support-email` (service) | 200 \| 0 \| 0 \| 1 \| 0 \| 387 \| 513 \| 23 | | 0 |
| sequences `support-email` (no Task 1 report) | – | 300 \| 1 \| 1 \| 1 \| 0 \| – \| – \| – | 0 |

- **Harness corpus block rate:** `support-email` 7.53% → 0%, `strict` 1.08% → 0%.
- **Recall:** every leak count equals Task 1. `PERSON gold_found` equals Task 1 everywhere. L98 could only have added spans in free text; none of the recall corpora has a lowercase-surname word standing alone, so none gained one.
- **Precision on the recall corpora:** 4 fewer false `PERSON` detections on tuning, 2 on safety, 1 on the name shapes. Every gated field (document count, leak rate, accepted leak rate, block rate, verifier FN rate, recall per kind) is identical to Task 1 in all six baseline runs.
- **The sequence run** (300 steps, targets met: 0 wrong links, 5 of 6 expected cache repeats served) matches the 2026-10-09 measurement, 1 accepted leak in 299 accepted documents.
- **The verifier's false positives** on the tuning corpus are unchanged: `Ner` 39, `Leak` 7, `Regex` 2 out of 2066 clean trials under both profiles. Held-out: `Regex` 51, `Ner` 8, `Leak` 1 of 200.

### Name shapes, gate and per id

The name-shape gate (`targets/name-shapes.toml`: zero residue, accepted leak 0, block rate ≤ 0.0834) exits 0 under both profiles. Per id, the outcome is the same as Task 1 under both profiles and both modes (`name-shape-outcomes.sh --compare`: "no id worse"):

| id | Task 1 | after (`block` and `tokenize`) |
|---|---|---|
| `shape-file-surname-hyphen` | blocked | blocked |
| `shape-file-surname`, `shape-file-surname-bare`, `shape-handle-surname`, `shape-path-claude`, `shape-username-claude`, `word-surname-model`, `word-surname-branch`, `word-surname-json`, `claude-first-name-de`, `claude-first-name-json`, `claude-first-name-en` | pass | pass |

No case ever released a gold value (`+residue`).

## Per-rule effect

The harness corpus, `support-email`, after each task. `PERSON` detected (distinct texts) and blocked documents. Every step passed the recall checkpoint: leak counts and `PERSON gold_found` equal to Task 1, no name-shape id worse.

| after | PERSON detected | blocked `support-email` / `strict` | what changed |
|---|---|---|---|
| Task 1 (no rule) | 1004 (433) | 7 / 1 | – |
| Task 2: identifier-shaped spans, business-number guard (L85, L88) | 686 (222) | 1 / 1 | identifier-shaped model `PERSON` spans (hashes, UUIDs, paths, model and tool names) dropped; business-number shapes the model alone covered (plates, typo'd labels) kept |
| Task 3: role nouns and technical vocabulary (L3-09, L3-10) | 67 (32) | 0 / 0 | role nouns and technical words standing alone (for example `user`, 259 spans at Task 1) dropped; a capitalized Census surname still counts as a name |
| Task 4: product names, model ids, the `Claude` cue | 25 (14) | 1 / 1 | `Codex`, `gpt-*` ids, `Claude` with a cue dropped; the verifier then flagged the released `Claude` (L78) |
| Task 5: `require_digit` on three label rules | 25 (14) | 1 / 1 | the `EULA` `CONTRACT_ID` false positive gone; no recall corpus changed |
| Task 6, 6a: `on_uncertain = "tokenize"` (not shipped), L106 merge fix | 25 (14) | 1 / 1 | no change under `block` |
| Task 6b: text origin, L98 | 25 harness-static, 66 free | 1 / 1 | lowercase surname words dropped only in harness-static text |
| Task 6c: the verifier's product cue (L103) | 25 | **0 / 0** | the L78 document released, harness-static only |
| Task 6d, 7r: review minors, rebase (L3-18) | 25 | 0 / 0 | no measured change (full report JSON identical to 6c) |
| Final fix wave: A1 glued surnames, A2/A3 bounded scans | 25 (14) | 0 / 0 | no measured change (every report equal to `after` except latency and provenance) |
| Final fix wave round 2: L118 CamelCase split in free text only, window edges | 25 harness-static, 76 free | 0 / 0 | free text keeps 10 more spans (`$SkillName` 6, `TodoWrite` 2, a git-log line and its hash 2); harness-static unchanged |

## The verifier's `Ner` counts

- **Harness corpus, `support-email`/`strict` verifier (mBERT):** 0 `PERSON` hits at Task 1, while the sanitizer still tokenized `Claude`. After Task 4 dropped `Claude` with a cue, the verifier flagged it in `synthetic/cc-system.txt` (`support-email` 2 hits, `strict` 1; conf 1.00; the corpus's only refusal). After Task 6c: 0 refusals as harness-static text. As free text that document still refuses (`PERSON/Ner`), as intended.
- **`thorough` (GLiNER verifier):** 3810 `PERSON` hits on the harness corpus at Task 1. Recorded as the plan-4c verifier-calibration residual (L78); this plan does not touch it.
- **Transformed proxy bench:** 26 `verifier-ner` hits under `block`, all `PERSON`, all one capitalized five-letter non-name word shape (see TRANSFORMS), identical to Task 1.

## `tokenize` against `block`

`on_uncertain = "tokenize"` (L70, L3-13) tokenizes a policy escalation of a `tokenize`/`preserve` kind instead of refusing or retrying, and keeps every verifier refusal and the retry guard. The configuration is `configs/default.toml` with the one `on_uncertain` line changed. The runs are not canonical, so the tuning and held-out runs go without `--baseline`. Columns as above.

| gate | `block` (after) | `tokenize` (after) | Task 6 `tokenize` (pre-6b) |
|---|---|---|---|
| harness corpus `support-email`, harness-static (refusal gate) | 93 \| 0 \| 0 \| 0 \| 0 \| 0 \| 25 \| 0 | identical, exit 0 | blocked 1 (L78), exit 5 |
| harness corpus `strict`, harness-static (refusal gate) | 93 \| 0 \| 0 \| 0 \| 0 \| 0 \| 25 \| 0 | identical, exit 0 | blocked 1 (L78), exit 5 |
| harness corpus free text, both profiles | 93 \| 0 \| 0 \| 1 \| 0 \| 0 \| 76 \| 0 (66 before L118) | identical | – |
| tuning `support-email` | 2079 \| 11 \| 11 \| 28 \| 0 \| 3918 \| 4668 \| 202 | 2079 \| **13** \| **13** \| 28 \| 0 \| 3918 \| 4668 \| 202 | same as now |
| tuning `strict` | 2079 \| 4 \| 4 \| 19 \| 0 \| 3917 \| 4668 \| 202 | identical | identical |
| held-out, both profiles | 200 \| 0 \| 0 \| 4 / 5 \| 0 \| 387 \| 513 \| 23 | identical | identical |
| safety, both profiles | 79 \| 0 \| 0 \| 2 \| 0 \| 63 \| 79 \| 5 | identical | identical |
| name shapes, both profiles | 12 \| 0 \| 0 \| 1 \| 0 \| 12 \| 14 \| 0 | identical, per id identical | identical |
| `tool-json` held-out `support-email` (service) | 300 \| 0 \| 0 \| 1 \| 0 \| 0 \| 0 \| 0 | identical | identical |
| proxy bench, untransformed, 0 / 5 mails | 0 / 0 refused | 0 / 0 refused | 0 / 0 |
| proxy bench, transformed, 5 mails | 29 of 51 refused | 29 of 51, same turns and reasons | 29 |

- **Refusals:** `tokenize` removes no refusal in any gate, on the rebased head as in Task 6. Under `block` a band span alone never refused: it sent the text to the `strict` retry, which tokenized it. What refused harness text was the verifier (L78), and Task 6c resolved that for harness-static text in both modes.
- **Recall:** `tokenize` costs 2 leaking tuning documents under `support-email` (11 → 13; `PERSON` leaked 16 → 18, `DATE_OF_BIRTH` 1 → 2). The documents settle at `support-email` instead of the `strict` retry, whose `DATE` and `ORGANIZATION` tokenization covered a birth date and two mislabelled names (Task 6, L73).
- **Latency:** the proxy bench (untransformed, 5 mails), alternated `block`, `tokenize`, `block`, `tokenize` at load 5.9–7.4:

  | | `block` | `tokenize` |
  |---|---|---|
  | cold first turn | 13.5 s, 13.3 s | 10.4 s, 9.0 s |
  | added per turn p50 | 515 ms, 486 ms | 464 ms, 450 ms |
  | added per turn p95 | 808 ms, 762 ms | 532 ms, 533 ms |

  That is the retry saving Task 6 could not time: about −25 to −30% cold, −5 to −10% median, −30% p95.

**Recommendation (Task 6, unchanged by these numbers): keep `block` as the shipped default everywhere,** for `support-email` in general and for the proxy's chat-dataset profile. `tokenize` buys latency, not availability, and pays for it with recall on mail-shaped text, which CLAUDE.md puts first. If the integrator wants the latency for the chat-dataset profile, it should come through an `extends` profile, not a change to `support-email`. **The integrator has not ruled; `configs/default.toml` keeps `on_uncertain = "block"`.**

## Harness-static against free text (L3-14)

The origin is caller knowledge of position, not a text property (L60, L3-14). Columns: `PERSON` detected | blocked | uncertain. 93 documents; the user-role subset is 16 documents (`synthetic/cc-reminders.txt` and `generated/env-{01,03,…,29}`), measured under `block` and `support-email` only.

| corpus | origin | `block` `support-email` | `block` `strict` | `tokenize` `support-email` | `tokenize` `strict` |
|---|---|---|---|---|---|
| harness corpus | harness-static | 25 \| 0 \| 0 | 25 \| 0 \| 0 | 25 \| 0 \| 0 | 25 \| 0 \| 0 |
| harness corpus | free | 76 \| 1 \| 0 | 76 \| 1 \| 0 | 76 \| 1 \| 0 | 76 \| 1 \| 0 |
| user-role subset | harness-static | 0 \| 0 \| 0 | – | – | – |
| user-role subset | free | 0 \| 0 \| 0 | – | – | – |

- **Every proxy request runs as free text until L2 passes the origin.** Until then, the proxy sees the free-text row: 51 more spans than harness-static (41 from L98, 10 from L118; tokenized, never sent in clear) and the L78 document refused. Under `tokenize` that document still refuses, because a verifier `Fail` is not `Uncertain`.
- **User-turn harness text stays free text after the wiring too.** That is Claude Code's `<system-reminder>` blocks and Codex's `<environment_context>` and `AGENTS.md` messages: the proxy knows only that they are user turns. The 16-document subset that stands for them yields no span and no refusal under either origin, so that limit costs nothing measured; but the subset is small (16 documents) and was run under `block` and `support-email` only.
- The harness-static reading is identical to Task 6c's on the rebased head (full report JSON minus latency and provenance, checked at Task 7r, at Task 7, and in both rounds of the final fix wave). The free-text reading was identical too until round 2, where ruling L118 added the 10 CamelCase spans (66 → 76).

## The L98 narrowing and the L103 verifier cue

**L98 (free text keeps lowercase surname words).** A lowercase word that is a Census surname or an `ALSO_NAMES` word, standing alone, is dropped as technical only in harness-static text, between backticks, or with other evidence in the span (R16, R17). In free text it stays a `PERSON` span, so it is tokenized: `danke rust`, `danke page`, `Shell: fish`, `a senior engineer`, `wrapped my head around`, `type "rust" or "py"`, `Main branch (you will usually use this)` (the rows Task 6b moved, pinned by `lowercase_surname_words_need_a_harness_static_text_or_a_code_cue`). With a code cue it is technical in free text too: `` `fish` ``, `` `rust` ``, `git main`, `rust-v0.159.2`. A capitalized surname keeps C2 under both origins (`Herr Model`, `Ansprechpartner: Sender`). On the harness corpus, free text keeps 41 more spans than harness-static: `Main branch` 5, `agent` 5, `main` 5, `base` 2, `fish` 2, `head` 2, `memory` 2, `owner` 2, `person` 2, `title` 2, and one each of `Code samples`, `Hero` (a `Link` copy, 0.90), `body`, `cargo`, `engineer`, `hero page`, `main agent`, `path`, `roots`, `rust`, `senior engineer`, `window ID`. Since ruling L118 (round 2), free text also keeps 10 CamelCase spans: `$SkillName` 6, `TodoWrite` 2, the git-log line `fede7fa feat(cart): keep the cart in localStorage` 1, and the hash `59f6b9b` on the next line 1 (the same model span, confidence 0.621, kept with it), 51 in all (`2026-10-12-harness-spans-after-free.txt`).

**L103 (the verifier's product cue).** In the verifier's own code path (`second_pass::is_harness_product_name`, no code shared with `detect::technical`), a `PERSON` hit from the NER re-scan is discarded only when:

- the text is harness-static;
- the hit is exactly, case-sensitively and as the whole hit, one of `Claude`, `Codex`, `Opus`, `Sonnet`, `Haiku` (R18);
- it is a whole word: letters, digits, `-` and `_` count as word characters, so `Jean-Claude` is not a match;
- and no token is next to it (fix round 1, L111): `Claude <PERSON_…>` still fails.

`Claude` in free text fails, and so do `Claude Dubois`, `claude`, `CLAUDE`, and `Thanks, Claude` as one hit. The leak check, the regex re-scan and the combination heuristic never see the origin. The retry pass gets the same origin as the primary pass (pinned).

**The `Thanks, Claude` decision** (R18, L107): when the NER returns `Claude` alone after `Thanks,` in harness-static text, the hit is discarded. A system prompt that thanks a real person named exactly Claude would release that first name; the leak check still catches it when it is a stored value. Recorded as a threat-model residual.

## Proxy wiring contract (open dependency, lane L2; ruling L3-14, L107)

This plan does not edit `crates/inumaki-proxy`. Lane L2's later origin-wiring plan (`docs/quality/2026-10-20-origin-wiring.md`) passes `HarnessStatic` for the leading system prompt of trusted requests; every other proxy leaf runs as `TextOrigin::Free`, at the cost measured above.

1. **System-prompt leaves.** In `crates/inumaki-proxy/src/pipeline.rs` `leaf_verdict`, a leaf with `role == Role::System` and `class == Class::Text` calls `eng.process_with_at(nfc, view, &reds, TextOrigin::HarnessStatic)` instead of `eng.process_with(nfc, view, &reds)`. `Role::System` already covers Anthropic `system`, Responses `instructions`, and `system`/`developer` messages (`wire/mod.rs` `role_of`). Every other leaf keeps `process_with` (free text): user turns, tool results, tool inputs, assistant text, and `Role::Other`.
2. **Definitions need nothing.** `Class::Definition` leaves (tool and schema definitions) never reach the engine's NER or verifier. The daemon's `scan_definitions` (`crates/inumakid/src/proxy_host.rs`) scans them with the dictionary, identity, and account detectors only, and the origin changes none of those.
3. **Caches and memos.** A per-leaf cache entry or memoized verdict keyed by the leaf text alone must also key on the origin: the same text can be released as a system prompt and refused in a user turn. The projection of cached harness-static text (`Engine::project`, which verifies through `Verifier::verify_with` and so judges as `Free` today, ruling L3-18) must carry the origin to `Verifier::verify_with_at` when L2 wires it.
   Answered by design decision D-6 ("The projection carries no origin") in the M8 spec, amendment 2026-10-20 (§20): the projection carries no origin, because its verifier runs no NER re-scan and no sanitizer detector runs, so the origin cannot change its result.
4. **No text-based guess.** The proxy derives the origin from the leaf's position only, never from its content (L60).
5. **Known limit.** Harness text that arrives in user turns stays free text (above). A finer origin for those positions would be a later ruling.

## The corpus: composition and refresh

`crates/inumaki-eval/harness/harness-static.jsonl`, 93 documents, 328 KB, built twice byte-identical (`sha1 a9ca2d68…`), negative-only (every `PERSON` span and every refusal is a false positive):

- 29 OpenAI Codex prompt templates, one document per file, and 20 distinct instruction strings from Codex's `models.json` (tag `rust-v0.159.2`, commit `ff6aec96`, Apache-2.0, attribution in `NOTICE`). `{{ user_first_name }}` is the empty string (R10).
- 4 Claude Code-shaped texts written for inumaki (`synthetic/cc-{system,tools,reminders,agents}.txt`), never copied from an installed harness.
- 40 generated blocks from a seeded generator: 30 environment and git-status blocks, 10 turn-metadata blocks (random temp suffixes, non-personal logins, hashes, UUIDs, timestamps, model ids).

**Refresh** when a harness release changes its prompts: set `CODEX_TAG` and `CODEX_COMMIT` in `scripts/harness-corpus/build.sh`, update `PATHS` if files moved, re-run, run the precision gate (`--origin harness-static --targets crates/inumaki-eval/targets/harness-static.toml`), and list what is left with `scripts/harness-corpus/person-spans.sh`. A new span that only a name word explains goes to the integrator (L3-04); the target is never raised to pass.

## The `CONTRACT_ID` hypothesis (R7)

The measured Claude Code `CONTRACT_ID/Regex` refusal is probably conversation content shaped like a customer id, kept by design. `bare_identifiers` matches no harness-corpus text. It matches ticket-, KB- and issue-shaped ids (`KB5012345`, `JDK-8123456`, `GH-12345`, `INC0012345`, `B123456`, `PR12345`, `SR-12345`), and not `E0382`, `TS2345`, `CVE-2026-12345`, `a3f9c12`, `48213`, `U+1F600`, `8787`. So it is unchanged. The one corpus `CONTRACT_ID` was a label-rule hit on `EULA` after `contract`, which `require_digit` removed (Task 5, R11). The integrator's post-merge re-test with the real Claude Code and Codex (Q1) records the real shape.

## TRANSFORMS (I2, R9), both modes

The proxy bench with the generator's noise transforms (signature and quote blocks, typos outside spans, wrapping at 72 columns), 5 history mails, 51 turns, `INUMAKI_BENCH_REASONS=1`, with throwaway diagnostics that print one line per verifier `Ner` hit and per span the technical filter drops (shape and flags only, never text; reverted, `git diff --stat` empty).

| | Task 1 (`block`) | after `block` | Task 6 `tokenize` | after `tokenize` |
|---|---|---|---|---|
| refused turns | 29 of 51 | 29 | 29 | 29 |
| first refused turn | 0 (cold turn refused) | 0 | 0 | 0 |
| `PERSON/Ner` | 25 (turns 0–5, 7–25) | same turns | 25 | same turns |
| `PERSON/Leak, Policy` | 4 (turns 6, 37, 43, 48) | same turns | 4 | same turns |
| `filtered` lines with `generator_name=true` | – (no rule) | **0** | – | **0** |

**Classes:**

- **(a) The verifier caught a generator name** (a correct refusal and a sanitizer recall miss): **none**, before or after, in either mode. No `verifier-ner` line has `generator_name=true`.
- **(b) A precision miss, by shape: 25 turns,** the same in all four columns. Under `block`, 26 `verifier-ner` hits: kind `Person`, shape `Aaaaa` (a capitalized five-letter word), `lower=false first_name=false generator_name=false`; confidence 0.84, 0.87, 0.90, 0.93, 0.95 ×3, 0.96 ×3, 0.99 ×7, 1.00 ×9. That is identical to Task 1. Under `tokenize`, 50 hits with the same shape and flags (0.68–1.00): the same refusals, seen in more verifier calls. The word is a capitalized common word in the transformed mail text, not a name. Per L78 (at least 20 of 51 still refused), it goes to plan 4c as **"verifier precision on capitalized common words"**. The examples are given by shape only, because they are generated-mail text.
- **(c) `Leak` and `Policy`: 4 turns,** unchanged since Task 1. The leak check found a stored `PERSON` value in clear in a mangled copy (the transforms wrap and quote text, so a value tokenized in one place recurs in another form). That is a correct refusal and a sanitizer recall miss on noisy text, as the bench's own note on transforms describes. `Policy` is the retry pass's escalation of the same span. The diagnostics did not split them further.
- **What the filter drops in this bench:** 27 `filtered` lines in each mode, all `PERSON` at 0.61 with the shape `+dd (ddd) ddd dd dd`, `lower=true first_name=false generator_name=false`. These are model `PERSON` spans over a phone number. The regex `PHONE` detector covers that shape (probe: `+43 (316) 123 45 67` → `PHONE` 0.85, tokenized), so dropping the duplicate `PERSON` span loses nothing. **No stop condition.**

## Latency

Both builds from the same machine session, release, alternated main (`ddded82`) and head, with the 1-minute load at each start. The raw outputs of these A/B runs and of the `block`/`tokenize` timing runs above live only in the measuring session's scratchpad (`t7-ab-*.txt`) and are not committed; the numbers in this report are their record.

- **`bench --profile support-email`** (200 short documents, fresh store per document). Process p50 main / head: rounds 3–5 (load 8.9–11.4) 62.4 / 61.6, 63.0 / 63.4, 63.5 / 62.4 ms; detect p50 26.5 / 26.9, 28.4 / 26.8, 26.8 / 25.9 ms. Rounds 1–2 (load 12.7–19.7, falling) were 38.4 / 41.6 and 45.6 / 60.9 ms, too noisy to read. **No measurable cost.** The single head run at load 5.8 gave process p50 37.7 ms, p95 78.4 ms (`2026-10-12-harness-after-bench-support-email.txt`); Task 1's 85.2 ms ran at load about 40 and is not comparable.
- **Proxy bench, `support-email`, untransformed, 5 mails, free text** (load 6.3–7.5):

  | | main | head |
  |---|---|---|
  | cold first turn | 17.5 s, 12.6 s | 17.6 s, 12.1 s |
  | added per turn p50 | 640 ms, 457 ms | 655 ms, 445 ms |
  | added per turn p95 | 1024 ms, 714 ms | 987 ms, 687 ms |
  | refused turns | 0 | 0 |

  Within noise. **This bench runs every leaf as free text until the L2 wiring lands,** so it does not show the harness-static reading. The committed single run (`2026-10-12-harness-after-bench-proxy-mails5.txt`, load 8.4) gave cold 17.7 s, p50 674 ms, p95 1050 ms.
- **Folder mirror, 20 KB file** (`mirror_latency_20kb`, release, load 6.0–11.2): `offline` p50 918 ms, p95 1119 ms, 0 of 51 withheld. `support-email` p50 4.0 s, p95 18.9 s, max 37.9 s, 0 timeouts. What the counts mean: the test writes 51 files (one untimed warm-up letter and 50 timed ones); **46 of 51** is the number of files withheld (a placeholder in the mirror) at the end of the run, so **5 of 51** end with a sanitized copy; **13** is the test's `released files` field, the number of sanitized copies the mirror wrote during the run (a count of writes, not of distinct files, so it can exceed 5). At M5 (`2026-09-29-m5-mirror-latency.md`) `support-email` withheld 51 of 51 at a median of 1.27 s to the placeholder, and no released file was ever timed. A released 20 KB file needs every sub-batch (longest engine call 15.3 s), which makes the tail. The tail is not caused by this branch: the same test on main `dec8362` withholds the same 46 of 51 and writes the same 13 copies in release (L115 measurement), with the same tail. The integrator should know it exists. The debug build of the same test timed out (60 s) once at load 8 and twice at load 20–31, which fails the full gate's model-test command (below).
- **The technical filter on long text (final fix wave, A2 and A3).** Before the fix, the text-wide `Claude` cue scanned the whole text once per span, and the time and commit cues scanned the whole line once per span, which is quadratic on long input. Measured with `cargo test --release -p inumaki-core --lib long_text_timing -- --ignored --nocapture` (`drop_technical_persons_at`, harness-static, synthetic text, release; load not recorded, the ratio is the point):

  | text | spans | before (A1 only, on `b5047e0`) | after (`984460c`) |
  |---|---|---|---|
  | prose with role nouns, 30 KB | 608 | 9.0 ms | 0.30 ms |
  | prose with role nouns, 120 KB | 2432 | 77.5 ms | 1.2 ms |
  | prose with role nouns, 240 KB | 4866 | 259.6 ms | 2.4 ms |
  | one line of minified JSON (hex ids, timestamps), 30 KB | 1888 | 44.9 ms | 2.1 ms |
  | one line of minified JSON, 120 KB | 7560 | 712.6 ms | 10.3 ms |
  | one line of minified JSON, 240 KB | 15120 | 2832 ms | 14.5 ms |

  The kept-span counts are identical before and after in every row. The `Claude` cue is now computed at most once per text; the time and commit cues read at most 256 bytes on each side of the word, and the widening at most 1024 bytes (a cue cut off by the window does not count, so the span is kept).

## Baselines

All six baseline gates (`support-email`, `strict`, `thorough`, `offline`, `held-out-support-email`, `held-out-strict`) exit 0. Compared with Task 1 field by field (document count, leaking and accepted-leak documents, pass documents, blocked and uncertain, verifier false negatives and broken trials, `gold_found` and `gold` per kind), every gated input is identical. **No baseline moved, so none was re-recorded.** The lower `PERSON detected` counts are not a gated field.

## Rulings

From the plan and its ledger (`.superpowers/sdd/2026-10-12-harness-static-precision/progress.md`, not committed).

| Ruling | Decision | Measured effect |
|---|---|---|
| L60 (integrator) | Harness-static text is its own plan; no exemption by client. | – |
| L3-04 | No silent corpus residual: a span only a name word explains goes to the integrator. | the 25-span list (L98, L103) |
| L3-05, L68 | All review-1 findings; name-shape eval cases; every gate holds on them. | 12 cases, per-id gate (R12, N1) |
| L3-06 | The C2 article-cue narrowing is not adopted. | `the Bash tool` stays tokenized |
| L70 | Census-surname words alone are not dropped; `on_uncertain = "tokenize"` measured against `block`. | Task 6; no refusal removed, +2 tuning leak docs |
| L71 | Names in paths and URLs are a known recall gap; next plan. | threat model |
| L73 | Task 6 guard in every pass under `tokenize`; settling-profile and store-pollution measurements. | 499 tuning docs settle at `support-email`; 48 distinct harness band values |
| L78 | `thorough` 3810 verifier hits are a 4c residual; `Branch` in CSV goes to the structured-positions plan; TRANSFORMS ≥ 20 of 51 → 4c item. | TRANSFORMS 29 of 51, recorded |
| L79 | `verifier_fn_rate` 0.1317 → 0.1500 proven a reshuffle before keeping the re-record. | proof in the baseline comment |
| L85, L88, L3-07, L3-08 | Business-number guard shapes; time cue; glued `key=value` values. | Task 2 recall stop narrowed; leak docs equal |
| L3-09, L3-10, L98 | Surname words in file names stay names; lowercase surname words alone drop only in harness-static text or with a code cue. | free text keeps 41 corpus spans (51 with L118) |
| L3-11, L103 | The 3 identifier keeps (`NotebookEdit`, `edit_mode`, `line_range`) are an R14 exception; n = 25; the verifier's product cue, harness-static only. | `PERSON = 25`; L78 document released |
| L3-13 | Under `tokenize`, only `tokenize`/`preserve` kinds convert; `block` kinds refuse, `remove` kinds are removed. | no shipped profile affected |
| L106 | A merged span that absorbed an escalation keeps `Escalate` over `Remove`. | block rate unchanged |
| L107 | Proxy origin wiring is a follow-up plan owned by L2; harness text in user turns stays free text; `Thanks, Claude` residual. | contract above |
| L109, L3-17 | `--origin harness-static` refuses `--baseline`/`--write-baseline`; final-wave minors run as Task 6d. | – |
| L111 | Next-to-token guard on the verifier cue, kept even if a gate fails. | the guard refused nothing in the corpus |
| L3-16 | The stale `docs = 97` cli test is test data (109). | fixed in 6d |
| L3-18, L3-19 | Verifier API after the rebase: `verify_with_at(s, ctx, leak, origin)`; `Engine::project` judges as `Free`; bisect gap accepted. | report JSON identical to 6c |
| R1–R20 (planner) | In the plan; R15 additive `_at` API, R16 backticks only, R17 `ALSO_NAMES` follow L98, R18 the five product names, R19 `eval --origin`, R20 only system-prompt leaves need the origin. | – |

**`on_uncertain` default:** not ruled. The proposal is Task 6's: keep `block` everywhere.

## Remaining harness-corpus spans, per word (L3-04, R14)

As harness-static text, `support-email` (`strict` identical), 25 spans, 14 distinct (`2026-10-12-harness-spans-after.txt`):

- Census-surname or `ALSO_NAMES` words standing alone, 22: `Yes` 8 (0.51–0.54, generated env blocks), `Bash` 2, `Bottom Line` 2, `HOME` 2, `Sender` 2, `Clarity` 1, `Rigor` 1, `NEVER` 1, `Title Case` 1, `Vague` 1, `Write` 1.
- Identifier keeps (a gazetteer first-name run with no technical context, L3-11), 3: `NotebookEdit` 1, `edit_mode` 1, `line_range` 1.

All are `Ner` spans between 0.505 and 0.750. Under `block` none refuses: each is tokenized, directly or in the `strict` retry when `support-email` escalates it. Under `tokenize` a band span is tokenized without the retry. Either way they cost meaning (a token in place of the word), never a leak or a refusal.

## Residuals

Recorded in `docs/threat-model.md` (Task 8):

- **The proxy runs as free text until L2 wires the origin (L107):** 76 corpus spans instead of 25, and the L78 document (`Claude` in a Claude Code-shaped system prompt) refused. After the wiring, harness text in user turns (`<system-reminder>`, `<environment_context>`, `AGENTS.md`) stays free text.
- **`Engine::project` judges as `Free` (L3-18):** the projection of cached harness-static text uses the free-text verifier until the contract's item 3 lands.
- **The `Thanks, Claude` bare hit:** in harness-static text, a bare NER hit `Claude` is discarded even when a real person is meant. The hit `Thanks, Claude` as one span still fails.
- **The next-to-token guard's limit (6c):** a `Claude` separated from a tokenized surname by more than two line breaks is not "next to" it (the same limit as the salutation filter).
- **`Claude.ai`:** `.` is not a word character, so `Claude.ai` still gets the cue (a heuristic boundary).
- **Task 4's text-wide C3 cue:** with `Claude Code` or `Anthropic` anywhere in the text, a standalone sign-off `Claude` is dropped by the sanitizer as the product. In harness-static text the verifier's cue then also discards it, unless a token is next to it.
- **`tokenize` costs recall on mail** (+2 tuning leak docs) and is not shipped.
- **Verifier precision on capitalized common words** (transformed bench, 25 of 51 turns): plan 4c.
- **`Branch` in a CSV first column, names in paths and URLs:** detected by nothing; the next plan ("names and identifiers in structured positions", L71, L78).
- **Regex gaps the model's `PERSON` tag backstops** (lowercase plates, typo'd invoice and customer labels): kept by the business-number guard. A regex fix is the better cover (Task 2).
- **An all-letter label value** (`Kundennummer: ABCDEFGH`) is no longer detected by the label rule (`require_digit`, Task 5).
- **Recall on harness-static text is unmeasured.** Every recall run is free text (above). The two origin-dependent drops, a lowercase Census-surname or `ALSO_NAMES` word as a span's only evidence (L98) and a CamelCase-glued surname in a whole-token span (L118), have no recall measurement; the other drops apply in both origins and are measured on free text.
- **CamelCase identifiers drop only in harness-static text** (ruling L118, round 2). In free text a CamelCase surname part keeps a whole-token model span (`HuberMaier`, `GruberAG`), as before the precision rule; the cost is 10 more free-text spans on the harness corpus (`$SkillName` 6, `TodoWrite` 2, a git-log line with `localStorage` and its hash 2). In harness-static text CamelCase is not split, so a surname glued in CamelCase there is dropped unless a part is a first name (`MaxHuber` is kept). A surname glued to digits, a `#`, or a key is kept in both origins (`Huber85`, `nachname=Huber`).
- **Names in whole lowercase path or URL spans, and digit or extension handles and paths** (`/home/huber/`, `@leitner85`, `C:\Users\mhuber\notes.txt`): a model span over the whole token is dropped. That loses chance coverage the model gave before the rule; no eval corpus holds such a name, so no eval shows it (L71).

## Commands and exit codes

From the worktree root: `B=target/release/inumaki`, `BL=crates/inumaki-eval/baselines`, `H` the harness corpus, `HT` its target, `NS`/`NST` the name shapes, `Q=docs/quality/2026-10-12-harness`, `TOK` the `tokenize` configuration. One eval at a time.

| Command | Exit |
|---|---|
| `cargo fmt --all --check` | 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 |
| `cargo test --workspace` | 0 (1686 passed, 5 ignored) |
| `cargo test -p inumaki-models -p inumakid --features models-tests` (debug) | 101: 316 passed, 1 failed, `mirror_latency_20kb` (`support-email`: 2 runs over the 60 s wait at load 20–31; a debug rerun at load 8: 1 timeout) |
| `cargo test --release -p inumakid --features models-tests --test mirror_latency -- mirror_latency_20kb` | 0 (0 timeouts) |
| `scripts/harness-corpus/check-surnames.sh` | 0 |
| `bash scripts/check-docs.sh` | 1 (`domain.labels.require_digit` undocumented), 0 after documenting it in `docs/configuration.md` |
| `cargo build --release -q -p inumaki-cli` | 0 |
| `$B eval --profile {support-email,strict,thorough,offline} --baseline $BL/<p>.toml …` | 0 each |
| `$B eval --profile {support-email,strict} --held-out --baseline $BL/held-out-<p>.toml …` | 0, 0 |
| `$B eval --profile {support-email,strict} --cases-only --targets …/safety.toml …` | 0, 0 |
| `$B eval --profile {support-email,strict} --corpus $H --origin harness-static --targets $HT …` | 0, 0 |
| `$B eval --profile {support-email,strict} --corpus $NS --targets $NST …` | 0, 0 |
| `name-shape-outcomes.sh <p>` and `--compare` against Task 1 | 0 each, "no id worse" |
| `$B eval --profile support-email --sequences --targets …/sequence.toml …` | 0 |
| `$B eval --profile {support-email,strict} --track tool-json --held-out --via-service …` | 0, 0 |
| `$B eval --profile support-email --held-out --via-service …` | 0 |
| `$B eval --profile {support-email,strict} --corpus $H …` (free text) | 0, 0 |
| `$B eval --profile support-email --corpus <user-role subset> --origin {free,harness-static} …` | 0, 0 |
| `$B bench --profile support-email`; `INUMAKI_BENCH_MAILS=5 $B bench --via-proxy --profile support-email` | 0, 0 |
| `person-spans.sh support-email`; `person-spans.sh support-email target/release/inumaki free` | 0, 0 |
| `$B --config $TOK eval …` (the Task 6 Step 4 set, harness lines with `--origin harness-static` and `targets/harness-static-tokenize.toml`, plus the two free-text harness lines) | 0 each (13 runs) |
| `INUMAKI_BENCH_MAILS={0,5} $B --config $TOK bench --via-proxy --profile support-email` | 0, 0 |
| diagnostic build: `INUMAKI_DIAG_NER=1 INUMAKI_BENCH_REASONS=1 INUMAKI_BENCH_TRANSFORMS=1 INUMAKI_BENCH_MAILS=5 $B [--config $TOK] bench --via-proxy --profile support-email` | 0, 0 |
| A/B: main and head `bench --profile support-email` (5 rounds) and `bench --via-proxy` (2 rounds); `block` and `tokenize` `bench --via-proxy` (2 rounds) | 0 each |

### Final fix wave (2026-10-20)

On head `984460c` (branch rebased onto main `0de40c0`; one conflict in `bench_proxy.rs`, both sides' bench knobs kept), after the A1–A3 fixes. `TOK` regenerated from `configs/default.toml` with the same one-line change (main had added a commented `static_cache` line).

| Command | Exit |
|---|---|
| `cargo fmt --all --check` | 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 |
| `cargo test --workspace` | 0 (1754 passed, 6 ignored) |
| `cargo test -p inumaki-models --features models-tests` | 0 (62 passed) |
| `cargo test -p inumakid --features models-tests -- --skip mirror_latency_20kb` | 0 (335 passed, 5 ignored) |
| `cargo test -p inumakid --features models-tests --test mirror_latency -- --nocapture mirror_latency_20kb` (debug, load 3.6–4.4) | 0 (0 timeouts; `support-email` p50 5.0 s, p95 9.5 s, max 38.9 s) |
| `scripts/harness-corpus/check-surnames.sh` | 0 |
| `bash scripts/check-docs.sh` | 0 |
| `cargo build --release -q -p inumaki-cli` | 0 |
| recall checkpoint (tuning, held-out, safety, harness-static corpus, name shapes, both profiles), `thorough`, `offline`, sequences, `tool-json` and held-out via the service, harness corpus free text | 0 each (18 runs) |
| `name-shape-outcomes.sh <p>` and `--compare` against Task 1 | 0 each, "no id worse" |
| `$B --config $TOK eval --profile {support-email,strict} --corpus $H --origin harness-static --targets …/harness-static-tokenize.toml …` | 0, 0 |
| `person-spans.sh support-email`, and with `free` | 0, 0 (25 and 66 spans, lists identical) |
| `cargo test --release -p inumaki-core --lib long_text_timing -- --ignored --nocapture` (before and after) | 0, 0 |

### Final fix wave, round 2 (2026-10-20)

Ruling L118: the CamelCase split applies in free text only. Re-review: a date, key, or hash cut by the 256-byte context window is no cue. Head `127a438`, release build, same `TOK`.

| Command | Exit |
|---|---|
| `cargo fmt --all --check` | 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 |
| `cargo test --workspace` | 0 (1756 passed, 6 ignored) |
| `bash scripts/check-docs.sh` | 0 |
| `cargo build --release -q -p inumaki-cli` | 0 |
| harness-static gates `support-email`, `strict` (`$HT`) | 0, 0 (`PERSON` 25, blocked 0) |
| harness tokenize gates `support-email`, `strict` | 0, 0 |
| tuning, held-out, `thorough`, `offline` baselines | 0 each (reports equal to `after`) |
| safety, name shapes, both profiles | 0 each (reports equal to `after`) |
| `name-shape-outcomes.sh <p>` and `--compare` against Task 1 | 0 each, "no id worse", outcomes identical to `after` |
| harness corpus free text, `block` and `TOK`, both profiles (measured) | 0 each: `PERSON` 66 → 76, blocked 1 |
| `person-spans.sh support-email` and with `free` | 0, 0 (25, list identical; 76, +10 spans listed above) |
