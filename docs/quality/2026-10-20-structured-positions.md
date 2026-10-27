# Structured positions: quality report

Plan `2026-10-20-structured-positions` (lane L3), spec `2026-10-20-structured-positions-design`. This file is written in stages: Task 1 wrote the "Before" section, Task 7 adds the "After" section (final measurement after the rebase onto `e041659`, the case registration and the single re-record of the tuning baselines). Task 8 adds "Residuals", "Rulings" and the closing "Summary".

## Provenance

- Commit measured: `2eeee59` plus the Task 1 working tree. The only Rust change in that tree is the `--outcomes` flag (a `#[serde(skip)]` list in `Report`); detection behavior is the behavior of `a82fd28` (no rule yet).
- Machine: Apple M4, 32 GB, Darwin 27.0.0 arm64 (`macos-aarch64`). Release build (`cargo build --release -p inumaki-cli`). Other lanes were running at the same time: load averages 10 to 15 at the benches (see below), so latencies are upper bounds.
- Seed 42 (tuning family, 79 cases + 2000 generated = 2079 documents), held-out seed 4242 (200 documents), embedded configuration (`configs/default.toml`, sha256 `31d513fd...`).
- Models (sha256 from the report provenance): `gliner-x-small` `d76b3349...`, `kiji-pii` `b5f33113...`, `mbert-ner-hrl` `1213fdd4...` (`INUMAKI_MODELS_DIR=$HOME/Library/Application Support/inumaki/models`).
- All numbers below are `before-*` reports in this directory. Per-document outcome files hold ids and outcomes only.

## Before

### Summary rows

Columns: report, profile, docs, `accepted_leak_docs`, `docs_with_leak`, `blocked_docs`, `uncertain_docs`, PERSON `gold_found`, PERSON `detected`. Recall runs (the Global Constraints compare against these): `support-email`, `strict`, `offline`, `held-out-*`, `safety-*`, `harness-static-*`, `name-shapes-*`. The negatives have no gold, so `detected` is the false-positive count.

| report | profile | docs | accepted leak | docs with leak | blocked | uncertain | PERSON found | PERSON detected |
|---|---|---|---|---|---|---|---|---|
| `support-email` | support-email | 2079 | 11 | 11 | 28 | 0 | 3918 | 4668 |
| `strict` | strict | 2079 | 4 | 4 | 19 | 0 | 3917 | 4668 |
| `offline` | offline | 2079 | 416 | 416 | 10 | 0 | 3122 | 4546 |
| `held-out-support-email` | support-email | 200 | 0 | 0 | 4 | 0 | 387 | 513 |
| `held-out-strict` | strict | 200 | 0 | 0 | 5 | 0 | 387 | 513 |
| `safety-support-email` | support-email | 79 | 0 | 0 | 2 | 0 | 63 | 79 |
| `safety-strict` | strict | 79 | 0 | 0 | 2 | 0 | 63 | 79 |
| `harness-static-support-email` | support-email | 93 | 0 | 0 | 0 | 0 | 0 | 25 |
| `harness-static-strict` | strict | 93 | 0 | 0 | 0 | 0 | 0 | 25 |
| `name-shapes-support-email` | support-email | 12 | 0 | 0 | 1 | 0 | 12 | 14 |
| `name-shapes-strict` | strict | 12 | 0 | 0 | 1 | 0 | 12 | 14 |
| `negatives-fnames-support-email` | support-email | 107 | 0 | 0 | 0 | 0 | 0 | 38 |
| `negatives-fnames-strict` | strict | 107 | 0 | 0 | 0 | 0 | 0 | 38 |
| `negatives-text-support-email` | support-email | 12 | 0 | 0 | 0 | 0 | 0 | 10 |
| `negatives-text-strict` | strict | 12 | 0 | 0 | 0 | 0 | 0 | 10 |
| `ext-support-email` | support-email | 2100 | 18 | 18 | 28 | 0 | 3927 | 4680 |
| `ext-strict` | strict | 2100 | 7 | 7 | 19 | 0 | 3926 | 4680 |
| `ext-offline` | offline | 2100 | 437 | 437 | 10 | 0 | 3122 | 4546 |
| `sequence-support-email` | support-email | 300 | 1 | 1 | 1 | 0 | 0 | 0 |
| `tool-json-held-out-support-email` | support-email | 300 | 0 | 0 | 1 | 0 | 0 | 0 |
| `tool-json-held-out-strict` | strict | 300 | 0 | 0 | 1 | 0 | 0 | 0 |
| `service-held-out-support-email` | support-email | 200 | 0 | 0 | 1 | 0 | 387 | 513 |
| `corpus-free-support-email` | support-email | 93 | 0 | 0 | 1 | 0 | 0 | 76 |

`ext-*` is the tuning corpus plus the 21 structured-position cases (2100 documents); its extra 21 documents account for the difference to the tuning rows. All baseline gates (`--baseline`) and target gates (`--targets`) exited 0.

### Structured-position cases (21), per-id outcome

`pass+residue` means the released text still holds a gold value. As the planner expected (spec 2.2): `support-email` leaks exactly the seven cases `shape-path-home-linux`, `shape-path-home-windows`, `shape-path-home-weber`, `shape-url-team`, `shape-url-staff-dotted`, `shape-url-github`, `shape-url-tilde`; `strict` leaks the three paths; `offline` leaks all 21.

| id | support-email | strict | offline |
|---|---|---|---|
| `shape-fname-surname-capital` | pass | pass | pass+residue |
| `shape-fname-surname-bare` | pass | pass | pass+residue |
| `shape-fname-surname-lower` | pass | pass | pass+residue |
| `shape-fname-surname-lower-word` | pass | pass | pass+residue |
| `shape-fname-first-surname-lower` | pass | pass | pass+residue |
| `shape-fname-first-surname-capital` | pass | pass | pass+residue |
| `shape-fname-surname-first` | pass | pass | pass+residue |
| `shape-path-home-linux` | pass+residue | pass+residue | pass+residue |
| `shape-path-home-mac` | pass | pass | pass+residue |
| `shape-path-home-windows` | pass+residue | pass+residue | pass+residue |
| `shape-path-home-dotted` | pass | pass | pass+residue |
| `shape-path-unc-home` | pass | pass | pass+residue |
| `shape-path-home-weber` | pass+residue | pass+residue | pass+residue |
| `shape-path-first-name` | pass | pass | pass+residue |
| `shape-url-team` | pass+residue | pass | pass+residue |
| `shape-url-people-full` | pass | pass | pass+residue |
| `shape-url-staff-dotted` | pass+residue | pass | pass+residue |
| `shape-url-github` | pass+residue | pass | pass+residue |
| `shape-url-tilde` | pass+residue | pass | pass+residue |
| `shape-url-linkedin` | pass | pass | pass+residue |
| `shape-scp-github` | pass | pass | pass+residue |

### Name-shape cases (12), per-id outcome

| id | support-email | strict |
|---|---|---|
| `shape-file-surname` | pass | pass |
| `shape-file-surname-hyphen` | blocked | blocked |
| `shape-file-surname-bare` | pass | pass |
| `shape-handle-surname` | pass | pass |
| `shape-path-claude` | pass | pass |
| `shape-username-claude` | pass | pass |
| `word-surname-model` | pass | pass |
| `word-surname-branch` | pass | pass |
| `word-surname-json` | pass | pass |
| `claude-first-name-de` | pass | pass |
| `claude-first-name-json` | pass | pass |
| `claude-first-name-en` | pass | pass |

### Negatives (precision corpus)

`structured-negatives-fnames.jsonl` (107 documents: each stem as written and, when different, in the mirror's detection spelling) plus `structured-negatives-text.jsonl` (12 path, URL and table lines), measured as free text (the `file-name` origin does not exist yet). `PERSON` detected: file names 38 + text lines 10 = **48** under `support-email` and under `strict`, as the planner measured. Both corpora have no gold, so every detection is a false positive; no document is blocked or uncertain.

### Bench (offline and support-email, 200 generated mails, avg 235 bytes)

`inumaki bench --profile offline`:

```
profile offline  docs 200  avg 235 bytes
detect   p50 0.2 ms  p95 0.4 ms  p99 0.8 ms
process  p50 0.4 ms  p95 0.7 ms  p99 1.3 ms
throughput 1491.1 docs/s
 9:43  up 22:44, 4 users, load averages: 14.63 13.36 10.72
```

`inumaki bench --profile support-email`:

```
profile support-email  docs 200  avg 235 bytes
detect   p50 19.2 ms  p95 35.8 ms  p99 41.3 ms
process  p50 43.7 ms  p95 91.4 ms  p99 107.6 ms
throughput 14.3 docs/s
 9:44  up 22:44, 4 users, load averages: 12.13 12.86 10.61
```

The machine was loaded by other lanes (load average above 10). Task 3, 4 and 4b compare their benches against these numbers and must note the load they ran under.

### Long input

```
scan --config configs/default.toml --profile offline long-paths.txt (245652 bytes, 1861 lines, deterministic)
median of 5 (/usr/bin/time -p real, 10 ms resolution): 0.03 s; runs: 0.03 0.03 0.03 0.03 0.03 
wall-clock runs (s): 0.037 0.037 0.036 0.035 0.034
median wall-clock: 0.036 s
 9:44  up 22:44, 4 users, load averages: 10.40 12.45 10.50
```

The `/usr/bin/time -p` median has 10 ms resolution (0.03 s); the wall-clock median over five runs (0.036 s) includes process start and model-free offline engine construction. The Task 4 and 4b budget (within 2x) is read against the wall-clock median 0.036 s and the `/usr/bin/time` median 0.03 s.

### B6 reproduction (spec 2.1)

`support-email`, `scan --config configs/default.toml --profile support-email --json -` on bare stems (synthetic). Confidences reproduce the spec's table to within 0.02; the spaced variant is every `_ - . +` spaced (the mirror's `spaced_variant`), not yet the date-aware detection variant of Task 3.

| stem | as written | spaced variant (every `_ - . +` spaced) |
|---|---|---|
| `mail-anfrage` | PERSON `mail-anfrage` 0.56 | nothing |
| `notizen` | PERSON `notizen` 0.51 | - |
| `readme` | PERSON `readme` 0.55 | - |
| `foto` | PERSON `foto` 0.53 | - |
| `tabelle` | PERSON `tabelle` 0.55 | - |
| `anhang` | PERSON `anhang` 0.64 | - |
| `index` | PERSON `index` 0.51 | - |
| `kundenliste` | PERSON `kundenliste` 0.53 | - |
| `offerte` | PERSON `offerte` 0.54 | - |
| `mahnung` | PERSON `mahnung` 0.53 | - |
| `anfrage-kunde` | PERSON `anfrage-kunde` 0.52 | nothing |
| `steuer-2025` | PERSON `steuer-2025` 0.51 | nothing |
| `Unbenannt` | PERSON `Unbenannt` 0.76 | - |
| `Untitled` | PERSON `Untitled` 0.65 | - |
| `Neues Dokument` | PERSON `Neues Dokument` 0.62 | - |
| `Mappe1` | PERSON `Mappe1` 0.73 | - |
| `Dokument1` | PERSON `Dokument1` 0.58 | - |
| `IMG_2034` | PERSON `IMG_2034` 0.62 | PERSON `IMG 2034` 0.66 |
| `DSC01234` | PERSON `DSC01234` 0.60 | - |
| `PXL_20261001_123456789` | PERSON `PXL_20261001_123456789` 0.60 | PERSON `PXL 20261001 123456789` 0.63 |
| `scan0001` | PERSON `scan0001` 0.51 | - |
| `Screenshot 2026-10-01 at 12.34.56` | DATE `2026-10-01` 0.85 | PHONE `2026 10 01` 0.66, PHONE `12 34 56` 0.86 |
| `foto-2025-07-14` | DATE `2025-07-14` 0.85 | PERSON `2025 07 14` 0.57 |
| `huber` | PERSON `huber` 0.56 | - |
| `gruber` | PERSON `gruber` 0.56 | - |
| `leitner` | PERSON `leitner` 0.65 | - |
| `mhuber` | PERSON `mhuber` 0.63 | - |
| `leitner-angebot` | PERSON `leitner-angebot` 0.62 | PERSON `leitner` 0.67 |
| `anna-gruber-cv` | PERSON `anna-gruber-cv` 0.69 | PERSON `anna gruber` 0.85 |
| `Rechnung_Huber_2026` | PERSON `Rechnung_Huber_2026` 0.68 | PERSON `Rechnung Huber` 0.84, INVOICE_ID `2026` 0.92 |
| `Huber` | PERSON `Huber` 0.78 | - |

## After

### Provenance

- Commit measured: `d6aa53f` (the branch rebased onto `main` `e041659`, `SANITIZER_GENERATION` 5) plus the Task 7 working tree: `structured_positions.toml` registered in `src/cases.rs`, `harness/name-shapes.jsonl` regenerated, `targets/name-shapes.toml` re-set, four tuning baselines re-recorded, and the `cli.rs` corpus-size constant derived from the case list. Release build (`cargo build --release -p inumaki-cli`).
- Same machine, seeds, embedded configuration and models as "Before". The tuning corpus is now 100 hand-written cases (79 + the 21 structured-position cases) plus 2000 generated mails = 2100 documents, so every tuning run has 21 more documents than its Task 1 report; `ext-*` (Task 1) is the same set under the old code and is the like-for-like comparison.
- All reports are `after-*` files in this directory. The thorough `before` reports (`before-ext-thorough.json`, `ext-outcomes-thorough-before.txt`) come from a release build of the Task 1 commit (`9a77f52`, rebased) with the same `--no-verifier-trials --corpus extended.jsonl` run; that build was also used as the "main" build in the benches.
- Load at the final benches: load averages 4.9 to 5.8 (Task 1: 10 to 15), so the latencies below are tighter than Task 1's.

### Summary rows

Columns as in "Before". A single value means before and after are equal. Held-out baselines did not change. `safety` and `name-shapes` grew by the 21 registered cases (79 -> 100, 12 -> 33). `thorough` has no Task 1 tuning report (L128 keeps it out of every earlier task); its comparison is the `ext-thorough` row.

| report | profile | docs (before -> after) | accepted leak | docs with leak | blocked | uncertain | PERSON found | PERSON detected |
|---|---|---|---|---|---|---|---|---|
| `support-email` | support-email | 2079 -> 2100 | 11 | 11 | 28 | 0 | 3918 -> 3937 | 4668 -> 4689 |
| `strict` | strict | 2079 -> 2100 | 4 | 4 | 19 | 0 | 3917 -> 3936 | 4668 -> 4689 |
| `offline` | offline | 2079 -> 2100 | 416 -> 419 | 416 -> 419 | 10 | 0 | 3122 -> 3140 | 4546 -> 4564 |
| `thorough (no Task 1 report; see text)` | thorough | 2100 | 0 | 0 | 1894 | 0 | 3937 | 4689 |
| `held-out-support-email` | support-email | 200 -> 200 | 0 | 0 | 4 | 0 | 387 | 513 |
| `held-out-strict` | strict | 200 -> 200 | 0 | 0 | 5 | 0 | 387 | 513 |
| `safety-support-email` | support-email | 79 -> 100 | 0 | 0 | 2 | 0 | 63 -> 82 | 79 -> 100 |
| `safety-strict` | strict | 79 -> 100 | 0 | 0 | 2 | 0 | 63 -> 82 | 79 -> 100 |
| `harness-static-support-email` | support-email | 93 -> 93 | 0 | 0 | 0 | 0 | 0 | 25 |
| `harness-static-strict` | strict | 93 -> 93 | 0 | 0 | 0 | 0 | 0 | 25 |
| `name-shapes-support-email` | support-email | 12 -> 33 | 0 | 0 | 1 | 0 | 12 -> 31 | 14 -> 35 |
| `name-shapes-strict` | strict | 12 -> 33 | 0 | 0 | 1 | 0 | 12 -> 31 | 14 -> 35 |
| `negatives-fnames-support-email` | support-email | 107 -> 107 | 0 | 0 | 0 -> 1 | 0 | 0 | 38 -> 7 |
| `negatives-fnames-strict` | strict | 107 -> 107 | 0 | 0 | 0 -> 1 | 0 | 0 | 38 -> 7 |
| `negatives-text-support-email` | support-email | 12 -> 12 | 0 | 0 | 0 | 0 | 0 | 10 -> 9 |
| `negatives-text-strict` | strict | 12 -> 12 | 0 | 0 | 0 | 0 | 0 | 10 -> 9 |
| `ext-support-email` | support-email | 2100 -> 2100 | 18 -> 11 | 18 -> 11 | 28 | 0 | 3927 -> 3937 | 4680 -> 4689 |
| `ext-strict` | strict | 2100 -> 2100 | 7 -> 4 | 7 -> 4 | 19 | 0 | 3926 -> 3936 | 4680 -> 4689 |
| `ext-thorough` | thorough | 2100 -> 2100 | 0 | 0 | 1895 -> 1894 | 0 | 3927 -> 3937 | 4680 -> 4689 |
| `ext-offline` | offline | 2100 -> 2100 | 437 -> 419 | 437 -> 419 | 10 | 0 | 3122 -> 3140 | 4546 -> 4564 |
| `sequence-support-email` | support-email | 300 -> 300 | 1 | 1 | 1 | 0 | 0 | 0 |
| `tool-json-held-out-support-email` | support-email | 300 -> 300 | 0 | 0 | 1 | 0 | 0 | 0 |
| `tool-json-held-out-strict` | strict | 300 -> 300 | 0 | 0 | 1 | 0 | 0 | 0 |
| `service-held-out-support-email` | support-email | 200 -> 200 | 0 | 0 | 1 | 0 | 387 | 513 |
| `corpus-free-support-email` | support-email | 93 -> 93 | 0 | 0 | 1 | 0 | 0 | 76 |

The negatives have no gold: `PERSON detected` is the false-positive count. File names: 38 -> 7 under `--origin file-name` (spec gate: at most 24; Task 3 target 7, never raised). Text lines: 10 -> 9. One file-name negative is blocked (`fname-058`, the bare camera stem `DSC01234`, known since Task 3); nothing in the negatives corpora leaks.

### Tuning baselines re-recorded once (the corpus grew by 21 documents)

Old value is the Task 1 baseline (2079 documents), new value is the Task 7 recording (2100). Per-kind recall changed only for `PERSON`; every other kind is bit-identical.

| profile | docs | leak rate | accepted leak rate | block rate | verifier_fn_rate | PERSON recall |
|---|---|---|---|---|---|---|
| support-email | 2079 -> 2100 | 0.005291 -> 0.005238 | 0.005363 -> 0.005309 | 0.013468 -> 0.013333 | 0.14997 -> 0.14187 | 0.938668 -> 0.938498 |
| strict | 2079 -> 2100 | 0.001924 -> 0.001905 | 0.001942 -> 0.001922 | 0.009139 -> 0.009048 | 0.14997 -> 0.14187 | 0.938428 -> 0.938260 |
| thorough | 2079 -> 2100 | 0 -> 0 | 0 -> 0 | 0.905724 -> 0.901905 | 0 -> 0 | 0.938668 -> 0.938498 |
| offline | 2079 -> 2100 | 0.200096 -> 0.199524 | 0.201063 -> 0.200478 | 0.004810 -> 0.004762 | 0.37695 -> 0.37507 | 0.747964 -> 0.748510 |

Leak counts did not rise: `accepted_leak_docs` is 11 / 4 / 0 for `support-email` / `strict` / `thorough` (as before) and 419 for `offline` (416 before). The three extra `offline` documents are the four accepted file-name residuals among the 21 new cases (offline leaked all 21 before any rule) minus the one old document Task 4 fixed (`shape-path-claude`, 416 -> 415). Against the like-for-like `ext-offline` (437) it is 18 fewer. `PERSON gold_found` rises in every profile (3918 -> 3937, 3917 -> 3936, 3122 -> 3140). The PERSON recall rate of the three NER profiles dips by 0.0002 because the denominator grew by 21 PERSON gold values while `gold_found` grew by 19 (two of the new gold values are not counted as found, and no document of the new set leaves a residue under `support-email`); `leaked` is 16 before and after.

**`verifier_fn_rate` reshuffle (ruling L79).** The rate moved 0.1500 -> 0.1419 (support-email and strict: 259/1727 -> 247/1741 false negatives per broken trial; offline 651/1727 -> 653/1741). The documents are drawn per document from one Rng stream, and the 21 cases sit before the generated mails, so they shift that stream (L79 measured +/- 0.01 to 0.02 for a change of this kind), and the 21 documents add 14 broken and 21 clean trials of their own. Task 4b's check removes one false negative on the old documents (259 -> 258, measured at Task 4b). The verifier-trial false positives rise by 7, all `Regex` hits (6 on URL spans, 1 on an EMAIL span; 48 -> 55 `support-email`, 9 -> 16 `offline`), which the 21 new documents' clean trials introduce; `Ner` 39, `Leak` 7 and `PERSON` 46 are unchanged. No verifier code changed after Task 4b, and no leak count depends on this rate. The comment at the top of each re-recorded baseline file records the same.

### Structured positions (21): per-id outcome, before -> after

`leak` means the released text still holds a gold value. `support-email`, `strict` and `offline` are Task 1 `sp` outcomes against Task 7 `sp` outcomes; `thorough` is the thorough before-build against this build (extended set).

| id | support-email | strict | thorough | offline |
|---|---|---|---|---|
| `shape-fname-surname-capital` | pass -> pass | pass -> pass | pass -> pass | leak -> leak |
| `shape-fname-surname-bare` | pass -> pass | pass -> pass | pass -> pass | leak -> leak |
| `shape-fname-surname-lower` | pass -> pass | pass -> pass | pass -> pass | leak -> leak |
| `shape-fname-surname-lower-word` | pass -> pass | pass -> pass | pass -> pass | leak -> leak |
| `shape-fname-first-surname-lower` | pass -> pass | pass -> pass | pass -> pass | leak -> pass |
| `shape-fname-first-surname-capital` | pass -> pass | pass -> pass | pass -> pass | leak -> pass |
| `shape-fname-surname-first` | pass -> pass | pass -> pass | pass -> pass | leak -> pass |
| `shape-path-home-linux` | leak -> pass | leak -> pass | blocked -> blocked | leak -> pass |
| `shape-path-home-mac` | pass -> pass | pass -> pass | blocked -> blocked | leak -> pass |
| `shape-path-home-windows` | leak -> pass | leak -> pass | blocked -> blocked | leak -> pass |
| `shape-path-home-dotted` | pass -> pass | pass -> pass | blocked -> blocked | leak -> pass |
| `shape-path-unc-home` | pass -> pass | pass -> pass | blocked -> blocked | leak -> pass |
| `shape-path-home-weber` | leak -> pass | leak -> pass | blocked -> pass | leak -> pass |
| `shape-path-first-name` | pass -> pass | pass -> pass | blocked -> blocked | leak -> pass |
| `shape-url-team` | leak -> pass | pass -> pass | pass -> pass | leak -> pass |
| `shape-url-people-full` | pass -> pass | pass -> pass | blocked -> blocked | leak -> pass |
| `shape-url-staff-dotted` | leak -> pass | pass -> pass | pass -> pass | leak -> pass |
| `shape-url-github` | leak -> pass | pass -> pass | blocked -> blocked | leak -> pass |
| `shape-url-tilde` | leak -> pass | pass -> pass | blocked -> blocked | leak -> pass |
| `shape-url-linkedin` | pass -> pass | pass -> pass | blocked -> blocked | leak -> pass |
| `shape-scp-github` | pass -> pass | pass -> pass | blocked -> blocked | leak -> pass |

After: `support-email` and `strict` 21/21 `pass` (before 14 and 18); `offline` 17/21 `pass` (before 0) with the four accepted file-name residuals; `thorough` 10 `pass`, 11 `blocked` by its verifier (before 9 and 12), none newly blocked. The `sp` compare (`name-shape-outcomes.sh --compare`) prints "no id worse" for all three profiles.

### Name shapes (33 ids)

`name-shape-outcomes.sh` for `support-email` and `strict`: 32 `pass`, 1 `blocked` (`shape-file-surname-hyphen`, as at Task 1), compare against the Task 1 outcomes "no id worse". The gate `eval --corpus name-shapes.jsonl --targets name-shapes.toml` exits 0 under both profiles with 1 of 33 documents blocked (0.0303). `max_block_rate` in `targets/name-shapes.toml` is set to 0.0304 (it was 0.0834 for 12 cases), so the gate now fails if a second name-shape case is blocked.

### Final fix wave (ruling L139)

The final review found that a capitalized document word cleared its identifier segment, so a lowercase or two-letter surname next to it was released in clear (`Bewerbung_mueller.pdf`, `Angebot_leitner_v2.docx`, `Rechnung_huber_2026`, `Rechnung_Li_2026.pdf`, `Rechnung Li`, `bewerbung_ng`). A document word now makes a span technical only when every other letter run of its token is vocabulary, a single letter, or a non-name-like stoplist word (design, implementation note after S3). The six shapes are registered cases (`shape-fname-doc-*`, `shape-text-doc-short-surname`; 21 -> 27 structured-position cases, name shapes 33 -> 39, tuning set 2100 -> 2106). Their before-outcomes come from a release build of `main` `e041659`. The four tuning baselines were re-recorded once more (header comments in each file). The reports below replace the Task 7 `after-*` files for tuning (4 profiles), `ext` (4 profiles, now 2106 documents: the Task 1 extended set plus the six), name shapes (2) and the `ns`, `sp` and `ext` outcome files. Held-out, harness, safety and negatives did not move and keep their Task 7 reports.

| run | Task 7 | final fix wave |
|---|---|---|
| tuning support-email (2100 -> 2106) | 11/11/28/3937/4689 | 11/11/28/3938/4694 |
| tuning strict | 4/4/19/3936/4689 | 4/4/19/3937/4694 |
| tuning thorough | 0/0/1894/3937/4689 | 0/0/1898/3938/4694 |
| tuning offline | 419/419/10/3140/4564 | 422/422/10/3140/4564 |
| name shapes, both (33 -> 39) | 0/0/1/31/35 | 0/0/1/32/40 |
| negatives file names, `PERSON` detected | 7 | 7 |
| harness-static, both | 0 refusals, `PERSON` 25 | unchanged |

- No old id changed outcome in any profile (the 2100 `ext` ids are identical to Task 7); every compare against the Task 1 before-outcomes, with `e041659` outcomes for the six, exits 0 "no id worse" (`ext` in four profiles, held-out in two, `ns` in two, `sp` in three).
- The six new cases: `pass` under `support-email` and `strict`; under `thorough` four are blocked by the verifier and two pass; under `offline` the three lowercase-surname stems leak (no NER, no surname list), exactly as on `e041659`. That is the whole `offline` rise 419 -> 422; it is no regression of an existing document.
- `Li` and `ng` are below the residue minimum (three characters), so the eval cannot show a leak of them; the unit test `document_words_never_clear_a_surname_next_to_them` pins both. `ng` in `bewerbung_ng` is tagged by no detector, on `e041659` as now.
- `name-shapes.toml` `max_block_rate` 0.0304 -> 0.0257 (1 of 39 blocked, `shape-file-surname-hyphen`).
- The home-login agreement property test at 1 000 000 cases (release) passes; the L134 code-sample gate shows 0 home-login refusals and 0 candidate fails (code sample: `support-email` 17 blocked, as at Task 7; rooted chunks: `support-email` 9 + 19 + 29 blocked against 9 + 19 + 28, `offline` 4 over all 540 documents as before). Round 2 (L140) cut the document-word check's runs at inner capitals as the segments are cut (`FolderInfo`, `FolderConfig`, `FolderStatus` are technical again), which removed one of two extra blocks (chunk 70 of the M5 folder-mirror plan); the other (chunk 9 of the app-redesign plan) holds `FolderInfo.outbox_destination` and `FolderStatus.outbox_destination`, kept by design (residual below). After round 2 every per-case outcome equals the final-fix-wave outcomes above (`ext` in four profiles, held-out, `ns`, `sp`), so no report or baseline moved.

### Per-case gate (S27, L3-25, S30)

All compares run `name-shape-outcomes.sh --compare <before> <after>`:

| compare | support-email | strict | thorough | offline |
|---|---|---|---|---|
| extended set (2100 ids), Task 1 build vs this build | no id worse (exit 0) | no id worse (exit 0) | no id worse (exit 0) | no id worse (exit 0) |
| held-out (200 ids) | no id worse (exit 0) | no id worse (exit 0) | not run | not run |
| tuning ids changed outcome (all of them improvements) | 7 | 3 | 1 | 18 |

- No case leaks that did not leak before, and none is newly blocked or uncertain.
- `ext` leak counts, before -> after: `support-email` 18 -> 11 (accepted and docs with leak), `strict` 7 -> 4, `thorough` 0 -> 0, `offline` 437 -> 419. The 21 new ids account for every changed id except one (`shape-path-claude` under `offline`, leak -> pass).
- New cases that leaked before and still leak after: **only `offline`, four ids**: `shape-fname-surname-capital` (`Rechnung_Huber_2026`), `shape-fname-surname-bare` (`Huber`), `shape-fname-surname-lower` (`huber`), `shape-fname-surname-lower-word` (`leitner-angebot`). Reason: the `offline` profile has no NER and no surname list, and a lone surname in a file-name stem has no cue the deterministic detectors can read (L127, S26 accepted residual). `support-email`, `strict` and `thorough` have none.
- Under `thorough` its verifier blocks 11 of the new cases (`shape-path-home-linux`, `-mac`, `-windows`, `-dotted`, `-unc-home`, `shape-path-first-name`, `shape-url-people-full`, `-github`, `-tilde`, `-linkedin`, `shape-scp-github`); before the work it blocked 12 (it also blocked `shape-path-home-weber`).

Release-build timing tests, once more: `path_names_timing` (4, 30, 120, 240 KB, prose and JSON line) 240 KB prose 8.2 ms, JSON line 13.7 ms (budget 20 ms, linear); `home_login_timing` 4 KB 0.031 ms, 30 KB 0.19 ms, 120 KB 0.76 ms, 240 KB 1.27 ms; `long_text_timing` (technical detector) passes.

### Bench

Alternating a main-behaviour build (the Task 1 commit, `9a77f52`) and this build, two runs each, `inumaki bench`, 200 generated mails (full output in `after-bench-offline.txt` and `after-bench-support-email.txt`). Load averages 4.9 to 5.8.

| profile | build | detect p50 / p95 / p99 (ms) | process p50 / p95 / p99 (ms) |
|---|---|---|---|
| offline | main run 1 / 2 | 0.2 / 0.4 / 1.5 ; 0.2 / 0.4 / 1.4 | 0.4 / 0.7 / 1.3 ; 0.4 / 0.7 / 1.8 |
| offline | this build run 1 / 2 | 0.2 / 0.4 / 0.8 ; 0.2 / 0.3 / 0.4 | 0.4 / 0.6 / 0.8 ; 0.4 / 0.7 / 0.8 |
| support-email | main run 1 / 2 | 18.0 / 36.3 / 38.8 ; 18.9 / 32.7 / 41.8 | 44.3 / 88.6 / 112.3 ; 45.4 / 93.5 / 123.0 |
| support-email | this build run 1 / 2 | 17.6 / 33.1 / 50.3 ; 19.6 / 33.7 / 37.2 | 41.3 / 92.8 / 129.5 ; 45.7 / 96.9 / 109.4 |

Task 1 (load 12 to 15): offline detect p50 0.2 ms, support-email detect p50 19.2 ms. `offline` `detect` p50 is unchanged (0.2 ms, budget 0.1 ms); `support-email` p50 differences are inside the run-to-run spread.

Long input (`scan --profile offline` on the 240 KB `long-paths.txt`): `/usr/bin/time -p` median of 5 0.04 s (Task 1 0.03 s; budget 2x = 0.06 s); interleaved wall clock median of 9: main build 0.0348 s, this build 0.0445 s (1.28x). See `after-bench-long-scan.txt`.

### Per-rule effect (after each task)

`PERSON detected` on the negatives (file names + text lines, `support-email`), structured-position passes (`support-email` / `offline`) and `offline` tuning documents with a leak. Task 1 is the 38 + 10 = 48 and 0 / 0 baseline; "-" is a measurement that task did not take. The tuning documents are the 2079 of the task's own run; `support-email` tuning leak docs stay 11 throughout.

| after | negatives PERSON detected | sp pass `support-email` | sp pass `offline` | offline tuning leak docs |
|---|---|---|---|---|
| Task 1 (no rule) | 48 (38 + 10) | 14 | 0 | 416 |
| Task 2 (B6 vocabulary, fix 1) | 19 file names (text -) | 14 | 0 | 416 |
| Task 3 (camera counters, ISO dates, detection variant) | 16 (7 + 9) | 14 | 0 | 416 |
| Task 4 (paths and URLs, fix 1) | 16 | 21 | 17 | 415 |
| Task 4b (home-login backstop; fix 1, fix 2) | 16 | 21 | 17 | 415 |
| Task 7 (final, 2100-document corpus) | 16 (7 + 9) | 21 | 17 | 419 (415 + 4 new-case residuals) |

### Acceptance and gate targets

| gate | result |
|---|---|
| tuning `support-email`, `strict`, `offline`, `thorough` (`--baseline`) | exit 0 each; leak docs <= before; `PERSON gold_found` > before |
| held-out `support-email`, `strict` (`--baseline`, `--outcomes`) | exit 0 each; no id worse |
| safety (21 new cases included, 100 documents) | exit 0 both profiles; targets met |
| name shapes (33 ids) | exit 0 both; block rate 0.0303 <= 0.0834 (target now 0.0304) |
| structured positions after Task 4b | `support-email` 21/21, `strict` 21/21, `offline` 17 (14 path/URL ids and the 3 first-name stems) |
| file-name negatives | `PERSON` 7 <= 7 (Task 3 target), strict 7 |
| text negatives | `PERSON` 9 <= 10 |
| harness-static (both profiles) | 0 refusals, `PERSON` 25 <= 25 |
| per case (extended set, 4 profiles; held-out, 2 profiles) | no id worse; overall leaks <= before |
| sequence, `tool-json` held-out (both), service held-out, free-text harness | exit 0; leak counts equal to their Task 1 reports (1, 0, 0, 0, 0) |
| bench `offline` `detect` p50 | 0.2 ms, within 0.1 ms of before |
| long-input scan | 0.04 s vs 0.03 s (<= 2x) |
| path detector timing (release) | 240 KB: 8.2 ms prose, 13.7 ms JSON line (<= 20 ms, linear) |
| home-login agreement property test, 1,000,000 cases (release) | pass |
| code-sample gate (L134 (a)), refreshed on this build, Free origin | 0 home-login refusals, 0 candidate fails: 181 code documents (harness code docs, synthetic files, 69 sampled `crates/**/*.rs`) and 359 4 KiB chunks of `.rs`/`.sh`/`.md` files holding a root or `~`, under `support-email` and `offline` |
| full gate | `cargo fmt --all --check`, `clippy --workspace --all-targets -D warnings`, `cargo test --workspace` (1797 passed, 8 ignored), models tests, `scripts/check-docs.sh`: exit 0 |

## Residuals

What this plan leaves, each with its reason (the same list, worded for a reader of the threat model, is "Structured-position residuals" in `docs/threat-model.md`):

- **Four `offline` file-name cases still leak** (S8, S26, L127): `shape-fname-surname-capital` (`Rechnung_Huber_2026`), `shape-fname-surname-bare` (`Huber`), `shape-fname-surname-lower` (`huber`), `shape-fname-surname-lower-word` (`leitner-angebot`). `offline` has no NER and there is no surname list at runtime; a first name next to the surname is enough (the three first-name stems pass). The model profiles pass all four.
- **A rare-surname document word in a file position** (S3, L123, L129): under `TextOrigin::FileName`, or in a token with an extension or a path separator, `Steuer` alone or in `Bewerbung Steuer` is dropped when the model tags it below 0.85; the verifier's NER is the backstop. Outside file positions nothing changed.
- **Document words next to unknown or short words** (L139, L140, L141): a document word clears nothing when another letter run of its token is no vocabulary word, so an identifier such as `FolderInfo.outbox_destination` keeps a model `PERSON` span (a precision cost: under `support-email` it can block a code text, chunk 9 of the app-redesign plan in the rooted code gate). The other way round, a lowercase `_` token with a two-letter surname and no capital (`bewerbung_ng`) takes the machine-word path and is dropped when the model tags it whole, as on `e041659`; the model tags nothing there today.
- **A path name with no cue** (S8, S12): `/projekte/huber/plan.txt` is read by no deterministic detector and checked by no verifier rule; only the model can tag it.
- **Multi-part and multi-word logins**: `weber.koch` is a name only after a home root (after a person cue only `weber` is tokenized, `.koch` read as an extension; as a code-host account neither part is; measured under `offline`). `C:\Users\Anna Maria Gruber\` tokenizes `Anna` only, and the verifier does not refuse `Maria Gruber` (its login ends at the space).
- **The home-login backstop's reach** (L127, L134, L135, L136): UNC `\\server\Users\x` and `home$` shares and the flattened `-Users-<login>-…` directories are sanitizer-only; a slashless `~login` followed by a word (`frag ~mhuber dazu`), after an operator, or in capitals is neither tokenized nor refused; a URL-encoded nested URL is not decoded; a real login equal to a generic account passes both lines; a slashless `~login` with a non-ASCII letter (`~müller`) is read by neither side.
- **`GENERIC_ACCOUNTS` and `identity.rs` drift** (S11, L124, L131): the core list (63 words) exempts `travis`, `jenkins` and `guest` too; `crates/inumakid/src/identity.rs` keeps its own smaller list. Follow-up after both lanes merge: `identity.rs` reads the core list, with an agreement test.
- **Pieces over 4 096 bytes** (L133, L135): after the cut at JSON and markup punctuation, a long `PATH=` line joined only by `:` or `;` is skipped by the path detector; the verifier's home-login check still reads it.
- **Precision costs, not leaks** (S13, L3-28, L3-29, L135, L136): code-host organizations and directories after a person cue become `PERSON` tokens (`github.com/openai`, `src/user/model.rs`); every non-generic segment after a home root is tokenized (`/home/about`, two-letter logins, `/home/foto/`, also inside URL paths); `x=~mask/2` is tokenized. 0 refusals on the code-sample gate and the harness corpus. `thorough` blocks 11 of the 21 new cases by its verifier (12 before).
- **Glued camera counters** (L3-27): `DSC01234` is withheld by the verifier's bare-identifier check and gets the mirror's opaque name; the one blocked file-name negative (`fname-058`).
- **Year linking across stems** (L130): a junk model `PERSON` over `Rechnung Huber 2026` lets the linker tokenize a bare `2026` in later stems of the batch. Follow-up: the linker never links a digit-only name part.
- **Mirrored CSV and long tables** (S15, L123): the mirror sends one CSV record per block and cuts text into 4 KiB chunks, so name columns in mirrored CSV, and in later chunks of a long Markdown table, rely on the model until `MirrorEngine` carries column hints.
- **Phase 2, deferred** (L128, design §9): names in table columns and after person labels, lowercase plates, typo'd and glued labels and long-prefix numbers stay model-only; the 13 cases are in `crates/inumaki-eval/cases/structured_positions_phase2.toml`, unregistered, and all leak under `offline`.
- **Deferred minors** (Task 3 review): a device prefix drops the L85 guard whatever the number length; unmarked order-number words (`auftrag`, `beleg`, `projekt`) get the ISO-date exemption; a contrived mixed space/`_` stem can cut a date-shaped piece out of an identifier (the byte-pass deviation, L130).

## Rulings

Integrator (`L…`) and controller (`L3-…`) rulings made during this plan, in order, each with its cost. The planner's rulings S0–S32 are stated with reasons and costs in the design spec; its §10 records where the build differs.

| ruling | decision | cost |
|---|---|---|
| L119 | `on_uncertain` stays `block` (fail closed); the T6 proposal is accepted; the L3-19 bisect gap is accepted (fast-forward merges only) | uncertain spans keep refusing (availability, not privacy) |
| L121 | next plan: names and identifiers in structured positions, B6 first; recall first; stay out of `crates/inumaki-proxy` | proxy origin wiring left to lane L2 |
| L3-23 | adopt every finding and minor of plan review 1; Opus re-review before Task 1 | one revision round |
| L3-24 | S3 (Census floor) and S12 (no verifier change) stand as planner rulings, reported for override | a rare-surname document word alone below 0.85 drops; no deterministic second line for path names (S12 later overruled by L127) |
| L123 | S15 is a recorded residual; S11 accepted with the drift named; S3 accepted only position-scoped | mirrored CSV name columns stay model-only; the generic lists drift until the follow-up |
| L124 | fix the three Criticals in revision 2 (stoplist surnames kept, digit separators only in date shapes, no lookaround); the Importants adopted | one revision round, more before-reports |
| L3-25 | the final gate is per case against the same set on the base code; leaking new cases covered or listed by id, never re-recorded silently | one more round on the `offline` file-name cases |
| L127 | S12 overruled: the home-folder login is a detected entity with a verifier backstop and a round trip, one task (4b); the four `offline` file-name cases accepted by id | one more task with its own review; four `offline` leaks accepted |
| L128 | scope cut to B6, paths and URLs, home login, gate and docs; table columns, labels and plates deferred to Phase 2; cheaper reviews and evals | the Phase 2 shapes stay model-only |
| L3-26 | revision 2 folds re-review 1, L127 and L128; the file position comes from the caller or the token shape, never "the whole text is one word" | one more revision |
| L129 | file position = an extension or a path separator, or `FileName`; an initial counts as a name part; the detection variant inherits the file position; no plan re-review after revision 2 | under `FileName` a rare-surname word alone drops (S3 residual) |
| L3-27 | `DSC01234`-style glued counters stay withheld by the verifier's bare-identifier check | such files get the opaque mirror name instead of their own |
| L130 | cross-stem year linking is a follow-up; the byte-pass detection variant is a recorded deviation; a non-model regex test on the variant is added in Task 4 | junk year tokens remain (precision) |
| L3-28 | a `Rare` vocabulary word is a login after a home root | `/home/foto/` becomes a `PERSON` token (meaning lost) |
| L3-29 | a `~login` without a slash is a candidate (narrowed by L3-30) | precision on `~word` prose |
| L131 | Task 4 fix round items 1–4 plus the L130 test; the `GENERIC_ACCOUNTS` residual to Task 8; tilde and rare-login concerns to Task 4b | `travis`, `jenkins`, `guest` exempt as logins |
| L132 | the JSON-escaped URL fix is folded into Task 4b | about ten lines, covered by the Task 4b review |
| L133 | Task 4 approved; nested query-string URLs added in Task 4b; long `;`/`:` pieces a residual | a long `PATH=` line is not read for names |
| L3-30 | slashless `~word` only in a login context, the same rule on both sides | a `~login` after an operator or followed by a word goes to the model only |
| L134 | code-sample gate (0 home-login refusals), the two sides agree, placeholders only at segment start, `/homes/` both sides, UNC a residual, verifier deviations into the design | every non-generic segment after a home root is tokenized (precision); UNC and `home$` sanitizer-only |
| L135 | the narrower L3-30 accepted (`frag ~mhuber dazu` a residual); `/home/about` tokenized; a pinned R5 panic test; long pieces refused only with a home root | `/home/about` loses its meaning; that `~login` shape is model-only |
| L136 | `~login/` after `:` or `=` is a root on both sides; slashless only after an option or an all-caps variable | `x=~mask/2` is tokenized, never refused |
| L137 | `x=~mask/2` tokens accepted; the agreement property test at 1 000 000 cases in the release gate; the three found inputs pinned | about 16 s in the release gate |

## Summary

The plan fixed the user-visible mirror bug (B6): ordinary file names are no longer renamed into person tokens (`PERSON` on 107 ordinary stems 38 -> 7, gate at most 7), while names, IBANs, social security and card numbers in stems stay tokenized (gated models test). Names in paths and URLs are now detected deterministically in every profile and both origins, and a home-folder login left in clear fails the verifier's own check. Recall rose and no leak count rose like for like: extended set `support-email` 18 -> 11 leaking documents, `strict` 7 -> 4, `thorough` 0 -> 0, `offline` 437 -> 419 (the tuning `offline` row reads 416 -> 419 only because the tuning set now holds the four accepted `offline` file-name residuals, which are new documents); `PERSON gold_found` up in every profile; held-out unchanged; harness corpus 0 refusals and `PERSON` 25 under both profiles. Latency stayed within budget (`offline` detect p50 0.2 ms; long input 0.04 s against 0.03 s; path detector 13.7 ms at 240 KB; home-login check 1.27 ms at 240 KB).

Per case (S27): no id is worse in any profile on the extended set (`support-email`, `strict`, `thorough`, `offline`) or on the held-out set (`support-email`, `strict`). New cases that leaked before and still leak: under `offline` only, `shape-fname-surname-capital`, `shape-fname-surname-bare`, `shape-fname-surname-lower`, `shape-fname-surname-lower-word` (no NER, no surname list; accepted, L127); none under `support-email`, `strict` or `thorough`. `thorough` blocks 11 new cases by its verifier (`shape-path-home-linux`, `-mac`, `-windows`, `-dotted`, `-unc-home`, `shape-path-first-name`, `shape-url-people-full`, `-github`, `-tilde`, `-linkedin`, `shape-scp-github`), one fewer than before.

Residuals, in short (full list above): a lone surname in a file name under `offline`; a rare-surname document word in a file position; a path name with no cue (`/projekte/huber/`); `weber.koch` outside a home root and the third word of a three-word login (`Anna Maria Gruber`); UNC, `home$` and flattened directories, a slashless `~login` followed by a word, and URL-encoded nested URLs outside the verifier's check; the generic-account exemptions and the `identity.rs` drift; pieces over 4 096 bytes; precision costs on code-host organizations, `/home/about`, `x=~mask/2`; glued camera counters withheld; year linking across stems; mirrored CSV columns and long tables; and the deferred Phase 2 shapes (table columns, person labels, lowercase plates, typo'd and glued labels, long prefixes), all still model-only.
