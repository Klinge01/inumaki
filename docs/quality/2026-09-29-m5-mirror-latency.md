# Folder mirror latency, 20 KB file (milestone 5)

Measured 2026-10-05 with `crates/inumakid/tests/mirror_latency.rs` (feature `models-tests`). These numbers are experimental and indicative. They are not a gate: the milestone ships measured (roadmap spec section 2, M5 spec section 16.2).

## Setup

| | |
|---|---|
| Machine | Apple M4, 10 cores, 32 GiB RAM, macOS 27.0 (Darwin 27.0.0) |
| Commit | `26342da` plus the test in `899bca5` |
| Build | `cargo test --release -p inumakid --features models-tests --test mirror_latency` (the release profile; a debug build is shown separately below) |
| Load | load average 4.2 (1 min) when the final run started, 6.3 when it ended; a shared development machine, not idle |
| Models | the pinned set in `~/Library/Application Support/inumaki/models` (GLiNER x-small, mBERT NER, Kiji PII) |
| Mirror settings | defaults: debounce 500 ms, 1 worker, 1 MiB file limit |

**What is timed.** One synthetic letter of at least 20 KB (several of the generator's documents concatenated), written into a watched source folder with an idle daemon, 50 times, after one untimed warm-up file. The clock starts at the write and stops when a new entry appears in the mirror (a file or a placeholder; a withheld file's placeholder has an opaque name, so entries are counted, not looked up by name). The mirror is polled every 2 ms, and the next run starts 300 ms later. The letters come from `inumaki-eval`'s generator, a different text for each run so the sanitization cache never answers (a repeated text would measure the cache). The generator's documents are dense with identifiers, which matters below. The mirror's own `debug` events supply the breakdown: the duration of each engine call (the wall time of one `sanitize()` call, which includes waiting for the session and the lock; an upper bound on how long the namespace lock was held) and, for released files, the sanitize and write time. They carry numbers only.

## Results (release build)

| Profile | p50 | p95 | max | Files withheld | Sanitize p50 / p95 (released files) | Write p50 / p95 | Longest engine call (wall time, upper bound of the lock hold) p50 / p95 / max |
|---|---|---|---|---|---|---|---|
| `offline` | 754 ms | 1060 ms | 1131 ms | 0 of 51 | 197 / 438 ms | 0 / 1 ms | 55 / 110 / 143 ms (150 calls, three per file) |
| `support-email` | 1272 ms | 1465 ms | 1597 ms | 51 of 51 | not applicable: no file was released | not applicable | 622 / 758 / 909 ms (50 calls, one per file) |

"Files withheld" counts blocked placeholders after the run, including the warm-up file. No run timed out (60 s limit).

**Breakdown.** The debounce takes 500 to 625 ms of every total (M5 spec section 6.1) and is not instrumented separately. Under `offline`, the remainder of the median (754 ms) is the sanitize stage: about 200 ms of engine time plus queueing, with the write under 1 ms. Under `support-email`, every letter was withheld at the first sub-batch the verifier judged blocked, so the engine call (about 620 ms) plus the debounce accounts for the 1.27 s median. That is the time to a placeholder, not to a released file. A released 20 KB file under `support-email` needs every sub-batch plus the verification blocks and was **not measured**, because this corpus never produced one; it would take several of those 600 ms calls.

**Blocked-file rate.** 0 of 51 under `offline`; 51 of 51 under `support-email` on the generated letters. The generated letters carry far more identifiers than a typical business letter, and `support-email` withholds a file at the first uncertain or blocked block, so 51 of 51 says the verifier is strict on this corpus, not what a real folder would see. In the model-backed no-original fixture (below), 1 of the 9 source files was withheld as blocked; the oversized file and the symlink got unsupported-class placeholders.

**Namespace lock.** The longest single engine call was 143 ms under `offline` and 909 ms under `support-email`. The mirror halves its sub-batch target after any call over 1 s (M5 spec section 5.1), and no call crossed that line. The hook's deadline is 10 s.

## Against the 1 s target

*Experimental, measured, not a gate.* The integration spec's target is one 20 KB file within 1 s of the change (integration spec section 12). The debounce alone is 500 to 625 ms. Under `offline` the median meets the target (754 ms) and the 95th percentile and the maximum miss it narrowly (1060 ms, 1131 ms). Under `support-email` the measured time to a placeholder already exceeds it (median 1272 ms), and a released file would take longer, so the model-backed profile misses the target. The dominant stage in both profiles is sanitize, and under `support-email` it is the model-backed engine call, as M3's 800 ms per 5 KB cold figure predicted. The levers are faster model inference in the engine, the sanitization cache (a file edited a little re-sanitizes only its changed blocks), and the debounce setting.

## Sensitivity: load and build type

The same test on a heavily loaded machine (load average about 40, release build): `offline` p50 1330 ms, p95 1747 ms, max 1826 ms, sanitize p50 769 ms, longest engine call 590 ms. A debug build (load average about 15): `offline` p50 6762 ms, p95 10168 ms, max 10429 ms, sanitize p50 6243 ms, engine calls up to 3140 ms. Treat a debug build's mirror latency as meaningless; only the release numbers above describe the product, and even those move with load.

## Daemon start with a 2000-file folder

A folder of 2000 small files (20 directories of 100, `offline` profile) was mirrored, the daemon stopped, and a new daemon started on the same data directory (release build):

| | |
|---|---|
| `AppState::start` | 1 ms |
| Until the control socket answered (includes `Folders::start`: decrypting the manifest, arming the watches) | 14 ms |
| First scan of the 2000 files (not part of start) | about 1 s |

The per-folder startup reconcile runs after the socket answers and was not timed. Two further runs measured 3 ms and 37 ms (load average about 40) and 11 ms and 416 ms (debug build). The manifest here is 2000 small records; a folder with far more files, or one with long paths, will take longer, and was not measured.

## The no-original test under a model profile

`no_original_in_the_mirror_under_support_email` runs the M5 spec section 16.1 item 1 fixture through the real engine under `support-email`: names in text, CSV cells and headers, JSON keys, values, and numbers, `.eml` headers, an HTML entity, a Windows-1252 CSV, and names of files, directories, a symlink, and an oversized file. After the scan, no original (whole, NFC, NFD, lower case, or with underscores) appears in any mirror path or file. It passed (15 mirror entries, 1 blocked placeholder).
