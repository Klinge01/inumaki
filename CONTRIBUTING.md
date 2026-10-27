# Contributing to inumaki

inumaki is a personal project in active development, pre-1.0. Issues and pull requests are welcome. Because it is a privacy boundary, a few rules are stricter than in most projects; read [Privacy rules](#privacy-rules-for-contributors) before you write code that touches text, logs, or errors.

To report a vulnerability or a leak across the boundary, do not open an issue. See [SECURITY.md](SECURITY.md).

## Build

You need Rust 1.85 or newer (edition 2024). The desktop app also needs Node and npm (the package manager is npm; do not use pnpm or yarn).

```bash
cargo build --workspace
cargo test --workspace
cargo run -p inumaki-cli -- scan FILE        # print detected spans
cargo run -p inumaki-cli -- tokenize FILE    # print sanitized text, no daemon
```

The workspace crates are `inumaki-core` (pure, no IO, no ONNX), `inumaki-models`, `inumaki-proxy`, `inumaki-cli`, `inumaki-eval`, and the service and connector crates around `inumakid`. Dependencies point one way: core ← models ← {proxy, cli, eval}. `docs/architecture.md` describes the crates. The desktop app is a separate Cargo project and an npm project under `apps/inumaki-app/`; `apps/inumaki-app/README.md` covers building it.

Model-backed work needs the pinned models (about 370 MB):

```bash
cargo run -p inumaki-cli -- models pull
```

Point `INUMAKI_MODELS_DIR` at that directory when you run the model-backed tests below.

## The gate

A change is ready when all of these pass. Run the first group on every change.

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
bash scripts/check-docs.sh
```

`scripts/check-docs.sh` checks the Markdown: relative links and `#anchors` resolve, every setting in `configs/default.toml` is documented in `docs/configuration.md`, and backticked repository paths exist. Run it whenever you touch a `.md` file, a path, or a setting. Warnings are errors; do not silence a lint to get a green build.

Run these when the change touches the desktop app (`apps/inumaki-app/`):

```bash
cargo clippy --manifest-path apps/inumaki-app/src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path apps/inumaki-app/src-tauri/Cargo.toml
cd apps/inumaki-app && npm run lint && npm run typecheck && npm test
```

Run these when the change touches `inumaki-core`, `inumaki-models`, `inumaki-eval`, `configs/`, or anything that can change what is detected or verified:

```bash
INUMAKI_MODELS_DIR=… cargo test -p inumaki-models -p inumakid --features models-tests

cargo run --release -p inumaki-cli -- eval --profile support-email --baseline crates/inumaki-eval/baselines/support-email.toml
cargo run --release -p inumaki-cli -- eval --profile offline       --baseline crates/inumaki-eval/baselines/offline.toml
cargo run --release -p inumaki-cli -- eval --profile strict        --baseline crates/inumaki-eval/baselines/strict.toml
```

The three eval gates compare recall, leak, and block rates with committed baselines and fail on a regression. The `offline` gate needs no models and is deterministic. The baselines were measured on Apple Silicon: int8 ONNX kernels differ on x86, so a model-backed gate can disagree there without a real regression. If you change a metric on purpose, re-record the baseline with `--write-baseline` and commit the before and after reports under `docs/quality/` in the same commit, saying why. A gate is never relaxed to get a build green. `docs/ci.md` lists what the continuous integration jobs run, including the held-out baselines and the reference runner.

Do not run every command on every commit while you iterate. Run the tests of the crate you touch (`cargo test -p inumaki-core token::`), then the full gate once before you open the pull request.

## Test tiers

| Tier | How to run | Needs |
|---|---|---|
| Unit | `cargo test -p CRATE` | nothing |
| Integration | `cargo test --workspace` (files under each crate's `tests/`) | nothing; they use temporary directories and in-process daemons |
| `models-tests` | `INUMAKI_MODELS_DIR=… cargo test -p inumaki-models -p inumakid --features models-tests` | the pinned models |
| `mail-tests` | `bash scripts/greenmail.sh start`, then `cargo test -p inumakid --features mail-tests --test mail_greenmail` | Docker, for the pinned GreenMail image |
| User-gated harness runs | `harness-tests` in the app (`cargo test --manifest-path apps/inumaki-app/src-tauri/Cargo.toml --features harness-tests --test harness_real -- --nocapture`), and the manual smoke test in `docs/smoke-claude-code.md` | the real `claude` and `codex` binaries, a login, and a throwaway daemon |

The last tier changes your machine or runs your own software and logins. Do not run it from a script or from CI, and do not add a test that does. Say in your pull request when you did not run it.

Write tests for critical behaviour: privacy (nothing sensitive in logs, errors, records, or `Debug`), fail-closed paths, data loss and corruption, and the contracts other components consume (control-API shapes, token grammar, schema tables). A test of formatting, a trivial getter, or a duplicate of an existing happy path is not needed.

## Privacy rules for contributors

inumaki's value is that the identifiers it detects stay local. A code path that could serialize a request is a privacy bug, so these rules apply to every change:

- **Nothing sensitive in logs, errors, `Debug`, records, or telemetry.** No original text, token, secret, dataset slug, file name, raw URI, or upstream JSON key. This holds for `tracing` events, error messages, panic messages, API error bodies, journal and activity records, metrics, and `Debug` output. Types that can hold text get a hand-written `Debug` that prints counts, ids, and flags, and no `Display`. Workspace lints deny `dbg!`, `print!`, and `eprint!` outside the CLI and the daemon binary; `inumaki-mcp` may also write to stderr (a one-line startup failure, `crates/inumaki-mcp/src/main.rs`). Do not work around the lints.
- **Fixed error classes.** An error says what class of thing failed (`privacy_block`, `upstream_unreachable`), not what the input was. Do not interpolate a value into an error to make it easier to debug; add a count or an id instead.
- **Fail closed.** When models are missing, a detector errors, the vault cannot be read, or a result cannot be verified, the request is refused or the text is withheld, never forwarded unchecked or served by a weaker profile. The exceptions are documented operator opt-outs (for example `proxy.uncertain`, `verifier.on_uncertain`, `proxy.binary`, `gateway.tripwire = "notify"`, `proxy.definitions_account_values = "allow"`, upstream `extra_headers`, and `allow_no_ner`; see `docs/configuration.md` and `docs/threat-model.md`), and the hook's pass-through when its program is missing, killed, or times out; do not add another without recording it there.
- **Synthetic data only.** Tests, fixtures, examples, bug reports, and eval corpora use invented people, addresses, and identifiers. Never paste a real customer, a real mailbox, a real key, or a real harness transcript into the repository or an issue.
- **A false negative is the dangerous failure.** A missed identifier crosses the privacy boundary; a false positive costs a retry. When recall, precision, and latency conflict, optimize recall first, then precision, then latency.
- **Measure latency.** The engine sits inline in agent loops. Do not add a stage to the hot path without measuring it (`inumaki bench`).
- **No GPU, no Python at runtime.** inumaki has to run on ordinary office hardware.
- **Bump `SANITIZER_GENERATION` when sanitized output can change.** Any change to detection, policy, the verifier, tokenization, or mirror rendering raises the constant in `crates/inumakid/src/config.rs`. It is part of the configuration fingerprint the folder mirror stores with each file; without the bump, a build of the same version keeps mirror files sanitized by the old code on disk. Reviewers check it.

`docs/threat-model.md` has the full list of rules and the tests that enforce them. Read it before you change the gateway, the mirror, the proxy, or the hook.

## Design changes

`local_privacy_proxy_design.md` is the concept and rationale. The maintainer's design specs are kept outside this repository; where they changed behaviour, `docs/architecture.md` and `docs/threat-model.md` describe what is built. If your change alters documented behaviour, update the document that describes it in the same pull request, not only the code. Update `docs/threat-model.md` when a change moves the boundary, adds a residual, or removes one, and `docs/configuration.md` when it adds a setting. Do not change a setting's default to a less safe value without saying so in the pull request.

Larger changes (a new detector, a new provider route, a new harness adapter) are easier to review if you open an issue first and describe the failure it addresses.

## Commit style

Commits use a conventional subject and an imperative, specific description:

```
fix(proxy): agent rule accepts SDK versions, refuses %
docs: configuration reference
feat(inumakid): [proxy.upstreams.<id>] extra_headers
```

The type is `feat`, `fix`, `docs`, `test`, `refactor`, or `chore`, with the crate or area in parentheses when it helps. A body explains why when the subject does not. Keep a commit to one change, include its tests, and stage files by explicit path. Do not put any text from real data in a commit message.

## License

inumaki is licensed under the Apache License 2.0 (`LICENSE`). By contributing you agree that your contribution is licensed under the same terms. `NOTICE` lists third-party material: code derived from [gline-rs](https://github.com/fbilhaut/gline-rs) (Apache-2.0) in `crates/inumaki-models/src/gliner.rs`, and the built-in first-name list from Statistik Austria (CC BY 4.0) and Berlin open data (CC BY 3.0 DE). Models are not distributed with inumaki; `inumaki models pull` downloads `knowledgator/gliner-x-small` (Apache-2.0) and an ONNX export of `Davlan/bert-base-multilingual-cased-ner-hrl` (AFL-3.0) from Hugging Face under their own licences. If you add third-party code, data, or a model, keep its licence compatible with Apache-2.0 and add it to `NOTICE`.
