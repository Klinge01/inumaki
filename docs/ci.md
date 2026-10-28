# Continuous integration

`check` and `models` run on every push and pull request. `reference` runs only for pushes to `main`, and only once the reference runner is set up (below). The separate `app` workflow builds the macOS `.dmg` on demand and for release tags (`docs/packaging.md`).

| Job | Runner | Gated on |
|---|---|---|
| `check` | GitHub-hosted `ubuntu-latest`, `macos-latest` | fmt, clippy, all tests, `offline` baseline (no models) |
| `models` | GitHub-hosted `ubuntu-latest` | model tests, the curated safety suite (see below); the corpus eval and the quantized `kiji-pii` model test are informational because int8 ONNX Runtime kernels differ between x86 (VNNI/AVX2) and Apple Silicon (NEON) and the committed baselines were measured on the latter |
| `reference` | self-hosted, labels `self-hosted, macOS, ARM64, inumaki-reference` | all tests, model tests, every committed baseline on the tuning corpus (`support-email`, `strict`, `thorough`, `offline`) and the held-out corpus (`support-email`, `strict`), the safety suite, the M4 targets (spec §13.1), bench |

The `reference` job is the quality gate the M4 spec requires (§13.1). Its baselines live in `crates/inumaki-eval/baselines/`; the reports behind them are under `docs/quality/`.

## Gating state

Steps marked `continue-on-error: true` in `.github/workflows/ci.yml` are informational. As of plan 1 (2026-09-25) that is: the M4 targets step. The curated safety suite is gated (no `continue-on-error`) because both `support-email` and `strict` pass it with zero residue (`docs/quality/2026-09-25-matrix.md`, "Gate status after calibration"). The M4 targets step stays informational because the full corpus and held-out targets (accepted leak rate, block rate, PERSON recall, and, on held-out, verifier false-positive rate) are missed on both profiles. Plan 4 removes the flag when the corresponding gate passes on the reference runner. A gate must never be made informational to get a red build green; a real regression is fixed or the change is reverted.

## Setting up the reference runner

One machine, Apple Silicon, macOS 14 or later, Rust stable, about 5 GB free (toolchain, target directory, 370 MB of models).

1. In the GitHub repository: Settings → Actions → Runners → New self-hosted runner → macOS, ARM64. Follow the download and `./config.sh` steps with these values:
   ```bash
   ./config.sh --url https://github.com/<owner>/inumaki --token <token> \
     --name inumaki-mac --labels inumaki-reference --work _work --unattended
   ```
   The `inumaki-reference` label is what the workflow selects; `self-hosted`, `macOS`, `ARM64` are added automatically.
2. Install it as a launchd service so it survives logouts and restarts:
   ```bash
   ./svc.sh install && ./svc.sh start && ./svc.sh status
   ```
3. Keep the machine awake while a job may run (System Settings → Energy → Prevent automatic sleeping on power adapter), or run `caffeinate -i` in a login item.
4. Pre-pull the models once so the first job does not download 370 MB:
   ```bash
   mkdir -p ~/inumaki-ci/models
   INUMAKI_MODELS_DIR=~/inumaki-ci/models cargo run --release -q -p inumaki-cli -- models pull
   ```
5. Turn the job on: set the repository variable `REFERENCE_RUNNER` to `true` (Settings → Secrets and variables → Actions → Variables). Until then the job is skipped. It never runs for pull requests: on a public repository a self-hosted runner would run a fork's code on your machine.
6. Branch protection (Settings → Branches → `main`): require status checks `check (ubuntu-latest)`, `check (macos-latest)`, `models`. `reference` cannot be a required pull-request check because it does not run for pull requests; it checks `main` after the merge. With one runner, jobs queue; a `reference` run takes 10–15 minutes.

Runner logs: `~/actions-runner/_diag/`. If the runner is offline while `REFERENCE_RUNNER` is `true`, GitHub queues the job and the run stays pending: a missing reference runner blocks qualification (spec §13.1), it does not skip it.

The `bench via daemon` step's socket lives under `$RUNNER_TEMP`. If the daemon logs `path too long` (a short path under `/private/var/folders` can still exceed macOS's 104-byte `AF_UNIX` socket path limit once combined with the runner's work directory), use `/tmp/inumakid-ci-$$.sock` instead.

## When a gate fails

- **A baseline regression** (`regression: … < baseline …`): the change lowered recall or raised leak/block rates on the reference machine. Fix the change, or, if the metric definition changed on purpose, re-record with `inumaki eval --profile P --write-baseline …` and commit the before/after `--report-json` reports under `docs/quality/` in the same commit, saying why.
- **A target miss** (`target missed: …`): the absolute M4 targets are not met; the build is labeled experimental until they are. Thresholds change only with a spec revision.
- **The offline gate on GitHub-hosted runners**: no models are involved; this is a deterministic regex/dictionary regression.
