# inumaki app

The tray icon and settings window of inumaki (M6 spec §6): Tauri 2, React, TypeScript, Vite. The Rust side talks to `inumakid` only through `inumaki-client` over the control socket and runs the harness adapters (`inumaki-adapters`) in this process. The UI reaches the daemon, the file system, and the plugins only through the commands in `src-tauri/src/ipc.rs`.

## Develop

The package manager is npm (the lock file is `package-lock.json`; do not use pnpm or yarn).

    npm install
    npx tauri dev          # needs a running inumakid for real data; views show "not available yet" for routes the daemon lacks

The first Rust build compiles Tauri and takes a few minutes. `src-tauri` is its own Cargo workspace with its own `Cargo.lock` and `target/`, outside the repository's root workspace: `cargo test --workspace` at the root does not build it, and it needs no WebKit or GTK packages there.

## Test

From this directory:

    cargo test --manifest-path src-tauri/Cargo.toml     # Rust: against the mock daemon, with fake harnesses
    cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
    cargo fmt --manifest-path src-tauri/Cargo.toml --check
    npm run lint && npm run typecheck && npm test       # frontend: lint rules, types, reveal hook, NFC offsets
    npm run build                                       # type check and production bundle into dist/

From the repository root, the Rust tests are `cargo test --manifest-path apps/inumaki-app/src-tauri/Cargo.toml`.

No test touches your harness configuration files or talks to a real daemon. `src-tauri/tests/no_leak.rs` drives every command against mock answers that carry canary values in every sensitive field and checks that none reaches `app.log`, `state.json`, a notification, or the `Debug` output and serialization of an error. Run it after any change to a command, a view type, or the poller.

## Rules this code keeps

- Originals appear only after an explicit reveal, carry the label "originals revealed locally — not for transmission", and are cleared after 60 seconds, on navigation, and when the window hides. They are never stored, logged, or copied except with the Copy button.
- Notifications name entity kinds, the front door, and counts — never a dataset, path, server name, or value.
- `app.log` takes only fixed strings and numbers (`src-tauri/src/applog.rs`; every IPC command logs through `applog::logged`); `state.json` holds no values, tokens, secrets, paths, or server names (servers are keyed by an HMAC under `state.key`).
- The app's own types that hold names, paths, tokens, or values print flags and counts only in `Debug`.
- Adapter behaviour is reached only through `src-tauri/src/harness/adapt.rs` (the `HarnessOps` seam); other files use the adapter crate's types only (`ReasonCode`, `CheckPlan`, `Invocation`).

Packaging (`.app`, `.dmg`, ad hoc signature) comes with M6-3 in `scripts/package-app.sh` and `docs/packaging.md`.
