# Packaging

Three unsigned packages: a Homebrew formula, a `.deb` with a systemd user unit, and the macOS app (`.app` in a `.dmg`, ad hoc signed). The app bundle is ad hoc signed, not Developer-ID signed or notarized (M6 spec §7.3), so Gatekeeper asks for confirmation on first launch. Models are never packaged: `inumaki models pull` downloads the pinned files (about 370 MB) into the platform data directory.

## Homebrew (macOS, Linuxbrew)

`scripts/package.sh` writes `dist/inumaki-<version>.tar.gz` from `git archive HEAD` and renders `packaging/homebrew/inumaki.rb.in` into `dist/inumaki.rb` with that tarball's URL and SHA-256; at release time the URL becomes the tagged tarball. Install and test from source:

```bash
scripts/package.sh --brew-test          # brew install --build-from-source, brew test, brew uninstall
brew install --formula ./dist/inumaki.rb
inumaki models pull
brew services start inumaki             # launchd runs inumakid; logs: $(brew --prefix)/var/log/inumakid.log; optional config: ~/Library/Application Support/inumaki/inumaki.toml
inumaki status
```

`brew services stop inumaki` stops the daemon (it checkpoints the vault; see `docs/runbook.md`). The formula builds with `cargo build --release --locked`; the `ort` crate downloads the pinned ONNX Runtime during the build.

## Debian and Ubuntu (`.deb`)

Built with `cargo-deb` inside `rust:1-bookworm` from the committed tree, because the reference machine is macOS; then installed into a fresh `debian:bookworm` container for a smoke test:

```bash
scripts/package-deb.sh                  # arm64 on Apple Silicon; --arch amd64 runs under emulation
sudo apt install ./dist/inumaki_<version>-1_<arch>.deb
inumaki models pull
systemctl --user enable --now inumakid  # the user unit in /usr/lib/systemd/user/inumakid.service
loginctl enable-linger "$USER"          # keep it running while logged out
inumaki status
```

Files: `/usr/bin/inumaki`, `/usr/bin/inumakid`, `/usr/bin/inumaki-mcp`, `/usr/bin/inumaki-hook`, `/usr/share/inumaki/default.toml` (the embedded default, for reference and `--config` copies), `/usr/lib/systemd/user/inumakid.service`, `/usr/share/doc/inumaki/*.md`. The unit runs as the user with `NoNewPrivileges`, `PrivateTmp`, and `UMask=0077`, and sets `INUMAKI_MANAGED_BY=deb`; data lives in `~/.local/share/inumaki`, and the unit starts `inumakid` without `--config`, so `~/.local/share/inumaki/inumaki.toml` is read if it exists, otherwise the embedded default (`docs/configuration.md`). A **system** unit with `DynamicUser=yes`, `StateDirectory=inumaki`, and `ProtectHome=yes` (Kiji's unit is the reference) is the Protected-mode shape for milestone 7, not this package.

The x86-64 (`amd64`) package is built the same way but its quality numbers are **not measured** unless `docs/quality/` has a report with `platform = linux-x86_64`. The build does not look at the platform when it labels qualification: `inumaki doctor` prints `unqualified` after every profile, and `inumaki status` prints one `qualification unqualified` on its gateway line, on every platform (see "Build label" below).

## macOS app (`.app` in a `.dmg`)

`scripts/package-app.sh` builds the four binaries (`inumakid`, `inumaki`, `inumaki-mcp`, `inumaki-hook`), puts them into the bundle as Tauri sidecars, builds `Inumaki.app`, signs it **ad hoc** (`codesign --force --deep -s -`), verifies the signature, and writes `dist/Inumaki-<version>.dmg`. There is no Developer ID and no notarization yet (M6 spec §2 decision 4).

When you click "Install and start" (in the first-run service step or in Settings), the app copies the four binaries to `~/Library/Application Support/inumaki/bin`, removes the `com.apple.quarantine` attribute from the copies, re-signs them ad hoc, and installs the LaunchAgent `~/Library/LaunchAgents/inumaki.inumakid.plist`, which runs `bin/inumakid` with `INUMAKI_MANAGED_BY=app`. The service starts `inumakid` without `--config`, so it reads `~/Library/Application Support/inumaki/inumaki.toml` if that file exists and otherwise the embedded default (`docs/configuration.md`). Every service file and harness entry refers to that `bin` directory, so moving or replacing the app changes nothing. At every start the app only refreshes helpers it already installed: after an update it replaces the copies whose SHA-256 differs from the bundled ones and restarts its service.

**Opening an unsigned download.** A `.dmg` downloaded with a browser is quarantined, and Gatekeeper refuses an app without a Developer ID. Either right-click `Inumaki.app` → Open → Open, or clear the attribute once: `xattr -dr com.apple.quarantine /Applications/Inumaki.app`.

**Keychain prompts after an update.** An ad hoc signature changes with every build, so macOS asks again whether `inumakid` may read its vault key from the Keychain. Enter the login password and choose **Always Allow**: plain Allow covers only that one start, and the next start asks again. `inumakid` waits up to 2 minutes for the answer before it gives up (`KEYRING_TIMEOUT`); meanwhile the app may report that the service did not start, and the service comes up once the prompt is answered. A daemon that gives up or is denied exits, launchd starts it again after about 10 s, and a new prompt appears; to stop that, Stop the service in the app or run `launchctl bootout gui/$(id -u)/inumaki.inumakid`. Prompts left on screen from a daemon that already exited close with Deny. A new vault can use `[vault] key_source = "file"` instead (see `docs/runbook.md`); an existing vault cannot switch. A Developer ID signature removes the prompt and is planned for the release.

**Existing installs.** If `inumakid` already answers on the default socket because Homebrew or the `.deb` installed it, the app uses that service and offers neither install nor remove.

**Uninstall.** Settings → Login service → Remove stops and unregisters the service; then delete `Inumaki.app`. The vault, models, backups, and `bin` stay in `~/Library/Application Support/inumaki` until you delete them.

## Known issues (2026-10-09)

- **Every upgrade asks for privacy grants again.** macOS binds a folder grant (Desktop, Documents, Downloads, iCloud Drive, external volumes) to the binary's code hash, and an ad hoc signature changes with every build. After each upgrade the first read of each protected folder shows the macOS prompt again; the read waits until it is answered, and the folder shows `pending` meanwhile. Answer the prompt; until then a folder removal may answer "the folder is busy; try again in a moment", and with the default single mirror worker every other folder waits too. The Keychain prompt above comes back for the same reason. A Developer ID signature is the expected fix and was not tested.
- **Replace binaries by rename, never in place.** macOS kills a signed binary whose file is overwritten in place (`OS_REASON_CODESIGNING`). The app writes `.<helper>.tmp` in `bin/`, clears and re-signs it, and renames it over the old copy; Homebrew installs a new keg; `dpkg` writes `.dpkg-new` and renames. If you replace a binary by hand, do the same (copy to a new file, then `mv`), never `cp` onto the installed file.
- **`inumakid` stays a bare LaunchAgent.** An `SMAppService` agent inside the app bundle would show the app's name in the prompt, but it loses the grant on an ad hoc upgrade as well and has to be re-registered after every upgrade (`docs/research/2026-09-29-m5-tcc-spike.md`); revisit with Developer ID signing.
- **Only part of the install path has been walked.** Per `docs/mvp-checklist.md`: the app route of criterion 1 (Install and start, Download models, `launchctl print` showing the service running) passed on 2026-10-11; the Homebrew route and the `.deb` on a real machine were not walked. The real-harness part of criterion 5 passed on 2026-10-10, but the harness connections (criteria 2 and 3) were walked on 2026-10-11 and are open for a re-walk, and the email and activity views (criterion 6) have not been walked. The checklist is not signed off. There is no Linux app package; Linux users get the `.deb` and the CLI.

## Release TODOs

Two values are placeholders that must be replaced before a release: the `.deb` maintainer (`inumaki maintainers <maintainers@inumaki.invalid>`) and the formula homepage (`https://github.com/OWNER/inumaki`, where `OWNER` is the GitHub account or organization). Until then they are deliberately unroutable, not a person's address.

## Build label

`inumaki status` and `inumaki doctor` report every profile as `unqualified`: no profile has passed the M4 quality gates, and no qualification record is committed yet (the measured numbers are in `docs/quality/`). The Homebrew formula's description says "experimental" for the same reason.
