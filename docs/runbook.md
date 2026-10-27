# Runbook: key custody, backup, restore

What to protect, what to copy, how to prove a copy works. Current state: the daemon runs as the user; Protected mode (a separate service user, M7) is not built. Backup tooling and portable key export are not built either; everything below is done with the shell and `inumaki`.

## What the vault is

`<data dir>/vault.sqlite` (SQLite, WAL mode) holds every dataset: token mappings (originals encrypted with XChaCha20-Poly1305, indexed by HMAC), known-entity state, the sanitization cache is *not* in it (memory only), upstream rows, secrets (`<dataset>/upstream/<name>/env`, `<dataset>/mail/password`), gateway token hashes, activity records, the egress journal, mailbox rows and mail handles. One file, one set of keys.

The data directory is `--data-dir`, else `$INUMAKI_DATA_DIR`, else `~/Library/Application Support/inumaki` (macOS) or `$XDG_DATA_HOME/inumaki` (Linux, default `~/.local/share/inumaki`). Homebrew's service and the `.deb`'s user unit use that default (`docs/packaging.md`, added with the packaging task).

`<data dir>/revocations/` holds pending gateway token revocations: the app's Revert writes one small file per harness there (`<harness>.json`, only the token label) when the service is stopped, and the service applies and deletes them before it serves anything at its next start, and on every 60 s sweep while it runs. The directory is normally empty or absent, and it is not part of a backup. If the service refuses to start because an entry there cannot be removed (for example a directory named `*.json`), delete that entry by hand and start the service again. Such a directory (or any entry that is not a regular file) counts as an unreadable record, so the service has already revoked every `app:` token before it stopped: Reconnect the harnesses afterwards. How this fits the token model: [Gateway tokens in harness files](threat-model.md#gateway-tokens-in-harness-files).

## Where the keys are

Two 32-byte keys (encryption, HMAC index), stored together:

| `[vault] key_source` | Location | Backed up by |
|---|---|---|
| `keyring` (default when a secret store is reachable) | macOS Keychain / Linux Secret Service item `inumaki-vault-<vault_id>`; `vault_id` is a random id in the vault's `meta` table | nothing this project ships; see "Keyring limitation" |
| `file` | `<data dir>/vault.key`, mode 0600 (the vault refuses a wider mode) | copying the file |

`inumaki status` prints `keys keyring` or `keys file`. `vault.sqlite` without its keys is unreadable and cannot be repaired; **there is no `export-key`/`import-key` command in this version.** Losing both the key file and the secret-store item means the vault's contents are gone; the datasets can be recreated but no earlier sanitized output can be rehydrated.

Treat `vault.key` as the vault itself. Do not keep it beside `vault.sqlite` inside one unencrypted backup, do not paste its contents into a command line (shell history keeps it), and do not let an unencrypted cloud-sync folder carry it.

## Taking a consistent copy

1. Stop the daemon so the WAL is checkpointed into the main file:
   - foreground: `kill -TERM <pid>` (or Ctrl-C); Homebrew: `brew services stop inumaki`; systemd: `systemctl --user stop inumakid`.
   - The daemon logs `vault checkpoint` problems as a warning; a clean stop leaves `vault.sqlite-wal` absent or empty. If it is not empty, the stop was not clean: start and stop again.
2. Copy `vault.sqlite` and, with the file key source, `vault.key` together, preserving modes: `cp -p vault.sqlite vault.key /path/to/backup/`. A copy taken while the daemon runs may lack the last minutes of writes and is not the procedure this runbook tests. Store `vault.key` apart from the copy of `vault.sqlite`, or inside an encrypted backup; a backup holding both in the clear gives its reader every original value.
3. With the keyring source, the copy of `vault.sqlite` is only useful on a machine whose secret store holds the same item (see below).

## Restore drill (do this before you need it)

Synthetic data only. The drill is the test `restore_drill_into_an_isolated_directory` in `crates/inumaki-cli/tests/daemon_cli.rs`; by hand, with the release binary and the file key source:

```bash
# 1. a throwaway live vault (run from the repository root; offline profile, so no models are needed)
mkdir -p /tmp/drill/no-models
{ cat configs/default.toml
  printf '\n[daemon]\ndefault_profile = "offline"\n[vault]\nkey_source = "file"\n[gateway]\nlisten = "127.0.0.1:0"\n'
} > /tmp/drill/inumaki.toml
inumaki daemon --config /tmp/drill/inumaki.toml --data-dir /tmp/drill/live --socket /tmp/drill/a.sock --models-dir /tmp/drill/no-models &
until inumaki --socket /tmp/drill/a.sock status >/dev/null 2>&1; do sleep 0.2; done   # wait until the daemon answers
inumaki --socket /tmp/drill/a.sock dataset add drill --name "Restore drill"
echo "Kundin Zyxwuria Quolnath, IBAN AT61 1904 3002 3457 3201" \
  | inumaki --socket /tmp/drill/a.sock sanitize --dataset drill - | tee /tmp/drill/out.txt
kill -TERM %1; wait
# 2. the copy, into an isolated directory
mkdir /tmp/drill/restore && cp -p /tmp/drill/live/vault.sqlite /tmp/drill/live/vault.key /tmp/drill/restore/
# 3. a daemon on the copy restores the output
inumaki daemon --config /tmp/drill/inumaki.toml --data-dir /tmp/drill/restore --socket /tmp/drill/b.sock --models-dir /tmp/drill/no-models &
until inumaki --socket /tmp/drill/b.sock status >/dev/null 2>&1; do sleep 0.2; done   # wait until the daemon answers
inumaki --socket /tmp/drill/b.sock dataset list                      # shows: drill
inumaki --socket /tmp/drill/b.sock rehydrate --strict --dataset drill /tmp/drill/out.txt
kill -TERM %1; wait; rm -rf /tmp/drill
```

Expected: `rehydrate --strict` prints the original line, exit 0. The negative case is tested too (`restore_without_the_key_fails_closed`): a copy of `vault.sqlite` without `vault.key` makes the daemon exit 2 with `inumakid failed to start` and `the loaded keys do not belong to this vault` in the log; it never opens the vault with a fresh key and never prints a value. Delete any `vault.key` such a failed start left behind before copying the real one in.

## Keyring limitation

With `key_source = "keyring"`, restoring onto the **same** machine and user works because the Keychain/Secret Service item is found by `vault_id`, not by path: moving or copying the data directory keeps the vault readable. Restoring onto **another** machine cannot be demonstrated with what this project ships: the item is not exported, and the drill above is run with the file source for that reason. Until key export exists, a vault that must survive the machine uses `[vault] key_source = "file"` and backs up `vault.key` as a secret (it is the vault). Do not assume a copy of `vault.sqlite` alone is a backup.

## What the copy does not contain

- The sanitization cache (memory), session contexts (memory, TTL), and the daemon's logs (counts and ids only).
- Models (`inumaki models pull` restores them from the pinned manifest).
- Configuration: `<data dir>/inumaki.toml` (read by default, if you made one) and any file passed with `--config`. The copy above is `vault.sqlite` and `vault.key` only, so back the configuration up with your dotfiles.

## Service management

How the service was installed decides how to stop it (`GET /v1/service` on the control socket, field `managed_by`, and the app's Settings view show it):

| Installed by | Stop | Start | Restart |
|---|---|---|---|
| the app (macOS LaunchAgent `inumaki.inumakid`) | `launchctl bootout gui/$(id -u)/inumaki.inumakid` | `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/inumaki.inumakid.plist` | `launchctl kickstart -k gui/$(id -u)/inumaki.inumakid`, or Settings → Restart |
| the app (Linux user unit) | `systemctl --user stop inumakid` | `systemctl --user start inumakid` | `systemctl --user restart inumakid`, or Settings → Restart |
| Homebrew | `brew services stop inumaki` | `brew services start inumaki` | `brew services restart inumaki` |
| the `.deb` | `systemctl --user stop inumakid` | `systemctl --user enable --now inumakid` | `systemctl --user restart inumakid` |

Every stop checkpoints the vault, so a copy taken after it is consistent. On Linux, `loginctl enable-linger $USER` keeps a user unit running while you are logged out. Removing the service (Settings → Remove, or deleting the plist or unit) never deletes the vault, the models, or the adapter backups in `<data dir>/adapters/backups/`, which can hold an MCP server's secrets after the Protect switch (see `docs/threat-model.md`).

## Folders (the folder mirror)

`inumaki folder list` shows each connected folder's state (`scanning`, `watching`, `pending`, `stopped`, `failed`) and, when something is wrong, an error class. The mirror keeps what it has while a folder is in error and retries on its own, backing off from 10 seconds to 10 minutes; `inumaki folder rescan ID` retries at once. The commands are in `docs/cli.md`.

### A folder shows `source_not_permitted`

macOS blocks a process from reading Desktop, Documents, Downloads, iCloud Drive, and external volumes until you grant it. The folder stays `failed` and the mirror keeps its sanitized copy; nothing is deleted.

1. Open System Settings, Privacy & Security, Files and Folders (or Full Disk Access) and allow the program that runs the daemon: the `inumakid` binary, or the inumaki app if it started the daemon.
2. Run `inumaki folder rescan ID`, or wait for the next retry. You do not need to add the folder again.

On macOS 27.0.1 a launchd job does get the system prompt, and the first read waits until you answer it; the folder shows `pending` meanwhile (`docs/research/2026-09-29-m5-tcc-spike.md`). While builds are ad hoc signed, every upgrade changes the code hash and **drops the grant** (confirmed by that spike with a probe binary; the mirror itself was not run against a protected folder), so macOS asks again after each upgrade; if you denied it, repeat the steps. A bare binary may not appear in the Files and Folders list until it is prompted; in Full Disk Access, use the "+" button and choose the `inumakid` binary (or the app). If no entry appears in the list, choose a source folder outside the protected locations. Linux has no equivalent; there the same error means a permission problem on the folder.

### A folder shows `source_missing`

The source folder is gone, was replaced by another directory (or a link), or its volume is not mounted. The mirror is left as it is. Mount the volume or restore the folder and the next retry clears the error.

**A folder on a USB or external drive shows `source_missing` after the drive came back.** inumaki identifies a folder by its device and inode number. A drive that re-enumerates (another port, another mount order) gets a new device number and reads as a replaced folder. Run `inumaki folder remove ID` and add the folder again with `inumaki folder add`; the mirror is rebuilt from scratch. The same applies after a restart that followed adding a folder while its volume was unreadable: such a folder shows `source_missing` and deletes nothing until it is added again.

### The mirror root is refused (`mirror_unwritable`)

The mirror root (`[mirror] root`, default `~/Inumaki Mirror`) is adopted only if it does not exist, is empty, or carries the `.inumaki-root` marker inumaki writes; any other directory is refused without being touched, and no folder is mirrored. On macOS the default volume is case-insensitive, so a root named `~/Inumaki` is the same directory as an existing `~/inumaki` (a source checkout, for example); the default `~/Inumaki Mirror` avoids that. Set `root` to another path in your configuration and restart the daemon. An install that used the old default `~/Inumaki` keeps its mirror by setting `[mirror] root = "~/Inumaki"`. After a root change, Reconnect each harness so the paths Connect wrote are updated.

The same class also appears when the root is a symlink, when its parent is not writable, or when a folder's label directory holds a marker with another label. In the last case inumaki leaves that directory alone and drops the folder's records on removal.

### The mirror looks stale

Events can be missed (a network volume sends none; the event queue can overflow). Every folder is reconciled hourly (`[mirror] rescan_interval`). To check now, run `inumaki folder rescan ID`: it re-checks every file and retries files that were blocked, unreadable, or pending. A rotation, a profile change, a change to a configuration value or a dictionary file, or a daemon upgrade that changes the version, the sanitizer generation, the build revision, or the pinned model manifest re-mirrors a folder once in the background (`remirror_pending` in `GET /v1/folders`, which the app shows, is true until it is done). A file you edit inside the mirror is not noticed until its source file changes; rescan does not restore it.

### Remove a folder

`inumaki folder remove ID` stops watching and deletes the mirror tree for that folder. The source folder and the outbox destination are never touched, so files already restored there stay. Add `--dataset` to delete the dataset and its tokens too; without it the dataset and its tokens remain.

After a crash, a `.inumaki-tmp-*` file can remain in an outbox destination directory. It holds a restored original (mode 0600). inumaki removes it when a later file lands in that directory; delete it by hand if you do not want to wait.
